"""Process-local scan execution and detector integration.

Detector secrets are held only in memory for the lifetime of a queued scan.
Only detector names and sanitized execution outcomes are persisted.
"""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import UTC, datetime
from threading import RLock
from time import sleep
from typing import Any

from sqlalchemy import inspect, select, update
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_engine, get_session_factory
from app.detectors.base import DetectorResult
from app.detectors.base import Evidence as DetectorEvidence
from app.detectors.bfla import BflaDetector
from app.detectors.bola import BolaDetector
from app.detectors.bopla import BoplaDetector
from app.detectors.broken_auth import BrokenAuthDetector
from app.detectors.http_client import DetectorHTTPError
from app.detectors.jwt_analyzer import JwtAnalyzer
from app.detectors.misconfiguration import MisconfigurationDetector
from app.detectors.sanitiser import sanitise_body, sanitise_headers
from app.models import Api, Endpoint, Evidence, Finding, Scan, ScanHistory
from app.security.target_allowlist import TargetNotAllowed, TargetPolicy, validate_controlled_target

_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="api-security-scan")
_execution_lock = RLock()
_active: dict[int, Future[None]] = {}
_runtime_configs: dict[int, dict[str, dict[str, object]]] = {}
_SQLITE_CLAIM_RETRIES = 3


class ScanCancelled(Exception):
    """Internal control flow for cooperative detector cancellation."""


def _policy() -> TargetPolicy:
    settings = get_settings()
    return TargetPolicy.from_strings(
        settings.controlled_target_hosts, settings.controlled_target_cidrs
    )


def register_runtime_config(scan_id: int, config: dict[str, dict[str, object]]) -> None:
    """Keep detector inputs transient; never write them to the database."""

    with _execution_lock:
        _runtime_configs[scan_id] = config


def discard_runtime_config(scan_id: int) -> None:
    with _execution_lock:
        _runtime_configs.pop(scan_id, None)


def _take_runtime_config(scan_id: int) -> dict[str, dict[str, object]]:
    with _execution_lock:
        return _runtime_configs.pop(scan_id, {})


def _record_history(db: Session, scan: Scan, event: str) -> None:
    db.add(ScanHistory(api_id=scan.api_id, scan_id=scan.id, status=scan.status, event=event))


def reconcile_interrupted_scans() -> int:
    """Mark scans from a previous process as failed without reconstructing secrets."""

    settings = get_settings()
    engine = get_engine(settings.database_url)
    if "scans" not in inspect(engine).get_table_names():
        return 0
    session_factory = get_session_factory(settings.database_url)
    recovered = 0
    with session_factory() as db:
        rows = db.execute(
            select(Scan.id, Scan.api_id, Scan.status).where(
                Scan.status.in_(("pending", "running"))
            )
        ).all()
        for scan_id, api_id, previous_status in rows:
            if previous_status == "running":
                error_summary = "scan interrupted by backend restart"
                event = "recovered_running"
            else:
                error_summary = "scan not started because runtime configuration was lost"
                event = "recovered_pending"
            result = db.execute(
                update(Scan)
                .where(Scan.id == scan_id, Scan.status == previous_status)
                .values(
                    status="failed",
                    completed_at=datetime.now(UTC),
                    error_summary=error_summary,
                )
            )
            if result.rowcount == 1:
                with _execution_lock:
                    _runtime_configs.pop(scan_id, None)
                db.add(
                    ScanHistory(
                        api_id=api_id,
                        scan_id=scan_id,
                        status="failed",
                        event=event,
                    )
                )
                recovered += 1
        db.commit()
    return recovered


def _safe_error_summary(exc: BaseException) -> str:
    if isinstance(exc, TargetNotAllowed):
        return "scan target is not authorized by the controlled target policy"
    if isinstance(exc, DetectorHTTPError):
        return "detector request failed"
    return f"scan execution failed ({type(exc).__name__})"


def _is_cancelled(db: Session, scan_id: int) -> bool:
    current_status = db.scalar(select(Scan.status).where(Scan.id == scan_id))
    return current_status is None or current_status == "cancelled"


def _execute_claim_update(db: Session, statement):
    """Retry only pre-commit SQLite lock failures for the claim statement."""

    for attempt in range(_SQLITE_CLAIM_RETRIES):
        try:
            return db.execute(statement)
        except OperationalError as exc:
            dialect = db.get_bind().dialect.name
            locked = "locked" in str(exc).lower()
            if dialect != "sqlite" or not locked or attempt == _SQLITE_CLAIM_RETRIES - 1:
                raise
            db.rollback()
            sleep(0.05 * (2**attempt))
    raise RuntimeError("unreachable claim retry state")


def _persist_result(
    db: Session,
    scan: Scan,
    endpoint: Endpoint,
    result: DetectorResult,
    *,
    evidence: list[DetectorEvidence] | None = None,
    vulnerable: bool | None = None,
) -> int:
    if vulnerable is None:
        vulnerable = result.vulnerable
    if not vulnerable:
        return 0
    dedupe_key = f"{scan.id}:{endpoint.id}:{result.owasp_category.value}"
    existing = db.scalar(
        select(Finding).where(
            (Finding.dedupe_key == dedupe_key)
            | (
                (Finding.scan_id == scan.id)
                & (Finding.endpoint_id == endpoint.id)
                & (Finding.category == result.owasp_category.value)
            )
        )
    )
    if existing is not None:
        return 0
    try:
        with db.begin_nested():
            finding = Finding(
                dedupe_key=dedupe_key,
                scan_id=scan.id,
                endpoint_id=endpoint.id,
                category=result.owasp_category.value,
                severity=result.severity.value,
                confidence=result.confidence,
            )
            db.add(finding)
            db.flush()
    except IntegrityError:
        return 0
    for item in evidence if evidence is not None else result.evidence:
        db.add(
            Evidence(
                finding_id=finding.id,
                request=sanitise_body(
                    {
                        "url": item.url,
                        "method": item.method,
                        "headers": item.request_headers,
                        "body": item.request_body,
                    }
                ),
                response=sanitise_body(
                    {
                        "status": item.response_status,
                        "headers": sanitise_headers(item.response_headers),
                        "body": item.response_body,
                    }
                ),
                context=sanitise_body(item.context),
            )
        )
    return 1


def _outcome(
    detector: str,
    state: str,
    *,
    reason: str | None = None,
    result: DetectorResult | None = None,
    findings: int = 0,
) -> dict[str, Any]:
    value: dict[str, Any] = {"detector": detector, "status": state, "finding_count": findings}
    if reason:
        value["reason"] = sanitise_body(reason)
    if result is not None:
        value.update(
            {
                "vulnerable": result.vulnerable,
                "severity": result.severity.value,
                "confidence": result.confidence,
                "title": sanitise_body(result.title),
                "detail": sanitise_body(result.detail),
            }
        )
    return value


def _find_endpoint(endpoints: list[Endpoint], path: str, method: str) -> Endpoint | None:
    expected_method = method.upper()
    return next(
        (
            endpoint
            for endpoint in endpoints
            if endpoint.path == path and endpoint.method.upper() == expected_method
        ),
        None,
    )


def _missing_operation(
    endpoints: list[Endpoint], path: str, methods: tuple[str, ...]
) -> str | None:
    missing = [method for method in methods if _find_endpoint(endpoints, path, method) is None]
    if missing:
        return f"endpoint '{path}' is missing required method(s): {', '.join(missing)}"
    return None


def _missing(config: dict[str, object], fields: tuple[str, ...]) -> list[str]:
    return [field for field in fields if not config.get(field)]


def validate_scan_inventory(
    detector_names: list[str],
    runtime_config: dict[str, dict[str, object]],
    endpoints: list[Endpoint],
) -> str | None:
    """Validate configured detector operations without contacting the target."""

    for name in detector_names:
        config = runtime_config.get(name, {})
        if name == "misconfiguration":
            paths = (
                [str(config["endpoint_path"])]
                if config.get("endpoint_path")
                else list(dict.fromkeys(endpoint.path for endpoint in endpoints))
            )
            if not paths:
                return "misconfiguration requires an endpoint with GET and POST operations"
            for path in paths:
                error = _missing_operation(endpoints, path, ("GET", "POST"))
                if error:
                    return error
            if config.get("graphql_path"):
                error = _missing_operation(endpoints, str(config["graphql_path"]), ("POST",))
                if error:
                    return error
            continue

        method_requirements = {
            "bola": ("endpoint_path", "GET"),
            "bfla": ("admin_endpoint_path", "GET"),
            "broken_auth": ("endpoint_path", "GET"),
            "jwt_analyzer": ("protected_path", "GET"),
        }
        if name == "bopla":
            for field, method in (("read_path", "GET"), ("write_path", "PATCH")):
                path = config.get(field)
                if not path:
                    return f"detector '{name}' requires '{field}'"
                if _find_endpoint(endpoints, str(path), method) is None:
                    return f"configured {field} with method {method} is not in the API inventory"
            continue
        field, method = method_requirements[name]
        path = config.get(field)
        if not path:
            return f"detector '{name}' requires '{field}'"
        if _find_endpoint(endpoints, str(path), method) is None:
            return f"configured {field} with method {method} is not in the API inventory"
        if name == "jwt_analyzer" and config.get("auth_path"):
            if _find_endpoint(endpoints, str(config["auth_path"]), "POST") is None:
                return "configured auth_path with method POST is not in the API inventory"
        if name == "jwt_analyzer" and not config.get("auth_path"):
            return "detector 'jwt_analyzer' requires 'auth_path'"
    return None


def _execute_detector(
    name: str,
    config: dict[str, object],
    base_url: str,
    policy: TargetPolicy,
    endpoints: list[Endpoint],
    db: Session,
    scan: Scan,
    cancel_check: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    requirements = {
        "bola": ("attacker_token", "victim_id", "endpoint_path"),
        "bfla": ("regular_user_token", "admin_endpoint_path"),
        "bopla": ("attacker_token", "victim_id", "read_path", "write_path"),
        "broken_auth": ("valid_token", "endpoint_path"),
        "jwt_analyzer": ("username", "password", "auth_path", "protected_path"),
        "misconfiguration": (),
    }
    missing = _missing(config, requirements[name])
    if missing:
        return _outcome(name, "skipped", reason=f"missing prerequisites: {', '.join(missing)}")

    if name == "misconfiguration":
        paths = list(
            dict.fromkeys(
            [config["endpoint_path"]]
            if config.get("endpoint_path")
            else [e.path for e in endpoints]
            )
        )
        if not paths:
            return _outcome(name, "skipped", reason="endpoint inventory is empty")
        finding_count = 0
        vulnerable = False
        last_result: DetectorResult | None = None
        for path in paths:
            if cancel_check is not None and cancel_check():
                raise ScanCancelled
            operation_error = _missing_operation(endpoints, str(path), ("GET", "POST"))
            if operation_error:
                return _outcome(name, "skipped", reason=operation_error)
            endpoint = _find_endpoint(endpoints, str(path), "GET")
            assert endpoint is not None
            if config.get("graphql_path"):
                graphql_error = _missing_operation(
                    endpoints, str(config["graphql_path"]), ("POST",)
                )
                if graphql_error:
                    return _outcome(name, "skipped", reason=graphql_error)
            result = MisconfigurationDetector().run(
                base_url,
                policy,
                probe_path=endpoint.path,
                graphql_path=config.get("graphql_path"),
            )
            finding_count += _persist_result(db, scan, endpoint, result)
            vulnerable = vulnerable or result.vulnerable
            last_result = result
        outcome = _outcome(name, "executed", result=last_result, findings=finding_count)
        outcome["vulnerable"] = vulnerable
        return outcome

    if name == "bola":
        endpoint = _find_endpoint(endpoints, str(config["endpoint_path"]), "GET")
        if endpoint is None:
            return _outcome(
                name,
                "skipped",
                reason="configured endpoint with method GET is not in the API inventory",
            )
        result = BolaDetector().run(
            base_url,
            policy,
            attacker_token=str(config["attacker_token"]),
            victim_id=str(config["victim_id"]),
            endpoint_path=endpoint.path,
            victim_id_field=str(config.get("victim_id_field", "id")),
        )
    elif name == "bfla":
        endpoint = _find_endpoint(endpoints, str(config["admin_endpoint_path"]), "GET")
        if endpoint is None:
            return _outcome(
                name,
                "skipped",
                reason="configured endpoint with method GET is not in the API inventory",
            )
        result = BflaDetector().run(
            base_url,
            policy,
            regular_user_token=str(config["regular_user_token"]),
            admin_endpoint_path=endpoint.path,
        )
    elif name == "bopla":
        endpoint = _find_endpoint(endpoints, str(config["read_path"]), "GET")
        write_endpoint = _find_endpoint(endpoints, str(config["write_path"]), "PATCH")
        if endpoint is None or write_endpoint is None:
            return _outcome(
                name,
                "skipped",
                reason="configured BOPLA read(GET) or write(PATCH) endpoint is missing",
            )
        result = BoplaDetector().run(
            base_url,
            policy,
            attacker_token=str(config["attacker_token"]),
            victim_id=str(config["victim_id"]),
            read_path=str(config["read_path"]),
            write_path=str(config["write_path"]),
        )
        read_evidence = [
            item for item in result.evidence if item.context.get("probe") == "read"
        ]
        write_evidence = [
            item for item in result.evidence if item.context.get("probe") == "write_escalation"
        ]
        read_vulnerable = any(
            item.context.get("sensitive_fields_exposed") for item in read_evidence
        )
        write_vulnerable = any(
            item.context.get("escalation_succeeded") for item in write_evidence
        )
        finding_count = _persist_result(
            db,
            scan,
            endpoint,
            result,
            evidence=read_evidence,
            vulnerable=read_vulnerable,
        )
        finding_count += _persist_result(
            db,
            scan,
            write_endpoint,
            result,
            evidence=write_evidence,
            vulnerable=write_vulnerable,
        )
        return _outcome(name, "executed", result=result, findings=finding_count)
    elif name == "broken_auth":
        endpoint = _find_endpoint(endpoints, str(config["endpoint_path"]), "GET")
        if endpoint is None:
            return _outcome(
                name,
                "skipped",
                reason="configured endpoint with method GET is not in the API inventory",
            )
        result = BrokenAuthDetector().run(
            base_url,
            policy,
            endpoint_path=endpoint.path,
            valid_token=str(config["valid_token"]),
            path_param=str(config.get("path_param", "")),
        )
    else:
        endpoint = _find_endpoint(endpoints, str(config["protected_path"]), "GET")
        if endpoint is None:
            return _outcome(
                name,
                "skipped",
                reason="configured protected endpoint with method GET is not in the API inventory",
            )
        auth_error = _missing_operation(endpoints, str(config["auth_path"]), ("POST",))
        if auth_error:
            return _outcome(name, "skipped", reason=auth_error)
        result = JwtAnalyzer().run(
            base_url,
            policy,
            auth_path=str(config["auth_path"]),
            login_payload={
                "username": str(config["username"]),
                "password": str(config["password"]),
            },
            protected_path=endpoint.path,
            protected_path_param=str(config.get("protected_path_param", "")),
        )

    return _outcome(
        name,
        "executed",
        result=result,
        findings=_persist_result(db, scan, endpoint, result),
    )


def _claim_scan(db: Session, scan_id: int) -> Scan | None:
    result = _execute_claim_update(
        db,
        update(Scan)
        .where(Scan.id == scan_id, Scan.status == "pending")
        .values(status="running", started_at=datetime.now(UTC))
    )
    if result.rowcount != 1:
        db.rollback()
        return None
    scan = db.scalar(
        select(Scan)
        .where(Scan.id == scan_id)
        .execution_options(populate_existing=True)
    )
    if scan is None:
        db.rollback()
        return None
    _record_history(db, scan, "started")
    db.commit()
    return scan


def _finalize_scan(
    db: Session, scan_id: int, status: str, error_summary: str | None = None
) -> bool:
    result = db.execute(
        update(Scan)
        .where(Scan.id == scan_id, Scan.status == "running")
        .values(
            status=status,
            completed_at=datetime.now(UTC),
            error_summary=error_summary,
        )
    )
    if result.rowcount != 1:
        db.rollback()
        return False
    scan = db.scalar(
        select(Scan)
        .where(Scan.id == scan_id)
        .execution_options(populate_existing=True)
    )
    if scan is None:
        db.rollback()
        return False
    _record_history(db, scan, status)
    db.commit()
    return True


def run_scan(scan_id: int) -> None:
    """Execute one scan using a worker-owned session."""

    runtime_config = _take_runtime_config(scan_id)
    settings = get_settings()
    session_factory = get_session_factory(settings.database_url)
    with session_factory() as db:
        try:
            with _execution_lock:
                scan = _claim_scan(db, scan_id)
            if scan is None:
                return
            api = db.get(Api, scan.api_id)
            if api is None or not api.base_url:
                raise TargetNotAllowed("registered API has no base URL")
            base_url = validate_controlled_target(api.base_url, _policy())
            policy = _policy()
            endpoints = list(
                db.scalars(select(Endpoint).where(Endpoint.api_id == api.id).order_by(Endpoint.id))
            )
            detector_names = (scan.configuration or {}).get("detectors", ["misconfiguration"])
            detector_failed = False
            detector_error_summary: str | None = None
            for detector_name in detector_names:
                if _is_cancelled(db, scan.id):
                    return
                config = runtime_config.get(detector_name, {})
                try:
                    result = _execute_detector(
                        detector_name,
                        config,
                        base_url,
                        policy,
                        endpoints,
                        db,
                        scan,
                        cancel_check=lambda: _is_cancelled(db, scan.id),
                    )
                except ScanCancelled:
                    return
                except Exception as exc:  # noqa: BLE001 - report detector-level failure
                    detector_failed = True
                    detector_error_summary = f"scan execution failed ({type(exc).__name__})"
                    result = _outcome(
                        detector_name,
                        "failed",
                        reason=f"detector execution failed ({type(exc).__name__})",
                    )
                scan.detector_results = [*(scan.detector_results or []), result]
                db.commit()
            if not _is_cancelled(db, scan.id) and detector_failed:
                _finalize_scan(
                    db,
                    scan.id,
                    "failed",
                    detector_error_summary or "one or more detectors failed",
                )
            elif not _is_cancelled(db, scan.id):
                _finalize_scan(db, scan.id, "completed")
        except Exception as exc:  # noqa: BLE001 - worker must persist failure state
            db.rollback()
            current_status = db.scalar(select(Scan.status).where(Scan.id == scan_id))
            if current_status == "running":
                _finalize_scan(db, scan_id, "failed", _safe_error_summary(exc))
        finally:
            with _execution_lock:
                _runtime_configs.pop(scan_id, None)
                _active.pop(scan_id, None)


def submit_scan(scan_id: int) -> bool:
    """Submit a scan once; return false if it is already being executed."""

    with _execution_lock:
        current = _active.get(scan_id)
        if current is not None and not current.done():
            return False
        try:
            future = _executor.submit(run_scan, scan_id)
        except BaseException:
            _runtime_configs.pop(scan_id, None)
            raise
        _active[scan_id] = future
        return True


def cancel_scan(db: Session, scan_id: int) -> Scan | None:
    """Cooperatively cancel a pending or running scan."""

    with _execution_lock:
        scan = db.get(Scan, scan_id)
        if scan is None:
            return None
        if scan.status == "pending":
            _runtime_configs.pop(scan_id, None)
        if scan.status in {"completed", "failed", "cancelled"}:
            return scan
        scan.status = "cancelled"
        scan.completed_at = datetime.now(UTC)
        _record_history(db, scan, "cancelled")
        db.commit()
        return scan
