"""Small, process-local scan executor.

The executor deliberately uses independent database sessions for worker tasks.
It is suitable for the current single-process SQLite deployment; a durable
queue is a later deployment concern.
"""

from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor
from datetime import UTC, datetime
from threading import RLock

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_session_factory
from app.detectors.base import DetectorResult
from app.detectors.http_client import DetectorHTTPError
from app.detectors.misconfiguration import MisconfigurationDetector
from app.detectors.sanitiser import sanitise_body, sanitise_headers
from app.models import Api, Endpoint, Evidence, Finding, Scan, ScanHistory
from app.security.target_allowlist import TargetNotAllowed, TargetPolicy, validate_controlled_target

_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="api-security-scan")
_execution_lock = RLock()
_active: dict[int, Future[None]] = {}


def _policy() -> TargetPolicy:
    settings = get_settings()
    return TargetPolicy.from_strings(
        settings.controlled_target_hosts, settings.controlled_target_cidrs
    )


def _record_history(db: Session, scan: Scan, event: str) -> None:
    db.add(
        ScanHistory(
            api_id=scan.api_id,
            scan_id=scan.id,
            status=scan.status,
            event=event,
        )
    )


def _safe_error_summary(exc: BaseException) -> str:
    if isinstance(exc, TargetNotAllowed):
        return "scan target is not authorized by the controlled target policy"
    if isinstance(exc, DetectorHTTPError):
        return "detector request failed"
    return f"scan execution failed ({type(exc).__name__})"


def _is_cancelled(db: Session, scan_id: int) -> bool:
    current_status = db.scalar(select(Scan.status).where(Scan.id == scan_id))
    return current_status is None or current_status == "cancelled"


def _persist_result(db: Session, scan: Scan, endpoint: Endpoint, result: DetectorResult) -> None:
    if not result.vulnerable:
        return

    existing = db.scalar(
        select(Finding).where(
            Finding.scan_id == scan.id,
            Finding.endpoint_id == endpoint.id,
            Finding.category == result.owasp_category.value,
        )
    )
    finding = existing or Finding(
        scan_id=scan.id,
        endpoint_id=endpoint.id,
        category=result.owasp_category.value,
        severity=result.severity.value,
        confidence=result.confidence,
    )
    if existing is None:
        db.add(finding)
        db.flush()

    if existing is None:
        for item in result.evidence:
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


def _claim_scan(db: Session, scan_id: int) -> Scan | None:
    scan = db.get(Scan, scan_id)
    if scan is None or scan.status != "pending":
        return None
    scan.status = "running"
    scan.started_at = datetime.now(UTC)
    _record_history(db, scan, "started")
    db.commit()
    return scan


def run_scan(scan_id: int) -> None:
    """Execute one scan using a worker-owned session."""

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
            endpoints = list(
                db.scalars(select(Endpoint).where(Endpoint.api_id == api.id).order_by(Endpoint.id))
            )
            detector_names = scan.configuration.get("detectors", ["misconfiguration"])
            for endpoint in endpoints:
                if _is_cancelled(db, scan.id):
                    return
                for detector_name in detector_names:
                    if detector_name == "misconfiguration":
                        result = MisconfigurationDetector().run(
                            base_url, _policy(), probe_path=endpoint.path
                        )
                        _persist_result(db, scan, endpoint, result)
                        db.commit()

            if not _is_cancelled(db, scan.id):
                scan.status = "completed"
                scan.completed_at = datetime.now(UTC)
                _record_history(db, scan, "completed")
                db.commit()
        except Exception as exc:  # noqa: BLE001 - worker must persist failure state
            db.rollback()
            scan = db.get(Scan, scan_id)
            if scan is not None and scan.status != "cancelled":
                scan.status = "failed"
                scan.completed_at = datetime.now(UTC)
                scan.error_summary = _safe_error_summary(exc)
                _record_history(db, scan, "failed")
                db.commit()
        finally:
            with _execution_lock:
                _active.pop(scan_id, None)


def submit_scan(scan_id: int) -> bool:
    """Submit a scan once; return false if it is already being executed."""

    with _execution_lock:
        current = _active.get(scan_id)
        if current is not None and not current.done():
            return False
        future = _executor.submit(run_scan, scan_id)
        _active[scan_id] = future
        return True


def cancel_scan(db: Session, scan_id: int) -> Scan | None:
    """Cooperatively cancel a pending or running scan."""

    with _execution_lock:
        scan = db.get(Scan, scan_id)
        if scan is None:
            return None
        if scan.status in {"completed", "failed", "cancelled"}:
            return scan
        scan.status = "cancelled"
        scan.completed_at = datetime.now(UTC)
        _record_history(db, scan, "cancelled")
        db.commit()
        return scan
