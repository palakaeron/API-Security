from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.database import get_db
from app.detectors.sanitiser import sanitise_body
from app.models import Api, Endpoint, Finding, Scan, ScanHistory
from app.risk_scoring import aggregate_finding_risk, summarize_detector_coverage
from app.routers.schemas import (
    EvidenceRead,
    FindingEndpointRead,
    FindingListResponse,
    FindingRead,
    ScanCreate,
    ScanHistoryListResponse,
    ScanListResponse,
    ScanRead,
    ScanSummaryRead,
    SeverityCounts,
)
from app.scan_runner import (
    cancel_scan,
    discard_runtime_config,
    register_runtime_config,
    submit_scan,
    validate_scan_inventory,
)

router = APIRouter(tags=["scans"])
DbSession = Annotated[Session, Depends(get_db)]


def _get_scan(db: Session, scan_id: int) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")
    return scan


def _finding_response(finding: Finding) -> FindingRead:
    """Serialize a finding with defense-in-depth evidence sanitisation."""

    endpoint = (
        FindingEndpointRead.model_validate(finding.endpoint)
        if finding.endpoint is not None and finding.endpoint.api_id == finding.scan.api_id
        else None
    )
    evidence = [
        EvidenceRead(
            id=item.id,
            finding_id=item.finding_id,
            request=sanitise_body(item.request),
            response=sanitise_body(item.response),
            context=sanitise_body(item.context),
            timestamp=item.timestamp,
        )
        for item in finding.evidence
    ]
    return FindingRead(
        id=finding.id,
        scan_id=finding.scan_id,
        endpoint_id=finding.endpoint_id if endpoint is not None else None,
        endpoint=endpoint,
        category=finding.category,
        issue_code=finding.issue_code,
        severity=finding.severity,
        confidence=float(finding.confidence),
        impact=float(finding.impact) if finding.impact is not None else None,
        exploitability=(
            float(finding.exploitability) if finding.exploitability is not None else None
        ),
        risk_score=float(finding.risk_score) if finding.risk_score is not None else None,
        risk_severity=finding.risk_severity,
        scoring_version=finding.scoring_version,
        status=finding.status,
        created_at=finding.created_at,
        evidence=evidence,
    )


def _scan_findings(db: Session, scan_id: int) -> list[Finding]:
    return list(
        db.scalars(
            select(Finding)
            .options(
                selectinload(Finding.scan),
                selectinload(Finding.endpoint),
                selectinload(Finding.evidence),
            )
            .where(Finding.scan_id == scan_id)
            .order_by(Finding.id)
        ).all()
    )


def _scan_summary(scan: Scan, findings: list[Finding]) -> ScanSummaryRead:
    configured = scan.configuration.get("detectors", []) if scan.configuration else []
    coverage = summarize_detector_coverage(configured, scan.detector_results or [])
    risk = aggregate_finding_risk(findings)
    scoring_complete = (
        scan.status == "completed"
        and scan.assessment_status == "complete"
        and not coverage.incomplete
        and not risk.has_unscored_findings
        and risk.scoring_versions <= {"1.0"}
        and scan.score is not None
    )
    assessment_complete = scoring_complete
    assessment_status = "complete" if assessment_complete else "incomplete"
    severity_counts = SeverityCounts(**risk.severity_counts)
    return ScanSummaryRead(
        scan_id=scan.id,
        status=scan.status,
        assessment_status=assessment_status,
        overall_risk_score=float(scan.score) if assessment_complete else None,
        scoring_version=scan.scoring_version,
        total_findings=len(findings),
        severity_counts=severity_counts,
        configured_detectors=len(coverage.configured),
        executed_detectors=len(coverage.executed),
        skipped_detectors=len(coverage.skipped),
        failed_detectors=len(coverage.failed),
        inconclusive_detectors=len(coverage.inconclusive),
        detector_coverage=coverage.coverage,
        assessment_complete=assessment_complete,
        assessment_incomplete=not assessment_complete,
    )


@router.post(
    "/apis/{api_id}/scans",
    response_model=ScanRead,
    status_code=status.HTTP_202_ACCEPTED,
)
def create_scan(api_id: int, payload: ScanCreate, db: DbSession) -> Scan:
    if db.get(Api, api_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="api not found")
    endpoints = list(
        db.scalars(select(Endpoint).where(Endpoint.api_id == api_id).order_by(Endpoint.id))
    )
    runtime_config = payload.runtime_config()
    validation_error = validate_scan_inventory(payload.detectors, runtime_config, endpoints)
    if validation_error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=validation_error,
        )
    scan = Scan(api_id=api_id, configuration={"detectors": payload.detectors})
    db.add(scan)
    db.commit()
    db.refresh(scan)
    register_runtime_config(scan.id, runtime_config)
    if not submit_scan(scan.id):
        discard_runtime_config(scan.id)
        scan.status = "failed"
        scan.error_summary = "scan could not be scheduled"
        db.commit()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="scan already running")
    return scan


@router.get("/apis/{api_id}/scans", response_model=ScanListResponse)
def list_scans(
    api_id: int,
    db: DbSession,
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> ScanListResponse:
    if db.get(Api, api_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="api not found")
    condition = Scan.api_id == api_id
    total = db.scalar(select(func.count()).select_from(Scan).where(condition)) or 0
    items = list(
        db.scalars(select(Scan).where(condition).order_by(Scan.id).offset(offset).limit(limit)).all()
    )
    return ScanListResponse(items=items, total=total, limit=limit, offset=offset)


@router.get("/scans/{scan_id}", response_model=ScanRead)
def get_scan(scan_id: int, db: DbSession) -> Scan:
    return _get_scan(db, scan_id)


@router.post("/scans/{scan_id}/cancel", response_model=ScanRead)
def request_cancel(scan_id: int, db: DbSession) -> Scan:
    scan = cancel_scan(db, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")
    return scan


@router.get("/scans/{scan_id}/history", response_model=ScanHistoryListResponse)
def get_scan_history(scan_id: int, db: DbSession) -> ScanHistoryListResponse:
    _get_scan(db, scan_id)
    items = list(
        db.scalars(
            select(ScanHistory)
            .where(ScanHistory.scan_id == scan_id)
            .order_by(ScanHistory.id)
        ).all()
    )
    return ScanHistoryListResponse(items=items)


@router.get("/scans/{scan_id}/findings", response_model=FindingListResponse)
def list_scan_findings(
    scan_id: int,
    db: DbSession,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> FindingListResponse:
    _get_scan(db, scan_id)
    condition = Finding.scan_id == scan_id
    total = db.scalar(select(func.count()).select_from(Finding).where(condition)) or 0
    findings = list(
        db.scalars(
            select(Finding)
            .options(
                selectinload(Finding.scan),
                selectinload(Finding.endpoint),
                selectinload(Finding.evidence),
            )
            .where(condition)
            .order_by(Finding.id)
            .offset(offset)
            .limit(limit)
        ).all()
    )
    return FindingListResponse(
        items=[_finding_response(finding) for finding in findings],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/findings/{finding_id}", response_model=FindingRead)
def get_finding(finding_id: int, db: DbSession) -> FindingRead:
    finding = db.scalar(
        select(Finding)
        .options(
            selectinload(Finding.scan),
            selectinload(Finding.endpoint),
            selectinload(Finding.evidence),
        )
        .where(Finding.id == finding_id)
    )
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding not found")
    return _finding_response(finding)


@router.get("/scans/{scan_id}/summary", response_model=ScanSummaryRead)
def get_scan_summary(scan_id: int, db: DbSession) -> ScanSummaryRead:
    scan = _get_scan(db, scan_id)
    return _scan_summary(scan, _scan_findings(db, scan_id))
