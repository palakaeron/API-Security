from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Api, Endpoint, Scan, ScanHistory
from app.routers.schemas import (
    ScanCreate,
    ScanHistoryListResponse,
    ScanListResponse,
    ScanRead,
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
