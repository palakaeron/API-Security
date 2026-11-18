from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.database import get_db
from app.discovery.models import ImportValidationError
from app.discovery.parsers import parse_openapi, parse_postman
from app.discovery.persistence import import_endpoints
from app.models import Api, Endpoint, Project
from app.routers.schemas import (
    ApiCreate,
    ApiListResponse,
    ApiRead,
    ApiUpdate,
    DiscoveryImportRequest,
    DiscoveryImportResponse,
    EndpointListResponse,
)

router = APIRouter(tags=["apis"])
DbSession = Annotated[Session, Depends(get_db)]


def _normalise_base_url(value) -> str | None:
    return str(value).rstrip("/") if value is not None else None


def _get_api(db: Session, api_id: int) -> Api:
    api = db.get(Api, api_id)
    if api is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="api not found")
    return api


@router.post(
    "/projects/{project_id}/apis",
    response_model=ApiRead,
    status_code=status.HTTP_201_CREATED,
)
def register_api(
    project_id: int, payload: ApiCreate, db: DbSession
) -> Api:
    if db.get(Project, project_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="project not found")
    values = payload.model_dump()
    values["base_url"] = _normalise_base_url(values.get("base_url"))
    api = Api(project_id=project_id, **values)
    db.add(api)
    db.commit()
    db.refresh(api)
    return api


@router.get("/projects/{project_id}/apis", response_model=ApiListResponse)
def list_project_apis(
    project_id: int,
    db: DbSession,
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> ApiListResponse:
    if db.get(Project, project_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="project not found")
    condition = Api.project_id == project_id
    total = db.scalar(select(func.count()).select_from(Api).where(condition)) or 0
    items = list(
        db.scalars(select(Api).where(condition).order_by(Api.id).offset(offset).limit(limit)).all()
    )
    return ApiListResponse(items=items, total=total, limit=limit, offset=offset)


@router.get("/apis/{api_id}", response_model=ApiRead)
def get_api(api_id: int, db: DbSession) -> Api:
    return _get_api(db, api_id)


@router.patch("/apis/{api_id}", response_model=ApiRead)
def update_api(api_id: int, payload: ApiUpdate, db: DbSession) -> Api:
    api = _get_api(db, api_id)
    changes = payload.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="at least one API field is required",
        )
    if "base_url" in changes:
        changes["base_url"] = _normalise_base_url(changes["base_url"])
    for field, value in changes.items():
        setattr(api, field, value)
    db.commit()
    db.refresh(api)
    return api


@router.delete("/apis/{api_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_api(api_id: int, db: DbSession) -> None:
    api = _get_api(db, api_id)
    db.delete(api)
    db.commit()


@router.get("/apis/{api_id}/endpoints", response_model=EndpointListResponse)
def list_api_endpoints(
    api_id: int,
    db: DbSession,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> EndpointListResponse:
    _get_api(db, api_id)
    condition = Endpoint.api_id == api_id
    total = db.scalar(select(func.count()).select_from(Endpoint).where(condition)) or 0
    items = list(
        db.scalars(
            select(Endpoint).where(condition).order_by(Endpoint.id).offset(offset).limit(limit)
        ).all()
    )
    return EndpointListResponse(items=items, total=total, limit=limit, offset=offset)


@router.post(
    "/apis/{api_id}/discovery/import",
    response_model=DiscoveryImportResponse,
)
def import_api_discovery(
    api_id: int,
    payload: DiscoveryImportRequest,
    db: DbSession,
) -> DiscoveryImportResponse:
    _get_api(db, api_id)
    try:
        endpoints = (
            parse_openapi(payload.content)
            if payload.format == "openapi"
            else parse_postman(payload.content)
        )
    except ImportValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc

    source = "spec" if payload.format == "openapi" else "postman"
    imported = import_endpoints(db.get_bind(), api_id, endpoints, source)
    return DiscoveryImportResponse(api_id=api_id, imported=imported, source=source)
