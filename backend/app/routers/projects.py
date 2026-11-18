from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Organization, Project, User
from app.routers.schemas import (
    ProjectCreate,
    ProjectListResponse,
    ProjectRead,
    ProjectUpdate,
)

router = APIRouter(prefix="/projects", tags=["projects"])
DbSession = Annotated[Session, Depends(get_db)]


def _get_project(db: Session, project_id: int) -> Project:
    project = db.get(Project, project_id)
    if project is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="project not found")
    return project


def _validate_project_links(db: Session, owner_id: int, org_id: int | None) -> None:
    if db.get(User, owner_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="owner not found")
    if org_id is not None and db.get(Organization, org_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="organization not found")


@router.post("", response_model=ProjectRead, status_code=status.HTTP_201_CREATED)
def create_project(payload: ProjectCreate, db: DbSession) -> Project:
    _validate_project_links(db, payload.owner_id, payload.org_id)
    project = Project(**payload.model_dump())
    db.add(project)
    db.commit()
    db.refresh(project)
    return project


@router.get("", response_model=ProjectListResponse)
def list_projects(
    db: DbSession,
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> ProjectListResponse:
    total = db.scalar(select(func.count()).select_from(Project)) or 0
    items = list(
        db.scalars(
            select(Project).order_by(Project.id).offset(offset).limit(limit)
        ).all()
    )
    return ProjectListResponse(items=items, total=total, limit=limit, offset=offset)


@router.get("/{project_id}", response_model=ProjectRead)
def get_project(project_id: int, db: DbSession) -> Project:
    return _get_project(db, project_id)


@router.patch("/{project_id}", response_model=ProjectRead)
def update_project(
    project_id: int, payload: ProjectUpdate, db: DbSession
) -> Project:
    project = _get_project(db, project_id)
    changes = payload.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="at least one project field is required",
        )
    if "org_id" in changes and changes["org_id"] is not None:
        if db.get(Organization, changes["org_id"]) is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="organization not found"
            )
    for field, value in changes.items():
        setattr(project, field, value)
    db.commit()
    db.refresh(project)
    return project


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_project(project_id: int, db: DbSession) -> None:
    project = _get_project(db, project_id)
    db.delete(project)
    db.commit()
