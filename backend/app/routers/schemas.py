"""Pydantic request and response schemas for project/API management."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import AnyHttpUrl, BaseModel, ConfigDict, Field, field_validator


def _validate_base_url(value: AnyHttpUrl | None) -> AnyHttpUrl | None:
    if value is None:
        return None
    if value.scheme not in {"http", "https"}:
        raise ValueError("base_url must use http or https")
    if value.username is not None or value.password is not None:
        raise ValueError("base_url must not contain credentials")
    return value


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    owner_id: int = Field(gt=0)
    org_id: int | None = Field(default=None, gt=0)


class ProjectUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    org_id: int | None = Field(default=None, gt=0)


class ProjectRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    owner_id: int
    org_id: int | None
    created_at: datetime


class ProjectListResponse(BaseModel):
    items: list[ProjectRead]
    total: int
    limit: int
    offset: int


class ApiCreate(BaseModel):
    model_config = ConfigDict(hide_input_in_errors=True)

    name: str = Field(min_length=1, max_length=200)
    version: str | None = Field(default=None, max_length=64)
    base_url: AnyHttpUrl | None = None
    description: str | None = Field(default=None, max_length=10_000)
    environment: str | None = Field(default=None, max_length=64)
    spec_location: str | None = Field(default=None, max_length=500)

    @field_validator("base_url")
    @classmethod
    def validate_base_url_scheme(cls, value: AnyHttpUrl | None) -> AnyHttpUrl | None:
        return _validate_base_url(value)


class ApiUpdate(BaseModel):
    model_config = ConfigDict(hide_input_in_errors=True)

    name: str | None = Field(default=None, min_length=1, max_length=200)
    version: str | None = Field(default=None, max_length=64)
    base_url: AnyHttpUrl | None = None
    description: str | None = Field(default=None, max_length=10_000)
    environment: str | None = Field(default=None, max_length=64)
    spec_location: str | None = Field(default=None, max_length=500)

    @field_validator("base_url")
    @classmethod
    def validate_base_url_scheme(cls, value: AnyHttpUrl | None) -> AnyHttpUrl | None:
        return _validate_base_url(value)


class ApiRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    project_id: int
    name: str
    version: str | None
    base_url: str | None
    description: str | None
    environment: str | None
    spec_location: str | None
    created_at: datetime


class ApiListResponse(BaseModel):
    items: list[ApiRead]
    total: int
    limit: int
    offset: int


class EndpointRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    api_id: int
    path: str
    method: str
    auth_scheme: str | None
    source: str
    parameters: list[dict] | None
    request_schema: dict | None
    response_schemas: dict | None
    deprecated: bool
    seen_in_traffic: bool
    created_at: datetime


class EndpointListResponse(BaseModel):
    items: list[EndpointRead]
    total: int
    limit: int
    offset: int


class ScanCreate(BaseModel):
    detectors: list[Literal["misconfiguration"]] = Field(
        default_factory=lambda: ["misconfiguration"], min_length=1
    )


class ScanRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    api_id: int
    status: Literal["pending", "running", "completed", "failed", "cancelled"]
    configuration: dict
    started_at: datetime | None
    completed_at: datetime | None
    error_summary: str | None
    created_at: datetime


class ScanListResponse(BaseModel):
    items: list[ScanRead]
    total: int
    limit: int
    offset: int


class ScanHistoryRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    scan_id: int | None
    api_id: int
    status: str
    event: str
    previous_score: float | None
    current_score: float | None
    delta: float | None
    created_at: datetime


class ScanHistoryListResponse(BaseModel):
    items: list[ScanHistoryRead]


class DiscoveryImportRequest(BaseModel):
    format: Literal["openapi", "postman"]
    content: str = Field(min_length=2)


class DiscoveryImportResponse(BaseModel):
    api_id: int
    imported: int
    source: Literal["spec", "postman"]
