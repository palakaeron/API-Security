"""Pydantic request and response schemas for project/API management."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Literal

from pydantic import (
    AnyHttpUrl,
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    field_validator,
    model_validator,
)

DetectorName = Literal[
    "bola",
    "bfla",
    "bopla",
    "broken_auth",
    "jwt_analyzer",
    "misconfiguration",
]
_SAFE_PATH_PARAMETER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._~-]{0,199}\Z")
_EMAIL = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def _validate_path(value: str | None) -> str | None:
    if value is not None and (not value.startswith("/") or value.startswith("//")):
        raise ValueError("detector paths must be relative paths beginning with a single '/'")
    return value


def _validate_path_parameter(value: str | None) -> str | None:
    if value in (None, ""):
        return value
    if _SAFE_PATH_PARAMETER.fullmatch(value) is None:
        raise ValueError("path parameters must contain only safe identifier characters")
    return value


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


class UserRegister(BaseModel):
    model_config = ConfigDict(hide_input_in_errors=True)

    email: str = Field(min_length=3, max_length=320)
    password: SecretStr = Field(min_length=12, max_length=128)

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        normalized = value.strip().lower()
        if _EMAIL.fullmatch(normalized) is None:
            raise ValueError("email must be a valid email address")
        return normalized


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: str
    role: str
    created_at: datetime
    updated_at: datetime


class UserLogin(BaseModel):
    model_config = ConfigDict(hide_input_in_errors=True)

    email: str = Field(min_length=3, max_length=320)
    password: SecretStr = Field(min_length=1, max_length=128)

    @field_validator("email")
    @classmethod
    def normalize_login_email(cls, value: str) -> str:
        normalized = value.strip().lower()
        if _EMAIL.fullmatch(normalized) is None:
            raise ValueError("email must be a valid email address")
        return normalized


class AccessTokenRead(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_in: int


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
    detectors: list[DetectorName] = Field(
        default_factory=lambda: ["misconfiguration"], min_length=1
    )
    detector_config: dict[DetectorName, DetectorConfig] = Field(default_factory=dict)

    @field_validator("detectors")
    @classmethod
    def unique_detectors(cls, value: list[DetectorName]) -> list[DetectorName]:
        if len(value) != len(set(value)):
            raise ValueError("detectors must not contain duplicates")
        return value

    @model_validator(mode="after")
    def validate_detector_config(self) -> ScanCreate:
        configured = set(self.detector_config)
        requested = set(self.detectors)
        if configured - requested:
            raise ValueError("detector_config may only configure requested detectors")
        for detector in requested - {"misconfiguration"}:
            if detector not in configured:
                raise ValueError(f"detector '{detector}' requires detector_config")
        return self

    def runtime_config(self) -> dict[str, dict[str, object]]:
        result: dict[str, dict[str, object]] = {}
        for detector, config in self.detector_config.items():
            values = config.model_dump()
            for field in (
                "attacker_token",
                "regular_user_token",
                "valid_token",
                "username",
                "password",
            ):
                secret = values.get(field)
                if isinstance(secret, SecretStr):
                    values[field] = secret.get_secret_value()
            result[detector] = values
        return result


class DetectorConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    endpoint_path: str | None = None
    admin_endpoint_path: str | None = None
    read_path: str | None = None
    write_path: str | None = None
    auth_path: str | None = None
    protected_path: str | None = None
    protected_path_param: str = ""
    path_param: str = ""
    victim_id: str | None = Field(default=None, min_length=1, max_length=200)
    victim_id_field: str = Field(default="id", min_length=1, max_length=100)
    attacker_token: SecretStr | None = Field(default=None, min_length=1)
    regular_user_token: SecretStr | None = Field(default=None, min_length=1)
    valid_token: SecretStr | None = Field(default=None, min_length=1)
    username: str | None = Field(default=None, min_length=1, max_length=200)
    password: SecretStr | None = Field(default=None, min_length=1)
    graphql_path: str | None = None

    @field_validator(
        "endpoint_path",
        "admin_endpoint_path",
        "read_path",
        "write_path",
        "auth_path",
        "protected_path",
        "graphql_path",
    )
    @classmethod
    def validate_paths(cls, value: str | None) -> str | None:
        return _validate_path(value)

    @field_validator("victim_id", "path_param", "protected_path_param")
    @classmethod
    def validate_path_parameters(cls, value: str | None) -> str | None:
        return _validate_path_parameter(value)


ScanCreate.model_rebuild()


class ScanRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    api_id: int
    status: Literal["pending", "running", "completed", "failed", "cancelled"]
    configuration: dict
    started_at: datetime | None
    completed_at: datetime | None
    error_summary: str | None
    detector_results: list[dict]
    score: float | None
    scoring_version: str | None
    assessment_status: Literal["complete", "incomplete"] | None
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


class FindingEndpointRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    api_id: int
    path: str
    method: str


class EvidenceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    finding_id: int
    request: dict
    response: dict
    context: dict
    timestamp: datetime


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    scan_id: int
    endpoint_id: int | None
    endpoint: FindingEndpointRead | None
    category: str
    issue_code: str | None
    severity: str
    confidence: float
    impact: float | None
    exploitability: float | None
    risk_score: float | None
    risk_severity: str | None
    scoring_version: str | None
    status: str
    created_at: datetime
    evidence: list[EvidenceRead]


class FindingListResponse(BaseModel):
    items: list[FindingRead]
    total: int
    limit: int
    offset: int


class SeverityCounts(BaseModel):
    critical: int
    high: int
    medium: int
    low: int
    informational: int


class ScanSummaryRead(BaseModel):
    scan_id: int
    status: Literal["pending", "running", "completed", "failed", "cancelled"]
    assessment_status: Literal["complete", "incomplete"]
    overall_risk_score: float | None
    scoring_version: str | None
    total_findings: int
    severity_counts: SeverityCounts
    configured_detectors: int
    executed_detectors: int
    skipped_detectors: int
    failed_detectors: int
    inconclusive_detectors: int
    detector_coverage: float
    assessment_complete: bool
    assessment_incomplete: bool


class DiscoveryImportRequest(BaseModel):
    format: Literal["openapi", "postman"]
    content: str = Field(min_length=2)


class DiscoveryImportResponse(BaseModel):
    api_id: int
    imported: int
    source: Literal["spec", "postman"]
