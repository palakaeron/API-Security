"""SQLAlchemy models for the API security platform."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import (
    JSON,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint("role IN ('viewer', 'analyst', 'admin')", name="ck_users_role"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False, server_default="viewer")
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.current_timestamp()
    )

    owned_projects: Mapped[list[Project]] = relationship(back_populates="owner")


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    plan: Mapped[str] = mapped_column(String(32), nullable=False, server_default="local")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.current_timestamp()
    )

    projects: Mapped[list[Project]] = relationship(back_populates="organization")


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    owner_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    org_id: Mapped[int | None] = mapped_column(
        ForeignKey("organizations.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.current_timestamp()
    )

    owner: Mapped[User] = relationship(back_populates="owned_projects")
    organization: Mapped[Organization | None] = relationship(back_populates="projects")
    apis: Mapped[list[Api]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )


class Api(Base):
    __tablename__ = "apis"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    version: Mapped[str | None] = mapped_column(String(64))
    spec_location: Mapped[str | None] = mapped_column(String(500))
    base_url: Mapped[str | None] = mapped_column(String(2048))
    description: Mapped[str | None] = mapped_column(Text)
    environment: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.current_timestamp()
    )

    project: Mapped[Project] = relationship(back_populates="apis")
    endpoints: Mapped[list[Endpoint]] = relationship(
        back_populates="api", cascade="all, delete-orphan"
    )
    scans: Mapped[list[Scan]] = relationship(back_populates="api", cascade="all, delete-orphan")
    scan_history: Mapped[list[ScanHistory]] = relationship(
        back_populates="api", cascade="all, delete-orphan"
    )


class Endpoint(Base):
    __tablename__ = "endpoints"
    __table_args__ = (
        CheckConstraint("source IN ('spec', 'postman', 'traffic')", name="ck_endpoints_source"),
        UniqueConstraint("api_id", "path", "method", name="uq_endpoints_api_path_method"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    api_id: Mapped[int] = mapped_column(ForeignKey("apis.id", ondelete="CASCADE"), nullable=False)
    path: Mapped[str] = mapped_column(String(2048), nullable=False)
    method: Mapped[str] = mapped_column(String(10), nullable=False)
    auth_scheme: Mapped[str | None] = mapped_column(String(100))
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.current_timestamp()
    )
    parameters: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON)
    request_schema: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    response_schemas: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    deprecated: Mapped[bool] = mapped_column(nullable=False, server_default="0")
    seen_in_traffic: Mapped[bool] = mapped_column(nullable=False, server_default="0")

    api: Mapped[Api] = relationship(back_populates="endpoints")
    findings: Mapped[list[Finding]] = relationship(back_populates="endpoint")


class Scan(Base):
    __tablename__ = "scans"
    __table_args__ = (
        Index("ix_scans_api_id_started_at", "api_id", "started_at"),
        CheckConstraint(
            "status IN ('pending', 'running', 'completed', 'failed', 'cancelled')",
            name="ck_scans_status",
        ),
        CheckConstraint("score IS NULL OR (score >= 0 AND score <= 100)", name="ck_scans_score"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    api_id: Mapped[int] = mapped_column(ForeignKey("apis.id", ondelete="CASCADE"), nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(32), nullable=False, server_default="pending")
    score: Mapped[Decimal | None] = mapped_column(Numeric(5, 2))
    job_id: Mapped[str | None] = mapped_column(String(255))
    configuration: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_summary: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.current_timestamp()
    )

    api: Mapped[Api] = relationship(back_populates="scans")
    findings: Mapped[list[Finding]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        Index("ix_findings_scan_id", "scan_id"),
        Index("ix_findings_severity_status", "severity", "status"),
        CheckConstraint(
            "severity IN ('info', 'low', 'medium', 'high', 'critical')",
            name="ck_findings_severity",
        ),
        CheckConstraint("confidence >= 0 AND confidence <= 100", name="ck_findings_confidence"),
        CheckConstraint(
            "risk_score IS NULL OR (risk_score >= 0 AND risk_score <= 100)",
            name="ck_findings_risk_score",
        ),
        CheckConstraint(
            "status IN ('open', 'confirmed', 'resolved', 'false_positive')",
            name="ck_findings_status",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    endpoint_id: Mapped[int | None] = mapped_column(
        ForeignKey("endpoints.id", ondelete="SET NULL")
    )
    category: Mapped[str] = mapped_column(String(100), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[Decimal] = mapped_column(Numeric(5, 2), nullable=False)
    risk_score: Mapped[Decimal | None] = mapped_column(Numeric(5, 2))
    status: Mapped[str] = mapped_column(String(32), nullable=False, server_default="open")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.current_timestamp()
    )

    scan: Mapped[Scan] = relationship(back_populates="findings")
    endpoint: Mapped[Endpoint | None] = relationship(back_populates="findings")
    evidence: Mapped[list[Evidence]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )
    remediation: Mapped[list[Remediation]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )
    alerts: Mapped[list[Alert]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )


class Evidence(Base):
    __tablename__ = "evidence"
    __table_args__ = (Index("ix_evidence_finding_id", "finding_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_id: Mapped[int] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    request: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    response: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    context: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.current_timestamp()
    )

    finding: Mapped[Finding] = relationship(back_populates="evidence")


class Remediation(Base):
    __tablename__ = "remediation"
    __table_args__ = (
        CheckConstraint(
            "verification_status IN ('pending', 'verified', 'failed')",
            name="ck_remediation_status",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_id: Mapped[int] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    recommendation: Mapped[str] = mapped_column(Text, nullable=False)
    verification_status: Mapped[str] = mapped_column(
        String(32), nullable=False, server_default="pending"
    )

    finding: Mapped[Finding] = relationship(back_populates="remediation")


class ScanHistory(Base):
    __tablename__ = "scan_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    api_id: Mapped[int] = mapped_column(ForeignKey("apis.id", ondelete="CASCADE"), nullable=False)
    scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    previous_score: Mapped[Decimal | None] = mapped_column(Numeric(5, 2))
    current_score: Mapped[Decimal | None] = mapped_column(Numeric(5, 2))
    delta: Mapped[Decimal | None] = mapped_column(Numeric(6, 2))
    status: Mapped[str] = mapped_column(String(32), nullable=False, server_default="pending")
    event: Mapped[str] = mapped_column(String(64), nullable=False, server_default="created")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.current_timestamp()
    )

    api: Mapped[Api] = relationship(back_populates="scan_history")
    scan: Mapped[Scan | None] = relationship()


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_id: Mapped[int] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    channel: Mapped[str] = mapped_column(String(32), nullable=False)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(32), nullable=False, server_default="pending")

    finding: Mapped[Finding] = relationship(back_populates="alerts")
