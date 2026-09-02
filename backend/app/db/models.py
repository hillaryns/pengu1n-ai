from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from app.db.database import Base


class ScanRecord(Base):
    __tablename__ = "scans"

    scan_id: Mapped[str] = mapped_column(String, primary_key=True)
    target: Mapped[str] = mapped_column(String, nullable=False)
    profile: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    duration_seconds: Mapped[float] = mapped_column(Float, nullable=False)
    risk_severity: Mapped[str] = mapped_column(String, nullable=False)
    risk_counts: Mapped[dict] = mapped_column(JSON, nullable=False)
    requests_per_second: Mapped[float | None] = mapped_column(Float, nullable=True)
    open_ports: Mapped[list] = mapped_column(JSON, nullable=False, default=list)

    services: Mapped[list["ServiceRecord"]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
    )
    findings: Mapped[list["FindingRecord"]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
    )
    report: Mapped["ReportRecord | None"] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        uselist=False,
    )


class ServiceRecord(Base):
    __tablename__ = "services"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.scan_id"), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    name: Mapped[str] = mapped_column(String, nullable=False)
    version: Mapped[str | None] = mapped_column(String, nullable=True)

    scan: Mapped[ScanRecord] = relationship(back_populates="services")


class FindingRecord(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.scan_id"), nullable=False)
    finding_id: Mapped[str] = mapped_column(String, nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String, nullable=False)
    category: Mapped[str] = mapped_column(String, nullable=False)
    recommendation: Mapped[str] = mapped_column(Text, nullable=False)
    target: Mapped[str | None] = mapped_column(String, nullable=True)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    cve_id: Mapped[str | None] = mapped_column(String, nullable=True)
    confidence: Mapped[str | None] = mapped_column(String, nullable=True)
    references: Mapped[list] = mapped_column(JSON, nullable=False, default=list)

    scan: Mapped[ScanRecord] = relationship(back_populates="findings")


class ReportRecord(Base):
    __tablename__ = "reports"

    report_id: Mapped[str] = mapped_column(String, primary_key=True)
    scan_id: Mapped[str] = mapped_column(
        String,
        ForeignKey("scans.scan_id"),
        nullable=False,
        unique=True,
    )
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    executive_summary: Mapped[str] = mapped_column(Text, nullable=False)
    recommendations: Mapped[list] = mapped_column(JSON, nullable=False)

    scan: Mapped[ScanRecord] = relationship(back_populates="report")
