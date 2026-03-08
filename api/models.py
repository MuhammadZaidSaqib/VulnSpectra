"""SQLAlchemy models for VulnSpectra scan data."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from .database import Base


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String(64), primary_key=True, index=True)
    target = Column(String(255), nullable=False)
    ports = Column(String(64), nullable=False, default="1-1000")
    timeout = Column(Integer, nullable=False, default=2)

    status = Column(String(32), nullable=False, default="queued", index=True)
    progress = Column(Float, nullable=False, default=0.0)
    error_message = Column(Text, nullable=True)

    started_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    total_hosts_scanned = Column(Integer, nullable=False, default=0)
    alive_hosts = Column(Integer, nullable=False, default=0)
    total_services = Column(Integer, nullable=False, default=0)
    total_vulnerabilities = Column(Integer, nullable=False, default=0)

    risk_score = Column(Float, nullable=False, default=0.0)
    average_cvss = Column(Float, nullable=False, default=0.0)
    max_cvss = Column(Float, nullable=False, default=0.0)

    hosts = relationship("Host", back_populates="scan", cascade="all, delete-orphan")
    services = relationship("Service", back_populates="scan", cascade="all, delete-orphan")
    vulnerabilities = relationship(
        "Vulnerability", back_populates="scan", cascade="all, delete-orphan"
    )
    result = relationship(
        "ScanResult", back_populates="scan", uselist=False, cascade="all, delete-orphan"
    )


class Host(Base):
    __tablename__ = "hosts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(64), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)

    ip = Column(String(64), nullable=False, index=True)
    hostname = Column(String(255), nullable=True)
    status = Column(String(32), nullable=False, default="unknown")
    is_alive = Column(Boolean, nullable=False, default=False)
    scan_timestamp = Column(Float, nullable=True)
    raw_data = Column(Text, nullable=True)

    scan = relationship("Scan", back_populates="hosts")
    services = relationship("Service", back_populates="host")
    vulnerabilities = relationship("Vulnerability", back_populates="host")


class Service(Base):
    __tablename__ = "services"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(64), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    host_id = Column(Integer, ForeignKey("hosts.id", ondelete="SET NULL"), nullable=True)

    ip = Column(String(64), nullable=False, index=True)
    port = Column(Integer, nullable=False, index=True)
    state = Column(String(32), nullable=False, default="open")
    service = Column(String(64), nullable=True)
    product = Column(String(255), nullable=True)
    version = Column(String(255), nullable=True)
    banner = Column(Text, nullable=True)
    raw_data = Column(Text, nullable=True)

    scan = relationship("Scan", back_populates="services")
    host = relationship("Host", back_populates="services")
    vulnerabilities = relationship("Vulnerability", back_populates="service_ref")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(64), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    host_id = Column(Integer, ForeignKey("hosts.id", ondelete="SET NULL"), nullable=True)
    service_id = Column(Integer, ForeignKey("services.id", ondelete="SET NULL"), nullable=True)

    ip = Column(String(64), nullable=True)
    port = Column(Integer, nullable=True)
    service = Column(String(64), nullable=True)
    product = Column(String(255), nullable=True)
    version = Column(String(255), nullable=True)

    cve_id = Column(String(64), nullable=False, index=True)
    description = Column(Text, nullable=True)
    severity = Column(String(32), nullable=True, index=True)
    cvss_score = Column(Float, nullable=True)
    published_date = Column(String(64), nullable=True)
    references_json = Column(Text, nullable=True)
    raw_data = Column(Text, nullable=True)

    scan = relationship("Scan", back_populates="vulnerabilities")
    host = relationship("Host", back_populates="vulnerabilities")
    service_ref = relationship("Service", back_populates="vulnerabilities")


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(
        String(64),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )

    summary_json = Column(Text, nullable=False)
    risk_analysis_json = Column(Text, nullable=False)
    severity_breakdown_json = Column(Text, nullable=False)
    completed_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="result")
