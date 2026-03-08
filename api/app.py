"""FastAPI application for VulnSpectra."""
from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime
from typing import Dict, List

import uvicorn
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from intelligence import CVEFetcher, VulnerabilityMatcher
from reporting import HTMLReporter, JSONReporter
from scanner import NetworkScanner, PortScanner, ServiceDetector
from utils.logger import setup_logger
from utils.validators import validate_target

from .database import SessionLocal, get_db, init_db
from .models import Host, Scan, ScanResult, Service, Vulnerability
from .schemas import DashboardOverview, ScanRequest, ScanResponse, ScanStatus

logger = logging.getLogger(__name__)

app = FastAPI(
    title="VulnSpectra API",
    description="Intelligent Network Vulnerability and CVE Analysis Platform API",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

dashboard_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "dashboard"))
if os.path.exists(dashboard_path):
    app.mount("/static", StaticFiles(directory=dashboard_path), name="static")


@app.on_event("startup")
def on_startup() -> None:
    init_db()


def _normalize_target(raw_target: str) -> str:
    target = raw_target.strip()
    target = re.sub(r"^https?://", "", target, flags=re.IGNORECASE)

    # Preserve CIDR notation while still trimming URL paths.
    if "/" in target and not re.search(r"/\d{1,2}$", target):
        target = target.split("/")[0]

    if ":" in target and not target.startswith("["):
        target = target.split(":")[0]
    return target


def _scan_to_payload(db: Session, scan: Scan) -> Dict:
    hosts = db.query(Host).filter(Host.scan_id == scan.id).all()
    services = db.query(Service).filter(Service.scan_id == scan.id).all()
    vulnerabilities = (
        db.query(Vulnerability)
        .filter(Vulnerability.scan_id == scan.id)
        .order_by(desc(Vulnerability.cvss_score))
        .all()
    )

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for vuln in vulnerabilities:
        sev = (vuln.severity or "UNKNOWN").upper()
        severity_counts[sev if sev in severity_counts else "UNKNOWN"] += 1

    severity_breakdown = {
        key: {"count": value}
        for key, value in severity_counts.items()
    }

    risk_analysis = {
        "total_vulnerabilities": scan.total_vulnerabilities,
        "average_cvss": scan.average_cvss,
        "max_cvss": scan.max_cvss,
        "risk_score": scan.risk_score,
        "severity_distribution": {
            "critical": severity_counts["CRITICAL"],
            "high": severity_counts["HIGH"],
            "medium": severity_counts["MEDIUM"],
            "low": severity_counts["LOW"],
        },
    }

    return {
        "scan_id": scan.id,
        "target": scan.target,
        "status": scan.status,
        "summary": {
            "total_hosts_scanned": scan.total_hosts_scanned,
            "alive_hosts": scan.alive_hosts,
            "total_services": scan.total_services,
            "total_vulnerabilities": scan.total_vulnerabilities,
            "severity_breakdown": severity_breakdown,
        },
        "hosts": [
            {
                "id": host.id,
                "ip": host.ip,
                "hostname": host.hostname,
                "status": host.status,
                "timestamp": host.scan_timestamp,
            }
            for host in hosts
        ],
        "services": [
            {
                "id": svc.id,
                "ip": svc.ip,
                "port": svc.port,
                "state": svc.state,
                "service": svc.service,
                "product": svc.product,
                "version": svc.version,
                "banner": svc.banner,
            }
            for svc in services
        ],
        "vulnerabilities": [
            {
                "id": vuln.id,
                "ip": vuln.ip,
                "port": vuln.port,
                "service": vuln.service,
                "product": vuln.product,
                "version": vuln.version,
                "cve_id": vuln.cve_id,
                "description": vuln.description,
                "severity": vuln.severity,
                "cvss_score": vuln.cvss_score,
                "published_date": vuln.published_date,
                "references": json.loads(vuln.references_json or "[]"),
            }
            for vuln in vulnerabilities
        ],
        "risk_analysis": risk_analysis,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
    }


def _set_scan_state(
    db: Session,
    scan: Scan,
    *,
    status: str | None = None,
    progress: float | None = None,
    error_message: str | None = None,
) -> None:
    if status is not None:
        scan.status = status
    if progress is not None:
        scan.progress = max(0.0, min(100.0, progress))
    if error_message is not None:
        scan.error_message = error_message
    db.add(scan)
    db.commit()


def run_scan_job(scan_id: str) -> None:
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            logger.error("Scan %s not found for background job", scan_id)
            return

        _set_scan_state(db, scan, status="running", progress=5.0)

        net_scanner = NetworkScanner(timeout=scan.timeout)
        port_scanner = PortScanner(timeout=scan.timeout)
        service_detector = ServiceDetector(timeout=scan.timeout)
        cve_fetcher = CVEFetcher()
        vuln_matcher = VulnerabilityMatcher()

        if "/" in scan.target:
            hosts = net_scanner.scan_range(scan.target)
        else:
            hosts = [net_scanner.scan_single(scan.target)]

        db.query(Host).filter(Host.scan_id == scan.id).delete()
        host_by_ip: Dict[str, Host] = {}
        for host in hosts:
            host_row = Host(
                scan_id=scan.id,
                ip=host.get("ip") or host.get("target") or "unknown",
                hostname=host.get("hostname") or "Unknown",
                status=host.get("status") or "unknown",
                is_alive=(host.get("status") == "up"),
                scan_timestamp=host.get("timestamp"),
                raw_data=json.dumps(host),
            )
            db.add(host_row)
            db.flush()
            host_by_ip[host_row.ip] = host_row
        db.commit()

        alive_hosts = [host for host in hosts if host.get("status") == "up"]
        scan.total_hosts_scanned = len(hosts)
        scan.alive_hosts = len(alive_hosts)
        db.add(scan)
        db.commit()
        _set_scan_state(db, scan, progress=30.0)

        port_list = port_scanner.parse_port_range(scan.ports)
        all_services: List[Dict] = []
        service_by_key: Dict[tuple, Service] = {}

        db.query(Service).filter(Service.scan_id == scan.id).delete()
        db.commit()

        # For single-target scans, still scan requested ports even if discovery says down.
        scan_targets = alive_hosts
        if not scan_targets and "/" not in scan.target:
            fallback_ip = hosts[0].get("ip") if hosts else scan.target
            scan_targets = [{"ip": fallback_ip}]
            logger.info(
                "[%s] Host discovery found 0 alive hosts; using explicit port-scan fallback for %s",
                scan.id,
                fallback_ip,
            )

        progress_step = 25 / max(1, len(scan_targets))
        for idx, host in enumerate(scan_targets):
            ip = host.get("ip")
            if not ip:
                continue

            port_results = port_scanner.scan_host(ip, port_list)
            if port_results.get("open_ports"):
                detected_services = service_detector.detect_services_bulk([port_results])
                all_services.extend(detected_services)
                for service in detected_services:
                    key = (service.get("ip"), service.get("port"))
                    host_ref = host_by_ip.get(service.get("ip", ""))
                    row = Service(
                        scan_id=scan.id,
                        host_id=host_ref.id if host_ref else None,
                        ip=service.get("ip") or "unknown",
                        port=service.get("port") or 0,
                        state="open",
                        service=service.get("service"),
                        product=service.get("product"),
                        version=service.get("version"),
                        banner=service.get("banner"),
                        raw_data=json.dumps(service),
                    )
                    db.add(row)
                    db.flush()
                    service_by_key[key] = row
                db.commit()

            _set_scan_state(db, scan, progress=30.0 + ((idx + 1) * progress_step))

        scan.total_services = len(all_services)
        db.add(scan)
        db.commit()
        _set_scan_state(db, scan, progress=60.0)

        products = {
            (service.get("product") or "").lower()
            for service in all_services
            if service.get("product") and service.get("product") != "Unknown"
        }

        all_cves: List[Dict] = []
        cve_step = 20 / max(1, len(products))
        for idx, product in enumerate(products):
            try:
                cves = cve_fetcher.search_cve_by_product(product)
                if cves:
                    all_cves.extend(cves)
            except Exception as cve_error:  # pragma: no cover - external API resilience
                logger.warning("Error fetching CVEs for %s: %s", product, cve_error)
            _set_scan_state(db, scan, progress=60.0 + ((idx + 1) * cve_step))

        vulnerabilities = vuln_matcher.match_vulnerabilities(all_services, all_cves)
        risk_analysis = vuln_matcher.calculate_risk_metrics(vulnerabilities)
        categorized = vuln_matcher.categorize_by_severity(vulnerabilities)

        db.query(Vulnerability).filter(Vulnerability.scan_id == scan.id).delete()
        db.commit()

        for vuln in vulnerabilities:
            host_ref = host_by_ip.get(vuln.get("ip", ""))
            service_ref = service_by_key.get((vuln.get("ip"), vuln.get("port")))
            vuln_row = Vulnerability(
                scan_id=scan.id,
                host_id=host_ref.id if host_ref else None,
                service_id=service_ref.id if service_ref else None,
                ip=vuln.get("ip"),
                port=vuln.get("port"),
                service=vuln.get("service"),
                product=vuln.get("product"),
                version=vuln.get("version"),
                cve_id=vuln.get("cve_id") or "unknown",
                description=vuln.get("description"),
                severity=vuln.get("severity") or "UNKNOWN",
                cvss_score=vuln.get("cvss_score") or 0.0,
                published_date=vuln.get("published_date"),
                references_json=json.dumps(vuln.get("references", [])),
                raw_data=json.dumps(vuln),
            )
            db.add(vuln_row)
        db.commit()

        summary = {
            "total_hosts_scanned": scan.total_hosts_scanned,
            "alive_hosts": scan.alive_hosts,
            "total_services": scan.total_services,
            "total_vulnerabilities": len(vulnerabilities),
            "severity_breakdown": {
                "CRITICAL": {"count": categorized.get("critical_count", 0)},
                "HIGH": {"count": categorized.get("high_count", 0)},
                "MEDIUM": {"count": categorized.get("medium_count", 0)},
                "LOW": {"count": categorized.get("low_count", 0)},
                "UNKNOWN": {"count": categorized.get("unknown_count", 0)},
            },
        }

        scan.total_vulnerabilities = len(vulnerabilities)
        scan.risk_score = risk_analysis.get("risk_score", 0.0)
        scan.average_cvss = risk_analysis.get("average_cvss", 0.0)
        scan.max_cvss = risk_analysis.get("max_cvss", 0.0)
        scan.status = "completed"
        scan.progress = 100.0
        scan.completed_at = datetime.utcnow()
        scan.error_message = None
        db.add(scan)

        db.query(ScanResult).filter(ScanResult.scan_id == scan.id).delete()
        db.add(
            ScanResult(
                scan_id=scan.id,
                summary_json=json.dumps(summary),
                risk_analysis_json=json.dumps(risk_analysis),
                severity_breakdown_json=json.dumps(summary["severity_breakdown"]),
                completed_at=scan.completed_at,
            )
        )
        db.commit()

        logger.info("Scan completed successfully: %s", scan.id)
    except Exception as scan_error:
        logger.exception("Scan failed for %s: %s", scan_id, scan_error)
        failed_scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if failed_scan:
            failed_scan.status = "failed"
            failed_scan.error_message = str(scan_error)
            failed_scan.progress = max(failed_scan.progress, 0.0)
            failed_scan.completed_at = datetime.utcnow()
            db.add(failed_scan)
            db.commit()
    finally:
        db.close()


@app.get("/")
async def root() -> Dict:
    return {
        "name": "VulnSpectra API",
        "version": "2.0.0",
        "status": "running",
        "endpoints": {
            "health": "/api/health",
            "start_scan": "/api/scans/start",
            "scan_status": "/api/scans/{scan_id}/status",
            "scan_results": "/api/scans/{scan_id}/results",
            "dashboard": "/api/dashboard/overview",
            "ui": "/dashboard",
        },
    }


@app.get("/dashboard")
@app.get("/dashboard/")
async def dashboard_index():
    index_path = os.path.join(dashboard_path, "index.html")
    if not os.path.exists(index_path):
        raise HTTPException(status_code=404, detail="Dashboard index not found")
    return FileResponse(index_path)


@app.get("/api/health")
async def health_check(db: Session = Depends(get_db)) -> Dict:
    active = db.query(func.count(Scan.id)).filter(Scan.status == "running").scalar() or 0
    completed = db.query(func.count(Scan.id)).filter(Scan.status == "completed").scalar() or 0
    return {
        "status": "healthy",
        "version": "2.0.0",
        "timestamp": datetime.utcnow().isoformat(),
        "scans": {"active": active, "completed": completed},
    }


@app.post("/api/scans/start", response_model=ScanResponse)
@app.post("/api/scan", response_model=ScanResponse)
async def start_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    normalized_target = _normalize_target(request.target)
    if not validate_target(normalized_target):
        raise HTTPException(status_code=400, detail=f"Invalid target: {request.target}")

    scan_id = f"scan_{datetime.utcnow().strftime('%Y%m%d%H%M%S_%f')}"
    scan = Scan(
        id=scan_id,
        target=normalized_target,
        ports=request.ports,
        timeout=request.timeout,
        status="queued",
        progress=0.0,
        started_at=datetime.utcnow(),
    )
    db.add(scan)
    db.commit()

    background_tasks.add_task(run_scan_job, scan_id)

    return ScanResponse(scan_id=scan_id, status="queued", message="Scan started successfully")


@app.get("/api/scans/{scan_id}/status", response_model=ScanStatus)
@app.get("/api/scan/{scan_id}/status", response_model=ScanStatus)
async def get_scan_status(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return ScanStatus(
        scan_id=scan.id,
        status=scan.status,
        progress=scan.progress,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        error_message=scan.error_message,
    )


@app.get("/api/scans/{scan_id}/results")
@app.get("/api/scan/{scan_id}/results")
async def get_scan_results(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status in {"queued", "running"}:
        raise HTTPException(status_code=202, detail="Scan still in progress")
    if scan.status == "failed":
        raise HTTPException(status_code=500, detail=scan.error_message or "Scan failed")

    return JSONResponse(content=_scan_to_payload(db, scan))


@app.get("/api/scans")
async def list_scans(limit: int = 50, db: Session = Depends(get_db)):
    scans = db.query(Scan).order_by(desc(Scan.started_at)).limit(max(1, min(limit, 200))).all()
    return {
        "scans": [
            {
                "scan_id": scan.id,
                "target": scan.target,
                "status": scan.status,
                "progress": scan.progress,
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                "total_hosts_scanned": scan.total_hosts_scanned,
                "total_services": scan.total_services,
                "total_vulnerabilities": scan.total_vulnerabilities,
                "risk_score": scan.risk_score,
            }
            for scan in scans
        ]
    }


@app.delete("/api/scans/{scan_id}")
@app.delete("/api/scan/{scan_id}")
async def delete_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    db.delete(scan)
    db.commit()
    return {"message": "Scan deleted successfully"}


@app.get("/api/dashboard/overview", response_model=DashboardOverview)
async def dashboard_overview(db: Session = Depends(get_db)):
    total_scans = db.query(func.count(Scan.id)).scalar() or 0
    active_scans = db.query(func.count(Scan.id)).filter(Scan.status == "running").scalar() or 0
    total_hosts = db.query(func.count(Host.id)).scalar() or 0
    total_services = db.query(func.count(Service.id)).scalar() or 0
    total_vulns = db.query(func.count(Vulnerability.id)).scalar() or 0
    avg_risk = db.query(func.avg(Scan.risk_score)).filter(Scan.status == "completed").scalar() or 0.0

    severity_distribution = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    grouped = db.query(Vulnerability.severity, func.count(Vulnerability.id)).group_by(Vulnerability.severity).all()
    for severity, count in grouped:
        key = (severity or "UNKNOWN").upper()
        severity_distribution[key if key in severity_distribution else "UNKNOWN"] = count

    timeline_scans = (
        db.query(Scan)
        .filter(Scan.status == "completed")
        .order_by(desc(Scan.completed_at))
        .limit(20)
        .all()
    )
    timeline_scans.reverse()

    risk_timeline = [
        {
            "scan_id": scan.id,
            "risk_score": scan.risk_score,
            "label": (scan.completed_at or scan.started_at).strftime("%H:%M")
            if (scan.completed_at or scan.started_at)
            else "n/a",
        }
        for scan in timeline_scans
    ]

    recent_scans = (
        db.query(Scan)
        .order_by(desc(Scan.started_at))
        .limit(10)
        .all()
    )

    recent_vulns = (
        db.query(Vulnerability)
        .order_by(desc(Vulnerability.id))
        .limit(20)
        .all()
    )

    return DashboardOverview(
        totals={
            "total_scans": total_scans,
            "active_scans": active_scans,
            "hosts_scanned": total_hosts,
            "services_detected": total_services,
            "vulnerabilities_found": total_vulns,
            "average_risk_score": round(float(avg_risk), 2),
        },
        severity_distribution=severity_distribution,
        risk_timeline=risk_timeline,
        recent_scans=[
            {
                "scan_id": scan.id,
                "target": scan.target,
                "status": scan.status,
                "progress": scan.progress,
                "risk_score": scan.risk_score,
                "total_services": scan.total_services,
                "total_vulnerabilities": scan.total_vulnerabilities,
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            }
            for scan in recent_scans
        ],
        recent_vulnerabilities=[
            {
                "cve_id": vuln.cve_id,
                "ip": vuln.ip,
                "port": vuln.port,
                "service": vuln.service,
                "severity": vuln.severity,
                "cvss_score": vuln.cvss_score,
                "published_date": vuln.published_date,
            }
            for vuln in recent_vulns
        ],
    )


@app.get("/api/scan/{scan_id}/report")
@app.get("/api/scans/{scan_id}/report")
async def download_report(scan_id: str, format: str = "html", db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if format not in ["html", "json"]:
        raise HTTPException(status_code=400, detail="Invalid format. Use 'html' or 'json'")

    payload = _scan_to_payload(db, scan)
    try:
        if format == "html":
            reporter = HTMLReporter(output_dir="reports")
            report_path = reporter.generate_report(payload, f"{scan_id}.html")
            return FileResponse(report_path, media_type="text/html", filename=f"{scan_id}.html")

        reporter = JSONReporter(output_dir="reports")
        report_path = reporter.generate_report(payload, f"{scan_id}.json")
        return FileResponse(report_path, media_type="application/json", filename=f"{scan_id}.json")
    except Exception as report_error:
        logger.error("Error generating report for %s: %s", scan_id, report_error)
        raise HTTPException(status_code=500, detail="Error generating report")


def run_api(host: str = "0.0.0.0", port: int = 8000):
    logger.info("Starting VulnSpectra API on %s:%s", host, port)
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    setup_logger()
    run_api()

