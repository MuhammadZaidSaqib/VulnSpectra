"""
FastAPI Application - REST API for VulnSpectra
"""
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel, Field
from typing import Optional, List
import logging
import uvicorn
import asyncio
from datetime import datetime
import os
import re

from scanner import NetworkScanner, PortScanner, ServiceDetector
from intelligence import CVEFetcher, VulnerabilityMatcher
from reporting import JSONReporter, HTMLReporter
from utils.logger import setup_logger
from utils.validators import validate_target

logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="VulnSpectra API",
    description="Intelligent Network Vulnerability & CVE Analysis Platform API",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global scan storage
active_scans = {}
scan_results = {}


# Pydantic models
class ScanRequest(BaseModel):
    target: str = Field(..., description="Target IP or IP range (CIDR)")
    ports: Optional[str] = Field("1-1000", description="Port range to scan")
    timeout: Optional[int] = Field(2, description="Connection timeout in seconds")


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str


class ScanStatus(BaseModel):
    scan_id: str
    status: str
    progress: float
    started_at: str
    completed_at: Optional[str] = None


@app.get("/")
async def root():
    """API root endpoint"""
    return {
        "name": "VulnSpectra API",
        "version": "1.0.0",
        "status": "running",
        "endpoints": {
            "scan": "/api/scan",
            "status": "/api/scan/{scan_id}/status",
            "results": "/api/scan/{scan_id}/results",
            "reports": "/api/scan/{scan_id}/report"
        }
    }


def _normalize_target(raw_target: str) -> str:
    """Normalize target to host/IP/CIDR only (strip protocol, path, and host port)."""
    target = raw_target.strip()
    target = re.sub(r"^https?://", "", target, flags=re.IGNORECASE)
    target = target.split("/")[0]
    # Strip host:port for common user input, keep plain host for scanner target.
    if ":" in target and not target.startswith("["):
        target = target.split(":")[0]
    return target


@app.post("/api/scan", response_model=ScanResponse)
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Start a new vulnerability scan
    """
    normalized_target = _normalize_target(request.target)
    if not validate_target(normalized_target):
        raise HTTPException(status_code=400, detail=f"Invalid target: {request.target}")

    logger.info(f"Starting scan for target: {normalized_target}")

    # Generate scan ID
    scan_id = f"scan_{datetime.now().strftime('%Y%m%d%H%M%S')}"

    # Store scan info
    active_scans[scan_id] = {
        "status": "running",
        "progress": 0.0,
        "started_at": datetime.now().isoformat(),
        "target": normalized_target,
        "ports": request.ports
    }

    # Start scan in background
    background_tasks.add_task(run_scan, scan_id, normalized_target, request.ports, request.timeout)

    return ScanResponse(
        scan_id=scan_id,
        status="running",
        message="Scan started successfully"
    )


@app.get("/api/scan/{scan_id}/status", response_model=ScanStatus)
async def get_scan_status(scan_id: str):
    """
    Get scan status
    """
    if scan_id not in active_scans:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan_info = active_scans[scan_id]

    return ScanStatus(
        scan_id=scan_id,
        status=scan_info["status"],
        progress=scan_info["progress"],
        started_at=scan_info["started_at"],
        completed_at=scan_info.get("completed_at")
    )


@app.get("/api/scan/{scan_id}/results")
async def get_scan_results(scan_id: str):
    """
    Get scan results
    """
    if scan_id not in scan_results:
        if scan_id in active_scans and active_scans[scan_id]["status"] == "running":
            raise HTTPException(status_code=202, detail="Scan still in progress")
        raise HTTPException(status_code=404, detail="Scan results not found")

    return JSONResponse(content=scan_results[scan_id])


@app.get("/api/scan/{scan_id}/report")
async def download_report(scan_id: str, format: str = "html"):
    """
    Download scan report
    """
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan results not found")

    if format not in ["html", "json"]:
        raise HTTPException(status_code=400, detail="Invalid format. Use 'html' or 'json'")

    # Generate report
    try:
        if format == "html":
            reporter = HTMLReporter(output_dir="reports")
            report_path = reporter.generate_report(scan_results[scan_id], f"{scan_id}.html")
            return FileResponse(report_path, media_type="text/html", filename=f"{scan_id}.html")
        else:
            reporter = JSONReporter(output_dir="reports")
            report_path = reporter.generate_report(scan_results[scan_id], f"{scan_id}.json")
            return FileResponse(report_path, media_type="application/json", filename=f"{scan_id}.json")
    except Exception as e:
        logger.error(f"Error generating report: {str(e)}")
        raise HTTPException(status_code=500, detail="Error generating report")


@app.delete("/api/scan/{scan_id}")
async def delete_scan(scan_id: str):
    """
    Delete scan results
    """
    deleted = False

    if scan_id in active_scans:
        del active_scans[scan_id]
        deleted = True

    if scan_id in scan_results:
        del scan_results[scan_id]
        deleted = True

    if not deleted:
        raise HTTPException(status_code=404, detail="Scan not found")

    return {"message": "Scan deleted successfully"}


@app.get("/api/scans")
async def list_scans():
    """
    List all scans
    """
    scans = []

    for scan_id, info in active_scans.items():
        scans.append({
            "scan_id": scan_id,
            "status": info["status"],
            "target": info["target"],
            "started_at": info["started_at"]
        })

    return {"scans": scans}


async def run_scan(scan_id: str, target: str, ports: str, timeout: int):
    """
    Execute vulnerability scan
    """
    try:
        logger.info(f"Executing scan {scan_id}")

        # Initialize scanners
        net_scanner = NetworkScanner(timeout=timeout)
        port_scanner = PortScanner(timeout=timeout)
        service_detector = ServiceDetector(timeout=timeout)
        cve_fetcher = CVEFetcher()
        vuln_matcher = VulnerabilityMatcher()

        # Update progress frequently
        active_scans[scan_id]["progress"] = 5.0
        await asyncio.sleep(0.1)
        active_scans[scan_id]["progress"] = 10.0

        # 1. Network scan
        logger.info(f"[{scan_id}] Starting network scan")
        if '/' in target:
            hosts = net_scanner.scan_range(target)
        else:
            hosts = [net_scanner.scan_single(target)]

        alive_hosts = [h for h in hosts if h.get('status') == 'up']
        logger.info(f"[{scan_id}] Found {len(alive_hosts)} alive hosts")

        active_scans[scan_id]["progress"] = 20.0
        await asyncio.sleep(0.05)
        active_scans[scan_id]["progress"] = 25.0
        await asyncio.sleep(0.05)
        active_scans[scan_id]["progress"] = 30.0

        # 2. Port scan
        logger.info(f"[{scan_id}] Starting port scan")
        port_list = port_scanner.parse_port_range(ports)

        all_services = []
        progress_step = 25 / (len(alive_hosts) + 1)
        for idx, host in enumerate(alive_hosts):
            ip = host['ip']
            port_results = port_scanner.scan_host(ip, port_list)

            # Service detection
            if port_results['open_ports']:
                services = service_detector.detect_services_bulk([port_results])
                all_services.extend(services)

            # Update progress smoothly
            current_progress = 30.0 + (idx * progress_step)
            active_scans[scan_id]["progress"] = current_progress
            await asyncio.sleep(0.05)

        logger.info(f"[{scan_id}] Detected {len(all_services)} services")

        active_scans[scan_id]["progress"] = 55.0
        await asyncio.sleep(0.05)
        active_scans[scan_id]["progress"] = 60.0

        # 3. CVE lookup
        logger.info(f"[{scan_id}] Fetching CVE data")
        all_cves = []

        # Get unique products
        products = set()
        for service in all_services:
            product = service.get('product', '').lower()
            if product and product != 'unknown':
                products.add(product)

        # Fetch CVEs for each product
        cve_progress_step = 15 / (len(products) + 1)
        for idx, product in enumerate(products):
            cves = cve_fetcher.search_cve_by_product(product)
            all_cves.extend(cves)

            # Update progress
            current_progress = 60.0 + (idx * cve_progress_step)
            active_scans[scan_id]["progress"] = current_progress
            await asyncio.sleep(0.05)

        logger.info(f"[{scan_id}] Found {len(all_cves)} CVEs")

        active_scans[scan_id]["progress"] = 75.0
        await asyncio.sleep(0.05)
        active_scans[scan_id]["progress"] = 80.0

        # 4. Vulnerability matching
        logger.info(f"[{scan_id}] Matching vulnerabilities")
        vulnerabilities = vuln_matcher.match_vulnerabilities(all_services, all_cves)

        logger.info(f"[{scan_id}] Found {len(vulnerabilities)} vulnerability matches")

        active_scans[scan_id]["progress"] = 85.0
        await asyncio.sleep(0.05)
        active_scans[scan_id]["progress"] = 90.0

        # 5. Calculate risk metrics
        risk_analysis = vuln_matcher.calculate_risk_metrics(vulnerabilities)
        severity_breakdown = vuln_matcher.categorize_by_severity(vulnerabilities)

        # Prepare results
        results = {
            "scan_id": scan_id,
            "target": target,
            "summary": {
                "total_hosts_scanned": len(hosts),
                "alive_hosts": len(alive_hosts),
                "total_services": len(all_services),
                "total_vulnerabilities": len(vulnerabilities),
                "severity_breakdown": severity_breakdown
            },
            "hosts": hosts,
            "services": all_services,
            "vulnerabilities": vulnerabilities,
            "risk_analysis": risk_analysis,
            "completed_at": datetime.now().isoformat()
        }

        # Store results
        scan_results[scan_id] = results

        # Update status
        active_scans[scan_id]["status"] = "completed"
        active_scans[scan_id]["progress"] = 95.0
        await asyncio.sleep(0.05)
        active_scans[scan_id]["progress"] = 100.0
        active_scans[scan_id]["completed_at"] = datetime.now().isoformat()

        logger.info(f"[{scan_id}] Scan completed successfully")

    except Exception as e:
        logger.error(f"[{scan_id}] Scan failed: {str(e)}")
        active_scans[scan_id]["status"] = "failed"
        active_scans[scan_id]["error"] = str(e)


def run_api(host: str = "0.0.0.0", port: int = 8000):
    """
    Run the FastAPI application
    """
    logger.info(f"Starting VulnSpectra API on {host}:{port}")
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    setup_logger()
    run_api()

