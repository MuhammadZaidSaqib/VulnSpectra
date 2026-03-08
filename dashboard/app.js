const API_BASE = window.location.origin;

let activeScanId = null;
let severityChart = null;
let riskChart = null;
let overviewRequestSeq = 0;
let backendOnline = false;
let latestCompletedScanId = null;
let dashboardRefreshMs = 8000;
let refreshTimerId = null;

function qs(id) {
    return document.getElementById(id);
}

function initClock() {
    const tick = () => {
        const now = new Date();
        qs("live-clock").textContent = now.toLocaleTimeString([], {
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit"
        });
    };
    tick();
    setInterval(tick, 1000);
}

function severityColor(severity) {
    const map = {
        CRITICAL: "#ff3b30",
        HIGH: "#ff8a00",
        MEDIUM: "#ffcc00",
        LOW: "#34c759",
        UNKNOWN: "#7f8fa6"
    };
    return map[(severity || "UNKNOWN").toUpperCase()] || map.UNKNOWN;
}

function initCharts() {
    const severityCtx = qs("severity-chart").getContext("2d");
    severityChart = new Chart(severityCtx, {
        type: "doughnut",
        data: {
            labels: ["No Findings"],
            datasets: [{
                data: [1],
                backgroundColor: ["#64748b"],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: "56%",
            plugins: {
                legend: { labels: { color: "#d7e6ff" } },
                tooltip: { enabled: true }
            }
        }
    });

    const riskCtx = qs("risk-chart").getContext("2d");
    riskChart = new Chart(riskCtx, {
        type: "line",
        data: {
            labels: ["No scans"],
            datasets: [{
                label: "Risk Score",
                data: [0],
                borderColor: "#00d4ff",
                backgroundColor: "rgba(0, 212, 255, 0.18)",
                fill: true,
                tension: 0.3,
                pointRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: { min: 0, max: 100, ticks: { color: "#d7e6ff" } },
                x: { ticks: { color: "#d7e6ff" } }
            },
            plugins: {
                legend: { labels: { color: "#d7e6ff" } }
            }
        }
    });
}

async function fetchJson(path) {
    const res = await fetch(`${API_BASE}${path}`);
    if (!res.ok) {
        const payload = await res.json().catch(() => ({}));
        throw new Error(payload.detail || `Request failed (${res.status})`);
    }
    return res.json();
}

function setProgress(progress, label) {
    const safe = Math.max(0, Math.min(100, Number(progress || 0)));
    qs("scan-progress-wrap").classList.remove("hidden");
    qs("progress-fill").style.width = `${safe}%`;
    qs("progress-value").textContent = `${Math.round(safe)}%`;
    qs("progress-label").textContent = label || "Running scan...";
}

function renderSeverityDistribution(distribution) {
    const d = distribution || {};
    const values = [
        Number(d.CRITICAL || 0),
        Number(d.HIGH || 0),
        Number(d.MEDIUM || 0),
        Number(d.LOW || 0),
        Number(d.UNKNOWN || 0)
    ];
    const total = values.reduce((acc, cur) => acc + cur, 0);

    // Update Risk Matrix severity cards
    if (qs("risk-critical-count")) qs("risk-critical-count").textContent = Number(d.CRITICAL || 0);
    if (qs("risk-high-count")) qs("risk-high-count").textContent = Number(d.HIGH || 0);
    if (qs("risk-medium-count")) qs("risk-medium-count").textContent = Number(d.MEDIUM || 0);
    if (qs("risk-low-count")) qs("risk-low-count").textContent = Number(d.LOW || 0);

    // Update Risk Matrix priority cards
    if (qs("critical-issues-count")) qs("critical-issues-count").textContent = Number(d.CRITICAL || 0);
    if (qs("high-priority-count")) qs("high-priority-count").textContent = Number(d.HIGH || 0);
    if (qs("medium-priority-count")) qs("medium-priority-count").textContent = Number(d.MEDIUM || 0);
    if (qs("low-priority-count")) qs("low-priority-count").textContent = Number(d.LOW || 0);

    if (total === 0) {
        severityChart.data.labels = ["No Findings"];
        severityChart.data.datasets[0].data = [1];
        severityChart.data.datasets[0].backgroundColor = ["#64748b"];
    } else {
        severityChart.data.labels = ["Critical", "High", "Medium", "Low", "Unknown"];
        severityChart.data.datasets[0].data = values;
        severityChart.data.datasets[0].backgroundColor = [
            "#ff453a",
            "#ff9f0a",
            "#ffcc00",
            "#2dd36f",
            "#95abd4"
        ];
    }
    severityChart.update();
}

function renderRiskTimeline(points) {
    const series = Array.isArray(points) ? points : [];
    if (!series.length) {
        riskChart.data.labels = ["No scans"];
        riskChart.data.datasets[0].data = [0];
        riskChart.update();
        return;
    }

    riskChart.data.labels = series.map((p) => p.label || "n/a");
    riskChart.data.datasets[0].data = series.map((p) => Number(p.risk_score || 0));
    riskChart.update();
}

function setSystemStatus(isOnline) {
    backendOnline = isOnline;
    qs("system-status").textContent = isOnline ? "System Online" : "Backend Offline";
}

function showView(view) {
    const summary = qs("summary-panel");
    const scan = qs("scan-panel");
    const charts = qs("charts-panel");
    const tables = qs("tables-panel");
    const vulnerabilities = qs("vulnerabilities-panel");
    const hosts = qs("hosts-panel");
    const services = qs("services-panel");
    const settings = qs("settings-panel");
    const reports = qs("reports-panel");
    const about = qs("about-panel");

    const all = [summary, scan, charts, tables, vulnerabilities, hosts, services, settings, reports, about];
    all.forEach((el) => {
        if (el) el.classList.add("view-hidden");
    });

    const show = (...els) => {
        els.forEach((el) => {
            if (el) el.classList.remove("view-hidden");
        });
    };

    switch (view) {
        case "new-scan":
            show(scan);
            break;
        case "active-scans":
            show(tables);
            break;
        case "vulnerabilities":
            show(vulnerabilities);
            break;
        case "hosts":
            show(hosts);
            break;
        case "services":
            show(services);
            break;
        case "risk-matrix":
            show(charts);
            break;
        case "reports":
            show(reports, tables);
            break;
        case "settings":
            show(settings);
            break;
        case "about":
            show(about);
            break;
        case "dashboard":
        default:
            show(summary, scan, charts, tables);
            break;
    }
}

function initNav() {
    const links = Array.from(document.querySelectorAll('.nav a[data-target]'));
    links.forEach((link) => {
        link.addEventListener("click", (event) => {
            event.preventDefault();
            links.forEach((l) => l.classList.remove("active"));
            link.classList.add("active");

            const view = link.getAttribute("data-view") || "dashboard";
            showView(view);

            const targetId = link.getAttribute("data-target");
            const target = targetId ? document.getElementById(targetId) : null;
            if (target) {
                target.scrollIntoView({ behavior: "smooth", block: "start" });
            }
        });
    });

    showView("dashboard");
}

async function checkBackend() {
    try {
        await fetchJson("/api/health");
        setSystemStatus(true);
    } catch (_) {
        setSystemStatus(false);
    }
}

function downloadReport(scanId, format) {
    const url = `${API_BASE}/api/scans/${encodeURIComponent(scanId)}/report?format=${format}`;
    window.open(url, "_blank", "noopener");
}

function renderScans(scans) {
    const body = qs("scans-table-body");
    if (!Array.isArray(scans) || !scans.length) {
        body.innerHTML = '<tr><td colspan="7">No scans yet</td></tr>';
        return;
    }

    latestCompletedScanId = null;

    body.innerHTML = scans
        .map((scan) => {
            const shortId = scan.scan_id.length > 18 ? `${scan.scan_id.slice(0, 18)}...` : scan.scan_id;
            const sev = (scan.status || "unknown").toLowerCase();
            const services = Number(scan.total_services || 0);
            const vulns = Number(scan.total_vulnerabilities || 0);
            const risk = Number(scan.risk_score || 0).toFixed(1);
            const canDownload = (scan.status || "").toLowerCase() === "completed";
            if (!latestCompletedScanId && canDownload) {
                latestCompletedScanId = scan.scan_id;
            }
            const disabled = canDownload ? "" : "disabled";

            return `
                <tr>
                    <td title="${scan.scan_id}">${shortId}</td>
                    <td>${scan.target || "-"}</td>
                    <td><span class="badge ${sev}">${scan.status || "unknown"}</span></td>
                    <td>${services}</td>
                    <td>${vulns}</td>
                    <td>${risk}</td>
                    <td class="scan-actions">
                        <button class="report-btn" ${disabled} onclick="downloadReport('${scan.scan_id}', 'html')">HTML</button>
                        <button class="report-btn" ${disabled} onclick="downloadReport('${scan.scan_id}', 'json')">JSON</button>
                    </td>
                </tr>
            `;
        })
        .join("");
}

function renderVulnerabilities(vulns) {
    const body = qs("vulns-table-body");
    if (!Array.isArray(vulns) || !vulns.length) {
        body.innerHTML = '<tr><td colspan="5">No vulnerabilities yet</td></tr>';
        return;
    }

    body.innerHTML = vulns
        .map((vuln) => {
            const score = Number(vuln.cvss_score || 0).toFixed(1);
            const sev = String(vuln.severity || "UNKNOWN").toLowerCase();
            return `
                <tr>
                    <td>${vuln.cve_id || "-"}</td>
                    <td>${vuln.ip || "-"}${vuln.port ? `:${vuln.port}` : ""}</td>
                    <td>${vuln.service || "-"}</td>
                    <td><span class="badge ${sev}">${vuln.severity || "UNKNOWN"}</span></td>
                    <td>${score}</td>
                </tr>
            `;
        })
        .join("");
}

function renderAllVulnerabilities(vulns) {
    const body = qs("vulnerabilities-table-body");
    if (!Array.isArray(vulns) || !vulns.length) {
        body.innerHTML = '<tr><td colspan="8">No vulnerability data available</td></tr>';
        return;
    }

    body.innerHTML = vulns
        .map((vuln) => {
            const score = Number(vuln.cvss_score || 0).toFixed(1);
            const sev = String(vuln.severity || "UNKNOWN").toLowerCase();
            const published = vuln.published_date ? new Date(vuln.published_date).toLocaleDateString() : "-";
            const desc = vuln.description ? vuln.description.substring(0, 60) + "..." : "-";
            return `
                <tr>
                    <td><strong>${vuln.cve_id || "-"}</strong></td>
                    <td>${vuln.ip || "-"}</td>
                    <td>${vuln.port || "-"}</td>
                    <td>${vuln.service || "-"}</td>
                    <td><span class="badge ${sev}">${vuln.severity || "UNKNOWN"}</span></td>
                    <td>${score}</td>
                    <td>${published}</td>
                    <td title="${vuln.description || ''}">${desc}</td>
                </tr>
            `;
        })
        .join("");
}

function renderAllHosts(hosts) {
    const body = qs("hosts-table-body");
    if (!Array.isArray(hosts) || !hosts.length) {
        body.innerHTML = '<tr><td colspan="8">No host data available</td></tr>';
        return;
    }

    body.innerHTML = hosts
        .map((host) => {
            const status = host.status || "unknown";
            const openPorts = host.open_ports || 0;
            const services = host.services_count || 0;
            const vulns = host.vulnerabilities_count || 0;
            const risk = Number(host.risk_score || 0).toFixed(1);
            const lastSeen = host.last_seen ? new Date(host.last_seen).toLocaleString() : "-";
            return `
                <tr>
                    <td><strong>${host.ip || "-"}</strong></td>
                    <td>${host.hostname || "-"}</td>
                    <td><span class="badge ${status.toLowerCase()}">${status}</span></td>
                    <td>${openPorts}</td>
                    <td>${services}</td>
                    <td>${vulns}</td>
                    <td>${risk}</td>
                    <td>${lastSeen}</td>
                </tr>
            `;
        })
        .join("");
}

function renderAllServices(services) {
    const body = qs("services-table-body");
    if (!Array.isArray(services) || !services.length) {
        body.innerHTML = '<tr><td colspan="8">No service data available</td></tr>';
        return;
    }

    body.innerHTML = services
        .map((svc) => {
            const protocol = svc.protocol || "TCP";
            const banner = svc.banner ? svc.banner.substring(0, 40) + "..." : "-";
            const vulns = svc.vulnerabilities_count || 0;
            const status = svc.status || "detected";
            return `
                <tr>
                    <td>${svc.ip || "-"}</td>
                    <td>${svc.port || "-"}</td>
                    <td>${protocol}</td>
                    <td><strong>${svc.service || "-"}</strong></td>
                    <td>${svc.version || "-"}</td>
                    <td title="${svc.banner || ''}">${banner}</td>
                    <td>${vulns}</td>
                    <td><span class="badge ${status.toLowerCase()}">${status}</span></td>
                </tr>
            `;
        })
        .join("");
}

async function loadDetailedData() {
    try {
        const overview = await fetchJson("/api/dashboard/overview");

        if (overview.recent_vulnerabilities) {
            renderAllVulnerabilities(overview.recent_vulnerabilities);
        }

        const scansData = await fetchJson("/api/scans?limit=100").catch(() => ({ scans: [] }));
        if (scansData.scans && scansData.scans.length > 0) {
            const hostsMap = new Map();
            const servicesArray = [];
            const vulnCountByService = new Map();

            for (const scan of scansData.scans.slice(0, 10)) {
                if (scan.status === "completed") {
                    try {
                        const result = await fetchJson(`/api/scans/${scan.scan_id}/results`);

                        // Process vulnerabilities to count per service
                        if (result.vulnerabilities) {
                            result.vulnerabilities.forEach(vuln => {
                                const key = `${vuln.ip}:${vuln.port}`;
                                vulnCountByService.set(key, (vulnCountByService.get(key) || 0) + 1);
                            });
                        }

                        // Process hosts
                        if (result.hosts) {
                            result.hosts.forEach(host => {
                                const hostServices = result.services ? result.services.filter(s => s.ip === host.ip) : [];
                                const hostVulns = result.vulnerabilities ? result.vulnerabilities.filter(v => v.ip === host.ip) : [];

                                if (!hostsMap.has(host.ip)) {
                                    hostsMap.set(host.ip, {
                                        ip: host.ip,
                                        hostname: host.hostname || "-",
                                        status: host.status || "up",
                                        open_ports: hostServices.length,
                                        services_count: hostServices.length,
                                        vulnerabilities_count: hostVulns.length,
                                        risk_score: 0,
                                        last_seen: scan.completed_at
                                    });
                                }
                            });
                        }

                        // Process services - they are at root level in scan results
                        if (result.services) {
                            result.services.forEach(svc => {
                                const key = `${svc.ip}:${svc.port}`;
                                servicesArray.push({
                                    ip: svc.ip,
                                    port: svc.port,
                                    protocol: "TCP",
                                    service: svc.service || "-",
                                    version: svc.version || "-",
                                    banner: svc.banner || "-",
                                    vulnerabilities_count: vulnCountByService.get(key) || 0,
                                    status: svc.state || "open"
                                });
                            });
                        }
                    } catch (err) {
                        console.warn(`Failed to load details for scan ${scan.scan_id}:`, err);
                    }
                }
            }

            renderAllHosts(Array.from(hostsMap.values()));
            renderAllServices(servicesArray);
        }
    } catch (err) {
        console.error("Failed to load detailed data:", err);
    }
}

async function refreshOverview() {
    const seq = ++overviewRequestSeq;
    try {
        const overview = await fetchJson("/api/dashboard/overview");
        if (seq !== overviewRequestSeq) return;

        const totals = overview.totals || {};
        qs("total-scans").textContent = Number(totals.total_scans || 0);
        qs("hosts-scanned").textContent = Number(totals.hosts_scanned || 0);
        qs("services-detected").textContent = Number(totals.services_detected || 0);
        qs("vulnerabilities-found").textContent = Number(totals.vulnerabilities_found || 0);
        qs("risk-score").textContent = Number(totals.average_risk_score || 0).toFixed(1);

        renderSeverityDistribution(overview.severity_distribution || {});
        renderRiskTimeline(overview.risk_timeline || []);
        renderScans(overview.recent_scans || []);
        renderVulnerabilities(overview.recent_vulnerabilities || []);

        loadDetailedData();

        setSystemStatus(true);
        qs("scan-error").textContent = "";
    } catch (err) {
        if (seq !== overviewRequestSeq) return;
        setSystemStatus(false);
        qs("scan-error").textContent = err.message;
    }
}

async function applyScanResult(scanId) {
    try {
        const result = await fetchJson(`/api/scans/${scanId}/results`);
        const summary = result.summary || {};
        const risk = Number((result.risk_analysis || {}).risk_score || 0);

        qs("hosts-scanned").textContent = Number(summary.total_hosts_scanned || 0);
        qs("services-detected").textContent = Number(summary.total_services || 0);
        qs("vulnerabilities-found").textContent = Number(summary.total_vulnerabilities || 0);
        qs("risk-score").textContent = risk.toFixed(1);

        const b = summary.severity_breakdown || {};
        renderSeverityDistribution({
            CRITICAL: Number((b.CRITICAL || {}).count || 0),
            HIGH: Number((b.HIGH || {}).count || 0),
            MEDIUM: Number((b.MEDIUM || {}).count || 0),
            LOW: Number((b.LOW || {}).count || 0),
            UNKNOWN: Number((b.UNKNOWN || {}).count || 0)
        });

        const label = result.completed_at
            ? new Date(result.completed_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
            : new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
        const existing = riskChart.data.labels || [];
        const existingData = riskChart.data.datasets[0].data || [];
        existing.push(label);
        existingData.push(risk);
        if (existing.length > 12) {
            existing.shift();
            existingData.shift();
        }
        riskChart.data.labels = existing;
        riskChart.data.datasets[0].data = existingData;
        riskChart.update();

        if (Number(summary.total_services || 0) === 0) {
            qs("scan-error").textContent = "Scan completed: no open ports/services found for that target and port list.";
        }
    } catch (err) {
        qs("scan-error").textContent = `Scan completed, but result load failed: ${err.message}`;
    }
}

async function pollScan(scanId) {
    activeScanId = scanId;
    qs("scan-error").textContent = "";

    const timer = setInterval(async () => {
        try {
            const status = await fetchJson(`/api/scans/${scanId}/status`);
            setProgress(status.progress, `Scan status: ${status.status}`);

            if (status.status === "completed") {
                clearInterval(timer);
                setProgress(100, "Scan completed");
                await applyScanResult(scanId);
                await refreshOverview();
                setTimeout(() => qs("scan-progress-wrap").classList.add("hidden"), 1200);
                activeScanId = null;
            } else if (status.status === "failed") {
                clearInterval(timer);
                qs("scan-error").textContent = status.error_message || "Scan failed";
                activeScanId = null;
            }
        } catch (err) {
            clearInterval(timer);
            qs("scan-error").textContent = err.message;
            activeScanId = null;
        }
    }, 1000);
}

async function startScan(event) {
    event.preventDefault();
    qs("scan-error").textContent = "";

    const payload = {
        target: qs("target").value.trim(),
        ports: qs("ports").value.trim() || "1-1000",
        timeout: Number(qs("timeout").value || 2)
    };

    try {
        const res = await fetch(`${API_BASE}/api/scans/start`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (!res.ok) {
            throw new Error(data.detail || "Failed to start scan");
        }
        setProgress(1, "Scan queued");
        pollScan(data.scan_id);
    } catch (err) {
        qs("scan-error").textContent = err.message;
    }
}

function initSettingsUI() {
    const defaults = {
        target: localStorage.getItem("vs.defaultTarget") || "127.0.0.1",
        ports: localStorage.getItem("vs.defaultPorts") || "80,443",
        timeout: Number(localStorage.getItem("vs.defaultTimeout") || 2),
        refreshSeconds: Number(localStorage.getItem("vs.refreshSeconds") || 8)
    };

    qs("setting-default-target").value = defaults.target;
    qs("setting-default-ports").value = defaults.ports;
    qs("setting-default-timeout").value = defaults.timeout;
    qs("setting-refresh-seconds").value = defaults.refreshSeconds;

    qs("target").value = defaults.target;
    qs("ports").value = defaults.ports;
    qs("timeout").value = defaults.timeout;

    const applyRefresh = (seconds) => {
        const safe = Math.max(5, Math.min(120, Number(seconds || 8)));
        dashboardRefreshMs = safe * 1000;
        if (refreshTimerId) {
            clearInterval(refreshTimerId);
        }
        refreshTimerId = setInterval(() => {
            checkBackend();
            refreshOverview();
        }, dashboardRefreshMs);
    };

    applyRefresh(defaults.refreshSeconds);

    qs("save-settings-btn").addEventListener("click", () => {
        const target = qs("setting-default-target").value.trim() || "127.0.0.1";
        const ports = qs("setting-default-ports").value.trim() || "80,443";
        const timeout = Math.max(1, Math.min(30, Number(qs("setting-default-timeout").value || 2)));
        const refreshSeconds = Math.max(5, Math.min(120, Number(qs("setting-refresh-seconds").value || 8)));

        localStorage.setItem("vs.defaultTarget", target);
        localStorage.setItem("vs.defaultPorts", ports);
        localStorage.setItem("vs.defaultTimeout", String(timeout));
        localStorage.setItem("vs.refreshSeconds", String(refreshSeconds));

        qs("target").value = target;
        qs("ports").value = ports;
        qs("timeout").value = timeout;
        applyRefresh(refreshSeconds);

        qs("settings-message").textContent = "Settings saved.";
    });

    qs("reset-settings-btn").addEventListener("click", () => {
        localStorage.removeItem("vs.defaultTarget");
        localStorage.removeItem("vs.defaultPorts");
        localStorage.removeItem("vs.defaultTimeout");
        localStorage.removeItem("vs.refreshSeconds");
        window.location.reload();
    });

    qs("download-latest-html-btn").addEventListener("click", () => {
        if (!latestCompletedScanId) {
            qs("reports-message").textContent = "No completed scans available yet.";
            return;
        }
        qs("reports-message").textContent = "";
        downloadReport(latestCompletedScanId, "html");
    });

    qs("download-latest-json-btn").addEventListener("click", () => {
        if (!latestCompletedScanId) {
            qs("reports-message").textContent = "No completed scans available yet.";
            return;
        }
        qs("reports-message").textContent = "";
        downloadReport(latestCompletedScanId, "json");
    });
}

function init() {
    initClock();
    initNav();
    initCharts();
    initSettingsUI();
    qs("scan-form").addEventListener("submit", startScan);
    checkBackend();
    refreshOverview();

    if (refreshTimerId) {
        clearInterval(refreshTimerId);
    }
    refreshTimerId = setInterval(() => {
        checkBackend();
        refreshOverview();
    }, dashboardRefreshMs);
}

document.addEventListener("DOMContentLoaded", init);
window.downloadReport = downloadReport;
