// VulnSpectra Dashboard JavaScript

// API Configuration
const API_BASE_URL = 'http://localhost:8000';

// Global state
let currentScanId = null;
let allVulnerabilities = [];
let severityChart = null;
let riskChart = null;

// Initialize dashboard
document.addEventListener('DOMContentLoaded', () => {
    initializeNavigation();
    initializeCharts();
    initializeScanForm();
    loadActiveScans();

    // Refresh data every 10 seconds
    setInterval(loadActiveScans, 10000);
});

// Navigation
function initializeNavigation() {
    const navLinks = document.querySelectorAll('.sidebar nav a');

    navLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();

            // Remove active class from all links and sections
            navLinks.forEach(l => l.classList.remove('active'));
            document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));

            // Add active class to clicked link
            link.classList.add('active');

            // Show corresponding section
            const sectionId = link.getAttribute('data-section') + '-section';
            document.getElementById(sectionId).classList.add('active');
        });
    });
}

// Initialize Charts
function initializeCharts() {
    // Severity Distribution Chart
    const severityCtx = document.getElementById('severity-chart').getContext('2d');
    severityChart = new Chart(severityCtx, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [{
                data: [0, 0, 0, 0],
                backgroundColor: [
                    '#ff0000',
                    '#ff6b00',
                    '#ffaa00',
                    '#00ff00'
                ],
                borderWidth: 2,
                borderColor: '#1a1f3a'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#e0e0e0',
                        font: { size: 12 }
                    }
                }
            }
        }
    });

    // Risk Score Trend Chart
    const riskCtx = document.getElementById('risk-chart').getContext('2d');
    riskChart = new Chart(riskCtx, {
        type: 'line',
        data: {
            labels: ['Scan 1', 'Scan 2', 'Scan 3', 'Scan 4', 'Scan 5'],
            datasets: [{
                label: 'Risk Score',
                data: [0, 0, 0, 0, 0],
                borderColor: '#00d9ff',
                backgroundColor: 'rgba(0, 217, 255, 0.1)',
                borderWidth: 3,
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            scales: {
                y: {
                    beginAtZero: true,
                    max: 100,
                    ticks: { color: '#e0e0e0' },
                    grid: { color: 'rgba(255, 255, 255, 0.1)' }
                },
                x: {
                    ticks: { color: '#e0e0e0' },
                    grid: { color: 'rgba(255, 255, 255, 0.1)' }
                }
            },
            plugins: {
                legend: {
                    labels: { color: '#e0e0e0' }
                }
            }
        }
    });
}

// Scan Form
function initializeScanForm() {
    const form = document.getElementById('scan-form');

    form.addEventListener('submit', async (e) => {
        e.preventDefault();

        const target = document.getElementById('target').value;
        const ports = document.getElementById('ports').value;
        const timeout = parseInt(document.getElementById('timeout').value);

        await startScan(target, ports, timeout);
    });

    // Filter buttons
    const filterBtns = document.querySelectorAll('.filter-btn');
    filterBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            filterBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');

            const filter = btn.getAttribute('data-filter');
            filterVulnerabilities(filter);
        });
    });
}

// Start Scan
async function startScan(target, ports, timeout) {
    try {
        const response = await fetch(`${API_BASE_URL}/api/scan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target, ports, timeout })
        });

        if (!response.ok) {
            throw new Error('Failed to start scan');
        }

        const data = await response.json();
        currentScanId = data.scan_id;

        // Show progress
        document.getElementById('scan-progress').classList.remove('hidden');
        document.getElementById('scan-form').style.display = 'none';

        // Poll for status
        pollScanStatus(currentScanId);

        showNotification('Scan started successfully!', 'success');

    } catch (error) {
        console.error('Error starting scan:', error);
        showNotification('Failed to start scan', 'error');
    }
}

// Poll Scan Status
async function pollScanStatus(scanId) {
    const interval = setInterval(async () => {
        try {
            const response = await fetch(`${API_BASE_URL}/api/scan/${scanId}/status`);
            const data = await response.json();

            // Update progress
            const progress = data.progress || 0;
            document.getElementById('progress-fill').style.width = `${progress}%`;
            document.getElementById('progress-text').textContent =
                `Progress: ${progress.toFixed(0)}% - ${data.status}`;

            // Check if completed
            if (data.status === 'completed') {
                clearInterval(interval);
                await loadScanResults(scanId);

                // Reset form
                document.getElementById('scan-progress').classList.add('hidden');
                document.getElementById('scan-form').style.display = 'block';
                document.getElementById('scan-form').reset();

                showNotification('Scan completed!', 'success');
            } else if (data.status === 'failed') {
                clearInterval(interval);
                showNotification('Scan failed', 'error');
            }

        } catch (error) {
            console.error('Error polling scan status:', error);
            clearInterval(interval);
        }
    }, 2000); // Poll every 2 seconds
}

// Load Scan Results
async function loadScanResults(scanId) {
    try {
        const response = await fetch(`${API_BASE_URL}/api/scan/${scanId}/results`);
        const data = await response.json();

        // Update dashboard
        updateDashboard(data);

        // Store vulnerabilities
        allVulnerabilities = data.vulnerabilities || [];

        // Update tables
        updateVulnerabilitiesTable(allVulnerabilities);
        updateHostsTable(data.hosts || []);

    } catch (error) {
        console.error('Error loading scan results:', error);
    }
}

// Update Dashboard
function updateDashboard(data) {
    const summary = data.summary || {};

    // Update summary cards
    document.getElementById('hosts-scanned').textContent = summary.total_hosts_scanned || 0;
    document.getElementById('services-detected').textContent = summary.total_services || 0;
    document.getElementById('vulnerabilities-found').textContent = summary.total_vulnerabilities || 0;

    const riskScore = data.risk_analysis?.risk_score || 0;
    document.getElementById('risk-score').textContent = riskScore.toFixed(1);

    // Update severity chart
    const severityBreakdown = summary.severity_breakdown?.categories || {};
    const criticalCount = severityBreakdown.CRITICAL?.length || 0;
    const highCount = severityBreakdown.HIGH?.length || 0;
    const mediumCount = severityBreakdown.MEDIUM?.length || 0;
    const lowCount = severityBreakdown.LOW?.length || 0;

    severityChart.data.datasets[0].data = [criticalCount, highCount, mediumCount, lowCount];
    severityChart.update();

    // Update risk chart (append new data)
    riskChart.data.labels.push(`Scan ${riskChart.data.labels.length + 1}`);
    riskChart.data.datasets[0].data.push(riskScore);

    // Keep only last 10 scans
    if (riskChart.data.labels.length > 10) {
        riskChart.data.labels.shift();
        riskChart.data.datasets[0].data.shift();
    }

    riskChart.update();
}

// Update Vulnerabilities Table
function updateVulnerabilitiesTable(vulnerabilities) {
    const tbody = document.getElementById('vulnerabilities-tbody');

    if (vulnerabilities.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="no-data">No vulnerabilities found</td></tr>';
        return;
    }

    tbody.innerHTML = '';

    // Show top 10 vulnerabilities
    const topVulns = vulnerabilities.slice(0, 10);

    topVulns.forEach(vuln => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td><strong>${vuln.cve_id}</strong></td>
            <td>${vuln.ip}:${vuln.port}</td>
            <td>${vuln.product} ${vuln.version}</td>
            <td><span class="badge badge-${vuln.severity.toLowerCase()}">${vuln.severity}</span></td>
            <td>${vuln.cvss_score.toFixed(1)}</td>
            <td><span class="badge badge-warning">Open</span></td>
        `;
        tbody.appendChild(row);
    });

    // Update all vulnerabilities table
    updateAllVulnerabilitiesTable(vulnerabilities);
}

// Update All Vulnerabilities Table
function updateAllVulnerabilitiesTable(vulnerabilities) {
    const tbody = document.getElementById('all-vulnerabilities-tbody');

    if (vulnerabilities.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="no-data">No vulnerabilities to display</td></tr>';
        return;
    }

    tbody.innerHTML = '';

    vulnerabilities.forEach(vuln => {
        const row = document.createElement('tr');
        row.dataset.severity = vuln.severity;

        const description = vuln.description.length > 80
            ? vuln.description.substring(0, 80) + '...'
            : vuln.description;

        row.innerHTML = `
            <td><strong>${vuln.cve_id}</strong></td>
            <td>${vuln.ip}</td>
            <td>${vuln.port}</td>
            <td>${vuln.product} ${vuln.version}</td>
            <td><span class="badge badge-${vuln.severity.toLowerCase()}">${vuln.severity}</span></td>
            <td>${vuln.cvss_score.toFixed(1)}</td>
            <td>${description}</td>
        `;
        tbody.appendChild(row);
    });
}

// Update Hosts Table
function updateHostsTable(hosts) {
    const tbody = document.getElementById('hosts-tbody');

    if (hosts.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="no-data">No hosts discovered</td></tr>';
        return;
    }

    tbody.innerHTML = '';

    hosts.forEach(host => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${host.ip}</td>
            <td>${host.hostname || 'Unknown'}</td>
            <td><span class="badge badge-${host.status === 'up' ? 'success' : 'danger'}">${host.status}</span></td>
            <td>${host.open_count || 0}</td>
            <td>-</td>
            <td>-</td>
        `;
        tbody.appendChild(row);
    });
}

// Load Active Scans
async function loadActiveScans() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/scans`);
        const data = await response.json();

        const tbody = document.getElementById('active-scans-tbody');

        if (data.scans.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="no-data">No active scans</td></tr>';
            return;
        }

        tbody.innerHTML = '';

        data.scans.forEach(scan => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${scan.scan_id}</td>
                <td>${scan.target}</td>
                <td><span class="badge badge-${scan.status === 'completed' ? 'success' : 'warning'}">${scan.status}</span></td>
                <td>-</td>
                <td>${new Date(scan.started_at).toLocaleString()}</td>
                <td>
                    <button class="btn-secondary" onclick="viewScanResults('${scan.scan_id}')">View</button>
                </td>
            `;
            tbody.appendChild(row);
        });

    } catch (error) {
        console.error('Error loading active scans:', error);
    }
}

// Filter Vulnerabilities
function filterVulnerabilities(filter) {
    const rows = document.querySelectorAll('#all-vulnerabilities-tbody tr');

    rows.forEach(row => {
        if (filter === 'all' || row.dataset.severity === filter) {
            row.style.display = '';
        } else {
            row.style.display = 'none';
        }
    });
}

// View Scan Results
async function viewScanResults(scanId) {
    currentScanId = scanId;
    await loadScanResults(scanId);

    // Switch to dashboard view
    document.querySelector('[data-section="dashboard"]').click();
}

// Download Report
async function downloadReport(format) {
    if (!currentScanId) {
        showNotification('No scan results available', 'warning');
        return;
    }

    try {
        const response = await fetch(`${API_BASE_URL}/api/scan/${currentScanId}/report?format=${format}`);
        const blob = await response.blob();

        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `vulnspectra_report_${currentScanId}.${format}`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);

        showNotification(`${format.toUpperCase()} report downloaded!`, 'success');

    } catch (error) {
        console.error('Error downloading report:', error);
        showNotification('Failed to download report', 'error');
    }
}

// Show Notification
function showNotification(message, type) {
    // Simple console notification
    // In production, implement a proper toast/notification system
    console.log(`[${type.toUpperCase()}] ${message}`);
}

