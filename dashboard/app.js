// VulnSpectra Dashboard Enhanced JavaScript

// API Configuration
const API_BASE_URL = 'http://localhost:8000';

// Global state
let currentScanId = null;
let allVulnerabilities = [];
let allScans = [];
let severityChart = null;
let riskChart = null;
let riskGaugeChart = null;

// Initialize dashboard
document.addEventListener('DOMContentLoaded', () => {
    console.log('VulnSpectra Dashboard: DOM Content Loaded');
    try {
        initializeNavigation();
        console.log('✓ Navigation initialized');
        initializeCharts();
        console.log('✓ Charts initialized');
        initializeScanForm();
        console.log('✓ Scan form initialized');
        initializeModals();
        console.log('✓ Modals initialized');
        initializeSettings();
        console.log('✓ Settings initialized');
        loadActiveScans();
        console.log('✓ Active scans loaded');

        // Refresh data every 30 seconds (reduced from 10s for performance)
        setInterval(loadActiveScans, 30000);
        console.log('✓ Dashboard ready!');
    } catch (error) {
        console.error('Dashboard initialization error:', error);
    }
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
            const section = document.getElementById(sectionId);
            if (section) {
                section.classList.add('active');
            }
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
                        font: { size: 12 },
                        padding: 15
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
            labels: [],
            datasets: [{
                label: 'Risk Score',
                data: [],
                borderColor: '#00d9ff',
                backgroundColor: 'rgba(0, 217, 255, 0.1)',
                borderWidth: 3,
                fill: true,
                tension: 0.4,
                pointRadius: 5,
                pointBackgroundColor: '#00d9ff'
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

    // Risk Gauge Chart
    try {
        const gaugeCanvas = document.getElementById('risk-gauge-canvas');
        if (gaugeCanvas) {
            const gaugeCtx = gaugeCanvas.getContext('2d');
            riskGaugeChart = new Chart(gaugeCtx, {
                type: 'doughnut',
                data: {
                    datasets: [{
                        data: [0, 100],
                        backgroundColor: ['#ff6b00', '#1a1f3a'],
                        borderColor: '#00d9ff',
                        borderWidth: 3
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: true,
                    circumference: 180,
                    rotation: 270,
                    plugins: {
                        legend: { display: false }
                    }
                }
            });
        }
    } catch (e) {
        console.log('Gauge chart not available');
    }
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

// Initialize Modals
function initializeModals() {
    const backdrop = document.getElementById('modal-backdrop');
    const modals = document.querySelectorAll('.modal');

    modals.forEach(modal => {
        const closeBtn = modal.querySelector('.modal-close');
        if (closeBtn) {
            closeBtn.addEventListener('click', () => {
                modal.classList.remove('active');
                backdrop.classList.remove('active');
            });
        }
    });

    backdrop.addEventListener('click', () => {
        modals.forEach(m => m.classList.remove('active'));
        backdrop.classList.remove('active');
    });
}

// Initialize Settings
function initializeSettings() {
    const settingsForm = document.getElementById('settings-form');
    const apiSettingsForm = document.getElementById('api-settings-form');

    if (settingsForm) {
        settingsForm.addEventListener('submit', (e) => {
            e.preventDefault();
            saveSettings();
        });
    }

    if (apiSettingsForm) {
        apiSettingsForm.addEventListener('submit', (e) => {
            e.preventDefault();
            saveAPISettings();
        });
    }

    // Load saved settings
    loadSettings();
}

function saveSettings() {
    const timeout = document.getElementById('default-timeout').value;
    const ports = document.getElementById('default-ports').value;
    const threads = document.getElementById('max-threads').value;

    localStorage.setItem('settings', JSON.stringify({
        timeout: timeout,
        ports: ports,
        threads: threads
    }));

    showNotification('Settings saved successfully!', 'success');
}

function saveAPISettings() {
    const apiKey = document.getElementById('nvd-api-key').value;
    const rateLimit = document.getElementById('api-rate-limit').value;

    localStorage.setItem('api-settings', JSON.stringify({
        apiKey: apiKey,
        rateLimit: rateLimit
    }));

    showNotification('API settings saved successfully!', 'success');
}

function loadSettings() {
    const settings = JSON.parse(localStorage.getItem('settings') || '{}');
    const apiSettings = JSON.parse(localStorage.getItem('api-settings') || '{}');

    if (settings.timeout) {
        document.getElementById('default-timeout').value = settings.timeout;
    }
    if (settings.ports) {
        document.getElementById('default-ports').value = settings.ports;
    }
    if (settings.threads) {
        document.getElementById('max-threads').value = settings.threads;
    }

    if (apiSettings.apiKey) {
        document.getElementById('nvd-api-key').value = apiSettings.apiKey;
    }
    if (apiSettings.rateLimit) {
        document.getElementById('api-rate-limit').value = apiSettings.rateLimit;
    }
}

// Start Scan
async function startScan(target, ports, timeout) {
    try {
        // Process target - clean URL if needed
        let processedTarget = target.trim();

        // Remove protocol if present (http://, https://)
        processedTarget = processedTarget.replace(/^https?:\/\//i, '');

        // Remove trailing slash
        processedTarget = processedTarget.replace(/\/$/, '');

        // Remove path if present (take only domain/IP)
        processedTarget = processedTarget.split('/')[0];

        // Show processing message
        showNotification('Processing target...', 'info');

        const response = await fetch(`${API_BASE_URL}/api/scan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                target: processedTarget,
                ports,
                timeout
            })
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.detail || 'Failed to start scan');
        }

        const data = await response.json();
        currentScanId = data.scan_id;

        // Reset error state and show progress
        document.getElementById('scan-error').classList.add('hidden');
        document.getElementById('scan-progress').classList.remove('hidden');
        document.getElementById('scan-form').style.display = 'none';
        document.getElementById('progress-fill').style.background =
            'linear-gradient(90deg, var(--accent-primary) 0%, var(--accent-secondary) 100%)';

        // Poll for status
        pollScanStatus(currentScanId);

        showNotification(`Scan started for ${processedTarget}`, 'success');

    } catch (error) {
        console.error('Error starting scan:', error);

        // Show error in the UI
        document.getElementById('error-message').textContent =
            `Failed to start scan: ${error.message}`;
        document.getElementById('scan-error').classList.remove('hidden');
        document.getElementById('scan-progress').classList.remove('hidden');
        document.getElementById('scan-form').style.display = 'none';
        document.getElementById('progress-text').textContent = 'Failed to start scan';

        showNotification(`Failed to start scan: ${error.message}`, 'error');
    }
}

// Reset Scan Form
function resetScanForm() {
    // Hide progress and error sections
    document.getElementById('scan-progress').classList.add('hidden');
    document.getElementById('scan-error').classList.add('hidden');

    // Show form
    document.getElementById('scan-form').style.display = 'block';

    // Reset progress bar
    document.getElementById('progress-fill').style.width = '0%';
    document.getElementById('progress-fill').style.background =
        'linear-gradient(90deg, var(--accent-primary) 0%, var(--accent-secondary) 100%)';
    document.getElementById('progress-text').textContent = 'Initializing scan...';

    // Clear error message
    document.getElementById('error-message').textContent = '';

    console.log('Scan form reset - ready for new scan');
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

                // Show error message with retry option
                const errorMsg = data.error || 'Scan failed. Please check the target and try again.';
                document.getElementById('error-message').textContent = errorMsg;
                document.getElementById('scan-error').classList.remove('hidden');
                document.getElementById('progress-text').textContent = 'Scan Failed';
                document.getElementById('progress-fill').style.width = '0%';
                document.getElementById('progress-fill').style.background = 'var(--danger)';

                showNotification('Scan failed - Click "Start New Scan" to try again', 'error');
            }

        } catch (error) {
            console.error('Error polling scan status:', error);
            clearInterval(interval);

            // Show connection error
            document.getElementById('error-message').textContent =
                'Connection error. Please check if the server is running.';
            document.getElementById('scan-error').classList.remove('hidden');
            document.getElementById('progress-text').textContent = 'Connection Error';

            showNotification('Connection error - Cannot reach server', 'error');
        }
    }, 2000);
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
        allScans.push(data);

        // Update tables
        updateVulnerabilitiesTable(allVulnerabilities);
        updateHostsTable(data.hosts || []);
        updateServicesTable(data.services || []);
        updateRiskMatrix(allVulnerabilities);

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

    // Update risk gauge
    if (riskGaugeChart) {
        riskGaugeChart.data.datasets[0].data = [riskScore, 100 - riskScore];
        riskGaugeChart.update();
    }

    // Update risk chart
    const timestamp = new Date().toLocaleTimeString();
    riskChart.data.labels.push(timestamp);
    riskChart.data.datasets[0].data.push(riskScore);

    if (riskChart.data.labels.length > 10) {
        riskChart.data.labels.shift();
        riskChart.data.datasets[0].data.shift();
    }

    riskChart.update();

    // Update statistics
    updateStatistics(severityBreakdown);
}

function updateStatistics(breakdown) {
    document.getElementById('critical-count').textContent = breakdown.CRITICAL?.length || 0;
    document.getElementById('high-count').textContent = breakdown.HIGH?.length || 0;
    document.getElementById('medium-count').textContent = breakdown.MEDIUM?.length || 0;
    document.getElementById('low-count').textContent = breakdown.LOW?.length || 0;
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

// Update Services Table
function updateServicesTable(services) {
    const tbody = document.getElementById('services-tbody');

    if (services.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="no-data">No services detected</td></tr>';
        return;
    }

    tbody.innerHTML = '';

    services.forEach(service => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${service.ip}</td>
            <td>${service.port}</td>
            <td>${service.service}</td>
            <td>${service.product}</td>
            <td>${service.version}</td>
            <td>-</td>
        `;
        tbody.appendChild(row);
    });
}

// Update Risk Matrix
function updateRiskMatrix(vulnerabilities) {
    const matrix = document.getElementById('risk-matrix');
    if (!matrix) return;

    matrix.innerHTML = '';

    const categories = ['Critical', 'High', 'Medium', 'Low'];
    categories.forEach(cat => {
        const count = vulnerabilities.filter(v => v.severity === cat.toUpperCase()).length;
        const cell = document.createElement('div');
        cell.className = `risk-matrix-cell badge-${cat.toLowerCase()}`;
        cell.innerHTML = `<strong>${cat}</strong><br>${count}`;
        matrix.appendChild(cell);
    });
}

// Load Active Scans
async function loadActiveScans() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/scans`);
        const data = await response.json();

        const tbody = document.getElementById('active-scans-tbody');
        const grid = document.getElementById('scans-grid');

        if (data.scans.length === 0) {
            if (tbody) tbody.innerHTML = '<tr><td colspan="6" class="no-data">No active scans</td></tr>';
            if (grid) grid.innerHTML = '<div class="no-data">No scans available</div>';
            return;
        }

        if (tbody) {
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
        }

        if (grid) {
            grid.innerHTML = '';
            data.scans.forEach(scan => {
                const card = document.createElement('div');
                card.className = `scan-card ${scan.status}`;
                card.innerHTML = `
                    <h4>${scan.scan_id}</h4>
                    <p>Target: ${scan.target}</p>
                    <p>Status: ${scan.status}</p>
                    <p>Started: ${new Date(scan.started_at).toLocaleString()}</p>
                `;
                grid.appendChild(card);
            });
        }

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
function showNotification(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;

    container.appendChild(toast);

    setTimeout(() => {
        toast.remove();
    }, 5000);
}

