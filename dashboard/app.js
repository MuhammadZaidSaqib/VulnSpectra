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
let hasAutoLoadedResults = false;

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

        // Remove :port if user entered host:port by mistake
        if (processedTarget.includes(':') && !processedTarget.includes(']')) {
            processedTarget = processedTarget.split(':')[0];
        }

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

        console.log('✓ Scan started:', currentScanId);

        // Debug: Check if elements exist
        const scanErrorDiv = document.getElementById('scan-error');
        const scanProgressDiv = document.getElementById('scan-progress');
        const scanFormDiv = document.getElementById('scan-form');
        const progressFill = document.getElementById('progress-fill');
        const progressText = document.getElementById('progress-text');

        console.log('DOM Elements Check:', {
            scanErrorDiv: !!scanErrorDiv,
            scanProgressDiv: !!scanProgressDiv,
            scanFormDiv: !!scanFormDiv,
            progressFill: !!progressFill,
            progressText: !!progressText
        });

        // Reset error state and show progress
        if (scanErrorDiv) scanErrorDiv.classList.add('hidden');
        if (scanProgressDiv) {
            scanProgressDiv.classList.remove('hidden');
            console.log('✓ Progress div shown, display:', scanProgressDiv.style.display);
        }
        if (scanFormDiv) scanFormDiv.style.display = 'none';

        // Reset and initialize progress bar with animation
        if (!progressFill || !progressText) {
            console.error('❌ Progress elements missing!', { progressFill, progressText });
            showNotification('Error: Progress bar not found', 'error');
            return;
        }

        // Start at 0% with immediate visibility
        progressFill.style.width = '0%';
        progressFill.style.background = 'linear-gradient(90deg, var(--accent-primary) 0%, var(--accent-secondary) 100%)';
        progressText.textContent = 'Initializing scan...';

        console.log('✓ Progress bar initialized at 0%');

        // Animate to 5% to show scan has started
        setTimeout(() => {
            progressFill.style.width = '5%';
            progressText.textContent = 'Starting scan...';
            console.log('✓ Progress bar animated to 5%');
        }, 100);

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

// Poll Scan Status with Ultra-Smooth Progress Animation
async function pollScanStatus(scanId) {
    console.log(`🚀 Starting smooth progress tracking for: ${scanId}`);

    let currentProgress = 0; // Start at 0%
    let targetProgress = 0;
    let scanCompleted = false;

    const progressFill = document.getElementById('progress-fill');
    const progressText = document.getElementById('progress-text');

    if (!progressFill || !progressText) {
        console.error('❌ Progress elements not found!');
        return;
    }

    // Reset to 0%
    progressFill.style.width = '0%';
    progressText.textContent = 'Starting scan...';
    console.log('✓ Progress bar reset to 0%');

    // Ultra-fast UI update interval (100ms) for smooth animation
    const smoothInterval = setInterval(() => {
        if (scanCompleted) {
            clearInterval(smoothInterval);
            return;
        }

        // Smoothly interpolate towards target with small random increments
        if (currentProgress < targetProgress) {
            // Small random increment (0.3% to 0.8%) for natural feel
            const randomIncrement = Math.random() * 0.5 + 0.3;
            const smoothIncrement = Math.min(randomIncrement, (targetProgress - currentProgress) / 8);
            currentProgress = Math.min(currentProgress + smoothIncrement, targetProgress, 99);

            // Update UI with smooth animation
            progressFill.style.width = `${currentProgress.toFixed(1)}%`;

            // Show progress percentage (cap at 99% until actually complete)
            const displayProgress = Math.floor(currentProgress);
            progressText.textContent = `Progress: ${displayProgress}% - Scanning...`;

            console.log(`📊 Progress: ${displayProgress}%`);
        } else if (currentProgress < 99) {
            // Add tiny increments even when waiting for server (keeps it feeling active)
            currentProgress = Math.min(currentProgress + 0.1, 99);
            progressFill.style.width = `${currentProgress.toFixed(1)}%`;
        }
    }, 100); // Update every 100ms for ultra-smooth animation

    // Server polling interval (600ms for responsive updates)
    const serverInterval = setInterval(async () => {
        try {
            const response = await fetch(`${API_BASE_URL}/api/scan/${scanId}/status`);
            const data = await response.json();

            const serverProgress = data.progress || 0;
            console.log(`🔄 Server progress: ${serverProgress}% - ${data.status}`);

            // Update target progress from server
            if (serverProgress > targetProgress) {
                targetProgress = Math.min(serverProgress, 99);
            }

            // Check if completed
            if (data.status === 'completed') {
                scanCompleted = true;
                clearInterval(smoothInterval);
                clearInterval(serverInterval);

                console.log('✅ Scan completed!');

                // Immediately animate to 100%
                progressFill.style.width = '100%';
                progressText.textContent = '✓ Scan Completed!';
                progressText.style.color = '#00ff88';
                progressText.style.fontWeight = 'bold';

                // Small delay for visual feedback
                setTimeout(async () => {
                    await loadScanResults(scanId);

                    // Reset form
                    document.getElementById('scan-progress').classList.add('hidden');
                    document.getElementById('scan-form').style.display = 'block';
                    document.getElementById('scan-form').reset();

                    showNotification('✓ Scan completed successfully!', 'success');
                }, 800);

            } else if (data.status === 'failed') {
                scanCompleted = true;
                clearInterval(smoothInterval);
                clearInterval(serverInterval);

                // Show error state
                const errorMsg = data.error || 'Scan failed. Please check the target and try again.';
                document.getElementById('error-message').textContent = errorMsg;
                document.getElementById('scan-error').classList.remove('hidden');
                document.getElementById('progress-text').textContent = '✗ Scan Failed';
                progressFill.style.width = '0%';
                progressFill.style.background = 'linear-gradient(90deg, #ff3366, #ff0000)';

                showNotification('Scan failed - Click "Start New Scan" to try again', 'error');
            }

        } catch (error) {
            console.error('❌ Error polling scan status:', error);
            scanCompleted = true;
            clearInterval(smoothInterval);
            clearInterval(serverInterval);

            // Show connection error
            document.getElementById('error-message').textContent =
                'Connection error. Please check if the server is running.';
            document.getElementById('scan-error').classList.remove('hidden');
            document.getElementById('progress-text').textContent = '✗ Connection Error';

            showNotification('Connection error - Cannot reach server', 'error');
        }
    }, 600); // Poll server every 600ms for fast feedback
}

// Load Scan Results
async function loadScanResults(scanId) {
    try {
        const response = await fetch(`${API_BASE_URL}/api/scan/${scanId}/results`);
        const data = await response.json();

        console.log('Loaded scan results:', data);

        // Update dashboard
        updateDashboard(data);

        // Store vulnerabilities
        allVulnerabilities = data.vulnerabilities || [];
        allScans.push(data);

        // Update tables
        updateVulnerabilitiesTable(allVulnerabilities);
        updateAllVulnerabilitiesTable(allVulnerabilities);
        updateHostsTable(data.hosts || []);
        updateServicesTable(data.services || []);
        updateRiskMatrix(allVulnerabilities);

    } catch (error) {
        console.error('Error loading scan results:', error);
    }
}

// Update Dashboard
function updateDashboard(data) {
    console.log('Updating dashboard with data:', data);

    const summary = data.summary || {};

    // Update summary cards
    document.getElementById('hosts-scanned').textContent = summary.total_hosts_scanned || 0;
    document.getElementById('services-detected').textContent = summary.total_services || 0;
    document.getElementById('vulnerabilities-found').textContent = summary.total_vulnerabilities || 0;

    // Calculate risk score if not provided
    let riskScore = 0;
    if (data.risk_analysis && data.risk_analysis.risk_score !== undefined) {
        riskScore = data.risk_analysis.risk_score;
    } else {
        // Calculate basic risk score from vulnerabilities
        const vulnerabilities = data.vulnerabilities || [];
        if (vulnerabilities.length > 0) {
            const criticalCount = vulnerabilities.filter(v => v.severity === 'CRITICAL').length;
            const highCount = vulnerabilities.filter(v => v.severity === 'HIGH').length;
            const mediumCount = vulnerabilities.filter(v => v.severity === 'MEDIUM').length;
            const lowCount = vulnerabilities.filter(v => v.severity === 'LOW').length;

            // Simple risk calculation
            riskScore = Math.min(100,
                (criticalCount * 10) +
                (highCount * 5) +
                (mediumCount * 2) +
                (lowCount * 0.5)
            );
        }
    }

    console.log('Risk score:', riskScore);
    document.getElementById('risk-score').textContent = riskScore.toFixed(1);

    // Update severity chart
    const severityBreakdown = summary.severity_breakdown?.categories || {};
    const criticalCount = severityBreakdown.CRITICAL?.length || 0;
    const highCount = severityBreakdown.HIGH?.length || 0;
    const mediumCount = severityBreakdown.MEDIUM?.length || 0;
    const lowCount = severityBreakdown.LOW?.length || 0;

    console.log('Severity counts:', { criticalCount, highCount, mediumCount, lowCount });

    severityChart.data.datasets[0].data = [criticalCount, highCount, mediumCount, lowCount];
    severityChart.update();

    // Update risk gauge
    if (riskGaugeChart) {
        riskGaugeChart.data.datasets[0].data = [riskScore, 100 - riskScore];
        riskGaugeChart.update();
    }

    // Update risk chart - ONLY add new data point if not already loaded (avoid duplicates)
    if (currentScanId && !document.getElementById('scan-progress').classList.contains('hidden')) {
        // During active scan, add data points
        const timestamp = new Date().toLocaleTimeString();
        riskChart.data.labels.push(timestamp);
        riskChart.data.datasets[0].data.push(riskScore);

        // Keep only last 10 data points
        if (riskChart.data.labels.length > 10) {
            riskChart.data.labels.shift();
            riskChart.data.datasets[0].data.shift();
        }

        console.log('Risk chart updated - Labels:', riskChart.data.labels.length, 'Risk scores:', riskChart.data.datasets[0].data);
        riskChart.update();
    }

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

    console.log(`Updating vulnerability table with ${vulnerabilities.length} vulnerabilities`);
    tbody.innerHTML = '';

    vulnerabilities.forEach((vuln, index) => {
        const row = document.createElement('tr');
        row.dataset.severity = vuln.severity;
        console.log(`Vuln ${index}: severity="${vuln.severity}", cve="${vuln.cve_id}"`);

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

        // Auto-load latest completed scan once so dashboard graphs/cards are populated.
        if (!hasAutoLoadedResults && !currentScanId) {
            const completed = data.scans
                .filter(s => s.status === 'completed')
                .sort((a, b) => new Date(b.started_at) - new Date(a.started_at));
            if (completed.length > 0) {
                hasAutoLoadedResults = true;
                await viewScanResults(completed[0].scan_id);
            }
        }

    } catch (error) {
        console.error('Error loading active scans:', error);
    }
}

// Filter Vulnerabilities
function filterVulnerabilities(filter) {
    console.log(`Filtering vulnerabilities for: ${filter}`);
    const rows = document.querySelectorAll('#all-vulnerabilities-tbody tr');
    console.log(`Total rows in table: ${rows.length}`);

    let visibleCount = 0;
    let hiddenCount = 0;

    rows.forEach((row, index) => {
        const rowSeverity = row.dataset.severity;
        console.log(`Row ${index}: severity="${rowSeverity}", filter="${filter}"`);

        if (filter === 'all' || rowSeverity === filter) {
            row.style.display = '';
            visibleCount++;
            console.log(`  → Showing row ${index}`);
        } else {
            row.style.display = 'none';
            hiddenCount++;
            console.log(`  → Hiding row ${index}`);
        }
    });

    console.log(`Filter complete: ${visibleCount} visible, ${hiddenCount} hidden`);
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
