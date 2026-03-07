# 🛡️ VulnSpectra - Intelligent Network Vulnerability & CVE Analysis Platform

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![Java Version](https://img.shields.io/badge/java-11%2B-orange.svg)](https://www.oracle.com/java/technologies/javase-downloads.html)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

VulnSpectra is a comprehensive, modular vulnerability scanning framework that combines network reconnaissance, service detection, CVE intelligence, and risk analysis to provide enterprise-grade security assessments.

## 🌟 Features

### Network Scanner
- **Port Scanning**: Multi-threaded port scanning with customizable ranges
- **Service Detection**: Automatic service identification and version fingerprinting
- **Banner Grabbing**: Extract service banners for version detection
- **Host Discovery**: Network range scanning with CIDR notation support

### CVE Intelligence Engine
- **NVD API Integration**: Query National Vulnerability Database
- **Real-time CVE Data**: Fetch latest vulnerability information
- **CVSS Scoring**: Extract severity levels and CVSS scores
- **Smart Matching**: Version-aware vulnerability matching

### Risk Analysis (Java Module)
- **Host Risk Scoring**: Calculate risk scores per host
- **Severity Weighting**: Weighted vulnerability prioritization
- **Remediation Planning**: Automated remediation priority ranking
- **JSON Processing**: Fast analysis of scan results

### Web Dashboard (SOC-Style)
- **Dark Theme UI**: Professional SOC-style interface
- **Real-time Updates**: Live scan progress monitoring
- **Interactive Charts**: Vulnerability distribution and risk trends
- **Responsive Design**: Desktop and mobile compatible

### Reporting
- **JSON Reports**: Machine-readable structured data
- **HTML Reports**: Professional security assessment documents
- **Console Output**: Colored terminal reports with tables
- **Multiple Formats**: Export in various formats

## 📋 Prerequisites

- **Python 3.8+**
- **Java 11+** (for risk analysis module)
- **Maven** (for building Java module)
- **Administrator/Root privileges** (for some network operations)

## 🚀 Installation

### 1. Clone Repository
```bash
git clone https://github.com/yourusername/vulnspectra.git
cd vulnspectra
```

### 2. Install Python Dependencies
```bash
pip install -r requirements.txt
```

### 3. Build Java Risk Analyzer
```bash
cd analysis_java
mvn clean package
cd ..
```

### 4. Configuration (Optional)
Set NVD API key for higher rate limits:
```bash
# Windows PowerShell
$env:NVD_API_KEY="your-api-key-here"

# Linux/Mac
export NVD_API_KEY="your-api-key-here"
```

Get your free API key at: https://nvd.nist.gov/developers/request-an-api-key

## 💻 Usage

### Command Line Interface

#### Basic Scan
```bash
python main.py --target 192.168.1.10
```

#### Network Range Scan
```bash
python main.py --range 192.168.1.0/24
```

#### Custom Port Range
```bash
python main.py --target 192.168.1.10 --ports 1-1000
```

#### Advanced Scan with Reports
```bash
python main.py --target 192.168.1.10 --ports 1-65535 --json --html --verbose
```

#### Start Web Dashboard
```bash
python main.py --dashboard
```

#### Start API Server
```bash
python main.py --api
```

### CLI Options

```
Options:
  --target TARGET       Target IP address
  --range RANGE         Target IP range (CIDR notation)
  --ports PORTS         Port range to scan (default: 1-1000)
  --timeout TIMEOUT     Connection timeout in seconds (default: 2)
  --dashboard           Start web dashboard
  --api                 Start API server
  --output OUTPUT       Output directory for reports
  --json                Generate JSON report
  --html                Generate HTML report
  --no-console          Disable console output
  --verbose, -v         Enable verbose logging
  --api-key API_KEY     NVD API key for CVE lookups
```

### Web Dashboard

1. Start the dashboard:
```bash
python main.py --dashboard
```

2. Dashboard will automatically open in your browser at `file:///path/to/dashboard/index.html`

3. API server runs on `http://localhost:8000`

### API Endpoints

#### Start Scan
```bash
POST http://localhost:8000/api/scan
Content-Type: application/json

{
  "target": "192.168.1.10",
  "ports": "1-1000",
  "timeout": 2
}
```

#### Get Scan Status
```bash
GET http://localhost:8000/api/scan/{scan_id}/status
```

#### Get Scan Results
```bash
GET http://localhost:8000/api/scan/{scan_id}/results
```

#### Download Report
```bash
GET http://localhost:8000/api/scan/{scan_id}/report?format=html
GET http://localhost:8000/api/scan/{scan_id}/report?format=json
```

#### List All Scans
```bash
GET http://localhost:8000/api/scans
```

### Java Risk Analyzer (Standalone)

```bash
cd analysis_java
java -jar target/risk-analyzer-1.0.0-jar-with-dependencies.jar scan_results.json output.json
```

## 📁 Project Structure

```
VulnSpectra/
├── scanner/                    # Network scanning modules
│   ├── __init__.py
│   ├── network_scanner.py      # Host discovery
│   ├── port_scanner.py         # Port scanning
│   └── service_detector.py     # Service fingerprinting
│
├── intelligence/               # CVE intelligence modules
│   ├── __init__.py
│   ├── cve_fetcher.py          # NVD API integration
│   └── vuln_matcher.py         # Vulnerability matching
│
├── analysis_java/              # Java risk analysis module
│   ├── RiskAnalyzer.java       # Risk calculation engine
│   └── pom.xml                 # Maven configuration
│
├── api/                        # FastAPI REST API
│   ├── __init__.py
│   └── app.py                  # API endpoints
│
├── dashboard/                  # Web dashboard
│   ├── index.html              # Dashboard UI
│   ├── styles.css              # SOC-style CSS
│   └── app.js                  # JavaScript logic
│
├── reporting/                  # Report generation
│   ├── __init__.py
│   ├── json_reporter.py        # JSON reports
│   ├── html_reporter.py        # HTML reports
│   └── console_reporter.py     # Console output
│
├── utils/                      # Utility modules
│   ├── __init__.py
│   ├── logger.py               # Logging configuration
│   └── validators.py           # Input validation
│
├── logs/                       # Log files
├── reports/                    # Generated reports
├── main.py                     # Main entry point
├── requirements.txt            # Python dependencies
└── README.md                   # This file
```

## 🎯 Use Cases

### Security Auditing
- Internal network security assessments
- Vulnerability discovery and tracking
- Compliance reporting

### Penetration Testing
- Reconnaissance phase
- Service enumeration
- Vulnerability identification

### DevSecOps
- CI/CD security integration
- Automated vulnerability scanning
- Security dashboard for teams

### SOC Operations
- Continuous monitoring
- Threat assessment
- Risk prioritization

## ⚙️ Configuration

### Scan Timeout
Adjust timeout for slower networks:
```bash
python main.py --target 192.168.1.10 --timeout 5
```

### Port Range
Common port configurations:
```bash
# Top 100 ports
python main.py --target 192.168.1.10 --ports 1-1000

# Web services only
python main.py --target 192.168.1.10 --ports 80,443,8080,8443

# Full port scan (slow!)
python main.py --target 192.168.1.10 --ports 1-65535
```

### API Rate Limiting
Configure NVD API rate limits in `intelligence/cve_fetcher.py`:
```python
CVEFetcher(api_key="your-key", rate_limit=0.6)  # 0.6 seconds between requests
```

## 📊 Reports

### Console Report
Colored terminal output with:
- Scan summary
- Detected services
- Vulnerabilities by severity
- Risk analysis

### JSON Report
Structured data including:
- Host information
- Service details
- CVE matches
- Risk metrics

### HTML Report
Professional report with:
- Executive summary
- Vulnerability tables
- Severity distribution
- Risk scoring

## 🔒 Security Considerations

### Legal Usage
- Only scan networks you have permission to test
- Respect rate limits of external APIs
- Follow responsible disclosure practices

### Network Impact
- Scans generate network traffic
- May trigger IDS/IPS alerts
- Use appropriate timeout values

### Data Privacy
- Reports may contain sensitive information
- Store reports securely
- Sanitize data before sharing

## 🛠️ Troubleshooting

### Port Scanning Fails
- Run with administrator/root privileges
- Check firewall settings
- Verify network connectivity

### CVE Data Not Found
- Check internet connection
- Verify NVD API is accessible
- Consider using API key for better rate limits

### Java Module Errors
- Ensure Java 11+ is installed
- Rebuild with `mvn clean package`
- Check classpath and dependencies

### Dashboard Not Loading
- Ensure API server is running
- Check browser console for errors
- Verify CORS settings

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **NVD** - National Vulnerability Database
- **MITRE** - CVE Program
- **NIST** - CVSS Scoring System
- **Chart.js** - Data visualization

## 📧 Contact

- **Project**: VulnSpectra
- **Author**: Security Researcher
- **Email**: security@example.com
- **GitHub**: https://github.com/yourusername/vulnspectra

## 🔮 Future Enhancements

- [ ] Docker containerization
- [ ] Database integration (PostgreSQL)
- [ ] Authentication & authorization
- [ ] Multi-user support
- [ ] Scheduled scanning
- [ ] Email notifications
- [ ] Export to SIEM systems
- [ ] Custom vulnerability rules
- [ ] Plugin system
- [ ] Mobile app

---

**⚠️ Disclaimer**: This tool is for educational and authorized security testing purposes only. Unauthorized scanning of networks is illegal. Always obtain proper authorization before conducting security assessments.

**Made with ❤️ by the VulnSpectra Team**

