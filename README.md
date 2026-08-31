# Port Scanner

A professional-grade network reconnaissance tool built with Flask and React. Performs rapid TCP port scanning, service enumeration, version detection, and vulnerability assessment against target hosts.

## Features

### Core Scanning
- **Fast TCP port scanning** with parallel execution (50 concurrent threads)
- **Customizable port ranges** — single ports, ranges, or comma-separated lists
- **Service detection** — identification of 15+ common services (SSH, HTTP, MySQL, SMB, etc.)
- **Banner grabbing** — retrieves service version information from banners
- **Timeout configuration** — adjustable per-port connection timeout (1-10 seconds)

### Vulnerability Intelligence
- **CVE database** — known vulnerabilities mapped to detected services
- **Risk assessment** — categorizes findings as High/Medium/Low risk
- **Detailed reporting** — service versions, CVE IDs, and remediation guidance

### User Interface
- **Real-time dashboard** — live progress updates during scanning
- **Dark terminal theme** — security-focused aesthetic with glowing terminal effects
- **Responsive design** — works on desktop and mobile devices
- **Export capabilities** — results in JSON and CSV formats

### Results Analysis
- **Sortable port table** — organized view of all scanned ports
- **Vulnerability highlighting** — CVE-tagged services in red for quick identification
- **Statistics panel** — summary of open/closed/filtered port counts
- **Service grouping** — view all instances of each detected service

## Architecture

### Backend
**Flask REST API** (`app.py`)
- `/api/scan` — POST endpoint to initiate port scan
- `/api/validate` — Verify host reachability before scanning
- `/api/cve/<service>` — Retrieve known CVEs for specific service
- `/health` — Health check endpoint

**Scanning Engine**
- Socket-based TCP connection scanning
- ThreadPoolExecutor for concurrent port testing
- Banner grabbing for version detection
- CVE correlation from local vulnerability database

### Frontend
**React SPA** (served via Flask template)
- Input validation and form handling
- Real-time scan progress display
- Dynamic results table with sorting
- Export to JSON and CSV
- Responsive grid layout with CSS Grid

### Data Flow
```
User Input → Validation → Parallel Port Scan → Service Detection 
→ CVE Lookup → Aggregation → UI Display → Export
```

## Installation

### Requirements
- Python 3.8+
- pip package manager

### Setup

1. **Clone repository**
```bash
git clone https://github.com/Korir555/port-scanner.git
cd port-scanner
```

2. **Create virtual environment**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

## Usage

### Starting the Scanner

```bash
python app.py
```

The application will start on `http://127.0.0.1:5000`

### Basic Scan

1. Open browser to `http://localhost:5000`
2. Enter target IP address (e.g., `192.168.1.1`)
3. Specify port range (default: `1-1000`)
4. Click "START SCAN"
5. View results in real-time

### Port Range Formats

- **Range**: `1-1000` (scan ports 1 through 1000)
- **Specific ports**: `22,80,443,3306` (comma-separated)
- **Single port**: `22` (SSH only)

### API Usage

**Direct HTTP requests:**

```bash
# Scan target
curl -X POST http://127.0.0.1:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"host":"192.168.1.1","ports":"1-1000"}'

# Validate host
curl -X POST http://127.0.0.1:5000/api/validate \
  -H "Content-Type: application/json" \
  -d '{"host":"192.168.1.1"}'

# Get CVEs for service
curl http://127.0.0.1:5000/api/cve/SSH
```

## Scan Results

### Open Port Information
- **Port**: TCP port number
- **Service**: Identified service name (SSH, HTTP, MySQL, etc.)
- **Version**: Service version from banner grab
- **CVEs**: Known Common Vulnerabilities and Exposures
- **Risk**: High/Medium/Low severity assessment

### Statistics
- **Ports Scanned**: Total ports attempted
- **Open Ports**: Ports responding to connection
- **Closed Ports**: Ports with explicit rejection
- **Filtered Ports**: Ports with no response (likely firewall)
- **Known CVEs**: Total vulnerabilities across all services

## Security Considerations

### Intended Use
This tool is designed for:
- ✅ Security testing on your own systems
- ✅ Authorized penetration testing engagements
- ✅ Network administration and asset discovery
- ✅ Vulnerability assessment with proper authorization

### Not For
- ❌ Unauthorized network scanning
- ❌ Testing systems you don't own/operate
- ❌ Malicious reconnaissance
- ❌ Denial of service attacks

### Responsible Disclosure
Always obtain written permission before scanning any network or system you don't own. Unauthorized port scanning may violate computer fraud and abuse laws in your jurisdiction.

## Limitations

- **Single-threaded port scanning** — Concurrency limited to 50 threads for stability
- **TCP only** — UDP scanning not implemented in current version
- **No SNMP/banner parsing** — Banner grab is simple socket read
- **Local CVE database** — Not real-time; would require API integration for latest threats
- **No authentication** — Scans unauthenticated services only
- **Rate limiting** — No built-in throttling; high concurrency may trigger IDS

## Future Enhancements

- [ ] UDP port scanning
- [ ] OS fingerprinting (TTL analysis, TCP/IP stack signatures)
- [ ] Nmap integration for advanced detection
- [ ] Real-time CVE API integration (NVD, CISA)
- [ ] Service fingerprinting for web applications
- [ ] Scheduled scanning and trend analysis
- [ ] Authentication support for protocol-specific enumeration
- [ ] Docker containerization
- [ ] Persistent results database

## Troubleshooting

### "Connection refused" error
- Ensure Flask backend is running (`python app.py`)
- Check firewall isn't blocking localhost:5000

### Slow scans
- Reduce port range or increase timeout
- Check network connectivity to target
- Firewall or IDS may be rate-limiting connections

### No results
- Verify target IP is reachable
- Check target is on network and not behind restrictive firewall
- Increase timeout value for slow/distant targets

## Performance

- **Typical scan (1-1000 ports)**: 30-60 seconds
- **Fast scan (1-100 ports)**: 5-10 seconds  
- **Throughput**: ~15-20 ports/second with 50 threads

Performance depends on network latency, target responsiveness, and timeout configuration.

## Dependencies

- **Flask** — Web framework and REST API
- **Flask-CORS** — Cross-origin resource sharing for frontend
- **Requests** — HTTP library for CVE lookups

## License

MIT License — See LICENSE file for details

## Author

Emmanuel Kibet Korir (@Korir555)

Built as part of a professional cybersecurity portfolio demonstrating:
- Network security and reconnaissance
- Full-stack application development
- Security tooling and automation
- API design and RESTful architecture

## Contributing

Issues and pull requests welcome. For major changes, please open an issue first to discuss proposed changes.

## References

- [IANA Port Registry](https://www.iana.org/assignments/service-names-port-numbers/)
- [CVE Details](https://www.cvedetails.com/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework/)
- [OWASP Reconnaissance](https://owasp.org/www-project-web-security-testing-guide/)
