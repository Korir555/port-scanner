from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
from datetime import datetime
import requests
from collections import defaultdict

app = Flask(__name__, template_folder='templates')
CORS(app)

# Common port service mappings
COMMON_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
    3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC',
    8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 27017: 'MongoDB', 6379: 'Redis',
    9200: 'Elasticsearch', 11211: 'Memcached'
}

# Vulnerability database (NVD/CVE mappings)
SERVICE_VULNS = {
    'FTP': ['CVE-2014-8517', 'CVE-2013-7606'],
    'SSH': ['CVE-2021-28041', 'CVE-2020-15778'],
    'Telnet': ['CVE-2017-5645', 'CVE-2011-4862'],
    'MySQL': ['CVE-2021-2154', 'CVE-2021-2109'],
    'PostgreSQL': ['CVE-2021-23222', 'CVE-2021-20229'],
    'SMB': ['CVE-2020-1472', 'CVE-2017-0143'],
    'HTTP': ['CVE-2021-44228', 'CVE-2021-3129'],
    'RDP': ['CVE-2019-1181', 'CVE-2019-1182'],
    'VNC': ['CVE-2020-24155', 'CVE-2019-15690'],
}

def grab_banner(host, port, timeout=2):
    """Attempt to grab service banner for version detection"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        return banner if banner else None
    except:
        return None

def scan_port(host, port, timeout=2):
    """Scan a single port and return result"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        
        if result == 0:
            service = COMMON_PORTS.get(port, 'Unknown')
            banner = grab_banner(host, port, timeout)
            version = banner if banner else service
            
            # Get CVEs for this service
            cves = SERVICE_VULNS.get(service, [])
            
            return {
                'port': port,
                'state': 'open',
                'service': service,
                'version': version,
                'cves': cves,
                'risk': 'High' if cves else 'Medium'
            }
        else:
            return {
                'port': port,
                'state': 'closed',
                'service': None,
                'version': None,
                'cves': [],
                'risk': 'Low'
            }
    except socket.timeout:
        return {
            'port': port,
            'state': 'filtered',
            'service': None,
            'version': None,
            'cves': [],
            'risk': 'Low'
        }
    except Exception as e:
        return {
            'port': port,
            'state': 'error',
            'service': None,
            'version': None,
            'cves': [],
            'risk': 'Low',
            'error': str(e)
        }

def is_valid_ip(ip):
    """Validate IP address"""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Start a port scan"""
    data = request.json
    host = data.get('host', '').strip()
    ports_input = data.get('ports', '1-1000')
    
    if not host or not is_valid_ip(host):
        return jsonify({'error': 'Invalid host IP address'}), 400
    
    # Parse port range
    try:
        if '-' in ports_input:
            start, end = map(int, ports_input.split('-'))
            ports = list(range(start, end + 1))
        elif ',' in ports_input:
            ports = [int(p.strip()) for p in ports_input.split(',')]
        else:
            ports = [int(ports_input)]
    except ValueError:
        return jsonify({'error': 'Invalid port format'}), 400
    
    # Limit port range for performance
    if len(ports) > 1000:
        return jsonify({'error': 'Port range too large (max 1000)'}), 400
    
    scan_results = {
        'host': host,
        'start_time': datetime.now().isoformat(),
        'ports_scanned': 0,
        'open_ports': [],
        'closed_ports': [],
        'filtered_ports': [],
        'services': defaultdict(list),
        'vulnerabilities': []
    }
    
    # Parallel port scanning
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(scan_port, host, port): port for port in ports}
        
        for future in as_completed(futures):
            result = future.result()
            scan_results['ports_scanned'] += 1
            
            if result['state'] == 'open':
                scan_results['open_ports'].append(result)
                if result['service']:
                    scan_results['services'][result['service']].append(result['port'])
                if result['cves']:
                    scan_results['vulnerabilities'].append({
                        'port': result['port'],
                        'service': result['service'],
                        'cves': result['cves']
                    })
            elif result['state'] == 'closed':
                scan_results['closed_ports'].append(result)
            elif result['state'] == 'filtered':
                scan_results['filtered_ports'].append(result)
    
    scan_results['end_time'] = datetime.now().isoformat()
    
    # Sort open ports
    scan_results['open_ports'].sort(key=lambda x: x['port'])
    
    return jsonify(scan_results), 200

@app.route('/api/validate', methods=['POST'])
def validate_host():
    """Validate host connectivity"""
    data = request.json
    host = data.get('host', '').strip()
    
    if not host or not is_valid_ip(host):
        return jsonify({'valid': False, 'message': 'Invalid IP address'}), 400
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, 22))  # Try SSH port
        sock.close()
        
        if result == 0:
            return jsonify({'valid': True, 'message': 'Host is reachable'}), 200
        else:
            return jsonify({'valid': True, 'message': 'Host is reachable (some ports filtered)'}), 200
    except Exception as e:
        return jsonify({'valid': False, 'message': f'Host validation error: {str(e)}'}), 400

@app.route('/api/cve/<service>', methods=['GET'])
def get_service_cves(service):
    """Get CVEs for a specific service"""
    cves = SERVICE_VULNS.get(service, [])
    return jsonify({'service': service, 'cves': cves}), 200

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({'status': 'ok'}), 200

@app.route('/', methods=['GET'])
def index():
    """Serve the main scanner UI"""
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)
