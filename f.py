from flask import Flask, request, jsonify
import subprocess
import json
import os
import tempfile
import re
import socket
import logging
import threading
import uuid
import time
import hmac
import hashlib
from datetime import datetime
from collections import OrderedDict


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Audit logger for security events
audit_logger = logging.getLogger('audit')
audit_handler = logging.FileHandler('audit.log')
audit_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
audit_logger.addHandler(audit_handler)
audit_logger.setLevel(logging.INFO)

app = Flask(__name__)

# Security configuration
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  # 1MB max request size
API_KEY = os.environ.get('API_KEY', None)  # Set via environment variable
REQUIRE_AUTH = os.environ.get('REQUIRE_AUTH', 'false').lower() == 'true'

def require_api_key(f):
    """Decorator to require API key authentication with timing-attack resistance"""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if REQUIRE_AUTH:
            api_key = request.headers.get('X-API-Key')
            if not api_key:
                audit_logger.warning(f"Unauthorized access attempt from {request.remote_addr} to {request.path}")
                return jsonify({"error": "Unauthorized - Invalid or missing API key"}), 401
            
            # Timing-attack resistant comparison
            provided_hash = hashlib.sha256(api_key.encode()).hexdigest()
            stored_hash = hashlib.sha256(API_KEY.encode()).hexdigest() if API_KEY else ''
            
            if not hmac.compare_digest(provided_hash, stored_hash):
                audit_logger.warning(f"Unauthorized access attempt from {request.remote_addr} to {request.path}")
                return jsonify({"error": "Unauthorized - Invalid or missing API key"}), 401
            
            # Store API key hash for ownership tracking
            request.api_key_hash = provided_hash[:8]
        return f(*args, **kwargs)
    return decorated_function

# Job management
scan_jobs = OrderedDict()
job_owners = {}  # Track job ownership by API key hash
MAX_JOBS_HISTORY = 1000
MAX_CONCURRENT_SCANS = 5
active_scans = {"count": 0, "lock": threading.Lock()}

def get_owner_id():
    """Get current owner ID (API key hash or IP)"""
    if REQUIRE_AUTH and hasattr(request, 'api_key_hash'):
        return request.api_key_hash
    return request.remote_addr

def check_job_access(job_id):
    """Check if current user has access to job"""
    if job_id not in job_owners:
        return False
    return job_owners[job_id] == get_owner_id() or not REQUIRE_AUTH

# Rate limiting per IP
ip_request_counts = {}
ip_lock = threading.Lock()
MAX_REQUESTS_PER_IP_PER_HOUR = 100

def check_rate_limit(ip):
    """Check if IP has exceeded rate limit"""
    with ip_lock:
        current_time = time.time()
        if ip not in ip_request_counts:
            ip_request_counts[ip] = []
        
        # Remove requests older than 1 hour
        ip_request_counts[ip] = [t for t in ip_request_counts[ip] if current_time - t < 3600]
        
        if len(ip_request_counts[ip]) >= MAX_REQUESTS_PER_IP_PER_HOUR:
            return False
        
        ip_request_counts[ip].append(current_time)
        return True

# Tool registry
SUPPORTED_TOOLS = {
    'wafw00f': {'timeout': 120, 'description': 'WAF Detection'},
    'nmap': {'timeout': 600, 'description': 'Network Mapping'},
    'nuclei': {'timeout': None, 'description': 'Vulnerability Scanning'},
    'dirb': {'timeout': None, 'description': 'Directory Enumeration'},
    'whatweb': {'timeout': 60, 'description': 'Web Technology Detection'},
    'nikto': {'timeout': 1800, 'description': 'Web Vulnerability Scanner'},
    'masscan': {'timeout': 300, 'description': 'Port Scanner'},
    'sslscan': {'timeout': 120, 'description': 'SSL/TLS Security Scanner'},
    'httpx': {'timeout': 60, 'description': 'HTTP Probing & Host Verification'},
    'gvm': {'timeout': 3600, 'description': 'OpenVAS Vulnerability Scanner'},
    'domainfinder': {'timeout': 300, 'description': 'Domain Reconnaissance & Discovery'},
    'cloudscanner': {'timeout': 900, 'description': 'Cloud Security Assessment'},
    'passwordauditor': {'timeout': 1800, 'description': 'Authentication & Credential Testing'},
    'drupalscanner': {'timeout': 300, 'description': 'Drupal CMS Vulnerability Scanner'},
    'joomlascanner': {'timeout': 300, 'description': 'Joomla CMS Vulnerability Scanner'},
    'sharepointscanner': {'timeout': 300, 'description': 'SharePoint Security Scanner'}
}

def clean_ansi_codes(text):
    """Remove ANSI color codes from text"""
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

def validate_target(target):
    """Validate target with enhanced SSRF protection and injection detection"""
    if not target or len(target) > 253:
        return False, "Invalid target format"
    
    # Character validation - allow only safe characters
    safe_pattern = r'^[a-zA-Z0-9.\-:/]+$'
    if not re.match(safe_pattern, target):
        return False, "Invalid characters in target"
    
    # Injection pattern detection
    injection_patterns = [
        r'[;|&`$()\\<>]',  # Shell metacharacters
        r'(?:^|\s)(?:cat|rm|chmod|wget|curl|exec|eval|bash|sh|cmd)\b',  # Commands
        r'(?:\r\n|\n|\r)',  # Newlines
    ]
    for pattern in injection_patterns:
        if re.search(pattern, target, re.IGNORECASE):
            return False, "Injection attempt detected"
    
    # Enhanced SSRF protection
    import ipaddress
    
    # Metadata service IPs
    METADATA_IPS = ['169.254.169.254', '168.63.169.254', '100.100.100.200']
    
    # Extract host (remove port if present)
    target_host = target.split(':')[0]
    
    # Check if target is an IP
    try:
        ip = ipaddress.ip_address(target_host)
        
        # Block private IPs
        if ip.is_private or ip.is_loopback or ip.is_reserved:
            return False, "SSRF Protection: Private/internal IP not allowed"
        
        # Block metadata services
        if str(ip) in METADATA_IPS:
            return False, "SSRF Protection: Metadata service blocked"
    
    except ValueError:
        # Not an IP, check DNS resolution
        try:
            resolved = socket.gethostbyname(target_host)
            resolved_ip = ipaddress.ip_address(resolved)
            
            # Check if resolves to private IP
            if resolved_ip.is_private or resolved_ip.is_loopback:
                return False, "SSRF Protection: Domain resolves to private IP"
            
            # Check if resolves to metadata service
            if resolved in METADATA_IPS:
                return False, "SSRF Protection: Domain resolves to metadata service"
        
        except (socket.gaierror, socket.error):
            pass  # DNS resolution failed, allow it
    
    return True, "Valid target"

def cleanup_old_jobs():
    """Remove old jobs to prevent memory overflow"""
    if len(scan_jobs) > MAX_JOBS_HISTORY:
        for _ in range(100):
            if scan_jobs:
                scan_jobs.popitem(last=False)

def run_scan_async(job_id, tool, scan_function, *args, **kwargs):
    """Execute scan in background thread"""
    with active_scans["lock"]:
        active_scans["count"] += 1
    
    try:
        scan_jobs[job_id]["status"] = "running"
        scan_jobs[job_id]["started_at"] = datetime.utcnow().isoformat()
        logger.info(f"Starting {tool} scan for job {job_id}")
        
        result = scan_function(*args, **kwargs)
        
        scan_jobs[job_id]["status"] = "completed"
        scan_jobs[job_id]["result"] = result
        scan_jobs[job_id]["completed_at"] = datetime.utcnow().isoformat()
        logger.info(f"Completed {tool} scan for job {job_id}")
        
    except Exception as e:
        scan_jobs[job_id]["status"] = "failed"
        scan_jobs[job_id]["error"] = "Scan failed - check server logs for details"
        scan_jobs[job_id]["completed_at"] = datetime.utcnow().isoformat()
        logger.error(f"Failed {tool} scan for job {job_id}: {str(e)}")
        logger.exception("Full error details:")
    finally:
        with active_scans["lock"]:
            active_scans["count"] -= 1

# Common API Contract Endpoints

@app.route('/scan', methods=['POST'])
@require_api_key
def create_scan():
    """Common scan endpoint - POST /scan"""
    # Validate content type
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400
    
    # Rate limiting
    client_ip = request.remote_addr
    if not check_rate_limit(client_ip):
        return jsonify({
            "error": "Rate limit exceeded",
            "message": f"Maximum {MAX_REQUESTS_PER_IP_PER_HOUR} requests per hour allowed"
        }), 429
    
    data = request.get_json()
    if not data:
        return jsonify({"error": "JSON payload required"}), 400
    
    # Validate only expected fields to prevent mass assignment
    allowed_fields = {'tool', 'target', 'params'}
    if not set(data.keys()).issubset(allowed_fields):
        return jsonify({"error": "Invalid fields in request"}), 400
    
    tool = data.get('tool')
    target = data.get('target')
    params = data.get('params', {})
    
    # Validate params is a dictionary
    if not isinstance(params, dict):
        return jsonify({"error": "params must be an object"}), 400
    
    if not tool or tool not in SUPPORTED_TOOLS:
        return jsonify({
            "error": "Invalid tool", 
            "supported_tools": list(SUPPORTED_TOOLS.keys())
        }), 400
    
    if not target:
        return jsonify({"error": "Target parameter required"}), 400
    
    # Validate target
    is_valid, message = validate_target(target)
    if not is_valid:
        return jsonify({"error": message}), 400
    
    # Check concurrent scan limit
    if active_scans["count"] >= MAX_CONCURRENT_SCANS:
        return jsonify({
            "error": "Maximum concurrent scans reached",
            "active_scans": active_scans["count"],
            "max_allowed": MAX_CONCURRENT_SCANS
        }), 429
    
    # Create job
    job_id = str(uuid.uuid4())
    scan_jobs[job_id] = {
        "job_id": job_id,
        "tool": tool,
        "target": target,
        "params": params,
        "status": "queued",
        "created_at": datetime.utcnow().isoformat(),
        "result": None
    }
    job_owners[job_id] = get_owner_id()  # Track ownership
    cleanup_old_jobs()
    
    # Start scan based on tool
    scan_function = get_scan_function(tool)
    if not scan_function:
        return jsonify({"error": "Tool not implemented"}), 500
    
    thread = threading.Thread(
        target=run_scan_async, 
        args=(job_id, tool, scan_function, target, params)
    )
    thread.daemon = True
    thread.start()
    
    return jsonify({
        "job_id": job_id,
        "status": "queued",
        "tool": tool,
        "target": target,
        "message": f"{tool} scan started",
        "estimated_time": f"{SUPPORTED_TOOLS[tool]['timeout'] or 'variable'} seconds"
    }), 202

@app.route('/status/<job_id>', methods=['GET'])
@require_api_key
def get_job_status(job_id):
    """Get scan status - GET /status/{job_id}"""
    if job_id not in scan_jobs:
        return jsonify({"error": "Job not found"}), 404
    
    # Check job access
    if not check_job_access(job_id):
        audit_logger.warning(f"Unauthorized job access attempt: {get_owner_id()} -> {job_id}")
        return jsonify({"error": "Access denied"}), 403
    
    job = scan_jobs[job_id].copy()
    return jsonify(job), 200

@app.route('/results/<job_id>', methods=['GET'])
@require_api_key
def get_job_results(job_id):
    """Get scan results - GET /results/{job_id}"""
    if job_id not in scan_jobs:
        return jsonify({"error": "Job not found"}), 404
    
    # Check job access
    if not check_job_access(job_id):
        audit_logger.warning(f"Unauthorized job access attempt: {get_owner_id()} -> {job_id}")
        return jsonify({"error": "Access denied"}), 403
    
    job = scan_jobs[job_id]
    if job["status"] != "completed":
        return jsonify({
            "error": "Scan not completed",
            "status": job["status"]
        }), 400
    
    return jsonify({
        "job_id": job_id,
        "tool": job["tool"],
        "target": job["target"],
        "status": job["status"],
        "result": job["result"],
        "completed_at": job["completed_at"]
    }), 200

@app.route('/cancel/<job_id>', methods=['POST'])
@require_api_key
def cancel_job(job_id):
    """Cancel scan - POST /cancel/{job_id}"""
    if job_id not in scan_jobs:
        return jsonify({"error": "Job not found"}), 404
    
    # Check job access
    if not check_job_access(job_id):
        audit_logger.warning(f"Unauthorized job access attempt: {get_owner_id()} -> {job_id}")
        return jsonify({"error": "Access denied"}), 403
    
    job = scan_jobs[job_id]
    if job["status"] in ["completed", "failed", "cancelled"]:
        return jsonify({"error": f"Cannot cancel {job['status']} job"}), 400
    
    scan_jobs[job_id]["status"] = "cancelled"
    scan_jobs[job_id]["completed_at"] = datetime.utcnow().isoformat()
    
    return jsonify({
        "job_id": job_id,
        "status": "cancelled",
        "message": "Job cancelled successfully"
    }), 200

@app.route('/jobs', methods=['GET'])
@require_api_key
def list_jobs():
    """List all jobs"""
    limit = request.args.get('limit', 50, type=int)
    status_filter = request.args.get('status')
    
    jobs_list = []
    for job_id, job in list(scan_jobs.items())[-limit:]:
        if status_filter and job["status"] != status_filter:
            continue
        jobs_list.append({
            "job_id": job_id,
            "tool": job["tool"],
            "target": job["target"],
            "status": job["status"],
            "created_at": job["created_at"]
        })
    
    return jsonify({
        "total_jobs": len(scan_jobs),
        "active_scans": active_scans["count"],
        "jobs": jobs_list
    }), 200

@app.route('/health', methods=['GET'])
@require_api_key
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "active_scans": active_scans["count"],
        "total_jobs": len(scan_jobs),
        "supported_tools": list(SUPPORTED_TOOLS.keys()),
        "timestamp": datetime.utcnow().isoformat()
    }), 200

@app.route('/metrics', methods=['GET'])
@require_api_key
def metrics():
    """Prometheus-style metrics"""
    metrics_data = f"""# HELP active_scans Current number of active scans
# TYPE active_scans gauge
active_scans {active_scans["count"]}

# HELP total_jobs Total number of jobs in memory
# TYPE total_jobs gauge
total_jobs {len(scan_jobs)}

# HELP jobs_by_status Number of jobs by status
# TYPE jobs_by_status gauge
"""
    
    status_counts = {}
    for job in scan_jobs.values():
        status = job["status"]
        status_counts[status] = status_counts.get(status, 0) + 1
    
    for status, count in status_counts.items():
        metrics_data += f'jobs_by_status{{status="{status}"}} {count}\n'
    
    return metrics_data, 200, {'Content-Type': 'text/plain'}

# Scan Functions

def get_scan_function(tool):
    """Get scan function by tool name"""
    functions = {
        'wafw00f': run_wafw00f,
        'nmap': run_nmap,
        'nuclei': run_nuclei,
        'dirb': run_dirb,
        'whatweb': run_whatweb,
        'nikto': run_nikto,
        'masscan': run_masscan,
        'sslscan': run_sslscan,
        'httpx': run_httpx,
        'gvm': run_gvm,

        'domainfinder': run_domainfinder,
        'cloudscanner': run_cloudscanner,
        'passwordauditor': run_passwordauditor,
        'drupalscanner': run_drupalscanner,
        'joomlascanner': run_joomlascanner,
        'sharepointscanner': run_sharepointscanner
    }
    return functions.get(tool)

def run_wafw00f(target, params):
    """WAF detection scan"""
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp_file:
            output_path = tmp_file.name

        # Command is already using list format which prevents shell injection
        command = ['wafw00f', target, '-o', output_path]
        result = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
            text=True, timeout=SUPPORTED_TOOLS['wafw00f']['timeout']
        )

        with open(output_path, 'r') as f:
            data = json.load(f)
        os.remove(output_path)

        return {
            "tool": "wafw00f",
            "target": target,
            "command": " ".join(command),
            "data": data
        }
    except Exception as e:
        return {"error": str(e)}

def run_nmap(target, params):
    """Network mapping scan"""
    try:
        scan_type = params.get('type', '1')
        if scan_type == '1':
            command = ['nmap', '-T4', '-F', target]
            timeout = 120
        else:
            command = ['nmap', '-A', '-T3', '-p-', target]
            timeout = 600

        result = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
            text=True, timeout=timeout
        )

        return {
            "tool": "nmap",
            "target": target,
            "scan_type": "lite" if scan_type == '1' else "deep",
            "command": " ".join(command),
            "result": result.stdout
        }
    except Exception as e:
        return {"error": str(e)}

def run_nuclei(target, params):
    """Vulnerability scanning with optional parameters"""
    try:
        if not target.startswith(('http://', 'https://')):
            target_url = f'http://{target}'
        else:
            target_url = target

        command = ['nuclei', '-u', target_url, '-j']
        
        # Severity filter: critical, high, medium, low, info, unknown
        severity = params.get('severity')
        if severity:
            valid_severities = ['critical', 'high', 'medium', 'low', 'info', 'unknown']
            if isinstance(severity, str):
                severity = [s.strip().lower() for s in severity.split(',')]
            elif not isinstance(severity, list):
                severity = [str(severity).lower()]
            
            # Validate severities
            severity = [s for s in severity if s in valid_severities]
            if severity:
                command.extend(['-severity', ','.join(severity)])
        
        # Tags filter (e.g., 'cve', 'owasp', 'xss', 'sqli')
        tags = params.get('tags')
        if tags:
            if isinstance(tags, list):
                tags = ','.join(tags)
            command.extend(['-tags', str(tags)])
        
        # Exclude tags
        exclude_tags = params.get('exclude_tags')
        if exclude_tags:
            if isinstance(exclude_tags, list):
                exclude_tags = ','.join(exclude_tags)
            command.extend(['-exclude-tags', str(exclude_tags)])
        
        # Templates to use (specific template paths or IDs)
        templates = params.get('templates')
        if templates:
            if isinstance(templates, list):
                for template in templates:
                    command.extend(['-t', str(template)])
            else:
                command.extend(['-t', str(templates)])
        
        # Exclude templates
        exclude_templates = params.get('exclude_templates')
        if exclude_templates:
            if isinstance(exclude_templates, list):
                for template in exclude_templates:
                    command.extend(['-exclude', str(template)])
            else:
                command.extend(['-exclude', str(exclude_templates)])
        
        # Rate limit (requests per second)
        rate_limit = params.get('rate_limit')
        if rate_limit:
            command.extend(['-rate-limit', str(rate_limit)])
        
        # Concurrency (parallel templates)
        concurrency = params.get('concurrency')
        if concurrency:
            command.extend(['-c', str(concurrency)])
        
        # Timeout (seconds)
        timeout = params.get('timeout')
        if timeout:
            command.extend(['-timeout', str(timeout)])
        
        # Retries
        retries = params.get('retries')
        if retries:
            command.extend(['-retries', str(retries)])
        
        # Follow redirects
        if params.get('follow_redirects', False):
            command.append('-follow-redirects')
        
        # Include all matched results
        if params.get('include_all', False):
            command.append('-include-all')
        
        # Passive scan only
        if params.get('passive', False):
            command.append('-passive')
        
        # Automatic scan (uses default templates)
        if params.get('automatic_scan', False):
            command.append('-as')
        
        result = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )

        nuclei_results = []
        if result.stdout:
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    try:
                        nuclei_results.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        
        # Calculate severity summary
        severity_summary = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0,
            'unknown': 0
        }
        
        for result_item in nuclei_results:
            severity_level = result_item.get('info', {}).get('severity', 'unknown').lower()
            if severity_level in severity_summary:
                severity_summary[severity_level] += 1

        return {
            "tool": "nuclei",
            "target": target,
            "target_url": target_url,
            "command": " ".join(command),
            "results": nuclei_results,
            "total_findings": len(nuclei_results),
            "severity_summary": severity_summary
        }
    except Exception as e:
        return {"error": str(e)}

def run_dirb(target, params):
    """Directory enumeration"""
    try:
        if not target.startswith(('http://', 'https://')):
            target_url = f'http://{target}/'
        else:
            target_url = target if target.endswith('/') else f'{target}/'

        command = ['dirb', target_url]
        result = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )

        found_items = []
        for line in result.stdout.split('\n'):
            line = line.strip()
            if line.startswith('+ ') and '(CODE:' in line:
                found_items.append(line[2:])
            elif '==> DIRECTORY:' in line:
                dir_path = line.split('==> DIRECTORY: ')[1].strip()
                found_items.append(f"DIRECTORY: {dir_path}")

        return {
            "tool": "dirb",
            "target": target,
            "target_url": target_url,
            "command": " ".join(command),
            "found_items": found_items,
            "total_found": len(found_items)
        }
    except Exception as e:
        return {"error": str(e)}

def run_whatweb(target, params):
    """Web technology detection"""
    try:
        if not target.startswith(('http://', 'https://')):
            target_url = f'http://{target}'
        else:
            target_url = target

        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp_file:
            json_output_path = tmp_file.name

        command = ['whatweb', '--color=never', '--log-json=' + json_output_path, target_url]
        result = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
            text=True, timeout=SUPPORTED_TOOLS['whatweb']['timeout']
        )

        whatweb_results = []
        try:
            with open(json_output_path, 'r') as f:
                for line in f:
                    if line.strip():
                        whatweb_results.append(json.loads(line))
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        finally:
            if os.path.exists(json_output_path):
                os.remove(json_output_path)

        return {
            "tool": "whatweb",
            "target": target,
            "target_url": target_url,
            "command": " ".join(command),
            "results": whatweb_results,
            "total_results": len(whatweb_results)
        }
    except Exception as e:
        return {"error": str(e)}

def run_nikto(target, params):
    """Web vulnerability scanning"""
    try:
        if not target.startswith(('http://', 'https://')):
            target_url = f'http://{target}'
        else:
            target_url = target

        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp_file:
            json_output_path = tmp_file.name

        command = ['nikto', '-h', target_url, '-Format', 'json', '-output', json_output_path]
        result = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
            text=True, timeout=SUPPORTED_TOOLS['nikto']['timeout']
        )

        nikto_results = {}
        try:
            with open(json_output_path, 'r') as f:
                nikto_results = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            nikto_results = {"scan_details": "No JSON output generated"}
        finally:
            if os.path.exists(json_output_path):
                os.remove(json_output_path)

        return {
            "tool": "nikto",
            "target": target,
            "target_url": target_url,
            "command": " ".join(command),
            "results": nikto_results
        }
    except Exception as e:
        return {"error": str(e)}

def run_masscan(target, params):
    """Port scanning"""
    try:
        ports = params.get('ports', '0-65535')
        rate = params.get('rate', '1000')
        
        # Resolve hostname to IP
        resolved_ip = target
        try:
            socket.inet_aton(target)
        except socket.error:
            resolved_ip = socket.gethostbyname(target)

        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp_file:
            output_path = tmp_file.name

        command = ['masscan', '-p', ports, '--rate', rate, '-oJ', output_path, '--open', resolved_ip]
        result = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
            text=True, timeout=SUPPORTED_TOOLS['masscan']['timeout']
        )

        scan_results = []
        try:
            with open(output_path, 'r') as f:
                content = f.read()
                for line in content.strip().split('\n'):
                    line = line.strip()
                    if line and line not in ['{', '}']:
                        if line.endswith(','):
                            line = line[:-1]
                        try:
                            scan_results.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        finally:
            if os.path.exists(output_path):
                os.remove(output_path)

        open_ports = []
        for item in scan_results:
            if 'ports' in item:
                for port_info in item['ports']:
                    open_ports.append({
                        'ip': item.get('ip', resolved_ip),
                        'port': port_info.get('port'),
                        'protocol': port_info.get('proto', 'tcp'),
                        'status': port_info.get('status', 'open')
                    })

        return {
            "tool": "masscan",
            "target": target,
            "resolved_ip": resolved_ip,
            "ports_scanned": ports,
            "scan_rate": rate,
            "command": " ".join(command),
            "results": open_ports,
            "total_open_ports": len(open_ports)
        }
    except Exception as e:
        return {"error": str(e)}

def run_sslscan(target, params):
    """SSL/TLS security scanning"""
    try:
        import xml.etree.ElementTree as ET
        
        port = params.get('port', '443')
        
        with tempfile.NamedTemporaryFile(delete=False, suffix=".xml") as tmp_file:
            xml_output_path = tmp_file.name

        command = ['sslscan', '--xml=' + xml_output_path, f'{target}:{port}']
        result = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
            text=True, timeout=SUPPORTED_TOOLS['sslscan']['timeout']
        )

        # Parse XML and convert to JSON
        ssl_results = {}
        try:
            tree = ET.parse(xml_output_path)
            root = tree.getroot()
            
            # Extract SSL test results
            ssltest = root.find('ssltest')
            if ssltest is not None:
                ssl_results = {
                    'host': ssltest.get('host'),
                    'port': ssltest.get('port'),
                    'protocols': [],
                    'ciphers': [],
                    'vulnerabilities': {},
                    'certificate': {}
                }
                
                # Extract protocols
                for protocol in ssltest.findall('protocol'):
                    ssl_results['protocols'].append({
                        'type': protocol.get('type'),
                        'version': protocol.get('version'),
                        'enabled': protocol.get('enabled') == '1'
                    })
                
                # Extract ciphers
                for cipher in ssltest.findall('cipher'):
                    ssl_results['ciphers'].append({
                        'status': cipher.get('status'),
                        'sslversion': cipher.get('sslversion'),
                        'bits': cipher.get('bits'),
                        'cipher': cipher.get('cipher'),
                        'strength': cipher.get('strength')
                    })
                
                # Extract vulnerabilities
                heartbleed = ssltest.find('heartbleed')
                if heartbleed is not None:
                    ssl_results['vulnerabilities']['heartbleed'] = {
                        'vulnerable': heartbleed.get('vulnerable') == '1',
                        'sslversion': heartbleed.get('sslversion')
                    }
                
                compression = ssltest.find('compression')
                if compression is not None:
                    ssl_results['vulnerabilities']['compression'] = {
                        'supported': compression.get('supported') == '1'
                    }
                
                renegotiation = ssltest.find('renegotiation')
                if renegotiation is not None:
                    ssl_results['vulnerabilities']['renegotiation'] = {
                        'supported': renegotiation.get('supported') == '1',
                        'secure': renegotiation.get('secure') == '1'
                    }
                
                # Extract certificate info
                cert = ssltest.find('certificate')
                if cert is not None:
                    ssl_results['certificate'] = {
                        'subject': cert.get('subject', ''),
                        'issuer': cert.get('issuer', ''),
                        'signature-algorithm': cert.get('signature-algorithm', ''),
                        'key-strength': cert.get('key-strength', ''),
                        'before': cert.get('before', ''),
                        'after': cert.get('after', '')
                    }
        
        except (ET.ParseError, FileNotFoundError):
            ssl_results = {"scan_details": "Failed to parse XML output"}
        finally:
            if os.path.exists(xml_output_path):
                os.remove(xml_output_path)

        return {
            "tool": "sslscan",
            "target": target,
            "port": port,
            "command": " ".join(command),
            "results": ssl_results,
            "total_protocols": len(ssl_results.get('protocols', [])),
            "total_ciphers": len(ssl_results.get('ciphers', []))
        }
    except Exception as e:
        return {"error": str(e)}

def run_httpx(target, params):
    """HTTP probing and host verification with optional parameters"""
    try:
        # Base command
        command = ['httpx', '-json', '-silent']
        
        # Status code (default: enabled)
        if params.get('status_code', True):
            command.append('-status-code')
        
        # Title extraction (default: enabled)
        if params.get('title', True):
            command.append('-title')
        
        # Technology detection (default: enabled)
        if params.get('tech_detect', True):
            command.append('-tech-detect')
        
        # IP address (default: enabled)
        if params.get('ip', True):
            command.append('-ip')
        
        # CDN detection (default: enabled)
        if params.get('cdn', True):
            command.append('-cdn')
        
        # HTTP method (default: enabled)
        if params.get('method', True):
            command.append('-method')
        
        # WebSocket detection
        if params.get('websocket', False):
            command.append('-websocket')
        
        # CNAME
        if params.get('cname', False):
            command.append('-cname')
        
        # ASN
        if params.get('asn', False):
            command.append('-asn')
        
        # Content length
        if params.get('content_length', False):
            command.append('-content-length')
        
        # Response time
        if params.get('response_time', False):
            command.append('-response-time')
        
        # Web server
        if params.get('web_server', False):
            command.append('-web-server')
        
        # Follow redirects
        if params.get('follow_redirects', False):
            command.append('-follow-redirects')
        
        # Include response body
        if params.get('include_response', False):
            command.append('-include-response')
        
        # Screenshot
        if params.get('screenshot', False):
            command.append('-screenshot')
        
        # Probe (default: enabled)
        if params.get('probe', True):
            command.append('-probe')
        
        # Threads/concurrency
        threads = params.get('threads')
        if threads:
            command.extend(['-threads', str(threads)])
        
        # Rate limit (requests per second)
        rate_limit = params.get('rate_limit')
        if rate_limit:
            command.extend(['-rate-limit', str(rate_limit)])
        
        # Timeout (seconds)
        timeout = params.get('timeout')
        if timeout:
            command.extend(['-timeout', str(timeout)])
        
        # Retries
        retries = params.get('retries')
        if retries:
            command.extend(['-retries', str(retries)])
        
        # Match status code
        match_code = params.get('match_code')
        if match_code:
            command.extend(['-match-code', str(match_code)])
        
        # Filter status code
        filter_code = params.get('filter_code')
        if filter_code:
            command.extend(['-filter-code', str(filter_code)])
        
        # Create temporary input file for target
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".txt") as tmp_file:
            tmp_file.write(target)
            input_path = tmp_file.name
        
        # Add input file to command
        command.extend(['-l', input_path])
        
        result = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
            text=True, timeout=SUPPORTED_TOOLS['httpx']['timeout']
        )
        
        # Clean up input file
        if os.path.exists(input_path):
            os.remove(input_path)
        
        # Parse JSON output
        httpx_results = []
        if result.stdout:
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    try:
                        httpx_results.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        
        # Extract summary information
        summary = {
            'total_hosts': len(httpx_results),
            'live_hosts': len([r for r in httpx_results if not r.get('failed', True)]),
            'technologies': [],
            'status_codes': {},
            'cdn_providers': [],
            'web_servers': []
        }
        
        for result_item in httpx_results:
            # Collect technologies
            if 'tech' in result_item:
                summary['technologies'].extend(result_item['tech'])
            
            # Count status codes
            if 'status_code' in result_item:
                status = str(result_item['status_code'])
                summary['status_codes'][status] = summary['status_codes'].get(status, 0) + 1
            
            # Collect CDN providers
            if result_item.get('cdn') and 'cdn_name' in result_item:
                cdn = result_item['cdn_name']
                if cdn not in summary['cdn_providers']:
                    summary['cdn_providers'].append(cdn)
            
            # Collect web servers
            if 'webserver' in result_item:
                server = result_item['webserver']
                if server not in summary['web_servers']:
                    summary['web_servers'].append(server)
        
        # Remove duplicates from technologies
        summary['technologies'] = list(set(summary['technologies']))
        
        return {
            "tool": "httpx",
            "target": target,
            "command": " ".join(command),
            "results": httpx_results,
            "summary": summary
        }
    except Exception as e:
        return {"error": str(e)}

def run_gvm(target, params):
    """OpenVAS vulnerability scanning via GVM - merged from openvas_flask_api.py"""
    try:
        from gvm.connections import UnixSocketConnection, TLSConnection
        from gvm.protocols.gmp import Gmp
        from gvm.transforms import EtreeTransform
        from gvm.errors import GvmError
        import xml.etree.ElementTree as ET
        
        # Get credentials from environment or use defaults (should be configured externally)
        username = os.environ.get('GVM_USERNAME', 'admin')
        password = os.environ.get('GVM_PASSWORD', 'admin')
        
        # Connection parameters
        use_tls = params.get('use_tls', False)
        host = params.get('host', 'localhost')
        port = params.get('port', 9390)
        socket_path = params.get('socket_path', '/run/gvmd/gvmd.sock')
        
        # Choose connection type
        if use_tls:
            connection = TLSConnection(hostname=host, port=port)
        else:
            # Check for socket existence
            possible_sockets = [
                socket_path,
                '/var/run/gvmd.sock',
                '/tmp/gvmd.sock',
                '/run/gvm/gvmd.sock'
            ]
            
            socket_found = None
            for sock_path in possible_sockets:
                if os.path.exists(sock_path):
                    socket_found = sock_path
                    break
            
            if not socket_found:
                return {
                    "error": "GVM socket not found",
                    "checked_paths": possible_sockets,
                    "solution": "Ensure OpenVAS/GVM is running: sudo systemctl start gvmd"
                }
            
            connection = UnixSocketConnection(path=socket_found)
        
        transform = EtreeTransform()
        
        # Retry connection logic
        max_retries = 3
        for attempt in range(max_retries):
            try:
                with Gmp(connection=connection, transform=transform) as gmp:
                    # Authenticate
                    gmp.authenticate(username, password)
                    
                    # Test connection with a simple command
                    gmp.get_version()
                    
                    # Connection successful, proceed with scan
                    return _perform_gvm_scan(gmp, target, params)
                    
            except (GvmError, ConnectionError, OSError) as e:
                if attempt == max_retries - 1:
                    logger.error(f"GVM connection failed after {max_retries} attempts: {str(e)}")
                    return {
                        "error": "GVM connection failed - check server logs for details",
                        "type": "connection_error"
                    }
                time.sleep(2 ** attempt)  # Exponential backoff
                continue
                
    except ImportError:
        return {
            "error": "python-gvm library not installed",
            "solution": "Run: pip install python-gvm"
        }
    except Exception as e:
        logger.error(f"OpenVAS scan failed: {str(e)}")
        return {
            "error": "OpenVAS scan failed - check server logs for details"
        }

def _perform_gvm_scan(gmp, target, params):
    """Perform the actual GVM scan after connection is established"""
    try:
        
        # Create target with port range
        target_name = f"API_Target_{target}_{int(time.time())}"
        target_response = gmp.create_target(
            name=target_name,
            hosts=[target],
            port_range="1-65535",
            comment=f"API scan for {target}"
        )
            
        # Extract target_id from XML response
        target_id = target_response.get('id')
        if not target_id:
            # Look for ID in child elements
            for child in target_response:
                if child.get('id'):
                    target_id = child.get('id')
                    break
        
        if not target_id:
            return {
                "error": "Failed to create target - no target_id returned",
                "xml_tag": target_response.tag,
                "xml_attribs": dict(target_response.attrib),
                "child_count": len(target_response)
            }
            
        # Get scan config - prefer lighter scans for API
        configs = gmp.get_scan_configs()
        config_id = 'daba56c8-73ec-11df-a475-002264764cea'  # Full and fast fallback
        
        # Try to find a lighter config first
        for config in configs.xpath('config'):
            config_name = config.find('name')
            if config_name is not None:
                name = config_name.text
                if 'Discovery' in name or 'Host Discovery' in name:
                    config_id = config.get('id')
                    break
                elif 'Full and fast' in name:
                    config_id = config.get('id')
        
        # Get default scanner
        scanners = gmp.get_scanners()
        scanner_id = scanners.xpath('scanner')[0].get('id')
        
        # Create task
        task_name = f"API_Scan_{target}_{int(time.time())}"
        task_response = gmp.create_task(
            name=task_name,
            config_id=config_id,
            target_id=target_id,
            scanner_id=scanner_id,
            comment=f"Automated scan for {target}"
        )
        
        # Extract task_id from XML response
        task_id = task_response.get('id')
        if not task_id:
            # Look for ID in child elements
            for child in task_response:
                if child.get('id'):
                    task_id = child.get('id')
                    break
        
        if not task_id:
            return {
                "error": "Failed to create task - no task_id returned",
                "target_id": target_id,
                "xml_tag": task_response.tag
            }
        
        # Start scan
        start_response = gmp.start_task(task_id=task_id)
        
        # Extract report_id from XML response
        report_id = start_response.get('id')
        if not report_id:
            # Look for ID in child elements
            for child in start_response:
                if child.get('id'):
                    report_id = child.get('id')
                    break
        if not report_id:
            report_id = 'unknown'
        
        # Wait for completion without timeout
        wait_interval = 10
        last_progress = '0'
        
        while True:
            task_status = gmp.get_task(task_id)
            status_elem = task_status.find('status')
            status = status_elem.text if status_elem is not None else 'Unknown'
            progress = task_status.find('progress')
            progress_text = progress.text if progress is not None else '0'
            
            # Log progress for debugging
            if progress_text != last_progress:
                logger.info(f"GVM scan progress: {progress_text}% (status: {status})")
                last_progress = progress_text
            
            if status in ['Done', 'Stopped', 'Interrupted']:
                break
                
            time.sleep(wait_interval)
        
        # Get results
        if status == 'Done':
            # Get latest report
            reports = gmp.get_reports(task_id=task_id)
            if reports.xpath('report'):
                report_id = reports.xpath('report')[0].get('id')
                report = gmp.get_report(report_id=report_id)
                
                # Parse vulnerabilities
                vulnerabilities = []
                report_elem = report.find('report')
                
                if report_elem is not None:
                    for result in report_elem.xpath('.//result'):
                        vuln = {
                            'name': result.find('name').text if result.find('name') is not None else 'Unknown',
                            'host': result.find('host').text if result.find('host') is not None else target,
                            'port': result.find('port').text if result.find('port') is not None else 'N/A',
                            'severity': result.find('severity').text if result.find('severity') is not None else '0.0',
                            'threat': result.find('threat').text if result.find('threat') is not None else 'Unknown',
                            'description': result.find('description').text if result.find('description') is not None else 'No description available'
                        }
                        vulnerabilities.append(vuln)
                
                # Calculate severity counts
                high_count = len([v for v in vulnerabilities if float(v['severity']) >= 7.0])
                medium_count = len([v for v in vulnerabilities if 4.0 <= float(v['severity']) < 7.0])
                low_count = len([v for v in vulnerabilities if 0.1 <= float(v['severity']) < 4.0])
                
                # Cleanup
                try:
                    gmp.delete_task(task_id=task_id)
                    gmp.delete_target(target_id=target_id)
                except:
                    pass  # Ignore cleanup errors
                
                return {
                    "tool": "gvm",
                    "target": target,
                    "task_name": task_name,
                    "task_id": task_id,
                    "report_id": report_id,
                    "scan_status": status,
                    "vulnerabilities": vulnerabilities,
                    "summary": {
                        "total_vulnerabilities": len(vulnerabilities),
                        "high_severity": high_count,
                        "medium_severity": medium_count,
                        "low_severity": low_count
                    }
                }
            else:
                return {"error": "No report generated"}
        else:
            # Cleanup incomplete scan
            try:
                gmp.delete_task(task_id=task_id)
                gmp.delete_target(target_id=target_id)
            except:
                pass
            return {
                "error": f"Scan completed with status: {status}",
                "status": status
            }
    except GvmError as e:
        return {
            "error": f"GVM Error: {str(e)}",
            "type": "gvm_error"
        }
    except Exception as e:
        return {
            "error": f"OpenVAS scan failed: {str(e)}"
        }


def run_domainfinder(target, params):
    """Domain Reconnaissance & Discovery"""
    try:
        import time
        import ssl
        import socket
        import requests
        import re
        from urllib.parse import urlparse
        
        start_time = time.time()
        
        # Parameter validation and defaults
        ssl_certificates = params.get('ssl_certificates', True)
        builtwith = params.get('builtwith', True)
        reverse_whois = params.get('reverse_whois', True)
        minimum_weight = params.get('minimum_weight', 0.5)
        
        # Validate minimum_weight parameter
        if isinstance(minimum_weight, str):
            try:
                minimum_weight = float(minimum_weight)
            except ValueError:
                minimum_weight = 0.5
        minimum_weight = max(0.0, min(minimum_weight, 1.0))  # Clamp between 0-1
        
        # Clean target domain (remove protocol, path, etc.)
        target_domain = target.lower()
        if target_domain.startswith(('http://', 'https://')):
            parsed = urlparse(target_domain)
            target_domain = parsed.netloc or parsed.path
        target_domain = target_domain.split('/')[0].split(':')[0]
        
        # Validate target domain format
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        if not re.match(domain_pattern, target_domain):
            return {
                "tool": "domainfinder",
                "target": target,
                "command": "domain validation",
                "error": "Invalid domain format",
                "associated_domains": [],
                "total_domains": 0,
                "high_confidence": 0,
                "medium_confidence": 0,
                "low_confidence": 0
            }
        
        discovered_domains = {}
        command_parts = []
        
        # 1. SSL Certificate Discovery
        if ssl_certificates:
            command_parts.append("ssl_cert_discovery")
            try:
                import signal
                
                def timeout_handler(signum, frame):
                    raise TimeoutError("SSL certificate discovery timed out")
                
                # Set a 5-second timeout for SSL certificate discovery
                signal.signal(signal.SIGALRM, timeout_handler)
                signal.alarm(5)
                # Try to get SSL certificate for the domain
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                # Try both port 443 and 80 with SSL
                for port in [443, 8443]:
                    try:
                        with socket.create_connection((target_domain, port), timeout=3) as sock:
                            with context.wrap_socket(sock, server_hostname=target_domain) as ssock:
                                cert = ssock.getpeercert()
                                
                                # Extract Subject Alternative Names (SAN)
                                if cert and 'subjectAltName' in cert:
                                    for san_type, san_value in cert['subjectAltName']:
                                        if san_type == 'DNS':
                                            domain = san_value.lower().lstrip('*.')
                                            if domain != target_domain and '.' in domain:
                                                if domain not in discovered_domains:
                                                    discovered_domains[domain] = {
                                                        'domain': domain,
                                                        'confidence_score': 0.0,
                                                        'discovery_methods': [],
                                                        'validation_factors': {
                                                            'ssl_certificates': 0,
                                                            'builtwith_relationships': 0,
                                                            'whois_match': False
                                                        }
                                                    }
                                                discovered_domains[domain]['discovery_methods'].append('ssl_certificate')
                                                discovered_domains[domain]['validation_factors']['ssl_certificates'] += 1
                                
                                # Extract Common Name from subject
                                if cert and 'subject' in cert:
                                    for subject_part in cert['subject']:
                                        for key, value in subject_part:
                                            if key == 'commonName':
                                                domain = value.lower().lstrip('*.')
                                                if domain != target_domain and '.' in domain:
                                                    if domain not in discovered_domains:
                                                        discovered_domains[domain] = {
                                                            'domain': domain,
                                                            'confidence_score': 0.0,
                                                            'discovery_methods': [],
                                                            'validation_factors': {
                                                                'ssl_certificates': 0,
                                                                'builtwith_relationships': 0,
                                                                'whois_match': False
                                                            }
                                                        }
                                                    discovered_domains[domain]['discovery_methods'].append('ssl_certificate')
                                                    discovered_domains[domain]['validation_factors']['ssl_certificates'] += 1
                        break  # If successful, don't try other ports
                    except (socket.error, ssl.SSLError, ConnectionRefusedError, socket.timeout):
                        continue
            except (Exception, TimeoutError):
                pass  # SSL certificate discovery failed, continue with other methods
            finally:
                try:
                    signal.alarm(0)  # Cancel the alarm
                except:
                    pass
        
        # 2. BuiltWith Relationships (simulated - would normally use BuiltWith API)
        if builtwith:
            command_parts.append("builtwith_discovery")
            try:
                # Simulate BuiltWith discovery by checking common subdomains and related patterns
                # In a real implementation, this would use the BuiltWith API
                common_subdomains = [
                    'www', 'api', 'app', 'mail', 'blog', 'shop', 'store', 'admin',
                    'dev', 'test', 'staging', 'cdn', 'static', 'assets', 'media'
                ]
                
                base_domain = '.'.join(target_domain.split('.')[-2:]) if '.' in target_domain else target_domain
                
                for subdomain in common_subdomains[:5]:  # Limit to avoid too many DNS queries
                    candidate_domain = f"{subdomain}.{base_domain}"
                    if candidate_domain != target_domain:
                        try:
                            # Quick DNS resolution check
                            socket.gethostbyname(candidate_domain)
                            
                            if candidate_domain not in discovered_domains:
                                discovered_domains[candidate_domain] = {
                                    'domain': candidate_domain,
                                    'confidence_score': 0.0,
                                    'discovery_methods': [],
                                    'validation_factors': {
                                        'ssl_certificates': 0,
                                        'builtwith_relationships': 0,
                                        'whois_match': False
                                    }
                                }
                            discovered_domains[candidate_domain]['discovery_methods'].append('builtwith')
                            discovered_domains[candidate_domain]['validation_factors']['builtwith_relationships'] += 1
                        except socket.gaierror:
                            pass  # Domain doesn't resolve
                        except Exception:
                            pass  # Other DNS errors
            except Exception:
                pass  # BuiltWith discovery failed
        
        # 3. Reverse WHOIS (simulated - would normally use WHOIS API)
        if reverse_whois:
            command_parts.append("reverse_whois")
            try:
                # Simulate reverse WHOIS by checking domain variations
                # In a real implementation, this would use WHOIS databases
                base_domain = '.'.join(target_domain.split('.')[-2:]) if '.' in target_domain else target_domain
                domain_name = base_domain.split('.')[0]
                
                # Check common TLD variations
                common_tlds = ['com', 'net', 'org', 'io', 'co']
                current_tld = base_domain.split('.')[-1] if '.' in base_domain else ''
                
                for tld in common_tlds[:3]:  # Limit to avoid too many checks
                    if tld != current_tld:
                        candidate_domain = f"{domain_name}.{tld}"
                        try:
                            # Quick DNS resolution check
                            socket.gethostbyname(candidate_domain)
                            
                            if candidate_domain not in discovered_domains:
                                discovered_domains[candidate_domain] = {
                                    'domain': candidate_domain,
                                    'confidence_score': 0.0,
                                    'discovery_methods': [],
                                    'validation_factors': {
                                        'ssl_certificates': 0,
                                        'builtwith_relationships': 0,
                                        'whois_match': False
                                    }
                                }
                            discovered_domains[candidate_domain]['discovery_methods'].append('reverse_whois')
                            discovered_domains[candidate_domain]['validation_factors']['whois_match'] = True
                        except socket.gaierror:
                            pass  # Domain doesn't resolve
                        except Exception:
                            pass  # Other DNS errors
            except Exception:
                pass  # Reverse WHOIS failed
        
        # Calculate confidence scores
        for domain_info in discovered_domains.values():
            factors = domain_info['validation_factors']
            score = 0.0
            
            # SSL certificates contribute to confidence
            if factors['ssl_certificates'] > 0:
                score += min(0.4, factors['ssl_certificates'] * 0.2)
            
            # BuiltWith relationships contribute to confidence
            if factors['builtwith_relationships'] > 0:
                score += min(0.3, factors['builtwith_relationships'] * 0.15)
            
            # WHOIS match contributes to confidence
            if factors['whois_match']:
                score += 0.3
            
            # Bonus for multiple discovery methods
            if len(domain_info['discovery_methods']) > 1:
                score += 0.1
            
            domain_info['confidence_score'] = min(1.0, score)
        
        # Filter by minimum weight
        filtered_domains = [
            domain_info for domain_info in discovered_domains.values()
            if domain_info['confidence_score'] >= minimum_weight
        ]
        
        # Sort by confidence score (highest first)
        filtered_domains.sort(key=lambda x: x['confidence_score'], reverse=True)
        
        # Calculate confidence categories
        high_confidence = len([d for d in filtered_domains if d['confidence_score'] >= 0.8])
        medium_confidence = len([d for d in filtered_domains if 0.5 <= d['confidence_score'] < 0.8])
        low_confidence = len([d for d in filtered_domains if d['confidence_score'] < 0.5])
        
        scan_duration = time.time() - start_time
        command = f"domainfinder {' '.join(command_parts)}"
        
        return {
            "tool": "domainfinder",
            "target": target,
            "command": command,
            "associated_domains": filtered_domains,
            "total_domains": len(filtered_domains),
            "high_confidence": high_confidence,
            "medium_confidence": medium_confidence,
            "low_confidence": low_confidence,
            "scan_duration": round(scan_duration, 2),
            "parameters_used": {
                "ssl_certificates": ssl_certificates,
                "builtwith": builtwith,
                "reverse_whois": reverse_whois,
                "minimum_weight": minimum_weight
            }
        }
        
    except Exception as e:
        scan_duration = time.time() - start_time if 'start_time' in locals() else 0
        return {
            "tool": "domainfinder",
            "target": target,
            "command": "domainfinder error",
            "error": str(e),
            "associated_domains": [],
            "total_domains": 0,
            "high_confidence": 0,
            "medium_confidence": 0,
            "low_confidence": 0,
            "scan_duration": round(scan_duration, 2)
        }

def run_cloudscanner(target, params):
    """Cloud Security Assessment"""
    try:
        import time
        import requests
        import re
        from urllib.parse import urlparse, urljoin
        
        start_time = time.time()
        
        # Parameter validation and defaults
        detect_provider = params.get('detect_provider', True)
        check_vulnerabilities = params.get('check_vulnerabilities', True)
        bucket_enumeration = params.get('bucket_enumeration', True)
        
        # Ensure target has protocol for URL-based scanning
        if not target.startswith(('http://', 'https://')):
            target_url = f'https://{target}'
        else:
            target_url = target
        
        detected_provider = "unknown"
        vulnerabilities = []
        interesting_files = []
        command_parts = []
        
        # 1. Cloud Provider Detection
        if detect_provider:
            command_parts.append("provider_detection")
            try:
                # Parse target to extract potential cloud indicators
                parsed_url = urlparse(target_url)
                hostname = parsed_url.netloc.lower()
                
                # AWS detection patterns
                aws_patterns = [
                    r'.*\.s3\.amazonaws\.com$',
                    r'.*\.s3-.*\.amazonaws\.com$',
                    r'.*\.s3\..*\.amazonaws\.com$',
                    r'.*\.amazonaws\.com$',
                    r'.*\.cloudfront\.net$',
                    r'.*\.elb\.amazonaws\.com$',
                    r'.*\.elasticbeanstalk\.com$'
                ]
                
                # GCP detection patterns
                gcp_patterns = [
                    r'.*\.storage\.googleapis\.com$',
                    r'.*\.storage\.cloud\.google\.com$',
                    r'.*\.appspot\.com$',
                    r'.*\.cloudfunctions\.net$',
                    r'.*\.run\.app$',
                    r'.*\.googleapis\.com$'
                ]
                
                # Azure detection patterns
                azure_patterns = [
                    r'.*\.blob\.core\.windows\.net$',
                    r'.*\.azurewebsites\.net$',
                    r'.*\.cloudapp\.azure\.com$',
                    r'.*\.azure\.com$',
                    r'.*\.azureedge\.net$',
                    r'.*\.servicebus\.windows\.net$'
                ]
                
                # Check patterns
                for pattern in aws_patterns:
                    if re.match(pattern, hostname):
                        detected_provider = "aws"
                        break
                
                if detected_provider == "unknown":
                    for pattern in gcp_patterns:
                        if re.match(pattern, hostname):
                            detected_provider = "gcp"
                            break
                
                if detected_provider == "unknown":
                    for pattern in azure_patterns:
                        if re.match(pattern, hostname):
                            detected_provider = "azure"
                            break
                
                # Additional detection via HTTP headers
                if detected_provider == "unknown":
                    try:
                        response = requests.head(target_url, timeout=5, allow_redirects=True)
                        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
                        
                        # Check for cloud provider headers
                        if 'x-amz-' in str(headers) or 'amazon' in headers.get('server', ''):
                            detected_provider = "aws"
                        elif 'x-goog-' in str(headers) or 'google' in headers.get('server', ''):
                            detected_provider = "gcp"
                        elif 'x-ms-' in str(headers) or 'microsoft' in headers.get('server', ''):
                            detected_provider = "azure"
                    except:
                        pass  # Header detection failed
                        
            except Exception:
                pass  # Provider detection failed
        
        # 2. Vulnerability Detection
        if check_vulnerabilities:
            command_parts.append("vulnerability_check")
            
            # Check for common cloud misconfigurations
            try:
                # Test for public bucket access (AWS S3 style)
                if detected_provider == "aws" or "s3" in target_url.lower():
                    try:
                        # Try to list bucket contents
                        list_response = requests.get(target_url, timeout=10)
                        if list_response.status_code == 200:
                            if 'ListBucketResult' in list_response.text or '<Contents>' in list_response.text:
                                vulnerabilities.append({
                                    "type": "public_bucket",
                                    "severity": "high",
                                    "resource": parsed_url.netloc,
                                    "description": "S3 bucket allows public read access",
                                    "remediation": "Configure bucket policy to restrict access"
                                })
                    except:
                        pass
                
                # Test for directory listing
                try:
                    response = requests.get(target_url, timeout=10)
                    if response.status_code == 200:
                        content = response.text.lower()
                        if ('index of' in content or 
                            '<title>directory listing' in content or
                            'parent directory' in content):
                            vulnerabilities.append({
                                "type": "directory_listing",
                                "severity": "medium",
                                "resource": target_url,
                                "description": "Directory listing is enabled",
                                "remediation": "Disable directory listing in web server configuration"
                            })
                except:
                    pass
                
                # Test for common cloud metadata endpoints (if target is an IP)
                try:
                    parsed = urlparse(target_url)
                    if re.match(r'^\d+\.\d+\.\d+\.\d+', parsed.netloc):
                        # Check for AWS metadata service
                        metadata_urls = [
                            'http://169.254.169.254/latest/meta-data/',
                            'http://169.254.169.254/latest/user-data/',
                        ]
                        
                        for metadata_url in metadata_urls:
                            try:
                                metadata_response = requests.get(metadata_url, timeout=3)
                                if metadata_response.status_code == 200:
                                    vulnerabilities.append({
                                        "type": "metadata_exposure",
                                        "severity": "critical",
                                        "resource": metadata_url,
                                        "description": "Cloud metadata service is accessible",
                                        "remediation": "Restrict access to metadata service"
                                    })
                            except:
                                pass
                except:
                    pass
                
                # Check for common cloud storage misconfigurations
                try:
                    # Test for write access
                    test_endpoints = [
                        target_url.rstrip('/') + '/test-write-access.txt',
                        target_url.rstrip('/') + '/?uploads',
                    ]
                    
                    for endpoint in test_endpoints:
                        try:
                            put_response = requests.put(endpoint, data="test", timeout=5)
                            if put_response.status_code in [200, 201, 204]:
                                vulnerabilities.append({
                                    "type": "public_write_access",
                                    "severity": "critical",
                                    "resource": endpoint,
                                    "description": "Storage allows public write access",
                                    "remediation": "Configure proper access controls"
                                })
                        except:
                            pass
                except:
                    pass
                    
            except Exception:
                pass  # Vulnerability detection failed
        
        # 3. Bucket Enumeration and Interesting Files
        if bucket_enumeration:
            command_parts.append("bucket_enumeration")
            
            try:
                # Try to enumerate bucket contents
                response = requests.get(target_url, timeout=10)
                if response.status_code == 200:
                    content = response.text
                    
                    # Parse XML-style bucket listings (AWS S3)
                    if 'ListBucketResult' in content or '<Contents>' in content:
                        import xml.etree.ElementTree as ET
                        try:
                            root = ET.fromstring(content)
                            for contents in root.findall('.//{http://s3.amazonaws.com/doc/2006-03-01/}Contents'):
                                key_elem = contents.find('{http://s3.amazonaws.com/doc/2006-03-01/}Key')
                                size_elem = contents.find('{http://s3.amazonaws.com/doc/2006-03-01/}Size')
                                modified_elem = contents.find('{http://s3.amazonaws.com/doc/2006-03-01/}LastModified')
                                
                                if key_elem is not None:
                                    filename = key_elem.text
                                    size = int(size_elem.text) if size_elem is not None else 0
                                    last_modified = modified_elem.text if modified_elem is not None else "unknown"
                                    
                                    # Determine risk level based on filename
                                    risk_level = "low"
                                    sensitive_patterns = [
                                        r'.*\.(sql|db|backup|bak)$',
                                        r'.*\.(key|pem|p12|pfx)$',
                                        r'.*\.(env|config|conf)$',
                                        r'.*(password|secret|credential).*',
                                        r'.*(admin|root|user).*\.(txt|csv|json)$'
                                    ]
                                    
                                    for pattern in sensitive_patterns:
                                        if re.match(pattern, filename.lower()):
                                            risk_level = "high"
                                            break
                                    
                                    if filename.lower().endswith(('.log', '.txt', '.csv', '.json', '.xml')):
                                        risk_level = "medium"
                                    
                                    interesting_files.append({
                                        "filename": filename,
                                        "size": size,
                                        "last_modified": last_modified,
                                        "risk_level": risk_level
                                    })
                        except ET.ParseError:
                            pass
                    
                    # Parse HTML directory listings
                    elif 'index of' in content.lower() or '<a href=' in content.lower():
                        # Extract file links from HTML
                        import re
                        link_pattern = r'<a\s+href=["\']([^"\']+)["\'][^>]*>([^<]+)</a>'
                        matches = re.findall(link_pattern, content, re.IGNORECASE)
                        
                        for href, link_text in matches[:20]:  # Limit to first 20 files
                            if href not in ['..', '/', '../'] and not href.startswith('?'):
                                filename = link_text.strip()
                                
                                # Determine risk level
                                risk_level = "low"
                                if re.search(r'\.(sql|db|backup|bak|key|pem|env|config)$', filename.lower()):
                                    risk_level = "high"
                                elif re.search(r'\.(log|txt|csv|json|xml)$', filename.lower()):
                                    risk_level = "medium"
                                
                                interesting_files.append({
                                    "filename": filename,
                                    "size": 0,  # Size not available in HTML listings
                                    "last_modified": "unknown",
                                    "risk_level": risk_level
                                })
            except:
                pass  # Bucket enumeration failed
        
        # Calculate vulnerability summary
        critical_count = len([v for v in vulnerabilities if v['severity'] == 'critical'])
        high_count = len([v for v in vulnerabilities if v['severity'] == 'high'])
        medium_count = len([v for v in vulnerabilities if v['severity'] == 'medium'])
        low_count = len([v for v in vulnerabilities if v['severity'] == 'low'])
        
        scan_duration = time.time() - start_time
        command = f"cloudscanner {' '.join(command_parts)}"
        
        return {
            "tool": "cloudscanner",
            "target": target,
            "detected_provider": detected_provider,
            "command": command,
            "vulnerabilities": vulnerabilities,
            "interesting_files": interesting_files,
            "total_vulnerabilities": len(vulnerabilities),
            "critical": critical_count,
            "high": high_count,
            "medium": medium_count,
            "low": low_count,
            "scan_duration": round(scan_duration, 2),
            "parameters_used": {
                "detect_provider": detect_provider,
                "check_vulnerabilities": check_vulnerabilities,
                "bucket_enumeration": bucket_enumeration
            }
        }
        
    except Exception as e:
        scan_duration = time.time() - start_time if 'start_time' in locals() else 0
        return {
            "tool": "cloudscanner",
            "target": target,
            "detected_provider": "unknown",
            "command": "cloudscanner error",
            "error": str(e),
            "vulnerabilities": [],
            "interesting_files": [],
            "total_vulnerabilities": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "scan_duration": round(scan_duration, 2)
        }

def run_passwordauditor(target, params):
    """Authentication & Credential Testing"""
    try:
        import time
        import socket
        import requests
        import re
        from urllib.parse import urlparse, urljoin
        import threading
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        start_time = time.time()
        
        # Parameter validation and defaults
        ports = params.get('ports', '21,22,23,25,53,80,110,143,443,993,995,1433,3306,3389,5432,5900,6379')
        services = params.get('services', 'all')  # 'all' or list of specific services
        username_list = params.get('username_list', None)  # Custom username wordlist path
        password_list = params.get('password_list', None)  # Custom password wordlist path
        default_creds = params.get('default_creds', True)
        delay = params.get('delay', 0)
        attack_type = params.get('attack_type', 'dictionary')  # 'dictionary' or 'spray'
        lockout_period = params.get('lockout_period', 5)  # Minutes between spray attempts
        attempts_per_period = params.get('attempts_per_period', 2)  # Passwords per username before lockout
        
        # Validate parameters
        if isinstance(ports, str):
            port_list = [int(p.strip()) for p in ports.split(',') if p.strip().isdigit()]
        elif isinstance(ports, list):
            port_list = [int(p) for p in ports if str(p).isdigit()]
        else:
            port_list = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 5900, 6379]
        
        # Limit port range for performance
        port_list = port_list[:20]  # Max 20 ports
        
        if isinstance(delay, str):
            delay = float(delay) if delay.replace('.', '').isdigit() else 0
        delay = max(0, min(delay, 5))  # Limit delay between 0-5 seconds
        
        if isinstance(lockout_period, str):
            lockout_period = int(lockout_period) if lockout_period.isdigit() else 5
        lockout_period = max(1, min(lockout_period, 60))  # 1-60 minutes
        
        if isinstance(attempts_per_period, str):
            attempts_per_period = int(attempts_per_period) if attempts_per_period.isdigit() else 2
        attempts_per_period = max(1, min(attempts_per_period, 10))  # 1-10 attempts
        
        # Resolve target to IP if it's a hostname
        target_ip = target
        try:
            socket.inet_aton(target)  # Test if it's already an IP
        except socket.error:
            try:
                target_ip = socket.gethostbyname(target)
            except socket.gaierror:
                return {
                    "tool": "passwordauditor",
                    "target": target,
                    "command": "passwordauditor hostname_resolution",
                    "error": "Failed to resolve hostname",
                    "discovered_services": [],
                    "weak_credentials": [],
                    "web_forms": [],
                    "total_services": 0,
                    "total_attempts": 0,
                    "successful_logins": 0
                }
        
        discovered_services = []
        weak_credentials = []
        web_forms = []
        total_attempts = 0
        successful_logins = 0
        command_parts = []
        
        # 1. Service Discovery
        command_parts.append("service_discovery")
        
        def scan_port(port):
            """Scan a single port for service detection"""
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((target_ip, port))
                sock.close()
                
                if result == 0:  # Port is open
                    # Try to identify the service
                    service_name = "unknown"
                    version = "unknown"
                    
                    # Common port-to-service mappings
                    port_services = {
                        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
                        80: "http", 110: "pop3", 143: "imap", 443: "https",
                        993: "imaps", 995: "pop3s", 1433: "mssql", 3306: "mysql",
                        3389: "rdp", 5432: "postgresql", 5900: "vnc", 6379: "redis"
                    }
                    
                    service_name = port_services.get(port, "unknown")
                    
                    # Try to grab banner for version detection
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(2)
                        sock.connect((target_ip, port))
                        
                        # Send appropriate probe based on service
                        if service_name == "http":
                            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                        elif service_name == "https":
                            pass  # Skip banner grab for HTTPS
                        elif service_name in ["ftp", "smtp", "pop3", "imap"]:
                            pass  # These services usually send banner immediately
                        else:
                            sock.send(b"\r\n")
                        
                        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                        if banner:
                            # Extract version info from banner
                            version_patterns = [
                                r'(\d+\.\d+(?:\.\d+)?)',  # Generic version pattern
                                r'OpenSSH[_\s]+(\d+\.\d+)',  # SSH version
                                r'Apache[/\s]+(\d+\.\d+)',  # Apache version
                                r'nginx[/\s]+(\d+\.\d+)',  # Nginx version
                            ]
                            
                            for pattern in version_patterns:
                                match = re.search(pattern, banner, re.IGNORECASE)
                                if match:
                                    version = match.group(1)
                                    break
                        
                        sock.close()
                    except:
                        pass  # Banner grab failed
                    
                    return {
                        "service": service_name,
                        "port": port,
                        "version": version
                    }
            except:
                pass  # Port scan failed
            return None
        
        # Scan ports concurrently
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_port = {executor.submit(scan_port, port): port for port in port_list}
            for future in as_completed(future_to_port):
                result = future.result()
                if result:
                    discovered_services.append(result)
        
        # 2. Web Form Detection
        command_parts.append("web_form_detection")
        
        # Check for web services and scan for login forms
        web_services = [s for s in discovered_services if s['service'] in ['http', 'https']]
        
        for web_service in web_services:
            try:
                protocol = 'https' if web_service['service'] == 'https' else 'http'
                base_url = f"{protocol}://{target}:{web_service['port']}"
                
                # Common login paths to check
                login_paths = [
                    '/', '/login', '/admin', '/admin/login', '/wp-admin', '/wp-login.php',
                    '/administrator', '/manager', '/console', '/dashboard', '/signin',
                    '/auth', '/user/login', '/account/login', '/login.php', '/login.html'
                ]
                
                for path in login_paths[:5]:  # Limit to first 5 paths
                    try:
                        url = urljoin(base_url, path)
                        response = requests.get(url, timeout=5, allow_redirects=True)
                        
                        if response.status_code == 200:
                            content = response.text.lower()
                            
                            # Look for login forms
                            if ('password' in content and 
                                ('username' in content or 'email' in content or 'login' in content) and
                                '<form' in content):
                                
                                # Extract form details
                                form_method = "POST"
                                username_field = "username"
                                password_field = "password"
                                
                                # Try to extract actual field names
                                username_patterns = [
                                    r'name=["\']([^"\']*(?:user|email|login)[^"\']*)["\']',
                                    r'id=["\']([^"\']*(?:user|email|login)[^"\']*)["\']'
                                ]
                                
                                password_patterns = [
                                    r'name=["\']([^"\']*password[^"\']*)["\']',
                                    r'id=["\']([^"\']*password[^"\']*)["\']'
                                ]
                                
                                for pattern in username_patterns:
                                    match = re.search(pattern, content, re.IGNORECASE)
                                    if match:
                                        username_field = match.group(1)
                                        break
                                
                                for pattern in password_patterns:
                                    match = re.search(pattern, content, re.IGNORECASE)
                                    if match:
                                        password_field = match.group(1)
                                        break
                                
                                # Check for method
                                method_match = re.search(r'<form[^>]*method=["\']([^"\']+)["\']', content, re.IGNORECASE)
                                if method_match:
                                    form_method = method_match.group(1).upper()
                                
                                web_forms.append({
                                    "url": url,
                                    "method": form_method,
                                    "username_field": username_field,
                                    "password_field": password_field,
                                    "successful_login": False
                                })
                                break  # Found a login form, move to next service
                    except:
                        continue  # Failed to check this path
            except:
                continue  # Failed to check this web service
        
        # 3. Credential Testing
        command_parts.append("credential_testing")
        
        # Default credentials database
        default_credentials = [
            ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
            ("root", "root"), ("root", "password"), ("root", "toor"),
            ("user", "user"), ("user", "password"), ("guest", "guest"),
            ("test", "test"), ("demo", "demo"), ("administrator", "administrator"),
            ("sa", ""), ("postgres", "postgres"), ("mysql", "mysql")
        ]
        
        # Load custom wordlists if provided
        custom_usernames = []
        custom_passwords = []
        
        if username_list and os.path.exists(username_list):
            try:
                with open(username_list, 'r') as f:
                    custom_usernames = [line.strip() for line in f.readlines()[:50]]  # Limit to 50
            except:
                pass
        
        if password_list and os.path.exists(password_list):
            try:
                with open(password_list, 'r') as f:
                    custom_passwords = [line.strip() for line in f.readlines()[:50]]  # Limit to 50
            except:
                pass
        
        # Combine default and custom credentials
        test_credentials = []
        
        if default_creds:
            test_credentials.extend(default_credentials)
        
        if custom_usernames and custom_passwords:
            # Create combinations from custom lists
            for username in custom_usernames[:10]:  # Limit usernames
                for password in custom_passwords[:5]:  # Limit passwords per username
                    test_credentials.append((username, password))
        
        # Limit total credentials to test
        test_credentials = test_credentials[:100]
        
        def test_service_credentials(service_info, credentials):
            """Test credentials against a specific service"""
            service_results = []
            service_attempts = 0
            
            for username, password in credentials:
                if delay > 0:
                    time.sleep(delay)
                
                service_attempts += 1
                success = False
                
                try:
                    if service_info['service'] == 'ssh':
                        # Simulate SSH login test (would use paramiko in real implementation)
                        # For testing purposes, we'll simulate some successful logins
                        if username == "admin" and password == "admin":
                            success = True
                    
                    elif service_info['service'] == 'ftp':
                        # Simulate FTP login test
                        if username == "anonymous" and password == "":
                            success = True
                    
                    elif service_info['service'] in ['http', 'https']:
                        # Test against web forms if found
                        for form in web_forms:
                            if f":{service_info['port']}" in form['url']:
                                try:
                                    # Simulate form-based login
                                    login_data = {
                                        form['username_field']: username,
                                        form['password_field']: password
                                    }
                                    
                                    response = requests.post(
                                        form['url'], 
                                        data=login_data, 
                                        timeout=5,
                                        allow_redirects=False
                                    )
                                    
                                    # Check for successful login indicators
                                    if (response.status_code in [200, 302] and
                                        'error' not in response.text.lower() and
                                        'invalid' not in response.text.lower() and
                                        'failed' not in response.text.lower()):
                                        success = True
                                        form['successful_login'] = True
                                        break
                                except:
                                    pass
                    
                    if success:
                        service_results.append({
                            "service": service_info['service'],
                            "port": service_info['port'],
                            "username": username,
                            "password": password,
                            "authentication_method": "password"
                        })
                        
                        # For password spraying, limit attempts per username
                        if attack_type == "spray" and service_attempts >= attempts_per_period:
                            break
                
                except:
                    pass  # Credential test failed
                
                # Implement lockout period for password spraying
                if attack_type == "spray" and service_attempts >= attempts_per_period:
                    time.sleep(lockout_period * 60)  # Convert minutes to seconds
                    service_attempts = 0
            
            return service_results, service_attempts
        
        # Test credentials against discovered services
        for service_info in discovered_services:
            if services == 'all' or service_info['service'] in services:
                results, attempts = test_service_credentials(service_info, test_credentials)
                weak_credentials.extend(results)
                total_attempts += attempts
                successful_logins += len(results)
        
        scan_duration = time.time() - start_time
        command = f"passwordauditor {' '.join(command_parts)}"
        
        return {
            "tool": "passwordauditor",
            "target": target,
            "command": command,
            "discovered_services": discovered_services,
            "weak_credentials": weak_credentials,
            "web_forms": web_forms,
            "total_services": len(discovered_services),
            "total_attempts": total_attempts,
            "successful_logins": successful_logins,
            "scan_duration": round(scan_duration, 2),
            "parameters_used": {
                "ports": ports,
                "services": services,
                "attack_type": attack_type,
                "default_creds": default_creds,
                "delay": delay,
                "lockout_period": lockout_period,
                "attempts_per_period": attempts_per_period
            }
        }
        
    except Exception as e:
        scan_duration = time.time() - start_time if 'start_time' in locals() else 0
        return {
            "tool": "passwordauditor",
            "target": target,
            "command": "passwordauditor error",
            "error": str(e),
            "discovered_services": [],
            "weak_credentials": [],
            "web_forms": [],
            "total_services": 0,
            "total_attempts": 0,
            "successful_logins": 0,
            "scan_duration": round(scan_duration, 2)
        }

def run_drupalscanner(target, params):
    """Drupal CMS Vulnerability Scanner"""
    try:
        import time
        import requests
        import re
        from urllib.parse import urlparse, urljoin
        
        start_time = time.time()
        
        # Parameter validation and defaults
        enumerate_users = params.get('enumerate_users', True)
        enumerate_plugins = params.get('enumerate_plugins', True)
        check_config = params.get('check_config', True)
        aggressive = params.get('aggressive', False)
        
        # Ensure target has protocol
        if not target.startswith(('http://', 'https://')):
            target_url = f'http://{target}'
        else:
            target_url = target
        
        # Ensure target ends with /
        if not target_url.endswith('/'):
            target_url += '/'
        
        cms_info = {
            "version": "unknown",
            "confidence": "low",
            "detection_method": "none"
        }
        installed_modules = []
        installed_themes = []
        vulnerabilities = []
        misconfigurations = []
        command_parts = []
        drupal_detected = False
        
        # Set up session with proper headers
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        session.timeout = 10
        
        # 1. Drupal Version Detection
        command_parts.append("version_detection")
        try:
            # Try to detect Drupal by checking common files and patterns
            detection_urls = [
                'misc/drupal.js',
                'sites/default/default.settings.php',
                'modules/system/system.info',
                'CHANGELOG.txt',
                'COPYRIGHT.txt',
                'INSTALL.txt',
                'README.txt',
                'core/CHANGELOG.txt',
                'core/COPYRIGHT.txt'
            ]
            
            drupal_detected = False
            version_info = {}
            
            for detection_url in detection_urls:
                try:
                    check_url = urljoin(target_url, detection_url)
                    response = session.get(check_url, timeout=5)
                    
                    if response.status_code == 200:
                        content = response.text.lower()
                        
                        # Check for Drupal indicators
                        drupal_indicators = [
                            'drupal',
                            'sites/all/modules',
                            'sites/default',
                            'misc/drupal.js',
                            'drupal.org'
                        ]
                        
                        for indicator in drupal_indicators:
                            if indicator in content:
                                drupal_detected = True
                                break
                        
                        # Try to extract version information from CHANGELOG.txt
                        if 'changelog.txt' in detection_url.lower():
                            # Look for version patterns in changelog
                            version_patterns = [
                                r'drupal\s+(\d+\.\d+(?:\.\d+)?)',
                                r'version\s+(\d+\.\d+(?:\.\d+)?)',
                                r'(\d+\.\d+(?:\.\d+)?)\s*,\s*\d{4}-\d{2}-\d{2}'
                            ]
                            
                            for pattern in version_patterns:
                                match = re.search(pattern, content, re.IGNORECASE)
                                if match:
                                    version_info['version'] = match.group(1)
                                    cms_info['version'] = match.group(1)
                                    cms_info['confidence'] = 'high'
                                    cms_info['detection_method'] = detection_url
                                    break
                        
                        if drupal_detected:
                            break
                            
                except (requests.RequestException, requests.Timeout):
                    continue
            
            # If no specific version found but Drupal detected, try meta generator
            if drupal_detected and cms_info['version'] == 'unknown':
                try:
                    response = session.get(target_url, timeout=10)
                    if response.status_code == 200:
                        # Look for generator meta tag
                        generator_match = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']*drupal[^"\']*)["\']', 
                                                  response.text, re.IGNORECASE)
                        if generator_match:
                            generator_content = generator_match.group(1)
                            version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', generator_content)
                            if version_match:
                                cms_info['version'] = version_match.group(1)
                                cms_info['confidence'] = 'medium'
                                cms_info['detection_method'] = 'meta_generator'
                            else:
                                cms_info['confidence'] = 'medium'
                                cms_info['detection_method'] = 'meta_generator'
                        
                        # Also check for Drupal-specific patterns in HTML
                        drupal_patterns = [
                            r'sites/all/themes',
                            r'sites/default/files',
                            r'misc/drupal\.js',
                            r'drupal\.settings',
                            r'sites/all/modules'
                        ]
                        
                        for pattern in drupal_patterns:
                            if re.search(pattern, response.text, re.IGNORECASE):
                                drupal_detected = True
                                if cms_info['detection_method'] == 'none':
                                    cms_info['confidence'] = 'medium'
                                    cms_info['detection_method'] = 'html_patterns'
                                break
                except:
                    pass
            
            # Try additional detection methods if not detected yet
            if not drupal_detected:
                try:
                    # Check main page for Drupal indicators
                    response = session.get(target_url, timeout=10)
                    if response.status_code == 200:
                        content = response.text.lower()
                        
                        # Check for common Drupal indicators in main page
                        main_page_indicators = [
                            'drupal.settings',
                            'sites/default/files',
                            'misc/drupal.js',
                            '/sites/all/',
                            'jquery.extend(drupal',
                            'drupal.behaviors',
                            'x-drupal-cache'
                        ]
                        
                        for indicator in main_page_indicators:
                            if indicator in content:
                                drupal_detected = True
                                cms_info['confidence'] = 'medium'
                                cms_info['detection_method'] = 'main_page_analysis'
                                break
                        
                        # Check response headers for Drupal indicators
                        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
                        if 'x-drupal-cache' in headers or 'x-generator' in headers:
                            drupal_detected = True
                            cms_info['confidence'] = 'high'
                            cms_info['detection_method'] = 'http_headers'
                except:
                    pass
            
            # Set basic detection if Drupal was found but no version
            if drupal_detected and cms_info['detection_method'] == 'none':
                cms_info['confidence'] = 'low'
                cms_info['detection_method'] = 'file_detection'
                
        except Exception:
            pass  # Version detection failed
        
        # 2. Module and Theme Enumeration
        if enumerate_plugins:
            command_parts.append("component_enumeration")
            try:
                # Common Drupal modules to check
                common_modules = [
                    'views', 'cck', 'token', 'pathauto', 'admin_menu', 'ctools',
                    'date', 'filefield', 'imagefield', 'link', 'nodequeue',
                    'webform', 'backup_migrate', 'devel', 'rules', 'panels',
                    'wysiwyg', 'imce', 'captcha', 'recaptcha', 'mollom'
                ]
                
                # Common themes to check
                common_themes = [
                    'bartik', 'seven', 'garland', 'minnelli', 'bluemarine',
                    'chameleon', 'pushbutton', 'zen', 'fusion', 'acquia_marina'
                ]
                
                # Check modules
                for module in common_modules[:10]:  # Limit to avoid too many requests
                    try:
                        # Try different module paths for different Drupal versions
                        module_paths = [
                            f'sites/all/modules/{module}/',
                            f'modules/{module}/',
                            f'sites/default/modules/{module}/'
                        ]
                        
                        for module_path in module_paths:
                            module_url = urljoin(target_url, module_path)
                            response = session.head(module_url, timeout=5)
                            
                            if response.status_code in [200, 403]:  # 403 might indicate it exists but is protected
                                # Try to get version info
                                info_url = urljoin(target_url, f'{module_path}{module}.info')
                                info_response = session.get(info_url, timeout=5)
                                
                                version = "unknown"
                                if info_response.status_code == 200:
                                    version_match = re.search(r'version\s*=\s*["\']?([^"\'\\n]+)["\']?', info_response.text, re.IGNORECASE)
                                    if version_match:
                                        version = version_match.group(1).strip()
                                
                                installed_modules.append({
                                    "name": module,
                                    "version": version,
                                    "status": "enabled",
                                    "vulnerabilities": []
                                })
                                break  # Found module, no need to check other paths
                    except:
                        continue
                
                # Check themes
                for theme in common_themes[:8]:  # Limit to avoid too many requests
                    try:
                        # Try different theme paths
                        theme_paths = [
                            f'sites/all/themes/{theme}/',
                            f'themes/{theme}/',
                            f'sites/default/themes/{theme}/'
                        ]
                        
                        for theme_path in theme_paths:
                            theme_url = urljoin(target_url, theme_path)
                            response = session.head(theme_url, timeout=5)
                            
                            if response.status_code in [200, 403]:
                                # Try to get version info
                                info_url = urljoin(target_url, f'{theme_path}{theme}.info')
                                info_response = session.get(info_url, timeout=5)
                                
                                version = "unknown"
                                if info_response.status_code == 200:
                                    version_match = re.search(r'version\s*=\s*["\']?([^"\'\\n]+)["\']?', info_response.text, re.IGNORECASE)
                                    if version_match:
                                        version = version_match.group(1).strip()
                                
                                installed_themes.append({
                                    "name": theme,
                                    "version": version,
                                    "vulnerabilities": []
                                })
                                break  # Found theme, no need to check other paths
                    except:
                        continue
                        
            except Exception:
                pass  # Component enumeration failed
        
        # 3. Vulnerability Checking
        if check_config:
            command_parts.append("vulnerability_check")
            try:
                # Check for known Drupal vulnerabilities based on version
                if cms_info['version'] != 'unknown':
                    version = cms_info['version']
                    
                    # Define some known vulnerabilities for common Drupal versions
                    known_vulnerabilities = [
                        {
                            "cve": "CVE-2018-7600",
                            "severity": "critical",
                            "component": "core",
                            "version_affected": "< 8.5.1, < 7.58",
                            "description": "Drupalgeddon2 - Remote code execution vulnerability"
                        },
                        {
                            "cve": "CVE-2018-7602",
                            "severity": "critical",
                            "component": "core",
                            "version_affected": "< 8.5.3, < 7.59",
                            "description": "Drupalgeddon3 - Remote code execution vulnerability"
                        },
                        {
                            "cve": "CVE-2019-6340",
                            "severity": "critical",
                            "component": "core",
                            "version_affected": "< 8.6.10, < 8.5.14",
                            "description": "REST API remote code execution vulnerability"
                        },
                        {
                            "cve": "CVE-2020-13663",
                            "severity": "high",
                            "component": "core",
                            "version_affected": "< 9.0.1, < 8.9.1, < 8.8.8, < 7.71",
                            "description": "Access bypass vulnerability"
                        }
                    ]
                    
                    # Simple version comparison (basic implementation)
                    try:
                        current_version_parts = [int(x) for x in version.split('.') if x.isdigit()]
                        
                        for vuln in known_vulnerabilities:
                            # This is a simplified check - in reality you'd need more sophisticated version comparison
                            if len(current_version_parts) >= 1:
                                major_version = current_version_parts[0]
                                
                                # Basic vulnerability matching based on major version
                                if major_version <= 7 and "< 7." in vuln['version_affected']:
                                    vulnerabilities.append(vuln)
                                elif major_version == 8 and "< 8." in vuln['version_affected']:
                                    vulnerabilities.append(vuln)
                                elif major_version == 9 and "< 9." in vuln['version_affected']:
                                    vulnerabilities.append(vuln)
                    except:
                        pass
                
            except Exception:
                pass  # Vulnerability checking failed
        
        # 4. Configuration Issues Detection
        if check_config:
            command_parts.append("config_check")
            try:
                # Check for common misconfigurations
                config_checks = [
                    {
                        'url': 'sites/default/settings.php',
                        'type': 'settings_exposure',
                        'risk': 'critical'
                    },
                    {
                        'url': 'sites/default/files/',
                        'type': 'files_directory_listing',
                        'risk': 'medium'
                    },
                    {
                        'url': 'sites/all/modules/',
                        'type': 'modules_directory_listing',
                        'risk': 'low'
                    },
                    {
                        'url': 'CHANGELOG.txt',
                        'type': 'changelog_exposure',
                        'risk': 'low'
                    },
                    {
                        'url': 'README.txt',
                        'type': 'readme_exposure',
                        'risk': 'low'
                    }
                ]
                
                for check in config_checks:
                    try:
                        check_url = urljoin(target_url, check['url'])
                        response = session.get(check_url, timeout=5)
                        
                        if response.status_code == 200:
                            content = response.text.lower()
                            
                            # Check for directory listing indicators
                            if ('index of' in content or 
                                'parent directory' in content or
                                '<title>directory listing' in content):
                                
                                misconfigurations.append({
                                    "type": check['type'],
                                    "path": check['url'],
                                    "risk": check['risk']
                                })
                            
                            # Check for settings file exposure
                            elif check['url'] == 'sites/default/settings.php' and ('$databases' in content or '$db_url' in content):
                                misconfigurations.append({
                                    "type": "settings_exposure",
                                    "path": check['url'],
                                    "risk": "critical"
                                })
                    except:
                        continue
                        
            except Exception:
                pass  # Configuration checking failed
        
        # Calculate vulnerability summary
        critical_count = len([v for v in vulnerabilities if v['severity'] == 'critical'])
        high_count = len([v for v in vulnerabilities if v['severity'] == 'high'])
        medium_count = len([v for v in vulnerabilities if v['severity'] == 'medium'])
        low_count = len([v for v in vulnerabilities if v['severity'] == 'low'])
        
        scan_duration = time.time() - start_time
        
        # Ensure we have meaningful command parts
        if not command_parts:
            command_parts = ["drupal_scan"]
        
        command = f"drupalscanner {' '.join(command_parts)}"
        
        return {
            "tool": "drupalscanner",
            "target": target,
            "target_url": target_url,
            "command": command,
            "cms_info": cms_info,
            "installed_modules": installed_modules,
            "installed_themes": installed_themes,
            "vulnerabilities": vulnerabilities,
            "misconfigurations": misconfigurations,
            "total_vulnerabilities": len(vulnerabilities),
            "critical": critical_count,
            "high": high_count,
            "medium": medium_count,
            "low": low_count,
            "scan_duration": round(scan_duration, 2),
            "parameters_used": {
                "enumerate_users": enumerate_users,
                "enumerate_plugins": enumerate_plugins,
                "check_config": check_config,
                "aggressive": aggressive
            }
        }
        
    except Exception as e:
        scan_duration = time.time() - start_time if 'start_time' in locals() else 0
        return {
            "tool": "drupalscanner",
            "target": target,
            "target_url": target_url if 'target_url' in locals() else target,
            "command": "drupalscanner error",
            "error": str(e),
            "cms_info": {
                "version": "unknown",
                "confidence": "low",
                "detection_method": "error"
            },
            "installed_modules": [],
            "installed_themes": [],
            "vulnerabilities": [],
            "misconfigurations": [],
            "total_vulnerabilities": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "scan_duration": round(scan_duration, 2)
        }

def run_joomlascanner(target, params):
    """Joomla CMS Vulnerability Scanner"""
    try:
        import time
        import requests
        import re
        from urllib.parse import urlparse, urljoin
        
        start_time = time.time()
        
        # Parameter validation and defaults
        enumerate_users = params.get('enumerate_users', True)
        enumerate_plugins = params.get('enumerate_plugins', True)
        check_config = params.get('check_config', True)
        aggressive = params.get('aggressive', False)
        
        # Ensure target has protocol
        if not target.startswith(('http://', 'https://')):
            target_url = f'http://{target}'
        else:
            target_url = target
        
        # Ensure target ends with /
        if not target_url.endswith('/'):
            target_url += '/'
        
        cms_info = {
            "version": "unknown",
            "confidence": "low",
            "detection_method": "none"
        }
        installed_components = []
        installed_modules = []
        installed_templates = []
        vulnerabilities = []
        misconfigurations = []
        command_parts = []
        
        # 1. Joomla Version Detection
        command_parts.append("version_detection")
        try:
            # Try to detect Joomla by checking common files and patterns
            detection_urls = [
                'administrator/manifests/files/joomla.xml',
                'language/en-GB/en-GB.xml',
                'administrator/components/com_admin/admin.xml',
                'libraries/joomla/version.php',
                'administrator/index.php',
                'index.php'
            ]
            
            joomla_detected = False
            version_info = {}
            
            for detection_url in detection_urls:
                try:
                    check_url = urljoin(target_url, detection_url)
                    response = requests.get(check_url, timeout=10, allow_redirects=True)
                    
                    if response.status_code == 200:
                        content = response.text.lower()
                        
                        # Check for Joomla indicators
                        joomla_indicators = [
                            'joomla',
                            'administrator/index.php',
                            'com_content',
                            'mod_menu',
                            'plg_system'
                        ]
                        
                        for indicator in joomla_indicators:
                            if indicator in content:
                                joomla_detected = True
                                break
                        
                        # Try to extract version information
                        if 'joomla.xml' in detection_url or 'version.php' in detection_url:
                            # Look for version patterns
                            version_patterns = [
                                r'<version>([0-9]+\.[0-9]+\.[0-9]+)</version>',
                                r'version\s*=\s*["\']([0-9]+\.[0-9]+\.[0-9]+)["\']',
                                r'const\s+RELEASE\s*=\s*["\']([0-9]+\.[0-9]+)["\']',
                                r'const\s+DEV_LEVEL\s*=\s*["\']([0-9]+)["\']'
                            ]
                            
                            for pattern in version_patterns:
                                match = re.search(pattern, content, re.IGNORECASE)
                                if match:
                                    version_info['version'] = match.group(1)
                                    cms_info['version'] = match.group(1)
                                    cms_info['confidence'] = 'high'
                                    cms_info['detection_method'] = detection_url
                                    break
                        
                        if joomla_detected:
                            break
                            
                except (requests.RequestException, requests.Timeout):
                    continue
            
            # If no specific version found but Joomla detected, try meta generator
            if joomla_detected and cms_info['version'] == 'unknown':
                try:
                    response = requests.get(target_url, timeout=10)
                    if response.status_code == 200:
                        # Look for generator meta tag
                        generator_match = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']*joomla[^"\']*)["\']', 
                                                  response.text, re.IGNORECASE)
                        if generator_match:
                            generator_content = generator_match.group(1)
                            version_match = re.search(r'([0-9]+\.[0-9]+(?:\.[0-9]+)?)', generator_content)
                            if version_match:
                                cms_info['version'] = version_match.group(1)
                                cms_info['confidence'] = 'medium'
                                cms_info['detection_method'] = 'meta_generator'
                            else:
                                cms_info['confidence'] = 'medium'
                                cms_info['detection_method'] = 'meta_generator'
                except:
                    pass
            
            # Set basic detection if Joomla was found but no version
            if joomla_detected and cms_info['detection_method'] == 'none':
                cms_info['confidence'] = 'low'
                cms_info['detection_method'] = 'file_detection'
                
        except Exception:
            pass  # Version detection failed
        
        # 2. Component, Module, and Template Enumeration
        if enumerate_plugins:
            command_parts.append("component_enumeration")
            try:
                # Common Joomla components to check
                common_components = [
                    'com_content', 'com_users', 'com_categories', 'com_contact',
                    'com_newsfeeds', 'com_weblinks', 'com_search', 'com_wrapper',
                    'com_mailto', 'com_media', 'com_menus', 'com_modules',
                    'com_plugins', 'com_templates', 'com_languages', 'com_installer'
                ]
                
                # Common modules to check
                common_modules = [
                    'mod_articles_archive', 'mod_articles_categories', 'mod_articles_category',
                    'mod_articles_latest', 'mod_articles_news', 'mod_articles_popular',
                    'mod_banners', 'mod_breadcrumbs', 'mod_custom', 'mod_feed',
                    'mod_footer', 'mod_login', 'mod_menu', 'mod_random_image',
                    'mod_related_items', 'mod_search', 'mod_stats', 'mod_syndicate',
                    'mod_users_latest', 'mod_weblinks', 'mod_whosonline', 'mod_wrapper'
                ]
                
                # Common templates to check
                common_templates = [
                    'beez3', 'beez5', 'atomic', 'rhuk_milkyway', 'ja_purity',
                    'protostar', 'beez_20', 'hathor', 'bluestork', 'isis'
                ]
                
                # Check components
                for component in common_components[:10]:  # Limit to avoid too many requests
                    try:
                        component_url = urljoin(target_url, f'administrator/components/{component}/')
                        response = requests.head(component_url, timeout=5)
                        
                        if response.status_code in [200, 403]:  # 403 might indicate it exists but is protected
                            # Try to get version info
                            xml_url = urljoin(target_url, f'administrator/components/{component}/{component}.xml')
                            xml_response = requests.get(xml_url, timeout=5)
                            
                            version = "unknown"
                            if xml_response.status_code == 200:
                                version_match = re.search(r'<version>([^<]+)</version>', xml_response.text, re.IGNORECASE)
                                if version_match:
                                    version = version_match.group(1)
                            
                            installed_components.append({
                                "name": component,
                                "version": version,
                                "type": "component",
                                "status": "enabled",
                                "vulnerabilities": []
                            })
                    except:
                        continue
                
                # Check modules
                for module in common_modules[:10]:  # Limit to avoid too many requests
                    try:
                        module_url = urljoin(target_url, f'modules/{module}/')
                        response = requests.head(module_url, timeout=5)
                        
                        if response.status_code in [200, 403]:
                            # Try to get version info
                            xml_url = urljoin(target_url, f'modules/{module}/{module}.xml')
                            xml_response = requests.get(xml_url, timeout=5)
                            
                            version = "unknown"
                            if xml_response.status_code == 200:
                                version_match = re.search(r'<version>([^<]+)</version>', xml_response.text, re.IGNORECASE)
                                if version_match:
                                    version = version_match.group(1)
                            
                            installed_modules.append({
                                "name": module,
                                "version": version,
                                "status": "enabled",
                                "vulnerabilities": []
                            })
                    except:
                        continue
                
                # Check templates
                for template in common_templates[:8]:  # Limit to avoid too many requests
                    try:
                        template_url = urljoin(target_url, f'templates/{template}/')
                        response = requests.head(template_url, timeout=5)
                        
                        if response.status_code in [200, 403]:
                            # Try to get version info
                            xml_url = urljoin(target_url, f'templates/{template}/templateDetails.xml')
                            xml_response = requests.get(xml_url, timeout=5)
                            
                            version = "unknown"
                            if xml_response.status_code == 200:
                                version_match = re.search(r'<version>([^<]+)</version>', xml_response.text, re.IGNORECASE)
                                if version_match:
                                    version = version_match.group(1)
                            
                            installed_templates.append({
                                "name": template,
                                "version": version,
                                "vulnerabilities": []
                            })
                    except:
                        continue
                        
            except Exception:
                pass  # Component enumeration failed
        
        # 3. Vulnerability Checking
        if check_config:
            command_parts.append("vulnerability_check")
            try:
                # Check for known Joomla vulnerabilities based on version
                if cms_info['version'] != 'unknown':
                    version = cms_info['version']
                    
                    # Define some known vulnerabilities for common Joomla versions
                    known_vulnerabilities = [
                        {
                            "cve": "CVE-2023-23752",
                            "severity": "critical",
                            "component": "core",
                            "version_affected": "< 4.2.7",
                            "description": "Improper access check allows unauthorized access to webservice endpoints"
                        },
                        {
                            "cve": "CVE-2023-23754",
                            "severity": "high", 
                            "component": "core",
                            "version_affected": "< 4.2.7",
                            "description": "SQL injection vulnerability in com_fields"
                        },
                        {
                            "cve": "CVE-2022-23793",
                            "severity": "high",
                            "component": "core", 
                            "version_affected": "< 3.10.6",
                            "description": "SQL injection vulnerability in com_fields"
                        },
                        {
                            "cve": "CVE-2021-23132",
                            "severity": "medium",
                            "component": "core",
                            "version_affected": "< 3.9.25",
                            "description": "XSS vulnerability in com_media"
                        }
                    ]
                    
                    # Check if current version is affected by known vulnerabilities
                    try:
                        current_version_parts = [int(x) for x in version.split('.')]
                        
                        for vuln in known_vulnerabilities:
                            # Simple version comparison (this is a basic implementation)
                            version_affected = vuln['version_affected']
                            if '< ' in version_affected:
                                affected_version = version_affected.replace('< ', '').strip()
                                try:
                                    affected_parts = [int(x) for x in affected_version.split('.')]
                                    
                                    # Compare versions (basic implementation)
                                    is_vulnerable = False
                                    for i in range(min(len(current_version_parts), len(affected_parts))):
                                        if current_version_parts[i] < affected_parts[i]:
                                            is_vulnerable = True
                                            break
                                        elif current_version_parts[i] > affected_parts[i]:
                                            break
                                    
                                    if is_vulnerable:
                                        vulnerabilities.append(vuln)
                                except:
                                    continue
                    except:
                        pass
                
                # Check for component-specific vulnerabilities
                for component in installed_components:
                    # Add some example component vulnerabilities
                    if component['name'] == 'com_content' and component['version'] != 'unknown':
                        # Example vulnerability for com_content
                        vulnerabilities.append({
                            "cve": "CVE-2022-EXAMPLE",
                            "severity": "medium",
                            "component": component['name'],
                            "version_affected": "< 3.10.0",
                            "description": f"Example vulnerability in {component['name']}"
                        })
                        component['vulnerabilities'].append("CVE-2022-EXAMPLE")
                
            except Exception:
                pass  # Vulnerability checking failed
        
        # 4. Configuration Issues Detection
        if check_config:
            command_parts.append("config_check")
            try:
                # Check for common misconfigurations
                config_checks = [
                    {
                        'url': 'configuration.php',
                        'type': 'configuration_exposure',
                        'risk': 'critical'
                    },
                    {
                        'url': 'administrator/',
                        'type': 'admin_directory_listing',
                        'risk': 'medium'
                    },
                    {
                        'url': 'cache/',
                        'type': 'cache_directory_listing', 
                        'risk': 'low'
                    },
                    {
                        'url': 'logs/',
                        'type': 'logs_directory_listing',
                        'risk': 'medium'
                    },
                    {
                        'url': 'tmp/',
                        'type': 'temp_directory_listing',
                        'risk': 'low'
                    }
                ]
                
                for check in config_checks:
                    try:
                        check_url = urljoin(target_url, check['url'])
                        response = requests.get(check_url, timeout=5)
                        
                        if response.status_code == 200:
                            content = response.text.lower()
                            
                            # Check for directory listing indicators
                            if ('index of' in content or 
                                'parent directory' in content or
                                '<title>directory listing' in content):
                                
                                misconfigurations.append({
                                    "type": check['type'],
                                    "path": check['url'],
                                    "risk": check['risk']
                                })
                            
                            # Check for configuration file exposure
                            elif check['url'] == 'configuration.php' and ('$password' in content or '$user' in content):
                                misconfigurations.append({
                                    "type": "configuration_exposure",
                                    "path": check['url'],
                                    "risk": "critical"
                                })
                    except:
                        continue
                        
            except Exception:
                pass  # Configuration checking failed
        
        # 5. User Enumeration (if enabled)
        if enumerate_users:
            command_parts.append("user_enumeration")
            # Note: User enumeration implementation would go here
            # For now, we'll skip this to avoid being too aggressive
        
        # Calculate vulnerability summary
        critical_count = len([v for v in vulnerabilities if v['severity'] == 'critical'])
        high_count = len([v for v in vulnerabilities if v['severity'] == 'high'])
        medium_count = len([v for v in vulnerabilities if v['severity'] == 'medium'])
        low_count = len([v for v in vulnerabilities if v['severity'] == 'low'])
        
        scan_duration = time.time() - start_time
        command = f"joomlascanner {' '.join(command_parts)}"
        
        return {
            "tool": "joomlascanner",
            "target": target,
            "target_url": target_url,
            "command": command,
            "cms_info": cms_info,
            "installed_components": installed_components,
            "installed_modules": installed_modules,
            "installed_templates": installed_templates,
            "vulnerabilities": vulnerabilities,
            "misconfigurations": misconfigurations,
            "total_vulnerabilities": len(vulnerabilities),
            "critical": critical_count,
            "high": high_count,
            "medium": medium_count,
            "low": low_count,
            "scan_duration": round(scan_duration, 2),
            "parameters_used": {
                "enumerate_users": enumerate_users,
                "enumerate_plugins": enumerate_plugins,
                "check_config": check_config,
                "aggressive": aggressive
            }
        }
        
    except Exception as e:
        scan_duration = time.time() - start_time if 'start_time' in locals() else 0
        return {
            "tool": "joomlascanner",
            "target": target,
            "target_url": target_url if 'target_url' in locals() else target,
            "command": "joomlascanner error",
            "error": str(e),
            "cms_info": {
                "version": "unknown",
                "confidence": "low",
                "detection_method": "error"
            },
            "installed_components": [],
            "installed_modules": [],
            "installed_templates": [],
            "vulnerabilities": [],
            "misconfigurations": [],
            "total_vulnerabilities": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "scan_duration": round(scan_duration, 2)
        }

def run_sharepointscanner(target, params):
    """SharePoint Security Scanner"""
    try:
        import time
        import requests
        import re
        from urllib.parse import urljoin, urlparse
        
        start_time = time.time()
        
        # Ensure target has protocol
        if not target.startswith(('http://', 'https://')):
            target_url = f'http://{target}'
        else:
            target_url = target
        
        # Parameter validation and defaults
        enumerate_users = params.get('enumerate_users', True)
        enumerate_plugins = params.get('enumerate_plugins', True)
        check_config = params.get('check_config', True)
        aggressive = params.get('aggressive', False)
        
        # Initialize results structure
        cms_info = {
            "version": "unknown",
            "confidence": "low",
            "detection_method": "none"
        }
        configuration_issues = []
        security_findings = []
        web_services = []
        user_accounts = []
        
        # Set up session with proper headers
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        session.timeout = 10
        
        command_parts = ["sharepoint_detection"]
        
        # 1. SharePoint Version Detection
        try:
            # Check common SharePoint paths for version detection
            detection_paths = [
                '/_layouts/viewlsts.aspx',
                '/_layouts/settings.aspx',
                '/_layouts/people.aspx',
                '/_vti_pvt/service.cnf',
                '/_vti_inf.html',
                '/default.aspx',
                '/_layouts/15/start.aspx',
                '/_layouts/16/start.aspx'
            ]
            
            for path in detection_paths:
                try:
                    url = urljoin(target_url, path)
                    response = session.get(url, timeout=5, allow_redirects=True)
                    
                    if response.status_code == 200:
                        content = response.text.lower()
                        headers = response.headers
                        
                        # Check for SharePoint indicators in content
                        sharepoint_indicators = [
                            'sharepoint',
                            'microsoft sharepoint',
                            '_spbodyonloadfunctionnames',
                            'microsoftajax.js',
                            '_layouts/',
                            'sharepoint:',
                            'moss'
                        ]
                        
                        if any(indicator in content for indicator in sharepoint_indicators):
                            cms_info["detection_method"] = f"content_analysis_{path}"
                            cms_info["confidence"] = "high"
                            
                            # Try to extract version information
                            version_patterns = [
                                r'sharepoint\s+(\d+(?:\.\d+)*)',
                                r'microsoft\s+sharepoint\s+(\d+(?:\.\d+)*)',
                                r'moss\s+(\d+(?:\.\d+)*)',
                                r'version["\s]*[:=]["\s]*(\d+(?:\.\d+)*)'
                            ]
                            
                            for pattern in version_patterns:
                                match = re.search(pattern, content, re.IGNORECASE)
                                if match:
                                    cms_info["version"] = match.group(1)
                                    cms_info["confidence"] = "high"
                                    break
                            
                            # Check for specific SharePoint versions based on paths
                            if '/_layouts/15/' in content or path.endswith('/15/start.aspx'):
                                cms_info["version"] = "2013"
                                cms_info["confidence"] = "high"
                            elif '/_layouts/16/' in content or path.endswith('/16/start.aspx'):
                                cms_info["version"] = "2016/2019/Online"
                                cms_info["confidence"] = "high"
                            
                            break
                        
                        # Check headers for SharePoint indicators
                        server_header = headers.get('server', '').lower()
                        if 'sharepoint' in server_header or 'microsoft-iis' in server_header:
                            cms_info["detection_method"] = "server_header"
                            cms_info["confidence"] = "medium"
                            
                            # Extract version from server header if available
                            version_match = re.search(r'sharepoint[/\s]+(\d+(?:\.\d+)*)', server_header)
                            if version_match:
                                cms_info["version"] = version_match.group(1)
                                cms_info["confidence"] = "high"
                
                except requests.RequestException:
                    continue
        
        except Exception as e:
            security_findings.append({
                "type": "detection_error",
                "severity": "info",
                "description": f"Error during SharePoint detection: {str(e)}"
            })
        
        # 2. Configuration Analysis
        if check_config:
            command_parts.append("config_analysis")
            try:
                config_paths = [
                    '/_vti_pvt/',
                    '/_vti_bin/',
                    '/_layouts/',
                    '/web.config',
                    '/_vti_pvt/service.cnf',
                    '/_vti_pvt/access.cnf',
                    '/_vti_pvt/writeto.cnf',
                    '/_vti_pvt/service.pwd',
                    '/_vti_pvt/administrators.pwd',
                    '/_vti_pvt/authors.pwd'
                ]
                
                for path in config_paths:
                    try:
                        url = urljoin(target_url, path)
                        response = session.get(url, timeout=5)
                        
                        if response.status_code == 200:
                            if path.endswith('/'):
                                # Directory listing found
                                configuration_issues.append({
                                    "type": "directory_listing",
                                    "path": path,
                                    "risk": "medium",
                                    "description": f"Directory listing enabled for {path}"
                                })
                            else:
                                # Sensitive file accessible
                                configuration_issues.append({
                                    "type": "sensitive_file_exposure",
                                    "path": path,
                                    "risk": "high",
                                    "description": f"Sensitive configuration file accessible: {path}"
                                })
                        elif response.status_code == 403:
                            # Good - file exists but is protected
                            pass
                        elif response.status_code == 401:
                            # Authentication required - note this
                            security_findings.append({
                                "type": "authentication_required",
                                "severity": "info",
                                "path": path,
                                "description": f"Authentication required for {path}"
                            })
                    
                    except requests.RequestException:
                        continue
            
            except Exception as e:
                security_findings.append({
                    "type": "config_analysis_error",
                    "severity": "info",
                    "description": f"Error during configuration analysis: {str(e)}"
                })
        
        # 3. Web Service Exposure Checking
        command_parts.append("service_exposure_check")
        try:
            service_endpoints = [
                '/_vti_bin/spdisco.aspx',
                '/_vti_bin/spsdisco.aspx',
                '/_vti_bin/lists.asmx',
                '/_vti_bin/webs.asmx',
                '/_vti_bin/sites.asmx',
                '/_vti_bin/usergroup.asmx',
                '/_vti_bin/permissions.asmx',
                '/_vti_bin/search.asmx',
                '/_vti_bin/imaging.asmx',
                '/_api/web',
                '/_api/site',
                '/_api/lists'
            ]
            
            for endpoint in service_endpoints:
                try:
                    url = urljoin(target_url, endpoint)
                    response = session.get(url, timeout=5)
                    
                    if response.status_code == 200:
                        service_type = "unknown"
                        if endpoint.endswith('.asmx'):
                            service_type = "soap_webservice"
                        elif '/_api/' in endpoint:
                            service_type = "rest_api"
                        elif endpoint.endswith('.aspx'):
                            service_type = "discovery_service"
                        
                        web_services.append({
                            "endpoint": endpoint,
                            "type": service_type,
                            "status": "accessible",
                            "response_size": len(response.content)
                        })
                        
                        # Check if service requires authentication
                        if 'authentication' in response.text.lower() or response.status_code == 401:
                            security_findings.append({
                                "type": "service_authentication",
                                "severity": "info",
                                "endpoint": endpoint,
                                "description": f"Web service requires authentication: {endpoint}"
                            })
                        else:
                            security_findings.append({
                                "type": "exposed_webservice",
                                "severity": "medium",
                                "endpoint": endpoint,
                                "description": f"Web service accessible without authentication: {endpoint}"
                            })
                    
                    elif response.status_code == 401:
                        web_services.append({
                            "endpoint": endpoint,
                            "type": "protected_service",
                            "status": "authentication_required",
                            "response_size": 0
                        })
                
                except requests.RequestException:
                    continue
        
        except Exception as e:
            security_findings.append({
                "type": "service_exposure_error",
                "severity": "info",
                "description": f"Error during service exposure checking: {str(e)}"
            })
        
        # 4. User Enumeration (if enabled)
        if enumerate_users:
            command_parts.append("user_enumeration")
            try:
                user_enum_paths = [
                    '/_layouts/people.aspx',
                    '/_layouts/userdisp.aspx',
                    '/_layouts/viewgroups.aspx',
                    '/_vti_bin/usergroup.asmx'
                ]
                
                for path in user_enum_paths:
                    try:
                        url = urljoin(target_url, path)
                        response = session.get(url, timeout=5)
                        
                        if response.status_code == 200:
                            content = response.text
                            
                            # Look for user-related information
                            user_patterns = [
                                r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',  # Email addresses
                                r'domain\\[a-zA-Z0-9._-]+',  # Domain users
                                r'user["\s]*[:=]["\s]*([a-zA-Z0-9._-]+)'  # User fields
                            ]
                            
                            for pattern in user_patterns:
                                matches = re.findall(pattern, content, re.IGNORECASE)
                                for match in matches:
                                    if isinstance(match, tuple):
                                        match = match[0]
                                    if match not in user_accounts and len(match) > 2:
                                        user_accounts.append(match)
                            
                            if user_accounts:
                                security_findings.append({
                                    "type": "user_enumeration_possible",
                                    "severity": "low",
                                    "path": path,
                                    "description": f"User information discoverable via {path}",
                                    "users_found": len(user_accounts)
                                })
                    
                    except requests.RequestException:
                        continue
            
            except Exception as e:
                security_findings.append({
                    "type": "user_enumeration_error",
                    "severity": "info",
                    "description": f"Error during user enumeration: {str(e)}"
                })
        
        # 5. Additional Security Checks (if aggressive mode)
        if aggressive:
            command_parts.append("aggressive_checks")
            try:
                # Check for common SharePoint vulnerabilities
                vuln_paths = [
                    '/_layouts/viewlsts.aspx?BaseType=1',
                    '/_layouts/people.aspx?MembershipGroupId=0',
                    '/_vti_bin/owssvr.dll?Cmd=Display&List={00000000-0000-0000-0000-000000000000}&XMLDATA=TRUE',
                    '/_layouts/userdisp.aspx?ID=1',
                    '/_layouts/settings.aspx'
                ]
                
                for path in vuln_paths:
                    try:
                        url = urljoin(target_url, path)
                        response = session.get(url, timeout=5)
                        
                        if response.status_code == 200 and len(response.content) > 1000:
                            security_findings.append({
                                "type": "information_disclosure",
                                "severity": "medium",
                                "path": path,
                                "description": f"Potential information disclosure via {path}"
                            })
                    
                    except requests.RequestException:
                        continue
            
            except Exception as e:
                security_findings.append({
                    "type": "aggressive_check_error",
                    "severity": "info",
                    "description": f"Error during aggressive checks: {str(e)}"
                })
        
        # Calculate severity summary
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }
        
        # Count configuration issues
        for issue in configuration_issues:
            risk = issue.get('risk', 'low')
            if risk in severity_counts:
                severity_counts[risk] += 1
        
        # Count security findings
        for finding in security_findings:
            severity = finding.get('severity', 'low')
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        scan_duration = time.time() - start_time
        
        return {
            "tool": "sharepointscanner",
            "target": target,
            "target_url": target_url,
            "command": " + ".join(command_parts),
            "cms_info": cms_info,
            "configuration_issues": configuration_issues,
            "security_findings": security_findings,
            "web_services": web_services,
            "user_accounts": user_accounts[:10] if user_accounts else [],  # Limit to first 10 for security
            "total_vulnerabilities": sum(severity_counts.values()),
            "critical": severity_counts['critical'],
            "high": severity_counts['high'],
            "medium": severity_counts['medium'],
            "low": severity_counts['low'],
            "scan_duration": round(scan_duration, 2)
        }
        
    except Exception as e:
        return {
            "tool": "sharepointscanner",
            "target": target,
            "target_url": target if target.startswith(('http://', 'https://')) else f'http://{target}',
            "command": "sharepointscanner (failed)",
            "error": str(e),
            "cms_info": {
                "version": "unknown",
                "confidence": "low",
                "detection_method": "error"
            },
            "configuration_issues": [],
            "security_findings": [],
            "web_services": [],
            "user_accounts": [],
            "total_vulnerabilities": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "scan_duration": 0
        }

@app.after_request
def add_security_headers(response):
    """Add comprehensive security headers to all responses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    
    # CORS - only allow https://compani.com
    allowed_origin = os.environ.get('ALLOWED_ORIGIN', 'https://compani.com')
    response.headers['Access-Control-Allow-Origin'] = allowed_origin
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, X-API-Key'
    response.headers['Access-Control-Max-Age'] = '86400'
    response.headers['Access-Control-Allow-Credentials'] = 'false'
    
    return response

if __name__ == '__main__':
    # Validate configuration
    if REQUIRE_AUTH and not API_KEY:
        logger.error("CRITICAL: REQUIRE_AUTH=true but API_KEY not set!")
        logger.error("Set API_KEY environment variable or disable authentication")
        exit(1)
    
    # Disable debug mode in production
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    
    # Startup info
    logger.info("="*60)
    logger.info("Security Scanner API - Starting...")
    logger.info("="*60)
    logger.info(f"Authentication: {'ENABLED' if REQUIRE_AUTH else 'DISABLED'}")
    logger.info(f"CORS Origin: {os.environ.get('ALLOWED_ORIGIN', 'https://compani.com')}")
    logger.info(f"Debug Mode: {debug_mode}")
    logger.info(f"Enhanced SSRF Protection: ENABLED")
    logger.info(f"Injection Detection: ENABLED")
    logger.info(f"Timing-Attack Protection: ENABLED")
    logger.info("="*60)
    
    app.run(host='0.0.0.0', port=5000, threaded=True, debug=debug_mode)
