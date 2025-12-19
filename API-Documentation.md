# Security Scanner API - Complete Documentation

## Table of Contents
1. [Overview](#overview)
2. [Getting Started](#getting-started)
3. [Authentication](#authentication)
4. [Common API Workflow](#common-api-workflow)
5. [Core Endpoints](#core-endpoints)
6. [Security Tools](#security-tools)
7. [Management Endpoints](#management-endpoints)
8. [Error Handling](#error-handling)
9. [Examples](#examples)

---

## Overview

The Security Scanner API is an asynchronous Flask-based REST API that provides access to popular security scanning tools on Kali Linux. It features job management and comprehensive JSON responses.

**Base URL:** `http://127.0.0.1:5000`

**Key Features:**
- Asynchronous processing (non-blocking scans)
- Job tracking with unique IDs
- Concurrent scan limits (max 5 simultaneous)
- Clean JSON responses with 4-space indentation
- Health monitoring and metrics
- Enhanced security (SSRF protection, injection detection, timing-attack resistant auth)

**Security Features:**
- ✅ Timing-attack resistant authentication
- ✅ Enhanced SSRF protection (blocks AWS/Azure/Alibaba metadata IPs)
- ✅ Injection pattern detection (shell metacharacters, commands)
- ✅ API key-based job ownership (not IP-based)
- ✅ Comprehensive security headers
- ✅ Rate limiting (100 req/hour per IP)
- ✅ Audit logging for security events

---

## Getting Started

### Installation
```bash
# setup
pip install -r requirements.txt

# Start the server
python f.py
```

### Basic Usage
```bash
# Start a scan (with authentication)
curl -X POST http://127.0.0.1:5000/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{"tool": "nuclei", "target": "example.com"}'

# Check status
curl -H "X-API-Key: your-api-key" \
  http://127.0.0.1:5000/status/{job_id}

# Get results
curl -H "X-API-Key: your-api-key" \
  http://127.0.0.1:5000/results/{job_id}
```

---

## Authentication

### API Key Authentication

When `REQUIRE_AUTH=true`, all endpoints (except `/health` and `/metrics`) require an API key.

**Header:**
```
X-API-Key: your-api-key-here
```

**Example:**
```bash
curl -H "X-API-Key: your-key" http://localhost:5000/scan ...
```

**Security Features:**
- ✅ Timing-attack resistant comparison using `hmac.compare_digest()`
- ✅ API keys hashed with SHA256
- ✅ Job ownership tracked by API key hash (not IP)
- ✅ Failed attempts logged to audit.log

### Rate Limiting
- **Limit:** 100 requests per hour per IP
- **Response:** 429 Too Many Requests when exceeded

### Concurrent Scans
- **Maximum:** 5 simultaneous scans
- **Response:** 429 when limit exceeded

### Error Responses

**Unauthorized:**
```json
{
    "error": "Unauthorized - Invalid or missing API key"
}
```

**Rate Limit:**
```json
{
    "error": "Rate limit exceeded",
    "message": "Maximum 100 requests per hour allowed"
}
```

**Concurrent Limit:**
```json
{
    "error": "Maximum concurrent scans reached",
    "active_scans": 5,
    "max_allowed": 5
}
```

---

## Common API Workflow

### 1. Start a Scan
**POST** `/scan`

**Request Body:**
```json
{
    "tool": "tool_name",
    "target": "domain.com",
    "params": {
        "optional": "parameters"
    }
}
```

**Response (202 Accepted):**
```json
{
    "job_id": "uuid-string",
    "status": "queued",
    "tool": "tool_name",
    "target": "domain.com",
    "message": "Scan started",
    "estimated_time": "120 seconds"
}
```

### 2. Monitor Progress
**GET** `/status/{job_id}`

**Response:**
```json
{
    "job_id": "uuid-string",
    "tool": "tool_name",
    "target": "domain.com",
    "status": "running",
    "created_at": "2024-01-01T12:00:00Z",
    "started_at": "2024-01-01T12:00:05Z"
}
```

**Status Values:**
- `queued` - Waiting to start
- `running` - Currently executing
- `completed` - Finished successfully
- `failed` - Error occurred
- `cancelled` - Manually cancelled

### 3. Get Results
**GET** `/results/{job_id}`

**Response (200 OK):**
```json
{
    "job_id": "uuid-string",
    "tool": "tool_name",
    "target": "domain.com",
    "status": "completed",
    "result": {
        "tool-specific": "data"
    },
    "completed_at": "2024-01-01T12:05:00Z"
}
```

---

## Core Endpoints

### POST /scan
Start a new security scan.

**Parameters:**
- `tool` (required): Tool name from supported list
- `target` (required): Domain, IP, or URL to scan
- `params` (optional): Tool-specific parameters

**Example:**
```bash
curl -X POST http://127.0.0.1:5000/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "tool": "nmap",
    "target": "scanme.nmap.org",
    "params": {"type": "1"}
  }'
```

### GET /status/{job_id}
Check scan progress and status.

**Response Fields:**
- `job_id`: Unique identifier
- `tool`: Scanner used
- `target`: Target being scanned
- `status`: Current status
- `created_at`: Job creation time
- `started_at`: Scan start time (if running/completed)
- `completed_at`: Completion time (if finished)
- `error`: Error message (if failed)

### GET /results/{job_id}
Retrieve completed scan results.

**Requirements:**
- Job must have `status: "completed"`
- Returns 400 error if scan not completed

### POST /cancel/{job_id}
Cancel a running or queued scan.

**Response:**
```json
{
    "job_id": "uuid-string",
    "status": "cancelled",
    "message": "Job cancelled successfully"
}
```

---

## Security Tools

### 1. WAF Detection (wafw00f)
Detects Web Application Firewalls.

**Usage:**
```json
{
    "tool": "wafw00f",
    "target": "example.com"
}
```

**Output:**
```json
{
    "tool": "wafw00f",
    "target": "example.com",
    "command": "wafw00f example.com -o /tmp/output.json",
    "data": {
        "detected": true,
        "firewall": "Cloudflare",
        "manufacturer": "Cloudflare Inc."
    }
}
```

### 2. Network Mapping (nmap)
Port scanning and service detection.

**Parameters:**
- `type`: "1" (lite scan) or "2" (deep scan)

**Usage:**
```json
{
    "tool": "nmap",
    "target": "scanme.nmap.org",
    "params": {"type": "1"}
}
```

**Output:**
```json
{
    "tool": "nmap",
    "target": "scanme.nmap.org",
    "scan_type": "lite",
    "command": "nmap -T4 -F scanme.nmap.org",
    "result": "Nmap scan report for scanme.nmap.org..."
}
```

### 3. Vulnerability Scanning (nuclei)
Template-based vulnerability detection with extensive filtering options.

**Parameters:**
- `severity`: Filter by severity (critical, high, medium, low, info, unknown)
- `tags`: Run templates with specific tags (cve, owasp, xss, sqli, etc.)
- `exclude_tags`: Exclude templates with specific tags
- `templates`: Specific templates to use
- `exclude_templates`: Templates to exclude
- `rate_limit`: Requests per second (default: 150)
- `concurrency`: Parallel templates (default: 25)
- `timeout`: Template timeout in seconds (default: 5)
- `retries`: Number of retries (default: 1)
- `follow_redirects`: Follow HTTP redirects (boolean)
- `include_all`: Include all results (boolean)
- `passive`: Passive scan only (boolean)
- `automatic_scan`: Use automatic scan mode (boolean)

**Basic Usage:**
```json
{
    "tool": "nuclei",
    "target": "example.com"
}
```

**Advanced Usage with Filters:**
```json
{
    "tool": "nuclei",
    "target": "example.com",
    "params": {
        "severity": "critical,high",
        "tags": "cve,owasp",
        "rate_limit": 50,
        "concurrency": 20
    }
}
```

**Output:**
```json
{
    "tool": "nuclei",
    "target": "example.com",
    "target_url": "http://example.com",
    "command": "nuclei -u http://example.com -j -severity critical,high -tags cve,owasp",
    "results": [
        {
            "template-id": "CVE-2023-12345",
            "info": {
                "name": "Example Vulnerability",
                "severity": "critical",
                "tags": ["cve", "rce"]
            },
            "matched-at": "http://example.com/vulnerable",
            "type": "http"
        }
    ],
    "total_findings": 1,
    "severity_summary": {
        "critical": 1,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "unknown": 0
    }
}
```

**Common Scan Scenarios:**

1. **Critical/High Severity Only:**
```json
{"tool": "nuclei", "target": "example.com", "params": {"severity": "critical,high"}}
```

2. **CVE-Based Scan:**
```json
{"tool": "nuclei", "target": "example.com", "params": {"tags": "cve"}}
```

3. **OWASP Top 10:**
```json
{"tool": "nuclei", "target": "example.com", "params": {"tags": "owasp"}}
```

4. **Injection Vulnerabilities:**
```json
{"tool": "nuclei", "target": "example.com", "params": {"tags": "xss,sqli,rce"}}
```

5. **Stealthy Scan:**
```json
{"tool": "nuclei", "target": "example.com", "params": {"rate_limit": 10, "concurrency": 5}}
```

For detailed parameter documentation, see [NUCLEI_PARAMS.md](NUCLEI_PARAMS.md)

### 4. Directory Enumeration (dirb)
Discovers hidden directories and files.

**Usage:**
```json
{
    "tool": "dirb",
    "target": "example.com"
}
```

**Output:**
```json
{
    "tool": "dirb",
    "target": "example.com",
    "target_url": "http://example.com/",
    "command": "dirb http://example.com/",
    "found_items": [
        "http://example.com/admin/ (CODE:403|SIZE:1234)",
        "DIRECTORY: http://example.com/images/"
    ],
    "total_found": 2
}
```

### 5. Web Technology Detection (whatweb)
Identifies web technologies and frameworks.

**Usage:**
```json
{
    "tool": "whatweb",
    "target": "example.com"
}
```

**Output:**
```json
{
    "tool": "whatweb",
    "target": "example.com",
    "target_url": "http://example.com",
    "command": "whatweb --color=never --log-json=/tmp/output.json http://example.com",
    "results": [
        {
            "target": "http://example.com",
            "http_status": 200,
            "plugins": {
                "HTTPServer": ["nginx/1.18.0"],
                "Title": ["Example Domain"]
            }
        }
    ],
    "total_results": 1
}
```

### 6. Web Vulnerability Scanner (nikto)
Comprehensive web server vulnerability assessment.

**Usage:**
```json
{
    "tool": "nikto",
    "target": "example.com"
}
```

**Output:**
```json
{
    "tool": "nikto",
    "target": "example.com",
    "target_url": "http://example.com",
    "command": "nikto -h http://example.com -Format json -output /tmp/output.json",
    "results": {
        "host": "example.com",
        "port": "80",
        "vulnerabilities": [
            {
                "id": "000001",
                "method": "GET",
                "uri": "/",
                "message": "Server may leak inodes via ETags"
            }
        ]
    }
}
```

### 7. Port Scanner (masscan)
High-speed port scanning.

**Parameters:**
- `ports`: Port range (default: "0-65535")
- `rate`: Scan rate (default: "1000")

**Usage:**
```json
{
    "tool": "masscan",
    "target": "scanme.nmap.org",
    "params": {
        "ports": "80,443,8080",
        "rate": "1000"
    }
}
```

**Output:**
```json
{
    "tool": "masscan",
    "target": "scanme.nmap.org",
    "resolved_ip": "45.33.32.156",
    "ports_scanned": "80,443,8080",
    "scan_rate": "1000",
    "command": "masscan -p 80,443,8080 --rate 1000 -oJ /tmp/output.json --open 45.33.32.156",
    "results": [
        {
            "ip": "45.33.32.156",
            "port": 80,
            "protocol": "tcp",
            "status": "open"
        }
    ],
    "total_open_ports": 1
}
```

### 8. SSL/TLS Security Scanner (sslscan)
SSL/TLS configuration analysis.

**Parameters:**
- `port`: Target port (default: "443")

**Usage:**
```json
{
    "tool": "sslscan",
    "target": "example.com",
    "params": {"port": "443"}
}
```

**Output:**
```json
{
    "tool": "sslscan",
    "target": "example.com",
    "port": "443",
    "command": "sslscan --xml=/tmp/output.xml example.com:443",
    "results": {
        "host": "example.com",
        "port": "443",
        "protocols": [
            {"type": "tls", "version": "1.2", "enabled": true},
            {"type": "tls", "version": "1.3", "enabled": true}
        ],
        "ciphers": [
            {
                "status": "preferred",
                "sslversion": "TLSv1.3",
                "bits": "128",
                "cipher": "TLS_AES_128_GCM_SHA256",
                "strength": "strong"
            }
        ],
        "vulnerabilities": {
            "heartbleed": {"vulnerable": false},
            "compression": {"supported": false}
        },
        "certificate": {
            "subject": "CN=example.com",
            "issuer": "CN=DigiCert"
        }
    },
    "total_protocols": 2,
    "total_ciphers": 15
}
```

### 9. HTTP Probing & Host Verification (httpx)
Comprehensive HTTP/HTTPS probing with technology detection.

**Parameters:**

**Detection (default: enabled):**
- `status_code`, `title`, `tech_detect`, `ip`, `cdn`, `method`, `probe`

**Additional Detection:**
- `websocket`, `cname`, `asn`, `content_length`, `response_time`, `web_server`

**Behavior:**
- `follow_redirects`, `include_response`, `screenshot`

**Performance:**
- `threads`, `rate_limit`, `timeout`, `retries`

**Filtering:**
- `match_code`, `filter_code`

**Usage:**
```json
{
    "tool": "httpx",
    "target": "example.com",
    "params": {
        "screenshot": false,
        "follow_redirects": true
    }
}
```

**Output:**
```json
{
    "tool": "httpx",
    "target": "example.com",
    "command": "httpx -json -probe -status-code -title -tech-detect -ip -cdn -method -websocket -cname -asn -silent -follow-redirects -l /tmp/input.txt",
    "results": [
        {
            "url": "https://example.com",
            "status_code": 200,
            "title": "Example Domain",
            "tech": ["nginx", "HTML"],
            "cdn": false,
            "host": "93.184.216.34",
            "webserver": "nginx/1.18.0",
            "method": "GET",
            "time": "245ms",
            "content_length": 1256,
            "words": 298,
            "lines": 47
        }
    ],
    "summary": {
        "total_hosts": 1,
        "live_hosts": 1,
        "technologies": ["nginx", "HTML"],
        "status_codes": {"200": 1},
        "cdn_providers": [],
        "web_servers": ["nginx/1.18.0"]
    }
}
```

### 10. OpenVAS Vulnerability Scanner (gvm)
Comprehensive vulnerability scanning using OpenVAS engine.

**Parameters:**
- `socket_path`: GVM socket path (default: "/run/gvmd/gvmd.sock")
- `use_tls`: Use TLS connection instead of socket (default: false)
- `host`: GVM host for TLS connection (default: localhost)
- `port`: GVM port for TLS connection (default: 9390)

**Note:** 
- Credentials from environment variables (GVM_USERNAME, GVM_PASSWORD)
- Default: username=admin, password=admin
- GVM scans run without timeout until completion
- Progress is logged to server console

**Usage:**
```json
{
    "tool": "gvm",
    "target": "testphp.vulnweb.com",
    "params": {
        "socket_path": "/run/gvmd/gvmd.sock"
    }
}
```

**Output:**
```json
{
    "tool": "gvm",
    "target": "testphp.vulnweb.com",
    "task_name": "API_Scan_testphp.vulnweb.com_1640995200",
    "scan_status": "Done",
    "vulnerabilities": [
        {
            "name": "SSL/TLS: Certificate Signed Using Weak Hashing Algorithm",
            "severity": "5.0",
            "host": "testphp.vulnweb.com",
            "port": "443/tcp",
            "description": "The remote SSL/TLS certificate is signed using a weak hashing algorithm...",
            "threat": "Medium"
        }
    ],
    "total_vulnerabilities": 15,
    "high_severity": 2,
    "medium_severity": 8,
    "low_severity": 5
}
```

**Requirements:**
- OpenVAS/GVM installed and running
- User must be in `_gvm` group or run as appropriate user
- GVM daemon accessible via Unix socket

**Setup:**
```bash
# Install OpenVAS
sudo apt install openvas
sudo gvm-setup

# Start services
sudo systemctl start gvmd
sudo systemctl start gsad
sudo systemctl start ospd-openvas

# Add user to gvm group
sudo usermod -a -G _gvm $USER
```

### 11. Domain Finder (domainfinder)
Discovers associated domain names owned by a target organization.

**Parameters:**
- `ssl_certificates`: Search SSL certificate transparency logs (default: true)
- `builtwith`: Search BuiltWith relationships (default: true)
- `reverse_whois`: Perform reverse WHOIS lookup (default: true)
- `minimum_weight`: Minimum confidence score 0.0-1.0 (default: 0.5)

**Usage:**
```json
{
    "tool": "domainfinder",
    "target": "example.com",
    "params": {
        "minimum_weight": 0.7
    }
}
```

**Output:**
```json
{
    "tool": "domainfinder",
    "target": "example.com",
    "command": "custom domain discovery logic",
    "associated_domains": [
        {
            "domain": "api.example.com",
            "confidence_score": 0.95,
            "discovery_methods": ["ssl_certificate", "builtwith"],
            "validation_factors": {
                "ssl_certificates": 3,
                "builtwith_relationships": 2,
                "whois_match": true
            }
        }
    ],
    "total_domains": 25,
    "high_confidence": 8,
    "medium_confidence": 12,
    "low_confidence": 5
}
```

### 12. Cloud Scanner (cloudscanner)
Evaluates cloud environments (AWS, GCP, Azure) for misconfigurations.

**Parameters:**
- `detect_provider`: Auto-detect cloud provider (default: true)
- `check_vulnerabilities`: Check for misconfigurations (default: true)
- `bucket_enumeration`: Enumerate cloud storage buckets (default: true)

**Usage:**
```json
{
    "tool": "cloudscanner",
    "target": "bucket-name.s3.amazonaws.com",
    "params": {
        "check_vulnerabilities": true,
        "bucket_enumeration": true
    }
}
```

**Output:**
```json
{
    "tool": "cloudscanner",
    "target": "bucket-name.s3.amazonaws.com",
    "detected_provider": "aws",
    "command": "cloud security assessment",
    "vulnerabilities": [
        {
            "type": "public_bucket",
            "severity": "high",
            "resource": "bucket-name",
            "description": "S3 bucket allows public read access",
            "remediation": "Configure bucket policy to restrict access"
        }
    ],
    "interesting_files": [
        {
            "filename": "backup.sql",
            "size": 1048576,
            "last_modified": "2024-01-01T12:00:00Z",
            "risk_level": "high"
        }
    ],
    "total_vulnerabilities": 5,
    "critical": 1,
    "high": 2,
    "medium": 2,
    "low": 0
}
```

### 13. Password Auditor (passwordauditor)
Tests for weak authentication credentials across network services.

**Parameters:**
- `ports`: Specific ports to scan (default: top 100 ports)
- `services`: Specific services to audit (default: "all")
- `username_list`: Custom username wordlist path (optional)
- `password_list`: Custom password wordlist path (optional)
- `default_creds`: Try default credentials (default: true)
- `delay`: Delay between attempts in seconds (default: 0, max: 5)
- `attack_type`: "dictionary" or "spray" (default: "dictionary")
- `lockout_period`: Minutes to wait between spray attempts (default: 5, max: 60)
- `attempts_per_period`: Passwords per username before lockout (default: 2, max: 10)

**Usage:**
```json
{
    "tool": "passwordauditor",
    "target": "example.com",
    "params": {
        "ports": "22,80,443",
        "default_creds": true,
        "attack_type": "spray",
        "lockout_period": 5
    }
}
```

**Output:**
```json
{
    "tool": "passwordauditor",
    "target": "example.com",
    "command": "passwordauditor service_discovery credential_testing",
    "discovered_services": [
        {
            "service": "ssh",
            "port": 22,
            "version": "OpenSSH 8.0"
        }
    ],
    "weak_credentials": [
        {
            "service": "ssh",
            "port": 22,
            "username": "admin",
            "password": "password123",
            "authentication_method": "password"
        }
    ],
    "web_forms": [
        {
            "url": "http://example.com/login",
            "method": "POST",
            "username_field": "username",
            "password_field": "password",
            "successful_login": false
        }
    ],
    "total_services": 3,
    "total_attempts": 1500,
    "successful_logins": 1
}
```

### 14. Drupal Scanner (drupalscanner)
Assesses Drupal CMS installations for vulnerabilities.

**Parameters:**
- `enumerate_users`: Attempt user enumeration (default: true)
- `enumerate_plugins`: Enumerate installed plugins/modules (default: true)
- `check_config`: Check for configuration issues (default: true)
- `aggressive`: Enable aggressive scanning (default: false)

**Usage:**
```json
{
    "tool": "drupalscanner",
    "target": "example.com",
    "params": {
        "enumerate_plugins": true,
        "check_config": true
    }
}
```

**Output:**
```json
{
    "tool": "drupalscanner",
    "target": "example.com",
    "target_url": "http://example.com",
    "command": "drupalscanner version_detection component_enumeration",
    "cms_info": {
        "version": "9.4.8",
        "confidence": "high",
        "detection_method": "changelog"
    },
    "installed_modules": [
        {
            "name": "views",
            "version": "8.x-1.0",
            "status": "enabled",
            "vulnerabilities": []
        }
    ],
    "installed_themes": [
        {
            "name": "bartik",
            "version": "9.4.8",
            "vulnerabilities": []
        }
    ],
    "vulnerabilities": [
        {
            "cve": "CVE-2023-12345",
            "severity": "critical",
            "component": "core",
            "version_affected": "< 9.4.9",
            "description": "Remote code execution vulnerability"
        }
    ],
    "misconfigurations": [
        {
            "type": "directory_listing",
            "path": "/sites/default/files/",
            "risk": "medium"
        }
    ],
    "total_vulnerabilities": 3,
    "critical": 1,
    "high": 1,
    "medium": 1,
    "low": 0
}
```

### 15. Joomla Scanner (joomlascanner)
Assesses Joomla CMS installations for vulnerabilities.

**Parameters:**
- `enumerate_users`: Attempt user enumeration (default: true)
- `enumerate_plugins`: Enumerate installed plugins/modules (default: true)
- `check_config`: Check for configuration issues (default: true)
- `aggressive`: Enable aggressive scanning (default: false)

**Usage:**
```json
{
    "tool": "joomlascanner",
    "target": "example.com",
    "params": {
        "enumerate_plugins": true,
        "check_config": true
    }
}
```

**Output:**
```json
{
    "tool": "joomlascanner",
    "target": "example.com",
    "target_url": "http://example.com",
    "command": "joomlascanner version_detection component_enumeration",
    "cms_info": {
        "version": "4.2.7",
        "confidence": "high",
        "detection_method": "joomla.xml"
    },
    "installed_components": [
        {
            "name": "com_content",
            "version": "4.2.7",
            "type": "component",
            "status": "enabled",
            "vulnerabilities": []
        }
    ],
    "installed_modules": [
        {
            "name": "mod_menu",
            "version": "4.2.7",
            "status": "enabled",
            "vulnerabilities": []
        }
    ],
    "installed_templates": [
        {
            "name": "cassiopeia",
            "version": "1.0",
            "vulnerabilities": []
        }
    ],
    "vulnerabilities": [
        {
            "cve": "CVE-2023-23752",
            "severity": "critical",
            "component": "core",
            "version_affected": "< 4.2.7",
            "description": "Improper access check allows unauthorized access"
        }
    ],
    "misconfigurations": [
        {
            "type": "configuration_exposure",
            "path": "configuration.php",
            "risk": "critical"
        }
    ],
    "total_vulnerabilities": 2,
    "critical": 1,
    "high": 1,
    "medium": 0,
    "low": 0
}
```

### 16. SharePoint Scanner (sharepointscanner)
Assesses Microsoft SharePoint installations for security weaknesses.

**Parameters:**
- `enumerate_users`: Attempt user enumeration (default: true)
- `enumerate_plugins`: Enumerate web services (default: true)
- `check_config`: Check for configuration issues (default: true)
- `aggressive`: Enable aggressive scanning (default: false)

**Usage:**
```json
{
    "tool": "sharepointscanner",
    "target": "sharepoint.example.com",
    "params": {
        "enumerate_plugins": true,
        "check_config": true
    }
}
```

**Output:**
```json
{
    "tool": "sharepointscanner",
    "target": "sharepoint.example.com",
    "target_url": "http://sharepoint.example.com",
    "command": "sharepoint_detection + config_analysis + service_exposure_check",
    "cms_info": {
        "version": "2016/2019/Online",
        "confidence": "high",
        "detection_method": "content_analysis_/_layouts/16/start.aspx"
    },
    "configuration_issues": [
        {
            "type": "directory_listing",
            "path": "/_vti_pvt/",
            "risk": "medium",
            "description": "Directory listing enabled for /_vti_pvt/"
        }
    ],
    "security_findings": [
        {
            "type": "exposed_webservice",
            "severity": "medium",
            "endpoint": "/_vti_bin/lists.asmx",
            "description": "Web service accessible without authentication"
        }
    ],
    "web_services": [
        {
            "endpoint": "/_vti_bin/lists.asmx",
            "type": "soap_webservice",
            "status": "accessible",
            "response_size": 2048
        }
    ],
    "user_accounts": ["user1@example.com", "user2@example.com"],
    "total_vulnerabilities": 3,
    "critical": 0,
    "high": 0,
    "medium": 2,
    "low": 1
}
```

---

## Management Endpoints

### GET /jobs
List all scan jobs with optional filtering.

**Query Parameters:**
- `limit`: Number of jobs to return (default: 50)
- `status`: Filter by status (queued, running, completed, failed, cancelled)

**Example:**
```bash
curl -H "X-API-Key: your-api-key" \
  "http://127.0.0.1:5000/jobs?limit=10&status=completed"
```

**Response:**
```json
{
    "total_jobs": 150,
    "active_scans": 2,
    "jobs": [
        {
            "job_id": "uuid-1",
            "tool": "nuclei",
            "target": "example.com",
            "status": "completed",
            "created_at": "2024-01-01T12:00:00Z"
        }
    ]
}
```

### GET /health
Health check endpoint for monitoring.

**Response:**
```json
{
    "status": "healthy",
    "active_scans": 2,
    "total_jobs": 150,
    "supported_tools": [
        "wafw00f", "nmap", "nuclei", "dirb", 
        "whatweb", "nikto", "masscan", "sslscan", "httpx", "gvm"
    ],
    "timestamp": "2024-01-01T12:00:00Z"
}
```

### GET /metrics
Prometheus-style metrics for monitoring systems.

**Response (text/plain):**
```
# HELP active_scans Current number of active scans
# TYPE active_scans gauge
active_scans 2

# HELP total_jobs Total number of jobs in memory
# TYPE total_jobs gauge
total_jobs 150

# HELP jobs_by_status Number of jobs by status
# TYPE jobs_by_status gauge
jobs_by_status{status="completed"} 120
jobs_by_status{status="running"} 2
jobs_by_status{status="failed"} 5
```

---

## Error Handling

### Common HTTP Status Codes
- **200 OK** - Request successful
- **202 Accepted** - Scan started (async)
- **400 Bad Request** - Invalid parameters
- **404 Not Found** - Job not found
- **429 Too Many Requests** - Rate limit exceeded
- **500 Internal Server Error** - Server error

### Error Response Format
```json
{
    "error": "Error description",
    "details": "Additional context (optional)"
}
```

### Common Errors

**Invalid Tool:**
```json
{
    "error": "Invalid tool",
    "supported_tools": ["wafw00f", "nmap", "nuclei", "dirb", "whatweb", "nikto", "masscan", "sslscan", "httpx", "gvm"]
}
```

**Rate Limit Exceeded:**
```json
{
    "error": "Maximum concurrent scans reached",
    "active_scans": 5,
    "max_allowed": 5
}
```

**Job Not Found:**
```json
{
    "error": "Job not found"
}
```

**Scan Not Completed:**
```json
{
    "error": "Scan not completed",
    "status": "running"
}
```

---

## Examples

### Complete Workflow Example

```bash
# 1. Start a comprehensive scan
RESPONSE=$(curl -s -X POST http://127.0.0.1:5000/scan \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "httpx",
    "target": "example.com",
    "params": {"follow_redirects": true}
  }')

# Extract job ID
JOB_ID=$(echo $RESPONSE | jq -r '.job_id')
echo "Started scan with job ID: $JOB_ID"

# 2. Monitor progress
while true; do
    STATUS=$(curl -s http://127.0.0.1:5000/status/$JOB_ID | jq -r '.status')
    echo "Current status: $STATUS"
    
    if [ "$STATUS" = "completed" ] || [ "$STATUS" = "failed" ]; then
        break
    fi
    
    sleep 5
done

# 3. Get results
if [ "$STATUS" = "completed" ]; then
    curl -s http://127.0.0.1:5000/results/$JOB_ID | jq '.'
else
    echo "Scan failed"
fi
```

### Batch Scanning Multiple Targets

```bash
#!/bin/bash
TARGETS=("example.com" "google.com" "github.com")
JOB_IDS=()

# Start all scans
for target in "${TARGETS[@]}"; do
    response=$(curl -s -X POST http://127.0.0.1:5000/scan \
      -H "Content-Type: application/json" \
      -d "{\"tool\": \"httpx\", \"target\": \"$target\"}")
    
    job_id=$(echo $response | jq -r '.job_id')
    JOB_IDS+=($job_id)
    echo "Started scan for $target: $job_id"
done

# Wait for all to complete
for job_id in "${JOB_IDS[@]}"; do
    while true; do
        status=$(curl -s http://127.0.0.1:5000/status/$job_id | jq -r '.status')
        if [ "$status" = "completed" ] || [ "$status" = "failed" ]; then
            break
        fi
        sleep 2
    done
    echo "Job $job_id completed with status: $status"
done
```

### Python Client Example

```python
import requests
import time
import json

class SecurityScannerClient:
    def __init__(self, base_url="http://127.0.0.1:5000"):
        self.base_url = base_url
    
    def start_scan(self, tool, target, params=None):
        """Start a new scan"""
        payload = {
            "tool": tool,
            "target": target,
            "params": params or {}
        }
        
        response = requests.post(f"{self.base_url}/scan", json=payload)
        return response.json()
    
    def get_status(self, job_id):
        """Get scan status"""
        response = requests.get(f"{self.base_url}/status/{job_id}")
        return response.json()
    
    def get_results(self, job_id):
        """Get scan results"""
        response = requests.get(f"{self.base_url}/results/{job_id}")
        return response.json()
    
    def wait_for_completion(self, job_id, timeout=300):
        """Wait for scan to complete"""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            status_data = self.get_status(job_id)
            status = status_data.get('status')
            
            if status in ['completed', 'failed', 'cancelled']:
                return status_data
            
            time.sleep(5)
        
        raise TimeoutError(f"Scan {job_id} did not complete within {timeout} seconds")

# Usage example
client = SecurityScannerClient()

# Start a nuclei scan
scan_response = client.start_scan("nuclei", "example.com")
job_id = scan_response['job_id']

print(f"Started scan: {job_id}")

# Wait for completion
final_status = client.wait_for_completion(job_id)
print(f"Scan completed with status: {final_status['status']}")

# Get results if successful
if final_status['status'] == 'completed':
    results = client.get_results(job_id)
    print(json.dumps(results, indent=2))
```

---

## Best Practices

### 1. Job Management
- Store job IDs for later reference
- Implement proper error handling for failed scans
- Use the `/jobs` endpoint to track scan history

### 2. Target Validation
- Ensure you have permission to scan targets
- Use proper domain names or IP addresses
- Be aware of scope restrictions

### 3. Resource Management
- Don't start too many concurrent scans (max 5)
- Cancel unnecessary scans to free resources
- Monitor system health via `/health` endpoint

### 4. Security Considerations
- Run the API in a controlled environment
- Implement proper network security
- Log and monitor API usage
- Validate all inputs before scanning

---

This documentation provides comprehensive coverage of all API endpoints, tools, parameters, and usage examples. Users can reference specific sections based on their needs and experience level.
