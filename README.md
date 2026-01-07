# Security Scanner API

Asynchronous Flask API for security scanning tools on Kali Linux with job management and comprehensive tool integration. Now featuring 16 specialized security scanners including advanced tools for domain reconnaissance, cloud security, credential auditing, and CMS vulnerability detection.

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Set environment variables
export REQUIRE_AUTH=true
export API_KEY=$(openssl rand -hex 32)

# 3. Start the server
python f.py
```

Server runs on `http://0.0.0.0:5000`

## Setup

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Configure Environment Variables

Create a `.env` file in the project root:

```bash
cp .env.example .env
```

Edit `.env` and set your credentials:

```bash
# Authentication (REQUIRED for production)
REQUIRE_AUTH=true
API_KEY=your-generated-api-key-here

# GVM/OpenVAS Credentials
GVM_USERNAME=admin
GVM_PASSWORD=your-gvm-password

# CORS Configuration
ALLOWED_ORIGIN=https://compani.com

# Debug Mode (disable in production)
FLASK_DEBUG=false
```

### 3. Generate Secure API Key

```bash
# Generate a secure API key
openssl rand -hex 32

# Or use Python
python3 -c "import secrets; print(secrets.token_hex(32))"
```

### 4. Load Environment Variables & Start Server

```bash
# Load .env file
export $(cat .env | xargs)

# Start the server
python f.py
```

## Common API Contract

All tools follow the same API workflow:

### 1. Start Scan
```bash
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key-here" \
  -d '{
    "tool": "nuclei",
    "target": "example.com",
    "params": {}
  }'
```

### 2. Check Status
```bash
curl -X GET http://localhost:5000/status/{job_id} \
  -H "X-API-Key: your-api-key-here"
```

### 3. Get Results
```bash
curl -X GET http://localhost:5000/results/{job_id} \
  -H "X-API-Key: your-api-key-here"
```

### 4. Cancel Scan (Optional)
```bash
curl -X POST http://localhost:5000/cancel/{job_id} \
  -H "X-API-Key: your-api-key-here"
```

## Supported Tools (21 Total)

### Core Security Tools
- **wafw00f** - WAF Detection
- **nmap** - Network Mapping (params: type=1|2)
- **nuclei** - Vulnerability Scanning (extensive parameter support)
- **dirb** - Directory Enumeration
- **whatweb** - Web Technology Detection
- **nikto** - Web Vulnerability Scanner
- **masscan** - Port Scanner (params: ports, rate)
- **sslscan** - SSL/TLS Security Scanner (params: port)
- **httpx** - HTTP Probing & Host Verification (extensive parameter support)
- **gvm** - OpenVAS Vulnerability Scanner

### Advanced Security Tools (7 tools)

- **domainfinder** - Domain Reconnaissance & Discovery
  - Parameters: ssl_certificates, builtwith, reverse_whois, minimum_weight
- **cloudscanner** - Cloud Security Assessment (AWS/GCP/Azure)
  - Parameters: detect_provider, check_vulnerabilities, bucket_enumeration
- **passwordauditor** - Authentication & Credential Testing
  - Parameters: ports, services, username_list, password_list, default_creds, delay, attack_type, lockout_period, attempts_per_period
- **drupalscanner** - Drupal CMS Vulnerability Scanner
  - Parameters: enumerate_users, enumerate_plugins, check_config, aggressive
- **joomlascanner** - Joomla CMS Vulnerability Scanner
  - Parameters: enumerate_users, enumerate_plugins, check_config, aggressive
- **sharepointscanner** - SharePoint Security Scanner
  - Parameters: enumerate_users, enumerate_plugins, check_config, aggressive
- **cvesearch** - CVE Search & Vulnerability Discovery
  - Parameters: use_nuclei, use_nmap, severity

### Offensive Security Tools (4 tools)

- **sqlmap** - SQL Injection Testing & Exploitation
  - Parameters: url, data, cookie, level, risk, technique, dbms, threads, timeout
- **subdomainfinder** - Subdomain Enumeration & Discovery
  - Parameters: use_subfinder, use_assetfinder, use_shodan, threads, timeout, wordlist
- **shodansearch** - Shodan Intelligence Gathering
  - Parameters: query, facets, limit, country, city, api_key
- **xssstrike** - XSS Detection & Exploitation
  - Parameters: crawl_depth, payload_level, blind_xss, custom_payloads, timeout, user_agent

## Management Endpoints

- `GET /jobs` - List all jobs (params: limit, status)
- `GET /health` - Health check
- `GET /metrics` - Prometheus metrics
- `POST /cancel/{job_id}` - Cancel running scan

## Features

- **Asynchronous Processing** - Non-blocking scans with background threading
- **Job Management** - Track scan progress with unique job IDs
- **Concurrent Limits** - Max 5 simultaneous scans
- **Enhanced Security** - SSRF protection, injection detection, timing-attack resistant auth
- **Target Validation** - Comprehensive validation with metadata IP blocking
- **Health Monitoring** - Built-in metrics and health checks
- **Complete Scans** - GVM scans run until completion without timeout
- **Job Ownership** - API key-based job tracking and access control
- **Rate Limiting** - 100 requests per hour per IP
- **Audit Logging** - All security events logged to audit.log

## Security Features

- **Timing-Attack Resistant Authentication** - Uses `hmac.compare_digest()` for secure API key comparison
- **Enhanced SSRF Protection** - Blocks AWS/Azure/Alibaba metadata IPs (169.254.169.254, 168.63.169.254, 100.100.100.200) and private networks
- **Injection Detection** - Detects shell metacharacters, command injection, and newline attacks
- **API Key-Based Ownership** - Jobs tracked by API key hash (not IP) for better security
- **Comprehensive Security Headers** - X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, HSTS, CSP, Referrer-Policy, Permissions-Policy
- **Audit Logging** - All security events logged to audit.log with timestamps
- **Rate Limiting** - 100 requests per hour per IP address
- **Input Validation** - Strict validation on all user inputs with character whitelisting
- **CORS Protection** - Configurable allowed origin (default: https://compani.com)

## Requirements

- Kali Linux with security tools installed
- Python 3.8+ with Flask, python-gvm, and requests
- OpenVAS/GVM configured and running (for GVM scans)
- Security tools: wafw00f, nmap, nuclei, dirb, whatweb, nikto, masscan, sslscan, httpx
- All responses are JSON formatted with 4-space indentation

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `REQUIRE_AUTH` | No | `false` | Enable API key authentication |
| `API_KEY` | Yes (if auth enabled) | None | API key for authentication |
| `GVM_USERNAME` | Yes (for GVM scans) | `admin` | OpenVAS/GVM username |
| `GVM_PASSWORD` | Yes (for GVM scans) | `admin` | OpenVAS/GVM password |
| `ALLOWED_ORIGIN` | No | `https://compani.com` | CORS allowed origin |
| `FLASK_DEBUG` | No | `false` | Enable Flask debug mode |


## Quick Examples



### Domain Discovery
```bash
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-key" \
  -d '{
    "tool": "domainfinder",
    "target": "example.com",
    "params": {
      "minimum_weight": 0.7
    }
  }'
```

### Cloud Security Scan
```bash
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-key" \
  -d '{
    "tool": "cloudscanner",
    "target": "bucket-name.s3.amazonaws.com",
    "params": {
      "check_vulnerabilities": true,
      "bucket_enumeration": true
    }
  }'
```

### CMS Vulnerability Scan
```bash
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-key" \
  -d '{
    "tool": "joomlascanner",
    "target": "example.com",
    "params": {
      "enumerate_plugins": true,
      "check_config": true
    }
  }'
```

## License

This project is for educational and authorized security testing purposes only. Always obtain proper authorization before scanning any targets.
