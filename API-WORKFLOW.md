# API Workflow Documentation

## Table of Contents
1. [Overview](#overview)
2. [Common Workflow Pattern](#common-workflow-pattern)
3. [Endpoint Details](#endpoint-details)
4. [Tool-Specific Workflows](#tool-specific-workflows)
5. [Internal Architecture](#internal-architecture)

---

## Overview

This document provides detailed workflow information for every API endpoint in the Security Scanner API. It explains how each endpoint works internally, what resources it uses, and how data flows through the system.

**Base URL:** `http://localhost:5000`

**Architecture:** Flask-based REST API with asynchronous job processing using Python threading.

---

## Common Workflow Pattern

All scanning tools follow the same workflow pattern:

### 1. Request Submission (POST /scan)
```
Client Request → Authentication → Rate Limiting → Validation → Job Creation → Background Thread → Response
```

### 2. Status Monitoring (GET /status/{job_id})
```
Client Request → Authentication → Job Lookup → Access Control → Status Response
```

### 3. Result Retrieval (GET /results/{job_id})
```
Client Request → Authentication → Job Lookup → Access Control → Completion Check → Results Response
```

### 4. Job Cancellation (POST /cancel/{job_id})
```
Client Request → Authentication → Job Lookup → Access Control → Status Update → Response
```

---

## Endpoint Details

### POST /scan

**Purpose:** Create and start a new security scan job

**Workflow:**

1. **Request Reception**
   - Flask receives POST request at `/scan`
   - Content-Type validation (must be `application/json`)

2. **Authentication** (if REQUIRE_AUTH=true)
   - Extract `X-API-Key` header
   - Hash provided key with SHA256
   - Compare with stored key hash using `hmac.compare_digest()` (timing-attack resistant)
   - Log failed attempts to `audit.log`
   - Return 401 if authentication fails

3. **Rate Limiting**
   - Check IP address against `ip_request_counts` dictionary
   - Remove requests older than 1 hour
   - Count requests in last hour
   - Return 429 if limit (100/hour) exceeded
   - Add current timestamp to request list

4. **Request Validation**
   - Parse JSON body
   - Validate allowed fields (tool, target, params)
   - Validate tool name against `SUPPORTED_TOOLS`
   - Validate target format and content
   - Check for SSRF attempts (private IPs, metadata services)
   - Check for injection patterns (shell metacharacters, commands)

5. **Concurrent Scan Check**
   - Acquire lock on `active_scans`
   - Check if `active_scans["count"]` < `MAX_CONCURRENT_SCANS` (5)
   - Return 429 if limit reached

6. **Job Creation**
   - Generate unique UUID for job_id
   - Create job dictionary with metadata
   - Store in `scan_jobs` OrderedDict
   - Track ownership in `job_owners` (API key hash or IP)
   - Call `cleanup_old_jobs()` if needed (max 1000 jobs)

7. **Background Thread Launch**
   - Get scan function from `get_scan_function(tool)`
   - Create daemon thread with `run_scan_async()`
   - Pass job_id, tool, scan_function, target, params
   - Start thread (non-blocking)

8. **Response**
   - Return 202 Accepted
   - Include job_id, status, tool, target, estimated_time

**Resources Used:**
- `scan_jobs` - OrderedDict for job storage
- `job_owners` - Dictionary for access control
- `active_scans` - Dictionary with lock for concurrency control
- `ip_request_counts` - Dictionary for rate limiting
- `audit_logger` - File logger for security events
- Background thread for async execution

**Data Flow:**
```
Request → Validation → Job Creation → Thread Launch → Response
                ↓
         Background Execution
                ↓
         Update job status/results
```


---

### GET /status/{job_id}

**Purpose:** Check the current status of a scan job

**Workflow:**

1. **Request Reception**
   - Flask receives GET request at `/status/{job_id}`
   - Extract job_id from URL path

2. **Authentication** (if REQUIRE_AUTH=true)
   - Same authentication process as POST /scan

3. **Job Lookup**
   - Check if job_id exists in `scan_jobs` dictionary
   - Return 404 if not found

4. **Access Control**
   - Get current owner ID (API key hash or IP)
   - Check if owner matches `job_owners[job_id]`
   - Log unauthorized attempts to `audit.log`
   - Return 403 if access denied

5. **Status Response**
   - Copy job dictionary (to avoid mutation)
   - Return job data with current status

**Resources Used:**
- `scan_jobs` - Read job data
- `job_owners` - Verify access
- `audit_logger` - Log unauthorized access

**Possible Status Values:**
- `queued` - Job created, waiting to start
- `running` - Scan currently executing
- `completed` - Scan finished successfully
- `failed` - Scan encountered an error
- `cancelled` - Scan was manually cancelled


---

### GET /results/{job_id}

**Purpose:** Retrieve completed scan results

**Workflow:**

1. **Request Reception**
   - Flask receives GET request at `/results/{job_id}`
   - Extract job_id from URL path

2. **Authentication** (if REQUIRE_AUTH=true)
   - Same authentication process as POST /scan

3. **Job Lookup**
   - Check if job_id exists in `scan_jobs`
   - Return 404 if not found

4. **Access Control**
   - Verify owner matches current user
   - Return 403 if access denied

5. **Completion Check**
   - Check if job status is "completed"
   - Return 400 with current status if not completed

6. **Results Response**
   - Extract result data from job
   - Return job_id, tool, target, status, result, completed_at

**Resources Used:**
- `scan_jobs` - Read job and result data
- `job_owners` - Verify access
- `audit_logger` - Log unauthorized access

**Data Structure:**
Results vary by tool but always include:
- `tool` - Scanner name
- `target` - Scanned target
- `command` - Command executed
- Tool-specific result fields


---

### POST /cancel/{job_id}

**Purpose:** Cancel a running or queued scan

**Workflow:**

1. **Request Reception**
   - Flask receives POST request at `/cancel/{job_id}`

2. **Authentication** (if REQUIRE_AUTH=true)
   - Same authentication process

3. **Job Lookup & Access Control**
   - Check job exists and user has access
   - Return 404 or 403 as appropriate

4. **Status Validation**
   - Check current status
   - Return 400 if already completed/failed/cancelled

5. **Cancellation**
   - Update job status to "cancelled"
   - Set completed_at timestamp
   - Note: Background thread may still complete

6. **Response**
   - Return job_id, status, success message

**Resources Used:**
- `scan_jobs` - Update job status
- `job_owners` - Verify access

**Limitations:**
- Cannot stop already running subprocess
- Thread will complete but results marked as cancelled


---

### GET /jobs

**Purpose:** List all scan jobs with filtering

**Workflow:**

1. **Request Reception**
   - Parse query parameters: limit (default 50), status (optional)

2. **Authentication** (if REQUIRE_AUTH=true)
   - Same authentication process

3. **Job Filtering**
   - Get last N jobs from `scan_jobs` OrderedDict
   - Filter by status if provided
   - Extract summary fields only

4. **Response**
   - Return total_jobs count
   - Return active_scans count
   - Return filtered job list

**Resources Used:**
- `scan_jobs` - Read all jobs
- `active_scans` - Get current count

---

### GET /health

**Purpose:** Health check for monitoring

**Workflow:**

1. **Request Reception**
   - No authentication required

2. **System Status Collection**
   - Get active_scans count
   - Get total_jobs count
   - Get supported_tools list
   - Get current timestamp

3. **Response**
   - Return health status and metrics

**Resources Used:**
- `scan_jobs`, `active_scans`, `SUPPORTED_TOOLS`


---

### GET /metrics

**Purpose:** Prometheus-style metrics

**Workflow:**

1. **Request Reception**
   - No authentication required

2. **Metrics Collection**
   - Count jobs by status
   - Get active scans
   - Format as Prometheus text

3. **Response**
   - Return text/plain format metrics

**Resources Used:**
- `scan_jobs` - Aggregate statistics
- `active_scans` - Current count

---

## Tool-Specific Workflows



### Domain Finder (domainfinder)

**Internal Execution:**

1. **Domain Validation**
   - Clean target (remove protocol, path)
   - Validate domain format with regex
   - Extract base domain

2. **SSL Certificate Discovery** (if enabled)
   - Connect to port 443/8443 with SSL
   - Extract certificate
   - Parse Subject Alternative Names (SAN)
   - Extract Common Name (CN)
   - Add discovered domains with confidence scores

3. **BuiltWith Discovery** (if enabled)
   - Simulate BuiltWith API lookup
   - Find related domains
   - Assign confidence based on relationship

4. **Reverse WHOIS** (if enabled)
   - Simulate WHOIS lookup
   - Find domains with same registrant
   - Assign confidence scores

5. **Confidence Scoring**
   - Calculate weights based on discovery methods
   - Filter by minimum_weight threshold
   - Categorize as high/medium/low confidence

6. **Response Formation**
   - Return associated_domains with scores
   - Include discovery_methods for each
   - Provide confidence summary


**Resources Used:**
- ssl module for certificate inspection
- socket module for connections
- requests library for HTTP calls
- DNS resolution

**Data Flow:**
```
Domain → SSL Cert Check → BuiltWith → WHOIS → Scoring → Filtering → Results
```

---

### Cloud Scanner (cloudscanner)

**Internal Execution:**

1. **Provider Detection** (if enabled)
   - Check URL patterns for AWS/GCP/Azure
   - Detect S3 buckets (.s3.amazonaws.com)
   - Detect GCS buckets (storage.googleapis.com)
   - Detect Azure blobs (blob.core.windows.net)

2. **Vulnerability Checking** (if enabled)
   - Test for public read access
   - Check for directory listing
   - Test metadata service access (169.254.169.254)
   - Test for public write access
   - Identify ACL misconfigurations

3. **Bucket Enumeration** (if enabled)
   - List bucket contents via HTTP GET
   - Parse XML listings (AWS S3 format)
   - Parse HTML directory listings
   - Identify sensitive files (sql, key, env, config)
   - Assign risk levels to files

4. **Response Formation**
   - Return detected_provider
   - List vulnerabilities with severity
   - List interesting_files with risk levels
   - Provide vulnerability summary


**Resources Used:**
- requests library for HTTP calls
- xml.etree.ElementTree for XML parsing
- Regular expressions for pattern matching
- File risk assessment logic

**Data Flow:**
```
Target → Provider Detection → Vulnerability Checks → Bucket Enum → Risk Assessment → Results
```

---

### Password Auditor (passwordauditor)

**Internal Execution:**

1. **Service Discovery**
   - Resolve hostname to IP
   - Scan specified ports (default: top 100)
   - Identify services (SSH, FTP, HTTP, etc.)
   - Grab banners for version detection
   - Use ThreadPoolExecutor for concurrent scanning

2. **Web Form Detection**
   - Identify HTTP/HTTPS services
   - Check common login paths
   - Parse HTML for login forms
   - Extract form fields (username, password)
   - Identify form method (POST/GET)

3. **Credential Testing**
   - Load default credentials database
   - Load custom wordlists if provided
   - Test credentials against services
   - Respect delay parameter
   - Implement lockout period for spray attacks
   - Track attempts per service

4. **Response Formation**
   - Return discovered_services
   - Return weak_credentials found
   - Return web_forms detected
   - Include attack statistics


**Resources Used:**
- socket module for port scanning
- requests library for web form testing
- ThreadPoolExecutor for concurrent operations
- Default credentials database
- Custom wordlist files

**Data Flow:**
```
Target → Port Scan → Service ID → Form Detection → Cred Testing → Results
```

---

### Drupal Scanner (drupalscanner)

**Internal Execution:**

1. **Version Detection**
   - Check common Drupal files
   - Parse XML manifests
   - Check meta generator tags
   - Identify version from changelog
   - Assign confidence level

2. **Module/Theme Enumeration** (if enabled)
   - Check common module paths
   - Check common theme paths
   - Parse XML for version info
   - Identify enabled components

3. **Vulnerability Checking** (if enabled)
   - Match version against CVE database
   - Check component versions
   - Identify known vulnerabilities
   - Assign severity levels

4. **Configuration Checks** (if enabled)
   - Test for directory listings
   - Check for exposed config files
   - Identify misconfigurations
   - Assign risk levels

**Resources Used:**
- requests library for HTTP calls
- Regular expressions for parsing
- CVE database (hardcoded)
- XML parsing


---

### Joomla Scanner (joomlascanner)

**Internal Execution:**

1. **Version Detection**
   - Check joomla.xml manifest
   - Check version.php file
   - Parse meta generator tag
   - Identify Joomla indicators
   - Extract version number

2. **Component Enumeration** (if enabled)
   - Check common components (com_*)
   - Check common modules (mod_*)
   - Check common templates
   - Parse XML for versions
   - Identify installed items

3. **Vulnerability Checking** (if enabled)
   - Match version against CVE database
   - Check component vulnerabilities
   - Record CVE numbers
   - Assign severity levels

4. **Configuration Checks** (if enabled)
   - Test for directory listings
   - Check configuration.php exposure
   - Check admin paths
   - Identify misconfigurations

**Resources Used:**
- requests library
- XML parsing
- CVE database
- Regular expressions

---

### SharePoint Scanner (sharepointscanner)

**Internal Execution:**

1. **Version Detection**
   - Check _layouts paths
   - Check _vti_pvt paths
   - Parse server headers
   - Identify SharePoint version
   - Detect 2013/2016/2019/Online

2. **Configuration Analysis** (if enabled)
   - Check _vti_pvt directory
   - Check _vti_bin directory
   - Test for sensitive file exposure
   - Identify directory listings

3. **Web Service Exposure** (if enabled)
   - Check SOAP web services (.asmx)
   - Check REST API endpoints (_api/)
   - Test for authentication requirements
   - Identify exposed services

4. **User Enumeration** (if enabled)
   - Check people.aspx
   - Check userdisp.aspx
   - Extract email addresses
   - Extract domain users


**Resources Used:**
- requests library with session management
- Regular expressions for parsing
- XML/HTML parsing
- User-Agent spoofing

**Data Flow:**
```
Target → Version Detection → Config Analysis → Service Check → User Enum → Results
```

---

## Internal Architecture

### Job Management System

**Data Structures:**

1. **scan_jobs** (OrderedDict)
   - Stores all job data
   - Key: job_id (UUID string)
   - Value: Job dictionary with metadata
   - Max size: 1000 jobs (auto-cleanup)

2. **job_owners** (Dictionary)
   - Tracks job ownership
   - Key: job_id
   - Value: owner_id (API key hash or IP)
   - Used for access control

3. **active_scans** (Dictionary with Lock)
   - Tracks concurrent scans
   - Fields: count (int), lock (threading.Lock)
   - Max concurrent: 5

4. **ip_request_counts** (Dictionary with Lock)
   - Tracks rate limiting
   - Key: IP address
   - Value: List of timestamps
   - Cleanup: Remove entries > 1 hour old

**Threading Model:**

- Main thread: Flask HTTP server
- Background threads: One per scan job
- Daemon threads: Auto-terminate on exit
- Thread safety: Locks on shared resources


### Background Scan Execution

**Function:** `run_scan_async(job_id, tool, scan_function, *args, **kwargs)`

**Workflow:**

1. **Initialization**
   - Acquire lock on active_scans
   - Increment active_scans["count"]
   - Release lock

2. **Status Update**
   - Set job status to "running"
   - Set started_at timestamp
   - Log scan start

3. **Scan Execution**
   - Call scan_function(target, params)
   - Catch all exceptions
   - Timeout handled by individual tools

4. **Success Handling**
   - Set job status to "completed"
   - Store result in job dictionary
   - Set completed_at timestamp
   - Log completion

5. **Error Handling**
   - Set job status to "failed"
   - Store generic error message
   - Set completed_at timestamp
   - Log full error with traceback

6. **Cleanup**
   - Acquire lock on active_scans
   - Decrement active_scans["count"]
   - Release lock

**Error Isolation:**
- Exceptions don't crash server
- Detailed errors logged server-side
- Generic errors returned to client


### Security Layer

**Authentication Flow:**

```
Request → Extract X-API-Key → Hash with SHA256 → Compare with stored hash
                                                          ↓
                                                   hmac.compare_digest()
                                                          ↓
                                              Timing-attack resistant
```

**SSRF Protection:**

1. **Character Validation**
   - Whitelist: alphanumeric, dots, hyphens, colons, slashes
   - Reject: shell metacharacters, commands

2. **Injection Detection**
   - Pattern matching for shell commands
   - Newline detection
   - Command injection patterns

3. **IP Validation**
   - Parse target as IP or resolve DNS
   - Block private IPs (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
   - Block loopback (127.0.0.0/8)
   - Block metadata services (169.254.169.254, 168.63.169.254, 100.100.100.200)
   - Block reserved ranges

**Audit Logging:**

Events logged to `audit.log`:
- Failed authentication attempts
- Unauthorized job access attempts
- SSRF attempts
- Injection attempts

Format: `timestamp - event_description`

### Response Headers

**Security Headers Applied:**

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Strict-Transport-Security: max-age=31536000`
- `Content-Security-Policy: default-src 'self'`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy: geolocation=(), microphone=(), camera=()`

**CORS Headers:**

- `Access-Control-Allow-Origin: {ALLOWED_ORIGIN}`
- `Access-Control-Allow-Methods: GET, POST, OPTIONS`
- `Access-Control-Allow-Headers: Content-Type, X-API-Key`


### Tool Registry

**SUPPORTED_TOOLS Dictionary:**

```python
{
    'tool_name': {
        'timeout': seconds,
        'description': 'Tool description'
    }
}
```

**Timeout Values:**
- wafw00f: 120s
- nmap: 600s
- nuclei: None (no timeout)
- dirb: None
- whatweb: 60s
- nikto: 1800s
- masscan: 300s
- sslscan: 120s
- httpx: 60s
- gvm: 3600s
- domainfinder: 300s
- cloudscanner: 900s
- passwordauditor: 1800s
- drupalscanner: 300s
- joomlascanner: 300s
- sharepointscanner: 300s

**Function Mapping:**

`get_scan_function(tool)` returns appropriate function:
- run_wafw00f()
- run_nmap()
- run_nuclei()
- run_dirb()
- run_whatweb()
- run_nikto()
- run_masscan()
- run_sslscan()
- run_httpx()
- run_gvm()

- run_domainfinder()
- run_cloudscanner()
- run_passwordauditor()
- run_drupalscanner()
- run_joomlascanner()
- run_sharepointscanner()


### Resource Management

**Memory Management:**

1. **Job Cleanup**
   - Function: `cleanup_old_jobs()`
   - Trigger: When scan_jobs > 1000
   - Action: Remove oldest 100 jobs
   - Uses FIFO from OrderedDict

2. **Rate Limit Cleanup**
   - Automatic on each request
   - Remove timestamps > 1 hour old
   - Prevents memory growth

**Concurrency Control:**

1. **Active Scans Limit**
   - Max: 5 concurrent scans
   - Enforced at job creation
   - Thread-safe with lock

2. **Thread Management**
   - Daemon threads auto-cleanup
   - No thread pool (one thread per job)
   - Threads tracked via active_scans counter

**File Resources:**

1. **Temporary Files**
   - Created with tempfile module
   - Auto-deleted after use
   - Used for tool output (JSON, XML)

2. **Log Files**
   - audit.log (append-only)
   - Server logs (stdout/stderr)

### Error Handling Strategy

**Client Errors (4xx):**
- 400: Invalid parameters, malformed JSON
- 401: Authentication failed
- 403: Access denied (wrong owner)
- 404: Job not found
- 429: Rate limit or concurrent limit exceeded

**Server Errors (5xx):**
- 500: Internal server error
- Scan failures return 200 with error in result

**Error Response Format:**
```json
{
    "error": "Error description",
    "details": "Additional context (optional)"
}
```


### Performance Considerations

**Optimization Strategies:**

1. **Asynchronous Processing**
   - Background threads prevent blocking
   - Client can poll for results
   - Multiple clients supported

2. **Resource Limits**
   - Timeouts prevent hung scans
   - Rate limiting prevents abuse
   - Concurrent limits prevent overload

3. **Efficient Data Structures**
   - OrderedDict for FIFO cleanup
   - Dictionary lookups O(1)
   - Minimal data copying

### Monitoring and Observability

**Health Check (/health):**
- Active scans count
- Total jobs count
- Supported tools list
- Timestamp

**Metrics (/metrics):**
- Prometheus format
- Active scans gauge
- Total jobs gauge
- Jobs by status gauge

**Logging:**
- Application logs (INFO level)
- Audit logs (security events)
- Error logs with tracebacks
- Scan start/completion logs

**Recommended Monitoring:**
- Track active_scans over time
- Alert on high failure rates
- Monitor response times
- Track authentication failures


---

## Complete Request/Response Examples

### Example 1: URL Fuzzer Scan

**Request:**
```bash
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: abc123" \
  -d '{
    "tool": "urlfuzzer",
    "target": "example.com",
    "params": {
      "extensions": "php,html",
      "threads": 10,
      "match_codes": "200,403"
    }
  }'
```

**Response (202):**
```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "queued",
  "tool": "urlfuzzer",
  "target": "example.com",
  "message": "urlfuzzer scan started",
  "estimated_time": "600 seconds"
}
```

**Internal Flow:**
1. Authenticate API key
2. Check rate limit for IP
3. Validate target "example.com"
4. Check concurrent scans (< 5)
5. Create job with UUID
6. Store in scan_jobs
7. Track owner in job_owners
8. Launch background thread
9. Return 202 response

**Background Thread:**
1. Set status to "running"
2. Build dirb command
3. Execute dirb with timeout
4. Parse output
5. Store results
6. Set status to "completed"
7. Decrement active_scans

**Status Check:**
```bash
curl -H "X-API-Key: abc123" \
  http://localhost:5000/status/550e8400-e29b-41d4-a716-446655440000
```

**Results Retrieval:**
```bash
curl -H "X-API-Key: abc123" \
  http://localhost:5000/results/550e8400-e29b-41d4-a716-446655440000
```


### Example 2: Domain Finder with Filtering

**Request:**
```bash
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: abc123" \
  -d '{
    "tool": "domainfinder",
    "target": "example.com",
    "params": {
      "ssl_certificates": true,
      "builtwith": true,
      "minimum_weight": 0.7
    }
  }'
```

**Internal Flow:**
1. Authenticate
2. Validate domain format
3. Create job
4. Launch thread:
   - Connect to SSL port
   - Extract certificate SANs
   - Simulate BuiltWith lookup
   - Calculate confidence scores
   - Filter by minimum_weight (0.7)
   - Return high-confidence domains only

**Result Structure:**
```json
{
  "tool": "domainfinder",
  "target": "example.com",
  "associated_domains": [
    {
      "domain": "api.example.com",
      "confidence_score": 0.95,
      "discovery_methods": ["ssl_certificate"],
      "validation_factors": {
        "ssl_certificates": 3
      }
    }
  ],
  "total_domains": 5,
  "high_confidence": 3,
  "medium_confidence": 2,
  "low_confidence": 0
}
```

### Example 3: Cloud Scanner

**Request:**
```bash
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: abc123" \
  -d '{
    "tool": "cloudscanner",
    "target": "bucket.s3.amazonaws.com",
    "params": {
      "check_vulnerabilities": true,
      "bucket_enumeration": true
    }
  }'
```

**Internal Flow:**
1. Detect provider (AWS S3)
2. Test for public access
3. Check for misconfigurations
4. Enumerate bucket contents
5. Identify sensitive files
6. Assign risk levels
7. Return vulnerabilities and files

---

## Troubleshooting Guide

### Common Issues

**Issue: 401 Unauthorized**
- Cause: Missing or invalid API key
- Solution: Check X-API-Key header, verify REQUIRE_AUTH setting

**Issue: 429 Rate Limit**
- Cause: Too many requests from IP
- Solution: Wait 1 hour or reduce request frequency

**Issue: 429 Concurrent Limit**
- Cause: 5 scans already running
- Solution: Wait for scans to complete or cancel unnecessary scans

**Issue: Scan stays in "running" forever**
- Cause: Tool hung or crashed
- Solution: Check server logs, restart server if needed

**Issue: 403 Access Denied**
- Cause: Trying to access another user's job
- Solution: Verify job_id, check API key

**Issue: SSRF Protection blocking valid target**
- Cause: Target resolves to private IP
- Solution: Use public IP or disable SSRF protection (not recommended)

---

## Summary

This API follows a consistent pattern across all tools:
1. Authenticate request
2. Validate input
3. Create job asynchronously
4. Execute tool in background
5. Store results
6. Allow polling for status/results