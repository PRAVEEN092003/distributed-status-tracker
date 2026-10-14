"""Smart Failure Detection and Root Cause Analysis (RCA) Module.

Provides deterministic classification of service disruptions, extracts diagnostic
evidence, determines probable root causes, and recommends troubleshooting steps.
"""

from typing import Dict, Any, Optional

# Standard Failure Categories
CAT_DNS_FAILURE = "DNS resolution failure"
CAT_TIMEOUT = "Connection timeout"
CAT_CONNECTION_TIMEOUT = CAT_TIMEOUT
CAT_CONN_REFUSED = "Connection refused"
CAT_CONNECTION_REFUSED = CAT_CONN_REFUSED
CAT_SSL_ERROR = "SSL/TLS certificate or handshake error"
CAT_NETWORK_FAILURE = "Network connection failure"
CAT_HTTP_CLIENT_ERROR = "HTTP client error"
CAT_HTTP_SERVER_ERROR = "HTTP server error"
CAT_SLOW_RESPONSE = "Slow response"
CAT_REDIRECT_CONFIG = "Unexpected redirect or configuration issue"
CAT_UNEXPECTED_REDIRECT = CAT_REDIRECT_CONFIG
CAT_UNKNOWN = "Unknown failure"
CAT_UNKNOWN_FAILURE = CAT_UNKNOWN


def analyze_failure(
    status: str,
    http_status_code: Optional[int],
    response_time_ms: float,
    raw_error: Any,
    timeout_limit: int = 5,
) -> Dict[str, Any]:
    """Perform deterministic Root Cause Analysis on a monitoring event.

    Returns dictionary containing:
        - failure_category (str)
        - evidence (str)
        - possible_cause (str)
        - recommended_steps (str)
        - confidence (str: 'High', 'Medium', 'Low')
    """
    err_str = str(raw_error) if raw_error is not None else ""
    err_lower = err_str.lower()

    # Healthy / normal checks
    if status == "UP" and not raw_error and (http_status_code is None or http_status_code < 400):
        return {
            "failure_category": None,
            "evidence": f"HTTP {http_status_code or 200} response received in {round(response_time_ms, 1)}ms",
            "possible_cause": "Service operating normally within expected parameters.",
            "recommended_steps": "No action required.",
            "confidence": "High",
        }

    # 1. DNS Resolution Failures
    if any(k in err_lower for k in ("dns", "resolv", "getaddrinfo", "gaierror", "name or service not known", "nodename nor servname")):
        return {
            "failure_category": CAT_DNS_FAILURE,
            "evidence": f"DNS query failed for domain. Diagnostic: {err_str}",
            "possible_cause": "Authoritative nameservers are unreachable, domain registration expired, or DNS A/AAAA records are missing/misconfigured.",
            "recommended_steps": "1. Run 'nslookup <domain>' or 'dig <domain>' to verify DNS records.\n2. Verify registrar status and nameserver delegation.\n3. Check authoritative DNS provider uptime.",
            "confidence": "High",
        }

    # 2. Connection Timeouts
    if any(k in err_lower for k in ("timed out", "timeout", "connecttimeout", "readtimeout")) or ("time" in err_lower and "out" in err_lower):
        return {
            "failure_category": CAT_TIMEOUT,
            "evidence": f"Connection timed out after {timeout_limit}s threshold without completing TCP handshake or HTTP headers. Diagnostic: {err_str}",
            "possible_cause": "Target server is unresponsive, dropped packets due to firewall/routing rules, or server is under heavy load.",
            "recommended_steps": "1. Verify host network connectivity with ping/traceroute.\n2. Inspect firewall/security group rules allowing inbound traffic on target port.\n3. Check server CPU, memory, and connection pool saturation.",
            "confidence": "High",
        }

    # 3. Connection Refused
    if any(k in err_lower for k in ("connection refused", "refused", "winerror 10061", "errno 111", "actively refused")):
        return {
            "failure_category": CAT_CONN_REFUSED,
            "evidence": f"TCP SYN packet was rejected with RST. Diagnostic: {err_str}",
            "possible_cause": "Target host is reachable, but the web server process (e.g. Nginx, Apache, Node, Flask) is stopped or not listening on this port.",
            "recommended_steps": "1. Verify web server process status (e.g. systemctl status nginx).\n2. Verify target port is actively bound with 'netstat -tuln' or 'Get-NetTCPConnection'.\n3. Restart web server service.",
            "confidence": "High",
        }

    # 4. SSL / TLS Certificate or Handshake Errors
    if any(k in err_lower for k in ("ssl", "certificate", "tls", "handshake", "cert")):
        return {
            "failure_category": CAT_SSL_ERROR,
            "evidence": f"TLS handshake negotiation failed. Diagnostic: {err_str}",
            "possible_cause": "SSL certificate expired, domain name mismatch (CN/SAN mismatch), untrusted CA authority, or cipher suite incompatibility.",
            "recommended_steps": "1. Inspect SSL certificate expiration date using 'openssl s_client -connect <host>:443'.\n2. Verify Let's Encrypt / certbot auto-renewal timer.\n3. Ensure TLS domain covers the full subdomain/hostname.",
            "confidence": "High",
        }

    # 5. Redirect & SSRF Configuration Issues
    if any(k in err_lower for k in ("redirect", "security check failed", "toomanyredirects")):
        return {
            "failure_category": CAT_REDIRECT_CONFIG,
            "evidence": f"Redirect loop or disallowed destination target encountered. Diagnostic: {err_str}",
            "possible_cause": "Infinite redirect loop (e.g. HTTP -> HTTPS -> HTTP), misconfigured rewrite rules, or redirect pointing to a restricted internal address.",
            "recommended_steps": "1. Test redirects with 'curl -IL <url>'.\n2. Verify web server reverse proxy rewrite rules.\n3. Ensure base URL Canonical configuration matches server scheme.",
            "confidence": "High",
        }

    # 6. HTTP Status Code Classifications
    if http_status_code:
        # HTTP 5xx Server Errors
        if 500 <= http_status_code < 600:
            if http_status_code == 502:
                cause = "Upstream reverse proxy (Nginx/Cloudflare) cannot communicate with backend application server."
                steps = "1. Verify backend application process is running.\n2. Check backend UNIX socket or TCP port.\n3. Check reverse proxy error logs (nginx error.log)."
            elif http_status_code == 503:
                cause = "Service temporarily unavailable due to scheduled maintenance, rate limiting, or backend worker pool exhaustion."
                steps = "1. Check if backend is in maintenance mode.\n2. Inspect server resource saturation.\n3. Scale up backend worker processes."
            elif http_status_code == 504:
                cause = "Upstream gateway timed out waiting for backend application response."
                steps = "1. Optimize slow database queries.\n2. Increase reverse proxy proxy_read_timeout if operation is long-running.\n3. Check backend application threads/workers."
            else:
                cause = f"Backend application crashed or threw an unhandled exception (HTTP {http_status_code})."
                steps = "1. Inspect application server error logs and stack traces.\n2. Check database connectivity from the application.\n3. Verify recent deployments or configuration changes."

            return {
                "failure_category": CAT_HTTP_SERVER_ERROR,
                "evidence": f"Received HTTP {http_status_code} server response code in {round(response_time_ms, 1)}ms.",
                "possible_cause": cause,
                "recommended_steps": steps,
                "confidence": "High",
            }

        # HTTP 4xx Client Errors
        if 400 <= http_status_code < 500:
            if http_status_code == 404:
                cause = "Target route or asset not found on the web server."
                steps = "1. Verify endpoint URL path spelling.\n2. Check web server routing configuration.\n3. Verify file or API route exists."
            elif http_status_code == 429:
                cause = "Target server rate limiting or Web Application Firewall (WAF) threshold triggered."
                steps = "1. Increase check interval to reduce request frequency.\n2. Whitelist monitoring agent IP/User-Agent in target firewall/rate-limiter."
            elif http_status_code in (401, 403):
                cause = "Target endpoint requires authentication credentials or IP is restricted by access control."
                steps = "1. Provide required authentication headers or cookies if supported.\n2. Configure endpoint to allow monitoring health checks without auth."
            else:
                cause = f"Client request rejected by server with HTTP {http_status_code}."
                steps = "1. Check request parameters and headers.\n2. Verify endpoint specification."

            return {
                "failure_category": CAT_HTTP_CLIENT_ERROR,
                "evidence": f"Server responded with HTTP {http_status_code} error code.",
                "possible_cause": cause,
                "recommended_steps": steps,
                "confidence": "High",
            }

    # 7. Slow Response
    if status == "DEGRADED" and response_time_ms > 2000:
        return {
            "failure_category": CAT_SLOW_RESPONSE,
            "evidence": f"Latency of {round(response_time_ms, 1)}ms exceeded degraded threshold (2000ms).",
            "possible_cause": "High server CPU/memory load, slow database queries, lack of caching, or network congestion.",
            "recommended_steps": "1. Profile slow database queries and backend execution time.\n2. Implement HTTP caching (Redis/CDN/Varnish).\n3. Check server bandwidth and network latency.",
            "confidence": "Medium",
        }

    # 8. Generic Network Connection Failure
    if any(k in err_lower for k in ("unreachable", "no route to host", "network is down", "connection error", "failed to establish a new connection")):
        return {
            "failure_category": CAT_NETWORK_FAILURE,
            "evidence": f"Underlying TCP/IP socket connection failure. Diagnostic: {err_str}",
            "possible_cause": "Intermediate network routing breakdown, ISP outage, or server dropped connection.",
            "recommended_steps": "1. Test connectivity via traceroute.\n2. Check datacenter or hosting provider network status.",
            "confidence": "Medium",
        }

    # 9. Fallback Unknown
    return {
        "failure_category": CAT_UNKNOWN,
        "evidence": f"Unrecognized failure condition. Error: {err_str or 'None'}, Code: {http_status_code or 'None'}",
        "possible_cause": "Unknown or undetermined cause based on currently available monitoring telemetry.",
        "recommended_steps": "1. Check host system logs.\n2. Verify network topology and application metrics.",
        "confidence": "Low",
    }
