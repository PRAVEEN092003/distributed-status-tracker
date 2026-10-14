"""URL Validation and SSRF Protection Module for Distributed Status Tracker.

Separates URL syntax/format validation from target availability checking,
ensuring offline, unresolvable, or degraded endpoints can be registered
for continuous health monitoring and Root Cause Analysis while strictly
blocking SSRF attacks against localhost, loopback, private IP ranges,
and cloud metadata endpoints.
"""

import ipaddress
import re
import socket
import urllib.parse
from typing import Tuple, Optional

# Sensible limits
MIN_TIMEOUT = 1
MAX_TIMEOUT = 30
DEFAULT_TIMEOUT = 5

MIN_CHECK_INTERVAL = 10
MAX_CHECK_INTERVAL = 3600
DEFAULT_CHECK_INTERVAL = 60

# Blacklisted hostnames commonly used for SSRF
DISALLOWED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "metadata.google.internal",
    "169.254.169.254",
    "instance-data",
}


def is_ip_disallowed(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Check if an IP address belongs to private, loopback, link-local, or reserved spaces."""
    # Convert IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1) to IPv4
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped

    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return True

    # Carrier Grade NAT (100.64.0.0/10)
    if isinstance(ip, ipaddress.IPv4Address):
        cgnat_net = ipaddress.ip_network("100.64.0.0/10")
        if ip in cgnat_net:
            return True

    return False


def validate_url_format(url_str: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """Validate URL syntax, structure, scheme, and non-DNS SSRF constraints.

    Separates syntax validation from availability: does not perform network DNS lookup.

    Returns:
        (is_valid, normalized_url, error_message)
    """
    if not url_str or not isinstance(url_str, str):
        return False, None, "URL cannot be empty."

    url_str = url_str.strip()

    try:
        parsed = urllib.parse.urlsplit(url_str)
    except Exception:
        return False, None, "Malformed URL format."

    # 1. Scheme check: only http and https allowed
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        return False, None, "Only HTTP and HTTPS URLs are supported."

    # 2. Hostname check
    hostname = parsed.hostname
    if not hostname:
        return False, None, "URL must include a valid host name."

    hostname_lower = hostname.lower().strip()
    if (
        hostname_lower in DISALLOWED_HOSTNAMES
        or hostname_lower.endswith(".localhost")
        or hostname_lower.endswith(".local")
        or hostname_lower.endswith(".internal")
        or hostname_lower.endswith(".arpa")
    ):
        return False, None, "Target host is disallowed for security reasons."

    # 3. Check if hostname is directly an IP address literal
    clean_host = hostname_lower.strip("[]")
    try:
        ip_obj = ipaddress.ip_address(clean_host)
        if is_ip_disallowed(ip_obj):
            return False, None, "Access to private or local network destinations is blocked."
    except ValueError:
        # Not a raw IP literal
        pass

    # Normalize clean URL representation (omitting fragment)
    normalized = urllib.parse.urlunsplit((
        scheme,
        parsed.netloc,
        parsed.path or "/",
        parsed.query,
        "",
    ))

    return True, normalized, None


def check_target_ssrf_dns(
    hostname: str,
    port: int = 80,
    require_dns: bool = False,
) -> Tuple[bool, Optional[str]]:
    """Verify that a hostname does not resolve to private or loopback IP addresses.

    Args:
        hostname: The target domain or host string.
        port: Destination port (default 80).
        require_dns: If True, fails when hostname cannot be resolved.
                     If False (default), unresolved hostnames pass security validation,
                     allowing offline/down endpoints to be saved and monitored.

    Returns:
        (is_allowed, error_message_or_None)
    """
    clean_host = hostname.lower().strip().strip("[]")
    try:
        # If already an IP literal, skip getaddrinfo (already checked in validate_url_format)
        ipaddress.ip_address(clean_host)
        return True, None
    except ValueError:
        pass

    try:
        addr_infos = socket.getaddrinfo(clean_host, port, family=socket.AF_UNSPEC, proto=socket.IPPROTO_TCP)
        if not addr_infos:
            if require_dns:
                return False, "Unable to resolve target host."
            return True, None

        for family, socktype, proto, canonname, sockaddr in addr_infos:
            ip_str = sockaddr[0]
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                if is_ip_disallowed(ip_obj):
                    return False, "Target host resolves to a disallowed internal network address."
            except ValueError:
                return False, "Host resolved to an unrecognized address format."
    except socket.gaierror:
        if require_dns:
            return False, "Could not resolve hostname. Please verify the domain name."
        # DNS failed, but it did not resolve to a private IP; allow saving for monitoring
        return True, None
    except Exception as exc:
        if require_dns:
            return False, f"Error validating network target address: {exc}"
        return True, None

    return True, None


def validate_target_url(
    url_str: str,
    require_dns: bool = False,
) -> Tuple[bool, Optional[str], Optional[str]]:
    """Validate a URL against malformed structure, unsupported schemes, and SSRF targets.

    Args:
        url_str: Target URL string to validate.
        require_dns: Whether target hostname must resolve during validation (default False).

    Returns:
        (is_valid, normalized_url, error_message)
    """
    is_valid_format, normalized_url, format_err = validate_url_format(url_str)
    if not is_valid_format:
        return False, None, format_err

    parsed = urllib.parse.urlsplit(normalized_url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    is_safe_ssrf, ssrf_err = check_target_ssrf_dns(parsed.hostname, port, require_dns=require_dns)
    if not is_safe_ssrf:
        return False, None, ssrf_err

    return True, normalized_url, None


def validate_service_inputs(
    service_name: str,
    service_url: str,
    check_interval_raw: any,
    timeout_raw: any,
) -> Tuple[bool, dict, list]:
    """Validate and sanitize all form fields for creating or editing a service.

    Allows offline, unreachable, or unresolvable URLs to be registered as long as
    URL syntax and SSRF security policies are satisfied.

    Returns:
        (is_valid, cleaned_data, list_of_errors)
    """
    errors = []
    cleaned = {}

    # Service Name
    name = (service_name or "").strip()
    if not name:
        errors.append("Service name is required.")
    elif len(name) > 100:
        errors.append("Service name must be 100 characters or fewer.")
    cleaned["service_name"] = name

    # Service URL & SSRF
    is_valid_url, normalized_url, url_err = validate_target_url(service_url, require_dns=False)
    if not is_valid_url:
        errors.append(url_err)
    cleaned["service_url"] = normalized_url

    # Check Interval
    try:
        interval = int(check_interval_raw)
        if interval < MIN_CHECK_INTERVAL or interval > MAX_CHECK_INTERVAL:
            errors.append(f"Monitoring interval must be between {MIN_CHECK_INTERVAL} and {MAX_CHECK_INTERVAL} seconds.")
        cleaned["check_interval"] = interval
    except (ValueError, TypeError):
        errors.append(f"Check interval must be a valid integer between {MIN_CHECK_INTERVAL} and {MAX_CHECK_INTERVAL}.")
        cleaned["check_interval"] = DEFAULT_CHECK_INTERVAL

    # Request Timeout
    try:
        timeout = int(timeout_raw)
        if timeout < MIN_TIMEOUT or timeout > MAX_TIMEOUT:
            errors.append(f"Request timeout must be between {MIN_TIMEOUT} and {MAX_TIMEOUT} seconds.")
        cleaned["timeout"] = timeout
    except (ValueError, TypeError):
        errors.append(f"Timeout must be a valid integer between {MIN_TIMEOUT} and {MAX_TIMEOUT}.")
        cleaned["timeout"] = DEFAULT_TIMEOUT

    return (len(errors) == 0), cleaned, errors
