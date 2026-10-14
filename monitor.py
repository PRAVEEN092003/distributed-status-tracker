"""Website Monitoring Engine for Distributed Status Tracker.

Performs safe HTTP checks using Requests, handles SSRF-protected redirects,
categorizes statuses (UP, DEGRADED, DOWN), and records results in SQLite.
"""

import logging
import sqlite3
import time
import urllib.parse
from typing import Dict, Any, Optional, Tuple

import requests
from requests.exceptions import RequestException, Timeout, SSLError, ConnectionError

from validator import validate_target_url
import rca_engine
import risk_engine

logger = logging.getLogger(__name__)

# Constants
LATENCY_DEGRADED_THRESHOLD_MS = 2000.0  # Latency > 2000ms is considered DEGRADED
MAX_REDIRECTS = 5
DEFAULT_USER_AGENT = "DistributedStatusTracker/1.0 (+https://localhost/bot)"


def perform_safe_request(url: str, timeout: int) -> Tuple[Optional[requests.Response], float, Optional[str]]:
    """Execute HTTP request with strict per-hop SSRF validation across all redirects.

    Returns:
        (response_obj_or_None, elapsed_ms, error_message_or_None)
    """
    current_url = url
    headers = {"User-Agent": DEFAULT_USER_AGENT}
    total_start_time = time.perf_counter()

    for hop in range(MAX_REDIRECTS + 1):
        # Validate current destination before every socket connect
        is_valid, normalized_url, err_msg = validate_target_url(current_url)
        if not is_valid:
            elapsed_ms = (time.perf_counter() - total_start_time) * 1000.0
            return None, elapsed_ms, f"Security check failed: {err_msg}"

        try:
            # We explicitly disable automatic redirects to intercept and validate each hop
            res = requests.get(
                normalized_url,
                headers=headers,
                timeout=timeout,
                allow_redirects=False,
                verify=True,
                stream=True,  # Avoid downloading large payloads
            )
            # Read first chunk or head to measure response without large payload
            _ = res.raw.read(1024)

            # Check if redirect
            if res.is_redirect and "Location" in res.headers:
                location = res.headers["Location"]
                current_url = urllib.parse.urljoin(normalized_url, location)
                continue
            else:
                elapsed_ms = (time.perf_counter() - total_start_time) * 1000.0
                return res, elapsed_ms, None

        except Timeout:
            elapsed_ms = (time.perf_counter() - total_start_time) * 1000.0
            return None, elapsed_ms, f"Request timed out after {timeout}s"
        except SSLError as e:
            elapsed_ms = (time.perf_counter() - total_start_time) * 1000.0
            return None, elapsed_ms, f"SSL certificate verification failed: {e}"
        except ConnectionError as e:
            elapsed_ms = (time.perf_counter() - total_start_time) * 1000.0
            err_str = str(e)
            err_lower = err_str.lower()
            if any(k in err_lower for k in ("dns", "resolv", "getaddrinfo", "gaierror", "nameresolutionerror", "name or service not known", "nodename nor servname")):
                return None, elapsed_ms, f"DNS resolution failed: {e}"
            elif any(k in err_lower for k in ("connection refused", "refused", "10061", "errno 111", "actively refused")):
                return None, elapsed_ms, f"Connection refused: {e}"
            elif any(k in err_lower for k in ("timeout", "timed out")):
                return None, elapsed_ms, f"Connection timed out: {e}"
            return None, elapsed_ms, f"Connection failed: {e}"
        except RequestException as e:
            elapsed_ms = (time.perf_counter() - total_start_time) * 1000.0
            err_str = str(e)
            err_lower = err_str.lower()
            if any(k in err_lower for k in ("dns", "resolv", "getaddrinfo", "gaierror", "nameresolutionerror", "name or service not known", "nodename nor servname")):
                return None, elapsed_ms, f"DNS resolution failed: {e}"
            return None, elapsed_ms, f"Network request error occurred: {e}"

    elapsed_ms = (time.perf_counter() - total_start_time) * 1000.0
    return None, elapsed_ms, "Too many redirects (exceeded limit of 5 hops)"


def evaluate_status(
    response: Optional[requests.Response],
    elapsed_ms: float,
    error_msg: Optional[str],
) -> Tuple[str, Optional[int], Optional[str]]:
    """Determine monitoring status (UP, DEGRADED, DOWN) according to response and latency.

    Returns:
        (status, http_status_code, final_error_message)
    """
    if response is None:
        err_text = str(error_msg) if error_msg is not None else "Connection failed"
        return "DOWN", None, err_text

    status_code = response.status_code

    # 1. Successful HTTP responses (2xx, 3xx)
    if status_code < 400:
        if elapsed_ms > LATENCY_DEGRADED_THRESHOLD_MS:
            return (
                "DEGRADED",
                status_code,
                f"High latency: {round(elapsed_ms)}ms (threshold {round(LATENCY_DEGRADED_THRESHOLD_MS)}ms)",
            )
        return "UP", status_code, None

    # 2. Authentication challenges: Server is operational, endpoint requires auth
    if status_code in (401, 403):
        if elapsed_ms > LATENCY_DEGRADED_THRESHOLD_MS:
            return "DEGRADED", status_code, f"HTTP {status_code}: Server reachable with high latency"
        return "UP", status_code, f"HTTP {status_code}: Endpoint reachable (Authentication required)"

    # 3. Client error indicating missing route
    if status_code == 404:
        return "DEGRADED", status_code, "HTTP 404: Endpoint not found"

    # 4. Rate limiting
    if status_code == 429:
        return "DEGRADED", status_code, "HTTP 429: Too Many Requests (Rate limited)"

    # 5. Server errors (5xx)
    if 500 <= status_code < 600:
        return "DEGRADED", status_code, f"HTTP {status_code}: Internal Server Error"

    # Other non-2xx codes
    return "DEGRADED", status_code, f"HTTP {status_code}: Unexpected response status"


def check_single_service(service: Dict[str, Any], conn: sqlite3.Connection) -> Dict[str, Any]:
    """Execute a single service check, run RCA, handle incident lifecycle, and persist results."""
    svc_dict = dict(service) if not isinstance(service, dict) else service
    service_id = svc_dict["id"]
    service_name = svc_dict["service_name"]
    service_url = svc_dict["service_url"]
    timeout = svc_dict.get("timeout") or 5

    logger.info("Checking service #%s (%s) at %s", service_id, service_name, service_url)

    # Perform check
    response, elapsed_ms, raw_err = perform_safe_request(service_url, timeout=timeout)
    status, http_code, error_msg = evaluate_status(response, elapsed_ms, raw_err)
    if error_msg is not None:
        error_msg = str(error_msg)

    rounded_latency = round(elapsed_ms, 2)

    # Perform deterministic Root Cause Analysis
    rca = rca_engine.analyze_failure(
        status=status,
        http_status_code=http_code,
        response_time_ms=rounded_latency,
        raw_error=error_msg or raw_err,
        timeout_limit=timeout,
    )

    cursor = conn.cursor()

    # Query current service failure tracking metrics
    svc_row = cursor.execute(
        "SELECT consecutive_failures, failure_threshold FROM services WHERE id = ?",
        (service_id,),
    ).fetchone()
    current_failures = svc_row["consecutive_failures"] if svc_row else 0
    threshold = svc_row["failure_threshold"] if svc_row else 2

    incident_id = None

    if status == "DOWN":
        new_failures = current_failures + 1

        # Check for already open incident
        active_inc = cursor.execute(
            "SELECT id FROM incidents WHERE service_id = ? AND status = 'OPEN'",
            (service_id,),
        ).fetchone()

        if active_inc:
            incident_id = active_inc["id"]
            # Update existing active incident with fresh diagnostics
            cursor.execute(
                """
                UPDATE incidents
                SET incident_type = ?,
                    failure_category = ?,
                    description = ?,
                    possible_cause = ?,
                    evidence = ?,
                    recommended_steps = ?,
                    confidence = ?
                WHERE id = ?
                """,
                (
                    rca["failure_category"] or "Outage",
                    rca["failure_category"] or "Outage",
                    f"Ongoing outage: {error_msg or 'Down'}",
                    rca["possible_cause"],
                    rca["evidence"],
                    rca["recommended_steps"],
                    rca["confidence"],
                    incident_id,
                ),
            )
        elif new_failures >= threshold:
            # Confirmed DOWN threshold reached: create incident
            cursor.execute(
                """
                INSERT INTO incidents (
                    service_id, incident_type, failure_category, description, possible_cause,
                    evidence, recommended_steps, confidence, started_at, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, 'OPEN')
                """,
                (
                    service_id,
                    rca["failure_category"] or "Outage",
                    rca["failure_category"] or "Outage",
                    f"Confirmed outage: {error_msg or 'Service is DOWN'}",
                    rca["possible_cause"],
                    rca["evidence"],
                    rca["recommended_steps"],
                    rca["confidence"],
                ),
            )
            incident_id = cursor.lastrowid
            logger.warning(
                "Incident #%s opened for service #%s (%s)",
                incident_id,
                service_id,
                service_name,
            )
    else:
        # Status is UP or DEGRADED
        if status == "UP":
            new_failures = 0
            # Check if active incident can now be resolved
            active_inc = cursor.execute(
                "SELECT id, started_at FROM incidents WHERE service_id = ? AND status = 'OPEN'",
                (service_id,),
            ).fetchone()

            if active_inc:
                inc_id = active_inc["id"]
                cursor.execute(
                    """
                    UPDATE incidents
                    SET status = 'RESOLVED',
                        resolved_at = CURRENT_TIMESTAMP,
                        duration_seconds = MAX(0, CAST(strftime('%s', 'now') AS INTEGER) - CAST(strftime('%s', started_at) AS INTEGER))
                    WHERE id = ?
                    """,
                    (inc_id,),
                )
                logger.info(
                    "Incident #%s resolved for service #%s (%s)",
                    inc_id,
                    service_id,
                    service_name,
                )
        else:
            # DEGRADED
            new_failures = 0

    # Persist in monitoring_results
    cursor.execute(
        """
        INSERT INTO monitoring_results (
            service_id, status, response_time, http_status_code, error_message,
            failure_category, possible_cause, evidence, recommended_steps, confidence, incident_id,
            checked_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        """,
        (
            service_id,
            status,
            rounded_latency,
            http_code,
            error_msg,
            rca.get("failure_category"),
            rca.get("possible_cause"),
            rca.get("evidence"),
            rca.get("recommended_steps"),
            rca.get("confidence"),
            incident_id,
        ),
    )

    # Calculate downtime risk assessment based on telemetry and history
    svc_eval_dict = dict(svc_dict)
    svc_eval_dict["current_status"] = status
    svc_eval_dict["consecutive_failures"] = new_failures
    risk_assessment = risk_engine.calculate_service_risk(svc_eval_dict, conn)

    # Update services summary table with status and risk
    cursor.execute(
        """
        UPDATE services
        SET current_status = ?,
            last_checked_at = CURRENT_TIMESTAMP,
            last_response_time = ?,
            last_status_code = ?,
            consecutive_failures = ?,
            risk_score = ?,
            risk_level = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (
            status,
            rounded_latency,
            http_code,
            new_failures,
            risk_assessment["risk_score"],
            risk_assessment["risk_level"],
            service_id,
        ),
    )
    conn.commit()

    logger.info(
        "Service #%s checked: status=%s, latency=%.1fms, code=%s, rca=%s, risk=%s(%s)",
        service_id,
        status,
        rounded_latency,
        http_code,
        rca.get("failure_category"),
        risk_assessment["risk_score"],
        risk_assessment["risk_level"],
    )

    return {
        "service_id": service_id,
        "status": status,
        "response_time": rounded_latency,
        "http_status_code": http_code,
        "error_message": error_msg,
        "rca": rca,
        "incident_id": incident_id,
        "risk": risk_assessment,
    }


def get_due_services(conn: sqlite3.Connection) -> list:
    """Fetch enabled services that are due for their next check based on check_interval."""
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    # strftime('%s', ...) calculates epoch seconds in SQLite
    query = """
    SELECT id, user_id, service_name, service_url, check_interval, timeout, current_status, is_active, last_checked_at
    FROM services
    WHERE is_active = 1
      AND (
          last_checked_at IS NULL
          OR (CAST(strftime('%s', 'now') AS INTEGER) - CAST(strftime('%s', last_checked_at) AS INTEGER)) >= check_interval
      )
    ORDER BY last_checked_at ASC NULLS FIRST
    """
    cursor.execute(query)
    return [dict(row) for row in cursor.fetchall()]
