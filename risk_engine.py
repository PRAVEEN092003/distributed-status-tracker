"""Downtime Risk Prediction and Assessment Engine.

Provides an explainable, rule-based scoring model (0-100)
evaluating service stability, latency degradation trends, consecutive failures,
and historical incident patterns.
"""

import sqlite3
from typing import Dict, Any, List, Optional, Tuple


# Risk Classification Levels
RISK_LOW = "LOW"        # 0 - 29
RISK_MEDIUM = "MEDIUM"  # 30 - 59
RISK_HIGH = "HIGH"      # 60 - 100


def classify_risk_level(score: int) -> str:
    """Classify numeric risk score into standardized categories."""
    if score >= 60:
        return RISK_HIGH
    if score >= 30:
        return RISK_MEDIUM
    return RISK_LOW


def calculate_service_risk(
    service: Dict[str, Any],
    conn: sqlite3.Connection,
    max_history_records: int = 50,
) -> Dict[str, Any]:
    """Calculate comprehensive downtime risk assessment for a monitored service.

    Args:
        service: Dict or sqlite3.Row containing service fields (id, current_status, consecutive_failures, etc.)
        conn: SQLite database connection.
        max_history_records: Number of recent monitoring results to analyze (default 50).

    Returns:
        Structured dictionary containing:
            - service_id: int
            - risk_score: int (0 to 100)
            - risk_level: str ('LOW', 'MEDIUM', 'HIGH')
            - latency_trend: str ('STABLE', 'INCREASING', 'SPIKING', 'INSUFFICIENT_DATA')
            - explanation: str
            - contributing_factors: List[str]
            - recommendations: List[str]
            - metrics: Dict[str, Any]
    """
    service_id = service["id"]
    current_status = service.get("current_status", "UNKNOWN")
    consecutive_failures = service.get("consecutive_failures", 0) or 0
    failure_threshold = service.get("failure_threshold", 2) or 2

    cursor = conn.cursor()

    # 1. Fetch recent monitoring records in chronological order
    cursor.execute(
        """
        SELECT status, response_time, http_status_code, error_message,
               failure_category, checked_at
        FROM monitoring_results
        WHERE service_id = ?
        ORDER BY id DESC
        LIMIT ?
        """,
        (service_id, max_history_records),
    )
    raw_results = [dict(r) for r in cursor.fetchall()]
    # Reverse so oldest to newest for trend analysis
    results = list(reversed(raw_results))
    total_samples = len(results)

    # 2. Query recent incident history in the last 24 hours
    cursor.execute(
        """
        SELECT id, status, failure_category, started_at, resolved_at, duration_seconds
        FROM incidents
        WHERE service_id = ?
          AND (
              status = 'OPEN'
              OR (resolved_at IS NOT NULL AND (CAST(strftime('%s', 'now') AS INTEGER) - CAST(strftime('%s', resolved_at) AS INTEGER)) <= 86400)
          )
        ORDER BY id DESC
        """,
        (service_id,),
    )
    recent_incidents = [dict(r) for r in cursor.fetchall()]
    active_incidents = [inc for inc in recent_incidents if inc["status"] == "OPEN"]

    contributing_factors: List[str] = []
    recommendations: List[str] = []

    # Handle brand-new / insufficient data scenarios
    if total_samples < 3:
        initial_score = 15 if current_status == "UP" else (85 if current_status == "DOWN" else 20)
        level = classify_risk_level(initial_score)
        return {
            "service_id": service_id,
            "risk_score": initial_score,
            "risk_level": level,
            "latency_trend": "INSUFFICIENT_DATA",
            "explanation": "Insufficient monitoring history collected. Initial risk assigned based on immediate service status.",
            "contributing_factors": ["Initial telemetry: Fewer than 3 monitoring checks recorded."],
            "recommendations": ["Allow monitoring daemon to gather regular telemetry over several check intervals."],
            "metrics": {
                "total_checks_analyzed": total_samples,
                "current_status": current_status,
                "consecutive_failures": consecutive_failures,
                "avg_latency_ms": None,
                "recent_latency_ms": None,
                "recent_incident_count": len(recent_incidents),
            },
        }

    # -------------------------------------------------------------
    # 3. Base Scoring & Signal Weight Calculation
    # -------------------------------------------------------------
    base_score = 0

    # Signal A: Current Operational Status
    if current_status == "DOWN":
        base_score += 45
        contributing_factors.append("Service is currently in DOWN status (unreachable or connection failed).")
    elif current_status == "DEGRADED":
        base_score += 25
        contributing_factors.append("Service is currently in DEGRADED status (elevated latency or partial client error).")

    # Signal B: Consecutive Failures
    if consecutive_failures > 0:
        failure_penalty = min(consecutive_failures * 15, 35)
        base_score += failure_penalty
        contributing_factors.append(
            f"{consecutive_failures} consecutive failed check(s) detected (Threshold: {failure_threshold})."
        )
        recommendations.append("Investigate persistent failure causes before failure threshold triggers outage.")

    # Signal C: Failure Frequency in Recent Samples
    failed_checks = sum(1 for r in results if r["status"] == "DOWN")
    degraded_checks = sum(1 for r in results if r["status"] == "DEGRADED")
    failure_ratio = (failed_checks + (degraded_checks * 0.5)) / total_samples

    if failure_ratio >= 0.5:
        base_score += 25
        contributing_factors.append(
            f"High failure frequency: {round(failure_ratio * 100)}% of recent {total_samples} checks exhibited failures or degradation."
        )
    elif failure_ratio >= 0.2:
        base_score += 15
        contributing_factors.append(
            f"Moderate failure rate: {round(failure_ratio * 100)}% of recent {total_samples} checks experienced issues."
        )

    # Signal D: Response-Time Degradation and Spikes
    valid_latencies = [r["response_time"] for r in results if r["response_time"] is not None and r["response_time"] > 0]
    latency_trend = "STABLE"
    avg_latency: Optional[float] = None
    recent_latency: Optional[float] = None
    max_latency: Optional[float] = None

    if len(valid_latencies) >= 4:
        # Split samples into baseline (first half) and recent (second half)
        midpoint = len(valid_latencies) // 2
        baseline_slice = valid_latencies[:midpoint]
        recent_slice = valid_latencies[midpoint:]

        baseline_avg = sum(baseline_slice) / len(baseline_slice)
        recent_avg = sum(recent_slice) / len(recent_slice)
        avg_latency = round(sum(valid_latencies) / len(valid_latencies), 1)
        recent_latency = round(recent_avg, 1)
        max_latency = round(max(valid_latencies), 1)

        # Detect latency inflation
        if baseline_avg > 0:
            percentage_increase = ((recent_avg - baseline_avg) / baseline_avg) * 100
            if percentage_increase >= 100 and recent_avg >= 500:
                # 2x latency surge
                latency_trend = "SPIKING"
                base_score += 20
                contributing_factors.append(
                    f"Severe latency surge: Recent average latency ({recent_latency}ms) is {round(percentage_increase)}% higher than baseline ({round(baseline_avg, 1)}ms)."
                )
                recommendations.append("Profile backend database queries and check server CPU/memory load.")
            elif percentage_increase >= 40 and recent_avg >= 400:
                # Noticeable degradation
                latency_trend = "INCREASING"
                base_score += 12
                contributing_factors.append(
                    f"Upward latency trend: Response times grew by {round(percentage_increase)}% over recent checks."
                )
                recommendations.append("Inspect slow backend logs and verify reverse proxy caching efficiency.")
            elif percentage_increase <= -25:
                latency_trend = "IMPROVING"

        # Check for absolute latency threshold exceedance
        if recent_avg > 2000:
            base_score += 10
            contributing_factors.append(f"Recent average response time ({recent_latency}ms) exceeds 2000ms degraded threshold.")
    elif valid_latencies:
        avg_latency = round(sum(valid_latencies) / len(valid_latencies), 1)
        max_latency = round(max(valid_latencies), 1)
        recent_latency = round(valid_latencies[-1], 1)

    # Signal E: Active & Historical Outage Incidents (Last 24 Hours)
    if active_incidents:
        base_score += 30
        contributing_factors.append(
            f"Active unresolved incident #{active_incidents[0]['id']} currently in progress."
        )
        recommendations.append("Follow Root Cause Analysis steps on active incident to achieve service recovery.")
    elif recent_incidents:
        # Service recovered but experienced recent instability within the past 24 hours
        rec_inc_count = len(recent_incidents)
        incident_penalty = min(rec_inc_count * 8, 20)
        base_score += incident_penalty
        contributing_factors.append(
            f"{rec_inc_count} resolved outage incident(s) occurred within the past 24 hours."
        )
        recommendations.append("Review post-incident fixes to prevent recurrence of recent failure modes.")

    # Signal F: Sustained Stability Discount
    # If the last 10+ checks are consecutively UP with low latency, reward stability
    consecutive_healthy = 0
    for r in reversed(results):
        if r["status"] == "UP" and (r["response_time"] is None or r["response_time"] < 1500):
            consecutive_healthy += 1
        else:
            break

    if consecutive_healthy >= 15 and current_status == "UP":
        discount = 20
        base_score = max(0, base_score - discount)
        contributing_factors.append(
            f"Sustained stability bonus: Last {consecutive_healthy} checks completed successfully with healthy response times."
        )
    elif consecutive_healthy >= 8 and current_status == "UP":
        discount = 10
        base_score = max(0, base_score - discount)

    # -------------------------------------------------------------
    # 4. Final Score Normalization & Explanation Formulation
    # -------------------------------------------------------------
    final_score = max(0, min(100, int(round(base_score))))
    risk_level = classify_risk_level(final_score)

    if not contributing_factors:
        contributing_factors.append("No significant negative signals detected. Telemetry indicates steady, healthy operations.")

    if not recommendations:
        if risk_level == RISK_LOW:
            recommendations.append("Maintain routine monitoring checks. Service is operating within expected stability parameters.")
        elif risk_level == RISK_MEDIUM:
            recommendations.append("Keep monitoring endpoint and inspect application metrics if response latency increases further.")
        else:
            recommendations.append("Investigate upstream network and server infrastructure immediately to avert prolonged downtime.")

    # Formulate natural, explainable summary
    if risk_level == RISK_HIGH:
        explanation = (
            f"High downtime risk ({final_score}/100) estimated. "
            f"{contributing_factors[0]} "
            "Immediate operational intervention recommended."
        )
    elif risk_level == RISK_MEDIUM:
        explanation = (
            f"Moderate downtime risk ({final_score}/100) estimated. "
            f"{contributing_factors[0]} "
            "Service shows early signs of degradation or recent instability."
        )
    else:
        explanation = (
            f"Low downtime risk ({final_score}/100) estimated. "
            "Service demonstrates healthy availability and consistent response performance."
        )

    return {
        "service_id": service_id,
        "risk_score": final_score,
        "risk_level": risk_level,
        "latency_trend": latency_trend,
        "explanation": explanation,
        "contributing_factors": contributing_factors,
        "recommendations": recommendations,
        "metrics": {
            "total_checks_analyzed": total_samples,
            "current_status": current_status,
            "consecutive_failures": consecutive_failures,
            "failure_rate_percent": round(failure_ratio * 100, 1),
            "avg_latency_ms": avg_latency,
            "recent_latency_ms": recent_latency,
            "max_latency_ms": max_latency,
            "recent_incident_count": len(recent_incidents),
            "active_incident_count": len(active_incidents),
        },
    }
