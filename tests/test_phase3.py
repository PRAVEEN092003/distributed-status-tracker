"""Automated test suite for Distributed Status Tracker - Phase 3.

Covers:
- Failure Classification (all 10 categories)
- Deterministic Root Cause Analysis (evidence, possible cause, steps, confidence)
- Incident Detection based on consecutive-failure threshold
- Continuous outage handling (no duplicate active incidents)
- Recovery Tracking (DOWN to UP, resolution timestamp, downtime duration calculation)
- User Isolation on incidents overview and details
- Dashboard & Website Detail integration
"""

import os
import re
import socket
import ssl
import tempfile
import time
import unittest
from unittest.mock import patch, MagicMock

import requests
from requests.exceptions import (
    ConnectTimeout,
    ReadTimeout,
    SSLError,
    ConnectionError as ReqConnectionError,
    TooManyRedirects,
)
import urllib3.exceptions

from app import create_app
import database
import monitor
import monitor_daemon
import rca_engine


class Phase3TestCase(unittest.TestCase):
    def setUp(self):
        if os.path.exists(monitor_daemon.LOCK_FILE):
            try:
                os.remove(monitor_daemon.LOCK_FILE)
            except Exception:
                pass

        self.db_fd, self.db_path = tempfile.mkstemp(suffix=".db")
        self.app = create_app({
            "TESTING": True,
            "DATABASE": self.db_path,
            "SECRET_KEY": "test-phase3-secret-key",
            "WTF_CSRF_ENABLED": True,
            "TESTING_SKIP_CSRF": False,
        })
        self.client = self.app.test_client()

    def tearDown(self):
        os.close(self.db_fd)
        if os.path.exists(self.db_path):
            os.unlink(self.db_path)
        if os.path.exists(monitor_daemon.LOCK_FILE):
            try:
                os.remove(monitor_daemon.LOCK_FILE)
            except Exception:
                pass

    def extract_csrf_token(self, html_text):
        """Helper to extract csrf_token from HTML form or meta tag."""
        match = re.search(r'name="csrf_token"\s+value="([^"]+)"', html_text)
        if not match:
            match = re.search(r'content="([^"]+)"\s+name="csrf-token"', html_text)
        if not match:
            match = re.search(r'name="csrf-token"\s+content="([^"]+)"', html_text)
        return match.group(1) if match else None

    def register_and_login(self, username="tester", email="tester@example.com", password="Password123!"):
        """Register a user and log them in."""
        res = self.client.get("/register")
        csrf = self.extract_csrf_token(res.get_data(as_text=True))
        self.client.post("/register", data={
            "csrf_token": csrf,
            "username": username,
            "email": email,
            "password": password,
            "confirm_password": password,
        })

        res2 = self.client.get("/login")
        csrf2 = self.extract_csrf_token(res2.get_data(as_text=True))
        self.client.post("/login", data={
            "csrf_token": csrf2,
            "email": email,
            "password": password,
        })

    # -------------------------------------------------------------
    # 1. RCA Engine: Failure Classification (All 10 Categories)
    # -------------------------------------------------------------
    def test_rca_all_failure_categories(self):
        """Verify deterministic RCA engine classifies all 10 failure categories accurately."""
        # 1. DNS resolution failure
        rca = rca_engine.analyze_failure(
            status="DOWN",
            http_status_code=None,
            response_time_ms=120.0,
            raw_error="DNS resolution failed: [Errno 11001] getaddrinfo failed",
        )
        self.assertEqual(rca["failure_category"], rca_engine.CAT_DNS_FAILURE)
        self.assertEqual(rca["confidence"], "High")
        self.assertIn("DNS query failed", rca["evidence"])
        self.assertIn("nslookup", rca["recommended_steps"])

        # 2. Connection timeout
        rca = rca_engine.analyze_failure(
            status="DOWN",
            http_status_code=None,
            response_time_ms=5000.0,
            raw_error="HTTPSConnectionPool: connect timed out after 5.0 seconds",
            timeout_limit=5,
        )
        self.assertEqual(rca["failure_category"], rca_engine.CAT_TIMEOUT)
        self.assertEqual(rca["confidence"], "High")
        self.assertIn("Connection timed out", rca["evidence"])

        # 3. Connection refused
        rca = rca_engine.analyze_failure(
            status="DOWN",
            http_status_code=None,
            response_time_ms=50.0,
            raw_error="HTTPConnectionPool: Max retries exceeded (Caused by NewConnectionError: Connection refused [Errno 111])",
        )
        self.assertEqual(rca["failure_category"], rca_engine.CAT_CONN_REFUSED)
        self.assertEqual(rca["confidence"], "High")
        self.assertIn("not listening", rca["possible_cause"])

        # 4. SSL/TLS certificate or handshake error
        rca = rca_engine.analyze_failure(
            status="DOWN",
            http_status_code=None,
            response_time_ms=200.0,
            raw_error="CERTIFICATE_VERIFY_FAILED: certificate has expired (ssl error)",
        )
        self.assertEqual(rca["failure_category"], rca_engine.CAT_SSL_ERROR)
        self.assertEqual(rca["confidence"], "High")
        self.assertIn("SSL certificate expired", rca["possible_cause"])

        # 5. Network connection failure
        rca = rca_engine.analyze_failure(
            status="DOWN",
            http_status_code=None,
            response_time_ms=30.0,
            raw_error="Failed to establish a new connection: network is unreachable",
        )
        self.assertEqual(rca["failure_category"], rca_engine.CAT_NETWORK_FAILURE)
        self.assertEqual(rca["confidence"], "Medium")

        # 6. HTTP client error (404, 429, 401/403)
        rca_404 = rca_engine.analyze_failure(
            status="DEGRADED",
            http_status_code=404,
            response_time_ms=120.0,
            raw_error="HTTP 404: Not Found",
        )
        self.assertEqual(rca_404["failure_category"], rca_engine.CAT_HTTP_CLIENT_ERROR)
        self.assertIn("404", rca_404["evidence"])
        self.assertEqual(rca_404["confidence"], "High")

        rca_429 = rca_engine.analyze_failure(
            status="DEGRADED",
            http_status_code=429,
            response_time_ms=80.0,
            raw_error="HTTP 429: Too Many Requests",
        )
        self.assertEqual(rca_429["failure_category"], rca_engine.CAT_HTTP_CLIENT_ERROR)
        self.assertIn("rate limiting", rca_429["possible_cause"])

        # 7. HTTP server error (500, 502, 503, 504)
        rca_502 = rca_engine.analyze_failure(
            status="DEGRADED",
            http_status_code=502,
            response_time_ms=350.0,
            raw_error="HTTP 502: Bad Gateway",
        )
        self.assertEqual(rca_502["failure_category"], rca_engine.CAT_HTTP_SERVER_ERROR)
        self.assertIn("502", rca_502["evidence"])
        self.assertEqual(rca_502["confidence"], "High")

        rca_503 = rca_engine.analyze_failure(
            status="DEGRADED",
            http_status_code=503,
            response_time_ms=300.0,
            raw_error="HTTP 503: Service Unavailable",
        )
        self.assertEqual(rca_503["failure_category"], rca_engine.CAT_HTTP_SERVER_ERROR)

        # 8. Slow response (>2000ms latency, status 200)
        rca_slow = rca_engine.analyze_failure(
            status="DEGRADED",
            http_status_code=200,
            response_time_ms=3400.0,
            raw_error="High latency: 3400ms",
        )
        self.assertEqual(rca_slow["failure_category"], rca_engine.CAT_SLOW_RESPONSE)
        self.assertIn("3400.0ms", rca_slow["evidence"])
        self.assertEqual(rca_slow["confidence"], "Medium")

        # 9. Unexpected redirect or configuration issue
        rca_redir = rca_engine.analyze_failure(
            status="DOWN",
            http_status_code=None,
            response_time_ms=500.0,
            raw_error="Exceeded 30 redirects: redirect loop encountered",
        )
        self.assertEqual(rca_redir["failure_category"], rca_engine.CAT_REDIRECT_CONFIG)
        self.assertEqual(rca_redir["confidence"], "High")

        # 10. Unknown failure
        rca_unk = rca_engine.analyze_failure(
            status="DOWN",
            http_status_code=None,
            response_time_ms=100.0,
            raw_error="An unspecified unknown condition occurred",
        )
        self.assertEqual(rca_unk["failure_category"], rca_engine.CAT_UNKNOWN)
        self.assertEqual(rca_unk["confidence"], "Low")

    # -------------------------------------------------------------
    # 2. Incident Detection: Consecutive Failure Threshold
    # -------------------------------------------------------------
    @patch("validator.socket.getaddrinfo")
    @patch("monitor.perform_safe_request")
    def test_incident_trigger_on_threshold(self, mock_check, mock_dns):
        """Test incident is only opened when consecutive_failures >= threshold (default 2)."""
        mock_dns.return_value = [(2, 1, 6, "", ("93.184.216.34", 443))]
        # Simulate connection timeout (DOWN)
        timeout_err = ConnectTimeout("Connection timed out after 5.0 seconds")
        mock_check.return_value = (None, 5000.0, timeout_err)

        with self.app.app_context():
            db = database.get_db()
            db.execute("INSERT INTO users (username, email, password_hash) VALUES ('inc_user', 'u@test.com', 'h')")
            u_id = db.execute("SELECT id FROM users WHERE username = 'inc_user'").fetchone()["id"]

            # Add service with failure_threshold = 2
            db.execute(
                """INSERT INTO services (user_id, service_name, service_url, check_interval, timeout, failure_threshold, consecutive_failures, current_status)
                   VALUES (?, 'Flaky Service', 'https://example.com', 60, 5, 2, 0, 'UP')""",
                (u_id,),
            )
            svc = db.execute("SELECT * FROM services WHERE service_name = 'Flaky Service'").fetchone()

            # First failure (consecutive_failures becomes 1 < threshold 2)
            res1 = monitor.check_single_service(svc, db)
            self.assertEqual(res1["status"], "DOWN")

            svc_after_1 = db.execute("SELECT * FROM services WHERE id = ?", (svc["id"],)).fetchone()
            self.assertEqual(svc_after_1["consecutive_failures"], 1)

            # Assert NO incident created yet
            incidents_1 = db.execute("SELECT * FROM incidents WHERE service_id = ?", (svc["id"],)).fetchall()
            self.assertEqual(len(incidents_1), 0)

            # Second failure (consecutive_failures becomes 2 >= threshold 2) -> Incident created!
            res2 = monitor.check_single_service(svc_after_1, db)
            self.assertEqual(res2["status"], "DOWN")

            svc_after_2 = db.execute("SELECT * FROM services WHERE id = ?", (svc["id"],)).fetchone()
            self.assertEqual(svc_after_2["consecutive_failures"], 2)

            incidents_2 = db.execute("SELECT * FROM incidents WHERE service_id = ?", (svc["id"],)).fetchall()
            self.assertEqual(len(incidents_2), 1)
            inc = incidents_2[0]
            self.assertEqual(inc["status"], "OPEN")
            self.assertEqual(inc["failure_category"], rca_engine.CAT_CONNECTION_TIMEOUT)
            self.assertIn("Connection timed out", inc["evidence"])
            self.assertIsNotNone(inc["started_at"])
            self.assertIsNone(inc["resolved_at"])

            # Monitoring result was linked to incident
            latest_result = db.execute(
                "SELECT * FROM monitoring_results WHERE service_id = ? ORDER BY id DESC LIMIT 1",
                (svc["id"],)
            ).fetchone()
            self.assertEqual(latest_result["incident_id"], inc["id"])

    # -------------------------------------------------------------
    # 3. Continuous Outage: No Duplicate Active Incidents
    # -------------------------------------------------------------
    @patch("validator.socket.getaddrinfo")
    @patch("monitor.perform_safe_request")
    def test_no_duplicate_incidents_during_continuous_outage(self, mock_check, mock_dns):
        """Verify repeated health check failures update the active incident rather than creating duplicates."""
        mock_dns.return_value = [(2, 1, 6, "", ("93.184.216.34", 443))]
        timeout_err = ConnectTimeout("Connection timed out after 5.0 seconds")
        mock_check.return_value = (None, 5000.0, timeout_err)

        with self.app.app_context():
            db = database.get_db()
            db.execute("INSERT INTO users (username, email, password_hash) VALUES ('cont_user', 'cont@test.com', 'h')")
            u_id = db.execute("SELECT id FROM users WHERE username = 'cont_user'").fetchone()["id"]

            db.execute(
                """INSERT INTO services (user_id, service_name, service_url, check_interval, failure_threshold, consecutive_failures, current_status)
                   VALUES (?, 'Continuous Fail Service', 'https://example.com', 60, 1, 0, 'UP')""",
                (u_id,),
            )
            svc = db.execute("SELECT * FROM services WHERE service_name = 'Continuous Fail Service'").fetchone()

            # First check -> opens incident (since threshold is 1)
            monitor.check_single_service(svc, db)
            incidents_count = db.execute("SELECT COUNT(*) AS c FROM incidents WHERE service_id = ?", (svc["id"],)).fetchone()["c"]
            self.assertEqual(incidents_count, 1)

            # Subsequent checks: simulate multiple failures
            for _ in range(4):
                updated_svc = db.execute("SELECT * FROM services WHERE id = ?", (svc["id"],)).fetchone()
                monitor.check_single_service(updated_svc, db)

            # Assert STILL only 1 incident exists
            all_incidents = db.execute("SELECT * FROM incidents WHERE service_id = ?", (svc["id"],)).fetchall()
            self.assertEqual(len(all_incidents), 1)
            self.assertEqual(all_incidents[0]["status"], "OPEN")

            svc_final = db.execute("SELECT * FROM services WHERE id = ?", (svc["id"],)).fetchone()
            self.assertEqual(svc_final["consecutive_failures"], 5)

    # -------------------------------------------------------------
    # 4. Recovery Tracking: Resolution & Downtime Duration
    # -------------------------------------------------------------
    @patch("validator.socket.getaddrinfo")
    @patch("monitor.perform_safe_request")
    def test_recovery_tracking_and_downtime_calculation(self, mock_check, mock_dns):
        """Verify transition from DOWN to UP resolves open incident and calculates downtime duration."""
        mock_dns.return_value = [(2, 1, 6, "", ("93.184.216.34", 443))]

        with self.app.app_context():
            db = database.get_db()
            db.execute("INSERT INTO users (username, email, password_hash) VALUES ('rec_user', 'rec@test.com', 'h')")
            u_id = db.execute("SELECT id FROM users WHERE username = 'rec_user'").fetchone()["id"]

            db.execute(
                """INSERT INTO services (user_id, service_name, service_url, failure_threshold, consecutive_failures, current_status)
                   VALUES (?, 'Recovering Service', 'https://example.com', 1, 0, 'UP')""",
                (u_id,),
            )
            svc = db.execute("SELECT * FROM services WHERE service_name = 'Recovering Service'").fetchone()

            # Fail 1: opens incident
            mock_check.return_value = (None, 5000.0, ConnectTimeout("Timeout 5s"))
            monitor.check_single_service(svc, db)

            inc = db.execute("SELECT * FROM incidents WHERE service_id = ? AND status = 'OPEN'", (svc["id"],)).fetchone()
            self.assertIsNotNone(inc)
            inc_id = inc["id"]

            # Manually backdate started_at by 120 seconds in SQLite to test accurate duration calculation
            db.execute(
                "UPDATE incidents SET started_at = datetime('now', '-120 seconds') WHERE id = ?",
                (inc_id,)
            )
            db.commit()

            # Recover: returns HTTP 200 OK
            mock_resp = MagicMock(status_code=200, is_redirect=False)
            mock_check.return_value = (mock_resp, 115.0, None)

            svc_down = db.execute("SELECT * FROM services WHERE id = ?", (svc["id"],)).fetchone()
            res_rec = monitor.check_single_service(svc_down, db)
            self.assertEqual(res_rec["status"], "UP")

            # Verify consecutive_failures reset
            svc_recovered = db.execute("SELECT * FROM services WHERE id = ?", (svc["id"],)).fetchone()
            self.assertEqual(svc_recovered["consecutive_failures"], 0)
            self.assertEqual(svc_recovered["current_status"], "UP")

            # Verify incident resolved
            resolved_inc = db.execute("SELECT * FROM incidents WHERE id = ?", (inc_id,)).fetchone()
            self.assertEqual(resolved_inc["status"], "RESOLVED")
            self.assertIsNotNone(resolved_inc["resolved_at"])
            self.assertIsNotNone(resolved_inc["duration_seconds"])
            # Duration should be approximately 120 seconds (+/- a few seconds)
            self.assertGreaterEqual(resolved_inc["duration_seconds"], 115)
            self.assertLessEqual(resolved_inc["duration_seconds"], 130)

            # Original failure details preserved
            self.assertEqual(resolved_inc["failure_category"], rca_engine.CAT_CONNECTION_TIMEOUT)
            self.assertIn("Timeout 5s", resolved_inc["evidence"])

            # Subsequent UP check should not create new incidents or modify resolved one
            monitor.check_single_service(svc_recovered, db)
            incidents_after = db.execute("SELECT * FROM incidents WHERE service_id = ?", (svc["id"],)).fetchall()
            self.assertEqual(len(incidents_after), 1)
            self.assertEqual(incidents_after[0]["status"], "RESOLVED")

    # -------------------------------------------------------------
    # 5. User Isolation on Incidents & Routes
    # -------------------------------------------------------------
    def test_incident_user_isolation(self):
        """Ensure User B cannot view User A's incidents on overview or detail page."""
        with self.app.app_context():
            db = database.get_db()
            db.execute("INSERT INTO users (username, email, password_hash) VALUES ('user_a', 'a@test.com', 'h')")
            db.execute("INSERT INTO users (username, email, password_hash) VALUES ('user_b', 'b@test.com', 'h')")
            u_a = db.execute("SELECT id FROM users WHERE username = 'user_a'").fetchone()["id"]
            u_b = db.execute("SELECT id FROM users WHERE username = 'user_b'").fetchone()["id"]

            # Service for User A
            db.execute(
                "INSERT INTO services (user_id, service_name, service_url, current_status) VALUES (?, 'Site A', 'https://a.com', 'DOWN')",
                (u_a,)
            )
            svc_a_id = db.execute("SELECT id FROM services WHERE user_id = ?", (u_a,)).fetchone()["id"]

            # Incident for User A
            db.execute(
                """INSERT INTO incidents (service_id, incident_type, failure_category, description, possible_cause, evidence, recommended_steps, confidence, status)
                   VALUES (?, ?, ?, 'Service DOWN', 'Server crashed', 'HTTP 500 error', 'Check nginx logs', 'High', 'OPEN')""",
                (svc_a_id, rca_engine.CAT_HTTP_SERVER_ERROR, rca_engine.CAT_HTTP_SERVER_ERROR)
            )
            inc_a_id = db.execute("SELECT id FROM incidents WHERE service_id = ?", (svc_a_id,)).fetchone()["id"]
            db.commit()

        # Login as User B
        self.register_and_login(username="user_b_actor", email="b_actor@example.com")

        # User B views /incidents -> should not show User A's incident
        res_list = self.client.get("/incidents")
        self.assertEqual(res_list.status_code, 200)
        self.assertNotIn(b"Site A", res_list.data)
        self.assertNotIn(b"Server crashed", res_list.data)

        # User B attempts to access User A's incident detail
        res_detail = self.client.get(f"/incidents/{inc_a_id}")
        self.assertEqual(res_detail.status_code, 404)

    # -------------------------------------------------------------
    # 6. Incident Details & Dashboard UI Integration
    # -------------------------------------------------------------
    def test_incident_detail_and_dashboard_integration(self):
        """Verify incident detail page displays RCA diagnosis, evidence, and recommendations."""
        self.register_and_login()

        with self.app.app_context():
            db = database.get_db()
            user_id = db.execute("SELECT id FROM users WHERE username = 'tester'").fetchone()["id"]

            # Service with active incident
            db.execute(
                "INSERT INTO services (user_id, service_name, service_url, current_status) VALUES (?, 'Production API', 'https://api.prod.com', 'DOWN')",
                (user_id,)
            )
            svc_id = db.execute("SELECT id FROM services WHERE service_name = 'Production API'").fetchone()["id"]

            db.execute(
                """INSERT INTO incidents (service_id, incident_type, failure_category, description, possible_cause, evidence, recommended_steps, confidence, status)
                   VALUES (?, ?, ?, 'Confirmed outage', 'DNS records expired', 'socket.gaierror 11001', '1. Verify domain registration\n2. Run nslookup', 'High', 'OPEN')""",
                (svc_id, rca_engine.CAT_DNS_FAILURE, rca_engine.CAT_DNS_FAILURE)
            )
            inc_id = db.execute("SELECT id FROM incidents WHERE service_id = ?", (svc_id,)).fetchone()["id"]
            db.commit()

        # 1. Dashboard shows active incident banner
        dash_res = self.client.get("/dashboard")
        self.assertEqual(dash_res.status_code, 200)
        self.assertIn(b"Production API", dash_res.data)
        self.assertIn(b"DNS resolution failure", dash_res.data)

        # 2. API /api/dashboard/stats shows active incidents
        api_res = self.client.get("/api/dashboard/stats")
        self.assertEqual(api_res.status_code, 200)
        api_data = api_res.get_json()
        self.assertEqual(api_data["stats"]["active_incidents"], 1)
        self.assertEqual(len(api_data["active_incidents"]), 1)
        self.assertEqual(api_data["active_incidents"][0]["service_name"], "Production API")

        # 3. Incident detail page renders all diagnostic components
        detail_res = self.client.get(f"/incidents/{inc_id}")
        self.assertEqual(detail_res.status_code, 200)
        self.assertIn(b"DNS resolution failure", detail_res.data)
        self.assertIn(b"DNS records expired", detail_res.data)
        self.assertIn(b"socket.gaierror 11001", detail_res.data)
        self.assertIn(b"Verify domain registration", detail_res.data)
        self.assertIn(b"High Confidence", detail_res.data)
        self.assertIn(b"OPEN", detail_res.data)

        # 4. Website details page shows active incident alert
        site_detail_res = self.client.get(f"/websites/{svc_id}")
        self.assertEqual(site_detail_res.status_code, 200)
        self.assertIn(b"Active Outage:", site_detail_res.data)
        self.assertIn(b"DNS resolution failure", site_detail_res.data)


if __name__ == "__main__":
    unittest.main()
