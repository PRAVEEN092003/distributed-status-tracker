"""Automated test suite for Distributed Status Tracker - Phase 2.

Covers:
- Website management (Add, Edit, Delete, Toggle, Manual Check)
- Multi-tenant User Isolation
- SSRF prevention and URL validation
- Monitoring engine HTTP status evaluation (UP, DEGRADED, DOWN)
- Latency and HTTP status code tracking
- SQLite persistence in services and monitoring_results
- Disabled service exclusion and check interval timing
- Duplicate monitor worker prevention via process lock
- Dashboard live polling JSON endpoint
"""

import os
import re
import sqlite3
import tempfile
import unittest
from unittest.mock import patch, MagicMock

import requests
from requests.exceptions import Timeout, ConnectionError, SSLError

from app import create_app
import database
import monitor
import monitor_daemon
import validator


class Phase2TestCase(unittest.TestCase):
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
            "SECRET_KEY": "test-phase2-secret-key",
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
    # 1. URL Validation & SSRF Protections
    # -------------------------------------------------------------
    def test_ssrf_and_url_validation(self):
        """Test URL validation rejecting schemes, localhost, and private IPs."""
        # Unsupported schemes
        self.assertFalse(validator.validate_target_url("ftp://example.com")[0])
        self.assertFalse(validator.validate_target_url("file:///etc/passwd")[0])
        self.assertFalse(validator.validate_target_url("javascript:alert(1)")[0])

        # Localhost & Loopback
        self.assertFalse(validator.validate_target_url("http://localhost")[0])
        self.assertFalse(validator.validate_target_url("http://127.0.0.1")[0])
        self.assertFalse(validator.validate_target_url("http://127.0.0.1:8080/admin")[0])
        self.assertFalse(validator.validate_target_url("http://[::1]")[0])

        # Private IP spaces
        self.assertFalse(validator.validate_target_url("http://10.0.0.1")[0])
        self.assertFalse(validator.validate_target_url("http://192.168.1.1")[0])
        self.assertFalse(validator.validate_target_url("http://172.16.0.1")[0])
        self.assertFalse(validator.validate_target_url("http://169.254.169.254")[0])

        # Limits validation
        valid, cleaned, errors = validator.validate_service_inputs(
            service_name="Test Service",
            service_url="http://127.0.0.1",
            check_interval_raw=5,  # below min 10
            timeout_raw=50,        # above max 30
        )
        self.assertFalse(valid)
        self.assertTrue(any("private or local" in e or "disallowed" in e for e in errors))
        self.assertTrue(any("interval must be between" in e for e in errors))
        self.assertTrue(any("timeout must be between" in e for e in errors))

    # -------------------------------------------------------------
    # 2. Website Management CRUD
    # -------------------------------------------------------------
    @patch("validator.socket.getaddrinfo")
    @patch("monitor.perform_safe_request")
    def test_add_edit_delete_website(self, mock_check, mock_dns):
        """Test adding, editing, and deleting a website with CSRF."""
        # Mock DNS resolution for public IP
        mock_dns.return_value = [(2, 1, 6, "", ("93.184.216.34", 443))]
        mock_check.return_value = (MagicMock(status_code=200, is_redirect=False), 120.5, None)

        self.register_and_login()

        # Add Website
        res = self.client.get("/websites")
        csrf = self.extract_csrf_token(res.get_data(as_text=True))
        post_add = self.client.post("/websites/add", data={
            "csrf_token": csrf,
            "service_name": "Example Corp",
            "service_url": "https://example.com",
            "check_interval": "60",
            "timeout": "5",
        }, follow_redirects=True)
        self.assertEqual(post_add.status_code, 200)
        self.assertIn(b"Example Corp", post_add.data)

        # Verify in DB
        with self.app.app_context():
            db = database.get_db()
            svc = db.execute("SELECT * FROM services WHERE service_name = 'Example Corp'").fetchone()
            self.assertIsNotNone(svc)
            self.assertEqual(svc["service_url"], "https://example.com/")
            self.assertEqual(svc["current_status"], "UP")
            service_id = svc["id"]

        # View details
        detail_res = self.client.get(f"/websites/{service_id}")
        self.assertEqual(detail_res.status_code, 200)
        self.assertIn(b"Example Corp", detail_res.data)

        # Edit Website
        res_edit = self.client.get(f"/websites/{service_id}/edit")
        csrf_edit = self.extract_csrf_token(res_edit.get_data(as_text=True))
        post_edit = self.client.post(f"/websites/{service_id}/edit", data={
            "csrf_token": csrf_edit,
            "service_name": "Example Corp Updated",
            "service_url": "https://example.com",
            "check_interval": "120",
            "timeout": "10",
        }, follow_redirects=True)
        self.assertEqual(post_edit.status_code, 200)
        self.assertIn(b"Example Corp Updated", post_edit.data)

        # Toggle Active/Paused
        res_site = self.client.get("/websites")
        csrf_toggle = self.extract_csrf_token(res_site.get_data(as_text=True))
        self.client.post(f"/websites/{service_id}/toggle", data={"csrf_token": csrf_toggle}, follow_redirects=True)

        with self.app.app_context():
            db = database.get_db()
            svc_toggled = db.execute("SELECT is_active FROM services WHERE id = ?", (service_id,)).fetchone()
            self.assertEqual(svc_toggled["is_active"], 0)

        # Delete Website
        res_del = self.client.get("/websites")
        csrf_del = self.extract_csrf_token(res_del.get_data(as_text=True))
        del_res = self.client.post(f"/websites/{service_id}/delete", data={"csrf_token": csrf_del}, follow_redirects=True)
        self.assertEqual(del_res.status_code, 200)
        self.assertIn(b"was successfully deleted", del_res.data)

        # Confirm deleted in DB
        with self.app.app_context():
            db = database.get_db()
            deleted = db.execute("SELECT * FROM services WHERE id = ?", (service_id,)).fetchone()
            self.assertIsNone(deleted)

    # -------------------------------------------------------------
    # 3. Multi-Tenant User Isolation
    # -------------------------------------------------------------
    def test_user_isolation_guards(self):
        """Ensure User A cannot view, edit, toggle, or delete User B's websites."""
        # Create User A with a service
        with self.app.app_context():
            db = database.get_db()
            db.execute("INSERT INTO users (username, email, password_hash) VALUES ('user_a', 'a@test.com', 'hash')")
            user_a_id = db.execute("SELECT id FROM users WHERE username = 'user_a'").fetchone()["id"]
            db.execute(
                "INSERT INTO services (user_id, service_name, service_url) VALUES (?, 'Private Site A', 'https://a.com')",
                (user_a_id,),
            )
            site_a_id = db.execute("SELECT id FROM services WHERE user_id = ?", (user_a_id,)).fetchone()["id"]
            db.commit()

        # Login as User B
        self.register_and_login(username="user_b", email="b@test.com")

        # User B attempts to access User A's service
        res_detail = self.client.get(f"/websites/{site_a_id}")
        self.assertEqual(res_detail.status_code, 404)

        res_edit = self.client.get(f"/websites/{site_a_id}/edit")
        self.assertEqual(res_edit.status_code, 404)

        # User B attempts mutation on User A's service
        res_dash = self.client.get("/dashboard")
        csrf = self.extract_csrf_token(res_dash.get_data(as_text=True))
        res_del = self.client.post(f"/websites/{site_a_id}/delete", data={"csrf_token": csrf})
        self.assertEqual(res_del.status_code, 404)

        res_toggle = self.client.post(f"/websites/{site_a_id}/toggle", data={"csrf_token": csrf})
        self.assertEqual(res_toggle.status_code, 404)

        res_check = self.client.post(f"/websites/{site_a_id}/check", data={"csrf_token": csrf})
        self.assertEqual(res_check.status_code, 404)

    # -------------------------------------------------------------
    # 4. Monitoring Engine Status Categorization
    # -------------------------------------------------------------
    def test_status_categorization_and_latency(self):
        """Test status evaluation rules for UP, DEGRADED, and DOWN."""
        # 1. UP: 200 OK with normal latency (<= 2000ms)
        mock_200 = MagicMock(status_code=200)
        status, code, err = monitor.evaluate_status(mock_200, 150.0, None)
        self.assertEqual(status, "UP")
        self.assertEqual(code, 200)
        self.assertIsNone(err)

        # 2. DEGRADED: 200 OK with high latency (> 2000ms)
        status, code, err = monitor.evaluate_status(mock_200, 2500.0, None)
        self.assertEqual(status, "DEGRADED")
        self.assertIn("High latency", err)

        # 3. UP: 401 / 403 Authentication required (server is operational)
        mock_401 = MagicMock(status_code=401)
        status, code, err = monitor.evaluate_status(mock_401, 100.0, None)
        self.assertEqual(status, "UP")
        self.assertIn("Authentication required", err)

        # 4. DEGRADED: 404 Not Found
        mock_404 = MagicMock(status_code=404)
        status, code, err = monitor.evaluate_status(mock_404, 100.0, None)
        self.assertEqual(status, "DEGRADED")
        self.assertIn("404", err)

        # 5. DEGRADED: 429 Too Many Requests
        mock_429 = MagicMock(status_code=429)
        status, code, err = monitor.evaluate_status(mock_429, 100.0, None)
        self.assertEqual(status, "DEGRADED")
        self.assertIn("429", err)

        # 6. DEGRADED: 500 / 503 Server Error
        mock_500 = MagicMock(status_code=500)
        status, code, err = monitor.evaluate_status(mock_500, 100.0, None)
        self.assertEqual(status, "DEGRADED")
        self.assertIn("500", err)

        # 7. DOWN: Connection failure / timeout (response is None)
        status, code, err = monitor.evaluate_status(None, 5000.0, "Request timed out after 5s")
        self.assertEqual(status, "DOWN")
        self.assertIsNone(code)
        self.assertIn("timed out", err)

    # -------------------------------------------------------------
    # 5. SQLite Persistence and Interval Timing
    # -------------------------------------------------------------
    @patch("validator.socket.getaddrinfo")
    @patch("requests.get")
    def test_monitoring_persistence_and_interval(self, mock_get, mock_dns):
        """Test DB persistence in services & monitoring_results, and due services query."""
        mock_dns.return_value = [(2, 1, 6, "", ("93.184.216.34", 443))]
        mock_resp = MagicMock(status_code=200, is_redirect=False)
        mock_resp.raw.read.return_value = b"OK"
        mock_get.return_value = mock_resp

        with self.app.app_context():
            db = database.get_db()
            db.execute("INSERT INTO users (username, email, password_hash) VALUES ('pers_user', 'p@test.com', 'h')")
            u_id = db.execute("SELECT id FROM users WHERE username = 'pers_user'").fetchone()["id"]

            # Service 1: Active, due now (last_checked_at is NULL)
            db.execute(
                "INSERT INTO services (user_id, service_name, service_url, check_interval, is_active) VALUES (?, 'Site Due', 'https://example.com', 60, 1)",
                (u_id,),
            )
            # Service 2: Inactive / Disabled
            db.execute(
                "INSERT INTO services (user_id, service_name, service_url, check_interval, is_active) VALUES (?, 'Site Paused', 'https://example.com', 60, 0)",
                (u_id,),
            )
            db.commit()

            # Verify get_due_services only returns the active due service
            due = monitor.get_due_services(db)
            self.assertEqual(len(due), 1)
            self.assertEqual(due[0]["service_name"], "Site Due")

            # Perform check on due service
            res = monitor.check_single_service(due[0], db)
            self.assertEqual(res["status"], "UP")

            # Check that service table was updated
            updated_svc = db.execute("SELECT * FROM services WHERE id = ?", (due[0]["id"],)).fetchone()
            self.assertEqual(updated_svc["current_status"], "UP")
            self.assertIsNotNone(updated_svc["last_checked_at"])
            self.assertIsNotNone(updated_svc["last_response_time"])
            self.assertEqual(updated_svc["last_status_code"], 200)

            # Check that monitoring_results table received a record
            history_rows = db.execute("SELECT * FROM monitoring_results WHERE service_id = ?", (due[0]["id"],)).fetchall()
            self.assertEqual(len(history_rows), 1)
            self.assertEqual(history_rows[0]["status"], "UP")

            # Now, due services should be empty because check_interval (60s) hasn't passed
            due_after = monitor.get_due_services(db)
            self.assertEqual(len(due_after), 0)

    # -------------------------------------------------------------
    # 6. Duplicate Worker Prevention
    # -------------------------------------------------------------
    def test_duplicate_worker_prevention(self):
        """Test process lock prevents duplicate monitor daemon workers."""
        lock_path = monitor_daemon.LOCK_FILE

        # Acquire lock first time
        acquired = monitor_daemon.acquire_process_lock()
        self.assertTrue(acquired)
        self.assertTrue(os.path.exists(lock_path))

        # Second attempt should detect lock from current process and reject
        # We simulate another attempt
        with patch("monitor_daemon.is_pid_alive", return_value=True):
            second_attempt = monitor_daemon.acquire_process_lock()
            self.assertFalse(second_attempt)

        # Release lock
        monitor_daemon.release_process_lock()
        self.assertFalse(os.path.exists(lock_path))

    # -------------------------------------------------------------
    # 7. Dashboard Live Polling JSON API & History Page
    # -------------------------------------------------------------
    def test_dashboard_api_and_history_page(self):
        """Test /api/dashboard/stats and /history with pagination."""
        self.register_and_login()

        with self.app.app_context():
            db = database.get_db()
            user_id = db.execute("SELECT id FROM users WHERE username = 'tester'").fetchone()["id"]

            # Insert service & results
            cursor = db.cursor()
            cursor.execute(
                "INSERT INTO services (user_id, service_name, service_url, current_status) VALUES (?, 'Alpha', 'https://alpha.com', 'UP')",
                (user_id,),
            )
            svc_id = cursor.lastrowid
            cursor.execute(
                "INSERT INTO monitoring_results (service_id, status, response_time, http_status_code, checked_at) VALUES (?, 'UP', 85.0, 200, CURRENT_TIMESTAMP)",
                (svc_id,),
            )
            cursor.execute(
                "INSERT INTO monitoring_results (service_id, status, response_time, http_status_code, error_message, checked_at) VALUES (?, 'DEGRADED', 2500.0, 200, 'High latency', CURRENT_TIMESTAMP)",
                (svc_id,),
            )
            db.commit()

        # Test API
        res = self.client.get("/api/dashboard/stats")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["stats"]["total_services"], 1)
        self.assertEqual(data["stats"]["up_services"], 1)
        self.assertEqual(len(data["latest_results"]), 2)

        # Test /history page
        hist_res = self.client.get("/history")
        self.assertEqual(hist_res.status_code, 200)
        self.assertIn(b"Alpha", hist_res.data)
        self.assertIn(b"High latency", hist_res.data)


if __name__ == "__main__":
    unittest.main()
