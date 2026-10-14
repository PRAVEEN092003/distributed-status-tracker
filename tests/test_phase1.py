"""Automated test suite for Distributed Status Tracker - Phase 1.

Tests database schema, foreign key enforcement, password hashing, registration,
duplicate handling, login/logout, CSRF protection, route guards, and dashboard statistics.
"""

import os
import re
import sqlite3
import tempfile
import unittest

from werkzeug.security import check_password_hash

from app import create_app
import database


class Phase1TestCase(unittest.TestCase):
    def setUp(self):
        # Create a temporary file to act as the test database
        self.db_fd, self.db_path = tempfile.mkstemp(suffix=".db")
        self.app = create_app({
            "TESTING": True,
            "DATABASE": self.db_path,
            "SECRET_KEY": "test-secret-key-12345",
            "WTF_CSRF_ENABLED": True,
            "TESTING_SKIP_CSRF": False,
        })
        self.client = self.app.test_client()

    def tearDown(self):
        os.close(self.db_fd)
        if os.path.exists(self.db_path):
            os.unlink(self.db_path)

    def extract_csrf_token(self, html_text):
        """Helper to extract csrf_token from HTML form or meta tag."""
        match = re.search(r'name="csrf_token"\s+value="([^"]+)"', html_text)
        if not match:
            match = re.search(r'content="([^"]+)"\s+name="csrf-token"', html_text)
        if not match:
            match = re.search(r'name="csrf-token"\s+content="([^"]+)"', html_text)
        return match.group(1) if match else None

    # -------------------------------------------------------------
    # 1. Database & Schema Tests
    # -------------------------------------------------------------
    def test_database_tables_exist(self):
        """Test that all required Phase 1 tables exist in SQLite."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [row[0] for row in cursor.fetchall()]
        conn.close()

        expected_tables = ["users", "services", "monitoring_results", "incidents"]
        for table in expected_tables:
            self.assertIn(table, tables, f"Table '{table}' was not created.")

    def test_foreign_key_enforcement(self):
        """Test that SQLite foreign key enforcement is active and rejects orphans."""
        with self.app.app_context():
            db = database.get_db()
            with self.assertRaises(sqlite3.IntegrityError):
                # Try inserting a service with non-existent user_id=999
                db.execute(
                    "INSERT INTO services (user_id, service_name, service_url) VALUES (?, ?, ?)",
                    (999, "Test Service", "https://example.com"),
                )
                db.commit()

    # -------------------------------------------------------------
    # 2. Registration Tests
    # -------------------------------------------------------------
    def test_registration_success_and_password_hashing(self):
        """Test valid user registration and verify password is safe and hashed."""
        # Get registration page to obtain CSRF token and session
        res = self.client.get("/register")
        self.assertEqual(res.status_code, 200)
        csrf_token = self.extract_csrf_token(res.get_data(as_text=True))
        self.assertIsNotNone(csrf_token, "CSRF token missing from registration page.")

        post_res = self.client.post("/register", data={
            "csrf_token": csrf_token,
            "username": "tester_one",
            "email": "tester1@example.com",
            "password": "SecurePassword123!",
            "confirm_password": "SecurePassword123!",
        }, follow_redirects=True)

        self.assertEqual(post_res.status_code, 200)
        self.assertIn(b"Registration successful", post_res.data)

        # Inspect database
        with self.app.app_context():
            db = database.get_db()
            user = db.execute("SELECT * FROM users WHERE username = ?", ("tester_one",)).fetchone()
            self.assertIsNotNone(user)
            self.assertEqual(user["email"], "tester1@example.com")
            # Verify password is not plaintext
            self.assertNotEqual(user["password_hash"], "SecurePassword123!")
            # Verify password hash is valid
            self.assertTrue(check_password_hash(user["password_hash"], "SecurePassword123!"))

    def test_registration_rejects_duplicate_username(self):
        """Test that registration rejects duplicate usernames."""
        res = self.client.get("/register")
        csrf_token = self.extract_csrf_token(res.get_data(as_text=True))

        # First registration
        self.client.post("/register", data={
            "csrf_token": csrf_token,
            "username": "same_user",
            "email": "user1@example.com",
            "password": "Password123!",
            "confirm_password": "Password123!",
        })

        # Second registration with same username but different email
        res2 = self.client.get("/register")
        csrf2 = self.extract_csrf_token(res2.get_data(as_text=True))
        dup_res = self.client.post("/register", data={
            "csrf_token": csrf2,
            "username": "same_user",
            "email": "user2@example.com",
            "password": "Password123!",
            "confirm_password": "Password123!",
        })

        self.assertEqual(dup_res.status_code, 400)
        self.assertIn(b"username is already taken", dup_res.data)

    def test_registration_rejects_duplicate_email(self):
        """Test that registration rejects duplicate email addresses."""
        res = self.client.get("/register")
        csrf_token = self.extract_csrf_token(res.get_data(as_text=True))

        self.client.post("/register", data={
            "csrf_token": csrf_token,
            "username": "user_a",
            "email": "duplicate@example.com",
            "password": "Password123!",
            "confirm_password": "Password123!",
        })

        res2 = self.client.get("/register")
        csrf2 = self.extract_csrf_token(res2.get_data(as_text=True))
        dup_res = self.client.post("/register", data={
            "csrf_token": csrf2,
            "username": "user_b",
            "email": "duplicate@example.com",
            "password": "Password123!",
            "confirm_password": "Password123!",
        })

        self.assertEqual(dup_res.status_code, 400)
        self.assertIn(b"already exists", dup_res.data)

    def test_registration_input_validation(self):
        """Test server-side validation for short password and mismatched passwords."""
        res = self.client.get("/register")
        csrf_token = self.extract_csrf_token(res.get_data(as_text=True))

        # Mismatched passwords
        res_mismatch = self.client.post("/register", data={
            "csrf_token": csrf_token,
            "username": "valid_user",
            "email": "test@example.com",
            "password": "Password123!",
            "confirm_password": "MismatchPassword456!",
        })
        self.assertEqual(res_mismatch.status_code, 400)
        self.assertIn(b"Passwords do not match", res_mismatch.data)

        # Short password
        res_short = self.client.post("/register", data={
            "csrf_token": csrf_token,
            "username": "valid_user",
            "email": "test@example.com",
            "password": "short",
            "confirm_password": "short",
        })
        self.assertEqual(res_short.status_code, 400)
        self.assertIn(b"at least 8 characters", res_short.data)

    # -------------------------------------------------------------
    # 3. Login & Authentication Tests
    # -------------------------------------------------------------
    def _create_user(self, username="alice", email="alice@example.com", password="Password123!"):
        res = self.client.get("/register")
        csrf_token = self.extract_csrf_token(res.get_data(as_text=True))
        self.client.post("/register", data={
            "csrf_token": csrf_token,
            "username": username,
            "email": email,
            "password": password,
            "confirm_password": password,
        })

    def test_login_success(self):
        """Test login with valid email and password."""
        self._create_user(username="bob", email="bob@example.com", password="SecurePassBob123")

        res = self.client.get("/login")
        csrf_token = self.extract_csrf_token(res.get_data(as_text=True))

        login_res = self.client.post("/login", data={
            "csrf_token": csrf_token,
            "email": "bob@example.com",
            "password": "SecurePassBob123",
        }, follow_redirects=True)

        self.assertEqual(login_res.status_code, 200)
        self.assertIn(b"Welcome back", login_res.data)
        self.assertIn(b"bob", login_res.data)

    def test_login_invalid_password(self):
        """Test login rejection when password is incorrect."""
        self._create_user(username="carol", email="carol@example.com", password="Password123!")

        res = self.client.get("/login")
        csrf_token = self.extract_csrf_token(res.get_data(as_text=True))

        login_res = self.client.post("/login", data={
            "csrf_token": csrf_token,
            "email": "carol@example.com",
            "password": "WrongPassword999",
        })

        self.assertEqual(login_res.status_code, 401)
        self.assertIn(b"Invalid email or password", login_res.data)

    def test_logout(self):
        """Test logging out clears the session and prevents dashboard access."""
        self._create_user(username="dan", email="dan@example.com", password="Password123!")

        res = self.client.get("/login")
        csrf_token = self.extract_csrf_token(res.get_data(as_text=True))
        self.client.post("/login", data={
            "csrf_token": csrf_token,
            "email": "dan@example.com",
            "password": "Password123!",
        })

        # Confirm dashboard is accessible
        dash_res = self.client.get("/dashboard")
        self.assertEqual(dash_res.status_code, 200)

        # Log out
        logout_res = self.client.get("/logout", follow_redirects=True)
        self.assertEqual(logout_res.status_code, 200)
        self.assertIn(b"successfully logged out", logout_res.data)

        # Subsequent dashboard access should redirect to login
        dash_after = self.client.get("/dashboard")
        self.assertEqual(dash_after.status_code, 302)
        self.assertIn("/login", dash_after.headers["Location"])

    # -------------------------------------------------------------
    # 4. Session Protection & Route Guards
    # -------------------------------------------------------------
    def test_unauthenticated_routes_redirect_to_login(self):
        """Test that unauthenticated requests to protected routes redirect to /login."""
        protected_routes = ["/dashboard", "/websites", "/history", "/incidents"]
        for route in protected_routes:
            res = self.client.get(route)
            self.assertEqual(res.status_code, 302, f"Route {route} did not redirect.")
            self.assertIn("/login", res.headers["Location"])

    # -------------------------------------------------------------
    # 5. CSRF Protection Tests
    # -------------------------------------------------------------
    def test_csrf_protection_rejects_missing_or_bad_token(self):
        """Test that state-changing requests without or with forged CSRF tokens are rejected."""
        # 1. Missing token
        res_missing = self.client.post("/register", data={
            "username": "hacker1",
            "email": "hacker1@example.com",
            "password": "Password123!",
            "confirm_password": "Password123!",
        })
        self.assertEqual(res_missing.status_code, 400)
        self.assertIn(b"CSRF token is missing or invalid", res_missing.data)

        # 2. Invalid forged token
        self.client.get("/register")  # establish session
        res_bad = self.client.post("/register", data={
            "csrf_token": "forged_malicious_token_12345",
            "username": "hacker2",
            "email": "hacker2@example.com",
            "password": "Password123!",
            "confirm_password": "Password123!",
        })
        self.assertEqual(res_bad.status_code, 400)
        self.assertIn(b"CSRF token is missing or invalid", res_bad.data)

    # -------------------------------------------------------------
    # 6. Dashboard Statistics & User Isolation Tests
    # -------------------------------------------------------------
    def test_dashboard_statistics_and_user_isolation(self):
        """Test dashboard query statistics with real DB rows and verify strict user isolation."""
        # Register User 1
        self._create_user(username="owner1", email="owner1@example.com", password="Password123!")
        # Register User 2
        self._create_user(username="owner2", email="owner2@example.com", password="Password123!")

        with self.app.app_context():
            db = database.get_db()
            user1 = db.execute("SELECT id FROM users WHERE username = 'owner1'").fetchone()
            user2 = db.execute("SELECT id FROM users WHERE username = 'owner2'").fetchone()

            # Insert services for User 1: 1 UP, 1 DOWN, 1 UNKNOWN
            db.execute("INSERT INTO services (user_id, service_name, service_url, current_status) VALUES (?, ?, ?, ?)",
                       (user1["id"], "User1 API", "https://api.user1.com", "UP"))
            db.execute("INSERT INTO services (user_id, service_name, service_url, current_status) VALUES (?, ?, ?, ?)",
                       (user1["id"], "User1 Web", "https://user1.com", "DOWN"))
            db.execute("INSERT INTO services (user_id, service_name, service_url, current_status) VALUES (?, ?, ?, ?)",
                       (user1["id"], "User1 Staging", "https://stage.user1.com", "UNKNOWN"))

            # Insert services for User 2: 2 UP, 0 DOWN
            db.execute("INSERT INTO services (user_id, service_name, service_url, current_status) VALUES (?, ?, ?, ?)",
                       (user2["id"], "User2 Service A", "https://a.user2.com", "UP"))
            db.execute("INSERT INTO services (user_id, service_url, service_name, current_status) VALUES (?, ?, ?, ?)",
                       (user2["id"], "https://b.user2.com", "User2 Service B", "UP"))
            db.commit()

        # Log in as User 1
        res = self.client.get("/login")
        csrf_token = self.extract_csrf_token(res.get_data(as_text=True))
        self.client.post("/login", data={
            "csrf_token": csrf_token,
            "email": "owner1@example.com",
            "password": "Password123!",
        })

        # Check Dashboard for User 1
        dash1 = self.client.get("/dashboard")
        self.assertEqual(dash1.status_code, 200)
        content1 = dash1.get_data(as_text=True)

        # Total Services should be 3 (not 5)
        self.assertIn('id="totalServicesCount">3<', content1)
        # UP Services should be 1 (not 3)
        self.assertIn('id="upServicesCount">1<', content1)
        # DOWN Services should be 1
        self.assertIn('id="downServicesCount">1<', content1)

        # Log out and log in as User 2
        self.client.get("/logout")
        res2 = self.client.get("/login")
        csrf2 = self.extract_csrf_token(res2.get_data(as_text=True))
        self.client.post("/login", data={
            "csrf_token": csrf2,
            "email": "owner2@example.com",
            "password": "Password123!",
        })

        # Check Dashboard for User 2
        dash2 = self.client.get("/dashboard")
        self.assertEqual(dash2.status_code, 200)
        content2 = dash2.get_data(as_text=True)

        # Total Services should be 2
        self.assertIn('id="totalServicesCount">2<', content2)
        # UP Services should be 2
        self.assertIn('id="upServicesCount">2<', content2)
        # DOWN Services should be 0
        self.assertIn('id="downServicesCount">0<', content2)


if __name__ == "__main__":
    unittest.main()
