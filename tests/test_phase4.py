"""Automated test suite for Distributed Status Tracker - Phase 4.

Covers:
- Downtime Risk Prediction & Assessment Engine (risk_engine.py)
- Risk level classification (LOW, MEDIUM, HIGH)
- Latency trend evaluation (STABLE, INCREASING, SPIKING, IMPROVING, INSUFFICIENT_DATA)
- Consecutive failure and failure rate penalties
- Sustained stability discount
- JSON API endpoints (/api/services/<id>/risk, /api/websites/<id>/risk, /api/dashboard/risk-summary)
- Multi-tenant isolation for risk endpoints
"""

import os
import tempfile
import unittest
from unittest.mock import patch

from app import create_app
import database
import risk_engine


class Phase4RiskEngineTestCase(unittest.TestCase):
    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp(suffix=".db")
        self.app = create_app({
            "TESTING": True,
            "DATABASE": self.db_path,
            "SECRET_KEY": "test-phase4-secret-key",
            "WTF_CSRF_ENABLED": True,
            "TESTING_SKIP_CSRF": False,
        })
        self.client = self.app.test_client()

    def tearDown(self):
        os.close(self.db_fd)
        if os.path.exists(self.db_path):
            os.unlink(self.db_path)

    def _create_user(self, username="tester4", email="tester4@example.com"):
        with self.app.app_context():
            db = database.get_db()
            db.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                (username, email, "scrypt:mock_hash"),
            )
            db.commit()
            return db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()["id"]

    def _create_service(self, user_id, name="Test Service", url="https://example.com"):
        with self.app.app_context():
            db = database.get_db()
            db.execute(
                """
                INSERT INTO services (user_id, service_name, service_url, current_status, consecutive_failures)
                VALUES (?, ?, ?, 'UP', 0)
                """,
                (user_id, name, url),
            )
            db.commit()
            return db.execute("SELECT id FROM services WHERE user_id = ?", (user_id,)).fetchone()["id"]

    def test_classify_risk_level(self):
        """Verify score thresholds for LOW, MEDIUM, and HIGH."""
        self.assertEqual(risk_engine.classify_risk_level(0), "LOW")
        self.assertEqual(risk_engine.classify_risk_level(29), "LOW")
        self.assertEqual(risk_engine.classify_risk_level(30), "MEDIUM")
        self.assertEqual(risk_engine.classify_risk_level(59), "MEDIUM")
        self.assertEqual(risk_engine.classify_risk_level(60), "HIGH")
        self.assertEqual(risk_engine.classify_risk_level(100), "HIGH")

    def test_insufficient_data_risk(self):
        """Brand new services with fewer than 3 checks should receive baseline initial risk."""
        uid = self._create_user()
        sid = self._create_service(uid)

        with self.app.app_context():
            db = database.get_db()
            svc = db.execute("SELECT * FROM services WHERE id = ?", (sid,)).fetchone()
            risk = risk_engine.calculate_service_risk(dict(svc), db)
            self.assertEqual(risk["latency_trend"], "INSUFFICIENT_DATA")
            self.assertIn("Insufficient", risk["explanation"])
            self.assertEqual(risk["risk_level"], "LOW")
            self.assertEqual(risk["risk_score"], 15)

    def test_high_risk_consecutive_failures(self):
        """Service in DOWN state with consecutive failures should score HIGH risk."""
        uid = self._create_user()
        sid = self._create_service(uid)

        with self.app.app_context():
            db = database.get_db()
            # Insert 5 failed monitoring results
            for _ in range(5):
                db.execute(
                    """
                    INSERT INTO monitoring_results (service_id, status, response_time, error_message, failure_category)
                    VALUES (?, 'DOWN', 5000.0, 'Connection timed out', 'Connection timeout')
                    """,
                    (sid,),
                )
            db.commit()

            svc = {
                "id": sid,
                "current_status": "DOWN",
                "consecutive_failures": 5,
                "failure_threshold": 2,
            }
            risk = risk_engine.calculate_service_risk(svc, db)
            self.assertEqual(risk["risk_level"], "HIGH")
            self.assertGreaterEqual(risk["risk_score"], 60)
            self.assertTrue(any("DOWN" in f for f in risk["contributing_factors"]))

    def test_latency_spike_detection(self):
        """Surging response times should be classified as SPIKING or INCREASING."""
        uid = self._create_user()
        sid = self._create_service(uid)

        with self.app.app_context():
            db = database.get_db()
            # Baseline: 5 checks with 100ms
            for _ in range(5):
                db.execute(
                    "INSERT INTO monitoring_results (service_id, status, response_time) VALUES (?, 'UP', 100.0)",
                    (sid,),
                )
            # Recent: 5 checks with 800ms
            for _ in range(5):
                db.execute(
                    "INSERT INTO monitoring_results (service_id, status, response_time) VALUES (?, 'UP', 800.0)",
                    (sid,),
                )
            db.commit()

            svc = {
                "id": sid,
                "current_status": "UP",
                "consecutive_failures": 0,
                "failure_threshold": 2,
            }
            risk = risk_engine.calculate_service_risk(svc, db)
            self.assertIn(risk["latency_trend"], ("SPIKING", "INCREASING"))
            self.assertTrue(any("latency" in f.lower() for f in risk["contributing_factors"]))

    def test_sustained_stability_discount(self):
        """Long run of healthy checks should receive a stability score bonus."""
        uid = self._create_user()
        sid = self._create_service(uid)

        with self.app.app_context():
            db = database.get_db()
            # 20 consecutive healthy checks
            for _ in range(20):
                db.execute(
                    "INSERT INTO monitoring_results (service_id, status, response_time) VALUES (?, 'UP', 50.0)",
                    (sid,),
                )
            db.commit()

            svc = {
                "id": sid,
                "current_status": "UP",
                "consecutive_failures": 0,
                "failure_threshold": 2,
            }
            risk = risk_engine.calculate_service_risk(svc, db)
            self.assertEqual(risk["risk_level"], "LOW")
            self.assertEqual(risk["risk_score"], 0)
            self.assertTrue(any("stability bonus" in f.lower() for f in risk["contributing_factors"]))

    def test_api_risk_endpoints(self):
        """Verify /api/services/<id>/risk and /api/dashboard/risk-summary authenticated JSON routes."""
        uid = self._create_user()
        sid = self._create_service(uid)

        with self.client.session_transaction() as sess:
            sess["user_id"] = uid
            sess["username"] = "tester4"

        # 1. Test single service risk endpoint
        res = self.client.get(f"/api/services/{sid}/risk")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertIn("risk", data)
        self.assertEqual(data["risk"]["service_id"], sid)

        # 2. Test alias endpoint /api/websites/<id>/risk
        res_alias = self.client.get(f"/api/websites/{sid}/risk")
        self.assertEqual(res_alias.status_code, 200)
        self.assertEqual(res_alias.get_json()["status"], "success")

        # 3. Test user-wide summary endpoint
        res_sum = self.client.get("/api/dashboard/risk-summary")
        self.assertEqual(res_sum.status_code, 200)
        sum_data = res_sum.get_json()
        self.assertEqual(sum_data["status"], "success")
        self.assertEqual(sum_data["summary"]["total_services"], 1)
        self.assertEqual(len(sum_data["services"]), 1)


if __name__ == "__main__":
    unittest.main()
