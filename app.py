"""Distributed Status Tracker - Main Application.

Provides core web routes, authentication, endpoint management,
monitoring telemetry, risk assessments, and incident diagnostics.
"""

import os
import re
import secrets
import logging
import math
import threading
from datetime import timedelta
from functools import wraps

from dotenv import load_dotenv
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    abort,
    jsonify,
    g,
)
from werkzeug.security import generate_password_hash, check_password_hash

import database
import validator
import monitor
import monitor_daemon
import risk_engine

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("status_tracker")

# Validation regex patterns
USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{3,30}$")
EMAIL_PATTERN = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


def generate_csrf_token():
    """Ensure a CSRF token exists in the session and return it."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def login_required(view_func):
    """Decorator to require login for protected routes."""
    @wraps(view_func)
    def decorated_view(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("login", next=request.path))
        return view_func(*args, **kwargs)
    return decorated_view


def create_app(test_config=None):
    """Application factory for the Flask application."""
    app = Flask(__name__, instance_relative_config=True)

    # Determine instance path and ensure it exists
    os.makedirs(app.instance_path, exist_ok=True)

    # Secret key configuration
    secret_key = os.getenv("SECRET_KEY")
    if not secret_key:
        logger.warning(
            "SECRET_KEY is not set in environment. Generating a transient secret key. "
            "Set SECRET_KEY in your .env file for persistent sessions."
        )
        secret_key = secrets.token_hex(32)

    default_db_path = os.path.join(app.instance_path, "status_tracker.db")

    app.config.from_mapping(
        SECRET_KEY=secret_key,
        DATABASE=os.getenv("DATABASE_PATH", default_db_path),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE", "False").lower() in ("true", "1"),
        PERMANENT_SESSION_LIFETIME=timedelta(days=7),
    )

    if test_config:
        app.config.update(test_config)

    # Initialize database
    database.init_app(app)

    # CSRF context processor
    @app.context_processor
    def inject_csrf_and_user():
        current_user = None
        if session.get("user_id"):
            current_user = {
                "id": session.get("user_id"),
                "username": session.get("username"),
                "email": session.get("email"),
            }
        return {
            "csrf_token": generate_csrf_token(),
            "current_user": current_user,
        }

    # CSRF verification before state-changing requests
    @app.before_request
    def check_csrf():
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            # Skip CSRF check only if explicitly disabled in testing
            if app.config.get("TESTING_SKIP_CSRF", False):
                return
            expected_token = session.get("csrf_token")
            submitted_token = request.form.get("csrf_token") or request.headers.get("X-CSRFToken")

            if not expected_token or not submitted_token or not secrets.compare_digest(expected_token, submitted_token):
                logger.warning("CSRF validation failed for path: %s", request.path)
                abort(400, description="CSRF token is missing or invalid. Please refresh the page and try again.")

    # Error Handlers
    @app.errorhandler(400)
    def bad_request_error(e):
        return render_template(
            "error.html",
            error_code=400,
            error_title="Bad Request",
            error_message=str(e.description if hasattr(e, "description") else e),
        ), 400

    @app.errorhandler(404)
    def not_found_error(e):
        return render_template(
            "error.html",
            error_code=404,
            error_title="Page Not Found",
            error_message="The requested resource could not be found.",
        ), 404

    @app.errorhandler(500)
    def internal_error(e):
        logger.error("Internal Server Error: %s", e)
        return render_template(
            "error.html",
            error_code=500,
            error_title="Internal Server Error",
            error_message="An unexpected server error occurred. Please try again later.",
        ), 500

    # -------------------------------------------------------------
    # Routes
    # -------------------------------------------------------------

    @app.route("/")
    def index():
        """Root route redirects authenticated users to dashboard and guests to login."""
        if session.get("user_id"):
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        """User registration route."""
        if session.get("user_id"):
            return redirect(url_for("dashboard"))

        if request.method == "POST":
            username = request.form.get("username", "").strip()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            confirm_password = request.form.get("confirm_password", "")

            errors = []

            # Server-side validation
            if not username:
                errors.append("Username is required.")
            elif not USERNAME_PATTERN.match(username):
                errors.append("Username must be 3-30 characters long and contain only letters, numbers, hyphens, and underscores.")

            if not email:
                errors.append("Email address is required.")
            elif not EMAIL_PATTERN.match(email):
                errors.append("Please provide a valid email address.")

            if not password:
                errors.append("Password is required.")
            elif len(password) < 8:
                errors.append("Password must be at least 8 characters long.")

            if password != confirm_password:
                errors.append("Passwords do not match.")

            if errors:
                for err in errors:
                    flash(err, "error")
                return render_template("register.html", username=username, email=email), 400

            # Database checks and insertion
            db = database.get_db()
            try:
                # Check for duplicate username
                existing_user = db.execute(
                    "SELECT id FROM users WHERE username = ?", (username,)
                ).fetchone()
                if existing_user:
                    flash("This username is already taken. Please choose another.", "error")
                    return render_template("register.html", username=username, email=email), 400

                # Check for duplicate email
                existing_email = db.execute(
                    "SELECT id FROM users WHERE email = ?", (email,)
                ).fetchone()
                if existing_email:
                    flash("An account with this email address already exists.", "error")
                    return render_template("register.html", username=username, email=email), 400

                # Hash password securely using Werkzeug
                password_hash = generate_password_hash(password)

                db.execute(
                    "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                    (username, email, password_hash),
                )
                db.commit()
                logger.info("User registered successfully: username=%s, email=%s", username, email)

                flash("Registration successful! You can now log in with your credentials.", "success")
                return redirect(url_for("login"))

            except Exception as e:
                db.rollback()
                logger.exception("Database error during registration: %s", e)
                flash("An error occurred during registration. Please try again.", "error")
                return render_template("register.html", username=username, email=email), 500

        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        """User login route."""
        if session.get("user_id"):
            return redirect(url_for("dashboard"))

        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")

            if not email or not password:
                flash("Please enter both email and password.", "error")
                return render_template("login.html", email=email), 400

            db = database.get_db()
            try:
                user = db.execute(
                    "SELECT id, username, email, password_hash FROM users WHERE email = ?",
                    (email,),
                ).fetchone()

                if user is None or not check_password_hash(user["password_hash"], password):
                    logger.warning("Failed login attempt for email: %s", email)
                    flash("Invalid email or password. Please try again.", "error")
                    return render_template("login.html", email=email), 401

                # Establish user session
                session.clear()
                # Re-generate CSRF token for the new session
                session["csrf_token"] = secrets.token_hex(32)
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                session["email"] = user["email"]
                session.permanent = True

                logger.info("User logged in successfully: id=%s, username=%s", user["id"], user["username"])
                flash(f"Welcome back, {user['username']}!", "success")

                next_url = request.args.get("next")
                # Basic protection against open redirect: ensure relative URL
                if next_url and next_url.startswith("/"):
                    return redirect(next_url)
                return redirect(url_for("dashboard"))

            except Exception as e:
                logger.exception("Database error during login: %s", e)
                flash("A database error occurred. Please try again.", "error")
                return render_template("login.html", email=email), 500

        return render_template("login.html")

    @app.route("/logout", methods=["GET", "POST"])
    def logout():
        """Log out the current user and clear session."""
        username = session.get("username")
        session.clear()
        if username:
            logger.info("User logged out: %s", username)
        flash("You have been successfully logged out.", "info")
        return redirect(url_for("login"))

    @app.route("/dashboard")
    @login_required
    def dashboard():
        """User dashboard displaying live counts and latest results for authenticated user."""
        user_id = session["user_id"]
        username = session["username"]
        db = database.get_db()

        try:
            total_services = db.execute(
                "SELECT COUNT(*) as count FROM services WHERE user_id = ?",
                (user_id,),
            ).fetchone()["count"]

            up_services = db.execute(
                "SELECT COUNT(*) as count FROM services WHERE user_id = ? AND current_status = 'UP'",
                (user_id,),
            ).fetchone()["count"]

            degraded_services = db.execute(
                "SELECT COUNT(*) as count FROM services WHERE user_id = ? AND current_status = 'DEGRADED'",
                (user_id,),
            ).fetchone()["count"]

            down_services = db.execute(
                "SELECT COUNT(*) as count FROM services WHERE user_id = ? AND current_status = 'DOWN'",
                (user_id,),
            ).fetchone()["count"]

            active_incidents = db.execute(
                """
                SELECT inc.id, inc.service_id, s.service_name, inc.incident_type, inc.failure_category, inc.possible_cause, inc.started_at
                FROM incidents inc
                JOIN services s ON inc.service_id = s.id
                WHERE s.user_id = ? AND inc.status = 'OPEN'
                ORDER BY inc.id DESC
                """,
                (user_id,),
            ).fetchall()

            stats = {
                "total_services": total_services,
                "up_services": up_services,
                "degraded_services": degraded_services,
                "down_services": down_services,
                "active_incidents": len(active_incidents),
            }

            # Fetch recent monitoring results for this user
            latest_results = db.execute(
                """
                SELECT mr.id, mr.service_id, s.service_name, s.service_url,
                       mr.status, mr.response_time, mr.http_status_code,
                       mr.error_message, mr.failure_category, mr.confidence, mr.checked_at
                FROM monitoring_results mr
                JOIN services s ON mr.service_id = s.id
                WHERE s.user_id = ?
                ORDER BY mr.id DESC
                LIMIT 6
                """,
                (user_id,),
            ).fetchall()

            # Fetch services list with risk indicators
            raw_services = db.execute(
                """
                SELECT id, service_name, service_url, check_interval, timeout,
                       current_status, is_active, last_checked_at, last_response_time, last_status_code,
                       consecutive_failures, failure_threshold, risk_score, risk_level
                FROM services
                WHERE user_id = ?
                ORDER BY id DESC
                LIMIT 8
                """,
                (user_id,),
            ).fetchall()

            services_with_risk = []
            for svc in raw_services:
                s_dict = dict(svc)
                risk_info = risk_engine.calculate_service_risk(s_dict, db)
                s_dict["risk_score"] = risk_info["risk_score"]
                s_dict["risk_level"] = risk_info["risk_level"]
                s_dict["latency_trend"] = risk_info["latency_trend"]
                s_dict["risk_explanation"] = risk_info["explanation"]
                s_dict["contributing_factors"] = risk_info["contributing_factors"]
                s_dict["recommendations"] = risk_info["recommendations"]
                services_with_risk.append(s_dict)

            return render_template(
                "dashboard.html",
                username=username,
                stats=stats,
                latest_results=latest_results,
                services_list=services_with_risk,
                active_incidents=active_incidents,
            )

        except Exception as e:
            logger.exception("Error loading dashboard data for user %s: %s", user_id, e)
            flash("Error retrieving monitoring statistics.", "error")
            stats = {"total_services": 0, "up_services": 0, "degraded_services": 0, "down_services": 0, "active_incidents": 0}
            return render_template("dashboard.html", username=username, stats=stats, latest_results=[], services_list=[], active_incidents=[])

    @app.route("/api/dashboard/stats")
    @login_required
    def api_dashboard_stats():
        """Authenticated JSON endpoint for client-side live polling."""
        user_id = session["user_id"]
        db = database.get_db()

        try:
            total_services = db.execute(
                "SELECT COUNT(*) as count FROM services WHERE user_id = ?",
                (user_id,),
            ).fetchone()["count"]

            up_services = db.execute(
                "SELECT COUNT(*) as count FROM services WHERE user_id = ? AND current_status = 'UP'",
                (user_id,),
            ).fetchone()["count"]

            degraded_services = db.execute(
                "SELECT COUNT(*) as count FROM services WHERE user_id = ? AND current_status = 'DEGRADED'",
                (user_id,),
            ).fetchone()["count"]

            down_services = db.execute(
                "SELECT COUNT(*) as count FROM services WHERE user_id = ? AND current_status = 'DOWN'",
                (user_id,),
            ).fetchone()["count"]

            active_incidents_rows = db.execute(
                """
                SELECT inc.id, inc.service_id, s.service_name, inc.incident_type, inc.failure_category, inc.possible_cause, inc.started_at
                FROM incidents inc
                JOIN services s ON inc.service_id = s.id
                WHERE s.user_id = ? AND inc.status = 'OPEN'
                ORDER BY inc.id DESC
                """,
                (user_id,),
            ).fetchall()
            active_incidents_count = len(active_incidents_rows)
            active_incidents_data = [dict(row) for row in active_incidents_rows]

            recent_results_rows = db.execute(
                """
                SELECT mr.id, mr.service_id, s.service_name, s.service_url,
                       mr.status, mr.response_time, mr.http_status_code,
                       mr.error_message, mr.failure_category, mr.confidence, mr.checked_at
                FROM monitoring_results mr
                JOIN services s ON mr.service_id = s.id
                WHERE s.user_id = ?
                ORDER BY mr.id DESC
                LIMIT 6
                """,
                (user_id,),
            ).fetchall()

            results_data = [dict(row) for row in recent_results_rows]

            return jsonify({
                "status": "success",
                "stats": {
                    "total_services": total_services,
                    "up_services": up_services,
                    "degraded_services": degraded_services,
                    "down_services": down_services,
                    "active_incidents": active_incidents_count,
                },
                "active_incidents": active_incidents_data,
                "latest_results": results_data,
            })
        except Exception as e:
            logger.exception("API stats error: %s", e)
            return jsonify({"status": "error", "message": "Failed to fetch stats"}), 500

    @app.route("/api/services/<int:service_id>/risk")
    @app.route("/api/websites/<int:service_id>/risk")
    @login_required
    def api_service_risk(service_id):
        """Authenticated JSON endpoint returning explainable downtime risk assessment."""
        user_id = session["user_id"]
        db = database.get_db()

        service = db.execute(
            "SELECT * FROM services WHERE id = ? AND user_id = ?",
            (service_id, user_id),
        ).fetchone()

        if not service:
            abort(404)

        risk_data = risk_engine.calculate_service_risk(dict(service), db)
        return jsonify({
            "status": "success",
            "service_id": service_id,
            "service_name": service["service_name"],
            "service_url": service["service_url"],
            "current_status": service["current_status"],
            "risk": risk_data,
        })

    @app.route("/api/dashboard/risk-summary")
    @login_required
    def api_dashboard_risk_summary():
        """Authenticated JSON endpoint returning user-wide risk summary and service rankings."""
        user_id = session["user_id"]
        db = database.get_db()

        services = db.execute(
            """
            SELECT id, service_name, service_url, current_status, consecutive_failures,
                   failure_threshold, risk_score, risk_level
            FROM services
            WHERE user_id = ?
            ORDER BY id DESC
            """,
            (user_id,),
        ).fetchall()

        assessments = []
        low_count = 0
        med_count = 0
        high_count = 0
        total_score = 0

        for svc in services:
            risk = risk_engine.calculate_service_risk(dict(svc), db)
            score = risk["risk_score"]
            level = risk["risk_level"]
            total_score += score
            if level == "HIGH":
                high_count += 1
            elif level == "MEDIUM":
                med_count += 1
            else:
                low_count += 1

            assessments.append({
                "service_id": svc["id"],
                "service_name": svc["service_name"],
                "service_url": svc["service_url"],
                "current_status": svc["current_status"],
                "risk_score": score,
                "risk_level": level,
                "latency_trend": risk["latency_trend"],
                "explanation": risk["explanation"],
                "contributing_factors": risk["contributing_factors"],
                "recommendations": risk["recommendations"],
                "metrics": risk["metrics"],
            })

        avg_score = round(total_score / len(services), 1) if services else 0

        return jsonify({
            "status": "success",
            "summary": {
                "total_services": len(services),
                "low_risk_count": low_count,
                "medium_risk_count": med_count,
                "high_risk_count": high_count,
                "average_risk_score": avg_score,
            },
            "services": assessments,
        })

    # -------------------------------------------------------------
    # Website Management Routes
    # -------------------------------------------------------------

    @app.route("/websites")
    @login_required
    def websites():
        """List all websites belonging to the logged-in user with risk levels."""
        user_id = session["user_id"]
        db = database.get_db()
        websites_list = db.execute(
            """
            SELECT id, service_name, service_url, check_interval, timeout,
                   current_status, is_active, last_checked_at, last_response_time, last_status_code,
                   risk_score, risk_level, created_at
            FROM services
            WHERE user_id = ?
            ORDER BY id DESC
            """,
            (user_id,),
        ).fetchall()
        return render_template("websites.html", websites=websites_list)

    @app.route("/websites/add", methods=["POST"])
    @login_required
    def add_website():
        """Add a new website with SSRF validation, and perform an immediate initial check."""
        user_id = session["user_id"]
        service_name = request.form.get("service_name", "")
        service_url = request.form.get("service_url", "")
        check_interval = request.form.get("check_interval", 60)
        timeout = request.form.get("timeout", 5)

        is_valid, cleaned, errors = validator.validate_service_inputs(
            service_name=service_name,
            service_url=service_url,
            check_interval_raw=check_interval,
            timeout_raw=timeout,
        )

        if not is_valid:
            for err in errors:
                flash(err, "error")
            return redirect(url_for("websites"))

        db = database.get_db()
        try:
            cursor = db.cursor()
            cursor.execute(
                """
                INSERT INTO services (user_id, service_name, service_url, check_interval, timeout, is_active, current_status)
                VALUES (?, ?, ?, ?, ?, 1, 'UNKNOWN')
                """,
                (
                    user_id,
                    cleaned["service_name"],
                    cleaned["service_url"],
                    cleaned["check_interval"],
                    cleaned["timeout"],
                ),
            )
            service_id = cursor.lastrowid
            db.commit()

            # Execute immediate initial check for user feedback
            new_service = {
                "id": service_id,
                "service_name": cleaned["service_name"],
                "service_url": cleaned["service_url"],
                "timeout": cleaned["timeout"],
                "check_interval": cleaned["check_interval"],
            }
            try:
                check_result = monitor.check_single_service(new_service, db)
                status_note = f" (Status: {check_result['status']}, {check_result['response_time']}ms)"
            except Exception as check_exc:
                logger.warning("Initial check failed for new service #%s: %s", service_id, check_exc)
                status_note = ""

            flash(f"Website '{cleaned['service_name']}' added successfully!{status_note}", "success")
            return redirect(url_for("websites"))

        except Exception as e:
            db.rollback()
            logger.exception("Failed to add website: %s", e)
            flash("An error occurred while saving the website. Please try again.", "error")
            return redirect(url_for("websites"))

    @app.route("/websites/<int:service_id>")
    @login_required
    def website_detail(service_id):
        """Website details view displaying history, response times, and error messages."""
        user_id = session["user_id"]
        db = database.get_db()

        service = db.execute(
            """
            SELECT * FROM services WHERE id = ? AND user_id = ?
            """,
            (service_id, user_id),
        ).fetchone()

        if not service:
            abort(404)

        recent_results = db.execute(
            """
            SELECT * FROM monitoring_results
            WHERE service_id = ?
            ORDER BY id DESC
            LIMIT 30
            """,
            (service_id,),
        ).fetchall()

        active_incident = db.execute(
            """
            SELECT * FROM incidents
            WHERE service_id = ? AND status = 'OPEN'
            ORDER BY id DESC LIMIT 1
            """,
            (service_id,),
        ).fetchone()

        past_incidents = db.execute(
            """
            SELECT * FROM incidents
            WHERE service_id = ?
            ORDER BY id DESC LIMIT 10
            """,
            (service_id,),
        ).fetchall()

        # Calculate explainable downtime risk assessment
        risk_assessment = risk_engine.calculate_service_risk(dict(service), db)

        return render_template(
            "website_detail.html",
            service=service,
            recent_results=recent_results,
            active_incident=active_incident,
            past_incidents=past_incidents,
            risk_assessment=risk_assessment,
        )

    @app.route("/websites/<int:service_id>/edit", methods=["GET", "POST"])
    @login_required
    def edit_website(service_id):
        """Edit an existing website's configuration."""
        user_id = session["user_id"]
        db = database.get_db()

        service = db.execute(
            "SELECT * FROM services WHERE id = ? AND user_id = ?",
            (service_id, user_id),
        ).fetchone()

        if not service:
            abort(404)

        if request.method == "POST":
            service_name = request.form.get("service_name", "")
            service_url = request.form.get("service_url", "")
            check_interval = request.form.get("check_interval", 60)
            timeout = request.form.get("timeout", 5)

            is_valid, cleaned, errors = validator.validate_service_inputs(
                service_name=service_name,
                service_url=service_url,
                check_interval_raw=check_interval,
                timeout_raw=timeout,
            )

            if not is_valid:
                for err in errors:
                    flash(err, "error")
                return render_template("website_edit.html", service=service)

            try:
                db.execute(
                    """
                    UPDATE services
                    SET service_name = ?, service_url = ?, check_interval = ?, timeout = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ? AND user_id = ?
                    """,
                    (
                        cleaned["service_name"],
                        cleaned["service_url"],
                        cleaned["check_interval"],
                        cleaned["timeout"],
                        service_id,
                        user_id,
                    ),
                )
                db.commit()
                flash("Website updated successfully.", "success")
                return redirect(url_for("website_detail", service_id=service_id))
            except Exception as e:
                db.rollback()
                logger.exception("Failed to update website #%s: %s", service_id, e)
                flash("Database error updating website.", "error")
                return render_template("website_edit.html", service=service)

        return render_template("website_edit.html", service=service)

    @app.route("/websites/<int:service_id>/delete", methods=["POST"])
    @login_required
    def delete_website(service_id):
        """Delete an existing website."""
        user_id = session["user_id"]
        db = database.get_db()

        service = db.execute(
            "SELECT id, service_name FROM services WHERE id = ? AND user_id = ?",
            (service_id, user_id),
        ).fetchone()

        if not service:
            abort(404)

        try:
            db.execute("DELETE FROM services WHERE id = ? AND user_id = ?", (service_id, user_id))
            db.commit()
            flash(f"Website '{service['service_name']}' was successfully deleted.", "info")
            return redirect(url_for("websites"))
        except Exception as e:
            db.rollback()
            logger.exception("Failed to delete service #%s: %s", service_id, e)
            flash("Error deleting website.", "error")
            return redirect(url_for("websites"))

    @app.route("/websites/<int:service_id>/toggle", methods=["POST"])
    @login_required
    def toggle_website(service_id):
        """Toggle monitoring enabled/disabled state."""
        user_id = session["user_id"]
        db = database.get_db()

        service = db.execute(
            "SELECT id, service_name, is_active FROM services WHERE id = ? AND user_id = ?",
            (service_id, user_id),
        ).fetchone()

        if not service:
            abort(404)

        new_status = 0 if service["is_active"] == 1 else 1
        try:
            db.execute(
                "UPDATE services SET is_active = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?",
                (new_status, service_id, user_id),
            )
            db.commit()
            msg = "Monitoring resumed." if new_status == 1 else "Monitoring paused."
            flash(f"{service['service_name']}: {msg}", "info")
        except Exception as e:
            db.rollback()
            logger.exception("Failed to toggle service #%s: %s", service_id, e)
            flash("Error updating monitoring status.", "error")

        # Redirect back to referring page or websites
        referer = request.headers.get("Referer")
        if referer and "/websites" in referer:
            return redirect(referer)
        return redirect(url_for("websites"))

    @app.route("/websites/<int:service_id>/check", methods=["POST"])
    @login_required
    def check_website_now(service_id):
        """Perform on-demand immediate check for a website."""
        user_id = session["user_id"]
        db = database.get_db()

        service = db.execute(
            "SELECT * FROM services WHERE id = ? AND user_id = ?",
            (service_id, user_id),
        ).fetchone()

        if not service:
            abort(404)

        try:
            result = monitor.check_single_service(dict(service), db)
            flash(
                f"Check completed: Status={result['status']}, Latency={result['response_time']}ms",
                "success" if result["status"] == "UP" else ("warning" if result["status"] == "DEGRADED" else "error"),
            )
        except Exception as e:
            logger.exception("Manual check failed for service #%s: %s", service_id, e)
            flash(f"Manual check failed: {str(e)}", "error")

        referer = request.headers.get("Referer")
        if referer and ("/websites" in referer or "/dashboard" in referer):
            return redirect(referer)
        return redirect(url_for("website_detail", service_id=service_id))

    # -------------------------------------------------------------
    # Monitoring History Route
    # -------------------------------------------------------------

    @app.route("/history")
    @login_required
    def history():
        """Monitoring history logs for authenticated user with pagination and filter."""
        user_id = session["user_id"]
        db = database.get_db()

        service_filter = request.args.get("service_id", type=int)
        page = max(request.args.get("page", 1, type=int), 1)
        per_page = 25
        offset = (page - 1) * per_page

        # User's services list for filter dropdown
        user_services = db.execute(
            "SELECT id, service_name FROM services WHERE user_id = ? ORDER BY service_name ASC",
            (user_id,),
        ).fetchall()

        base_count_sql = """
            SELECT COUNT(*) as count
            FROM monitoring_results mr
            JOIN services s ON mr.service_id = s.id
            WHERE s.user_id = ?
        """
        params_count = [user_id]
        if service_filter:
            base_count_sql += " AND mr.service_id = ?"
            params_count.append(service_filter)

        total_count = db.execute(base_count_sql, tuple(params_count)).fetchone()["count"]
        total_pages = max(math.ceil(total_count / per_page), 1)

        base_data_sql = """
            SELECT mr.id, mr.service_id, s.service_name, s.service_url,
                   mr.status, mr.response_time, mr.http_status_code,
                   mr.error_message, mr.failure_category, mr.possible_cause,
                   mr.evidence, mr.recommended_steps, mr.confidence, mr.incident_id,
                   mr.checked_at
            FROM monitoring_results mr
            JOIN services s ON mr.service_id = s.id
            WHERE s.user_id = ?
        """
        params_data = [user_id]
        if service_filter:
            base_data_sql += " AND mr.service_id = ?"
            params_data.append(service_filter)

        base_data_sql += " ORDER BY mr.id DESC LIMIT ? OFFSET ?"
        params_data.extend([per_page, offset])

        history_rows = db.execute(base_data_sql, tuple(params_data)).fetchall()

        return render_template(
            "history.html",
            history_rows=history_rows,
            user_services=user_services,
            current_filter=service_filter,
            page=page,
            total_pages=total_pages,
            total_count=total_count,
        )

    # -------------------------------------------------------------
    # Incidents & Failure Diagnostics Routes
    # -------------------------------------------------------------

    @app.route("/incidents")
    @login_required
    def incidents():
        """Incident tracking & Root Cause Analysis overview for authenticated user."""
        user_id = session["user_id"]
        db = database.get_db()
        status_filter = request.args.get("status", "ALL").upper()

        query = """
            SELECT inc.id, inc.service_id, s.service_name, s.service_url,
                   inc.incident_type, inc.description, inc.possible_cause,
                   inc.evidence, inc.recommended_steps, inc.confidence,
                   inc.started_at, inc.resolved_at, inc.duration_seconds, inc.status
            FROM incidents inc
            JOIN services s ON inc.service_id = s.id
            WHERE s.user_id = ?
        """
        params = [user_id]
        if status_filter in ("OPEN", "RESOLVED"):
            query += " AND inc.status = ?"
            params.append(status_filter)

        query += " ORDER BY CASE WHEN inc.status = 'OPEN' THEN 0 ELSE 1 END, inc.id DESC"
        incidents_list = db.execute(query, tuple(params)).fetchall()

        open_count = db.execute(
            """
            SELECT COUNT(*) as count
            FROM incidents inc
            JOIN services s ON inc.service_id = s.id
            WHERE s.user_id = ? AND inc.status = 'OPEN'
            """,
            (user_id,),
        ).fetchone()["count"]

        resolved_count = db.execute(
            """
            SELECT COUNT(*) as count
            FROM incidents inc
            JOIN services s ON inc.service_id = s.id
            WHERE s.user_id = ? AND inc.status = 'RESOLVED'
            """,
            (user_id,),
        ).fetchone()["count"]

        return render_template(
            "incidents.html",
            incidents=incidents_list,
            status_filter=status_filter,
            open_count=open_count,
            resolved_count=resolved_count,
        )

    @app.route("/incidents/<int:incident_id>")
    @login_required
    def incident_detail(incident_id):
        """Detailed view of an individual incident with root cause analysis and evidence logs."""
        user_id = session["user_id"]
        db = database.get_db()

        incident = db.execute(
            """
            SELECT inc.*, s.service_name, s.service_url
            FROM incidents inc
            JOIN services s ON inc.service_id = s.id
            WHERE inc.id = ? AND s.user_id = ?
            """,
            (incident_id, user_id),
        ).fetchone()

        if not incident:
            abort(404)

        # Related monitoring check results for this service during the incident
        related_results = db.execute(
            """
            SELECT * FROM monitoring_results
            WHERE service_id = ? AND checked_at >= ?
            ORDER BY id DESC LIMIT 20
            """,
            (incident["service_id"], incident["started_at"]),
        ).fetchall()

        return render_template(
            "incident_detail.html",
            incident=incident,
            related_results=related_results,
        )

    return app


def start_background_worker(app):
    """Start integrated background monitoring worker thread if not already running."""
    is_reloader_child = os.environ.get("WERKZEUG_RUN_MAIN") == "true"
    is_direct_run = not app.debug
    if is_reloader_child or is_direct_run:
        t = threading.Thread(
            target=monitor_daemon.run_daemon,
            kwargs={"poll_interval": 3.0, "db_path": app.config["DATABASE"]},
            daemon=True,
            name="AppBackgroundMonitorThread",
        )
        t.start()
        logger.info("Integrated monitoring background worker thread started.")


# Application entry point for WSGI / direct script run
app = create_app()

if __name__ == "__main__":
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "5000"))
    debug_mode = os.getenv("FLASK_DEBUG", "1") == "1"
    start_background_worker(app)
    print(f"Starting Distributed Status Tracker on http://{host}:{port}")
    app.run(host=host, port=port, debug=debug_mode)
