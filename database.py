"""Database module for Distributed Status Tracker.

Handles SQLite connection lifecycle, schema initialization, and foreign key enforcement.
"""

import os
import sqlite3
import logging
from flask import g, current_app

logger = logging.getLogger(__name__)

SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT COLLATE NOCASE UNIQUE NOT NULL,
    email TEXT COLLATE NOCASE UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    service_name TEXT NOT NULL,
    service_url TEXT NOT NULL,
    check_interval INTEGER NOT NULL DEFAULT 60,
    timeout INTEGER NOT NULL DEFAULT 5,
    current_status TEXT NOT NULL DEFAULT 'UNKNOWN',
    is_active INTEGER NOT NULL DEFAULT 1,
    last_checked_at TIMESTAMP,
    last_response_time REAL,
    last_status_code INTEGER,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    failure_threshold INTEGER NOT NULL DEFAULT 2,
    risk_score INTEGER NOT NULL DEFAULT 0,
    risk_level TEXT NOT NULL DEFAULT 'LOW',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS monitoring_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    service_id INTEGER NOT NULL,
    status TEXT NOT NULL,
    response_time REAL,
    http_status_code INTEGER,
    error_message TEXT,
    failure_category TEXT,
    possible_cause TEXT,
    evidence TEXT,
    recommended_steps TEXT,
    confidence TEXT,
    incident_id INTEGER,
    checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    service_id INTEGER NOT NULL,
    incident_type TEXT,
    failure_category TEXT,
    description TEXT,
    possible_cause TEXT,
    evidence TEXT,
    recommended_steps TEXT,
    confidence TEXT,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP,
    duration_seconds INTEGER,
    status TEXT NOT NULL DEFAULT 'OPEN',
    FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE
);

-- Indexes for performance and quick lookups
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_services_user_id ON services(user_id);
CREATE INDEX IF NOT EXISTS idx_monitoring_results_service_id ON monitoring_results(service_id);
CREATE INDEX IF NOT EXISTS idx_monitoring_results_checked_at ON monitoring_results(checked_at);
CREATE INDEX IF NOT EXISTS idx_incidents_service_id ON incidents(service_id);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
"""


def get_db_path():
    """Retrieve database path from app config, env var, or default location."""
    if current_app and "DATABASE" in current_app.config:
        return current_app.config["DATABASE"]
    env_path = os.getenv("DATABASE_PATH", "instance/status_tracker.db")
    return env_path


def get_db():
    """Obtain or reuse SQLite database connection for the current application context."""
    if "db" not in g:
        db_path = get_db_path()
        # Ensure parent directory exists
        db_dir = os.path.dirname(os.path.abspath(db_path))
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)

        g.db = sqlite3.connect(
            db_path,
            timeout=10.0,
        )
        g.db.row_factory = sqlite3.Row
        # Enforce foreign key constraints on every connection
        g.db.execute("PRAGMA foreign_keys = ON;")
    return g.db


def close_db(e=None):
    """Close the database connection at the end of the request."""
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(app=None):
    """Initialize SQLite database with schema if tables do not exist."""
    db_path = app.config["DATABASE"] if app else get_db_path()
    db_dir = os.path.dirname(os.path.abspath(db_path))
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)

    logger.info("Initializing database at: %s", db_path)
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.executescript(SCHEMA_SQL)
        
        # Safe migration for existing services table
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(services);")
        columns = [row[1] for row in cursor.fetchall()]
        if columns:
            if "is_active" not in columns:
                cursor.execute("ALTER TABLE services ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1;")
            if "last_checked_at" not in columns:
                cursor.execute("ALTER TABLE services ADD COLUMN last_checked_at TIMESTAMP;")
            if "last_response_time" not in columns:
                cursor.execute("ALTER TABLE services ADD COLUMN last_response_time REAL;")
            if "last_status_code" not in columns:
                cursor.execute("ALTER TABLE services ADD COLUMN last_status_code INTEGER;")
            if "consecutive_failures" not in columns:
                cursor.execute("ALTER TABLE services ADD COLUMN consecutive_failures INTEGER NOT NULL DEFAULT 0;")
            if "failure_threshold" not in columns:
                cursor.execute("ALTER TABLE services ADD COLUMN failure_threshold INTEGER NOT NULL DEFAULT 2;")
            if "risk_score" not in columns:
                cursor.execute("ALTER TABLE services ADD COLUMN risk_score INTEGER NOT NULL DEFAULT 0;")
            if "risk_level" not in columns:
                cursor.execute("ALTER TABLE services ADD COLUMN risk_level TEXT NOT NULL DEFAULT 'LOW';")
            
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_services_active ON services(is_active);")

        # Safe migration for monitoring_results table
        cursor.execute("PRAGMA table_info(monitoring_results);")
        mr_columns = [row[1] for row in cursor.fetchall()]
        if mr_columns:
            if "failure_category" not in mr_columns:
                cursor.execute("ALTER TABLE monitoring_results ADD COLUMN failure_category TEXT;")
            if "possible_cause" not in mr_columns:
                cursor.execute("ALTER TABLE monitoring_results ADD COLUMN possible_cause TEXT;")
            if "evidence" not in mr_columns:
                cursor.execute("ALTER TABLE monitoring_results ADD COLUMN evidence TEXT;")
            if "recommended_steps" not in mr_columns:
                cursor.execute("ALTER TABLE monitoring_results ADD COLUMN recommended_steps TEXT;")
            if "confidence" not in mr_columns:
                cursor.execute("ALTER TABLE monitoring_results ADD COLUMN confidence TEXT;")
            if "incident_id" not in mr_columns:
                cursor.execute("ALTER TABLE monitoring_results ADD COLUMN incident_id INTEGER;")

        # Safe migration for incidents table
        cursor.execute("PRAGMA table_info(incidents);")
        inc_columns = [row[1] for row in cursor.fetchall()]
        if inc_columns:
            if "failure_category" not in inc_columns:
                cursor.execute("ALTER TABLE incidents ADD COLUMN failure_category TEXT;")
            if "evidence" not in inc_columns:
                cursor.execute("ALTER TABLE incidents ADD COLUMN evidence TEXT;")
            if "recommended_steps" not in inc_columns:
                cursor.execute("ALTER TABLE incidents ADD COLUMN recommended_steps TEXT;")
            if "confidence" not in inc_columns:
                cursor.execute("ALTER TABLE incidents ADD COLUMN confidence TEXT;")
        
        conn.commit()
        logger.info("Database schema initialized and verified successfully.")
    except Exception as exc:
        logger.error("Failed to initialize database schema: %s", exc)
        raise
    finally:
        conn.close()


def init_app(app):
    """Register database teardown and auto-initialization hooks on the Flask application."""
    app.teardown_appcontext(close_db)
    with app.app_context():
        init_db(app)
