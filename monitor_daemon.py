"""Dedicated Background Monitoring Daemon for Distributed Status Tracker.

Periodically queries SQLite for due services, performs safe HTTP checks,
updates status, and records results into monitoring_results.
Guards against duplicate worker processes using a file-based lock.
"""

import os
import sys
import time
import signal
import sqlite3
import threading
import logging
from dotenv import load_dotenv

import monitor
import database

# Load environment configuration
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [MONITOR-DAEMON] [%(levelname)s]: %(message)s",
)
logger = logging.getLogger("monitor_daemon")

RUNNING = True
LOCK_FILE = os.path.join("instance", "monitor_daemon.lock")


def acquire_process_lock() -> bool:
    """Ensure only one instance of the background monitoring daemon runs."""
    os.makedirs("instance", exist_ok=True)
    if os.path.exists(LOCK_FILE):
        try:
            with open(LOCK_FILE, "r") as f:
                content = f.read().strip()
                if content:
                    existing_pid = int(content)
                    # Check if process with PID is alive on Windows/Unix
                    if is_pid_alive(existing_pid):
                        logger.warning(
                            "Another monitor daemon process is already running (PID: %s). Exiting.",
                            existing_pid,
                        )
                        return False
        except Exception:
            # Stale or corrupt lock file; proceed to acquire
            pass

    # Write current PID
    try:
        with open(LOCK_FILE, "w") as f:
            f.write(str(os.getpid()))
        return True
    except Exception as e:
        logger.error("Failed to acquire process lock: %s", e)
        return False


def release_process_lock():
    """Release the daemon lock file upon exit."""
    if os.path.exists(LOCK_FILE):
        should_remove = False
        try:
            with open(LOCK_FILE, "r") as f:
                content = f.read().strip()
                if content and int(content) == os.getpid():
                    should_remove = True
        except Exception:
            pass

        if should_remove:
            try:
                os.remove(LOCK_FILE)
            except Exception:
                pass


def is_pid_alive(pid: int) -> bool:
    """Check if process with PID exists and is running."""
    if pid <= 0:
        return False
    if sys.platform == "win32":
        import ctypes
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return False
        exit_code = ctypes.c_ulong()
        success = ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))
        ctypes.windll.kernel32.CloseHandle(handle)
        return bool(success and exit_code.value == 259)
    else:
        try:
            os.kill(pid, 0)
            return True
        except (OSError, PermissionError):
            return False


def sig_handler(signum, frame):
    """Handle graceful shutdown signals."""
    global RUNNING
    logger.info("Termination signal received. Gracefully shutting down...")
    RUNNING = False


def run_daemon(poll_interval: float = 3.0, db_path: str = None):
    """Main loop for background monitoring."""
    global RUNNING

    if not acquire_process_lock():
        sys.exit(1)

    if threading.current_thread() is threading.main_thread():
        try:
            signal.signal(signal.SIGINT, sig_handler)
            signal.signal(signal.SIGTERM, sig_handler)
        except (ValueError, AttributeError):
            pass

    if not db_path:
        db_path = os.getenv("DATABASE_PATH", os.path.join("instance", "status_tracker.db"))

    logger.info("Starting monitoring engine against database: %s", db_path)

    # Active checking tracker to avoid overlapping checks for same service
    in_flight_services = set()

    try:
        while RUNNING:
            try:
                # Open isolated connection for this tick
                conn = sqlite3.connect(db_path, timeout=10.0)
                conn.row_factory = sqlite3.Row
                conn.execute("PRAGMA foreign_keys = ON;")

                due_services = monitor.get_due_services(conn)

                if due_services:
                    logger.info("Found %d service(s) due for monitoring check.", len(due_services))

                for svc in due_services:
                    if not RUNNING:
                        break

                    svc_id = svc["id"]
                    if svc_id in in_flight_services:
                        continue

                    in_flight_services.add(svc_id)
                    try:
                        monitor.check_single_service(svc, conn)
                    except Exception as err:
                        logger.error("Error monitoring service #%s: %s", svc_id, err)
                    finally:
                        in_flight_services.discard(svc_id)

                conn.close()

            except Exception as loop_err:
                logger.error("Error during monitoring loop tick: %s", loop_err)

            # Sleep in small increments for responsive termination
            for _ in range(int(poll_interval * 10)):
                if not RUNNING:
                    break
                time.sleep(0.1)

    finally:
        release_process_lock()
        logger.info("Monitoring daemon stopped.")


if __name__ == "__main__":
    run_daemon()
