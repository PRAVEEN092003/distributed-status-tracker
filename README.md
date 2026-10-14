# Distributed Status Tracker
### Website Monitoring, Root Cause Analysis & Downtime Risk Prediction

## 📌 Project Overview

Distributed Status Tracker is a web-based website and API monitoring application developed to monitor endpoint availability, track response times, detect service failures, identify probable root causes, and assess downtime risks.

The application continuously monitors registered endpoints using an automated background monitoring engine. It records monitoring results, classifies failures, maintains incident records, and provides a centralized dashboard for service health visibility.

The system also includes a rule-based downtime risk assessment engine that evaluates historical monitoring data to calculate risk scores and identify services that may require attention.

## 🎯 Objectives

- Monitor multiple websites and HTTP endpoints.
- Detect service availability issues and performance degradation.
- Record response times and HTTP status codes.
- Identify probable causes of monitoring failures.
- Calculate downtime risk scores using historical monitoring data.
- Maintain incident records and track service recovery.
- Provide a centralized dashboard for monitoring and diagnostics.
- Implement secure user authentication and user-specific data isolation.

## ✨ Key Features

### 1. Website & API Monitoring
- Register and manage website endpoints.
- Perform manual health checks.
- Automatically monitor active endpoints using a background worker.
- Configure monitoring intervals and request timeouts.
- Pause, resume, edit, and delete monitored endpoints.
- Track service availability and response times.

### 2. Service Health Classification

The monitoring engine classifies endpoint health into three categories:

- **UP:** The endpoint responds within the configured acceptable conditions.
- **DEGRADED:** The endpoint exhibits high latency or other configured warning conditions.
- **DOWN:** The endpoint is unreachable or experiences a qualifying failure.

### 3. Smart Failure Detection & Root Cause Analysis

The Root Cause Analysis (RCA) engine identifies and classifies common monitoring failures, including:

- DNS resolution failures
- Connection timeouts
- Connection refused errors
- SSL/TLS errors
- Network failures
- HTTP 4xx errors
- HTTP 5xx errors
- Slow response times
- Redirect or configuration issues
- Unknown failures

For detected failures, the system provides diagnostic information, probable causes, confidence levels, and recommended troubleshooting steps.

### 4. Downtime Risk Prediction

The rule-based risk assessment engine calculates a risk score between 0 and 100 using historical monitoring information.

Risk classifications:

- **LOW:** 0–29
- **MEDIUM:** 30–59
- **HIGH:** 60–100

Risk assessment considers factors such as consecutive failures, historical failure frequency, latency changes, incident activity, and service stability.

The dashboard displays risk scores, contributing factors, latency trends, and recommended preventive actions.

*Note: Risk scores are rule-based estimates derived from monitoring data. They are not guaranteed predictions of future outages.*

### 5. Incident Management & Recovery Tracking

- Create incidents when qualifying consecutive failures meet the configured threshold.
- Associate incidents with affected endpoints.
- Record failure categories and probable root causes.
- Track incident start times and ongoing downtime.
- Prevent duplicate active incidents for the same service according to the incident policy.
- Track recovery and resolve incidents after successful recovery detection.

### 6. Monitoring History & Telemetry

The application maintains historical monitoring records containing relevant information such as:

- Timestamp
- Endpoint
- Service status
- Response time
- HTTP status code
- Failure classification
- Diagnostic information

Users can review previous monitoring results and investigate service availability issues.

### 7. Dashboard & Visualization

The dashboard provides a centralized view of:

- Total monitored websites
- UP, DEGRADED, and DOWN service counts
- Response-time trends
- Active outage alerts
- Recent monitoring results
- Downtime risk assessments
- Links to incident diagnostics and monitoring history

### 8. Authentication & Security

- User registration and login.
- Secure password hashing.
- Session-based authentication.
- CSRF protection.
- User-specific data isolation.
- URL validation and SSRF protections for monitored endpoints.
- Environment-based configuration for sensitive settings.

## 🛠️ Technology Stack

### Frontend
- HTML5
- CSS3
- Vanilla JavaScript
- Chart.js

### Backend
- Python
- Flask
- Python Requests

### Database
- SQLite

### Security
- Werkzeug password hashing
- Session-based authentication
- CSRF protection
- Server-Side Request Forgery (SSRF) protections

### Development Tools
- Visual Studio Code / Antigravity IDE
- Python Virtual Environment
- Git

## 🏗️ System Architecture

The application follows a modular web architecture.

```text
                 User / Browser
                       |
                       v
              HTML, CSS, JavaScript
                       |
                       v
                 Flask Application
                       |
          +------------+------------+
          |            |            |
          v            v            v
    Authentication   Monitoring   Risk Assessment
          |          & RCA Engine       |
          |            |                |
          +------------+----------------+
                       |
                       v
                  SQLite Database
                       ^
                       |
              Background Monitoring
                     Worker
                       |
                       v
                Website / API
                  Endpoints
```

The Flask application handles user interactions and dashboard requests. The monitoring worker performs scheduled endpoint checks and records the results in SQLite. The RCA and risk assessment components use monitoring information to generate diagnostics and risk indicators.

## ⚙️ Installation & Setup

### Prerequisites

Ensure the following are installed:

- Python 3.10 or later
- pip
- Windows PowerShell or a compatible terminal

### Step 1: Open the Project Directory

Open a terminal and navigate to the project folder.

```powershell
cd "C:\Users\Sys\Desktop\Distributed Status Tracker"
```

### Step 2: Activate the Virtual Environment

If the project already contains a virtual environment:

```powershell
.\venv\Scripts\Activate.ps1
```

If a virtual environment has not been created, create one first:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### Step 3: Install Dependencies

```powershell
pip install -r requirements.txt
```

### Step 4: Configure Environment Variables

Create a `.env` file using the project's `.env.example` as a reference.

Configure the required application settings according to the existing project configuration.

Do not expose secret keys or other sensitive configuration values.

### Step 5: Start the Flask Application

Open the first terminal:

```powershell
python app.py
```

Open the application in your browser:

http://127.0.0.1:5000

### Step 6: Start the Monitoring Worker

Open a second terminal:

```powershell
cd "C:\Users\Sys\Desktop\Distributed Status Tracker"
.\venv\Scripts\Activate.ps1
python monitor_daemon.py
```

Keep the Flask application and monitoring worker running in their respective terminals for continuous monitoring.

The database is initialized automatically during application startup if supported by the current application configuration.

## 🚀 Usage

1. Start the Flask application and monitoring worker.
2. Register an account and log in.
3. Open the Websites page.
4. Add a website or API endpoint.
5. Configure the monitoring interval and timeout.
6. Use the manual Check action to initiate a health check.
7. Review the endpoint's status and response time.
8. Open Monitoring History to inspect historical results.
9. Review failure diagnostics and probable causes when an endpoint becomes unavailable.
10. Open Incidents to inspect recorded outages and recovery information.
11. Review downtime risk scores and contributing factors on the dashboard or website details page.

## 🧪 Testing

The project includes automated unit and integration tests covering its principal components.

The final project verification report records the following test results:

```text
Ran 31 tests in 12.208s

OK
```

The reported test coverage includes:

- Authentication and data isolation
- Endpoint registration and validation
- SSRF protection
- Monitoring status classification
- Background worker locking
- Root Cause Analysis
- Incident creation and recovery tracking
- Downtime risk scoring
- Latency trend detection
- Risk API endpoints

To execute the test suite:

```powershell
python -m unittest discover tests/
```

*The test results above are from the project's final verification report.*

## 🔒 Security Considerations

The application incorporates security measures intended to protect user accounts, stored data, and monitored infrastructure.

These include password hashing, CSRF protection, user-specific data isolation, URL validation, and SSRF protections.

The monitoring system must reject prohibited internal destinations and unsafe endpoint configurations according to its security policy.

Environment variables should be used for sensitive configuration, and `.env` files should not be included in project submissions.

## 📈 Future Enhancements

Potential future improvements include:

- Email notifications for critical outages.
- Exportable monitoring and incident reports.
- Additional monitoring visualizations.
- Configurable alert thresholds.
- Extended performance analytics.
- Additional monitoring integrations.

These are possible future enhancements and are not claimed as implemented features.

## 🎓 Project Information

**Project Title:** Distributed Status Tracker

**Project Category:** Web Application / Website Monitoring System

**Primary Domain:** Web Monitoring, Network Diagnostics, and Reliability Engineering

**Development Type:** Academic / Internship Project

**Purpose:** To monitor website availability, diagnose service failures, assess downtime risks, and maintain incident and recovery records through a centralized web application.

## 👨‍💻 Conclusion

Distributed Status Tracker provides a centralized solution for website and API availability monitoring, historical telemetry collection, failure diagnosis, downtime risk assessment, and incident management.

By combining Flask-based web development, automated HTTP monitoring, SQLite persistence, rule-based risk analysis, and Root Cause Analysis, the project demonstrates practical application development and service reliability monitoring concepts.