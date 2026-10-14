# Distributed Status Tracker

A web-based monitoring application for tracking website availability, identifying service failures, analyzing root causes, and assessing downtime risks.

## Overview

Distributed Status Tracker provides a centralized dashboard for monitoring multiple websites and HTTP endpoints. It automatically checks endpoint availability, records response times, identifies failures, and maintains historical monitoring records.

The application includes a Root Cause Analysis (RCA) engine to classify monitoring failures and a rule-based risk assessment engine to evaluate potential downtime risks using historical monitoring data.

It also provides incident tracking, recovery monitoring, and visual representations of service health and performance.

## Features

### Website & API Monitoring
- Monitor multiple websites and HTTP endpoints.
- Perform manual health checks.
- Automatically monitor active endpoints using a background worker.
- Configure monitoring intervals and request timeouts.
- Track response times and HTTP status codes.
- Manage monitored websites through the dashboard.

### Service Health Detection
Endpoints are classified into three health states:

- **UP** — The endpoint is responding within the configured acceptable conditions.
- **DEGRADED** — The endpoint exhibits performance issues or configured warning conditions.
- **DOWN** — The endpoint is unreachable or experiences a qualifying failure.

### Root Cause Analysis
The diagnostic engine identifies and classifies common monitoring failures, including:

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

For detected failures, the application provides probable causes, diagnostic confidence, and troubleshooting recommendations.

### Downtime Risk Assessment
The rule-based risk engine calculates a score from 0 to 100 using historical monitoring information.

| Risk Level | Score |
|---|---:|
| LOW | 0–29 |
| MEDIUM | 30–59 |
| HIGH | 60–100 |

Risk assessment considers consecutive failures, failure frequency, latency trends, active incidents, and historical stability.

Risk scores are estimates based on configured rules and historical observations. They do not guarantee that a future outage will occur.

### Incident Management
- Create incidents when configured failure thresholds are reached.
- Record incident start times and failure diagnostics.
- Track ongoing outages and downtime duration.
- Prevent duplicate active incidents according to the incident policy.
- Track service recovery and resolve incidents after successful recovery detection.

### Monitoring History
- Store historical monitoring results.
- Review service status and response times.
- Inspect HTTP status codes and failure classifications.
- Review diagnostic information associated with monitoring checks.

### Dashboard & Visualization
The dashboard provides an overview of:

- Total monitored websites
- UP, DEGRADED, and DOWN service counts
- Response-time trends
- Active incidents and outage alerts
- Recent monitoring activity
- Downtime risk scores
- Service diagnostics

### Authentication & Security
- User registration and login
- Secure password hashing
- Session-based authentication
- CSRF protection
- User-specific data isolation
- URL validation
- Server-Side Request Forgery (SSRF) protections

## Technology Stack

| Component | Technology |
|---|---|
| Frontend | HTML5, CSS3, Vanilla JavaScript |
| Backend | Python, Flask |
| Database | SQLite |
| HTTP Monitoring | Python Requests |
| Charts | Chart.js |
| Authentication | Flask sessions, Werkzeug password hashing |

## Project Structure

```text
Distributed Status Tracker/
│
├── app.py
├── database.py
├── monitor.py
├── monitor_daemon.py
├── validator.py
├── rca_engine.py
├── risk_engine.py
│
├── templates/
│   ├── base.html
│   ├── dashboard.html
│   ├── websites.html
│   ├── website_detail.html
│   ├── history.html
│   ├── incidents.html
│   └── incident_detail.html
│
├── static/
│   ├── css/
│   └── js/
│
├── tests/
├── instance/
├── .env.example
├── .gitignore
├── requirements.txt
└── README.md
```

*The exact template and static file contents may vary with the current implementation.*

## Installation

### Prerequisites

- Python 3.10 or later
- pip
- Windows PowerShell or a compatible terminal

### 1. Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/distributed-status-tracker.git
cd distributed-status-tracker
```

Replace `YOUR_USERNAME` with your GitHub username.

### 2. Create a Virtual Environment

```powershell
python -m venv venv
```

Activate it:

```powershell
.\venv\Scripts\Activate.ps1
```

### 3. Install Dependencies

```powershell
pip install -r requirements.txt
```

### 4. Configure Environment Variables

Create a `.env` file using `.env.example` as a reference.

Configure the required environment variables according to the application settings.

Do not commit `.env` files, passwords, or secret keys to the repository.

### 5. Start the Application

```powershell
python app.py
```

Open the application in your browser:

**http://127.0.0.1:5000**

### 6. Background Monitoring

The application includes a background monitoring worker.

When using the integrated worker started by `app.py`, keep the application running to maintain monitoring.

If running the standalone worker separately, follow the project's configured daemon startup procedure to avoid starting duplicate monitoring workers.

## Usage

1. Register an account and log in.
2. Open the Websites page.
3. Add a website or API endpoint.
4. Configure its monitoring settings.
5. Perform a manual health check or allow scheduled monitoring to run.
6. Review service status and response times.
7. Inspect monitoring history for previous results.
8. Review diagnostic information when a failure occurs.
9. Open the Incidents page to inspect outages and recovery information.
10. Review risk scores and contributing factors to assess service stability.

## Testing

The project contains automated tests covering authentication, monitoring, URL security validation, failure classification, incident handling, and risk assessment.

The final verification report recorded the following result:

```text
Ran 31 tests in 12.208s

OK
```

To run the test suite:

```powershell
python -m unittest discover tests/
```

## Security Considerations

The application incorporates URL validation and SSRF protections for monitored endpoints.

It is designed to prevent requests to prohibited internal destinations, including restricted private and loopback addresses, according to the configured security policy.

Keep environment variables and sensitive configuration outside the public repository.

## Future Improvements

Potential future enhancements include:

- Email notifications for critical outages
- Exportable monitoring reports
- Additional performance analytics
- Configurable alert thresholds
- Extended monitoring integrations

These are potential enhancements and are not represented as existing features.

## Project Information

**Project Name:** Distributed Status Tracker

**Category:** Web Application / Website Monitoring

**Primary Focus:** Website Availability, Root Cause Analysis, Downtime Risk Assessment, and Incident Management

**Development Type:** Academic / Internship Project

## Conclusion

Distributed Status Tracker combines automated website monitoring, historical telemetry, failure diagnosis, rule-based downtime risk assessment, and incident management in a centralized web application.

The project demonstrates practical implementation of Python web development, HTTP monitoring, database management, application security, and service reliability concepts.
