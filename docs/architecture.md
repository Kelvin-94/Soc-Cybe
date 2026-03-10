# SOC-CyBe Architecture

SOC-CyBe means Security Operations Center - Cyber Behavior Engine.

## Core principles

- Zero Trust: authenticate, authorize, and risk-score every request.
- Defense in depth: layered controls for auth, authorization, rate limiting, validation, logging, and monitoring.
- Modular delivery: frontend, backend, and database are isolated but aligned around shared domain entities.
- Distributed SOC pipeline: `Data Sources -> Ingestion -> Processing -> Detection -> Response -> Visualization`

## System overview

`Data Sources -> Log Ingestion Layer -> Event Processing Engine -> Detection Engine -> Alert & Incident System -> Automation Response Layer -> Security Data Storage -> SOC Dashboard Visualization`

## Data sources layer

- Endpoint telemetry:
  - Windows Event Logs
  - Linux syslogs
  - process execution logs
  - file modification events
  - user login activity
- Network telemetry:
  - firewall traffic
  - DNS queries
  - proxy logs
  - VPN access logs
  - flow records
- Cloud telemetry:
  - AWS CloudTrail
  - Azure Activity Logs
  - GCP audit logs
- Application telemetry:
  - API access logs
  - authentication events
  - database access logs
  - authorization changes
  - privilege modifications

## Ingestion layer

- Intended collector pattern:
  - devices and services
  - log collector agents
  - message queue
  - processing engine
- Integration targets:
  - Kafka
  - RabbitMQ
  - Fluentd
  - Logstash
- Endpoint telemetry agent:
  - cross-platform Python scaffold for Windows, Linux, and macOS
  - process creation, file integrity, network connections, login activity, privilege escalation attempts, and USB connection telemetry
  - TLS 1.3 transport design to collector endpoint

## Backend

- `app/core/security.py`: password hashing, JWT creation, bearer token decoding
- `app/core/rbac.py`: role and permission checks
- `app/core/rate_limit.py`: per-user request throttling
- `app/services/risk_engine.py`: dynamic risk score calculation
- `app/services/zero_trust.py`: request evaluation, anomaly signals, and Zero Trust decisions
- `app/services/threat_monitor.py`: suspicious login detection, alert generation, and threat analysis
- `app/services/incident_response.py`: ticketing, workflow progression, and investigation dashboard metrics
- `app/services/compliance.py`: consent records, retention policies, and compliance reporting
- `app/api/routes.py`: SOC endpoints for dashboards, alerts, incidents, sessions, logs, threat analysis, and compliance review

## Processing and detection

- Processing responsibilities:
  - parse incoming formats
  - normalize event structure
  - enrich events with context and threat intelligence
  - assign initial severity
- Detection modes:
  - rule-based detections for brute force and privilege escalation
  - behavioral detections for location change, API misuse, abnormal request rate, and session anomalies
- Threat intelligence role:
  - identify malicious IPs
  - identify phishing and malware infrastructure
  - elevate detection confidence and severity
- SIEM correlation:
  - multi-event correlation
  - time-based correlation
  - cross-system correlation
  - correlated incident creation for compromise sequences
- Detection rule management:
  - custom rule creation
  - rule activation and deactivation
  - testing sandbox
  - MITRE ATT&CK tactic and technique mapping

## Frontend

- App Router based dashboard
- Role-aware panels for Admin, Analyst, Incident Responder, and Viewer
- Cyber-themed layout with animated terminal background, network activity panels, analytics graphs, alert feed, and monitoring views

## Response and storage

- Alert engine produces analyst-facing alerts and incident candidates
- Incident workflow supports identification, containment, eradication, recovery, and lessons learned
- Case management supports incident-linked investigations, notes, evidence references, and resolution tracking
- Automation layer is structured around SOAR-style actions:
  - lock account
  - block IP
  - isolate endpoint
  - revoke session token
- Security posture monitoring tracks patch status, vulnerable software, inactive controls, and unsecured services
- Red team simulation validates detection coverage for brute force, phishing, privilege escalation, and exfiltration-style scenarios
- Storage model:
  - hot storage for fast investigation
  - cold storage for compliance retention

## Multi-tenant model

- Tenant entity and tenant-scoped operational data
- Tenant-specific rules, threat intelligence, cases, playbooks, posture snapshots, simulations, and correlations
- Tenant-specific dashboard and policy foundations through authenticated tenant context

## Compliance mapping

- GDPR / POPIA / CCPA: consent logging, minimization, deletion workflow hooks
- ISO 27001 / NIST CSF: governance, protective controls, detection, response, and auditability
- OWASP: validated inputs, secure auth defaults, least privilege

## MVP scope

The current MVP focuses on:

- API security monitoring
- user risk scoring
- authentication anomaly detection
- incident dashboard
- audit log monitoring

This keeps the initial platform realistic while leaving enterprise-scale ingestion and intelligence feed expansion for later iterations.
