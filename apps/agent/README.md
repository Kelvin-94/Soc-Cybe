# SOC-CyBe Endpoint Agent

Lightweight cross-platform endpoint telemetry agent scaffold for Windows, Linux, and macOS.

Collected telemetry:

- process creation events
- file integrity changes
- network connections
- user login activity
- privilege escalation attempts
- USB device connections

Transport design:

- HTTPS transport intended for TLS 1.3
- bearer-token agent authentication
- JSON telemetry payloads to collector endpoint

Run:

- `python3 agent.py --server https://soc.example/api/v1/ingestion/endpoint --token <agent-token>`
