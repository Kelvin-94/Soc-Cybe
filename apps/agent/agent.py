"""
SOC-CyBe Security Platform
Module: Endpoint Telemetry Agent

Purpose:
This lightweight agent demonstrates how endpoint telemetry can be collected
from Windows, Linux, and macOS devices and forwarded to the SOC-CyBe
ingestion layer over a secure channel.

Security Considerations:
- TLS 1.3 is required for transport to protect telemetry in transit.
- The agent authenticates with a bearer token so collectors can reject
  unauthenticated devices.
- This MVP sends sample telemetry only; production agents would use
  platform-native collection APIs and local buffering.

Related Components:
- `apps/backend/app/api/routes.py` ingestion endpoints
- `apps/backend/app/services/ingestion.py` normalization and enrichment
"""

import argparse
import json
import platform
import ssl
import time
import urllib.request
from datetime import datetime


def collect_sample_telemetry() -> list[dict]:
    """
    Build a small cross-platform sample telemetry set.

    The goal here is clarity rather than deep OS integration. It shows the
    shape of data the collectors expect without introducing platform-specific
    dependencies into the starter project.
    """
    system = platform.system()
    return [
        {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": "process_creation",
            "device_id": f"{system.lower()}-agent",
            "source_type": "endpoint",
            "username": "local-user",
            "process_name": "python3",
            "os": system,
        },
        {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": "user_login_activity",
            "device_id": f"{system.lower()}-agent",
            "source_type": "endpoint",
            "username": "local-user",
            "os": system,
        },
    ]


def send_events(server: str, token: str, events: list[dict]) -> None:
    """
    Send telemetry to the configured collector endpoint over HTTPS.

    TLS 1.3 is enforced at the SSL context level to match the platform's
    transport-security requirement.
    """
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    for event in events:
        payload = json.dumps({"source_type": "endpoint", "payload": event}).encode("utf-8")
        request = urllib.request.Request(
            server,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}",
                "User-Agent": "soc-cybe-endpoint-agent/0.1",
            },
            method="POST",
        )
        with urllib.request.urlopen(request, context=context, timeout=10) as response:
            response.read()


def main() -> None:
    """Run the agent loop and periodically forward telemetry samples."""
    parser = argparse.ArgumentParser(description="SOC-CyBe endpoint telemetry agent")
    parser.add_argument("--server", required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--interval", type=int, default=30)
    args = parser.parse_args()

    while True:
        send_events(args.server, args.token, collect_sample_telemetry())
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
