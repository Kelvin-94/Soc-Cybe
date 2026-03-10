"""
SOC-CyBe Security Platform
Module: Ingestion and Enrichment Helpers

Purpose:
This module represents the early processing stages of the SOC pipeline.
It normalizes raw telemetry into a predictable structure and enriches it
with context before detection and correlation run.
"""

from datetime import datetime


def normalize_event(raw_event: dict) -> dict:
    """
    Convert raw telemetry into a normalized event shape used by the platform.

    Normalization is a core SIEM concept because detections become easier to
    write and audit when fields are consistent across log sources.
    """
    return {
        "timestamp": raw_event.get("timestamp") or datetime.utcnow().isoformat(),
        "source_ip": raw_event.get("source_ip") or raw_event.get("ip_address"),
        "destination_ip": raw_event.get("destination_ip"),
        "username": raw_event.get("username"),
        "event_type": raw_event.get("event_type", "unknown"),
        "severity": raw_event.get("severity", "Medium"),
        "device_id": raw_event.get("device_id"),
        "raw": raw_event,
    }


def enrich_event(normalized_event: dict) -> dict:
    """Attach lightweight context that later detection stages can use."""
    enriched = dict(normalized_event)
    enriched["enriched"] = True
    enriched["threat_context"] = {
        "geo": normalized_event.get("source_ip", "unknown"),
        "ingestion_pipeline": "collector -> queue -> processor",
    }
    return enriched
