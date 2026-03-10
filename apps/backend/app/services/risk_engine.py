"""
SOC-CyBe Security Platform
Module: Risk Scoring Engine

Purpose:
This service converts identity, device, and behavior signals into a bounded
risk score used by Zero Trust decision-making.

Security Considerations:
- Risk scoring is intentionally transparent so analysts can explain why access
  was allowed, challenged, or denied.
- The score is not a replacement for authorization; it is an additional layer
  that helps detect abuse of otherwise valid accounts.
"""

def calculate_risk_score(
    *,
    failed_logins: int,
    ip_reputation: int,
    device_trust: int,
    privilege_changes: int,
) -> int:
    """
    Calculate a bounded user risk score from core identity and behavior inputs.

    The formula is intentionally simple for the MVP so developers and auditors
    can understand why a given score was produced.
    """
    score = 20
    score += failed_logins * 7
    score += max(0, 100 - ip_reputation) // 4
    score += max(0, 100 - device_trust) // 3
    score += privilege_changes * 12
    return max(0, min(score, 100))


def evaluate_request_risk(
    *,
    base_risk_score: int,
    device_trust: int,
    new_ip: bool,
    session_age_minutes: int,
    sensitive_action: bool,
    anomaly_flags: int,
    privilege_escalation_signal: bool,
) -> tuple[int, str]:
    """
    Turn request-specific context into a Zero Trust access decision.

    The function returns both the final score and an access decision so the
    caller can log the reasoning and apply policy consistently.
    """
    score = base_risk_score
    if new_ip:
        score += 14
    if session_age_minutes > 720:
        score += 8
    if sensitive_action:
        score += 12
    score += anomaly_flags * 11
    score += max(0, 100 - device_trust) // 5
    if privilege_escalation_signal:
        score += 18
    score = max(0, min(score, 100))
    if score >= 80:
        return score, "deny"
    if score >= 55:
        return score, "step-up-authentication"
    return score, "allow"
