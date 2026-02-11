from mitigation.actions import take_action


def classify_threat(threat_score: float) -> str:
    if threat_score < 0.4:
        return "Normal"
    elif threat_score < 0.7:
        return "Suspicious"
    else:
        return "Attack"


def mitigate(label: str, source_ip: str) -> str:
    """Convenience wrapper: classify + act in one call."""
    return take_action(label, source_ip)
