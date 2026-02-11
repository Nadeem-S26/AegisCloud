def take_action(threat_label: str, source_ip: str) -> str:
    if threat_label == "Normal":
        return "No action required"
    elif threat_label == "Suspicious":
        return "Alert"
    elif threat_label == "Attack":
        return "IP Blocked"
    else:
        return "Unknown"
