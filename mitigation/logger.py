from datetime import datetime

def log_event(log_id, threat_score, threat_label, action_taken, source_ip):
    return {
        "log_id": log_id,
        "timestamp": datetime.utcnow().isoformat(),
        "source_ip": source_ip,
        "threat_score": threat_score,
        "threat_label": threat_label,
        "action_taken": action_taken
    }
