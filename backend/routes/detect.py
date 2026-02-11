from flask import Blueprint, jsonify
from services.db_service import logs_collection, alerts_collection
from services.ml_service import predict_log
from mitigation.actions import take_action
from mitigation.logger import log_event

detect_bp = Blueprint("detect", __name__)

@detect_bp.route("/detect", methods=["POST"])
def detect():
    """
    Analyze all logs in database with ML threat detection.
    Returns detailed results for EVERY analyzed event.
    """
    logs = list(logs_collection.find())

    if not logs:
        return jsonify([])

    alerts = []
    analyzed_events = []

    for log in logs:
        # Extract log data (exclude MongoDB _id)
        log_dict = {k: v for k, v in log.items() if k != "_id"}
        log_id = str(log.get("_id", "unknown"))

        # Run ML threat detection on this log
        label, score = predict_log(log_dict)
        
        # Extract source IP from various possible field names
        source_ip = (log.get("source_ip") or 
                     log.get("Source IP") or 
                     log.get("Src IP") or 
                     "unknown")
        
        # Determine action to take based on threat level
        action = take_action(label, source_ip)

        # Create alert record
        alert = log_event(
            log_id=log_id,
            threat_score=score,
            threat_label=label,
            action_taken=action,
            source_ip=source_ip,
        )

        # Store alert in database
        alerts_collection.insert_one(alert.copy())
        alerts.append(alert)
        
        # Add detailed analysis result for frontend display
        analyzed_events.append({
            "log_id": log_id,
            "source_ip": str(source_ip),
            "threat_label": label,
            "threat_score": round(float(score), 4),
            "action_taken": action,
            "timestamp": alert.get("timestamp"),
            "analyzed": True
        })

    # Return all analyzed events with threat classifications
    return jsonify(analyzed_events)
