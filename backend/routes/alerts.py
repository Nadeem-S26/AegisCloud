from flask import Blueprint, jsonify
from services.db_service import alerts_collection

alerts_bp = Blueprint("alerts", __name__)

@alerts_bp.route("/alerts", methods=["GET"])
def get_alerts():
    alerts = list(alerts_collection.find({}, {"_id": 0}))
    return jsonify(alerts)

@alerts_bp.route("/alerts/clear", methods=["POST"])
def clear_alerts():
    alerts_collection.delete_many({})
    return jsonify({"message": "All alerts cleared"})

@alerts_bp.route("/stats", methods=["GET"])
def get_stats():
    """Return dashboard statistics from the database."""
    total_alerts = alerts_collection.count_documents({})
    attacks = alerts_collection.count_documents({"threat_label": "Attack"})
    suspicious = alerts_collection.count_documents({"threat_label": "Suspicious"})
    normal = alerts_collection.count_documents({"threat_label": "Normal"})

    blocked = alerts_collection.count_documents({"action_taken": "IP Blocked"})

    # Health score: 100% if no attacks, lower as attacks increase
    if total_alerts > 0:
        health = max(0, round(100 - (attacks / total_alerts * 100)))
    else:
        health = 100

    return jsonify({
        "total_alerts": total_alerts,
        "attacks": attacks,
        "suspicious": suspicious,
        "normal": normal,
        "blocked": blocked,
        "health_score": health,
    })
