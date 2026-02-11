from flask import Blueprint, request, jsonify
from services.db_service import logs_collection, alerts_collection

logs_bp = Blueprint("logs", __name__)

@logs_bp.route("/logs", methods=["POST"])
def add_log():
    log = request.json
    logs_collection.insert_one(log)
    return jsonify({"message": "Log stored"})

@logs_bp.route("/logs", methods=["GET"])
def get_logs():
    # Return only the most recent 100 logs for performance (instead of all 24k+)
    logs = logs_collection.find({}, {"_id": 0}, limit=100)
    return jsonify(logs)

@logs_bp.route("/logs/count", methods=["GET"])
def get_log_count():
    count = logs_collection.count_documents({})
    return jsonify({"count": count})


@logs_bp.route("/logs/clear", methods=["POST"])
def clear_logs():
    """Delete all logs; optionally clear alerts too."""
    data = request.get_json(silent=True) or {}
    clear_alerts = data.get("clear_alerts", True)

    logs_collection.delete_many({})
    if clear_alerts:
        alerts_collection.delete_many({})

    return jsonify({
        "message": "All logs cleared",
        "alerts_cleared": bool(clear_alerts)
    })
