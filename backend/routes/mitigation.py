from flask import Blueprint, jsonify
import logging

from services.db_service import ip_threats_collection

logger = logging.getLogger(__name__)

mitigation_bp = Blueprint('mitigation', __name__, url_prefix='/api/mitigation')


@mitigation_bp.route('/ips', methods=['GET'])
def get_tracked_ips():
    """
    Get all tracked IP addresses with their threat escalation status.
    
    Returns:
    {
        "success": true,
        "data": [
            {
                "source_ip": "192.168.1.100",
                "threat_count": 5,
                "escalation_level": 2,
                "escalation_status": "Blocked",
                "first_incident": "2026-02-12T14:10:23",
                "last_incident": "2026-02-12T14:25:45"
            },
            ...
        ]
    }
    """
    try:
        tracked_ips = ip_threats_collection.find_all()
        
        # Enhance with escalation status labels
        enhanced_data = []
        for ip_record in tracked_ips:
            enhanced_data.append({
                "source_ip": ip_record["source_ip"],
                "threat_count": ip_record["threat_count"],
                "escalation_level": ip_record["escalation_level"],
                "escalation_status": ip_threats_collection.get_escalation_action(ip_record["escalation_level"]),
                "first_incident": ip_record["first_incident"],
                "last_incident": ip_record["last_incident"]
            })
        
        return jsonify({
            "success": True,
            "data": enhanced_data,
            "total": len(enhanced_data)
        }), 200
    except Exception as e:
        logger.error(f"Error fetching tracked IPs: {str(e)}")
        return jsonify({"error": "Failed to fetch tracked IPs", "success": False}), 500


@mitigation_bp.route('/ips/<source_ip>', methods=['GET'])
def get_ip_threat_status(source_ip: str):
    """
    Get threat escalation status for a specific IP address.
    
    Parameters:
        source_ip: IP address to query
    
    Returns:
    {
        "success": true,
        "data": {
            "source_ip": "192.168.1.100",
            "threat_count": 5,
            "escalation_level": 2,
            "escalation_status": "Blocked",
            "first_incident": "2026-02-12T14:10:23",
            "last_incident": "2026-02-12T14:25:45"
        }
    }
    """
    try:
        ip_record = ip_threats_collection.find_by_ip(source_ip)
        
        if not ip_record:
            return jsonify({
                "success": False,
                "error": f"No threat data for IP {source_ip}"
            }), 404
        
        enhanced_data = {
            "source_ip": ip_record["source_ip"],
            "threat_count": ip_record["threat_count"],
            "escalation_level": ip_record["escalation_level"],
            "escalation_status": ip_threats_collection.get_escalation_action(ip_record["escalation_level"]),
            "first_incident": ip_record["first_incident"],
            "last_incident": ip_record["last_incident"]
        }
        
        return jsonify({
            "success": True,
            "data": enhanced_data
        }), 200
    except Exception as e:
        logger.error(f"Error fetching IP threat status: {str(e)}")
        return jsonify({"error": "Failed to fetch IP threat status", "success": False}), 500


@mitigation_bp.route('/ips/blocked', methods=['GET'])
def get_blocked_ips():
    """
    Get all IPs that have reached 'Blocked' status (escalation_level >= 2).
    
    Returns:
    {
        "success": true,
        "data": [
            {
                "source_ip": "192.168.1.100",
                "threat_count": 5,
                "escalation_level": 2,
                "escalation_status": "Blocked",
                "first_incident": "2026-02-12T14:10:23",
                "last_incident": "2026-02-12T14:25:45"
            },
            ...
        ],
        "total": 3
    }
    """
    try:
        blocked_ips = ip_threats_collection.find_all(min_escalation_level=2)
        
        enhanced_data = []
        for ip_record in blocked_ips:
            enhanced_data.append({
                "source_ip": ip_record["source_ip"],
                "threat_count": ip_record["threat_count"],
                "escalation_level": ip_record["escalation_level"],
                "escalation_status": "Blocked",
                "first_incident": ip_record["first_incident"],
                "last_incident": ip_record["last_incident"]
            })
        
        return jsonify({
            "success": True,
            "data": enhanced_data,
            "total": len(enhanced_data)
        }), 200
    except Exception as e:
        logger.error(f"Error fetching blocked IPs: {str(e)}")
        return jsonify({"error": "Failed to fetch blocked IPs", "success": False}), 500


@mitigation_bp.route('/stats', methods=['GET'])
def get_mitigation_stats():
    """
    Get aggregated mitigation statistics.
    
    Returns:
    {
        "success": true,
        "data": {
            "total_tracked_ips": 10,
            "warning_level": 3,
            "alert_level": 4,
            "blocked_level": 3
        }
    }
    """
    try:
        all_ips = ip_threats_collection.find_all()
        blocked_ips = ip_threats_collection.find_all(min_escalation_level=2)
        alert_ips = ip_threats_collection.find_all(min_escalation_level=1)
        
        # Count IPs at each level
        blocked_count = len(blocked_ips)
        alert_count = len(alert_ips) - blocked_count  # Alert but not blocked
        warning_count = len(all_ips) - len(alert_ips)  # Warning level
        
        return jsonify({
            "success": True,
            "data": {
                "total_tracked_ips": len(all_ips),
                "warning_level": warning_count,
                "alert_level": alert_count,
                "blocked_level": blocked_count
            }
        }), 200
    except Exception as e:
        logger.error(f"Error fetching mitigation stats: {str(e)}")
        return jsonify({"error": "Failed to fetch mitigation stats", "success": False}), 500
