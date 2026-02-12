"""Request validation and error handling utilities."""
from flask import jsonify

def validate_log(log_data):
    """
    Validate incoming log data.
    Returns (is_valid: bool, error_message: str or None)
    """
    if not isinstance(log_data, dict):
        return False, "Log data must be a JSON object"
    
    if len(log_data) == 0:
        return False, "Log data cannot be empty"
    
    # Check for reasonable size (prevent abuse)
    if len(str(log_data)) > 1_000_000:  # 1MB limit
        return False, "Log data exceeds maximum size (1MB)"
    
    return True, None

def validate_detection_request(data):
    """
    Validate detection request parameters.
    Returns (is_valid: bool, error_message: str or None, cleaned_data: dict)
    """
    if not isinstance(data, dict):
        return False, "Request body must be a JSON object", {}
    
    limit = data.get("limit", None)
    
    # Validate limit if provided
    if limit is not None:
        if not isinstance(limit, int):
            return False, "Limit must be an integer", {}
        if limit < 1 or limit > 50000:
            return False, "Limit must be between 1 and 50000", {}
    
    return True, None, {"limit": limit}

def validate_clear_request(data):
    """
    Validate clear logs request parameters.
    Returns (is_valid: bool, error_message: str or None, cleaned_data: dict)
    """
    if data is None:
        data = {}
    
    if not isinstance(data, dict):
        return False, "Request body must be a JSON object", {}
    
    clear_alerts = data.get("clear_alerts", True)
    
    if not isinstance(clear_alerts, bool):
        return False, "clear_alerts must be a boolean", {}
    
    return True, None, {"clear_alerts": clear_alerts}

def error_response(error_msg, status_code=400):
    """
    Format standardized error response as Flask Response object.
    """
    return jsonify({
        "error": error_msg,
        "status": status_code,
        "success": False
    }), status_code

def success_response(data, message=None):
    """
    Format standardized success response as Flask Response object.
    """
    response = {
        "success": True,
        "data": data
    }
    if message:
        response["message"] = message
    return jsonify(response), 200
