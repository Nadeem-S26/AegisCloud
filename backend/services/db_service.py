import sqlite3
import json
import os
from datetime import datetime
from threading import Lock

# Get the database path from config
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "db_config.json")
with open(CONFIG_PATH, "r") as f:
    config = json.load(f)

DB_PATH = config.get("database_path", "./aegis_cloud.db")
# Resolve relative paths to the backend directory
if not os.path.isabs(DB_PATH):
    DB_PATH = os.path.join(os.path.dirname(__file__), "..", DB_PATH)

# Thread-safe database connection
_db_lock = Lock()

def get_db_connection():
    """Get a thread-safe database connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # Allow dict-like access
    return conn

def init_db():
    """Initialize the SQLite database with required tables."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Create logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                data TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create alerts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                log_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                threat_score REAL NOT NULL,
                threat_label TEXT NOT NULL,
                action_taken TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        print("✅ SQLite database initialized successfully")
    except Exception as e:
        print(f"❌ Error initializing database: {e}")
    finally:
        conn.close()

# Initialize database on import
init_db()

# ════════════════════════════════════════════════════════════
# Logs Collection (dict-like MongoDB interface for compatibility)
# ════════════════════════════════════════════════════════════

class LogsCollection:
    def insert_one(self, log_dict):
        """Insert a single log record."""
        with _db_lock:
            conn = get_db_connection()
            cursor = conn.cursor()
            try:
                log_json = json.dumps(log_dict)
                cursor.execute(
                    "INSERT INTO logs (data) VALUES (?)",
                    (log_json,)
                )
                conn.commit()
                log_dict["_id"] = cursor.lastrowid
            finally:
                conn.close()
    
    def find(self, query=None, projection=None, limit=None):
        """Find logs matching the query. Optionally limit results."""
        with _db_lock:
            conn = get_db_connection()
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT id, data FROM logs ORDER BY created_at DESC")
                rows = cursor.fetchall()
                
                results = []
                for row in rows:
                    log_data = json.loads(row[1])
                    log_data["_id"] = row[0]
                    results.append(log_data)
                
                # Apply limit if specified
                if limit:
                    results = results[:limit]
                
                return results
            finally:
                conn.close()
    
    def count_documents(self, query=None):
        """Count total logs."""
        with _db_lock:
            conn = get_db_connection()
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT COUNT(*) FROM logs")
                return cursor.fetchone()[0]
            finally:
                conn.close()
    
    def delete_many(self, query=None):
        """Delete all logs."""
        with _db_lock:
            conn = get_db_connection()
            cursor = conn.cursor()
            try:
                cursor.execute("DELETE FROM logs")
                conn.commit()
            finally:
                conn.close()

# ════════════════════════════════════════════════════════════
# Alerts Collection (dict-like MongoDB interface for compatibility)
# ════════════════════════════════════════════════════════════

class AlertsCollection:
    def insert_one(self, alert_dict):
        """Insert a single alert record."""
        with _db_lock:
            conn = get_db_connection()
            cursor = conn.cursor()
            try:
                cursor.execute('''
                    INSERT INTO alerts 
                    (log_id, timestamp, source_ip, threat_score, threat_label, action_taken)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    alert_dict.get("log_id"),
                    alert_dict.get("timestamp"),
                    alert_dict.get("source_ip"),
                    alert_dict.get("threat_score"),
                    alert_dict.get("threat_label"),
                    alert_dict.get("action_taken")
                ))
                conn.commit()
                alert_dict["_id"] = cursor.lastrowid
            finally:
                conn.close()
    
    def find(self, query=None, projection=None):
        """Find alerts matching the query."""
        with _db_lock:
            conn = get_db_connection()
            cursor = conn.cursor()
            try:
                cursor.execute('''
                    SELECT id, log_id, timestamp, source_ip, threat_score, threat_label, action_taken
                    FROM alerts
                    ORDER BY created_at DESC
                ''')
                rows = cursor.fetchall()
                
                results = []
                for row in rows:
                    alert_data = {
                        "_id": row[0],
                        "log_id": row[1],
                        "timestamp": row[2],
                        "source_ip": row[3],
                        "threat_score": row[4],
                        "threat_label": row[5],
                        "action_taken": row[6]
                    }
                    results.append(alert_data)
                
                return results
            finally:
                conn.close()
    
    def count_documents(self, query=None):
        """Count alerts by threat label."""
        with _db_lock:
            conn = get_db_connection()
            cursor = conn.cursor()
            try:
                if query is None:
                    query = {}
                
                # Handle different query types
                if "threat_label" in query:
                    cursor.execute(
                        "SELECT COUNT(*) FROM alerts WHERE threat_label = ?",
                        (query["threat_label"],)
                    )
                elif "action_taken" in query:
                    cursor.execute(
                        "SELECT COUNT(*) FROM alerts WHERE action_taken = ?",
                        (query["action_taken"],)
                    )
                else:
                    cursor.execute("SELECT COUNT(*) FROM alerts")
                
                return cursor.fetchone()[0]
            finally:
                conn.close()
    
    def delete_many(self, query=None):
        """Delete all alerts."""
        with _db_lock:
            conn = get_db_connection()
            cursor = conn.cursor()
            try:
                cursor.execute("DELETE FROM alerts")
                conn.commit()
            finally:
                conn.close()

# Create singleton instances
logs_collection = LogsCollection()
alerts_collection = AlertsCollection()
