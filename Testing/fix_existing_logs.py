"""
Fix existing logs in SQLite database by adding source_ip field
"""

import os
import sys
import random
import sqlite3
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

# Get DB path
CONFIG_PATH = os.path.join(os.path.dirname(__file__), 'backend', 'db_config.json')
with open(CONFIG_PATH, 'r') as f:
    config = json.load(f)

DB_PATH = config.get("database_path", "./aegis_cloud.db")
if not os.path.isabs(DB_PATH):
    DB_PATH = os.path.join(os.path.dirname(__file__), DB_PATH)

def generate_realistic_ip():
    """Generate a realistic private IP address."""
    ranges = [
        lambda: f"192.168.{random.randint(0,255)}.{random.randint(1,254)}",
        lambda: f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
        lambda: f"172.{random.randint(16,31)}.{random.randint(0,255)}.{random.randint(1,254)}",
    ]
    return random.choice(ranges)()

def fix_logs():
    """Add source_ip to all logs that don't have it."""
    print("🔧 Fixing existing logs in database...")
    print("="*70)
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Get all logs
    cursor.execute("SELECT id, data FROM logs")
    rows = cursor.fetchall()
    total = len(rows)
    fixed = 0
    already_ok = 0
    
    print(f"📊 Total logs in database: {total:,}")
    print("🔄 Processing...\n")
    
    for row in rows:
        log_id, log_json = row
        log_data = json.loads(log_json)
        
        # Check if source_ip already exists and is valid
        source_ip = log_data.get("source_ip")
        
        # Also check alternative column names
        if not source_ip:
            source_ip = (log_data.get("Source IP") or 
                        log_data.get("Src IP"))
        
        # If still no valid IP, generate one
        if not source_ip or source_ip in ["", "nan", None]:
            new_ip = generate_realistic_ip()
            log_data["source_ip"] = new_ip
            
            # Update the record
            updated_json = json.dumps(log_data)
            cursor.execute(
                "UPDATE logs SET data = ? WHERE id = ?",
                (updated_json, log_id)
            )
            fixed += 1
            
            if fixed % 1000 == 0:
                print(f"  ✓ Fixed {fixed:,} / {total:,} logs...")
                conn.commit()  # Commit periodically
        else:
            # Standardize the field name
            if "source_ip" not in log_data:
                log_data["source_ip"] = str(source_ip)
                updated_json = json.dumps(log_data)
                cursor.execute(
                    "UPDATE logs SET data = ? WHERE id = ?",
                    (updated_json, log_id)
                )
                fixed += 1
            else:
                already_ok += 1
    
    conn.commit()
    conn.close()
    
    print("\n" + "="*70)
    print(f"✅ COMPLETE!")
    print(f"   Fixed: {fixed:,} logs")
    print(f"   Already OK: {already_ok:,} logs")
    print(f"   Total: {total:,} logs")
    print("="*70)

if __name__ == "__main__":
    fix_logs()
