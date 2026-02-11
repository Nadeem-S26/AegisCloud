"""
Helper script to insert test logs into SQLite database
for testing the detection functionality.
"""
import sys
import os
import json

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

from services.db_service import logs_collection

# Sample test logs with features expected by the model
test_logs = [
    {
        "source_ip": "192.168.1.100",
        "bytes_sent": 1024,
        "bytes_received": 2048,
        "Flow Duration": 5000,
        "Total Fwd Packets": 10,
        "Total Backward Packets": 8,
        "Fwd Packet Length Max": 256,
        "Fwd Packet Length Min": 32,
        "Bwd Packet Length Max": 512,
        "Bwd Packet Length Min": 64,
    },
    {
        "source_ip": "10.0.0.50",
        "bytes_sent": 5120,
        "bytes_received": 10240,
        "Flow Duration": 15000,
        "Total Fwd Packets": 50,
        "Total Backward Packets": 45,
        "Fwd Packet Length Max": 1024,
        "Fwd Packet Length Min": 128,
        "Bwd Packet Length Max": 2048,
        "Bwd Packet Length Min": 256,
    },
    {
        "source_ip": "172.16.0.200",
        "bytes_sent": 2560,
        "bytes_received": 5120,
        "Flow Duration": 8000,
        "Total Fwd Packets": 25,
        "Total Backward Packets": 20,
        "Fwd Packet Length Max": 512,
        "Fwd Packet Length Min": 64,
        "Bwd Packet Length Max": 1024,
        "Bwd Packet Length Min": 128,
    },
]

print("🔧 Adding test logs to SQLite database...\n")

for i, log in enumerate(test_logs, 1):
    logs_collection.insert_one(log)
    print(f"✅ Added test log {i}: {log['source_ip']}")

print(f"\n✨ Successfully added {len(test_logs)} test logs!")
print("   Now go to the web UI and click 'Run Detection'")
