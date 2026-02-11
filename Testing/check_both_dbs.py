import sqlite3
import os

DB_PATHS = [
    "D:/PROJECTS/cloud/AegisCloud/aegis_cloud.db",
    "D:/PROJECTS/cloud/AegisCloud/backend/aegis_cloud.db"
]

for db_path in DB_PATHS:
    if not os.path.exists(db_path):
        print(f"❌ {db_path} does not exist\n")
        continue
        
    print("="*70)
    print(f"DATABASE: {db_path}")
    print("="*70)
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row[0] for row in cursor.fetchall()]
    
    print(f"Tables: {tables}")
    print()
    
    for table in tables:
        cursor.execute(f"SELECT COUNT(*) FROM {table}")
        count = cursor.fetchone()[0]
        print(f"  {table}: {count:,} rows")
    
    conn.close()
    print()
