import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "aegis_cloud.db")

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = [row[0] for row in cursor.fetchall()]

print("="*70)
print("DATABASE STRUCTURE")
print("="*70)
print(f"Database: {DB_PATH}")
print(f"Tables: {tables}")
print()

for table in tables:
    cursor.execute(f"PRAGMA table_info({table})")
    columns = cursor.fetchall()
    print(f"Table: {table}")
    print(f"  Columns: {[col[1] for col in columns]}")
    
    cursor.execute(f"SELECT COUNT(*) FROM {table}")
    count = cursor.fetchone()[0]
    print(f"  Rows: {count:,}")
    print()

conn.close()
