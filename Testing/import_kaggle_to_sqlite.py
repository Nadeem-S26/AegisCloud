"""
🚀 OPTIMIZED Kaggle Dataset Bulk Importer to SQLite
Uses sampling to efficiently load large Kaggle datasets
"""

import os
import sys
import pandas as pd
import numpy as np
import random

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))
from services.db_service import logs_collection

ML_DIR = os.path.join(os.path.dirname(__file__), "ml")
DATA_FOLDERS = [
    os.path.join(ML_DIR, "CICIDS2017_improved"),
    os.path.join(ML_DIR, "CSECICIDS2018_improved"),
]

# Sampling configuration
SAMPLE_ROWS_PER_FILE = 10000  # Take 10k rows per CSV file
CHUNK_SIZE = 50000  # Read in chunks of 50k

def generate_realistic_ip():
    """Generate a realistic private IP address."""
    ranges = [
        lambda: f"192.168.{random.randint(0,255)}.{random.randint(1,254)}",
        lambda: f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
        lambda: f"172.{random.randint(16,31)}.{random.randint(0,255)}.{random.randint(1,254)}",
    ]
    return random.choice(ranges)()

def import_kaggle_datasets_sampled():
    """Import Kaggle datasets with smart sampling."""
    total_imported = 0
    
    for data_folder in DATA_FOLDERS:
        if not os.path.exists(data_folder):
            print(f"⚠️  Skipping (not found): {data_folder}")
            continue
        
        dataset_name = os.path.basename(data_folder)
        print(f"\n📂 Dataset: {dataset_name}")
        print("-" * 70)
        
        csv_files = sorted([f for f in os.listdir(data_folder) if f.endswith(".csv")])
        
        if not csv_files:
            print(f"  ❌ No CSV files found\n")
            continue
        
        for csv_file in csv_files:
            file_path = os.path.join(data_folder, csv_file)
            file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
            
            print(f"  📄 {csv_file:30s} ({file_size_mb:6.1f} MB) ", end="", flush=True)
            
            try:
                # Read only SAMPLE_ROWS_PER_FILE rows from each file
                chunk_imported = 0
                rows_read = 0
                
                for chunk in pd.read_csv(
                    file_path, 
                    chunksize=CHUNK_SIZE, 
                    encoding="latin1", 
                    low_memory=False,
                    nrows=SAMPLE_ROWS_PER_FILE  # LIMIT: only read first SAMPLE_ROWS_PER_FILE
                ):
                    # Clean data
                    chunk = chunk.replace([np.inf, -np.inf], np.nan)
                    chunk = chunk.dropna()
                    chunk.columns = chunk.columns.str.strip()
                    
                    # Keep numeric columns + Label + IP columns
                    cols_to_keep = chunk.select_dtypes(include=[np.number]).columns.tolist()
                    
                    # Add important text columns
                    text_cols_to_keep = ["Label", "Source IP", "Destination IP", "Src IP", "Dst IP"]
                    for col in text_cols_to_keep:
                        if col in chunk.columns and col not in cols_to_keep:
                            cols_to_keep.append(col)
                    
                    filtered_chunk = chunk[cols_to_keep].copy()
                    
                    # Insert rows with generated IPs if missing
                    for _, row in filtered_chunk.iterrows():
                        row_dict = row.to_dict()
                        
                        # Ensure source_ip exists (check multiple possible column names)
                        source_ip = (row_dict.get("Source IP") or 
                                   row_dict.get("Src IP") or 
                                   row_dict.get("source_ip"))
                        
                        # Generate IP if missing or invalid
                        if not source_ip or pd.isna(source_ip) or source_ip == "":
                            source_ip = generate_realistic_ip()
                        
                        # Standardize to "source_ip" field
                        row_dict["source_ip"] = str(source_ip)
                        
                        logs_collection.insert_one(row_dict)
                        chunk_imported += 1
                    
                    rows_read += len(chunk)
                
                total_imported += chunk_imported
                print(f"✅ {chunk_imported:,} rows")
                
            except Exception as e:
                print(f"❌ Error: {str(e)[:40]}")
    
    print("\n" + "="*70)
    print(f"✨ IMPORT SUCCESSFUL!")
    print(f"   Total rows in database: {total_imported:,}")
    print(f"   Ready for detection analysis")
    print("="*70)

if __name__ == "__main__":
    print("🚀 KAGGLE DATASETS → SQLITE (SAMPLED IMPORT)")
    print("="*70)
    print(f"Configuration:")
    print(f"  - Rows per file: {SAMPLE_ROWS_PER_FILE:,}")
    print(f"  - Chunk size: {CHUNK_SIZE:,}")
    print("="*70)
    import_kaggle_datasets_sampled()

