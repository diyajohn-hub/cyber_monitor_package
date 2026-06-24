import json
import os
from src.cyber_monitor.ml_anomaly import TelemetryFeatureExtractor

def run_example():
    print("--- ML Feature Extraction Example ---\n")
    
    # 1. Create some dummy raw JSON telemetry data that mimics what agents send
    dummy_telemetry = [
        {"hostname": "SERVER-01", "cpu_percent": 12.5, "ram_percent": 45.0, "usb_count": 1, "timestamp": "10:00:00"},
        {"hostname": "SERVER-01", "cpu_percent": 15.0, "ram_percent": 45.5, "usb_count": 1, "timestamp": "10:00:05"},
        {"hostname": "LAPTOP-X9", "cpu_percent": 88.0, "ram_percent": 90.2, "usb_count": 0, "timestamp": "10:00:01"},
        {"hostname": "LAPTOP-X9", "cpu_percent": 92.5, "ram_percent": 91.0, "usb_count": 2, "timestamp": "10:00:06"},
    ]
    
    # Write it to a temporary file
    temp_file = "dummy_log.json"
    with open(temp_file, "w") as f:
        json.dump(dummy_telemetry, f)
        
    print(f"1. Raw JSON Data stored in {temp_file}:")
    print(json.dumps(dummy_telemetry, indent=2))
    print("\n" + "="*50 + "\n")
    
    # 2. Initialize our Feature Extractor
    extractor = TelemetryFeatureExtractor()
    
    # 3. Load and Preprocess (Raw JSON -> Pandas DataFrame)
    print("2. Preprocessed Pandas DataFrame (structured table):")
    df = extractor.load_and_preprocess(temp_file)
    print(df)
    print("\n" + "="*50 + "\n")
    
    # 4. Extract Machine Learning Vectors (DataFrame -> Numpy Arrays grouped by Host)
    print("3. Final ML Vectors (Numpy Arrays grouped by Hostname ready for the model):")
    host_vectors = extractor.extract_host_vectors(df)
    
    for host, vector_matrix in host_vectors.items():
        print(f"\nHost: {host}")
        print(f"Matrix shape: {vector_matrix.shape} (Rows=Timeframes, Columns=Features)")
        print(f"Features [CPU%, RAM%, USB]:")
        print(vector_matrix)
        
    # Cleanup
    os.remove(temp_file)

if __name__ == "__main__":
    run_example()
