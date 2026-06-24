import json
import os
import numpy as np
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
        print(vector_matrix)
        
    # --- STEP 2 & 3: Initialize and Train ---
    print("\n" + "="*50 + "\n")
    print("4. Step 2 & 3: Model Initialization and Baseline Training...")
    
    from src.cyber_monitor.ml_anomaly import AnomalyDetector
    
    # Let's train the model on the LAPTOP-X9 normal baseline data
    laptop_baseline = host_vectors["LAPTOP-X9"]
    detector = AnomalyDetector(contamination=0.1) # Expecting ~10% anomalies max
    detector.train_baseline(laptop_baseline)
    print("Model successfully trained on LAPTOP-X9 baseline!\n")
    
    # --- STEP 4: Inference (Simulating an attack) ---
    print("5. Step 4: Real-time Inference (Testing the model with new data)")
    
    # Simulate some live data: one normal reading, one massive CPU spike (Anomaly!)
    # Format: [CPU%, RAM%, USB Count]
    live_test_data = np.array([
        [90.0, 91.5, 0],   # Normal (similar to baseline 88-92% CPU)
        [100.0, 99.9, 5]   # MASSIVE ANOMALY (100% CPU, high RAM, 5 USBs plugged in)
    ])
    
    predictions = detector.predict(live_test_data)
    
    print("Live Test Data:")
    print(live_test_data)
    print("\nModel Predictions (1 = Normal, -1 = ANOMALY):")
    print(predictions)
    
    for i, pred in enumerate(predictions):
        status = "NORMAL" if pred == 1 else "🚨 ANOMALY DETECTED 🚨"
        print(f"Reading {i+1}: {status}")

    # Cleanup
    os.remove(temp_file)

if __name__ == "__main__":
    run_example()
