import json
import pandas as pd
import numpy as np
import time
import os
import threading
from sklearn.ensemble import IsolationForest

class TelemetryFeatureExtractor:
    """
    Extracts numerical features from raw telemetry JSON logs for ML processing.
    """
    def __init__(self):
        # We define the columns we care about for the ML model.
        self.feature_columns = ['cpu_percent', 'ram_percent', 'usb_count']

    def load_and_preprocess(self, json_file_path):
        """
        Reads a JSON log file containing telemetry from multiple agents,
        and returns a structured Pandas DataFrame suitable for training.
        """
        try:
            with open(json_file_path, 'r') as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            print(f"Warning: Could not read {json_file_path}")
            return pd.DataFrame()
            
        # Handle cases where the JSON is a list of events or a single dict
        if not isinstance(data, list):
            data = [data]
            
        df = pd.DataFrame(data)
        
        # Ensure our required columns exist, even if missing in the data
        for col in self.feature_columns:
            if col not in df.columns:
                df[col] = 0.0
                
        # If 'host' or 'hostname' isn't provided, group by 'unknown'
        if 'hostname' not in df.columns:
            df['hostname'] = 'local_system'
            
        # Fill any missing numerical values with 0
        df[self.feature_columns] = df[self.feature_columns].fillna(0.0)
        
        # Ensure numeric types
        for col in self.feature_columns:
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0.0)
            
        return df

    def extract_host_vectors(self, df):
        """
        Takes the preprocessed DataFrame and returns a dictionary mapping
        each hostname to its corresponding feature matrix (numpy array).
        This is what the model actually reads!
        """
        if df.empty:
            return {}
            
        host_vectors = {}
        # Group data by each unique agent/host
        for hostname, group in df.groupby('hostname'):
            # Extract just the numbers for our model
            features = group[self.feature_columns].values
            host_vectors[hostname] = features
            
        return host_vectors

class AnomalyDetector:
    """
    Step 2 & 3: Initializes the IsolationForest model and trains it to learn normal behavior.
    """
    def __init__(self, contamination=0.1):
        # contamination is the expected percentage of anomalies in the training data
        self.model = IsolationForest(n_estimators=100, contamination=contamination, random_state=42)
        self.is_trained = False
        
    def train_baseline(self, feature_matrix):
        """
        Trains the model on a baseline matrix of features to learn "normal".
        """
        if len(feature_matrix) == 0:
            return
            
        self.model.fit(feature_matrix)
        self.is_trained = True
        
    def predict(self, live_features):
        """
        Predicts if new live features are anomalous.
        Returns an array where 1 = Normal, -1 = Anomaly.
        """
        if not self.is_trained:
            raise ValueError("Model must be trained before calling predict.")
            
        return self.model.predict(live_features)

def run_anomaly_monitor():
    """
    Background worker that continuously polls the master logs, trains the baseline 
    if needed, and outputs anomalies to mnt/master/anomalies.json.
    """
    log_file = "mnt/master/log.json"
    anomalies_file = "mnt/master/anomalies.json"
    stats_file = "mnt/master/ml_stats.json"
    
    extractor = TelemetryFeatureExtractor()
    detectors = {} # dict mapping hostname to AnomalyDetector instance
    
    # Ensure mnt/master exists
    os.makedirs(os.path.dirname(anomalies_file), exist_ok=True)
    
    print("[ML] Starting Anomaly Monitor thread...")
    
    while True:
        try:
            time.sleep(5) # Poll every 5 seconds
            
            if not os.path.exists(log_file):
                continue
                
            df = extractor.load_and_preprocess(log_file)
            host_vectors = extractor.extract_host_vectors(df)
            
            anomalies_detected = []
            ml_stats = {
                "timestamp": time.strftime("%H:%M:%S"),
                "hosts": {}
            }
            
            for host, features in host_vectors.items():
                if len(features) < 5:
                    continue # Not enough data for this host yet
                    
                if host not in detectors:
                    detectors[host] = AnomalyDetector(contamination=0.05)
                    
                detector = detectors[host]
                
                # Train baseline if not trained
                if not detector.is_trained:
                    detector.train_baseline(features)
                    print(f"[ML] Baseline trained on host: {host}")
                    
                # Predict on the latest row
                latest_reading = features[-1].reshape(1, -1)
                pred = detector.predict(latest_reading)
                
                # Get the raw anomaly score (negative = anomaly, positive = normal)
                score = float(detector.model.decision_function(latest_reading)[0])
                
                # Record stats
                ml_stats["hosts"][host] = {
                    "trained": detector.is_trained,
                    "data_points": len(features),
                    "last_score": round(score, 4)
                }
                
                if pred[0] == -1:
                    # It's an anomaly!
                    anomalies_detected.append({
                        "timestamp": time.strftime("%H:%M:%S"),
                        "hostname": host,
                        "features": {
                            "cpu_percent": float(latest_reading[0][0]),
                            "ram_percent": float(latest_reading[0][1]),
                            "usb_count": int(latest_reading[0][2])
                        },
                        "score": round(score, 4)
                    })
            
            # Write to anomalies file
            if anomalies_detected:
                with open(anomalies_file, 'w') as f:
                    json.dump(anomalies_detected, f)
                    
            # Write ML stats file
            with open(stats_file, 'w') as f:
                json.dump(ml_stats, f)
                    
        except Exception as e:
            print(f"[ML] Error in anomaly monitor: {e}")


