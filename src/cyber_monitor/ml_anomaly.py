import json
import pandas as pd
import numpy as np
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

