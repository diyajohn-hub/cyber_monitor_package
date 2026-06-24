import json
import pandas as pd
import numpy as np

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
