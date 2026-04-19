from sklearn.ensemble import IsolationForest
import numpy as np

# Initialize model
model = IsolationForest(contamination=0.1, random_state=42)

trained = False

def train_model(data):
    global trained
    model.fit(data)
    trained = True

def predict(data):
    if not trained:
        return None
    return model.predict(data)

def features_to_vector(features):
    return [
        features["packet_count"],
        features["unique_src_ips"],
        features["unique_dst_ips"],
        features["avg_packet_size"],
        features["tcp_count"],
        features["udp_count"]
    ]