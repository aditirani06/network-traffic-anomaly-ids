import pandas as pd
import time

WINDOW_SIZE = 5  # seconds

def compute_features(df):
    if df.empty:
        return None

    features = {}

    # Total packets in window
    features["packet_count"] = len(df)

    # Unique source IPs
    features["unique_src_ips"] = df["src_ip"].nunique()

    # Unique destination IPs
    features["unique_dst_ips"] = df["dst_ip"].nunique()

    # Average packet size
    features["avg_packet_size"] = float(df["length"].mean())

    # Protocol distribution
    features["tcp_count"] = len(df[df["protocol"] == 1])
    features["udp_count"] = len(df[df["protocol"] == 2])

    return features