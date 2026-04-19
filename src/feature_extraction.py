from pyexpat import features
from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
import time
from window_processor import compute_features
from threading import Lock
import threading
from model import train_model, predict, features_to_vector
from explainer import explain_anomaly
from logger import log_anomaly, log_normal

baseline = None
stop_event = threading.Event()
lock = Lock()
traffic_data = []

def process_packet(packet):
    try:
        if packet.haslayer(IP):
            ip_layer = packet[IP]

            src_ip = ip_layer.src
            dst_ip = ip_layer.dst

            protocol = 0
            if packet.haslayer(TCP):
                protocol = 1
            elif packet.haslayer(UDP):
                protocol = 2

            packet_length = len(packet)
            timestamp = time.time()

            features = {
                "timestamp": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol,
                "length": packet_length
            }

            with lock:
                traffic_data.append(features)

                if len(traffic_data) > 1000:
                    traffic_data.pop(0)

            # Optional debug (reduced frequency)
                if len(traffic_data) % 50 == 0:
                    df = pd.DataFrame(traffic_data)
                    print(df.head())
            
    except Exception as e:
        print("Error:", e)


def start_capture():
    print("🚀 Capturing traffic for feature extraction...")
    sniff(
        prn=process_packet,
        store=False,
        stop_filter=lambda x: stop_event.is_set()
    )

feature_history = []

def analyze_traffic():
    global feature_history
    global baseline
    while not stop_event.is_set():
        time.sleep(5)

        with lock:
            if len(traffic_data) == 0:
                continue
            df = pd.DataFrame(traffic_data)

        current_time = time.time()
        window_df = df[df["timestamp"] > current_time - 5]

        features = compute_features(window_df)

        if features:
            vector = features_to_vector(features)
            feature_history.append(vector)

            print("\n📊 Traffic Summary:")
            print(features)

            # Train model after enough data
            if len(feature_history) == 10:
                print("🧠 Training model...")
                train_model(feature_history)

                # Compute baseline
                import numpy as np
                avg = np.mean(feature_history, axis=0)

                baseline = {
                    "packet_count": float(avg[0]),
                    "unique_src_ips": float(avg[1]),
                    "unique_dst_ips": float(avg[2]),
                    "avg_packet_size": float(avg[3]),
                    "tcp_count": float(avg[4]),
                    "udp_count": float(avg[5]),
            }

            print("📌 Baseline established:", baseline)

            # Predict
            rule_triggered = False

            if baseline:
                if features["packet_count"] > baseline["packet_count"] * 3:
                    print("🚨 RULE ALERT: Traffic spike detected")
                    log_anomaly(features, ["Traffic spike (rule-based)"])
                    rule_triggered = True

                if features["unique_src_ips"] > baseline["unique_src_ips"] * 3:
                    print("🚨 RULE ALERT: Possible scanning activity")
                    rule_triggered = True

            if not rule_triggered and len(feature_history) > 10:
                prediction = predict([vector])[0]

                if prediction == -1:
                    print("🚨 ANOMALY DETECTED!")
                    reasons = []
                    if baseline:
                        reasons = explain_anomaly(features, baseline)

                        if reasons:
                            print("🔍 Reasons:")
                            for r in reasons:
                                print(f"- {r}")
                        else:
                            print("- Unknown pattern (ML detected anomaly)")

                     # ✅ LOG IT
                    log_anomaly(features, reasons)

                else:
                    print("✅ Normal traffic")
                    if len(feature_history) % 5 == 0:
                        log_normal(features)

def get_dataframe():
    with lock:
        return pd.DataFrame(traffic_data)
    
if __name__ == "__main__":
    t1 = threading.Thread(target=start_capture)
    t2 = threading.Thread(target=analyze_traffic)

    t1.start()
    t2.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Stopping system...")
        stop_event.set()

        t1.join()
        t2.join()

        print("✅ Shutdown complete")
   
    