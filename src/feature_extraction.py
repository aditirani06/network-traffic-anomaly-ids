from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
import time

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

            traffic_data.append(features)

            if len(traffic_data) > 1000:
                traffic_data.pop(0)

            if len(traffic_data) % 20 == 0:
                df = pd.DataFrame(traffic_data)
                print(df.head())

            print(features)  # debug view

    except Exception as e:
        print("Error:", e)


def start_capture():
    print("🚀 Capturing traffic for feature extraction...")
    sniff(prn=process_packet, store=False)

def get_dataframe():
    return pd.DataFrame(traffic_data)

if __name__ == "__main__":
    start_capture()
   
    