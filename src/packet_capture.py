from scapy.all import sniff, IP, TCP, UDP

def process_packet(packet):
    try:
        # Check if packet has IP layer
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            
            protocol = "OTHER"
            if packet.haslayer(TCP):
                protocol = "TCP"
            elif packet.haslayer(UDP):
                protocol = "UDP"

            packet_length = len(packet)

            print({
                "src": src_ip,
                "dst": dst_ip,
                "protocol": protocol,
                "length": packet_length
            })

    except Exception as e:
        print("Error processing packet:", e)


def start_sniffing():
    print("🚀 Starting packet capture... (Press Ctrl+C to stop)")
    
    sniff(
        prn=process_packet,   # function to call for each packet
        store=False           # don’t store packets in memory
    )


if __name__ == "__main__":
    start_sniffing()