def explain_anomaly(features, baseline):
    reasons = []

    if features["packet_count"] > baseline["packet_count"] * 2.5:
        reasons.append("High traffic spike")

    if features["unique_src_ips"] > baseline["unique_src_ips"] * 2.5:
        reasons.append("Too many source IPs (possible scan)")

    if features["udp_count"] > baseline["udp_count"] * 2.5:
        reasons.append("Unusual UDP surge")

    if features["avg_packet_size"] > baseline["avg_packet_size"] * 2.5:
        reasons.append("Large packet size anomaly")

    return reasons