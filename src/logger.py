import json
from datetime import datetime

ANOMALY_LOG = "logs/anomalies.log"
NORMAL_LOG = "logs/normal.log"

def log_anomaly(features, reasons):
    entry = {
        "timestamp": datetime.now().isoformat(),
        "type": "anomaly",
        "features": features,
        "reasons": reasons
    }

    with open(ANOMALY_LOG, "a") as f:
        f.write(json.dumps(entry, indent=2) + "\n")

def log_normal(features):
    entry = {
        "timestamp": datetime.now().isoformat(),
        "type": "normal",
        "features": features
    }

    with open(NORMAL_LOG, "a") as f:
        f.write(json.dumps(entry, indent=2) + "\n")