import os
import json
import csv

PASSIVE_DIR = r"E:\trust-auditor\passive_output"
CSV_FILE = os.path.join(PASSIVE_DIR, "passive_dataset.csv")

rows = []

for filename in os.listdir(PASSIVE_DIR):
    if filename.endswith(".json"):
        path = os.path.join(PASSIVE_DIR, filename)

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        if "passive_features" not in data:
            continue

        features = data["passive_features"]

        rows.append([
            data["domain"],
            features.get("packet_count", 0),
            features.get("avg_packet_size", 0),
            features.get("dns_count", 0),
            data.get("context", "unknown"),
            data.get("passive_score", 0)
        ])

# Write CSV fresh
with open(CSV_FILE, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)

    writer.writerow([
        "domain",
        "packet_count",
        "avg_packet_size",
        "dns_count",
        "context",
        "passive_score"
    ])

    writer.writerows(rows)

print("Passive CSV rebuilt successfully.")
print("Total records:", len(rows))
print("Saved to:", CSV_FILE)