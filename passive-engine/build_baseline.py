import os
import json
import statistics

INPUT_DIR = "../passive_output"
OUTPUT_FILE = "baseline_model.json"

packet_counts = []
avg_sizes = []
dns_counts = []

# Collect only JSON files
files = [
    f for f in os.listdir(INPUT_DIR)
    if f.endswith(".json")
]

print("Processing", len(files), "files for baseline...")

for file in files:
    path = os.path.join(INPUT_DIR, file)

    try:
        with open(path, "r") as f:
            data = json.load(f)

        # Skip files without passive_features
        if "passive_features" not in data:
            print("Skipping invalid structure:", file)
            continue

        features = data["passive_features"]

        packet_counts.append(features.get("packet_count", 0))
        avg_sizes.append(features.get("avg_packet_size", 0))
        dns_counts.append(
            features.get("protocol_distribution", {}).get("DNS", 0)
        )

    except Exception as e:
        print("Error reading file:", file, "|", e)
        continue

# Ensure we have data before computing statistics
if not packet_counts:
    print("No valid passive data found. Baseline not created.")
    exit()

baseline = {
    "packet_count": {
        "mean": statistics.mean(packet_counts),
        "std": statistics.stdev(packet_counts) if len(packet_counts) > 1 else 0
    },
    "avg_packet_size": {
        "mean": statistics.mean(avg_sizes),
        "std": statistics.stdev(avg_sizes) if len(avg_sizes) > 1 else 0
    },
    "dns_count": {
        "mean": statistics.mean(dns_counts),
        "std": statistics.stdev(dns_counts) if len(dns_counts) > 1 else 0
    }
}

with open(OUTPUT_FILE, "w") as f:
    json.dump(baseline, f, indent=4)

print("Baseline model created successfully.")
print(json.dumps(baseline, indent=4))