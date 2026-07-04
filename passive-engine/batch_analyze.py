import os
import subprocess
import sys

PCAP_DIR = r"E:\trust-auditor\passive_engine\pcaps"
OUTPUT_DIR = r"E:\trust-auditor\passive_output"

if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

if not os.path.exists(PCAP_DIR):
    print("PCAP directory not found:", PCAP_DIR)
    sys.exit(1)


# Collect actual PCAP files (sorted for consistency)
pcap_files = sorted([
    f for f in os.listdir(PCAP_DIR)
    if f.endswith(".pcap") or f.endswith(".pcapng")
])

LIMIT = 1000  # change to None to process all files

if LIMIT:
    pcap_files = pcap_files[:LIMIT]

print("Total PCAP files found:", len(pcap_files))

processed = 0
skipped = 0

for file in pcap_files:

    pcap_path = os.path.join(PCAP_DIR, file)

    # Correct extension handling
    if file.endswith(".pcapng"):
        domain = file[:-7]
    elif file.endswith(".pcap"):
        domain = file[:-5]
    else:
        continue

    domain = domain.replace("_", ".")

    print("\n---------------------------------")
    print("Analyzing:", domain)
    print("Using file:", pcap_path)

    cmd = [
        sys.executable,
        os.path.join(r"E:\trust-auditor\passive_engine", "main.py"),
        pcap_path,
        domain
    ]

    result = subprocess.run(cmd)

    if result.returncode == 0:
        processed += 1
    else:
        skipped += 1

print("\n=================================")
print("Batch analysis completed.")
print("Processed:", processed)
print("Skipped (corrupted/errors):", skipped)
print("=================================")