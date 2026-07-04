import sys
import os
import json
import sqlite3
import csv
import subprocess
import glob
from datetime import datetime


# =========================================
# CONFIG
# =========================================

OUTPUT_DIR = r"E:\trust-auditor\passive_output"
BASELINE_DIR = "baselines"
DB_FILE = r"E:\trust-auditor\trust_history.db"
DATASET_FILE = r"E:\trust-auditor\passive_output\passive_dataset.csv"


# =========================================
# INPUT VALIDATION
# =========================================

if len(sys.argv) < 3:
    print("Usage: python main.py <pcap_file> <domain>")
    sys.exit(1)

PCAP_FILE = os.path.abspath(sys.argv[1])
DOMAIN = sys.argv[2]

if not os.path.exists(PCAP_FILE):
    print("PCAP file not found:", PCAP_FILE)
    sys.exit(1)


# =========================================
# CONTEXT DETECTION
# =========================================

def detect_context(packet_count, dns_count):
    dns_ratio = dns_count / packet_count if packet_count else 0

    if packet_count > 30000:
        return "high_traffic"

    if dns_ratio > 0.15:
        return "dns_heavy"

    return "general"


# =========================================
# LOAD BASELINE
# =========================================

def load_baseline(context):
    baseline_path = os.path.join(BASELINE_DIR, f"{context}.json")

    if not os.path.exists(baseline_path):
        baseline_path = os.path.join(BASELINE_DIR, "general.json")

    if not os.path.exists(baseline_path):
        print("No baseline model found.")
        sys.exit(1)

    with open(baseline_path, "r") as f:
        return json.load(f)


def compute_z(value, mean, std):
    if std == 0:
        return 0
    return (value - mean) / std


# =========================================
# TRUST DATABASE
# =========================================

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS trust (
            domain TEXT,
            score REAL,
            timestamp TEXT
        )
    """)
    conn.commit()
    conn.close()


def update_trust(domain, current_score):

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    c.execute(
        "SELECT score FROM trust WHERE domain=? ORDER BY timestamp DESC LIMIT 1",
        (domain,)
    )

    row = c.fetchone()

    if row:
        old_score = row[0]
        updated_score = 0.8 * old_score + 0.2 * current_score
    else:
        updated_score = current_score

    c.execute(
        "INSERT INTO trust VALUES (?, ?, ?)",
        (domain, updated_score, datetime.now().isoformat())
    )

    conn.commit()
    conn.close()

    return updated_score


# =========================================
# FAST PACKET ANALYSIS USING TSHARK
# =========================================

print("Analyzing:", DOMAIN)

packet_count = 0
protocols = {}
total_size = 0

try:
    cmd = [
        "tshark",
        "-r", PCAP_FILE,
        "-T", "fields",
        "-e", "frame.len",
        "-e", "_ws.col.Protocol"
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print("⚠ Corrupted PCAP skipped:", PCAP_FILE)
        sys.exit(1)

    lines = result.stdout.splitlines()

    for line in lines:
        parts = line.split("\t")

        if len(parts) >= 2:
            packet_count += 1

            try:
                total_size += int(parts[0])
            except:
                pass

            proto = parts[1]
            protocols[proto] = protocols.get(proto, 0) + 1

except Exception:
    print("⚠ Error processing:", PCAP_FILE)
    sys.exit(1)


if packet_count == 0:
    print("⚠ Empty capture skipped:", PCAP_FILE)
    sys.exit(1)


avg_size = total_size / packet_count
dns_count = protocols.get("DNS", 0)

context = detect_context(packet_count, dns_count)
baseline = load_baseline(context)


# =========================================
# Z-SCORE CALCULATION
# =========================================

z_packet = compute_z(
    packet_count,
    baseline["packet_count"]["mean"],
    baseline["packet_count"]["std"]
)

z_size = compute_z(
    avg_size,
    baseline["avg_packet_size"]["mean"],
    baseline["avg_packet_size"]["std"]
)

z_dns = compute_z(
    dns_count,
    baseline["dns_count"]["mean"],
    baseline["dns_count"]["std"]
)


# =========================================
# ANOMALY MODEL
# =========================================

anomaly_score = (
    abs(z_packet) * 0.4 +
    abs(z_size) * 0.3 +
    abs(z_dns) * 0.3
)

raw_passive_score = max(0, min(100, 100 - anomaly_score * 20))


# =========================================
# TEMPORAL TRUST EVOLUTION
# =========================================

init_db()
final_passive_score = update_trust(DOMAIN, raw_passive_score)


# =========================================
# BUILD RESULT JSON
# =========================================

result = {
    "domain": DOMAIN,
    "timestamp": datetime.now().isoformat(),
    "context": context,
    "passive_score": round(final_passive_score, 2),
    "passive_features": {
        "packet_count": packet_count,
        "avg_packet_size": round(avg_size, 2),
        "dns_count": dns_count,
        "protocol_distribution": protocols,
        "z_scores": {
            "packet_count": round(z_packet, 3),
            "avg_packet_size": round(z_size, 3),
            "dns_count": round(z_dns, 3)
        }
    }
}


# =========================================
# SAVE JSON
# =========================================

if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

output_file = os.path.join(OUTPUT_DIR, DOMAIN + ".json")

with open(output_file, "w", encoding="utf-8") as f:
    json.dump(result, f, indent=4)


# =========================================
# APPEND TO MASTER DATASET CSV
# =========================================

file_exists = os.path.exists(DATASET_FILE)

with open(DATASET_FILE, "a", newline="", encoding="utf-8") as csvfile:
    writer = csv.writer(csvfile)

    if not file_exists:
        writer.writerow([
            "domain",
            "packet_count",
            "avg_packet_size",
            "dns_count",
            "context",
            "raw_passive_score",
            "final_passive_score"
        ])

    writer.writerow([
        DOMAIN,
        packet_count,
        round(avg_size, 2),
        dns_count,
        context,
        round(raw_passive_score, 2),
        round(final_passive_score, 2)
    ])


print("Passive analysis complete.")
print("Final Trust Score:", round(final_passive_score, 2))
print("Saved JSON to:", output_file)
print("Updated dataset:", DATASET_FILE)


def analyze_domain(domain):
    """Analyze passive data for a specific domain - for backend integration"""
    # Look for PCAP files for this domain
    pcap_pattern = os.path.join(r"E:\trust-auditor\passive_engine\pcaps", f"{domain.replace('.', '_')}*.pcap*")
    pcap_files = glob.glob(pcap_pattern)
    
    if not pcap_files:
        return {
            "domain": domain,
            "passive_score": 0.5,
            "error": "No PCAP files found for domain"
        }
    
    # Use the most recent PCAP file
    latest_pcap = max(pcap_files, key=os.path.getctime)
    
    # Create a mock PCAP_FILE variable and DOMAIN for the existing logic
    global PCAP_FILE, DOMAIN
    PCAP_FILE = latest_pcap
    DOMAIN = domain
    
    # Re-run the analysis with the new domain/pcap
    try:
        # Re-execute the analysis logic
        packet_count = 0
        protocols = {}
        total_size = 0

        cmd = [
            "tshark",
            "-r", PCAP_FILE,
            "-T", "fields",
            "-e", "frame.len",
            "-e", "_ws.col.Protocol"
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            return {
                "domain": domain,
                "passive_score": 0.3,
                "error": "Failed to analyze PCAP file"
            }

        lines = result.stdout.splitlines()

        for line in lines:
            parts = line.split("\t")

            if len(parts) >= 2:
                packet_count += 1

                try:
                    total_size += int(parts[0])
                except:
                    pass

                proto = parts[1]
                protocols[proto] = protocols.get(proto, 0) + 1

        if packet_count == 0:
            return {
                "domain": domain,
                "passive_score": 0.3,
                "error": "Empty PCAP file"
            }

        avg_size = total_size / packet_count
        dns_count = protocols.get("DNS", 0)

        context = detect_context(packet_count, dns_count)
        baseline = load_baseline(context)

        z_packet = compute_z(
            packet_count,
            baseline["packet_count"]["mean"],
            baseline["packet_count"]["std"]
        )

        z_size = compute_z(
            avg_size,
            baseline["avg_packet_size"]["mean"],
            baseline["avg_packet_size"]["std"]
        )

        z_dns = compute_z(
            dns_count,
            baseline["dns_count"]["mean"],
            baseline["dns_count"]["std"]
        )

        anomaly_score = (
            abs(z_packet) * 0.4 +
            abs(z_size) * 0.3 +
            abs(z_dns) * 0.3
        )

        raw_passive_score = max(0, min(100, 100 - anomaly_score * 20))
        
        # Initialize database and update trust
        init_db()
        final_passive_score = update_trust(DOMAIN, raw_passive_score)

        result = {
            "domain": DOMAIN,
            "timestamp": datetime.now().isoformat(),
            "context": context,
            "passive_score": round(final_passive_score, 2),
            "passive_features": {
                "packet_count": packet_count,
                "avg_packet_size": round(avg_size, 2),
                "dns_count": dns_count,
                "protocol_distribution": protocols,
                "z_scores": {
                    "packet_count": round(z_packet, 3),
                    "avg_packet_size": round(z_size, 3),
                    "dns_count": round(z_dns, 3)
                }
            }
        }

        # Save JSON result
        if not os.path.exists(OUTPUT_DIR):
            os.makedirs(OUTPUT_DIR)

        output_file = os.path.join(OUTPUT_DIR, DOMAIN + ".json")

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=4)

        # Append to dataset
        file_exists = os.path.exists(DATASET_FILE)

        with open(DATASET_FILE, "a", newline="", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile)

            if not file_exists:
                writer.writerow([
                    "domain",
                    "packet_count",
                    "avg_packet_size",
                    "dns_count",
                    "context",
                    "raw_passive_score",
                    "final_passive_score"
                ])

            writer.writerow([
                DOMAIN,
                packet_count,
                round(avg_size, 2),
                dns_count,
                context,
                round(raw_passive_score, 2),
                round(final_passive_score, 2)
            ])

        return result

    except Exception as e:
        return {
            "domain": domain,
            "passive_score": 0.3,
            "error": f"Analysis failed: {str(e)}"
        }