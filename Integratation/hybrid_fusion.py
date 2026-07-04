import json
import os
import sqlite3
from datetime import datetime

# ==============================
# PATH CONFIGURATION
# ==============================

ACTIVE_FILE = r"E:\trust-auditor\active_output\active_audit_master.json"
PASSIVE_DIR = r"E:\trust-auditor\passive_output"
OUTPUT_FILE = r"E:\trust-auditor\integration\hybrid_results.json"
DB_FILE = r"E:\trust-auditor\trust_history.db"
# ==============================
# TRUST CLASSIFICATION
# ==============================

def classify_trust(score):
    if score >= 85:
        return "High Trust"
    elif score >= 60:
        return "Moderate Trust"
    else:
        return "Low Trust"
def classify_threat(hybrid_score, severity, rci):

    if hybrid_score < 60 or severity == "Severe Anomaly" or rci > 30:
        return "High Risk"

    elif hybrid_score < 85 or severity == "Moderate Anomaly" or rci > 15:
        return "Medium Risk"

    else:
        return "Low Risk"
# ==============================
# DATABASE FUNCTIONS
# ==============================

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS trust_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT,
            timestamp TEXT,
            hybrid_score REAL,
            rci REAL
        )
    """)

    conn.commit()
    conn.close()

def save_to_history(domain, timestamp, hybrid_score, rci):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO trust_history (domain, timestamp, hybrid_score, rci)
        VALUES (?, ?, ?, ?)
    """, (domain, timestamp, hybrid_score, rci))

    conn.commit()
    conn.close()

def get_trust_trend(domain):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT hybrid_score FROM trust_history
        WHERE domain = ?
        ORDER BY id DESC
        LIMIT 2
    """, (domain,))

    rows = cursor.fetchall()
    conn.close()

    if len(rows) < 2:
        return "Insufficient Data"

    latest = rows[0][0]
    previous = rows[1][0]

    if latest > previous:
        return "Improving"
    elif latest < previous:
        return "Declining"
    else:
        return "Stable"

# ==============================
# HYBRID SCORE CALCULATION
# ==============================
# ==============================
# 🔥 TRUST STABILITY INDEX (TSI)
# ==============================

def calculate_tsi(domain, window=10):

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT hybrid_score FROM trust_history
        WHERE domain = ?
        ORDER BY id DESC
        LIMIT ?
    """, (domain, window))

    rows = cursor.fetchall()
    conn.close()

    scores = [row[0] for row in rows]

    if len(scores) < 2:
        return 0  # Not enough data for variance

    mean_score = sum(scores) / len(scores)
    variance = sum((x - mean_score) ** 2 for x in scores) / len(scores)
    std_dev = variance ** 0.5

    return round(std_dev, 2)
def calculate_tvi(domain, window=10):

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT hybrid_score FROM trust_history
        WHERE domain = ?
        ORDER BY id DESC
        LIMIT ?
    """, (domain, window))

    rows = cursor.fetchall()
    conn.close()

    scores = [row[0] for row in rows]

    if len(scores) < 2:
        return 0

    mean_score = sum(scores) / len(scores)

    variance = sum((x - mean_score) ** 2 for x in scores) / len(scores)
    std_dev = variance ** 0.5

    if mean_score == 0:
        return 0

    tvi = (std_dev / mean_score) * 100

    return round(tvi, 2)
def volatility_alert(tsi):

    if tsi > 15:
        return "High Volatility Alert"

    elif tsi > 5:
        return "Moderate Volatility"

    else:
        return "Stable Trust"
def calculate_hybrid_score(active_score, passive_score, z_scores):

    max_z = max(
        abs(z_scores.get("packet_count", 0)),
        abs(z_scores.get("avg_packet_size", 0)),
        abs(z_scores.get("dns_count", 0))
    )

    if max_z <= 1:
        active_weight = 0.7
        passive_weight = 0.3
        severity = "Normal"
    elif max_z <= 2:
        active_weight = 0.5
        passive_weight = 0.5
        severity = "Moderate Anomaly"
    else:
        active_weight = 0.3
        passive_weight = 0.7
        severity = "Severe Anomaly"

    base_score = (active_weight * active_score) + \
                 (passive_weight * passive_score)

    if active_score >= 80 and passive_score < 60:
        base_score -= 15
    elif abs(active_score - passive_score) > 30:
        base_score -= 10

    final_score = round(max(base_score, 0), 2)

    return final_score, severity, active_weight, passive_weight

# ==============================
# CONFIDENCE CALCULATION
# ==============================

def calculate_confidence(rci, severity):

    confidence = 100

    if rci > 30:
        confidence -= 30
    elif rci > 15:
        confidence -= 15

    if severity == "Severe Anomaly":
        confidence -= 25
    elif severity == "Moderate Anomaly":
        confidence -= 10

    return max(confidence, 0)
def calculate_clci(rci, severity):

    if severity == "Severe Anomaly":
        weight = 1.6
    elif severity == "Moderate Anomaly":
        weight = 1.3
    else:
        weight = 1.0

    return round(rci * weight, 2)
def calculate_risk_breakdown(active_score, passive_score, aw, pw, hybrid_score):

    if hybrid_score == 0:
        return 0, 0

    config_part = (aw * active_score)
    behavior_part = (pw * passive_score)

    config_percent = (config_part / hybrid_score) * 100
    behavior_percent = (behavior_part / hybrid_score) * 100

    return round(config_percent, 2), round(behavior_percent, 2)
def detect_behavioral_drift(domain):

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT hybrid_score FROM trust_history
        WHERE domain = ?
        ORDER BY id DESC
        LIMIT 3
    """, (domain,))

    rows = cursor.fetchall()
    conn.close()

    if len(rows) < 3:
        return "Insufficient Data"

    latest = rows[0][0]
    middle = rows[1][0]
    oldest = rows[2][0]

    if latest < middle < oldest:
        return "Increasing Risk Drift"

    elif latest > middle > oldest:
        return "Decreasing Risk Drift"

    else:
        return "Stable Behavior"
# ==============================
# 🔥 EXPLAINABILITY ENGINE
# ==============================

def generate_reasoning(active_score, passive_score, severity, rci, confidence):

    # Configuration reasoning
    if active_score >= 85:
        config_status = "Strong security configuration detected."
    elif active_score >= 60:
        config_status = "Moderate security configuration."
    else:
        config_status = "Weak or insecure configuration."

    # Behavioral reasoning
    if severity == "Normal":
        behavior_status = "Network behavior is within expected baseline."
    elif severity == "Moderate Anomaly":
        behavior_status = "Minor deviation in network behavior detected."
    else:
        behavior_status = "Significant abnormal traffic behavior detected."

    # Cross-layer consistency reasoning
    if rci < 15:
        consistency = "High consistency between configuration and behavior."
    elif rci < 30:
        consistency = "Moderate mismatch between configuration and behavior."
    else:
        consistency = "Severe inconsistency between configuration and behavior."

    # Confidence reasoning
    if confidence >= 80:
        confidence_msg = "Trust decision has high reliability."
    elif confidence >= 50:
        confidence_msg = "Trust decision has moderate reliability."
    else:
        confidence_msg = "Trust decision has low reliability due to conflicting indicators."

    return {
        "configuration_assessment": config_status,
        "behavior_assessment": behavior_status,
        "cross_layer_consistency": consistency,
        "confidence_explanation": confidence_msg
    }

# ==============================
# LOADERS
# ==============================

def load_active_results():
    if not os.path.exists(ACTIVE_FILE):
        print("Active results file not found.")
        return []
    with open(ACTIVE_FILE, 'r') as f:
        return json.load(f)

def load_passive_result(domain):
    path = os.path.join(PASSIVE_DIR, f"{domain}.json")
    if os.path.exists(path):
        with open(path, 'r') as f:
            return json.load(f)
    return None

# ==============================
# MAIN INTEGRATION
# ==============================

def integrate():

    init_db()

    active_results = load_active_results()
    hybrid_results = []

    for active in active_results:

        domain = active["domain"]
        passive = load_passive_result(domain)

        if not passive:
            continue
        if "passive_features" not in passive:
            print(f"Skipping {domain} (missing passive_features)")
            continue
        if "z_scores" not in passive["passive_features"]:
            print(f"Skipping {domain} (missing z_scores)")
            continue
        z_scores = passive["passive_features"]["z_scores"]

        hybrid_score, severity, aw, pw = calculate_hybrid_score(
            active["active_score"],
            passive["passive_score"],
            z_scores
        )
        config_pct, behavior_pct = calculate_risk_breakdown(
            active["active_score"],
            passive["passive_score"],
            aw,
            pw,
            hybrid_score
            )

        rci = abs(active["active_score"] - passive["passive_score"])
        timestamp_now = datetime.utcnow().isoformat() + "Z"

        save_to_history(domain, timestamp_now, hybrid_score, rci)

        trend = get_trust_trend(domain)
        drift = detect_behavioral_drift(domain)
        tsi = calculate_tsi(domain)
        tvi = calculate_tvi(domain)
        volatility_status = volatility_alert(tsi)
        confidence = calculate_confidence(rci, severity)
        clci = calculate_clci(rci, severity)
        threat_category = classify_threat(hybrid_score, severity, rci)

        reasoning = generate_reasoning(
            active["active_score"],
            passive["passive_score"],
            severity,
            rci,
            confidence
        )

        hybrid_results.append({
            "domain": domain,
            "timestamp": timestamp_now,
            "active_score": active["active_score"],
            "passive_score": passive["passive_score"],
            "hybrid_score": hybrid_score,
            "trust_level": classify_trust(hybrid_score),
            "risk_consistency_index": round(rci, 2),
            "trust_trend": trend,
            "trust_stability_index": tsi,
            "trust_volatility_index": tvi,
            "confidence_score": confidence,
            "cross_layer_conflict_index": clci,
            "trust_reasoning": reasoning,
            "threat_category": threat_category,
            "behavioral_drift_status": drift,
            "volatility_status": volatility_status,
            "risk_breakdown_percentage": {
                "configuration_contribution_percent": config_pct,
                "behavior_contribution_percent": behavior_pct
                },
            "fusion_metadata": {
                "anomaly_severity": severity,
                "active_weight_used": aw,
                "passive_weight_used": pw
            }
        })
    hybrid_results.sort(key=lambda x: x["hybrid_score"])

    for rank, item in enumerate(hybrid_results, start=1):
        item["risk_rank"] = rank
    with open(OUTPUT_FILE, 'w') as f:
        json.dump(hybrid_results, f, indent=4)

    print("Hybrid integration complete!")
    print(f"Saved to: {OUTPUT_FILE}")