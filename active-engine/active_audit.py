import socket
import ssl
import requests
import json
import os
import re
from datetime import datetime


# ==================================================
# CONFIGURATION
# ==================================================

PASSIVE_DIR = r"E:\trust-auditor\passive_output"
OUTPUT_DIR = r"E:\trust-auditor\active_output"
output_file = r"E:\trust-auditor\active_output\active_audit_master.json"
DB_FILE = r"E:\trust-auditor\trust_history.db"

if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)


# ==================================================
# SSL CERTIFICATE CHECK
# ==================================================

def get_certificate_info(domain):
    """Performs SSL handshake to get certificate and TLS details."""
    try:
        context = ssl.create_default_context()

        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:

                cert = ssock.getpeercert()
                tls_version = ssock.version()

                exp_date_str = cert['notAfter']
                exp_date = datetime.strptime(
                    exp_date_str,
                    '%b %d %H:%M:%S %Y %Z'
                )

                days_to_expire = (exp_date - datetime.utcnow()).days

                return True, days_to_expire, tls_version

    except Exception:
        return False, 0, "Unknown"


# ==================================================
# ACTIVE AUDIT FUNCTION
# ==================================================

def audit_domain(domain):

    features = {
        "https_valid": False,
        "certificate_valid": False,
        "certificate_expiry_days": 0,
        "tls_version": "Unknown",
        "hsts_enabled": False,
        "redirects_count": 0,
        "server_header_leak": False,
        "software_version_exposed": "None",
        "security_headers_present": [],
        "open_ports_detected": [],
        "phishing_indicators": 0
    }

    # ------------------------------
    # 1. Port Checking
    # ------------------------------

    for port in [80, 443]:
        try:
            with socket.create_connection((domain, port), timeout=2):
                features["open_ports_detected"].append(port)
        except:
            pass

    # ------------------------------
    # 2. SSL/TLS Handshake
    # ------------------------------

    cert_valid, expiry, tls_ver = get_certificate_info(domain)

    features["certificate_valid"] = cert_valid
    features["certificate_expiry_days"] = expiry
    features["tls_version"] = tls_ver

    # ------------------------------
    # 3. HTTP Probe
    # ------------------------------

    try:
        url = (
            f"https://{domain}"
            if 443 in features["open_ports_detected"]
            else f"http://{domain}"
        )

        headers = {
            "User-Agent": "Mozilla/5.0 WebSecurityAuditor/1.0"
        }

        response = requests.get(
            url,
            timeout=5,
            headers=headers,
            verify=True,
            allow_redirects=True
        )

        if response.url.startswith("https"):
            features["https_valid"] = True

        features["redirects_count"] = len(response.history)

        target_headers = [
            "Content-Security-Policy",
            "X-Frame-Options",
            "Strict-Transport-Security",
            "X-Content-Type-Options",
            "Referrer-Policy"
        ]

        features["security_headers_present"] = [
            h for h in target_headers if h in response.headers
        ]

        features["hsts_enabled"] = (
            "Strict-Transport-Security" in response.headers
        )

        server_val = response.headers.get("Server", "None")
        features["software_version_exposed"] = server_val

        if server_val != "None" and re.search(r"\d", server_val):
            features["server_header_leak"] = True

    except Exception:
        pass

    # ------------------------------
    # 4. Risk Flags
    # ------------------------------

    risk_flags = {
        "expired_cert":
            features["certificate_expiry_days"] <= 0
            and features["certificate_valid"],

        "weak_tls":
            features["tls_version"] in ["TLSv1", "TLSv1.1", "SSLv3"],

        "missing_hsts":
            not features["hsts_enabled"],

        "info_disclosure":
            features["server_header_leak"],

        "suspicious_redirect":
            features["redirects_count"] > 3,

        "insecure_ports":
            80 in features["open_ports_detected"]
            and 443 not in features["open_ports_detected"]
    }

    # ------------------------------
    # 5. Scoring Logic
    # ------------------------------

    score = 100.0

    if not features["https_valid"]:
        score -= 30

    if not features["certificate_valid"]:
        score -= 20

    if risk_flags["missing_hsts"]:
        score -= 10

    if risk_flags["info_disclosure"]:
        score -= 10

    if risk_flags["weak_tls"]:
        score -= 10

    if len(features["security_headers_present"]) < 2:
        score -= 10

    return {
        "domain": domain,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "active_score": round(max(0.0, score), 2),
        "active_features": features,
        "risk_flags": risk_flags
    }


def run_audit(domain):
    """Run audit for a single domain - for backend integration"""
    result = audit_domain(domain)
    
    # Save to master file
    if not os.path.exists(os.path.dirname(output_file)):
        os.makedirs(os.path.dirname(output_file))
    
    # Load existing data
    if os.path.exists(output_file):
        with open(output_file, 'r') as f:
            try:
                existing_data = json.load(f)
                if isinstance(existing_data, dict) and "scans" in existing_data:
                    scans = existing_data["scans"]
                else:
                    scans = existing_data if isinstance(existing_data, list) else []
            except:
                scans = []
    else:
        scans = []
    
    # Add new scan
    scans.append(result)
    
    # Save updated data
    with open(output_file, 'w') as f:
        json.dump({"scans": scans}, f, indent=4)
    
    return result


# ==================================================
# MAIN EXECUTION
# ==================================================

if __name__ == "__main__":

    if not os.path.exists(PASSIVE_DIR):
        print("Passive output directory not found.")
        exit()

    domains = [
        filename.replace(".json", "")
        for filename in os.listdir(PASSIVE_DIR)
        if filename.endswith(".json")
    ]

    if not domains:
        print("No passive JSON files found.")
        exit()

    print(f"Starting Active Audit on {len(domains)} domains...\n")

    for i, domain in enumerate(domains, start=1):
        print(f"[{i}/{len(domains)}] Auditing: {domain}")

        result = audit_domain(domain)

        # Create safe filename
        safe_name = domain.replace(".", "_")

        output_file = os.path.join(
            OUTPUT_DIR,
            f"{safe_name}_active_audit_v1.json"
        )

        # Save separate JSON file
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=4)

        print(f"Saved: {output_file}")

    print("\nAudit complete!")
    print("All domain reports saved separately.")