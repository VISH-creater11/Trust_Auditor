import os
import sys
import time
import subprocess
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

# ======================================
# CONFIG
# ======================================

DOMAIN_LIST_FILE = r"E:\trust-auditor\domain_list_900.txt"
PCAP_FOLDER = r"E:\trust-auditor\passive_engine\pcaps"
INTERFACE = "5"        # <-- your WiFi interface number from tshark -D
CAPTURE_DURATION = 15  # seconds per domain
LIMIT = 900      # change to 5 / 50 / 500 as needed


# ======================================
# PREPARE FOLDER
# ======================================

if not os.path.exists(PCAP_FOLDER):
    os.makedirs(PCAP_FOLDER)


# ======================================
# CAPTURE FUNCTION
# ======================================

def capture_domain(domain):

    safe_name = domain.replace(".", "_")
    pcap_path = os.path.join(PCAP_FOLDER, f"{safe_name}.pcapng")

    print("\n=================================")
    print("Capturing:", domain)

    # Start tshark capture
    tshark_cmd = [
        "tshark",
        "-i", INTERFACE,
        "-a", f"duration:{CAPTURE_DURATION}",
        "-w", pcap_path
    ]

    process = subprocess.Popen(tshark_cmd)

    # Launch headless Chrome
    options = Options()
    options.add_argument("--headless")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")

    driver = webdriver.Chrome(options=options)

    try:
        driver.set_page_load_timeout(15)
        driver.get("https://" + domain)
        time.sleep(10)
    except:
        pass

    driver.quit()

    # Wait for tshark to finish cleanly
    process.wait()

    # Validate file
    if os.path.exists(pcap_path):
        size = os.path.getsize(pcap_path)

        if size < 5000:
            print("❌ Capture too small (", size, "bytes ) → deleting")
            os.remove(pcap_path)
        else:
            print("✅ Saved:", pcap_path, "| Size:", size, "bytes")
    else:
        print("❌ Capture failed:", domain)


# ======================================
# MAIN EXECUTION
# ======================================

# Support both command line domain input and domain list file
if len(sys.argv) > 1:
    # Single domain mode
    domain = sys.argv[1]
    print(f"Capturing traffic for: {domain}")
    capture_domain(domain)
    print("\nCapture completed.")
else:
    # Batch mode from domain list file
    if not os.path.exists(DOMAIN_LIST_FILE):
        print("Domain list file not found:", DOMAIN_LIST_FILE)
        print("Usage: python capture_script.py <domain> for single domain")
        exit()

    with open(DOMAIN_LIST_FILE, "r", encoding="utf-8") as f:
        sites = [line.strip() for line in f if line.strip()]

    # Apply limit
    sites = sites[:LIMIT]

    print("Total sites to capture:", len(sites))

    for site in sites:
        capture_domain(site)

    print("\nAll captures completed.")