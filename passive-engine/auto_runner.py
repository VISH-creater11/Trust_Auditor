import os
import time
import subprocess
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

SITES_FILE = "../shared_schema/sites.txt"
PCAP_FOLDER = "pcaps"

INTERFACE = "5"   # <-- YOUR WIFI INTERFACE NUMBER
CAPTURE_DURATION = 15  # increase to 15 seconds


if not os.path.exists(PCAP_FOLDER):
    os.makedirs(PCAP_FOLDER)


def capture_domain(domain):
    safe_name = domain.replace(".", "_")
    pcap_path = os.path.join(PCAP_FOLDER, f"{safe_name}.pcapng")

    print(f"\nCapturing: {domain}")

    # Start tshark
    tshark_cmd = [
        "tshark",
        "-i", INTERFACE,
        "-a", f"duration:{CAPTURE_DURATION}",
        "-w", pcap_path
    ]

    process = subprocess.Popen(tshark_cmd)

    # Launch browser
    options = Options()
    options.add_argument("--headless")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")

    driver = webdriver.Chrome(options=options)

    try:
        driver.get("https://" + domain)
        time.sleep(10)
    except:
        pass

    driver.quit()

    # Wait for tshark to finish cleanly
    process.wait()

    # Verify file size
    if os.path.exists(pcap_path):
        size = os.path.getsize(pcap_path)
        if size < 5000:  # less than 5KB = bad capture
            print("❌ Too small, deleting:", pcap_path)
            os.remove(pcap_path)
        else:
            print("✅ Saved:", pcap_path)


with open(SITES_FILE) as f:
    sites = [line.strip() for line in f if line.strip()]

print("Total sites:", len(sites))

for site in sites:
    capture_domain(site)

print("\nAll captures completed.")