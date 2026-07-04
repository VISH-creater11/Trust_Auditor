piimport sys
import subprocess
import os

def run_full_pipeline(domain):

    print(f"Starting full audit for {domain}")

    # STEP 1: Capture
    subprocess.run([
        sys.executable,
        r"E:\trust-auditor\passive_engine\capture_script.py",
        domain
    ])

    # STEP 2: Passive
    pcap_file = r"E:\trust-auditor\passive_engine\pcaps\\" + domain.replace(".", "_") + ".pcapng"

    if os.path.exists(pcap_file):
        subprocess.run([
            sys.executable,
            r"E:\trust-auditor\passive_engine\main.py",
            pcap_file,
            domain
        ])

    # STEP 3: Active (IMPORTANT FIX)
    sys.path.append(r"E:\trust-auditor\active_engine")
    from active_audit import run_audit
    run_audit(domain)

    # STEP 4: Fusion
    subprocess.run([
        sys.executable,
        r"E:\trust-auditor\integration\hybrid_fusion.py"
    ])

    print("Pipeline complete.")