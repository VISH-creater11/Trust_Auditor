import pandas as pd
import os

# ===== CONFIG =====
DATASET_PATH = r"E:\trust-auditor\active_engine\top-1m.csv"
OUTPUT_FILE = r"E:\trust-auditor\domain_list_900.txt"
NUM_DOMAINS = 900
RANDOM_SEED = 42   # ensures reproducibility

# ===== LOAD DATASET =====
if not os.path.exists(DATASET_PATH):
    print("Dataset not found.")
    exit()

df = pd.read_csv(DATASET_PATH, header=None, names=["rank", "domain"])

if len(df) < NUM_DOMAINS:
    print("Dataset smaller than requested sample size.")
    exit()

# ===== RANDOM SAMPLE =====
df_sample = df.sample(n=NUM_DOMAINS, random_state=RANDOM_SEED)

# ===== SAVE DOMAIN LIST =====
with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    for domain in df_sample["domain"]:
        f.write(domain.strip() + "\n")

print("900-domain subset created successfully.")
print("Saved to:", OUTPUT_FILE)
print("Total domains:", len(df_sample))