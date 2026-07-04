import csv

INPUT_FILE = "top-1m.csv"
OUTPUT_FILE = "../shared_schema/sites.txt"

LIMIT = 100   # Top 100 sites

with open(INPUT_FILE, newline='', encoding="utf-8") as f:
    reader = csv.reader(f)

    sites = []

    for i, row in enumerate(reader):
        if i >= LIMIT:
            break

        domain = row[1]   # Domain column
        sites.append(domain)


with open(OUTPUT_FILE, "w") as f:
    for site in sites:
        f.write(site + "\n")


print("Saved", len(sites), "sites to sites.txt")
