from tabulate import tabulate
import sqlite3

DB_PATH = r"E:\trust-auditor\trust_history.db"

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

cursor.execute("SELECT * FROM trust_history")
rows = cursor.fetchall()

if rows:
    print(tabulate(
        rows,
        headers=["ID", "Domain", "Timestamp", "Hybrid Score", "RCI"],
        tablefmt="grid"
    ))
else:
    print("No rows found in trust_history table.")

conn.close()