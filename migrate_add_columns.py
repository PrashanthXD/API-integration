import sqlite3
import os

DB = os.path.join(os.getcwd(), "sample.db")
print("DB:", DB)
if not os.path.exists(DB):
    print("sample.db not found — nothing to migrate. Run the app to create DB or import sample data.")
    raise SystemExit(0)

conn = sqlite3.connect(DB)
cur = conn.cursor()
cols = [("identifier","TEXT"),("last_modified","TEXT"),("status","TEXT")]
for col,typ in cols:
    try:
        cur.execute(f"ALTER TABLE cves ADD COLUMN {col} {typ}")
        print(f"Added column: {col}")
    except sqlite3.OperationalError as e:
        # Likely column already exists
        print(f"Skipping {col}: {e}")

conn.commit()
conn.close()
print("Migration complete.")
