import sqlite3
import json
import os

DB = os.path.join(os.getcwd(), "sample.db")
JSON = os.path.join(os.getcwd(), "cve_rdb_app", "sample_data", "sample_cves.json")

if not os.path.exists(DB):
    print("sample.db not found; run the importer or start the app to create it first.")
    raise SystemExit(1)

if not os.path.exists(JSON):
    print("sample JSON not found; aborting")
    raise SystemExit(1)

with open(JSON, 'r', encoding='utf-8') as f:
    data = json.load(f)

conn = sqlite3.connect(DB)
cur = conn.cursor()
updated = 0
inserted = 0
for item in data:
    cve_id = item.get('cve_id')
    identifier = item.get('identifier')
    desc = item.get('description')
    year = item.get('year')
    cvss = item.get('cvss')
    published = item.get('published')
    last_modified = item.get('last_modified')
    status = item.get('status')

    # check existence
    cur.execute('SELECT id FROM cves WHERE cve_id = ?', (cve_id,))
    row = cur.fetchone()
    if row:
        cid = row[0]
        cur.execute(
            'UPDATE cves SET identifier = ?, description = ?, year = ?, cvss = ?, published = ?, last_modified = ?, status = ? WHERE id = ?',
            (identifier, desc, year, cvss, published, last_modified, status, cid)
        )
        updated += 1
    else:
        cur.execute(
            'INSERT INTO cves (cve_id, identifier, description, year, cvss, published, last_modified, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            (cve_id, identifier, desc, year, cvss, published, last_modified, status)
        )
        inserted += 1

conn.commit()
conn.close()
print(f"Upsert complete. Inserted: {inserted}, Updated: {updated}")
