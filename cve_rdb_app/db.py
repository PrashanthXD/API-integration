import sqlite3
import json
from typing import List, Dict, Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS vendors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vendor_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    UNIQUE(vendor_id, name),
    FOREIGN KEY(vendor_id) REFERENCES vendors(id)
);

CREATE TABLE IF NOT EXISTS cves (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT UNIQUE NOT NULL,
    identifier TEXT,
    description TEXT,
    year INTEGER,
    cvss REAL,
    published TEXT,
    last_modified TEXT,
    status TEXT
);

CREATE TABLE IF NOT EXISTS cve_product (
    cve_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    PRIMARY KEY(cve_id, product_id),
    FOREIGN KEY(cve_id) REFERENCES cves(id),
    FOREIGN KEY(product_id) REFERENCES products(id)
);

CREATE TABLE IF NOT EXISTS references_table (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id INTEGER NOT NULL,
    url TEXT NOT NULL,
    FOREIGN KEY(cve_id) REFERENCES cves(id)
);
"""


def connect(path: str):
    return sqlite3.connect(path)


def init_db(path: str):
    conn = connect(path)
    try:
        cur = conn.cursor()
        cur.executescript(SCHEMA)
        conn.commit()
        # ensure optional columns exist for backwards compatibility
        _ensure_cve_columns(conn)
    finally:
        conn.close()


def _ensure_cve_columns(conn):
    """Ensure newer optional columns exist on the cves table (migration safe)."""
    cur = conn.cursor()
    cur.execute("PRAGMA table_info(cves)")
    existing = {row[1] for row in cur.fetchall()}  # column name is at index 1
    needed = {
        "identifier": "TEXT",
        "last_modified": "TEXT",
        "status": "TEXT",
    }
    for col, typ in needed.items():
        if col not in existing:
            try:
                cur.execute(f"ALTER TABLE cves ADD COLUMN {col} {typ}")
            except Exception:
                # ignore if cannot add
                pass
    conn.commit()


def _get_or_create_vendor(conn, name: str):
    cur = conn.cursor()
    cur.execute("SELECT id FROM vendors WHERE name = ?", (name,))
    row = cur.fetchone()
    if row:
        return row[0]
    cur.execute("INSERT INTO vendors(name) VALUES (?)", (name,))
    return cur.lastrowid


def _get_or_create_product(conn, vendor_id: int, name: str):
    cur = conn.cursor()
    cur.execute("SELECT id FROM products WHERE vendor_id = ? AND name = ?", (vendor_id, name))
    row = cur.fetchone()
    if row:
        return row[0]
    cur.execute("INSERT INTO products(vendor_id, name) VALUES (?, ?)", (vendor_id, name))
    return cur.lastrowid


def import_from_json(db_path: str, json_path: str):
    # use utf-8-sig to tolerate files that include a BOM (created by some editors/tools)
    with open(json_path, "r", encoding="utf-8-sig") as f:
        data = json.load(f)

    conn = connect(db_path)
    try:
        cur = conn.cursor()
        for item in data:
            cve_id = item.get("cve_id")
            identifier = item.get("identifier")
            desc = item.get("description")
            year = item.get("year")
            cvss = item.get("cvss")
            published = item.get("published")
            last_modified = item.get("last_modified")
            status = item.get("status")
            cur.execute("INSERT OR IGNORE INTO cves(cve_id, identifier, description, year, cvss, published, last_modified, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        (cve_id, identifier, desc, year, cvss, published, last_modified, status))
            cur.execute("SELECT id FROM cves WHERE cve_id = ?", (cve_id,))
            cve_row = cur.fetchone()
            cve_row_id = cve_row[0]

            # products: list of {vendor, product}
            for p in item.get("products", []):
                vendor = p.get("vendor")
                product = p.get("product")
                vendor_id = _get_or_create_vendor(conn, vendor)
                product_id = _get_or_create_product(conn, vendor_id, product)
                cur.execute("INSERT OR IGNORE INTO cve_product(cve_id, product_id) VALUES (?, ?)",
                            (cve_row_id, product_id))

            # references
            for url in item.get("references", []):
                cur.execute("INSERT INTO references_table(cve_id, url) VALUES (?, ?)", (cve_row_id, url))

        conn.commit()
    finally:
        conn.close()


def query_by_year(db_path: str, year: int) -> List[Dict[str, Any]]:
    conn = connect(db_path)
    try:
        cur = conn.cursor()
        # SQLite doesn't support NULLS LAST, so rely on ordering; keep cvss desc
        cur.execute("SELECT cve_id, description, cvss FROM cves WHERE year = ? ORDER BY cvss DESC", (year,))
        rows = cur.fetchall()
        return [{"cve_id": r[0], "description": r[1], "cvss": r[2]} for r in rows]
    finally:
        conn.close()


def get_total_cves(db_path: str) -> int:
    conn = connect(db_path)
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM cves")
        return cur.fetchone()[0]
    finally:
        conn.close()


def query_cves(db_path: str, limit: int = 10, offset: int = 0, sort: str = "desc") -> List[Dict[str, Any]]:
    """Return paginated CVE rows. sort should be 'desc' or 'asc' for published date.
    Returns fields suitable for the list view: cve_id, identifier, published, last_modified, status."""
    conn = connect(db_path)
    try:
        cur = conn.cursor()
        if sort == "desc":
            order = "CASE WHEN published IS NULL THEN 1 ELSE 0 END, published DESC"
        else:
            order = "CASE WHEN published IS NULL THEN 1 ELSE 0 END, published ASC"
        sql = f"SELECT cve_id, identifier, published, last_modified, status FROM cves ORDER BY {order} LIMIT ? OFFSET ?"
        cur.execute(sql, (limit, offset))
        rows = cur.fetchall()
        return [{"cve_id": r[0], "identifier": r[1], "published": r[2], "last_modified": r[3], "status": r[4]} for r in rows]
    finally:
        conn.close()


def get_cve_by_id(db_path: str, cve_id: str) -> Dict[str, Any]:
    """Return a CVE record with related products/vendors and references."""
    conn = connect(db_path)
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, cve_id, identifier, description, cvss, year, published, last_modified, status FROM cves WHERE cve_id = ?", (cve_id,))
        r = cur.fetchone()
        if not r:
            return None
        cid = r[0]
        result = {
            "cve_id": r[1],
            "identifier": r[2],
            "description": r[3],
            "cvss": r[4],
            "year": r[5],
            "published": r[6],
            "last_modified": r[7],
            "status": r[8],
            "products": [],
            "references": []
        }

        cur.execute(
            "SELECT v.name, p.name FROM products p JOIN vendors v ON p.vendor_id = v.id JOIN cve_product cp ON cp.product_id = p.id WHERE cp.cve_id = ?",
            (cid,)
        )
        prod_rows = cur.fetchall()
        for pv in prod_rows:
            result["products"].append({"vendor": pv[0], "product": pv[1]})

        cur.execute("SELECT url FROM references_table WHERE cve_id = ?", (cid,))
        refs = cur.fetchall()
        for r0 in refs:
            result["references"].append(r0[0])

        return result
    finally:
        conn.close()


def top_vendors(db_path: str, limit: int = 10) -> List[Dict[str, Any]]:
    conn = connect(db_path)
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT v.name, COUNT(*) as cnt FROM vendors v JOIN products p ON p.vendor_id = v.id JOIN cve_product cp ON cp.product_id = p.id GROUP BY v.id ORDER BY cnt DESC LIMIT ?",
            (limit,))
        rows = cur.fetchall()
        return [{"vendor": r[0], "count": r[1]} for r in rows]
    finally:
        conn.close()


def counts(db_path: str) -> Dict[str, int]:
    conn = connect(db_path)
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM cves")
        cves = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM vendors")
        vendors = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM products")
        products = cur.fetchone()[0]
        return {"cves": cves, "vendors": vendors, "products": products}
    finally:
        conn.close()
