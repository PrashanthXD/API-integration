
# CVE RDB APP — runnable CVE RDB demo

A small, opinionated demo that models CVE (NVD) data in SQLite and exposes a tiny web UI and CLI for querying. It's designed as a compact, runnable assessment project you can extend.

Why this repo
- Implements a minimal normalized schema (vendors, products, cves, product mappings, references).
- Provides a small web UI at `/cves/list` with server-side pagination, page-size selector, and date sorting.
- Includes a CLI for quick DB operations and a tiny test suite.

Quick features
- Local SQLite DB (no external deps required for core logic)
- JSON importer for sample CVE data
- Web UI (Flask) with:
	- Total records count
	- Results per page (10 / 50 / 100)
	- Server-side pagination and sorting by publish date
	- Clickable CVE IDs -> detail view (products + references)

Prerequisites
- Python 3.8+ (tested with 3.11/3.13)
- (Optional) `pip` for installing `Flask` (used by the web UI)

Getting started (Windows PowerShell)
1. Open PowerShell and cd to the project root:

```powershell
cd "c:\Users\ben\trainingfiles\CVE API"
```

2. (Optional) create and activate a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

3. Install web dependencies (only required for the web UI):

```powershell
pip install -r requirements.txt
```

4. Initialize DB and import the sample data (creates `sample.db`):

```powershell
python -m cve_rdb_app.cli init --db sample.db
python -m cve_rdb_app.cli import --db sample.db --json "cve_rdb_app/sample_data/sample_cves.json"
```

5. Run the web UI (development server):

```powershell
python -m cve_rdb_app.web
```

Open: http://127.0.0.1:5000/cves/list

Command-line examples

```powershell
# List CVEs for a year
python -m cve_rdb_app.cli query-year --db sample.db --year 2021

# Top vendors
python -m cve_rdb_app.cli top-vendors --db sample.db --limit 5

# Counts
python -m cve_rdb_app.cli counts --db sample.db
```

Running tests

```powershell
python -m unittest discover -s tests
```

Project layout
```
cve_rdb_app/
	├─ db.py            # SQLite schema, importers, query helpers
	├─ cli.py           # CLI entry points
	├─ web.py           # Flask app (route: /cves/list)
	└─ sample_data/     # sample_cves.json (demo data)
tests/                # unit tests
README.md             # this file
```

Notes & next steps
- The repo uses a local SQLite file (`sample.db`) by default. For production or multi-user use, migrate to a server DB (Postgres) and a WSGI server (Waitress/gunicorn) behind a reverse proxy.
- Want it public? I can quickly expose the running server via ngrok for demos, or help deploy to Render/Heroku for a stable public URL.

Contact / Help
- Tell me which enhancement you want next: package as ZIP, deploy to Render, add NVD JSON importer, or polish the UI.

---
Lightweight demo — built to be easy to run and extend.
