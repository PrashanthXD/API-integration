import argparse
import sys
from . import db


def main(argv=None):
    parser = argparse.ArgumentParser(prog="cve-rdb", description="Small CVE RDB CLI")
    sub = parser.add_subparsers(dest="cmd")

    p_init = sub.add_parser("init", help="Initialize DB")
    p_init.add_argument("--db", required=True, help="SQLite DB path")

    p_import = sub.add_parser("import", help="Import sample JSON")
    p_import.add_argument("--db", required=True)
    p_import.add_argument("--json", required=True)

    p_qy = sub.add_parser("query-year", help="List CVEs for a year")
    p_qy.add_argument("--db", required=True)
    p_qy.add_argument("--year", type=int, required=True)

    p_tv = sub.add_parser("top-vendors", help="Top vendors by affected CVEs")
    p_tv.add_argument("--db", required=True)
    p_tv.add_argument("--limit", type=int, default=10)

    p_counts = sub.add_parser("counts", help="Show counts")
    p_counts.add_argument("--db", required=True)

    args = parser.parse_args(argv)
    if args.cmd == "init":
        db.init_db(args.db)
        print(f"Initialized DB: {args.db}")
    elif args.cmd == "import":
        db.import_from_json(args.db, args.json)
        print(f"Imported JSON to DB: {args.db}")
    elif args.cmd == "query-year":
        rows = db.query_by_year(args.db, args.year)
        for r in rows:
            print(f"{r['cve_id']}: CVSS={r['cvss']} - {r['description']}")
    elif args.cmd == "top-vendors":
        rows = db.top_vendors(args.db, args.limit)
        for r in rows:
            print(f"{r['vendor']}: {r['count']}")
    elif args.cmd == "counts":
        c = db.counts(args.db)
        print(c)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
