from flask import Flask, render_template, request, url_for, redirect
import os
from . import db


def create_app(db_path: str = None):
    app = Flask(__name__, template_folder=os.path.join(os.path.dirname(__file__), "templates"))
    # default DB path if not provided
    if db_path:
        app.config["DB_PATH"] = db_path
    else:
        app.config["DB_PATH"] = os.path.join(os.getcwd(), "sample.db")

    @app.route("/")
    def index():
        return redirect(url_for("cves_list"))

    @app.route("/cves/list")
    def cves_list():
        try:
            page = int(request.args.get("page", 1))
        except ValueError:
            page = 1
        try:
            per_page = int(request.args.get("per_page", 10))
        except ValueError:
            per_page = 10
        sort = request.args.get("sort", "desc")

        total = db.get_total_cves(app.config["DB_PATH"])
        offset = (page - 1) * per_page
        rows = db.query_cves(app.config["DB_PATH"], limit=per_page, offset=offset, sort=sort)

        # compute pagination helpers
        last_page = max(1, (total + per_page - 1) // per_page)

        return render_template("cves_list.html", rows=rows, total=total, page=page, per_page=per_page, last_page=last_page, sort=sort)

    @app.route("/cves/<cve_id>")
    def cve_detail(cve_id):
        # fetch by CVE id
        row = db.get_cve_by_id(app.config["DB_PATH"], cve_id)
        if not row:
            return render_template("cve_not_found.html", cve_id=cve_id), 404
        return render_template("cve_detail.html", cve=row)

    return app


if __name__ == "__main__":
    # quick run for development: create DB if missing and import sample data
    default_db = os.path.join(os.getcwd(), "sample.db")
    if not os.path.exists(default_db):
        db.init_db(default_db)
        sample_json = os.path.join(os.path.dirname(__file__), "sample_data", "sample_cves.json")
        db.import_from_json(default_db, sample_json)
    app = create_app(default_db)
    app.run(host="127.0.0.1", port=5000, debug=True)
