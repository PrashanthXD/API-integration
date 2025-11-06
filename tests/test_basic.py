
import os
import tempfile
import unittest
from cve_rdb_app import db


class TestBasic(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.dbpath = os.path.join(self.tmpdir.name, "test.db")
        db.init_db(self.dbpath)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_import_and_counts(self):
        sample = os.path.join(os.path.dirname(__file__), "..", "cve_rdb_app", "sample_data", "sample_cves.json")
        sample = os.path.normpath(sample)
        db.import_from_json(self.dbpath, sample)
        counts = db.counts(self.dbpath)
        # sample set may contain 3 or more CVEs; assert at least 3 so tests remain stable
        self.assertGreaterEqual(counts["cves"], 3)
        self.assertGreaterEqual(counts["vendors"], 2)
        self.assertGreaterEqual(counts["products"], 3)

    def test_query_by_year(self):
        sample = os.path.join(os.path.dirname(__file__), "..", "cve_rdb_app", "sample_data", "sample_cves.json")
        sample = os.path.normpath(sample)
        db.import_from_json(self.dbpath, sample)
        rows = db.query_by_year(self.dbpath, 2021)
        cve_ids = [r["cve_id"] for r in rows]
        self.assertIn("CVE-2021-0001", cve_ids)
        self.assertIn("CVE-2021-0002", cve_ids)

    def test_top_vendors(self):
        sample = os.path.join(os.path.dirname(__file__), "..", "cve_rdb_app", "sample_data", "sample_cves.json")
        sample = os.path.normpath(sample)
        db.import_from_json(self.dbpath, sample)
        top = db.top_vendors(self.dbpath, limit=10)
        # ExampleCorp should appear
        vendors = [v["vendor"] for v in top]
        self.assertIn("ExampleCorp", vendors)


if __name__ == "__main__":
    unittest.main()
