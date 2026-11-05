"""Tests for the local UI server, read model, and action registry."""
from __future__ import annotations

import http.client
import json
import sys
import threading
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from vulnforge.config import load_config  # noqa: E402
from vulnforge.ui import readmodel  # noqa: E402
from vulnforge.ui.jobs import (  # noqa: E402
    JobManager,
    build_command,
    validate_request,
)
from vulnforge.ui.server import create_server  # noqa: E402

CVE = "CVE-2026-116078"


def _fake_runner(argv: list[str], emit) -> int:
    emit("fake command: " + " ".join(argv))
    return 0


class UIServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cfg = load_config(REPO_ROOT)
        cls.paths = cls.cfg.paths()

    def start(self, *, read_only: bool = False):
        jobs = JobManager(self.cfg, self.paths, runner=_fake_runner)
        server = create_server(
            self.cfg,
            self.paths,
            port=0,
            read_only=read_only,
            job_manager=jobs,
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.shutdown)
        return server

    def request(self, server, method: str, path: str, *, body=None, headers=None):
        host, port = server.server_address[:2]
        connection = http.client.HTTPConnection(host, port, timeout=10)
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        payload = response.read()
        result = (response.status, dict(response.getheaders()), payload)
        connection.close()
        return result

    def json_request(self, server, method: str, path: str, *, body=None, headers=None):
        status, response_headers, payload = self.request(
            server, method, path, body=body, headers=headers
        )
        data = json.loads(payload) if payload else None
        return status, response_headers, data

    def test_session_and_status(self):
        server = self.start()
        status, headers, session = self.json_request(server, "GET", "/api/session")
        self.assertEqual(status, 200)
        self.assertIn("csrf_token", session)
        self.assertFalse(session["read_only"])
        self.assertIn("default-src 'self'", headers["Content-Security-Policy"])
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")

        status, _, payload = self.json_request(server, "GET", "/api/status")
        self.assertEqual(status, 200)
        self.assertEqual(payload["counts"]["packages"], 2)
        self.assertGreaterEqual(payload["counts"]["advisories"], 1)

    def test_package_detail_and_report_download(self):
        server = self.start()
        status, _, payload = self.json_request(server, "GET", f"/api/packages/{CVE}")
        self.assertEqual(status, 200)
        self.assertEqual(payload["summary"]["cve"], CVE)
        self.assertTrue(payload["validation"]["targets"]["vulnerable"]["metrics"])
        self.assertIn("health", payload)

        status, headers, body = self.request(
            server, "GET", f"/api/packages/{CVE}/report.md"
        )
        self.assertEqual(status, 200)
        self.assertIn("attachment", headers["Content-Disposition"])
        self.assertIn(b"CVE-2026-116078", body)

    def test_unknown_package_and_api(self):
        server = self.start()
        status, _, payload = self.json_request(
            server, "GET", "/api/packages/CVE-2099-000000"
        )
        self.assertEqual(status, 404)
        self.assertIn("unknown package", payload["error"])
        status, _, _ = self.json_request(server, "GET", "/api/nope")
        self.assertEqual(status, 404)

    def test_static_index_and_traversal_rejected(self):
        server = self.start()
        status, headers, body = self.request(server, "GET", "/")
        self.assertEqual(status, 200)
        self.assertIn("text/html", headers["Content-Type"])
        self.assertIn(b"VulnForge", body)
        status, _, _ = self.request(
            server, "GET", "/static/../../../../etc/passwd"
        )
        self.assertEqual(status, 404)

    def test_non_loopback_host_rejected(self):
        server = self.start()
        status, _, _ = self.request(server, "GET", "/api/session", headers={"Host": "evil.example"})
        self.assertEqual(status, 403)

    def test_read_only_blocks_post(self):
        server = self.start(read_only=True)
        body = json.dumps({"action": "package_validate", "cve": CVE})
        status, _, payload = self.json_request(
            server,
            "POST",
            "/api/jobs",
            body=body,
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(status, 403)
        self.assertIn("read-only", payload["error"])

    def test_post_requires_csrf(self):
        server = self.start()
        body = json.dumps({"action": "package_validate", "cve": CVE})
        status, _, payload = self.json_request(
            server,
            "POST",
            "/api/jobs",
            body=body,
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(status, 403)
        self.assertIn("CSRF", payload["error"])

    def test_post_runs_allowlisted_job(self):
        server = self.start()
        _, _, session = self.json_request(server, "GET", "/api/session")
        body = json.dumps({"action": "package_validate", "cve": CVE})
        status, _, job = self.json_request(
            server,
            "POST",
            "/api/jobs",
            body=body,
            headers={
                "Content-Type": "application/json",
                "X-VulnForge-CSRF": session["csrf_token"],
            },
        )
        self.assertEqual(status, 202)
        self.assertEqual(job["action"], "package_validate")
        job_id = job["id"]

        deadline = time.time() + 5
        while time.time() < deadline:
            _, _, result = self.json_request(server, "GET", f"/api/jobs/{job_id}")
            if result["status"] in ("succeeded", "failed"):
                break
            time.sleep(0.02)
        self.assertEqual(result["status"], "succeeded")
        self.assertEqual(result["returncode"], 0)
        self.assertIn("fake command", result["log"][0])

    def test_post_rejects_unknown_action_and_bad_cve(self):
        server = self.start()
        _, _, session = self.json_request(server, "GET", "/api/session")
        headers = {
            "Content-Type": "application/json",
            "X-VulnForge-CSRF": session["csrf_token"],
        }
        status, _, payload = self.json_request(
            server,
            "POST",
            "/api/jobs",
            body=json.dumps({"action": "rm_rf", "cve": CVE}),
            headers=headers,
        )
        self.assertEqual(status, 400)
        self.assertIn("unknown action", payload["error"])

        status, _, payload = self.json_request(
            server,
            "POST",
            "/api/jobs",
            body=json.dumps({"action": "package_validate", "cve": "CVE-2099-000000"}),
            headers=headers,
        )
        self.assertEqual(status, 400)
        self.assertIn("unknown package", payload["error"])


class ActionRegistryTests(unittest.TestCase):
    def setUp(self):
        self.known = {CVE}

    def test_command_builders(self):
        self.assertEqual(
            build_command("report", None, {}), ["report", "--all"]
        )
        self.assertEqual(
            build_command("report", CVE, {}), ["report", CVE]
        )
        self.assertEqual(
            build_command("detect", None, {}), ["detect", "--all"]
        )
        self.assertEqual(
            build_command("package_validate", None, {}),
            ["package", "validate", "--all"],
        )
        self.assertEqual(
            build_command("validate", CVE, {"runs": 5}),
            ["validate", CVE, "--runs", "5"],
        )
        self.assertEqual(
            build_command("poc_run", CVE, {"role": "patched"}),
            ["poc", "run", CVE, "--role", "patched"],
        )

    def test_validation_rejects_bad_input(self):
        with self.assertRaises(ValueError):
            validate_request("unknown", CVE, {}, self.known)
        with self.assertRaises(ValueError):
            validate_request("validate", CVE, {"runs": 99}, self.known)
        with self.assertRaises(ValueError):
            validate_request("poc_run", CVE, {"role": "root"}, self.known)
        with self.assertRaises(ValueError):
            validate_request("triage_check", CVE, {}, self.known)
        with self.assertRaises(ValueError):
            validate_request("validate", "CVE-2099-000000", {}, self.known)


class ReadModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cfg = load_config(REPO_ROOT)
        cls.paths = cls.cfg.paths()

    def test_portfolio_counts(self):
        data = readmodel.portfolio(self.cfg, self.paths)
        self.assertEqual(data["counts"]["packages"], 2)
        self.assertEqual(
            {item["cve"] for item in data["packages"]},
            {"CVE-2026-111101", CVE},
        )

    def test_package_detail_has_evidence(self):
        detail = readmodel.package_detail(self.cfg, self.paths, CVE)
        self.assertEqual(detail["summary"]["verdict"], "CONFIRMED")
        self.assertEqual(detail["detection"]["result"], "TRIGGERED")
        self.assertIsInstance(detail["health"], list)

    def test_matrix_has_all_advisories(self):
        self.assertEqual(len(readmodel.matrix(self.paths)), 24)


if __name__ == "__main__":
    unittest.main(verbosity=2)
