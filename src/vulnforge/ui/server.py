"""Lightweight stdlib HTTP server for the VulnForge UI."""
from __future__ import annotations

import json
import mimetypes
import secrets
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ..config import FactoryConfig
from ..packages import discover_package_dirs
from ..paths import Paths
from . import readmodel
from .jobs import ACTIONS, JobManager, actions_payload

STATIC_DIR = Path(__file__).parent / "static"
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
MAX_BODY_BYTES = 1_000_000


class UIApp:
    def __init__(
        self,
        cfg: FactoryConfig,
        paths: Paths,
        *,
        read_only: bool = False,
        job_manager: JobManager | None = None,
        static_dir: Path | None = None,
    ):
        self.cfg = cfg
        self.paths = paths
        self.read_only = read_only
        self.jobs = job_manager or JobManager(cfg, paths)
        self.static_dir = static_dir or STATIC_DIR
        self.csrf_token = secrets.token_urlsafe(32)

    def known_cves(self) -> set[str]:
        return {path.name for path in discover_package_dirs(self.paths)}

    def known_advisories(self) -> set[str]:
        catalog_path = self.paths.data / "advisories.json"
        try:
            rows = json.loads(catalog_path.read_text()).get("advisories", [])
        except (FileNotFoundError, json.JSONDecodeError):
            return set()
        return {
            str(row.get("cve"))
            for row in rows
            if isinstance(row, dict) and row.get("cve")
        }


class UIServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], app: UIApp):
        super().__init__(address, UIHandler)
        self.app = app


class UIHandler(BaseHTTPRequestHandler):
    server_version = "VulnForgeUI/0.1"
    protocol_version = "HTTP/1.1"

    @property
    def app(self) -> UIApp:
        return self.server.app  # type: ignore[attr-defined]

    # -- plumbing ---------------------------------------------------------

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"[ui] {self.address_string()} {fmt % args}", flush=True)

    def _security_headers(self) -> None:
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "connect-src 'self'; object-src 'none'; base-uri 'none'; "
            "frame-ancestors 'none'",
        )
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")

    def _send(self, status: int, body: bytes, content_type: str, *, download: str | None = None) -> None:
        self.send_response(status)
        self._security_headers()
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if download:
            self.send_header(
                "Content-Disposition", f'attachment; filename="{download}"'
            )
        self.end_headers()
        self.wfile.write(body)

    def _json(self, payload: Any, status: int = 200) -> None:
        body = (json.dumps(payload, indent=2) + "\n").encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8")

    def _error(self, status: int, message: str) -> None:
        self._json({"error": message}, status)

    def _host_ok(self) -> bool:
        host = self.headers.get("Host")
        if not host:
            return True
        hostname = urlsplit("//" + host).hostname
        return hostname in LOOPBACK_HOSTS

    def _origin_ok(self) -> bool:
        origin = self.headers.get("Origin")
        if not origin:
            return True
        parsed = urlsplit(origin)
        return parsed.scheme in ("http", "https") and parsed.hostname in LOOPBACK_HOSTS

    def _csrf_ok(self) -> bool:
        token = self.headers.get("X-VulnForge-CSRF", "")
        return secrets.compare_digest(token, self.app.csrf_token)

    def _read_json_body(self) -> dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("invalid Content-Length") from exc
        if length <= 0:
            raise ValueError("request body is required")
        if length > MAX_BODY_BYTES:
            raise ValueError("request body is too large")
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise ValueError("request body must be a JSON object")
        return data

    def _static_path(self, url_path: str) -> Path | None:
        relative = url_path.removeprefix("/static/").lstrip("/")
        candidate = (self.app.static_dir / relative).resolve()
        try:
            candidate.relative_to(self.app.static_dir.resolve())
        except ValueError:
            return None
        return candidate if candidate.is_file() else None

    # -- HTTP verbs -------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802
        if not self._host_ok():
            self._error(HTTPStatus.FORBIDDEN, "invalid Host header")
            return
        path = urlsplit(self.path).path
        try:
            if path.startswith("/api/"):
                self._get_api(path)
                return
            if path == "/" or path == "":
                self._send_file(self.app.static_dir / "index.html")
                return
            if path.startswith("/static/"):
                candidate = self._static_path(path)
                if candidate is None:
                    self._error(HTTPStatus.NOT_FOUND, "not found")
                    return
                self._send_file(candidate)
                return
            if path == "/favicon.ico":
                self._send(HTTPStatus.NO_CONTENT, b"", "image/x-icon")
                return
            # Hash routing: unknown non-API paths return the SPA shell.
            self._send_file(self.app.static_dir / "index.html")
        except Exception as exc:  # pragma: no cover - defensive boundary
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR, str(exc))

    def do_POST(self) -> None:  # noqa: N802
        if not self._host_ok():
            self._error(HTTPStatus.FORBIDDEN, "invalid Host header")
            return
        if not self._origin_ok():
            self._error(HTTPStatus.FORBIDDEN, "cross-origin request rejected")
            return
        path = urlsplit(self.path).path
        if path != "/api/jobs":
            self._error(HTTPStatus.NOT_FOUND, "not found")
            return
        if self.app.read_only:
            self._error(HTTPStatus.FORBIDDEN, "UI is running in read-only mode")
            return
        if not self._csrf_ok():
            self._error(HTTPStatus.FORBIDDEN, "invalid CSRF token")
            return
        try:
            payload = self._read_json_body()
        except ValueError as exc:
            self._error(HTTPStatus.BAD_REQUEST, str(exc))
            return

        action_id = str(payload.get("action") or "")
        cve = payload.get("cve")
        cve = str(cve) if cve else None
        options = payload.get("options") or {}
        if not isinstance(options, dict):
            self._error(HTTPStatus.BAD_REQUEST, "options must be an object")
            return
        spec = ACTIONS.get(action_id)
        if spec is None:
            self._error(HTTPStatus.BAD_REQUEST, f"unknown action: {action_id}")
            return
        if spec.requires_docker and not readmodel.docker_ready(self.app.paths):
            self._error(HTTPStatus.CONFLICT, "Docker daemon or Compose is not available")
            return
        try:
            job = self.app.jobs.submit(
                action_id,
                cve,
                options,
                self.app.known_cves(),
                self.app.known_advisories(),
            )
        except ValueError as exc:
            self._error(HTTPStatus.BAD_REQUEST, str(exc))
            return
        self._json(job, HTTPStatus.ACCEPTED)

    def _send_file(self, path: Path, *, download: str | None = None) -> None:
        if not path.is_file():
            self._error(HTTPStatus.NOT_FOUND, "not found")
            return
        content_type = mimetypes.guess_type(str(path))[0] or "application/octet-stream"
        if content_type.startswith("text/") or content_type in (
            "application/javascript",
            "application/json",
        ):
            content_type += "; charset=utf-8"
        self._send(HTTPStatus.OK, path.read_bytes(), content_type, download=download)

    # -- API --------------------------------------------------------------

    def _get_api(self, path: str) -> None:
        app = self.app
        if path == "/api/session":
            self._json(
                {
                    "csrf_token": app.csrf_token,
                    "read_only": app.read_only,
                    "root": str(app.paths.root),
                }
            )
            return
        if path == "/api/status":
            self._json(readmodel.portfolio(app.cfg, app.paths))
            return
        if path == "/api/packages":
            self._json(readmodel.portfolio(app.cfg, app.paths)["packages"])
            return
        if path == "/api/matrix":
            self._json(readmodel.matrix(app.paths))
            return
        if path == "/api/labs":
            self._json(readmodel.labs(app.cfg, app.paths))
            return
        if path == "/api/doctor":
            self._json(readmodel.doctor(app.paths))
            return
        if path == "/api/actions":
            self._json(
                actions_payload(
                    known_cves=app.known_cves(),
                    known_catalog=app.known_advisories(),
                    docker_ok=readmodel.docker_ready(app.paths),
                    read_only=app.read_only,
                )
            )
            return
        if path == "/api/jobs":
            self._json(app.jobs.list())
            return
        if path.startswith("/api/jobs/"):
            job_id = path.rsplit("/", 1)[-1]
            try:
                self._json(app.jobs.snapshot(job_id))
            except KeyError:
                self._error(HTTPStatus.NOT_FOUND, "unknown job")
            return
        if path.startswith("/api/packages/"):
            self._package_api(path)
            return
        self._error(HTTPStatus.NOT_FOUND, "not found")

    def _package_api(self, path: str) -> None:
        tail = path.removeprefix("/api/packages/")
        parts = [part for part in tail.split("/") if part]
        if not parts:
            self._error(HTTPStatus.NOT_FOUND, "not found")
            return
        cve = parts[0]
        if cve not in self.app.known_cves():
            self._error(HTTPStatus.NOT_FOUND, f"unknown package: {cve}")
            return
        if len(parts) == 1:
            try:
                self._json(readmodel.package_detail(self.app.cfg, self.app.paths, cve))
            except Exception as exc:
                self._error(HTTPStatus.NOT_FOUND, str(exc))
            return
        if parts[1] == "report.md":
            self._send_file(
                readmodel.report_path(self.app.paths, cve, "md"),
                download=f"{cve}-report.md",
            )
            return
        if parts[1] == "report.json":
            self._send_file(
                readmodel.report_path(self.app.paths, cve, "json"),
                download=f"{cve}-report.json",
            )
            return
        self._error(HTTPStatus.NOT_FOUND, "not found")


def create_server(
    cfg: FactoryConfig,
    paths: Paths,
    *,
    host: str = "127.0.0.1",
    port: int = 0,
    read_only: bool = False,
    job_manager: JobManager | None = None,
    static_dir: Path | None = None,
) -> UIServer:
    app = UIApp(
        cfg,
        paths,
        read_only=read_only,
        job_manager=job_manager,
        static_dir=static_dir,
    )
    return UIServer((host, port), app)


def serve(
    cfg: FactoryConfig,
    paths: Paths,
    *,
    host: str = "127.0.0.1",
    port: int = 0,
    read_only: bool = False,
) -> None:
    server = create_server(
        cfg, paths, host=host, port=port, read_only=read_only
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
