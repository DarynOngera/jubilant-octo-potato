# Toy target

A minimal Python HTTP target used only to prove the VulnForge `TargetAdapter`
boundary. It is **not a CVE** and does not model a real vulnerability.

- `GET /healthz` — readiness probe.
- `GET /stats` — toy version and process memory.
- `POST /echo` — reads the declared body and reports the byte count.

The `ToyAdapter` uses one listener for both the app and the stats endpoint,
which proves the core no longer assumes Bandit's two-port `/admin/stats`
layout.

Contract test (requires Docker):

```bash
VULNFORGE_DOCKER=1 .venv/bin/python -m unittest tests.test_toy_adapter -v
```
