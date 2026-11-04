# CI and local checks

## Local

```bash
.venv/bin/pip install -e '.[dev]'

.venv/bin/pytest -q
.venv/bin/ruff check src tests
.venv/bin/vulnforge package validate
.venv/bin/vulnforge triage --check
.venv/bin/vulnforge report --all
git diff --exit-code
```

`vulnforge report --all` regenerates per-CVE `report.md`/`report.json` and the
global `reports/technical-report.md`. The global report date is derived from the
latest validation evidence, so report drift checks are deterministic.

## GitHub Actions

`.github/workflows/ci.yml`:

- unit job on Python 3.10–3.13
- `pytest`, package validation, resolver drift, report drift, ruff
- integration job on `workflow_dispatch`/weekly schedule:
  - real Bandit lab build/start/status/stop
  - toy adapter build/start/status/stop

## Gated Docker tests

```bash
VULNFORGE_DOCKER=1 python -m unittest tests.test_lab_integration -v
VULNFORGE_DOCKER=1 python -m unittest \
  tests.test_adapter_contract.ToyAdapterDockerTests -v
```

These are skipped by default so unit runs do not need Docker.

## Doctor and cleanup

```bash
vulnforge doctor
vulnforge clean --dry-run
vulnforge clean
```

`doctor` checks Python, Docker, Compose, config, schemas, and packages.
`clean` removes generated `.vulnforge` runtime state only; package evidence is
not touched.
