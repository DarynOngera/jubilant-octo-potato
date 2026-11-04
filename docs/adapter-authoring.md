# Adapter authoring

Bandit is the first adapter, not the core. A target adapter owns everything
target-specific: app build context, image tag, build args, service env,
health/metrics, lockfiles, and version reporting.

## Contract

`src/vulnforge/targets/base.py` defines:

```python
image_tag(cve, role, version)
build_args(version, cve, role)
labels(cve, role, version, git_commit)
lockfile(version)              # Path | None
version_from_stats(stats)      # str | None
service(target, service, limits)
health(target)                 # (bool, detail)
stats(target)                  # dict | None
```

The orchestrator, provenance recorder, validator, and CLI do not import a
concrete adapter. The adapter is resolved from `config/vulnforge.yaml`:

```yaml
targets:
  bandit:
    adapter: vulnforge.targets.bandit:BanditAdapter
    app_dir: lab/app
  toy:
    adapter: vulnforge.targets.toy:ToyAdapter
    app_dir: targets/toy
```

## What the adapter must provide

- A Docker build context with a `Dockerfile`.
- A `service` mapping that respects the lab limits and dynamic ports.
- Health and stats endpoints.
- A version extraction rule from the stats payload.
- Optional lockfiles; return `None` if the target has no dependency lock.

The toy adapter at `targets/toy/` proves a one-listener target works without
Bandit's two-port `/admin/stats` assumption.

## Requirements

- Loopback-only published ports.
- Resource caps, read-only root, dropped capabilities, no restart.
- Image/build labels for provenance.
- No arbitrary host/port input from a probe.

## Test

```bash
VULNFORGE_DOCKER=1 python -m unittest tests.test_adapter_contract.ToyAdapterDockerTests -v
```
