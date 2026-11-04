# Lab Runtime Fixes -- 2026-11-04

This note records the independent problems found while bringing the Docker
lab up for the first time. They are separate from the version-resolution and
report-generation work; each has its own root cause and verification.

## 1. OTP 27 port-table OOM (the startup failure)

**Symptom.** All three targets exited `137` with `OOMKilled=true` and no log
output, even at the *build* stage's `mix local.hex` step. A bare
`elixir --version` was also OOM-killed at 512 MiB and 1 GiB, but succeeded at
1.2 GiB. A sleeping `elixir -e 'Process.sleep(...)'` under a 2 GiB cap
reported `VmRSS ~= 2.1 GiB` with only ~8 MB of loaded code.

**Root cause.** OTP 27 auto-sizes `max_ports` (and therefore the fixed
`port_table`) from host memory. On this 15.5 GiB host that reserves roughly
1.5 GiB at VM startup, before any application code runs. Every `mix`
invocation starts a fresh BEAM, so the cap applies to `mix local.hex`,
`mix deps.get`, `mix deps.compile`, and `mix run` alike. It also hides PoC
memory deltas inside the container's `mem_limit`.

**Fix.** Pin the port table in both Docker stages, before the first `mix`
command:

```dockerfile
ENV ERL_AFLAGS="+Q 262144"
```

`lab/compose.yaml` repeats the same value in the shared environment so it is
visible and overridable at runtime.

**Verification.**

| Metric | Before | After |
|---|---|---|
| VM baseline (`/admin/stats` `erlang_memory.total`) | ~2.1 GiB (VM killed before app start) | 52 MiB |
| Container memory at idle | OOM-killed | 72--78 MiB / 512 MiB |
| `docker inspect .State.OOMKilled` | `true` | `false` |
| Health endpoints 4100 / 4120 / 4110 | unreachable | `ok` |
| Reported Bandit versions | n/a | 1.13.1 / 1.14.0 / 1.14.1 |

## 2. Invalid Bandit option (`protocol_options`)

**Symptom.** With the OOM fixed and the memory cap removed, the app failed at
startup:

```
(RuntimeError) Unsupported key(s) in top level config: [:protocol_options]
```

**Root cause.** Bandit 1.13.1 and 1.14.1 configure protocol stacks with
`http_1_options` / `http_2_options`; there is no top-level
`:protocol_options` key. The lab was using an older/nonexistent API.

**Fix.** `lab/app/lib/lab_app/application.ex` now starts the app listener
with:

```elixir
http_1_options: [enabled: true],
http_2_options: [enabled: http2]
```

HTTP/2 (h2c, prior knowledge) remains enabled by default; `BANDIT_HTTP2=false`
disables it.

## 3. `internal: true` silently drops published ports

**Symptom.** After switching `labnet` to `internal: true`, the containers were
running and logging normally, but the host could not reach 4100/4120/4110.
`docker port` returned nothing and `NetworkSettings.Ports` was `{}` even
though `HostConfig.PortBindings` was populated.

**Root cause.** On this Docker version, an internal bridge has no gateway and
Docker does not create published port mappings for containers attached to it.
Reproduced with a minimal container on a fresh internal network.

**Fix.** `labnet` is a dedicated project-scoped bridge with
`internal: false`. Every published port is still bound to `127.0.0.1`, the
network is still separate from other Compose projects, and the lab app makes
no outbound connections. A hard egress block should be an explicit firewall
rule for the lab subnet, not `internal: true`.

**Verification.** `docker port bandit-vulnerable` now reports
`127.0.0.1:4100->4000/tcp` and `127.0.0.1:4101->4001/tcp`; all three health
endpoints return `ok`.

## 4. CVE-2026-116078 probe needed 20k frames

The registry used 5,000 DATA frames, which was below the point where the
per-frame overhead separates from GC noise, so both targets looked noisy.
Raising it to 20,000 frames (~200 KB wire, ~2 s) gives a stable signal while
staying far inside the lab budgets.

## Current live A/B results

Recorded in `evidence/metrics/regression-results.json`:

| CVE | Pair | Vulnerable amp | Patched amp | Verdict |
|---|---|---|---|---|
| CVE-2026-116078 | interim `1.14.0` vs patched `1.14.1` | 8.90x | 0.58x | **CONFIRMED** |
| CVE-2026-111101 | vulnerable `1.13.1` vs patched `1.14.1` | 1.01x | 0.37x | **INCONCLUSIVE** |

CVE-2026-111101 is not a confirmed finding. Even with a longer paced run
(20k chunks, 1 ms pacing), both `1.13.1` and `1.14.1` show large per-chunk
growth against the large-chunk control (~4.2 MB vs ~2.2 MB), so the current
metric does not isolate what the 1.14.0 fix changed. The harness correctly
exits non-zero for this, and the report labels it as inconclusive.
