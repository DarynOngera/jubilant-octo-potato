# Building a package PoC

A VulnForge PoC is a bounded experiment. It
must prove a pre-registered behavioral difference between the vulnerable and
patched targets in the same lab configuration.

## Research sequence

For a CVE covered by a reviewed profile, build the initial lab PoC directly:

```bash
vulnforge poc build CVE-2026-XXXXX
```

The builder reads `advisory.json`, selects a target-specific profile, writes
`poc/exploit.py`, derives `poc/manifest.json` from the profile, and records
the decision in `poc/proposal.json`. It only replaces the scaffold placeholder.
Unsupported CVE mechanisms require a new reviewed profile.

The generated probe starts with a provenance marker such as
`# generated-by: vulnforge poc build bandit-http2-one-byte-data
ref=CVE-2026-116078`. Re-running `poc build` on an unchanged generated probe
is an idempotent no-op; once you edit it, the probe is researcher-owned and
the builder refuses to replace it unless you pass `--force`. Hand-authored
probes are never replaced. `poc/proposal.json` is schema-checked by
`vulnforge package validate` whenever it exists.

Currently reviewed profiles:

| Profile | Reference package | Shape |
|---|---|---|
| `bandit-http2-one-byte-data` | `CVE-2026-116078` | HTTP/2 body as 1-byte DATA frames |
| `bandit-http1-one-byte-chunks` | `CVE-2026-111101` | HTTP/1.1 body as 1-byte chunks |
| `bandit-http1-chunked-length-cap` | `CVE-2026-39803` | Oversized chunked body vs the application length cap |

If `vulnforge analyze` has captured fixing commits, the builder also reads
them. A patch that contradicts the advisory's protocol (for example an HTTP/2
advisory whose fix only touches HTTP/1 modules) vetoes automatic selection,
and the proposal records `selector.confidence`, changed paths, and mechanism
indicators. With no captured patch, selection is advisory-only at confidence
0.5.

1. **Write the claim.** State the reachable input, required protocol state,
   expected effect, and the fixed version. Put the evidence in
   `analysis/attack-surface.md` and `analysis/root-cause.md`.
2. **Choose a pair.** The vulnerable package version must be affected; the
   patched version is the first fixed release. `vulnforge package scaffold`
   derives the pair and `package validate` enforces the affected-range check.
3. **Pin the lab.** Add the target's dependency locks and verify that both
   images build from the same application/configuration. The package keeps the
   versions and the generated provenance records image identities.
4. **Define a measurable predicate before running it.** Choose the metric,
   minimum number of runs, variance guard, and fixed threshold in
   `poc/manifest.json`. Do not lower a threshold after observing data.
5. **Implement the smallest discriminating stimulus.** Start from a benign
   request, add only the protocol/state element required by the hypothesis,
   and implement an explicit control stimulus of comparable size.
6. **Enforce bounds in code.** Call `enforce_loopback`,
   `validate_payload_budget`, and `validate_duration_budget` before sending
   data. Derive ports from `ProbeTarget`; never hard-code a host or port.
7. **Collect observations.** Use `MemorySampler` for target-provided stats and
   `capture_benign_pool` for a normal baseline. Return a `ProbeResult` with
   the declared metric, observations, duration, sample count, and errors.
8. **Run the sequence.** Validate package → start lab → run the PoC once on
   both roles → validate repeatedly → detect → report → stop lab. Persisted
   evidence includes application telemetry, host-side Docker telemetry,
   container logs, and image provenance.

## Probe shape

```python
from vulnforge.probe import (
    MemorySampler,
    ProbeResult,
    ProbeTarget,
    Timer,
    capture_benign_pool,
    enforce_loopback,
    validate_duration_budget,
    validate_payload_budget,
)


def run(target: ProbeTarget, **kwargs) -> ProbeResult:
    enforce_loopback(target)
    wire_bytes = estimate_wire_bytes(kwargs)
    validate_payload_budget(wire_bytes)
    validate_duration_budget(estimated_duration(kwargs))

    target.admin_gc()
    benign_pool = capture_benign_pool(target)
    with Timer() as timer, MemorySampler(target) as sampler:
        attack = send_smallest_trigger(target, **kwargs)

    baseline = sampler.samples[0]["total"] if sampler.samples else 0
    peak = sampler.peak or baseline
    return ProbeResult(
        metrics={"attack_memory_delta": float(max(0, peak - baseline))},
        observations={
            "one_byte_result": attack,
            "control_result": send_control(target, **kwargs),
            "benign_pool": benign_pool,
            "telemetry": {"attack": sampler.samples},
        },
        duration_s=timer.elapsed,
        sample_count=len(sampler.samples),
    )
```

The exact metric need not be memory. A CPU, latency, connection-lifetime, or
correctness metric is valid when it is tied to the advisory and supports a
vulnerable-versus-patched predicate. Update detection rules when the existing
memory/frame/process rules do not describe the effect.

## Completion gates

| Gate | Evidence required |
|---|---|
| Draft | Advisory, analysis, lab pair, probe manifest, and detection hypothesis validate. |
| PoC implemented | The probe performs bounded loopback I/O and returns the declared metric for both roles. |
| Validated | Repeated A/B evidence meets the pre-registered verdict predicate. |
| Reported | Detection and report are generated from the completed evidence bundle. |

