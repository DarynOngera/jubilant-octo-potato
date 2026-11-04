#!/usr/bin/env python3
"""
generate_report.py

Builds reports/technical-report.md from data/advisories.json and
data/vulnerability-matrix.json (the output of triage/prioritizer.py). Run
the triage step first:

    python3 triage/prioritizer.py --csv reports/vulnerability-matrix.csv
    python3 reports/generate_report.py

Keeps the report a build artifact rather than hand-maintained prose, so
adding/revising an advisory means editing data/advisories.json, and revising
a score means editing data/prioritization.json or config/research.yaml.
"""
from __future__ import annotations

import json
import sys
from datetime import date
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "triage"))
sys.path.insert(0, str(REPO_ROOT / "probes"))

import yaml  # noqa: E402
from registry import PROBE_REGISTRY  # noqa: E402
from version_resolver import (  # noqa: E402
    exposure_summary,
    resolve_all,
    suggested_checkpoints,
    version_in_range,
)

DATA = REPO_ROOT / "data"
OUT = REPO_ROOT / "reports" / "technical-report.md"

RESEARCH_CFG = yaml.safe_load((REPO_ROOT / "config" / "research.yaml").read_text())
LAB_VULNERABLE_VERSION = RESEARCH_CFG["targets"]["vulnerable"]["bandit_version"]
REG_RESULTS = REPO_ROOT / "evidence" / "metrics" / "regression-results.json"


def load_regression_results() -> list[dict]:
    """Latest legacy single-run A/B verdicts, if the old harness was run."""
    if not REG_RESULTS.exists():
        return []
    try:
        data = json.loads(REG_RESULTS.read_text())
    except (json.JSONDecodeError, OSError):
        return []
    return data if isinstance(data, list) else []


def load_package_probes() -> dict[str, dict]:
    probes: dict[str, dict] = {}
    for path in sorted((REPO_ROOT / "vulnerabilities").glob("*/poc/manifest.json")):
        try:
            data = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        if isinstance(data, dict) and data.get("cve"):
            probes[str(data["cve"])] = data
    return probes


def load_package_validations() -> list[dict]:
    results: list[dict] = []
    for path in sorted((REPO_ROOT / "vulnerabilities").glob("*/evidence/validation.json")):
        try:
            data = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        if isinstance(data, dict):
            results.append(data)
    return results


def load_package_detections() -> dict[str, dict]:
    results: dict[str, dict] = {}
    for path in sorted((REPO_ROOT / "vulnerabilities").glob("*/detection/evidence.json")):
        try:
            data = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        if isinstance(data, dict) and data.get("cve"):
            results[str(data["cve"])] = data
    return results


def latest_evidence_date() -> str:
    """Use the newest validation date so reports are deterministic in CI."""
    dates = []
    for result in load_package_validations():
        finished = result.get("finished_at")
        if isinstance(finished, str) and len(finished) >= 10:
            dates.append(finished[:10])
    return max(dates) if dates else date.today().isoformat()


def package_poc_relpath(cve: str) -> str | None:
    path = REPO_ROOT / "vulnerabilities" / cve / "poc" / "exploit.py"
    if path.is_file():
        return str(path.relative_to(REPO_ROOT))
    return None


def format_metric(value, metric: str) -> str:
    if value is None:
        return "-"
    if metric in ("attack_memory_delta", "control_memory_delta"):
        return f"{float(value) / 1048576:.2f} MiB"
    return f"{float(value):.2f}x"


def load():
    advisories_list = json.loads((DATA / "advisories.json").read_text())["advisories"]
    advisories = {a["cve"]: a for a in advisories_list}
    matrix = json.loads((DATA / "vulnerability-matrix.json").read_text())
    return advisories, advisories_list, matrix


def track_label(t: str) -> str:
    return {
        "http1_resource_exhaustion": "HTTP/1 resource exhaustion",
        "http2_resource_exhaustion": "HTTP/2 resource exhaustion",
        "websocket_exhaustion": "WebSocket resource exhaustion",
        "websocket_state_correctness": "WebSocket state correctness",
        "http_request_smuggling": "HTTP request smuggling",
        "request_metadata_validation": "Request metadata validation",
    }.get(t, t)


def poc_relpath(cve: str) -> str | None:
    package_path = package_poc_relpath(cve)
    if package_path:
        return package_path
    spec = PROBE_REGISTRY.get(cve)
    if spec is None:
        return None
    return str(spec["module"].relative_to(REPO_ROOT))


def _affected_text(adv: dict) -> str:
    """Render one or more affected ranges without dropping any of them."""
    ranges = adv.get("affected_ranges")
    if ranges:
        parts = []
        for item in ranges:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict) and ("introduced" in item or "fixed" in item):
                introduced = item.get("introduced")
                fixed = item.get("fixed")
                has_lower = bool(introduced) and introduced != "0"
                if has_lower and fixed:
                    parts.append(f">= {introduced} and < {fixed}")
                elif has_lower:
                    parts.append(f">= {introduced}")
                elif fixed:
                    parts.append(f"< {fixed}")
            elif isinstance(item, dict):
                parts.append(
                    f"{item.get('lower_op', '>=')} {item['lower']} and "
                    f"{item.get('upper_op', '<')} {item['upper']}"
                )
        if parts:
            return " or ".join(parts)
    affected = adv.get("affected")
    if isinstance(affected, (list, tuple)):
        return " or ".join(str(a) for a in affected)
    return str(affected)


def _fixed_text(adv: dict) -> str:
    fixed = adv.get("fixed_in")
    if isinstance(fixed, (list, tuple)):
        return ", ".join(str(v) for v in fixed)
    return str(fixed)


def render_per_version_section(lines: list[str], exposure: dict, checkpoints: list[dict]) -> None:
    lines.append("\n## 2. Per-version CVE exposure\n")
    lines.append(
        "`triage/version_resolver.py::resolve_all()` maps every known Bandit "
        "release to the full list of advisories whose affected ranges contain it. "
        "The table below is restricted to the lab checkpoint versions; the second "
        "table groups consecutive releases with an identical exposure set."
    )
    lines.append("\n| Checkpoint version | Roles | Vulnerable CVEs | Count |")
    lines.append("|---|---|---|---|")
    for cp in checkpoints:
        cves = ", ".join(cp["vulnerable_cves"]) or "none"
        lines.append(
            f"| `{cp['version']}` | {', '.join(cp['roles'])} | {cves} | "
            f"{cp['vulnerable_count']} |"
        )

    lines.append("\n**Contiguous exposure bands** (versions with the same vulnerable-CVE set grouped together):\n")
    lines.append("| Versions | Count | CVEs |")
    lines.append("|---|---|---|")
    for band in exposure_summary(exposure):
        if band["start"] == band["end"]:
            label = band["start"]
        else:
            label = f"{band['start']} .. {band['end']}"
        cves = ", ".join(band["cves"]) or "none"
        lines.append(f"| `{label}` | {band['count']} | {cves} |")

    lines.append(
        "\nThis is why a single \"vulnerable\" lab image is not enough: 1.13.1 is "
        "still exposed to several later advisories but is already patched for the "
        "older ones. Each advisory must be tested against a version that actually "
        "falls inside its affected range."
    )


def main():
    advisories, advisories_list, matrix = load()
    today = latest_evidence_date()
    exposure = resolve_all(advisories_list)
    checkpoints = suggested_checkpoints(advisories_list, exposure)

    lines = []
    lines.append("# Bandit Vulnerability Research -- Technical Report")
    lines.append(f"\nGenerated {today} from `data/advisories.json` "
                  f"({len(advisories)} advisories) and `data/vulnerability-matrix.json`.")
    lines.append("\nSource: [Hex advisory registry](https://hex.pm/packages/bandit/advisories), "
                  "cross-referenced against OSV (`EEF-CVE-*`) and GHSA records linked from each entry.")
    lines.append("\n**Scope note:** CVSS scores are reproduced verbatim from the advisory records. "
                  "The `priority_P` column is this project's own research-priority score "
                  "(`0.40*Impact + 0.35*Exploitability + 0.15*Reachability + 0.10*Detectability`, "
                  "see `data/prioritization.json` and `config/research.yaml`) and is independent of CVSS by design -- "
                  "see Section 3.")

    lines.append("\n## 1. Exploitability matrix\n")
    lines.append("| Rank | CVE | CVSS | Priority P | Tier | Track | Fixed in |")
    lines.append("|---|---|---|---|---|---|---|")
    for i, r in enumerate(matrix, 1):
        lines.append(
            f"| {i} | [{r['cve']}](#{r['cve'].lower()}) | {r['cvss']} | {r['priority_P']} | "
            f"{r['exploit_tier'].split(' - ')[0]} | {track_label(r['track'])} | {r['fixed_in']} |"
        )

    render_per_version_section(lines, exposure, checkpoints)

    lines.append("\n## 3. Methodology note: why priority != CVSS\n")
    lines.append(
        "CVSS answers 'how bad if it fires, under worst-case assumptions.' It does not answer "
        "'how much researcher/attacker effort does firing it take.' Several advisories here carry "
        "the same 8.7 CVSS score (the HTTP/2 resource-exhaustion family largely does) but differ "
        "sharply in how many wire-format details, timing constraints, or protocol-state-machine "
        "steps stand between a client and triggering them. The priority score keeps those axes "
        "separate and explicit (`data/prioritization.json` documents the per-CVE scoring rationale "
        "in the `notes` field; weights/tiers live in `config/research.yaml`) rather than letting CVSS stand in for both."
    )

    lines.append("\n## 4. Per-advisory detail\n")
    for r in matrix:
        cve = r["cve"]
        adv = advisories[cve]
        lines.append(f"### {cve}\n")
        lines.append(f"**{adv['title']}**\n")
        lines.append(f"- GHSA: {adv['ghsa']} &nbsp;|&nbsp; OSV: {adv['osv']}")
        lines.append(f"- CVSS 4.0: **{adv['cvss_score']}** &nbsp;(`{adv['cvss_vector']}`)")
        lines.append(f"- Affected: `{_affected_text(adv)}` &nbsp;|&nbsp; Fixed in: `{_fixed_text(adv)}`")
        lines.append(f"- Published: {adv['published']}")
        lines.append(f"- Track: {track_label(adv['track'])}")
        lines.append(f"- Research priority: **{r['priority_P']}** "
                      f"(I={r['impact_I']} E={r['exploit_E']} R={r['reach_R']} D={r['detect_D']}) -- {r['exploit_tier']}")
        lines.append(f"- Analyst note: {r['notes']}")
        lines.append(f"- Fixing commit(s): " + ", ".join(
            f"[`{c[:10]}`](https://github.com/mtrudel/bandit/commit/{c})" for c in adv["commits"]
        ))
        poc_path = poc_relpath(cve)
        lines.append(f"- PoC status: " + (f"**implemented** -- `{poc_path}`" if poc_path
                                           else "not yet implemented (see Section 5 for the pattern to extend)"))
        lines.append("")

    lines.append("## 5. PoC coverage and how to extend it\n")
    package_probes = load_package_probes()
    package_validations = load_package_validations()

    if package_probes:
        lines.append(
            f"{len(package_probes)} package probes are implemented under "
            "`vulnerabilities/*/poc/` and run by `vulnforge validate`. The legacy "
            "`probes/registry.py` harness remains for historical comparison.\n"
        )
        for cve in sorted(package_probes):
            spec = package_probes[cve]
            targets = spec.get("targets", {})
            lines.append(
                f"- `{cve}` -> `{poc_relpath(cve)}` "
                f"(vulnerable `{targets.get('vulnerable', '?')}` vs patched "
                f"`{targets.get('patched', '?')}`; metric `{spec.get('metric', '?')}`)"
            )
    else:
        lines.append(
            f"{len(PROBE_REGISTRY)} legacy probes are registered in "
            "`probes/registry.py` and run by `tests/regression/compare_versions.py`.\n"
        )
        for cve in sorted(PROBE_REGISTRY):
            spec = PROBE_REGISTRY[cve]
            lines.append(
                f"- `{cve}` -> `{poc_relpath(cve)}` "
                f"(vulnerable `{spec.get('vulnerable_target', 'vulnerable')}` vs "
                f"patched `{spec.get('patched_target', 'patched')}`)"
            )

    if package_validations:
        package_detections = load_package_detections()
        lines.append(
            "\nMulti-run results (`vulnerabilities/*/evidence/validation.json`):\n"
        )
        lines.append(
            "| CVE | Pair | Metric | Vulnerable median | Patched median | Runs | Verdict | Detection |"
        )
        lines.append("|---|---|---|---|---|---|---|---|")
        for result in package_validations:
            targets = result.get("targets", {})
            vuln = targets.get("vulnerable", {})
            patched = targets.get("patched", {})
            vuln_summary = vuln.get("summary", {})
            patched_summary = patched.get("summary", {})
            metric = result.get("aggregates", {}).get("metric", "unknown")
            detection = package_detections.get(result.get("cve"), {})
            lines.append(
                f"| `{result.get('cve')}` | `{vuln.get('version', '?')}` -> "
                f"`{patched.get('version', '?')}` | `{metric}` | "
                f"{format_metric(vuln_summary.get('median'), metric)} | "
                f"{format_metric(patched_summary.get('median'), metric)} | "
                f"{result.get('runs', '?')} | **{result.get('verdict')}** | "
                f"{detection.get('result', '-')} |"
            )
        lines.append(
            "\nVerdicts are median-based with a patched-CV guard; run ranges must "
            "not overlap in absolute mode. A non-`CONFIRMED` verdict is a real "
            "result, not a reporting gap."
        )
        for result in package_validations:
            if result.get("verdict") != "CONFIRMED":
                lines.append(
                    f"- `{result.get('cve')}`: {result.get('verdict')} -- "
                    f"{result.get('reason', 'no reason recorded')}"
                )
    else:
        reg_results = load_regression_results()
        if reg_results:
            lines.append(
                "\nLegacy single-run results "
                "(`evidence/metrics/regression-results.json`):\n"
            )
            lines.append(
                "| CVE | Vulnerable target | Patched target | Vulnerable amp | Patched amp | Verdict |"
            )
            lines.append("|---|---|---|---|---|---|")
            for r in reg_results:
                lines.append(
                    f"| `{r.get('cve')}` | `{r.get('vulnerable_target')}` | "
                    f"`{r.get('patched_target')}` | "
                    f"{r.get('vulnerable_amplification', 0):.2f}x | "
                    f"{r.get('patched_amplification', 0):.2f}x | "
                    f"**{r.get('verdict')}** |"
                )
            lines.append(
                "\nThese are historical single-run measurements; M3 package "
                "validation replaces them with medians and a variance guard."
            )
        else:
            lines.append(
                "\nNo validation results are recorded yet; run "
                "`vulnforge validate <CVE> --runs 3`."
            )

    implemented_cves = set(package_probes) | set(PROBE_REGISTRY)
    unimplemented = [r for r in matrix if r["cve"] not in implemented_cves]
    testable = [
        r for r in unimplemented
        if version_in_range(LAB_VULNERABLE_VERSION, advisories[r["cve"]])
    ]
    untestable = [r for r in unimplemented if r not in testable]

    lines.append("")
    if testable:
        nxt = testable[0]
        lines.append(
            f"The next-highest-priority item that is still vulnerable at the lab's "
            f"`{LAB_VULNERABLE_VERSION}` checkpoint is **{nxt['cve']}** "
            f"({nxt['title']}). Add its package under `vulnerabilities/`, "
            f"register the probe in `poc/manifest.json`, and re-run "
            f"`vulnforge validate`."
        )
    else:
        lines.append(
            f"Every remaining advisory is already patched at the lab's "
            f"`{LAB_VULNERABLE_VERSION}` checkpoint; adding an older checkpoint image "
            f"is required before those can be tested."
        )

    if untestable:
        examples = ", ".join(r["cve"] for r in untestable[:4])
        lines.append(
            f"\n{len(untestable)} remaining advisories are fixed before "
            f"`{LAB_VULNERABLE_VERSION}` (for example {examples}) and cannot be "
            f"reproduced against the current \"vulnerable\" container. Add the "
            f"corresponding older checkpoint version from `data/lab-checkpoints.json` "
            f"before implementing those PoCs."
        )

    lines.append("\n## 6. Remediation\n")
    lines.append(
        "All 24 advisories are fixed upstream; the single remediation is "
        "**upgrade to Bandit >= 1.14.1**. For the request-smuggling family "
        "(CVE-2026-114216, CVE-2026-39805), also audit any reverse proxy in front of Bandit "
        "for matching chunk-extension and duplicate-Content-Length handling -- the advisory fixes "
        "Bandit's own parsing, but smuggling impact is a property of the Bandit+proxy pair."
    )

    lines.append("\n## 7. Detection guidance\n")
    lines.append(
        "`tests/detection/thresholds.py` implements four behavioral rules that do not "
        "depend on the exact PoC payload:"
    )
    lines.append(
        "- `per_connection_frame_rate` -- sustained tiny-frame/tiny-chunk rate far above "
        "what a legitimate client needs to deliver its payload.\n"
        "- `memory_per_connection_outlier` -- one connection's attributable memory delta "
        "is a statistical outlier against the rest of the pool.\n"
        "- `body_duration_vs_size` -- a body takes far longer to arrive than its size and "
        "the configured rate suggest (trickle attacks).\n"
        "- `unbounded_process_growth` -- BEAM process count or top-process memory grows "
        "monotonically across polling intervals with no completed-request progress."
    )

    lines.append("\n## 8. Limitations\n")
    lines.append(
        "- This report classifies exploitability independently per-CVE; it does not model "
        "combined/chained exploitation across advisories.\n"
        "- `priority_P` scores are analyst judgment calls recorded in `data/prioritization.json`, "
        "not derived mechanically -- treat disagreements with them as a reason to revise the "
        "scoring data, not the report text.\n"
        "- PoCs sample `erlang:memory()` on a minimal lab app while the request is in flight; "
        "absolute amplification ratios on a production app with different Plug/body-handling "
        "behaviour will differ, though the direction of the effect (vulnerable amplifies, "
        "patched does not) should not.\n"
        "- The lab currently ships 1.13.1, 1.14.0, and 1.14.1 only. Advisories fixed before "
        "1.13.1 need an older checkpoint image before they can be tested.\n"
        "- CVE-2026-111101 is INCONCLUSIVE: the corrected 1.13.1 vs 1.14.0 pair shows "
        "a stable 1.60x reduction, below the pre-registered 2.00x threshold, and the "
        "recorded commits do not identify the 1.14.0 fix. Do not cite it as a confirmed finding.\n"
    )

    OUT.write_text("\n".join(lines))
    print(f"Wrote {OUT}")


if __name__ == "__main__":
    main()
