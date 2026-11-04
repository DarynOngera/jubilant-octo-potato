"""Generate per-CVE reports from package evidence."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..errors import LabError
from ..models import Package


def _load(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise LabError(f"invalid JSON in {path}: {exc}") from exc
    return data if isinstance(data, dict) else None


def _format_metric(value: Any, metric: str) -> str:
    if value is None:
        return "-"
    number = float(value)
    if metric in ("attack_memory_delta", "control_memory_delta"):
        return f"{number / 1048576:.2f} MiB"
    return f"{number:.2f}x"


def _report_data(package: Package) -> dict[str, Any]:
    manifest = package.manifest
    if manifest is None:
        raise LabError(f"{package.cve} has no package manifest")
    base = package.root
    validation = _load(base / "evidence" / "validation.json")
    detection = _load(base / "detection" / "evidence.json")
    execution = _load(base / "evidence" / "execution.json")
    provenance = _load(base / "lab" / "provenance.json")
    advisory = _load(base / manifest.paths.get("advisory", "advisory.json"))
    exploitability = _load(base / manifest.paths.get("analysis", "analysis") / "exploitability.json")
    probe = _load(base / manifest.paths.get("poc", "poc/manifest.json"))
    return {
        "package": package,
        "manifest": manifest,
        "advisory": advisory,
        "exploitability": exploitability,
        "probe": probe,
        "validation": validation,
        "detection": detection,
        "execution": execution,
        "provenance": provenance,
    }


def render_package_report(package: Package) -> str:
    data = _report_data(package)
    manifest = data["manifest"]
    advisory = data["advisory"] or {}
    validation = data["validation"] or {}
    detection = data["detection"] or {}
    execution = data["execution"] or {}
    provenance = data["provenance"] or {}
    probe = data["probe"] or {}
    metric = (validation.get("aggregates") or {}).get("metric", probe.get("metric", "unknown"))

    lines: list[str] = []
    lines.append(f"# {package.cve} — Technical Report\n")
    lines.append(f"**Status:** `{manifest.status}`")
    lines.append(f"**Target:** {manifest.target}")
    lines.append(
        f"**Vulnerable:** `{manifest.vulnerable_version}` | "
        f"**Patched:** `{manifest.patched_version}` | "
        f"**First fixed:** `{manifest.first_fixed}`"
    )
    lines.append(
        f"**Verdict:** `{validation.get('verdict', manifest.last_verdict)}`"
    )
    if validation.get("reason"):
        lines.append(f"**Reason:** {validation['reason']}")
    lines.append("")

    if advisory:
        lines.append("## 1. Advisory\n")
        lines.append(f"- **Title:** {advisory.get('title')}")
        aliases = ", ".join(
            str(value)
            for value in (advisory.get("ghsa"), advisory.get("osv"))
            if value
        )
        if aliases:
            lines.append(f"- **Aliases:** {aliases}")
        lines.append(f"- **Affected:** `{advisory.get('affected')}`")
        lines.append(f"- **Fixed in:** `{advisory.get('fixed_in')}`")
        lines.append(
            f"- **CVSS 4.0:** {advisory.get('cvss_score')} "
            f"(`{advisory.get('cvss_vector')}`)"
        )
        lines.append(f"- **Track:** {advisory.get('track')}")
        if advisory.get("references"):
            lines.append("- **References:**")
            for reference in advisory["references"]:
                lines.append(f"  - {reference}")
        lines.append("")

    lines.append("## 2. Research question and pair\n")
    lines.append(
        f"This package tests the last vulnerable release "
        f"(`{manifest.vulnerable_version}`) against the first fixed release "
        f"(`{manifest.patched_version}`)."
    )
    if probe:
        lines.append(
            f"\nProbe `{probe.get('entrypoint')}`; metric "
            f"`{probe.get('metric')}`; mode "
            f"`{(probe.get('thresholds') or {}).get('mode', 'absolute')}`."
        )
    lines.append("")

    if validation:
        lines.append("## 3. Validation result\n")
        lines.append(
            f"Runs: **{validation.get('runs')}**; "
            f"metric: `{metric}`; verdict: **{validation.get('verdict')}**."
        )
        lines.append("")
        lines.append("| Role | Version | Median | Min | Max | CV |")
        lines.append("|---|---|---:|---:|---:|---:|")
        for role in ("vulnerable", "patched"):
            target = (validation.get("targets") or {}).get(role, {})
            summary = target.get("summary", {})
            lines.append(
                f"| {role} | `{target.get('version')}` | "
                f"{_format_metric(summary.get('median'), metric)} | "
                f"{_format_metric(summary.get('min'), metric)} | "
                f"{_format_metric(summary.get('max'), metric)} | "
                f"{summary.get('cv', 0):.2%} |"
            )
        ratio = (validation.get("aggregates") or {}).get("ratio")
        if ratio is not None:
            lines.append(f"\nRelative reduction: **{ratio:.2f}x**.")
        if validation.get("reason"):
            lines.append(f"\n**Why this verdict:** {validation['reason']}")
        lines.append("")

    if detection:
        lines.append("## 4. Detection\n")
        lines.append(
            f"Overall detection result: **{detection.get('result')}** — "
            f"{detection.get('reason', '')}"
        )
        lines.append("")
        lines.append("| Role | Rule | Triggered | Detail |")
        lines.append("|---|---|---|---|")
        for role, target in (detection.get("targets") or {}).items():
            for rule in target.get("rules", []):
                lines.append(
                    f"| {role} | `{rule.get('id')}` | "
                    f"{'yes' if rule.get('triggered') else 'no'} | "
                    f"{rule.get('detail')} |"
                )
        lines.append("")
    else:
        lines.append("## 4. Detection\n")
        lines.append("Detection has not been run for this package yet. Run "
                     "`vulnforge detect` after validation.\n")

    lines.append("## 5. Reproduction\n")
    lines.append("```bash")
    lines.append(f"vulnforge lab start {package.cve}")
    lines.append(f"vulnforge validate {package.cve} --runs {validation.get('runs', 3)}")
    lines.append(f"vulnforge detect {package.cve}")
    lines.append(f"vulnforge report {package.cve}")
    lines.append(f"vulnforge lab stop {package.cve}")
    lines.append("```\n")

    if execution or provenance:
        lines.append("## 6. Evidence and provenance\n")
        if provenance:
            build = provenance.get("build", {})
            lines.append(f"- Base image: `{build.get('base_image')}`")
            dockerfile = build.get("dockerfile", {})
            lines.append(
                f"- Dockerfile: `{dockerfile.get('path')}` "
                f"(`{dockerfile.get('sha256')}`)"
            )
            for version, lock in (build.get("lockfiles") or {}).items():
                lines.append(
                    f"- Lock {version}: `{lock.get('path')}` "
                    f"(`{lock.get('sha256')}`)"
                )
            for role, image in (provenance.get("images") or {}).items():
                lines.append(
                    f"- Image {role}: `{image.get('tag')}` "
                    f"(`{image.get('id')}`)"
                )
        if execution:
            lines.append(
                f"- Evidence command: `{' '.join(execution.get('command', []))}`"
            )
            lines.append(f"- Evidence artifacts: {len(execution.get('artifacts', []))}")
            for artifact in execution.get("artifacts", []):
                lines.append(
                    f"  - `{artifact.get('path')}` "
                    f"(`{artifact.get('sha256')}`)"
                )
        lines.append("")

    lines.append("## 7. Analysis and limitations\n")
    lines.append(
        "- Root cause and attack surface are maintained in `analysis/`; "
        "the root-cause document is a working hypothesis until commit-level "
        "review is completed."
    )
    lines.append(
        "- Absolute memory numbers are specific to the minimal lab app and "
        "transport; the vulnerable/patched direction is the portable result."
    )
    lines.append(
        "- Detection is offline evidence review, not a production IDS."
    )
    if validation.get("verdict") != "CONFIRMED":
        lines.append(
            "- This package is not a confirmed exploit. Do not cite it as one "
            "without a new validation result that meets the pre-registered "
            "predicate."
        )
    lines.append("")

    return "\n".join(lines)


def write_package_report(package: Package) -> tuple[Path, Path]:
    data = _report_data(package)
    report_path = package.root / "report.md"
    report_path.write_text(render_package_report(package))

    json_path = package.root / "report.json"
    json_path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "cve": package.cve,
                "manifest": data["manifest"].__dict__,
                "advisory": data["advisory"],
                "validation": data["validation"],
                "detection": data["detection"],
                "provenance": data["provenance"],
                "evidence": data["execution"],
            },
            indent=2,
            default=str,
        )
        + "\n"
    )
    return report_path, json_path
