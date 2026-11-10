"""Build a vetted lab PoC directly from a package's CVE metadata.

Profiles deliberately reuse a completed, reviewed probe from the same target
and vulnerability family. The builder never invents a transport interaction:
an unsupported CVE remains a draft until a researcher adds a profile.
"""
from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .. import __version__
from ..errors import PackageError
from ..models import Package
from .signals import PatchSignals, extract_patch_signals

GENERATOR_VERSION = __version__

PLACEHOLDER_MARK = 'NotImplementedError("implement the package probe for this CVE")'
GENERATED_MARKER = "# generated-by: vulnforge poc build {profile} ref={reference}"
_MARKER_RE = re.compile(
    r"^# generated-by: vulnforge poc build (?P<profile>\S+) ref=(?P<reference>\S+)\s*$"
)


@dataclass(frozen=True)
class Profile:
    id: str
    reference_cve: str
    summary: str
    track: str
    title_phrase: str
    capability: str
    protocol: str = ""
    signal_indicators: tuple[str, ...] = ()

    def matches(self, advisory: Any) -> bool:
        return (
            advisory.track == self.track
            and self.title_phrase.lower() in advisory.title.lower()
        )


PROFILES = (
    Profile(
        id="bandit-http2-one-byte-data",
        reference_cve="CVE-2026-116078",
        summary="HTTP/2 request bodies fragmented into one-byte DATA frames",
        track="http2_resource_exhaustion",
        title_phrase="1-byte data frames",
        capability="Bandit HTTP/2 one-byte DATA-frame memory-amplification profile",
        protocol="http2",
        signal_indicators=("data_frames",),
    ),
    Profile(
        id="bandit-http1-one-byte-chunks",
        reference_cve="CVE-2026-111101",
        summary="HTTP/1.1 request bodies fragmented into one-byte chunks",
        track="http1_resource_exhaustion",
        title_phrase="1-byte chunks",
        capability="Bandit HTTP/1 one-byte chunk memory-amplification profile",
        protocol="http1",
        signal_indicators=("chunked_framing",),
    ),
    Profile(
        id="bandit-http1-chunked-length-cap",
        reference_cve="CVE-2026-39803",
        summary=(
            "HTTP/1.1 chunked bodies buffered past the application's length cap"
        ),
        track="http1_resource_exhaustion",
        title_phrase="length cap",
        capability="Bandit HTTP/1 chunked length-cap profile",
        protocol="http1",
        signal_indicators=("chunked_framing", "length_cap"),
    ),
)

# What a CVE of a known track still needs before the engine can build it.
# Used in the unsupported-CVE failure so the next work item is specific.
TRACK_CAPABILITIES = {
    "http2_resource_exhaustion": "Bandit HTTP/2",
    "http1_resource_exhaustion": "Bandit HTTP/1",
    "websocket_exhaustion": "Bandit WebSocket",
    "websocket_state_correctness": "Bandit WebSocket correctness",
    "http_request_smuggling": "Bandit request-smuggling correctness",
    "request_metadata_validation": "Bandit request metadata validation",
}


def supported_profile_ids() -> tuple[str, ...]:
    return tuple(profile.id for profile in PROFILES)


def matching_profiles(advisory: Any) -> tuple[Profile, ...]:
    """Profiles whose advisory track and title phrase match."""
    return tuple(profile for profile in PROFILES if profile.matches(advisory))


def select_profile(package: Package) -> tuple[Profile, PatchSignals]:
    """Choose the reviewed profile for a package and corroborate it.

    Advisory match is mandatory. When captured fixing patches exist, the
    selected profile's protocol must appear in them; otherwise the engine
    refuses automatic selection instead of guessing.
    """
    if package.advisory is None or package.manifest is None:
        raise PackageError(f"{package.cve} has no valid advisory/package manifest")
    if package.manifest.adapter_name != "bandit":
        raise PackageError(
            f"no CVE-driven PoC profile is available for adapter "
            f"{package.manifest.adapter_name!r}"
        )

    candidates = matching_profiles(package.advisory)
    if not candidates:
        track = package.advisory.track
        capability = TRACK_CAPABILITIES.get(track, "a reviewed target-specific")
        raise PackageError(
            f"{package.cve} does not match a supported CVE-driven PoC profile.\n"
            f"Required capability: {capability} profile for this advisory mechanism.\n"
            f"Supported profiles: {', '.join(supported_profile_ids())}."
        )

    signals = extract_patch_signals(package)
    if len(candidates) > 1:
        ranked = sorted(
            candidates,
            key=lambda profile: signals.confidence_for(profile),
            reverse=True,
        )
        if not signals.available or (
            signals.confidence_for(ranked[0])
            <= signals.confidence_for(ranked[1])
        ):
            ids = ", ".join(profile.id for profile in candidates)
            raise PackageError(
                f"{package.cve} matches multiple CVE-driven PoC profiles "
                f"({ids}); captured patch signals do not disambiguate them; "
                "refusing automatic profile selection"
            )
        candidates = (ranked[0],)

    profile = candidates[0]
    if signals.available and signals.confidence_for(profile) == 0.0:
        observed = ", ".join(signals.protocols) or "no protocol modules"
        raise PackageError(
            f"{package.cve} advisory matches profile {profile.id!r}, but the "
            f"captured fixing patch has no {profile.protocol!r} signal "
            f"(observed: {observed}); refusing automatic profile selection"
        )
    return profile, signals


def _placeholder(path: Path) -> bool:
    try:
        text = path.read_text()
    except FileNotFoundError:
        return True
    return PLACEHOLDER_MARK in text


def _generated(path: Path) -> tuple[str, str] | None:
    """Return the (profile, reference CVE) recorded in the generated marker."""
    try:
        text = path.read_text()
    except FileNotFoundError:
        return None
    for line in text.splitlines()[:5]:
        match = _MARKER_RE.match(line)
        if match:
            return match.group("profile"), match.group("reference")
    return None


def _targets(package: Package) -> dict[str, str]:
    if package.lab is None:
        raise PackageError(f"{package.cve} has no valid lab specification")
    targets = {}
    for role in ("vulnerable", "patched"):
        target = package.lab.target_by_role(role)
        if target is None:
            raise PackageError(f"{package.cve} lab has no {role!r} target")
        targets[role] = target.name
    return targets


def _reference(package: Package, profile: Profile) -> tuple[str, dict[str, Any]]:
    root = (package.root.parent / profile.reference_cve / "poc").resolve()
    if root == (package.root / "poc").resolve():
        raise PackageError(
            f"PoC profile {profile.id!r} uses {profile.reference_cve} as its "
            "reviewed reference, so that package cannot rebuild itself; "
            "restore its reviewed probe or build a different package"
        )
    source_path = root / "exploit.py"
    manifest_path = root / "manifest.json"
    try:
        source = source_path.read_text()
        manifest = json.loads(manifest_path.read_text())
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        raise PackageError(
            f"PoC profile {profile.id!r} is missing its reviewed reference package"
        ) from exc
    for key in ("entrypoint", "targets", "kwargs", "metric", "thresholds"):
        if key not in manifest:
            raise PackageError(
                f"reference package {profile.reference_cve} poc/manifest.json "
                f"is missing {key!r}"
            )
    return source, manifest


def _render(source: str, package: Package, profile: Profile) -> str:
    rendered = source.replace(profile.reference_cve, package.cve)
    marker = GENERATED_MARKER.format(
        profile=profile.id, reference=profile.reference_cve
    )
    lines = rendered.splitlines(keepends=True)
    if lines and lines[0].startswith("#!"):
        lines.insert(1, f"{marker}\n")
    else:
        lines.insert(0, f"{marker}\n")
    return "".join(lines)


def _predicate(metric: str, thresholds: dict[str, Any], runs: int) -> str:
    mode = str(thresholds.get("mode", "absolute"))
    vuln_min = thresholds["vulnerable_min"]
    patched_max = thresholds["patched_max"]
    max_cv = float(thresholds.get("max_cv", 1.0))
    min_samples = int(thresholds.get("min_samples", 1))
    head = (
        f"vulnerable {metric} median >= {vuln_min} and patched median <= "
        f"{patched_max}"
    )
    if mode == "relative":
        min_ratio = thresholds.get("min_ratio", 2.0)
        head += f" with vulnerable/patched median ratio >= {min_ratio}x"
    clauses = [
        f"{head} over {runs} runs (>= {min_samples} successful runs per role)",
        f"patched coefficient of variation <= {max_cv:.0%}",
    ]
    if mode != "relative":
        clauses.append("run ranges must not overlap")
    return "; ".join(clauses)


def _patch_analysis(package: Package) -> list[str]:
    """List captured patch-analysis files the selector considered."""
    analysis = package.root / "analysis"
    found: list[str] = []
    commits_dir = analysis / "commits"
    if commits_dir.is_dir():
        for path in sorted(commits_dir.iterdir()):
            if path.suffix in {".patch", ".json"}:
                found.append(str(path.relative_to(package.root)))
    scaffold = analysis / "root-cause.generated.md"
    if scaffold.is_file():
        found.append(str(scaffold.relative_to(package.root)))
    return found


def _load_manifest(path: Path, package: Package) -> dict[str, Any]:
    try:
        return json.loads(path.read_text())
    except FileNotFoundError as exc:
        raise PackageError(
            f"{package.cve} has no poc/manifest.json; scaffold the package first"
        ) from exc
    except json.JSONDecodeError as exc:
        raise PackageError(
            f"{package.cve} poc/manifest.json is not valid JSON: {exc}"
        ) from exc


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n")


def build_poc(package: Package, *, force: bool = False) -> dict[str, Any]:
    """Generate a package probe and manifest values from the CVE's profile.

    Only the scaffold placeholder is replaced. A hand-authored probe is never
    overwritten. Re-running the builder on an unchanged generated probe is an
    idempotent no-op; a generated probe that no longer matches the rendered
    reference needs ``force``. The proposal records the advisory facts,
    reviewed reference, predicate, and patch-analysis provenance.
    """
    if package.manifest is None or package.advisory is None:
        raise PackageError(f"{package.cve} has no valid package/advisory")
    profile, signals = select_profile(package)

    poc_dir = package.root / "poc"
    exploit_path = poc_dir / "exploit.py"
    manifest_path = poc_dir / "manifest.json"
    proposal_path = poc_dir / "proposal.json"
    existing_manifest = _load_manifest(manifest_path, package)

    replace = False
    if _placeholder(exploit_path):
        replace = True
    else:
        generated = _generated(exploit_path)
        if generated is None:
            raise PackageError(
                f"refusing to replace existing probe {exploit_path}; "
                "CVE-driven generation only replaces the scaffold placeholder"
            )

    source, reference_manifest = _reference(package, profile)
    rendered = _render(source, package, profile)
    expected_manifest = dict(existing_manifest)
    expected_manifest.update(
        {
            "cve": package.cve,
            "entrypoint": "poc.exploit:run",
            "targets": _targets(package),
            "kwargs": copy.deepcopy(reference_manifest["kwargs"]),
            "metric": reference_manifest["metric"],
            "thresholds": copy.deepcopy(reference_manifest["thresholds"]),
            "runs": int(reference_manifest.get("runs", 3)),
            "disruptive": bool(reference_manifest.get("disruptive", False)),
        }
    )
    predicate = _predicate(
        expected_manifest["metric"],
        expected_manifest["thresholds"],
        expected_manifest["runs"],
    )

    if not replace:
        generated_profile, generated_reference = generated
        same_profile = (
            generated_profile == profile.id
            and generated_reference == profile.reference_cve
        )
        identical = (
            same_profile
            and exploit_path.read_text() == rendered
            and existing_manifest == expected_manifest
        )
        if not identical and not force:
            if not same_profile:
                detail = (
                    f"it was generated by profile {generated_profile!r} "
                    f"(reference {generated_reference})"
                )
            else:
                detail = "it no longer matches the rendered reference"
            raise PackageError(
                f"refusing to replace generated probe {exploit_path}: {detail}; "
                "pass --force to regenerate"
            )
        replace = not identical

    package_manifest_path = package.root / "package.json"
    package_manifest = json.loads(package_manifest_path.read_text())
    desired_package_manifest = dict(package_manifest)
    if desired_package_manifest.get("status") == "draft":
        desired_package_manifest["status"] = "poc-implemented"
    validation = dict(desired_package_manifest.get("validation", {}))
    validation["predicate"] = predicate
    desired_package_manifest["validation"] = validation

    unchanged = (
        not replace
        and proposal_path.is_file()
        and desired_package_manifest == package_manifest
    )
    if unchanged:
        return {
            "cve": package.cve,
            "profile": profile.id,
            "proposal": proposal_path,
            "status": "unchanged",
        }

    if replace:
        poc_dir.mkdir(parents=True, exist_ok=True)
        exploit_path.write_text(rendered)
        manifest_path.write_text(json.dumps(expected_manifest, indent=2) + "\n")

    proposal = {
        "schema_version": "1.0",
        "cve": package.cve,
        "status": "built",
        "profile": profile.id,
        "summary": profile.summary,
        "generator_version": GENERATOR_VERSION,
        "source": {
            "advisory_title": package.advisory.title,
            "track": package.advisory.track,
            "adapter": package.manifest.adapter_name,
            "versions": {
                "vulnerable": package.manifest.vulnerable_version,
                "patched": package.manifest.patched_version,
            },
            "reference_cve": profile.reference_cve,
        },
        "probe": {
            "entrypoint": expected_manifest["entrypoint"],
            "kwargs": expected_manifest["kwargs"],
            "metric": expected_manifest["metric"],
            "thresholds": expected_manifest["thresholds"],
            "predicate": predicate,
        },
        "patch_analysis": _patch_analysis(package),
        "selector": {
            "confidence": signals.confidence_for(profile),
            "changed_paths": list(signals.changed_paths),
            "indicators": list(signals.indicators),
            "analyzed_patches": list(signals.patches),
            "notes": list(signals.notes),
        },
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    _write_json(proposal_path, proposal)
    if desired_package_manifest != package_manifest:
        _write_json(package_manifest_path, desired_package_manifest)

    return {
        "cve": package.cve,
        "profile": profile.id,
        "proposal": proposal_path,
        "status": "built",
    }
