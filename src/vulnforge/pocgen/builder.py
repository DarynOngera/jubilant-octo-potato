"""Build a vetted lab PoC directly from a package's CVE metadata.

Profiles deliberately reuse a completed, reviewed probe from the same target
and vulnerability family. The builder never invents a transport interaction:
an unsupported CVE remains a draft until a researcher adds a profile.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..errors import PackageError
from ..models import Package


@dataclass(frozen=True)
class Profile:
    id: str
    reference_cve: str
    summary: str
    track: str
    title_phrase: str

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
    ),
    Profile(
        id="bandit-http1-one-byte-chunks",
        reference_cve="CVE-2026-111101",
        summary="HTTP/1.1 request bodies fragmented into one-byte chunks",
        track="http1_resource_exhaustion",
        title_phrase="1-byte chunks",
    ),
)


def _profile(package: Package) -> Profile:
    if package.advisory is None or package.manifest is None:
        raise PackageError(f"{package.cve} has no valid advisory/package manifest")
    if package.manifest.adapter_name != "bandit":
        raise PackageError(
            f"no CVE-driven PoC profile is available for adapter {package.manifest.adapter_name!r}"
        )
    for profile in PROFILES:
        if profile.matches(package.advisory):
            return profile
    raise PackageError(
        f"{package.cve} does not match a supported CVE-driven PoC profile; "
        "add a reviewed profile for its advisory mechanism"
    )


def _placeholder(path: Path) -> bool:
    try:
        text = path.read_text()
    except FileNotFoundError:
        return True
    return "NotImplementedError(\"implement the package probe for this CVE\")" in text


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
    root = package.root.parent / profile.reference_cve / "poc"
    source_path = root / "exploit.py"
    manifest_path = root / "manifest.json"
    try:
        source = source_path.read_text()
        manifest = json.loads(manifest_path.read_text())
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        raise PackageError(
            f"PoC profile {profile.id!r} is missing its reviewed reference package"
        ) from exc
    return source, manifest


def build_poc(package: Package) -> dict[str, Any]:
    """Generate a package probe and manifest values from the CVE's profile.

    Existing hand-authored probes are protected. The generated proposal records
    the advisory facts and reviewed reference used for the decision.
    """
    if package.manifest is None or package.advisory is None:
        raise PackageError(f"{package.cve} has no valid package/advisory")
    profile = _profile(package)
    exploit_path = package.root / "poc" / "exploit.py"
    if not _placeholder(exploit_path):
        raise PackageError(
            f"refusing to replace existing probe {exploit_path}; "
            "CVE-driven generation only replaces the scaffold placeholder"
        )

    source, reference_manifest = _reference(package, profile)
    source = source.replace(profile.reference_cve, package.cve)
    exploit_path.write_text(source)

    manifest_path = package.root / "poc" / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest.update(
        {
            "entrypoint": "poc.exploit:run",
            "targets": _targets(package),
            "kwargs": dict(reference_manifest["kwargs"]),
            "metric": reference_manifest["metric"],
            "thresholds": dict(reference_manifest["thresholds"]),
            "runs": int(reference_manifest.get("runs", 3)),
            "disruptive": bool(reference_manifest.get("disruptive", False)),
        }
    )
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")

    proposal = {
        "schema_version": "1.0",
        "cve": package.cve,
        "status": "built",
        "profile": profile.id,
        "summary": profile.summary,
        "source": {
            "advisory_title": package.advisory.title,
            "track": package.advisory.track,
            "reference_cve": profile.reference_cve,
        },
        "probe": {
            "entrypoint": manifest["entrypoint"],
            "kwargs": manifest["kwargs"],
            "metric": manifest["metric"],
            "thresholds": manifest["thresholds"],
        },
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    proposal_path = package.root / "poc" / "proposal.json"
    proposal_path.write_text(json.dumps(proposal, indent=2) + "\n")

    package_manifest_path = package.root / "package.json"
    package_manifest = json.loads(package_manifest_path.read_text())
    package_manifest["status"] = "poc-implemented"
    validation = dict(package_manifest.get("validation", {}))
    validation["predicate"] = (
        f"generated by {profile.id}; use poc/manifest.json thresholds for validation"
    )
    package_manifest["validation"] = validation
    package_manifest_path.write_text(json.dumps(package_manifest, indent=2) + "\n")

    return {"cve": package.cve, "profile": profile.id, "proposal": proposal_path}
