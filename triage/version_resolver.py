#!/usr/bin/env python3
"""
version_resolver.py

Parses Hex-style affected-version ranges ("&gt;= 0.3.1 and &lt; 1.14.1") and resolves
them against a concrete list of Bandit releases, so we know -- for each advisory --
exactly which published versions are vulnerable and which is the first fixed one.

An advisory may declare more than one affected range (Hex/OSV do this when a fix
was backported, or when two ranges are written for different audiences). A single
advisory therefore maps to a *list* of ranges, and a version is vulnerable if it
falls inside any one of them.

Usage:
    python3 triage/version_resolver.py                 # checkpoints + per-version map
    python3 triage/version_resolver.py --list          # per-version CVE map
    python3 triage/version_resolver.py --checkpoints   # lab checkpoint plan
    python3 triage/version_resolver.py --summary       # compact exposure bands
    python3 triage/version_resolver.py --check         # verify checked-in artifacts
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

try:
    from packaging.version import Version, InvalidVersion
except ImportError:  # pragma: no cover
    raise SystemExit(
        "Missing dependency 'packaging'. Create/activate a venv and install "
        "requirements.txt first:\n"
        "  python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt"
    )

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

# All published Bandit releases up to 1.14.1 (pre-release suffixes included),
# taken from the Hex package version listing. Kept as static data so triage is
# reproducible without hitting the network every run; refresh with
# `python3 triage/version_resolver.py --list` when a new release ships.
KNOWN_VERSIONS = [
    "0.1.0", "0.1.1",
    "0.2.0", "0.2.1", "0.2.2", "0.2.3",
    "0.3.2", "0.3.3", "0.3.4", "0.3.5", "0.3.6", "0.3.7", "0.3.8", "0.3.9",
    "0.4.0", "0.4.1", "0.4.2", "0.4.3", "0.4.4", "0.4.5", "0.4.6", "0.4.7", "0.4.8", "0.4.9", "0.4.10",
    "0.5.0", "0.5.1", "0.5.2", "0.5.3", "0.5.4", "0.5.5", "0.5.6", "0.5.7", "0.5.8", "0.5.9", "0.5.10", "0.5.11",
    "0.6.0", "0.6.1", "0.6.2", "0.6.3", "0.6.4", "0.6.5", "0.6.6", "0.6.7", "0.6.8", "0.6.9", "0.6.10", "0.6.11",
    "0.7.0", "0.7.1", "0.7.2", "0.7.3", "0.7.4", "0.7.5", "0.7.6", "0.7.7",
    "1.0.0-pre.1", "1.0.0-pre.2", "1.0.0-pre.3", "1.0.0-pre.4", "1.0.0-pre.5",
    "1.0.0-pre.6", "1.0.0-pre.7", "1.0.0-pre.8", "1.0.0-pre.9", "1.0.0-pre.10",
    "1.0.0-pre.11", "1.0.0-pre.12", "1.0.0-pre.13", "1.0.0-pre.14", "1.0.0-pre.15",
    "1.0.0-pre.16", "1.0.0-pre.17", "1.0.0-pre.18", "1.0.0",
    "1.1.0", "1.1.1", "1.1.2", "1.1.3",
    "1.2.0", "1.2.1", "1.2.2", "1.2.3",
    "1.3.0",
    "1.4.0", "1.4.1", "1.4.2",
    "1.5.0", "1.5.1", "1.5.2", "1.5.3", "1.5.4", "1.5.5", "1.5.6", "1.5.7",
    "1.6.0", "1.6.1", "1.6.2", "1.6.3", "1.6.4", "1.6.5", "1.6.6", "1.6.7", "1.6.8", "1.6.9", "1.6.10", "1.6.11",
    "1.7.0", "1.8.0", "1.9.0",
    "1.10.0", "1.10.1", "1.10.2", "1.10.3", "1.10.4",
    "1.11.0", "1.11.1",
    "1.12.0", "1.12.1", "1.12.2", "1.12.3", "1.12.4", "1.12.5",
    "1.13.0", "1.13.1",
    "1.14.0", "1.14.1",
]

# Tokenizes comparators in an affected-version expression. Supports the Hex
# HTML-escaped form (&gt;= / &lt;) after normalization, multiple ranges
# concatenated with "and"/commas/whitespace, and exact pins ("= 1.2.3").
_COMPARATOR_RE = re.compile(
    r"(?P<op>>=|<=|==|=|>|<)\s*(?P<version>[0-9][0-9A-Za-z.\-+]*)"
)
_BARE_VERSION_RE = re.compile(r"^[0-9][0-9A-Za-z.\-+]*$")
_HTML_ENTITIES = {"&gt;": ">", "&lt;": "<", "&amp;": "&"}


@dataclass(frozen=True)
class VersionRange:
    """One contiguous affected range. A missing bound means unbounded."""

    lower_op: str | None
    lower: Version | None
    upper_op: str | None
    upper: Version | None

    def contains(self, version: Version) -> bool:
        if self.lower is not None:
            if self.lower_op == ">":
                if not version > self.lower:
                    return False
            elif not version >= self.lower:
                return False
        if self.upper is not None:
            if self.upper_op == "<":
                if not version < self.upper:
                    return False
            elif not version <= self.upper:
                return False
        return True

    def __str__(self) -> str:
        parts = []
        if self.lower is not None:
            parts.append(f"{self.lower_op} {self.lower}")
        if self.upper is not None:
            parts.append(f"{self.upper_op} {self.upper}")
        return " and ".join(parts)


def _parse_version(value: str) -> Version:
    try:
        return Version(value)
    except InvalidVersion as exc:
        raise ValueError(f"Invalid version {value!r} in affected-version range") from exc


def _make_range(lower_op: str | None, lower: str | None,
                upper_op: str | None, upper: str | None) -> VersionRange:
    return VersionRange(
        lower_op=lower_op,
        lower=_parse_version(lower) if lower is not None else None,
        upper_op=upper_op,
        upper=_parse_version(upper) if upper is not None else None,
    )


def parse_ranges(affected: str) -> list[VersionRange]:
    """
    Parse an affected-version expression into one or more contiguous ranges.

    Examples:
        ">= 0.1.0 and < 1.14.0"                    -> one range
        ">= 1.6.1 and < 1.11.1 >= 1.6.0 and < 1.11.1" -> two overlapping ranges
        ">= 1.0 and < 1.2, >= 2.0 and < 2.1"       -> two disjoint ranges
        "< 1.11.0"                                  -> single upper bound
        "= 1.0.0"                                   -> exact version
    """
    text = affected.strip()
    for entity, char in _HTML_ENTITIES.items():
        text = text.replace(entity, char)

    tokens = list(_COMPARATOR_RE.finditer(text))
    if not tokens:
        if _BARE_VERSION_RE.match(text):
            return [_make_range(">=", text, "<=", text)]
        raise ValueError(f"Unparseable affected-version expression: {affected!r}")

    ranges: list[VersionRange] = []
    pending_lower: tuple[str, str] | None = None

    for token in tokens:
        op, version = token.group("op"), token.group("version")
        if op in (">", ">="):
            if pending_lower is not None:
                # A previous lower bound never got an upper bound; keep it as
                # an open-ended range and start a new one.
                ranges.append(_make_range(pending_lower[0], pending_lower[1], None, None))
            pending_lower = (op, version)
        elif op in ("<", "<="):
            if pending_lower is not None:
                ranges.append(_make_range(pending_lower[0], pending_lower[1], op, version))
                pending_lower = None
            else:
                ranges.append(_make_range(None, None, op, version))
        else:  # "=" / "==" exact pin
            if pending_lower is not None:
                ranges.append(_make_range(pending_lower[0], pending_lower[1], None, None))
                pending_lower = None
            ranges.append(_make_range(">=", version, "<=", version))

    if pending_lower is not None:
        ranges.append(_make_range(pending_lower[0], pending_lower[1], None, None))

    return ranges


def _ranges_from_affected_value(affected) -> list[VersionRange]:
    """Accept a string, a list of strings, or an advisory dict."""
    if isinstance(affected, dict):
        return ranges_for_advisory(affected)
    if isinstance(affected, str):
        return parse_ranges(affected)
    if isinstance(affected, (list, tuple)):
        ranges: list[VersionRange] = []
        for item in affected:
            if isinstance(item, str):
                ranges.extend(parse_ranges(item))
            elif isinstance(item, dict):
                ranges.extend(_ranges_from_dict(item))
            else:
                raise TypeError(f"Unsupported affected-version entry: {item!r}")
        return ranges
    raise TypeError(f"Unsupported affected-version value: {affected!r}")


def _ranges_from_dict(item: dict) -> list[VersionRange]:
    """Support OSV-style {"introduced": "1.0.0", "fixed": "1.2.0"} entries."""
    if "introduced" in item or "fixed" in item:
        introduced = item.get("introduced")
        fixed = item.get("fixed")
        return [_make_range(
            ">=" if introduced not in (None, "0") else None,
            introduced if introduced not in (None, "0") else None,
            "<" if fixed is not None else None,
            fixed,
        )]
    if "lower" in item or "upper" in item:
        return [_make_range(
            item.get("lower_op", ">="),
            item.get("lower"),
            item.get("upper_op", "<"),
            item.get("upper"),
        )]
    raise ValueError(f"Unsupported affected-range object: {item!r}")


def ranges_for_advisory(adv: dict) -> list[VersionRange]:
    """Return every affected range declared by one advisory."""
    if adv.get("affected_ranges"):
        return _ranges_from_affected_value(adv["affected_ranges"])
    if "affected" not in adv:
        raise KeyError(f"Advisory {adv.get('cve', '<unknown>')} has no 'affected' field")
    return _ranges_from_affected_value(adv["affected"])


def version_in_range(version: str, affected) -> bool:
    """True if `version` falls inside any affected range in `affected`."""
    try:
        candidate = _parse_version(version)
    except ValueError:
        return False
    try:
        ranges = _ranges_from_affected_value(affected)
    except (TypeError, ValueError):
        return False
    return any(r.contains(candidate) for r in ranges)


def resolve_all(advisories: Iterable[dict]) -> dict[str, list[str]]:
    """Map each known version -> sorted list of CVEs affecting it."""
    parsed_versions = {v: _parse_version(v) for v in KNOWN_VERSIONS}
    result: dict[str, list[str]] = {v: [] for v in KNOWN_VERSIONS}

    for adv in advisories:
        ranges = ranges_for_advisory(adv)
        for version, parsed in parsed_versions.items():
            if any(r.contains(parsed) for r in ranges):
                result[version].append(adv["cve"])

    return {version: sorted(set(cves)) for version, cves in result.items()}


def exposure_summary(mapping: dict[str, list[str]]) -> list[dict]:
    """Group consecutive known versions that share the same vulnerable-CVE set."""
    versions = list(mapping)
    bands: list[dict] = []
    i = 0
    while i < len(versions):
        key = tuple(mapping[versions[i]])
        j = i + 1
        while j < len(versions) and tuple(mapping[versions[j]]) == key:
            j += 1
        bands.append({
            "start": versions[i],
            "end": versions[j - 1],
            "count": len(key),
            "cves": list(key),
        })
        i = j
    return bands


def _fixed_versions(adv: dict) -> list[str]:
    fixed = adv.get("fixed_in")
    if isinstance(fixed, (list, tuple)):
        return [str(v) for v in fixed]
    if fixed is None:
        return []
    return [str(fixed)]


def suggested_checkpoints(advisories: Iterable[dict],
                          exposure: dict[str, list[str]] | None = None) -> list[dict]:
    """
    Pick the versions needed to bracket every fix boundary:
    for each distinct fixed_in version, include the version immediately
    before it (last vulnerable) and the fixed version itself (first patched).

    Entries are deduplicated by version. A version can be both "last vulnerable"
    for one boundary and "first patched" for another (e.g. 1.11.0); the merged
    entry records both roles. Each entry also carries the full set of CVEs that
    affect that version, which is *not* the same as the CVEs fixed there.
    """
    advisories = list(advisories)
    if exposure is None:
        exposure = resolve_all(advisories)

    all_fixes = sorted({fix for adv in advisories for fix in _fixed_versions(adv)}, key=Version)
    missing = [fix for fix in all_fixes if fix not in KNOWN_VERSIONS]
    if missing:
        raise ValueError(
            "fixed_in version(s) not present in KNOWN_VERSIONS: "
            + ", ".join(missing)
            + " -- refresh KNOWN_VERSIONS from the Hex version list"
        )

    by_version: dict[str, dict] = {}
    for fix in all_fixes:
        idx = KNOWN_VERSIONS.index(fix)
        prior = KNOWN_VERSIONS[idx - 1] if idx > 0 else None
        cves_fixed_here = sorted({
            adv["cve"] for adv in advisories if fix in _fixed_versions(adv)
        })

        def add(version: str | None, role: str) -> None:
            if version is None:
                return
            entry = by_version.setdefault(version, {
                "version": version,
                "roles": set(),
                "fixes_boundaries": set(),
                "cves_fixed_here": set(),
            })
            entry["roles"].add(role)
            entry["fixes_boundaries"].add(fix)
            entry["cves_fixed_here"].update(cves_fixed_here)

        add(prior, "last-vulnerable")
        add(fix, "first-patched")

    checkpoints: list[dict] = []
    for version in sorted(by_version, key=Version):
        entry = by_version[version]
        roles = sorted(entry["roles"])
        boundaries = sorted(entry["fixes_boundaries"], key=Version)
        fixed_cves = sorted(entry["cves_fixed_here"])
        vulnerable_cves = exposure.get(version, [])
        checkpoints.append({
            "version": version,
            "roles": roles,
            "fixes_boundaries": boundaries,
            "cves_fixed_here": fixed_cves,
            "vulnerable_cves": vulnerable_cves,
            "vulnerable_count": len(vulnerable_cves),
            # Backwards-compatible single-boundary aliases.
            "role": roles[0] if len(roles) == 1 else "mixed",
            "fixes_boundary": boundaries[0] if len(boundaries) == 1 else None,
            "cves": fixed_cves,
        })
    return checkpoints


def _json(data) -> str:
    return json.dumps(data, indent=2)


def _check_artifact(path: Path, expected: str) -> bool:
    actual = path.read_text() if path.exists() else None
    if actual == expected:
        print(f"OK: {path}")
        return True
    print(f"DRIFT: {path} is not up to date; re-run the resolver", file=sys.stderr)
    return False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true", help="print/write per-version CVE map")
    ap.add_argument("--checkpoints", action="store_true", help="print/write lab checkpoint plan")
    ap.add_argument("--summary", action="store_true", help="print compact exposure bands")
    ap.add_argument("--check", action="store_true", help="verify checked-in artifacts are current")
    args = ap.parse_args()

    advisories = json.loads((DATA_DIR / "advisories.json").read_text())["advisories"]
    exposure = resolve_all(advisories)
    checkpoints = suggested_checkpoints(advisories, exposure)

    explicit = args.list or args.checkpoints or args.summary or args.check
    do_list = args.list or not explicit
    do_checkpoints = args.checkpoints or not explicit

    if args.check:
        ok = _check_artifact(DATA_DIR / "version-cve-map.json", _json(exposure))
        ok &= _check_artifact(DATA_DIR / "lab-checkpoints.json", _json(checkpoints))
        return 0 if ok else 1

    if do_list:
        print(_json(exposure))
        (DATA_DIR / "version-cve-map.json").write_text(_json(exposure))

    if do_checkpoints:
        print(_json(checkpoints))
        (DATA_DIR / "lab-checkpoints.json").write_text(_json(checkpoints))

    if args.summary:
        for band in exposure_summary(exposure):
            label = band["start"] if band["start"] == band["end"] else f"{band['start']} .. {band['end']}"
            print(f"{label:<24} {band['count']:2d} CVEs")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
