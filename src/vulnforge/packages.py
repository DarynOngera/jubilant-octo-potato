"""Package discovery, loading, and cross-file validation."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from .contract import ANALYSIS_FILES, DETECTION_FILES, missing_artifacts
from .errors import PackageError
from .models import Advisory, LabSpec, Package, PackageManifest, ProbeManifest
from .paths import Paths
from .schema import validate_instance

REQUIRED_ANALYSIS_FILES = ANALYSIS_FILES
REQUIRED_DETECTION_FILES = DETECTION_FILES


def _load_json(path: Path, label: str, errors: list[str]) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text())
    except FileNotFoundError:
        errors.append(f"{label} not found: {path}")
        return None
    except json.JSONDecodeError as exc:
        errors.append(f"{label} is not valid JSON ({path}): {exc}")
        return None
    if not isinstance(data, dict):
        errors.append(f"{label} must be a JSON object: {path}")
        return None
    return data


def discover_package_dirs(paths: Paths) -> list[Path]:
    if not paths.packages.exists():
        return []
    return sorted(
        path
        for path in paths.packages.iterdir()
        if path.is_dir() and path.name.startswith("CVE-")
    )


def package_path(package_root: Path, relative: str) -> Path:
    """Resolve a package-relative path without allowing it to escape the package."""
    root = package_root.resolve()
    path = (root / relative).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise PackageError(
            f"package path {relative!r} escapes package root {root}"
        ) from exc
    return path


def _package_path(
    package_root: Path, relative: str, label: str, errors: list[str]
) -> Path:
    """Return a safe package path and retain validation errors for the caller."""
    try:
        return package_path(package_root, relative)
    except PackageError as exc:
        errors.append(f"{label}: {exc}")
        return package_root / ".invalid-package-path"


def _version_in_affected_ranges(version: str, affected: Any) -> bool:
    """Return whether a version is covered by a package/advisory range.

    Package manifests accept the same range forms as the advisory schema: a
    Hex-style expression, a list of expressions, or OSV-style introduced/fixed
    objects.  ``or`` separates independent ranges; ``and`` joins constraints
    within a range.
    """
    try:
        candidate = Version(version)
    except InvalidVersion:
        return False

    if isinstance(affected, dict):
        introduced = affected.get("introduced")
        fixed = affected.get("fixed")
        try:
            if introduced not in (None, "", "0") and candidate < Version(str(introduced)):
                return False
            if fixed not in (None, "") and candidate >= Version(str(fixed)):
                return False
        except InvalidVersion:
            return False
        return True

    if isinstance(affected, (list, tuple)):
        return any(_version_in_affected_ranges(version, item) for item in affected)

    if not isinstance(affected, str):
        return False

    normalized = (
        affected.replace("&gt;", ">")
        .replace("&lt;", "<")
        .replace("&amp;", "&")
    )
    for expression in re.split(r"\s+or\s+|\s*;\s*", normalized):
        expression = re.sub(r"\s+and\s+", ",", expression.strip())
        if not expression:
            continue
        if re.fullmatch(r"[0-9][0-9A-Za-z.\-+]*", expression):
            expression = f"=={expression}"
        try:
            if candidate in SpecifierSet(expression):
                return True
        except InvalidSpecifier:
            continue
    return False


def _check(condition: bool, message: str, errors: list[str]) -> None:
    if not condition:
        errors.append(message)


def _contains_version(fixed_in: Any, version: str) -> bool:
    if isinstance(fixed_in, str):
        return fixed_in == version
    if isinstance(fixed_in, (list, tuple)):
        return version in {str(item) for item in fixed_in}
    return False


def load_package(package_root: Path, schemas_dir: Path) -> Package:
    package_root = package_root.resolve()
    pkg = Package(root=package_root)

    manifest_path = package_root / "package.json"
    manifest_data = _load_json(manifest_path, "package.json", pkg.errors)
    if manifest_data is not None:
        pkg.errors.extend(
            validate_instance(
                manifest_data, schemas_dir, "package", label="package.json"
            )
        )
        try:
            pkg.manifest = PackageManifest.from_dict(manifest_data)
        except (KeyError, TypeError, ValueError) as exc:
            pkg.errors.append(f"package.json could not be parsed: {exc}")

    manifest = pkg.manifest
    advisory_rel = manifest.paths.get("advisory", "advisory.json") if manifest else "advisory.json"
    lab_rel = manifest.paths.get("lab", "lab/lab.json") if manifest else "lab/lab.json"
    probe_rel = manifest.paths.get("poc", "poc/manifest.json") if manifest else "poc/manifest.json"

    advisory_data = _load_json(
        _package_path(package_root, advisory_rel, "advisory", pkg.errors),
        "advisory",
        pkg.errors,
    )
    if advisory_data is not None:
        pkg.errors.extend(
            validate_instance(
                advisory_data, schemas_dir, "advisory", label=advisory_rel
            )
        )
        try:
            pkg.advisory = Advisory.from_dict(advisory_data)
        except (KeyError, TypeError, ValueError) as exc:
            pkg.errors.append(f"advisory could not be parsed: {exc}")

    lab_data = _load_json(
        _package_path(package_root, lab_rel, "lab spec", pkg.errors),
        "lab spec",
        pkg.errors,
    )
    if lab_data is not None:
        pkg.errors.extend(
            validate_instance(lab_data, schemas_dir, "lab", label=lab_rel)
        )
        try:
            pkg.lab = LabSpec.from_dict(lab_data)
        except (KeyError, TypeError, ValueError) as exc:
            pkg.errors.append(f"lab spec could not be parsed: {exc}")

    probe_data = _load_json(
        _package_path(package_root, probe_rel, "probe manifest", pkg.errors),
        "probe manifest",
        pkg.errors,
    )
    if probe_data is not None:
        pkg.errors.extend(
            validate_instance(
                probe_data, schemas_dir, "probe", label=probe_rel
            )
        )
        try:
            pkg.probe = ProbeManifest.from_dict(probe_data)
        except (KeyError, TypeError, ValueError) as exc:
            pkg.errors.append(f"probe manifest could not be parsed: {exc}")

    if manifest is not None:
        # These artifacts are not modeled as dataclasses yet, but they are
        # part of the package contract and must be schema-valid.
        artifact_checks = (
            (
                _package_path(
                    package_root,
                    manifest.paths.get("analysis", "analysis"),
                    "analysis directory",
                    pkg.errors,
                ) / "exploitability.json",
                "exploitability",
                "analysis/exploitability.json",
            ),
            (
                _package_path(
                    package_root,
                    manifest.paths.get("detection", "detection"),
                    "detection directory",
                    pkg.errors,
                ) / "spec.json",
                "detection-spec",
                "detection/spec.json",
            ),
            (
                _package_path(
                    package_root,
                    manifest.paths.get("detection", "detection"),
                    "detection directory",
                    pkg.errors,
                ) / "evidence.json",
                "detection",
                "detection/evidence.json",
            ),
            (
                _package_path(
                    package_root,
                    manifest.paths.get("evidence", "evidence"),
                    "evidence directory",
                    pkg.errors,
                ) / "execution.json",
                "evidence",
                "evidence/execution.json",
            ),
            (
                _package_path(
                    package_root,
                    manifest.paths.get("lab", "lab/lab.json"),
                    "lab spec",
                    pkg.errors,
                ).parent
                / "provenance.json",
                "provenance",
                "lab/provenance.json",
            ),
        )
        for path, schema_name, label in artifact_checks:
            if not path.is_file():
                continue
            data = _load_json(path, label, pkg.errors)
            if data is None:
                continue
            pkg.errors.extend(
                validate_instance(data, schemas_dir, schema_name, label=label)
            )
            if data.get("cve") != manifest.cve:
                pkg.errors.append(
                    f"{label} cve {data.get('cve')!r} does not match package cve "
                    f"{manifest.cve!r}"
                )

    if pkg.manifest is not None:
        check_package_consistency(pkg)
    return pkg


def check_package_consistency(pkg: Package) -> None:
    errors = pkg.errors
    manifest = pkg.manifest
    assert manifest is not None

    _check(pkg.root.name == manifest.cve, (
        f"directory name {pkg.root.name!r} does not match package cve "
        f"{manifest.cve!r}"
    ), errors)

    if pkg.advisory is not None:
        _check(pkg.advisory.cve == manifest.cve, (
            f"advisory cve {pkg.advisory.cve!r} does not match package cve "
            f"{manifest.cve!r}"
        ), errors)
        _check(
            _contains_version(pkg.advisory.fixed_in, manifest.first_fixed),
            (
                f"advisory fixed_in {pkg.advisory.fixed_in!r} does not include "
                f"first_fixed {manifest.first_fixed!r}"
            ),
            errors,
        )
        _check(
            _version_in_affected_ranges(
                manifest.vulnerable_version,
                pkg.advisory.affected_ranges or pkg.advisory.affected,
            ),
            (
                f"vulnerable version {manifest.vulnerable_version!r} is not in "
                f"the advisory affected range"
            ),
            errors,
        )

    if pkg.lab is not None:
        _check(pkg.lab.cve == manifest.cve, (
            f"lab cve {pkg.lab.cve!r} does not match package cve "
            f"{manifest.cve!r}"
        ), errors)
        _check(pkg.lab.adapter_name == manifest.adapter_name, (
            f"lab adapter {pkg.lab.adapter_name!r} does not match package adapter "
            f"{manifest.adapter_name!r}"
        ), errors)
        _check(
            pkg.lab.versions.get("vulnerable") == manifest.vulnerable_version,
            (
                f"lab vulnerable version {pkg.lab.versions.get('vulnerable')!r} "
                f"does not match package version {manifest.vulnerable_version!r}"
            ),
            errors,
        )
        _check(
            pkg.lab.versions.get("patched") == manifest.patched_version,
            (
                f"lab patched version {pkg.lab.versions.get('patched')!r} "
                f"does not match package version {manifest.patched_version!r}"
            ),
            errors,
        )
        for role in ("vulnerable", "patched"):
            target = pkg.lab.target_by_role(role)
            _check(target is not None, f"lab is missing a {role!r} target", errors)
            if target is not None:
                expected = (
                    manifest.vulnerable_version
                    if role == "vulnerable"
                    else manifest.patched_version
                )
                _check(target.version == expected, (
                    f"lab {role} target version {target.version!r} does not "
                    f"match package version {expected!r}"
                ), errors)

    if pkg.probe is not None:
        _check(pkg.probe.cve == manifest.cve, (
            f"probe cve {pkg.probe.cve!r} does not match package cve "
            f"{manifest.cve!r}"
        ), errors)
        _check(
            pkg.probe.module_path(pkg.root).is_file(),
            f"probe entrypoint module not found: {pkg.probe.module_path(pkg.root)}",
            errors,
        )
        if pkg.lab is not None:
            for role in ("vulnerable", "patched"):
                target = pkg.lab.target_by_role(role)
                _check(
                    target is not None and pkg.probe.targets.get(role) == target.name,
                    (
                        f"probe target.{role} {pkg.probe.targets.get(role)!r} "
                        f"does not match lab {role} target "
                        f"{(target.name if target else None)!r}"
                    ),
                    errors,
                )

    _check(
        manifest.patched_version == manifest.first_fixed,
        (
            "M1 requires patched == first_fixed; a later patched release needs "
            "an explicit rationale and a future schema field"
        ),
        errors,
    )

    for rel in (
        manifest.paths.get("advisory", "advisory.json"),
        manifest.paths.get("lab", "lab/lab.json"),
        manifest.paths.get("poc", "poc/manifest.json"),
    ):
        path = _package_path(pkg.root, rel, "referenced file", errors)
        _check(path.is_file(), f"referenced file is missing: {rel}", errors)

    for directory, filenames in (
        (manifest.paths.get("analysis", "analysis"), REQUIRED_ANALYSIS_FILES),
        (manifest.paths.get("detection", "detection"), REQUIRED_DETECTION_FILES),
    ):
        base = _package_path(pkg.root, directory, "referenced directory", errors)
        _check(base.is_dir(), f"referenced directory is missing: {directory}", errors)
        for filename in filenames:
            _check((base / filename).is_file(), (
                f"referenced file is missing: {directory}/{filename}"
            ), errors)

    tests_dir = _package_path(
        pkg.root, manifest.paths.get("tests", "tests"), "tests directory", errors
    )
    _check(tests_dir.is_dir(), f"referenced tests directory is missing: {tests_dir}", errors)

    report_rel = manifest.paths.get("report")
    if report_rel:
        _check(_package_path(pkg.root, report_rel, "report", errors).is_file(), (
            f"referenced report is missing: {report_rel}"
        ), errors)

    verdict = manifest.last_verdict
    expected_by_status = {
        "validated": "CONFIRMED",
        "inconclusive": "INCONCLUSIVE",
    }
    if manifest.status in expected_by_status:
        _check(verdict == expected_by_status[manifest.status], (
            f"status {manifest.status!r} requires last_verdict "
            f"{expected_by_status[manifest.status]!r}, found {verdict!r}"
        ), errors)

    evidence_rel = manifest.validation.get("evidence")
    if evidence_rel:
        _check(_package_path(pkg.root, evidence_rel, "validation evidence", errors).is_file(), (
            f"validation evidence is missing: {evidence_rel}"
        ), errors)

    for relative in missing_artifacts(pkg.root, manifest.status, manifest.paths):
        errors.append(
            f"required artifact for status {manifest.status!r} is missing: {relative}"
        )


def load_packages(paths: Paths) -> list[Package]:
    return [load_package(path, paths.schemas) for path in discover_package_dirs(paths)]


def find_package(paths: Paths, cve: str) -> Package:
    for path in discover_package_dirs(paths):
        if path.name == cve:
            return load_package(path, paths.schemas)
    raise PackageError(
        f"package {cve!r} not found under {paths.packages}; known packages: "
        + (", ".join(p.name for p in discover_package_dirs(paths)) or "<none>")
    )


def validate_against_catalog(pkg: Package, paths: Paths) -> list[str]:
    """Check the materialized advisory against the global catalog."""
    errors: list[str] = []
    if pkg.advisory is None:
        return errors

    catalog_path = paths.data / "advisories.json"
    try:
        catalog = json.loads(catalog_path.read_text())["advisories"]
    except (FileNotFoundError, KeyError, json.JSONDecodeError) as exc:
        return [f"could not read advisory catalog {catalog_path}: {exc}"]

    rows = {row.get("cve"): row for row in catalog if isinstance(row, dict)}
    source = rows.get(pkg.advisory.cve)
    if source is None:
        return [f"{pkg.advisory.cve} is not present in {catalog_path}"]

    for field in (
        "title",
        "affected",
        "affected_ranges",
        "fixed_in",
        "track",
        "commits",
        "references",
        "ghsa",
        "osv",
        "cvss_score",
        "cvss_vector",
        "published",
    ):
        expected = source.get(field)
        actual = getattr(pkg.advisory, field, None)
        if expected is None and actual in (None, [], {}):
            continue
        if actual != expected:
            errors.append(
                f"advisory {field!r} is out of sync with {catalog_path}: "
                f"package={actual!r} catalog={expected!r}"
            )
    return errors


def validate_package(pkg: Package, paths: Paths) -> list[str]:
    return [*pkg.errors, *validate_against_catalog(pkg, paths)]
