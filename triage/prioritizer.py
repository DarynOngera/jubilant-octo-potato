#!/usr/bin/env python3
"""
prioritizer.py

Scores every advisory on four independent axes and produces a research
priority order. CVSS is retained as its own column but deliberately does
NOT feed the priority score -- it tells you regulatory/compliance severity,
not how worthwhile the finding is to chase first.

Axes (0-10 each) are analyst judgments stored in ``data/prioritization.json``:

  I  Impact        -- what breaks, and how completely, if it fires.
  E  Exploitability-- protocol complexity, auth, client tooling needed.
  R  Reachability  -- is the vulnerable code on the default, unauthenticated
                       request path, or gated behind opt-in config/features.
  D  Detectability -- how cleanly a lab experiment can observe & measure it.

Weights and exploitability-tier thresholds live in ``config/research.yaml``.

Run:
    python3 triage/prioritizer.py                  # table + matrix
    python3 triage/prioritizer.py --csv out.csv    # also write CSV
    python3 triage/prioritizer.py --check          # verify matrix is current
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
DEFAULT_CONFIG = ROOT / "config" / "research.yaml"
DEFAULT_SCORES = DATA_DIR / "prioritization.json"
SCHEMA_PATH = ROOT / "schemas" / "prioritization.schema.json"
MATRIX_PATH = DATA_DIR / "vulnerability-matrix.json"

AXES = ("impact", "exploitability", "reachability", "detectability")
TIER_NAMES = ("E1", "E2", "E3", "E4")


def load_config(path: Path = DEFAULT_CONFIG) -> tuple[dict[str, float], dict[str, dict]]:
    try:
        raw = yaml.safe_load(path.read_text()) or {}
    except FileNotFoundError as exc:
        raise SystemExit(f"prioritizer: config not found: {path}") from exc
    except yaml.YAMLError as exc:
        raise SystemExit(f"prioritizer: invalid YAML in {path}: {exc}") from exc

    weights_raw = raw.get("priority_weights")
    if not isinstance(weights_raw, dict) or set(weights_raw) != set(AXES):
        raise SystemExit(
            "prioritizer: priority_weights must define exactly "
            + ", ".join(AXES)
        )
    weights = {axis: float(weights_raw[axis]) for axis in AXES}
    total = sum(weights.values())
    if abs(total - 1.0) > 1e-9:
        raise SystemExit(
            f"prioritizer: priority_weights must sum to 1.0, got {total}"
        )

    tiers_raw = raw.get("priority_tiers")
    if not isinstance(tiers_raw, dict) or set(tiers_raw) != set(TIER_NAMES):
        raise SystemExit(
            "prioritizer: priority_tiers must define exactly "
            + ", ".join(TIER_NAMES)
        )
    tiers: dict[str, dict] = {}
    for name in TIER_NAMES:
        entry = tiers_raw[name]
        if not isinstance(entry, dict):
            raise SystemExit(f"prioritizer: priority_tiers.{name} must be a mapping")
        threshold = entry.get("threshold")
        label = entry.get("label")
        if not isinstance(threshold, int) or isinstance(threshold, bool) or not 0 <= threshold <= 10:
            raise SystemExit(
                f"prioritizer: priority_tiers.{name}.threshold must be an integer 0-10"
            )
        if not isinstance(label, str) or not label.strip():
            raise SystemExit(f"prioritizer: priority_tiers.{name}.label is required")
        tiers[name] = {"threshold": threshold, "label": label}

    ordered = sorted(tiers.items(), key=lambda item: item[1]["threshold"], reverse=True)
    thresholds = [entry["threshold"] for _, entry in ordered]
    if thresholds != sorted(thresholds, reverse=True) or len(set(thresholds)) != len(thresholds):
        raise SystemExit("prioritizer: priority tier thresholds must be distinct and descending")
    return weights, tiers


def load_scores(path: Path = DEFAULT_SCORES) -> dict[str, dict]:
    try:
        data = json.loads(path.read_text())
    except FileNotFoundError as exc:
        raise SystemExit(f"prioritizer: scores file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"prioritizer: invalid JSON in {path}: {exc}") from exc

    try:
        schema = json.loads(SCHEMA_PATH.read_text())
    except FileNotFoundError as exc:
        raise SystemExit(f"prioritizer: schema not found: {SCHEMA_PATH}") from exc
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(data), key=lambda error: list(error.path))
    if errors:
        details = "; ".join(
            f"{'/'.join(str(part) for part in error.path) or '<root>'}: {error.message}"
            for error in errors
        )
        raise SystemExit(f"prioritizer: invalid prioritization data: {details}")

    scores = data.get("scores")
    if not isinstance(scores, dict) or not scores:
        raise SystemExit("prioritizer: prioritization data contains no scores")
    return scores


def validate_scores(
    scores: dict[str, dict],
    advisories: list[dict],
) -> None:
    advisory_cves = {str(advisory["cve"]) for advisory in advisories if advisory.get("cve")}
    scored_cves = set(scores)
    missing = sorted(advisory_cves - scored_cves)
    unknown = sorted(scored_cves - advisory_cves)
    if missing:
        raise SystemExit(
            "prioritizer: missing scores for advisories: " + ", ".join(missing)
        )
    if unknown:
        raise SystemExit(
            "prioritizer: scores reference unknown advisories: " + ", ".join(unknown)
        )


def score_priority(score: dict, weights: dict[str, float]) -> float:
    return round(
        weights["impact"] * score["impact"]
        + weights["exploitability"] * score["exploitability"]
        + weights["reachability"] * score["reachability"]
        + weights["detectability"] * score["detectability"],
        2,
    )


def exploitability_tier(exploitability: int, tiers: dict[str, dict]) -> str:
    ordered = sorted(
        tiers.items(), key=lambda item: item[1]["threshold"], reverse=True
    )
    for name, entry in ordered:
        if exploitability >= entry["threshold"]:
            return f"{name} - {entry['label']}"
    return f"E1 - {tiers['E1']['label']}"


def build_matrix(
    advisories: list[dict],
    scores: dict[str, dict],
    weights: dict[str, float],
    tiers: dict[str, dict],
) -> list[dict]:
    by_cve = {str(advisory["cve"]): advisory for advisory in advisories}
    rows = []
    for cve in sorted(scores):
        advisory = by_cve[cve]
        score = scores[cve]
        rows.append(
            {
                "cve": cve,
                "title": advisory["title"],
                "cvss": advisory["cvss_score"],
                "track": advisory["track"],
                "affected": advisory["affected"],
                "fixed_in": advisory["fixed_in"],
                "impact_I": score["impact"],
                "exploit_E": score["exploitability"],
                "reach_R": score["reachability"],
                "detect_D": score["detectability"],
                "priority_P": score_priority(score, weights),
                "exploit_tier": exploitability_tier(score["exploitability"], tiers),
                "notes": score["notes"],
            }
        )
    rows.sort(key=lambda row: (-row["priority_P"], row["cve"]))
    return rows


def _matrix_text(rows: list[dict]) -> str:
    return json.dumps(rows, indent=2)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", type=str, default=None, help="also write matrix to this CSV path")
    parser.add_argument("--check", action="store_true", help="verify the checked-in matrix is current")
    parser.add_argument("--scores", type=Path, default=DEFAULT_SCORES)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    args = parser.parse_args()

    weights, tiers = load_config(args.config)
    scores = load_scores(args.scores)
    advisories = json.loads((DATA_DIR / "advisories.json").read_text())["advisories"]
    validate_scores(scores, advisories)
    rows = build_matrix(advisories, scores, weights, tiers)
    generated = _matrix_text(rows)

    if args.check:
        actual = MATRIX_PATH.read_text() if MATRIX_PATH.exists() else None
        if actual == generated:
            print(f"OK: {MATRIX_PATH}")
            return 0
        print(
            f"DRIFT: {MATRIX_PATH} is not up to date; re-run the prioritizer",
            file=sys.stderr,
        )
        return 1

    print(f"{'CVE':<18}{'CVSS':<6}{'P':<6}{'Tier':<42}{'Track'}")
    print("-" * 100)
    for row in rows:
        print(
            f"{row['cve']:<18}{row['cvss']:<6}{row['priority_P']:<6}"
            f"{row['exploit_tier']:<44} {row['track']}"
        )

    MATRIX_PATH.write_text(generated)
    print(f"\nWrote {MATRIX_PATH}")

    if args.csv:
        with open(args.csv, "w", newline="") as handle:
            writer = csv.DictWriter(
                handle, fieldnames=list(rows[0].keys()), lineterminator="\n"
            )
            writer.writeheader()
            writer.writerows(rows)
        print(f"Wrote {args.csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
