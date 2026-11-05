"""Commit-diff capture and root-cause scaffolds."""
from __future__ import annotations

import hashlib
import json
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..errors import VulnForgeError
from ..models import Package
from .osv import IngestError

DEFAULT_GITHUB_REPO = "mtrudel/bandit"
GITHUB_PATCH = "https://github.com/mtrudel/bandit/commit/{sha}.patch"
GITHUB_PATCH_TEMPLATE = "https://github.com/{repo}/commit/{sha}.patch"


def fetch_patch(
    commit: str,
    cache_dir: Path,
    refresh: bool = False,
    repo: str = DEFAULT_GITHUB_REPO,
) -> Path:
    cache_dir.mkdir(parents=True, exist_ok=True)
    patch_path = cache_dir / f"{commit}.patch"
    meta_path = cache_dir / f"{commit}.json"
    if patch_path.is_file() and meta_path.is_file() and not refresh:
        return patch_path

    url = GITHUB_PATCH_TEMPLATE.format(repo=repo, sha=commit)
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            content = response.read()
    except (urllib.error.URLError, TimeoutError) as exc:
        raise IngestError(f"could not fetch commit {commit}: {exc}") from exc

    patch_path.write_bytes(content)
    meta_path.write_text(
        json.dumps(
            {
                "commit": commit,
                "source": url,
                "retrieved_at": datetime.now(timezone.utc).isoformat(),
                "sha256": hashlib.sha256(content).hexdigest(),
                "bytes": len(content),
            },
            indent=2,
        )
        + "\n"
    )
    return patch_path


def changed_files(patch_text: str) -> list[str]:
    files = []
    for match in re.finditer(r"^diff --git a/(.+?) b/(.+)$", patch_text, re.M):
        files.append(match.group(2))
    return sorted(set(files))


def analyze_package(
    package: Package, refresh: bool = False, repo: str | None = None
) -> dict[str, Any]:
    if package.advisory is None:
        raise VulnForgeError(f"{package.cve} has no advisory")
    commits = list(package.advisory.commits or [])
    repo = repo or DEFAULT_GITHUB_REPO
    commits_dir = package.root / "analysis" / "commits"
    captured = []
    errors = []
    all_files: set[str] = set()
    for commit in commits:
        try:
            patch_path = fetch_patch(commit, commits_dir, refresh=refresh, repo=repo)
            files = changed_files(patch_path.read_text(errors="replace"))
            all_files.update(files)
            captured.append({"commit": commit, "patch": str(patch_path), "files": files})
        except IngestError as exc:
            errors.append({"commit": commit, "error": str(exc)})

    scaffold = package.root / "analysis" / "root-cause.generated.md"
    lines = [
        f"# {package.cve} — Generated root-cause scaffold",
        "",
        f"Advisory: {package.advisory.title}",
        "",
        "## Fixing commits",
        "",
    ]
    for item in captured:
        lines.append(f"- `{item['commit']}`")
        if item["files"]:
            lines.append(f"  - changed files: {', '.join(item['files'])}")
    if errors:
        lines.append("")
        lines.append("## Fetch errors")
        for error in errors:
            lines.append(f"- `{error['commit']}`: {error['error']}")
    lines.extend(
        [
            "",
            "## Questions to answer",
            "",
            "1. Which changed file owns the vulnerable state?",
            "2. What is the allocation/retention mechanism?",
            "3. What exactly does the fix change (cap, reuse, flush, accounting)?",
            "4. Which observable in the lab best distinguishes the two versions?",
            "",
            "Human review is required before this is treated as a root cause.",
            "",
        ]
    )
    scaffold.write_text("\n".join(lines))

    return {
        "cve": package.cve,
        "commits": captured,
        "errors": errors,
        "changed_files": sorted(all_files),
        "scaffold": str(scaffold),
    }
