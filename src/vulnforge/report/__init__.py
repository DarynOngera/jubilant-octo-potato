"""Report generation."""

import subprocess
import sys
from pathlib import Path

from ..errors import VulnForgeError
from ..paths import Paths
from .package_report import render_package_report, write_package_report

__all__ = [
    "generate_global_report",
    "render_package_report",
    "write_package_report",
]


def generate_global_report(paths: Paths) -> Path:
    script = paths.root / "reports" / "generate_report.py"
    if not script.is_file():
        raise FileNotFoundError(f"global report generator not found: {script}")
    result = subprocess.run(
        [sys.executable, str(script)],
        cwd=str(paths.root),
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        raise VulnForgeError(
            "global report generation failed: "
            f"{(result.stderr or result.stdout).strip()}"
        )
    return paths.root / "reports" / "technical-report.md"
