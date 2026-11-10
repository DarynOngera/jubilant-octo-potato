"""Patch-analysis signals used by the CVE-to-profile selector.

The selector's primary input is the advisory: its track and title must match a
reviewed profile. Captured fixing patches are a secondary, corroborating
signal. They can raise confidence when the changed modules and keywords agree
with the profile, and they can veto automatic selection when the patch clearly
belongs to a different protocol family.

Patch analysis never overrides the advisory. It only prevents the engine from
silently assigning a profile to an advisory whose own fixing commit contradicts
it.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..ingest.github import changed_files

PROTOCOL_INDICATORS = ("http1", "http2", "websocket")

# Indicators are coarse on purpose: the goal is corroboration, not a parser.
# Each pattern is matched case-insensitively against the captured patch text
# (file paths and diff bodies).
_INDICATOR_PATTERNS: dict[str, re.Pattern[str]] = {
    "http1": re.compile(r"bandit/http1|http1|http/1", re.IGNORECASE),
    "http2": re.compile(r"bandit/http2|http2|http/2", re.IGNORECASE),
    "websocket": re.compile(r"websocket|websock", re.IGNORECASE),
    "length_cap": re.compile(
        r"max_(?:chunk|body|frame)|opts\[:length\]|length:\s|"
        r"read_length|@max_|length[ _-]?cap|\bcap\b",
        re.IGNORECASE,
    ),
    "chunked_framing": re.compile(r"chunk", re.IGNORECASE),
    "data_frames": re.compile(
        r"data[ _]frame|frame_size|max_frame", re.IGNORECASE
    ),
    "flow_control": re.compile(
        r"flow[ _-]control|window_update|window size", re.IGNORECASE
    ),
    "timeout": re.compile(r"timeout|deadline", re.IGNORECASE),
    "trailers": re.compile(r"trailer", re.IGNORECASE),
    "accounting": re.compile(r"account|memory|alloc", re.IGNORECASE),
    "cleanup": re.compile(r"cleanup|flush|reuse", re.IGNORECASE),
    "parser_validation": re.compile(
        r"malformed|decode_packet|validate|invalid", re.IGNORECASE
    ),
}


@dataclass(frozen=True)
class PatchSignals:
    """What the captured fixing patches imply about an advisory."""

    changed_paths: tuple[str, ...] = ()
    indicators: tuple[str, ...] = ()
    patches: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()

    @property
    def available(self) -> bool:
        return bool(self.patches)

    @property
    def protocols(self) -> tuple[str, ...]:
        return tuple(
            indicator
            for indicator in PROTOCOL_INDICATORS
            if indicator in self.indicators
        )

    def confidence_for(self, profile: Any) -> float:
        """0.0 when the patch contradicts the profile, up to 1.0 on agreement.

        With no captured patch the selector falls back to the advisory alone,
        which is a supported (lower-confidence) path.
        """
        if not self.available:
            return 0.5
        if profile.protocol and profile.protocol not in self.indicators:
            return 0.0
        score = 0.5
        if profile.protocol:
            score += 0.25
        wanted = tuple(profile.signal_indicators)
        if wanted:
            matched = sum(1 for item in wanted if item in self.indicators)
            score += 0.25 * matched / len(wanted)
        return round(min(1.0, score), 2)


def _patches(package: Any) -> list[Path]:
    commits_dir = Path(package.root) / "analysis" / "commits"
    if not commits_dir.is_dir():
        return []
    return sorted(commits_dir.glob("*.patch"))


def extract_patch_signals(package: Any) -> PatchSignals:
    """Extract changed paths and mechanism indicators from captured patches."""
    patches = _patches(package)
    if not patches:
        return PatchSignals(
            notes=(
                "no captured fixing commits; profile selected from advisory "
                "facts only",
            )
        )

    changed: set[str] = set()
    indicators: set[str] = set()
    analyzed: list[str] = []
    for path in patches:
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        analyzed.append(str(path.relative_to(Path(package.root))))
        changed.update(changed_files(text))
        for name, pattern in _INDICATOR_PATTERNS.items():
            if pattern.search(text):
                indicators.add(name)

    notes: list[str] = []
    if not changed:
        notes.append("captured patches contained no parseable file diffs")
    return PatchSignals(
        changed_paths=tuple(sorted(changed)),
        indicators=tuple(
            sorted(indicators, key=lambda item: (
                PROTOCOL_INDICATORS.index(item)
                if item in PROTOCOL_INDICATORS
                else len(PROTOCOL_INDICATORS),
                item,
            ))
        ),
        patches=tuple(analyzed),
        notes=tuple(notes),
    )
