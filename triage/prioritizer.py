#!/usr/bin/env python3
"""
prioritizer.py

Scores every advisory on four independent axes and produces a research
priority order. CVSS is retained as its own column but deliberately does
NOT feed the priority score -- it tells you regulatory/compliance severity,
not how worthwhile the finding is to chase first.

Axes (0-10 each, analyst-set from the advisory text + source diff, not
derived mechanically from CVSS):

  I  Impact        -- what breaks, and how completely, if it fires.
  E  Exploitability-- protocol complexity, auth, client tooling needed.
  R  Reachability  -- is the vulnerable code on the default, unauthenticated
                       request path, or gated behind opt-in config/features.
  D  Detectability -- how cleanly a lab experiment can observe & measure it
                       (clean signal is also what makes a good detection rule).

  P = 0.40*I + 0.35*E + 0.15*R + 0.10*D

Run:
    python3 triage/prioritizer.py                # table to stdout
    python3 triage/prioritizer.py --csv out.csv   # also write CSV
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

# Analyst-assigned scores per CVE. These encode judgment calls documented in
# reports/technical-report.md -- update both together if you revise one.
# impact, exploitability, reachability, detectability, notes
SCORES: dict[str, dict] = {
    # --- HTTP/1 resource exhaustion ---
    "CVE-2026-111101": dict(I=8, E=9, R=10, D=9,
        notes="Plain HTTP/1.1, no TLS/ALPN juggling, no auth, no special client lib. Single connection, trickle 1-byte chunks. Easiest PoC in the set."),
    "CVE-2026-39803": dict(I=8, E=8, R=10, D=8,
        notes="Body-size cap silently not enforced during streaming reads; needs a body-consuming Plug but no other prerequisite."),
    "CVE-2026-39806": dict(I=7, E=6, R=8, D=6,
        notes="Needs a trailer-bearing chunked request to hit the decoder loop; slightly more wire-format precision than the two above."),
    "CVE-2026-113436": dict(I=6, E=7, R=9, D=7,
        notes="Oversized Content-Length / Host port digit strings; trivial to construct, impact is parse-time CPU not memory."),

    # --- HTTP/2 resource exhaustion ---
    "CVE-2026-116078": dict(I=8, E=7, R=9, D=9,
        notes="Needs an HTTP/2 client (h2) but otherwise a single stream of 1-byte DATA frames; very clean memory signal, good PoC candidate."),
    "CVE-2026-108525": dict(I=8, E=6, R=8, D=8,
        notes="Requires understanding Bandit's flow-control accounting (send WINDOW_UPDATE generously, never let the stream process drain) -- more h2 state-machine work than 116078."),
    "CVE-2026-105659": dict(I=7, E=6, R=7, D=7,
        notes="Timer-reset trickle attack; needs sustained low-rate WINDOW_UPDATEs, good for a long-duration lab run rather than a quick PoC."),
    "CVE-2026-115269": dict(I=7, E=6, R=7, D=7,
        notes="Same family as 105659 -- SETTINGS/WINDOW_UPDATE resets the body-read timeout instead of the blocked-send deadline."),
    "CVE-2026-108529": dict(I=6, E=5, R=6, D=6,
        notes="Quadratic cost needs many blocked streams plus repeated SETTINGS/stream-0 WINDOW_UPDATE; more streams to orchestrate."),
    "CVE-2026-110499": dict(I=6, E=5, R=6, D=6,
        notes="HPACK dynamic-table size update per response; needs many requests over one connection to accumulate state."),
    "CVE-2026-109584": dict(I=6, E=5, R=6, D=6,
        notes="Cookie-crumb join amplification depends on HPACK header-block construction, more encoding nuance than raw frame spam."),
    "CVE-2026-111103": dict(I=6, E=4, R=5, D=5,
        notes="Requires driving streams into StreamError recovery repeatedly to roll back connection-level counters; more protocol-edge-case orchestration."),
    "CVE-2026-74836": dict(I=6, E=5, R=6, D=6,
        notes="Connection-window starvation pins Plug processes; needs the connection window, not just stream windows, held at zero."),
    "CVE-2026-42788": dict(I=4, E=5, R=6, D=5,
        notes="Frame-size check ordering bug; impact capped at VA:L per CVSS, smaller blast radius than the rest of the HTTP/2 family."),

    # --- WebSocket exhaustion ---
    "CVE-2026-114213": dict(I=7, E=6, R=6, D=7,
        notes="1-byte continuation frames bypassing max_fragmented_message_size; needs a WS handshake first but payload construction is simple."),
    "CVE-2026-42786": dict(I=7, E=6, R=6, D=6,
        notes="Unbounded fragment reassembly pre-1.11; same shape as 114213 on an older code path."),
    "CVE-2026-39804": dict(I=7, E=5, R=5, D=6,
        notes="permessage-deflate zip-bomb; requires negotiating the extension and crafting a compressible payload -- moderately more work."),
    "CVE-2026-65623": dict(I=6, E=5, R=6, D=6,
        notes="Quadratic CPU on fragment reassembly; CPU-bound rather than memory-bound, needs wall-clock timing to observe cleanly."),

    # --- Request smuggling ---
    "CVE-2026-114216": dict(I=5, E=4, R=4, D=5,
        notes="Needs a front-end proxy with different line-ending tolerance in front of Bandit to matter; pure-Bandit repro shows parser behavior only, not smuggling impact."),
    "CVE-2026-39805": dict(I=5, E=4, R=4, D=5,
        notes="CL.CL duplicate Content-Length; same caveat -- exploitability is a property of the proxy/Bandit pair, not Bandit alone."),

    # --- Request metadata / header validation ---
    "CVE-2026-105660": dict(I=4, E=6, R=7, D=5,
        notes="Trivial to send a crafted request-target; real impact depends entirely on whether the app trusts conn.host/conn.port for authz or routing decisions."),
    "CVE-2026-75484": dict(I=4, E=6, R=7, D=5,
        notes="CRLF/NUL in HTTP/2 header values reaching the app; impact is header/log/response-splitting downstream of Bandit, not in Bandit itself."),
    "CVE-2026-39807": dict(I=3, E=5, R=5, D=4,
        notes="Client-supplied scheme trusted without transport check; impact is app-level (e.g. incorrect redirect/secure-cookie logic) not Bandit crashing."),

    # --- WebSocket state correctness ---
    "CVE-2026-110314": dict(I=3, E=5, R=5, D=5,
        notes="Post-close frame delivery; mostly an application-correctness/isolation issue, modest direct security impact."),
}


def score_priority(s: dict) -> float:
    return round(0.40 * s["I"] + 0.35 * s["E"] + 0.15 * s["R"] + 0.10 * s["D"], 2)


def exploitability_tier(e: int) -> str:
    if e >= 8:
        return "E4 - low complexity, unauthenticated, remote"
    if e >= 6:
        return "E3 - straightforward protocol interaction"
    if e >= 4:
        return "E2 - needs specific protocol feature/topology"
    return "E1 - unusual config / multiple prerequisites"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", type=str, default=None, help="also write matrix to this CSV path")
    args = ap.parse_args()

    advisories = {a["cve"]: a for a in json.loads((DATA_DIR / "advisories.json").read_text())["advisories"]}

    rows = []
    for cve, s in SCORES.items():
        adv = advisories[cve]
        p = score_priority(s)
        rows.append({
            "cve": cve,
            "title": adv["title"],
            "cvss": adv["cvss_score"],
            "track": adv["track"],
            "affected": adv["affected"],
            "fixed_in": adv["fixed_in"],
            "impact_I": s["I"],
            "exploit_E": s["E"],
            "reach_R": s["R"],
            "detect_D": s["D"],
            "priority_P": p,
            "exploit_tier": exploitability_tier(s["E"]),
            "notes": s["notes"],
        })

    rows.sort(key=lambda r: r["priority_P"], reverse=True)

    print(f"{'CVE':<18}{'CVSS':<6}{'P':<6}{'Tier':<42}{'Track'}")
    print("-" * 100)
    for r in rows:
        print(f"{r['cve']:<18}{r['cvss']:<6}{r['priority_P']:<6}{r['exploit_tier']:<42}{r['track']}")

    out = DATA_DIR / "vulnerability-matrix.json"
    out.write_text(json.dumps(rows, indent=2))
    print(f"\nWrote {out}")

    if args.csv:
        with open(args.csv, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)
        print(f"Wrote {args.csv}")


if __name__ == "__main__":
    main()
