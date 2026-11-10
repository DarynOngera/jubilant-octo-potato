# Bandit Vulnerability Research -- Technical Report

Generated 2026-11-04 from `data/advisories.json` (24 advisories) and `data/vulnerability-matrix.json`.

Source: [Hex advisory registry](https://hex.pm/packages/bandit/advisories), cross-referenced against OSV (`EEF-CVE-*`) and GHSA records linked from each entry.

**Scope note:** CVSS scores are reproduced verbatim from the advisory records. The `priority_P` column is this project's own research-priority score (`0.40*Impact + 0.35*Exploitability + 0.15*Reachability + 0.10*Detectability`, see `data/prioritization.json` and `config/research.yaml`) and is independent of CVSS by design -- see Section 3.

## 1. Exploitability matrix

| Rank | CVE | CVSS | Priority P | Tier | Track | Fixed in |
|---|---|---|---|---|---|---|
| 1 | [CVE-2026-111101](#cve-2026-111101) | 8.7 | 8.75 | E4 | HTTP/1 resource exhaustion | 1.14.0 |
| 2 | [CVE-2026-39803](#cve-2026-39803) | 8.7 | 8.3 | E4 | HTTP/1 resource exhaustion | 1.11.1 |
| 3 | [CVE-2026-116078](#cve-2026-116078) | 8.7 | 7.9 | E3 | HTTP/2 resource exhaustion | 1.14.1 |
| 4 | [CVE-2026-108525](#cve-2026-108525) | 8.7 | 7.3 | E3 | HTTP/2 resource exhaustion | 1.14.0 |
| 5 | [CVE-2026-113436](#cve-2026-113436) | 8.7 | 6.9 | E3 | HTTP/1 resource exhaustion | 1.14.0 |
| 6 | [CVE-2026-39806](#cve-2026-39806) | 8.7 | 6.7 | E3 | HTTP/1 resource exhaustion | 1.11.1 |
| 7 | [CVE-2026-105659](#cve-2026-105659) | 8.7 | 6.65 | E3 | HTTP/2 resource exhaustion | 1.13.0 |
| 8 | [CVE-2026-115269](#cve-2026-115269) | 8.7 | 6.65 | E3 | HTTP/2 resource exhaustion | 1.14.0 |
| 9 | [CVE-2026-114213](#cve-2026-114213) | 8.7 | 6.5 | E3 | WebSocket resource exhaustion | 1.14.0 |
| 10 | [CVE-2026-42786](#cve-2026-42786) | 8.7 | 6.4 | E3 | WebSocket resource exhaustion | 1.11.0 |
| 11 | [CVE-2026-39804](#cve-2026-39804) | 8.2 | 5.9 | E2 | WebSocket resource exhaustion | 1.11.0 |
| 12 | [CVE-2026-108529](#cve-2026-108529) | 8.7 | 5.65 | E2 | HTTP/2 resource exhaustion | 1.14.0 |
| 13 | [CVE-2026-109584](#cve-2026-109584) | 8.7 | 5.65 | E2 | HTTP/2 resource exhaustion | 1.14.0 |
| 14 | [CVE-2026-110499](#cve-2026-110499) | 8.7 | 5.65 | E2 | HTTP/2 resource exhaustion | 1.14.0 |
| 15 | [CVE-2026-65623](#cve-2026-65623) | 8.7 | 5.65 | E2 | WebSocket resource exhaustion | 1.12.1 |
| 16 | [CVE-2026-74836](#cve-2026-74836) | 8.7 | 5.65 | E2 | HTTP/2 resource exhaustion | 1.12.5 |
| 17 | [CVE-2026-105660](#cve-2026-105660) | 6.9 | 5.25 | E3 | Request metadata validation | 1.13.0 |
| 18 | [CVE-2026-75484](#cve-2026-75484) | 6.9 | 5.25 | E3 | Request metadata validation | 1.12.5 |
| 19 | [CVE-2026-111103](#cve-2026-111103) | 8.2 | 5.05 | E2 | HTTP/2 resource exhaustion | 1.14.0 |
| 20 | [CVE-2026-42788](#cve-2026-42788) | 6.9 | 4.75 | E2 | HTTP/2 resource exhaustion | 1.11.0 |
| 21 | [CVE-2026-114216](#cve-2026-114216) | 6.3 | 4.5 | E2 | HTTP request smuggling | 1.14.0 |
| 22 | [CVE-2026-39805](#cve-2026-39805) | 6.3 | 4.5 | E2 | HTTP request smuggling | 1.11.0 |
| 23 | [CVE-2026-110314](#cve-2026-110314) | 6.3 | 4.2 | E2 | WebSocket state correctness | 1.14.0 |
| 24 | [CVE-2026-39807](#cve-2026-39807) | 6.3 | 4.1 | E2 | Request metadata validation | 1.11.0 |

## 2. Per-version CVE exposure

`triage/version_resolver.py::resolve_all()` maps every known Bandit release to the full list of advisories whose affected ranges contain it. The table below is restricted to the lab checkpoint versions; the second table groups consecutive releases with an identical exposure set.

| Checkpoint version | Roles | Vulnerable CVEs | Count |
|---|---|---|---|
| `1.10.4` | last-vulnerable | CVE-2026-105659, CVE-2026-105660, CVE-2026-108525, CVE-2026-108529, CVE-2026-109584, CVE-2026-110314, CVE-2026-110499, CVE-2026-111101, CVE-2026-111103, CVE-2026-113436, CVE-2026-115269, CVE-2026-116078, CVE-2026-39803, CVE-2026-39804, CVE-2026-39805, CVE-2026-39806, CVE-2026-39807, CVE-2026-42786, CVE-2026-42788, CVE-2026-74836, CVE-2026-75484 | 21 |
| `1.11.0` | first-patched, last-vulnerable | CVE-2026-105659, CVE-2026-105660, CVE-2026-108525, CVE-2026-108529, CVE-2026-109584, CVE-2026-110314, CVE-2026-110499, CVE-2026-111101, CVE-2026-111103, CVE-2026-113436, CVE-2026-114213, CVE-2026-115269, CVE-2026-116078, CVE-2026-39803, CVE-2026-39806, CVE-2026-65623, CVE-2026-74836, CVE-2026-75484 | 18 |
| `1.11.1` | first-patched | CVE-2026-105659, CVE-2026-105660, CVE-2026-108525, CVE-2026-108529, CVE-2026-109584, CVE-2026-110314, CVE-2026-110499, CVE-2026-111101, CVE-2026-111103, CVE-2026-113436, CVE-2026-114213, CVE-2026-115269, CVE-2026-116078, CVE-2026-65623, CVE-2026-74836, CVE-2026-75484 | 16 |
| `1.12.0` | last-vulnerable | CVE-2026-105659, CVE-2026-105660, CVE-2026-108525, CVE-2026-108529, CVE-2026-109584, CVE-2026-110314, CVE-2026-110499, CVE-2026-111101, CVE-2026-111103, CVE-2026-113436, CVE-2026-114213, CVE-2026-115269, CVE-2026-116078, CVE-2026-65623, CVE-2026-74836, CVE-2026-75484 | 16 |
| `1.12.1` | first-patched | CVE-2026-105659, CVE-2026-105660, CVE-2026-108525, CVE-2026-108529, CVE-2026-109584, CVE-2026-110314, CVE-2026-110499, CVE-2026-111101, CVE-2026-111103, CVE-2026-113436, CVE-2026-114213, CVE-2026-115269, CVE-2026-116078, CVE-2026-74836, CVE-2026-75484 | 15 |
| `1.12.4` | last-vulnerable | CVE-2026-105659, CVE-2026-105660, CVE-2026-108525, CVE-2026-108529, CVE-2026-109584, CVE-2026-110314, CVE-2026-110499, CVE-2026-111101, CVE-2026-111103, CVE-2026-113436, CVE-2026-114213, CVE-2026-114216, CVE-2026-115269, CVE-2026-116078, CVE-2026-74836, CVE-2026-75484 | 16 |
| `1.12.5` | first-patched, last-vulnerable | CVE-2026-105659, CVE-2026-105660, CVE-2026-108525, CVE-2026-108529, CVE-2026-109584, CVE-2026-110314, CVE-2026-110499, CVE-2026-111101, CVE-2026-111103, CVE-2026-113436, CVE-2026-114213, CVE-2026-114216, CVE-2026-115269, CVE-2026-116078 | 14 |
| `1.13.0` | first-patched | CVE-2026-108525, CVE-2026-108529, CVE-2026-109584, CVE-2026-110314, CVE-2026-110499, CVE-2026-111101, CVE-2026-111103, CVE-2026-113436, CVE-2026-114213, CVE-2026-114216, CVE-2026-115269, CVE-2026-116078 | 12 |
| `1.13.1` | last-vulnerable | CVE-2026-108525, CVE-2026-108529, CVE-2026-109584, CVE-2026-110314, CVE-2026-110499, CVE-2026-111101, CVE-2026-111103, CVE-2026-113436, CVE-2026-114213, CVE-2026-114216, CVE-2026-115269, CVE-2026-116078 | 12 |
| `1.14.0` | first-patched, last-vulnerable | CVE-2026-116078 | 1 |
| `1.14.1` | first-patched | none | 0 |

**Contiguous exposure bands** (versions with the same vulnerable-CVE set grouped together):

| Versions | Count | CVEs |
|---|---|---|
| `0.1.0 .. 0.2.3` | 2 | CVE-2026-111101, CVE-2026-39805 |
| `0.3.2` | 4 | CVE-2026-108525, CVE-2026-111101, CVE-2026-116078, CVE-2026-39805 |
| `0.3.3` | 5 | CVE-2026-108525, CVE-2026-109584, CVE-2026-111101, CVE-2026-116078, CVE-2026-39805 |
| `0.3.4` | 7 | CVE-2026-108525, CVE-2026-108529, CVE-2026-109584, CVE-2026-111101, CVE-2026-116078, CVE-2026-39805, CVE-2026-74836 |
| `0.3.5` | 8 | CVE-2026-108525, CVE-2026-108529, CVE-2026-109584, CVE-2026-111101, CVE-2026-116078, CVE-2026-39805, CVE-2026-42788, CVE-2026-74836 |
| `0.3.6 .. 0.4.10` | 9 | CVE-2026-108525, CVE-2026-108529, CVE-2026-109584, CVE-2026-110499, CVE-2026-111101, CVE-2026-116078, CVE-2026-39805, CVE-2026-42788, CVE-2026-74836 |
| `0.5.0` | 10 | CVE-2026-108525, CVE-2026-108529, CVE-2026-109584, CVE-2026-110499, CVE-2026-111101, CVE-2026-116078, CVE-2026-39805, CVE-2026-42786, CVE-2026-42788, CVE-2026-74836 |
| `0.5.1 .. 0.5.7` | 11 | CVE-2026-108525, CVE-2026-108529, CVE-2026-109584, CVE-2026-110314, CVE-2026-110499, CVE-2026-111101, CVE-2026-116078, CVE-2026-39805, CVE-2026-42786, CVE-2026-42788, CVE-2026-74836 |
| `0.5.8 .. 0.5.11` | 12 | CVE-2026-108525, CVE-2026-108529, CVE-2026-109584, CVE-2026-110314, CVE-2026-110499, CVE-2026-111101, CVE-2026-116078, CVE-2026-39804, CVE-2026-39805, CVE-2026-42786, CVE-2026-42788, CVE-2026-74836 |
| `0.6.0 .. 1.0.0-pre.6` | 13 | CVE-2026-105660, CVE-2026-108525, CVE-2026-108529, CVE-2026-109584, CVE-2026-110314, CVE-2026-110499, CVE-2026-111101, CVE-2026-116078, CVE-2026-39804, CVE-2026-39805, CVE-2026-42786, CVE-2026-42788, CVE-2026-74836 |
| `1.0.0-pre.7 .. 1.0.0-pre.18` | 14 | CVE-2026-105660, CVE-2026-108525, CVE-2026-108529, CVE-2026-109584, CVE-2026-110314, CVE-2026-110499, CVE-2026-111101, CVE-2026-113436, CVE-2026-116078, CVE-2026-39804, CVE-2026-39805, CVE-2026-42786, CVE-2026-42788, CVE-2026-74836 |
| `1.0.0 .. 1.3.0` | 15 | CVE-2026-105660, CVE-2026-108525, CVE-2026-108529, CVE-2026-109584, CVE-2026-110314, CVE-2026-110499, CVE-2026-111101, CVE-2026-113436, CVE-2026-116078, CVE-2026-39804, CVE-2026-39805, CVE-2026-39807, CVE-2026-42786, CVE-2026-42788, CVE-2026-74836 |
| `1.4.0 .. 1.5.7` | 19 | CVE-2026-105659, CVE-2026-105660, CVE-2026-108525, CVE-2026-108529, CVE-2026-109584, CVE-2026-110314, CVE-2026-110499, CVE-2026-111101, CVE-2026-113436, CVE-2026-115269, CVE-2026-116078, CVE-2026-39803, CVE-2026-39804, CVE-2026-39805, CVE-2026-39807, CVE-2026-42786, CVE-2026-42788, CVE-2026-74836, CVE-2026-75484 |
| `1.6.0 .. 1.8.0` | 20 | CVE-2026-105659, CVE-2026-105660, CVE-2026-108525, CVE-2026-108529, CVE-2026-109584, CVE-2026-110314, CVE-2026-110499, CVE-2026-111101, CVE-2026-113436, CVE-2026-115269, CVE-2026-116078, CVE-2026-39803, CVE-2026-39804, CVE-2026-39805, CVE-2026-39806, CVE-2026-39807, CVE-2026-42786, CVE-2026-42788, CVE-2026-74836, CVE-2026-75484 |
| `1.9.0 .. 1.10.4` | 21 | CVE-2026-105659, CVE-2026-105660, CVE-2026-108525, CVE-2026-108529, CVE-2026-109584, CVE-2026-110314, CVE-2026-110499, CVE-2026-111101, CVE-2026-111103, CVE-2026-113436, CVE-2026-115269, CVE-2026-116078, CVE-2026-39803, CVE-2026-39804, CVE-2026-39805, CVE-2026-39806, CVE-2026-39807, CVE-2026-42786, CVE-2026-42788, CVE-2026-74836, CVE-2026-75484 |
| `1.11.0` | 18 | CVE-2026-105659, CVE-2026-105660, CVE-2026-108525, CVE-2026-108529, CVE-2026-109584, CVE-2026-110314, CVE-2026-110499, CVE-2026-111101, CVE-2026-111103, CVE-2026-113436, CVE-2026-114213, CVE-2026-115269, CVE-2026-116078, CVE-2026-39803, CVE-2026-39806, CVE-2026-65623, CVE-2026-74836, CVE-2026-75484 |
| `1.11.1 .. 1.12.0` | 16 | CVE-2026-105659, CVE-2026-105660, CVE-2026-108525, CVE-2026-108529, CVE-2026-109584, CVE-2026-110314, CVE-2026-110499, CVE-2026-111101, CVE-2026-111103, CVE-2026-113436, CVE-2026-114213, CVE-2026-115269, CVE-2026-116078, CVE-2026-65623, CVE-2026-74836, CVE-2026-75484 |
| `1.12.1 .. 1.12.3` | 15 | CVE-2026-105659, CVE-2026-105660, CVE-2026-108525, CVE-2026-108529, CVE-2026-109584, CVE-2026-110314, CVE-2026-110499, CVE-2026-111101, CVE-2026-111103, CVE-2026-113436, CVE-2026-114213, CVE-2026-115269, CVE-2026-116078, CVE-2026-74836, CVE-2026-75484 |
| `1.12.4` | 16 | CVE-2026-105659, CVE-2026-105660, CVE-2026-108525, CVE-2026-108529, CVE-2026-109584, CVE-2026-110314, CVE-2026-110499, CVE-2026-111101, CVE-2026-111103, CVE-2026-113436, CVE-2026-114213, CVE-2026-114216, CVE-2026-115269, CVE-2026-116078, CVE-2026-74836, CVE-2026-75484 |
| `1.12.5` | 14 | CVE-2026-105659, CVE-2026-105660, CVE-2026-108525, CVE-2026-108529, CVE-2026-109584, CVE-2026-110314, CVE-2026-110499, CVE-2026-111101, CVE-2026-111103, CVE-2026-113436, CVE-2026-114213, CVE-2026-114216, CVE-2026-115269, CVE-2026-116078 |
| `1.13.0 .. 1.13.1` | 12 | CVE-2026-108525, CVE-2026-108529, CVE-2026-109584, CVE-2026-110314, CVE-2026-110499, CVE-2026-111101, CVE-2026-111103, CVE-2026-113436, CVE-2026-114213, CVE-2026-114216, CVE-2026-115269, CVE-2026-116078 |
| `1.14.0` | 1 | CVE-2026-116078 |
| `1.14.1` | 0 | none |

This is why a single "vulnerable" lab image is not enough: 1.13.1 is still exposed to several later advisories but is already patched for the older ones. Each advisory must be tested against a version that actually falls inside its affected range.

## 3. Methodology note: why priority != CVSS

CVSS answers 'how bad if it fires, under worst-case assumptions.' It does not answer 'how much researcher/attacker effort does firing it take.' Several advisories here carry the same 8.7 CVSS score (the HTTP/2 resource-exhaustion family largely does) but differ sharply in how many wire-format details, timing constraints, or protocol-state-machine steps stand between a client and triggering them. The priority score keeps those axes separate and explicit (`data/prioritization.json` documents the per-CVE scoring rationale in the `notes` field; weights/tiers live in `config/research.yaml`) rather than letting CVSS stand in for both.

## 4. Per-advisory detail

### CVE-2026-111101

**HTTP/1.1 chunked request bodies made of 1-byte chunks amplify memory use in Bandit**

- GHSA: GHSA-jwh3-j29h-qfmw &nbsp;|&nbsp; OSV: EEF-CVE-2026-111101
- CVSS 4.0: **8.7** &nbsp;(`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N`)
- Affected: `>= 0.1.0 and < 1.14.0` &nbsp;|&nbsp; Fixed in: `1.14.0`
- Published: 2026-10-26
- Track: HTTP/1 resource exhaustion
- Research priority: **8.75** (I=8 E=9 R=10 D=9) -- E4 - low complexity, unauthenticated, remote
- Analyst note: Plain HTTP/1.1, no TLS/ALPN juggling, no auth, no special client lib. Single connection, trickle 1-byte chunks. Easiest PoC in the set.
- Fixing commit(s): [`220b9dfd27`](https://github.com/mtrudel/bandit/commit/220b9dfd27f9a21305be2afc75cbe585ddc24e7a), [`7201270c34`](https://github.com/mtrudel/bandit/commit/7201270c34b90f6c9e15c0386c2bb802c0c72ab4)
- PoC status: **implemented** -- `vulnerabilities/CVE-2026-111101/poc/exploit.py`

### CVE-2026-39803

**HTTP/1 chunked body reader ignores length cap in Bandit**

- GHSA: GHSA-9q9q-324x-93r2 &nbsp;|&nbsp; OSV: EEF-CVE-2026-39803
- CVSS 4.0: **8.7** &nbsp;(`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N`)
- Affected: `>= 1.4.0 and < 1.11.1` &nbsp;|&nbsp; Fixed in: `1.11.1`
- Published: 2026-05-13
- Track: HTTP/1 resource exhaustion
- Research priority: **8.3** (I=8 E=8 R=10 D=8) -- E4 - low complexity, unauthenticated, remote
- Analyst note: Body-size cap silently not enforced during streaming reads; needs a body-consuming Plug but no other prerequisite.
- Fixing commit(s): [`ae3520dfdb`](https://github.com/mtrudel/bandit/commit/ae3520dfdbfab115c638f8c7f6f6b805db34e1ab)
- PoC status: **implemented** -- `vulnerabilities/CVE-2026-39803/poc/exploit.py`

### CVE-2026-116078

**HTTP/2 request bodies made of 1-byte DATA frames amplify memory use in Bandit**

- GHSA: GHSA-pxjf-g536-7r93 &nbsp;|&nbsp; OSV: EEF-CVE-2026-116078
- CVSS 4.0: **8.7** &nbsp;(`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N`)
- Affected: `>= 0.3.1 and < 1.14.1` &nbsp;|&nbsp; Fixed in: `1.14.1`
- Published: 2026-10-28
- Track: HTTP/2 resource exhaustion
- Research priority: **7.9** (I=8 E=7 R=9 D=9) -- E3 - straightforward protocol interaction
- Analyst note: Needs an HTTP/2 client (h2) but otherwise a single stream of 1-byte DATA frames; very clean memory signal, good PoC candidate.
- Fixing commit(s): [`327bb02ff8`](https://github.com/mtrudel/bandit/commit/327bb02ff84171237e1aeff787930debd16155ee), [`c8dc1e9705`](https://github.com/mtrudel/bandit/commit/c8dc1e97050cf359f61ed6cdd110f3cdaf1d6f5f)
- PoC status: **implemented** -- `vulnerabilities/CVE-2026-116078/poc/exploit.py`

### CVE-2026-108525

**HTTP/2 inbound flow control is not enforced, letting a client queue unbounded DATA in stream processes in Bandit**

- GHSA: GHSA-c3g7-2pg5-qvwh &nbsp;|&nbsp; OSV: EEF-CVE-2026-108525
- CVSS 4.0: **8.7** &nbsp;(`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N`)
- Affected: `>= 0.3.1 and < 1.14.0` &nbsp;|&nbsp; Fixed in: `1.14.0`
- Published: 2026-10-26
- Track: HTTP/2 resource exhaustion
- Research priority: **7.3** (I=8 E=6 R=8 D=8) -- E3 - straightforward protocol interaction
- Analyst note: Requires understanding Bandit's flow-control accounting (send WINDOW_UPDATE generously, never let the stream process drain) -- more h2 state-machine work than 116078.
- Fixing commit(s): [`220b9dfd27`](https://github.com/mtrudel/bandit/commit/220b9dfd27f9a21305be2afc75cbe585ddc24e7a), [`c8dc1e9705`](https://github.com/mtrudel/bandit/commit/c8dc1e97050cf359f61ed6cdd110f3cdaf1d6f5f)
- PoC status: not yet implemented (see Section 5 for the pattern to extend)

### CVE-2026-113436

**Quadratic bignum parsing of Content-Length and Host port values in Bandit**

- GHSA: GHSA-29cr-8477-rg6r &nbsp;|&nbsp; OSV: EEF-CVE-2026-113436
- CVSS 4.0: **8.7** &nbsp;(`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N`)
- Affected: `>= 1.0.0-pre.7 and < 1.14.0` &nbsp;|&nbsp; Fixed in: `1.14.0`
- Published: 2026-10-26
- Track: HTTP/1 resource exhaustion
- Research priority: **6.9** (I=6 E=7 R=9 D=7) -- E3 - straightforward protocol interaction
- Analyst note: Oversized Content-Length / Host port digit strings; trivial to construct, impact is parse-time CPU not memory.
- Fixing commit(s): [`220b9dfd27`](https://github.com/mtrudel/bandit/commit/220b9dfd27f9a21305be2afc75cbe585ddc24e7a), [`e0c8c0c30a`](https://github.com/mtrudel/bandit/commit/e0c8c0c30af9b0f57d8aafac37ddd9294363a8be)
- PoC status: not yet implemented (see Section 5 for the pattern to extend)

### CVE-2026-39806

**HTTP/1 chunked decoder infinite loop on requests with trailer fields in Bandit**

- GHSA: GHSA-rf5q-vwxw-gmrf &nbsp;|&nbsp; OSV: EEF-CVE-2026-39806
- CVSS 4.0: **8.7** &nbsp;(`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N`)
- Affected: `>= 1.6.1 and < 1.11.1 or >= 1.6.0 and < 1.11.1` &nbsp;|&nbsp; Fixed in: `1.11.1`
- Published: 2026-05-13
- Track: HTTP/1 resource exhaustion
- Research priority: **6.7** (I=7 E=6 R=8 D=6) -- E3 - straightforward protocol interaction
- Analyst note: Needs a trailer-bearing chunked request to hit the decoder loop; slightly more wire-format precision than the two above.
- Fixing commit(s): [`ae3520dfdb`](https://github.com/mtrudel/bandit/commit/ae3520dfdbfab115c638f8c7f6f6b805db34e1ab)
- PoC status: not yet implemented (see Section 5 for the pattern to extend)

### CVE-2026-105659

**HTTP/2 blocked-send deadlines reset on every WINDOW_UPDATE, letting a trickle pin stream processes indefinitely in Bandit**

- GHSA: GHSA-69m6-wcv4-rwcf &nbsp;|&nbsp; OSV: EEF-CVE-2026-105659
- CVSS 4.0: **8.7** &nbsp;(`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N`)
- Affected: `>= 1.4.0 and < 1.13.0` &nbsp;|&nbsp; Fixed in: `1.13.0`
- Published: 2026-10-14
- Track: HTTP/2 resource exhaustion
- Research priority: **6.65** (I=7 E=6 R=7 D=7) -- E3 - straightforward protocol interaction
- Analyst note: Timer-reset trickle attack; needs sustained low-rate WINDOW_UPDATEs, good for a long-duration lab run rather than a quick PoC.
- Fixing commit(s): [`d88b21953c`](https://github.com/mtrudel/bandit/commit/d88b21953c65061f21136ea76a89a4f95a2ac7a1), [`fff06efe3b`](https://github.com/mtrudel/bandit/commit/fff06efe3be962b484bd4d3eb339372fda5a231f)
- PoC status: **implemented** -- `vulnerabilities/CVE-2026-105659/poc/exploit.py`

### CVE-2026-115269

**HTTP/2 WINDOW_UPDATE and SETTINGS frames reset the request body read timeout in Bandit**

- GHSA: GHSA-p2qv-vx88-385x &nbsp;|&nbsp; OSV: EEF-CVE-2026-115269
- CVSS 4.0: **8.7** &nbsp;(`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N`)
- Affected: `>= 1.4.0 and < 1.14.0` &nbsp;|&nbsp; Fixed in: `1.14.0`
- Published: 2026-10-26
- Track: HTTP/2 resource exhaustion
- Research priority: **6.65** (I=7 E=6 R=7 D=7) -- E3 - straightforward protocol interaction
- Analyst note: Same family as 105659 -- SETTINGS/WINDOW_UPDATE resets the body-read timeout instead of the blocked-send deadline.
- Fixing commit(s): [`220b9dfd27`](https://github.com/mtrudel/bandit/commit/220b9dfd27f9a21305be2afc75cbe585ddc24e7a), [`fff06efe3b`](https://github.com/mtrudel/bandit/commit/fff06efe3be962b484bd4d3eb339372fda5a231f)
- PoC status: not yet implemented (see Section 5 for the pattern to extend)

### CVE-2026-114213

**WebSocket 1-byte continuation frames bypass max_fragmented_message_size in Bandit**

- GHSA: GHSA-cpx7-qf6w-jc63 &nbsp;|&nbsp; OSV: EEF-CVE-2026-114213
- CVSS 4.0: **8.7** &nbsp;(`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N`)
- Affected: `>= 1.11.0 and < 1.14.0` &nbsp;|&nbsp; Fixed in: `1.14.0`
- Published: 2026-10-26
- Track: WebSocket resource exhaustion
- Research priority: **6.5** (I=7 E=6 R=6 D=7) -- E3 - straightforward protocol interaction
- Analyst note: 1-byte continuation frames bypassing max_fragmented_message_size; needs a WS handshake first but payload construction is simple.
- Fixing commit(s): [`21612c7c7b`](https://github.com/mtrudel/bandit/commit/21612c7c7b1ce43eccd36d3af3a2299d23513667), [`220b9dfd27`](https://github.com/mtrudel/bandit/commit/220b9dfd27f9a21305be2afc75cbe585ddc24e7a)
- PoC status: not yet implemented (see Section 5 for the pattern to extend)

### CVE-2026-42786

**WebSocket fragmented message reassembly unbounded in Bandit**

- GHSA: GHSA-pf94-94m9-536p &nbsp;|&nbsp; OSV: EEF-CVE-2026-42786
- CVSS 4.0: **8.7** &nbsp;(`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N`)
- Affected: `>= 0.5.0 and < 1.11.0` &nbsp;|&nbsp; Fixed in: `1.11.0`
- Published: 2026-05-01
- Track: WebSocket resource exhaustion
- Research priority: **6.4** (I=7 E=6 R=6 D=6) -- E3 - straightforward protocol interaction
- Analyst note: Unbounded fragment reassembly pre-1.11; same shape as 114213 on an older code path.
- Fixing commit(s): [`21612c7c7b`](https://github.com/mtrudel/bandit/commit/21612c7c7b1ce43eccd36d3af3a2299d23513667)
- PoC status: not yet implemented (see Section 5 for the pattern to extend)

### CVE-2026-39804

**WebSocket permessage-deflate inflate has no output-size cap in Bandit**

- GHSA: GHSA-frh3-6pv6-rc8j &nbsp;|&nbsp; OSV: EEF-CVE-2026-39804
- CVSS 4.0: **8.2** &nbsp;(`CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N`)
- Affected: `>= 0.5.9 and < 1.11.0 or >= 0.5.8 and < 1.11.0` &nbsp;|&nbsp; Fixed in: `1.11.0`
- Published: 2026-05-01
- Track: WebSocket resource exhaustion
- Research priority: **5.9** (I=7 E=5 R=5 D=6) -- E2 - needs specific protocol feature/topology
- Analyst note: permessage-deflate zip-bomb; requires negotiating the extension and crafting a compressible payload -- moderately more work.
- Fixing commit(s): [`8156921a51`](https://github.com/mtrudel/bandit/commit/8156921a51e684a951221da7bc30a70a022f722e)
- PoC status: not yet implemented (see Section 5 for the pattern to extend)

### CVE-2026-108529

**SETTINGS and stream-0 WINDOW_UPDATE frames trigger quadratic work over blocked streams in Bandit**

- GHSA: GHSA-j363-h72p-296m &nbsp;|&nbsp; OSV: EEF-CVE-2026-108529
- CVSS 4.0: **8.7** &nbsp;(`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N`)
- Affected: `>= 0.3.4 and < 1.14.0` &nbsp;|&nbsp; Fixed in: `1.14.0`
- Published: 2026-10-26
- Track: HTTP/2 resource exhaustion
- Research priority: **5.65** (I=6 E=5 R=6 D=6) -- E2 - needs specific protocol feature/topology
- Analyst note: Quadratic cost needs many blocked streams plus repeated SETTINGS/stream-0 WINDOW_UPDATE; more streams to orchestrate.
- Fixing commit(s): [`220b9dfd27`](https://github.com/mtrudel/bandit/commit/220b9dfd27f9a21305be2afc75cbe585ddc24e7a), [`6feadb3118`](https://github.com/mtrudel/bandit/commit/6feadb31189d18b7dcda6c663112cd3bbaf63a46)
- PoC status: not yet implemented (see Section 5 for the pattern to extend)

### CVE-2026-109584

**HTTP/2 cookie crumb join expands a small HPACK header block into an unbounded allocation in Bandit**

- GHSA: GHSA-7gfj-7gvq-3xqj &nbsp;|&nbsp; OSV: EEF-CVE-2026-109584
- CVSS 4.0: **8.7** &nbsp;(`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N`)
- Affected: `>= 0.3.3 and < 1.14.0` &nbsp;|&nbsp; Fixed in: `1.14.0`
- Published: 2026-10-26
- Track: HTTP/2 resource exhaustion
- Research priority: **5.65** (I=6 E=5 R=6 D=6) -- E2 - needs specific protocol feature/topology
- Analyst note: Cookie-crumb join amplification depends on HPACK header-block construction, more encoding nuance than raw frame spam.
- Fixing commit(s): [`220b9dfd27`](https://github.com/mtrudel/bandit/commit/220b9dfd27f9a21305be2afc75cbe585ddc24e7a), [`44bf969cd5`](https://github.com/mtrudel/bandit/commit/44bf969cd59851622fb6ee4d16227fbc39a77fb4)
- PoC status: not yet implemented (see Section 5 for the pattern to extend)

### CVE-2026-110499

**Client-chosen HPACK encoder table size is applied uncapped, growing per-connection state with every response in Bandit**

- GHSA: GHSA-47x4-3fxf-82fr &nbsp;|&nbsp; OSV: EEF-CVE-2026-110499
- CVSS 4.0: **8.7** &nbsp;(`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N`)
- Affected: `>= 0.3.6 and < 1.14.0` &nbsp;|&nbsp; Fixed in: `1.14.0`
- Published: 2026-10-26
- Track: HTTP/2 resource exhaustion
- Research priority: **5.65** (I=6 E=5 R=6 D=6) -- E2 - needs specific protocol feature/topology
- Analyst note: HPACK dynamic-table size update per response; needs many requests over one connection to accumulate state.
- Fixing commit(s): [`0e68313fab`](https://github.com/mtrudel/bandit/commit/0e68313fab9d204257ebad5c447e4cd9cea8e0ea), [`220b9dfd27`](https://github.com/mtrudel/bandit/commit/220b9dfd27f9a21305be2afc75cbe585ddc24e7a)
- PoC status: not yet implemented (see Section 5 for the pattern to extend)

### CVE-2026-65623

**Quadratic CPU blow-up reassembling fragmented WebSocket messages in Bandit**

- GHSA: GHSA-vg8x-66vg-5pxh &nbsp;|&nbsp; OSV: EEF-CVE-2026-65623
- CVSS 4.0: **8.7** &nbsp;(`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N`)
- Affected: `>= 1.11.0 and < 1.12.1` &nbsp;|&nbsp; Fixed in: `1.12.1`
- Published: 2026-07-24
- Track: WebSocket resource exhaustion
- Research priority: **5.65** (I=6 E=5 R=6 D=6) -- E2 - needs specific protocol feature/topology
- Analyst note: Quadratic CPU on fragment reassembly; CPU-bound rather than memory-bound, needs wall-clock timing to observe cleanly.
- Fixing commit(s): [`418ef7e906`](https://github.com/mtrudel/bandit/commit/418ef7e906192a230ddba112f7a669c87b6b0e3a)
- PoC status: not yet implemented (see Section 5 for the pattern to extend)

### CVE-2026-74836

**HTTP/2 connection-window starvation pins Plug processes indefinitely in Bandit**

- GHSA: GHSA-xj8g-532w-jv94 &nbsp;|&nbsp; OSV: EEF-CVE-2026-74836
- CVSS 4.0: **8.7** &nbsp;(`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N`)
- Affected: `>= 0.3.4 and < 1.12.5` &nbsp;|&nbsp; Fixed in: `1.12.5`
- Published: 2026-08-20
- Track: HTTP/2 resource exhaustion
- Research priority: **5.65** (I=6 E=5 R=6 D=6) -- E2 - needs specific protocol feature/topology
- Analyst note: Connection-window starvation pins Plug processes; needs the connection window, not just stream windows, held at zero.
- Fixing commit(s): [`f6914aad14`](https://github.com/mtrudel/bandit/commit/f6914aad14bb1365dd6f306aa592cfb0819bed3e)
- PoC status: not yet implemented (see Section 5 for the pattern to extend)

### CVE-2026-105660

**Unvalidated HTTP/1 request-target authority lets a client choose conn.host and conn.port in Bandit**

- GHSA: GHSA-v53v-9hvg-37jf &nbsp;|&nbsp; OSV: EEF-CVE-2026-105660
- CVSS 4.0: **6.9** &nbsp;(`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N`)
- Affected: `>= 0.6.0 and < 1.13.0` &nbsp;|&nbsp; Fixed in: `1.13.0`
- Published: 2026-10-15
- Track: Request metadata validation
- Research priority: **5.25** (I=4 E=6 R=7 D=5) -- E3 - straightforward protocol interaction
- Analyst note: Trivial to send a crafted request-target; real impact depends entirely on whether the app trusts conn.host/conn.port for authz or routing decisions.
- Fixing commit(s): [`0e3edda0ed`](https://github.com/mtrudel/bandit/commit/0e3edda0edf6322e9164b827c6d3ddecd080ff2e), [`6ea8021013`](https://github.com/mtrudel/bandit/commit/6ea80210137b3f69caf65f67398934259dc365d0)
- PoC status: not yet implemented (see Section 5 for the pattern to extend)

### CVE-2026-75484

**HTTP/2 header field values containing CR, LF or NUL are passed to the application unvalidated in Bandit**

- GHSA: GHSA-x3gh-xhj4-3vq8 &nbsp;|&nbsp; OSV: EEF-CVE-2026-75484
- CVSS 4.0: **6.9** &nbsp;(`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N`)
- Affected: `>= 1.4.0 and < 1.12.5` &nbsp;|&nbsp; Fixed in: `1.12.5`
- Published: 2026-08-20
- Track: Request metadata validation
- Research priority: **5.25** (I=4 E=6 R=7 D=5) -- E3 - straightforward protocol interaction
- Analyst note: CRLF/NUL in HTTP/2 header values reaching the app; impact is header/log/response-splitting downstream of Bandit, not in Bandit itself.
- Fixing commit(s): [`d38cf046c9`](https://github.com/mtrudel/bandit/commit/d38cf046c9a3cae4d0f88001c2ceb4143f86366b)
- PoC status: not yet implemented (see Section 5 for the pattern to extend)

### CVE-2026-111103

**HTTP/2 StreamError recovery rolls back connection state and bypasses per-connection limits in Bandit**

- GHSA: GHSA-2238-pgfc-w82m &nbsp;|&nbsp; OSV: EEF-CVE-2026-111103
- CVSS 4.0: **8.2** &nbsp;(`CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N`)
- Affected: `>= 1.9.0 and < 1.14.0` &nbsp;|&nbsp; Fixed in: `1.14.0`
- Published: 2026-10-26
- Track: HTTP/2 resource exhaustion
- Research priority: **5.05** (I=6 E=4 R=5 D=5) -- E2 - needs specific protocol feature/topology
- Analyst note: Requires driving streams into StreamError recovery repeatedly to roll back connection-level counters; more protocol-edge-case orchestration.
- Fixing commit(s): [`220b9dfd27`](https://github.com/mtrudel/bandit/commit/220b9dfd27f9a21305be2afc75cbe585ddc24e7a), [`3ad49c80c2`](https://github.com/mtrudel/bandit/commit/3ad49c80c268891e7cc412e69649115456638e59)
- PoC status: not yet implemented (see Section 5 for the pattern to extend)

### CVE-2026-42788

**HTTP/2 frame size limit checked after body is buffered in Bandit**

- GHSA: GHSA-q6v9-r226-v65f &nbsp;|&nbsp; OSV: EEF-CVE-2026-42788
- CVSS 4.0: **6.9** &nbsp;(`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N`)
- Affected: `>= 0.3.6 and < 1.11.0 or >= 0.3.5 and < 1.11.0` &nbsp;|&nbsp; Fixed in: `1.11.0`
- Published: 2026-05-01
- Track: HTTP/2 resource exhaustion
- Research priority: **4.75** (I=4 E=5 R=6 D=5) -- E2 - needs specific protocol feature/topology
- Analyst note: Frame-size check ordering bug; impact capped at VA:L per CVSS, smaller blast radius than the rest of the HTTP/2 family.
- Fixing commit(s): [`1e8e55966d`](https://github.com/mtrudel/bandit/commit/1e8e55966da9129016b73d32f0e1df4630e3b463)
- PoC status: not yet implemented (see Section 5 for the pattern to extend)

### CVE-2026-114216

**Chunk extensions accept bare LF and CR, enabling request smuggling in Bandit**

- GHSA: GHSA-w5wc-g2hc-g7m2 &nbsp;|&nbsp; OSV: EEF-CVE-2026-114216
- CVSS 4.0: **6.3** &nbsp;(`CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:L/VA:N/SC:L/SI:L/SA:N`)
- Affected: `>= 1.12.4 and < 1.14.0` &nbsp;|&nbsp; Fixed in: `1.14.0`
- Published: 2026-10-26
- Track: HTTP request smuggling
- Research priority: **4.5** (I=5 E=4 R=4 D=5) -- E2 - needs specific protocol feature/topology
- Analyst note: Needs a front-end proxy with different line-ending tolerance in front of Bandit to matter; pure-Bandit repro shows parser behavior only, not smuggling impact.
- Fixing commit(s): [`220b9dfd27`](https://github.com/mtrudel/bandit/commit/220b9dfd27f9a21305be2afc75cbe585ddc24e7a), [`c31e9e3c76`](https://github.com/mtrudel/bandit/commit/c31e9e3c76dcbfc239a96eabed5341ced7885ae5)
- PoC status: not yet implemented (see Section 5 for the pattern to extend)

### CVE-2026-39805

**CL.CL HTTP request smuggling via duplicate Content-Length in Bandit**

- GHSA: GHSA-c67r-gc9j-2qf7 &nbsp;|&nbsp; OSV: EEF-CVE-2026-39805
- CVSS 4.0: **6.3** &nbsp;(`CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N`)
- Affected: `>= 0.1.0 and < 1.11.0 or < 1.11.0` &nbsp;|&nbsp; Fixed in: `1.11.0`
- Published: 2026-05-01
- Track: HTTP request smuggling
- Research priority: **4.5** (I=5 E=4 R=4 D=5) -- E2 - needs specific protocol feature/topology
- Analyst note: CL.CL duplicate Content-Length; same caveat -- exploitability is a property of the proxy/Bandit pair, not Bandit alone.
- Fixing commit(s): [`f2ca636eb6`](https://github.com/mtrudel/bandit/commit/f2ca636eb6df385219957e8934e9fc6efa1630d1)
- PoC status: not yet implemented (see Section 5 for the pattern to extend)

### CVE-2026-110314

**WebSocket frames keep reaching the WebSock after a server-initiated close in Bandit**

- GHSA: GHSA-2v5v-8f9v-xh85 &nbsp;|&nbsp; OSV: EEF-CVE-2026-110314
- CVSS 4.0: **6.3** &nbsp;(`CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N`)
- Affected: `>= 0.5.1 and < 1.14.0` &nbsp;|&nbsp; Fixed in: `1.14.0`
- Published: 2026-10-26
- Track: WebSocket state correctness
- Research priority: **4.2** (I=3 E=5 R=5 D=5) -- E2 - needs specific protocol feature/topology
- Analyst note: Post-close frame delivery; mostly an application-correctness/isolation issue, modest direct security impact.
- Fixing commit(s): [`220b9dfd27`](https://github.com/mtrudel/bandit/commit/220b9dfd27f9a21305be2afc75cbe585ddc24e7a), [`bb407f2277`](https://github.com/mtrudel/bandit/commit/bb407f2277dcb65a58dd8cc07913a0b58a80e266)
- PoC status: not yet implemented (see Section 5 for the pattern to extend)

### CVE-2026-39807

**Client-supplied URI scheme trusted without transport verification in Bandit**

- GHSA: GHSA-375f-4r2h-f99j &nbsp;|&nbsp; OSV: EEF-CVE-2026-39807
- CVSS 4.0: **6.3** &nbsp;(`CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N`)
- Affected: `>= 1.0.0 and < 1.11.0` &nbsp;|&nbsp; Fixed in: `1.11.0`
- Published: 2026-05-01
- Track: Request metadata validation
- Research priority: **4.1** (I=3 E=5 R=5 D=4) -- E2 - needs specific protocol feature/topology
- Analyst note: Client-supplied scheme trusted without transport check; impact is app-level (e.g. incorrect redirect/secure-cookie logic) not Bandit crashing.
- Fixing commit(s): [`45feea20de`](https://github.com/mtrudel/bandit/commit/45feea20dea8af7ffd7245271107b695c040e667)
- PoC status: not yet implemented (see Section 5 for the pattern to extend)

## 5. PoC coverage and how to extend it

4 package probes are implemented under `vulnerabilities/*/poc/` and run by `vulnforge validate`. The legacy `probes/registry.py` harness remains for historical comparison.

- `CVE-2026-105659` -> `vulnerabilities/CVE-2026-105659/poc/exploit.py` (vulnerable `vulnerable` vs patched `patched`; metric `attack_memory_delta`)
- `CVE-2026-111101` -> `vulnerabilities/CVE-2026-111101/poc/exploit.py` (vulnerable `vulnerable` vs patched `interim`; metric `attack_memory_delta`)
- `CVE-2026-116078` -> `vulnerabilities/CVE-2026-116078/poc/exploit.py` (vulnerable `interim` vs patched `patched`; metric `attack_memory_delta`)
- `CVE-2026-39803` -> `vulnerabilities/CVE-2026-39803/poc/exploit.py` (vulnerable `vulnerable` vs patched `patched`; metric `attack_memory_delta`)

Multi-run results (`vulnerabilities/*/evidence/validation.json`):

| CVE | Pair | Metric | Vulnerable median | Patched median | Runs | Verdict | Detection |
|---|---|---|---|---|---|---|---|
| `CVE-2026-111101` | `1.13.1` -> `1.14.0` | `attack_memory_delta` | 2.66 MiB | 1.67 MiB | 3 | **INCONCLUSIVE** | INCONCLUSIVE |
| `CVE-2026-116078` | `1.14.0` -> `1.14.1` | `attack_memory_delta` | 7.78 MiB | 0.60 MiB | 3 | **CONFIRMED** | TRIGGERED |

Verdicts are median-based with a patched-CV guard; run ranges must not overlap in absolute mode. A non-`CONFIRMED` verdict is a real result, not a reporting gap.
- `CVE-2026-111101`: INCONCLUSIVE -- relative reduction 1.60x is below the pre-registered 2.00x threshold

The next-highest-priority item that is still vulnerable at the lab's `1.13.1` checkpoint is **CVE-2026-108525** (HTTP/2 inbound flow control is not enforced, letting a client queue unbounded DATA in stream processes in Bandit). Add its package under `vulnerabilities/`, register the probe in `poc/manifest.json`, and re-run `vulnforge validate`.

10 remaining advisories are fixed before `1.13.1` (for example CVE-2026-39806, CVE-2026-42786, CVE-2026-39804, CVE-2026-65623) and cannot be reproduced against the current "vulnerable" container. Add the corresponding older checkpoint version from `data/lab-checkpoints.json` before implementing those PoCs.

## 6. Remediation

All 24 advisories are fixed upstream; the single remediation is **upgrade to Bandit >= 1.14.1**. For the request-smuggling family (CVE-2026-114216, CVE-2026-39805), also audit any reverse proxy in front of Bandit for matching chunk-extension and duplicate-Content-Length handling -- the advisory fixes Bandit's own parsing, but smuggling impact is a property of the Bandit+proxy pair.

## 7. Detection guidance

`tests/detection/thresholds.py` implements four behavioral rules that do not depend on the exact PoC payload:
- `per_connection_frame_rate` -- sustained tiny-frame/tiny-chunk rate far above what a legitimate client needs to deliver its payload.
- `memory_per_connection_outlier` -- one connection's attributable memory delta is a statistical outlier against the rest of the pool.
- `body_duration_vs_size` -- a body takes far longer to arrive than its size and the configured rate suggest (trickle attacks).
- `unbounded_process_growth` -- BEAM process count or top-process memory grows monotonically across polling intervals with no completed-request progress.

## 8. Limitations

- This report classifies exploitability independently per-CVE; it does not model combined/chained exploitation across advisories.
- `priority_P` scores are analyst judgment calls recorded in `data/prioritization.json`, not derived mechanically -- treat disagreements with them as a reason to revise the scoring data, not the report text.
- PoCs sample `erlang:memory()` on a minimal lab app while the request is in flight; absolute amplification ratios on a production app with different Plug/body-handling behaviour will differ, though the direction of the effect (vulnerable amplifies, patched does not) should not.
- The lab currently ships 1.13.1, 1.14.0, and 1.14.1 only. Advisories fixed before 1.13.1 need an older checkpoint image before they can be tested.
- CVE-2026-111101 is INCONCLUSIVE: the corrected 1.13.1 vs 1.14.0 pair shows a stable 1.60x reduction, below the pre-registered 2.00x threshold, and the recorded commits do not identify the 1.14.0 fix. Do not cite it as a confirmed finding.
