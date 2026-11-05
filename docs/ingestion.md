# Ingestion and source analysis

## Ingest

The target name comes from `config/vulnforge.yaml`; the adapter supplies the
OSV ecosystem/package and the GitHub repository used by `analyze`.

```bash
vulnforge ingest bandit --refresh          # fetch OSV, write a proposal
vulnforge ingest bandit --offline --raw path/to/snapshot.json
vulnforge ingest bandit --refresh --apply  # explicit apply
```

A target with no OSV coordinates (for example the toy adapter) is refused with
a clear error rather than falling back to Bandit's package name.

Default behavior is a dry-run:

- raw response saved to `data/raw/osv/bandit.json` with timestamp and SHA-256
- normalized records compared to `data/advisories.json`
- proposed catalog in `data/proposed/advisories.json`
- reviewable unified diff in `data/proposed/diff.txt`

Merge rules:

- existing human-maintained fields (`track`, `cvss_score`, notes) are preserved
  when the source omits them
- commits/references are unioned
- existing advisories not returned by the source are never deleted
- records without a CVE alias are skipped

The current catalog contains synthetic 2026 advisories; a live OSV refresh may
return a different set. Treat the proposal as intelligence, not authority.

## Source analysis

```bash
vulnforge analyze CVE-2026-116078 --refresh
```

This:

- fetches fixing commit patches into `analysis/commits/`
- records source URL, timestamp, and SHA-256
- writes `analysis/root-cause.generated.md` with changed files and review
  questions
- never overwrites the human-written `analysis/root-cause.md`

## Triage

```bash
vulnforge triage
vulnforge triage --check
vulnforge triage --from-packages
```

`--from-packages` overlays packaged `advisory.json` files onto the global
catalog before running the resolver/prioritizer. The catalog remains the source
of truth for un-packaged advisories. A full catalog-to-package flip is deferred
until all advisories have packages.

## Known data-quality caveat

CVE-2026-111101's recorded commits are a version bump and an unrelated 2020
refactor. The analysis output flags the mismatch; do not treat a commit URL as
proof of the fix without inspecting the diff.
