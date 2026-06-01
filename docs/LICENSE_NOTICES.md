# MaybeEdgeScanner License Notices (Pre-Release Baseline)

Last updated: 2026-06-01

This document is a baseline notices file for pre-release verification.
It is not the final shipped NOTICE bundle.

## Project License

- Repository license: AGPLv3 (`/LICENSE`).

## Third-Party Dependency License Baseline

Dependency inventories are recorded in:

- `docs/SBOM_BASELINE.md`
- `docs/sbom/cyclonedx.pre-release.json`
- `docs/sbom/spdx.pre-release.json`

This baseline records where dependency license review must attach.

## Release-Time Notice Requirements

Before stable release, attach a finalized NOTICE bundle that is aligned to the exact signed artifact set and includes:

- Android dependency notices from resolved release dependencies.
- Go module notices from the sidecar release module graph.
- Bundled sidecar binary provenance from `docs/sidecar-binary-provenance.json`.
- Any bundled non-code assets with license/attribution requirements.

## Explicit Non-Claims

- This file is not a legal opinion.
- This file does not claim that all third-party notice obligations are complete.
- This file does not replace release-time legal/compliance review.
