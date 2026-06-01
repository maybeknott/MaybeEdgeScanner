# MaybeEdgeScanner Source Offer Notes (Pre-Release Baseline)

Last updated: 2026-06-01

This file records the source-offer baseline for release readiness.
It is not a final legal distribution notice.

## Baseline Position

- Primary repository code is distributed under AGPLv3 (`/LICENSE`).
- Release artifacts must map back to corresponding source revisions and build instructions.
- Sidecar binary provenance is tracked in `docs/sidecar-binary-provenance.json`.

## Release-Time Source Offer Requirements

Before stable release, ensure the release package and release notes include:

- The corresponding source commit/tag for each distributed binary artifact.
- Reproducible build instructions or scripted build references for app + sidecar.
- Dependency baseline artifacts (`docs/SBOM_BASELINE.md`, `docs/sbom/*.json`).
- Any additional source-offer text required by bundled dependency licenses.

## External Reference Guardrails

External ecosystem references under `D:\GitHub\SCANNERS\tooling_inventory\external_refs` are planning inputs only.
They must not be treated as bundled runtime source unless explicit provenance and license review are complete.

## Explicit Non-Claims

- This document does not claim final legal sufficiency for distribution.
- This document does not claim all provider/plugin licensing obligations are closed.
