# Phase 0 documentation review (MaybeEdgeScanner)

Date: 2026-05-31

## README

- Product is described as route-pairing and evidence-based route comparison, not IP-first CDN scanning.
- Observer-only vs attachable route states are mentioned at a high level.

## Sidecar README (`go-sidecar/README.md`)

- Same NDJSON/error envelope documentation as MaybeScanner sidecar (shared implementation).
- Route-aware scan paths documented; classification hints are not route proof.

## Architecture / verification

- `docs/ARCHITECTURAL_GUIDE.md`: no lock-free/arena overclaims.
- `docs/VERIFICATION_GUIDE.md`: route validation proves listener/dialer attachability for selected modes, not full provider VPN lifecycle or end-user account state.

## User guide (2026-05-31)

- `docs/USER_GUIDE.md` reframed: explicit targets and route pairing first; CDN presets are optional advanced sources, not the default onboarding path.
- Removed default positioning of “Verify CDN Edge” as a core profile.

## Deferred

- Device screenshots for route observer/attachable states (B4).
