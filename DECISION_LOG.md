# Decision Log

Purpose
- Canonical decision-rationale file for this repository.
- `DEV_NOTES.md` remains the historical source during migration; this file captures current/high-impact decisions in canonical form.

## Decision Entries

### 2026-02-13: Preserve lock naming from app-level sources and prevent stale fallbacks
Why
- Users reported persistent incorrect lock naming in Home Assistant despite app-side labels changing.

Decision
- Treat auth payload names as fallback only.
- Apply app-launch overrides only when needed and allow updates when names differ.
- Harden app-launch parsing so location labels are not misattributed as lock names.

Impact
- Non-breaking.
- Device names now track Nest app labels more reliably.

Validation
- Manual HA verification via observer logs and device registry name checks.

### 2026-02-13: Keep lock identity and registry entries canonical to `DEVICE_*`
Why
- Regression introduced duplicate/ghost lock devices from non-device resource IDs and legacy identifiers.

Decision
- Restrict lock discovery and coordinator/device updates to `DEVICE_*` IDs.
- Clean stale non-`DEVICE_*` and `USER_*` registry artifacts at setup.

Impact
- Non-breaking for valid entities.
- Removes invalid duplicate artifacts created by pre-release regressions.

Validation
- Manual HA device registry verification after reload.

### 2026-02-13: Support guest passcode management with explicit scope and validation
Why
- Requested capability to manage guest passcodes from Home Assistant.

Decision
- Add services for set/delete guest passcodes.
- Require explicit guest user IDs and validate passcode format/length.

Impact
- Backward-compatible feature addition.
- Adds new service surface area requiring user validation.

Validation
- Manual service-call tests for set/delete and invalid input paths.

## Migration Note
- Historical decisions prior to these entries are preserved in `DEV_NOTES.md`.
