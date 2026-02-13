# Execution Plan

Purpose
- Canonical execution-planning file for this repository.
- `skill.md` remains the detailed historical plan during migration; this file tracks active execution state in canonical format.

## Active Workstream

### Name Sync and Passcode Reliability
Goal
- Ensure lock naming in Home Assistant matches current Nest app labels.
- Keep guest passcode workflows stable after recent parser/trait changes.

Execution Outline
1. Stabilize data ingestion and lock identity
- Keep lock resources constrained to `DEVICE_*`.
- Maintain map-field-safe protobuf merge behavior for passcode traits.

2. Stabilize naming source precedence
- Prefer lock-specific name sources over location-catalog values.
- Allow app-launch name refresh to update stale names.
- Ensure refresh still runs when `id_token` is unavailable (user-ID fallback path).

3. Validate registry behavior
- Confirm only one lock device record persists per physical lock.
- Confirm names propagate without creating orphans/duplicates.

4. Validate guest passcode behavior
- Verify `set_guest_passcode` and `delete_guest_passcode` calls.
- Verify input validation and error surfacing.

Risks
- App-launch payload structure and user-ID resolution vary by account.
- Existing HA user overrides (`name_by_user`) can mask integration-driven name updates.

Validation Expectations
- Manual HA validation in dev environment for:
  - Name propagation (`Garage door`/current app label)
  - Single-device registry consistency
  - Passcode service success/failure paths

Status
- In progress.
- See `skill.md` for full historical execution trail.
