# Execution Plan

Purpose
- Canonical execution-planning file for this repository.
- Tracks planned work, execution order, risks, and validation expectations.

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

## Historical Plan and Status (migrated from `skill.md` on 2026-02-13)

Goal
- Improve HA best-practice alignment and UX without introducing regressions.

Constraints
- Prefer low-risk changes first.
- Keep changes small and reversible.

Prioritized plan (least impactful -> most impactful)
1) Localization + entity names via translations (completed)
- Add translation keys for switch/sensor/select/binary_sensor.
- Resolve stale entity registry state after remove/re-add.
- Avoid setting _attr_name for entity-named entities (HA skips translations when _attr_name exists).
- Ensure registry name normalization runs after add to correct old original_name values.
- Guard translation_key assignment so only string values are stored (prevents registry serialization errors).
- Keep device identifiers stable (device_id only) to avoid device/entry splits when serial arrives.

2) Diagnostics-only IDs (remove from state attrs) (completed)
- Move user_id/structure_id to diagnostics only.
- Optional debug toggle if needed for troubleshooting.
- Mild risk: attribute removal may affect existing dashboards.

3) Options flow (optional tuning) (completed)
- Added options for stale timeout and debug attributes.
- Default behavior unchanged; options are additive.

4) Reauth flow (completed)
- Raise ConfigEntryAuthFailed on auth/cookie expiration.
- Add reauth step to config flow.
- Higher risk: impacts setup path and user flows.

5) Code health review follow-ups (completed)
- Unify trait filtering/extraction helpers used by observer + fallback paths.
- Fix trait key mismatch in metadata lookup so cached DeviceIdentityTrait is used consistently.
- Consolidate entity coordinator update boilerplate in the base class.
- Simplify device_info update flow to reduce duplication and branching.
- Consolidate battery trait parsing to a shared helper to avoid drift.
- Reduce INFO log noise for routine trait updates; keep verbose logs at DEBUG.
- Add last command status to diagnostics-only output for easier troubleshooting.
- Risk: medium (refactor-heavy; must preserve entity/state behavior).

6) Device name from LabelSettingsTrait (completed)
- Add LabelSettingsTrait to observe payload.
- Decode label settings and extract a non-empty device name.
- Normalize invalid placeholders (e.g., "undefined") to avoid polluting device registry.
- Update device registry name when user has not overridden it and the name changes.
- Risk: low-medium (new trait parsing; potential for unexpected name sources).

7) Device name from located fixture labels (completed)
- Parse CustomLocatedAnnotationsTrait fixture labels for lock names when LabelSettingsTrait is missing.
- Use where labels for where_label/area display only (no suggested_area updates).
- Remove suggested_area updates (HA deprecates suggested_area).
- Prefer custom fixture labels over fixtureNameLabel when available.
- Risk: low-medium (new manual trait decoding; device naming updates).

8) Legacy app_launch name override (in progress)
- Fetch app_launch data (throttled) and extract device names for locks.
- Override lock names when app_launch provides a more accurate device label than protobuf traits.
- Risk: medium (extra API call; parsing heuristics).

9) LabelSettingsTrait decode hardening (in progress)
- Prefer protobuf unpack of LabelSettingsTrait when the proto class is available.
- Guard protobuf unpack behind presence checks and fall back to manual decode.
- Risk: low (name parsing only).

10) Guest passcode management services (completed)
- Add Home Assistant services to set/update and delete guest passcodes.
- Use `UserPincodesSettingsTrait.SetUserPincodeRequest` and `DeleteUserPincodeRequest` command payloads through existing `SendCommand` plumbing.
- Resolve target lock by `device_id` when provided; otherwise auto-select when a single lock is configured.
- Require explicit guest user resource IDs for this first version and validate passcode format before sending commands.
- Add service docs and logging/diagnostics hooks for troubleshooting command outcomes.
- Risk: medium-high (Nest guest/passcode APIs are under-documented; behavior may vary by account/firmware).
- Test/validation: manual HA service-call validation for successful set/delete, invalid passcode handling, missing/ambiguous device targeting, and command error surfacing.

Validation approach
- Manual HA test after each step.
- Keep pre-releases for each step to isolate regressions.

Status updates
- 2025-12-31: No plan changes; b42 includes HA 2025.12 compatibility fix for entity naming guard.
- 2025-12-31: Completed reauth flow and prepared for b43 pre-release.
- 2025-12-31: Filter trait cache to lock-only devices plus structure/user metadata to reduce unrelated device bleed-through.
- 2025-12-31: Sync coordinator device data on entity add to avoid unknown values until the next observer update.
- 2026-01-01: Code health review captured follow-up refactors for duplication and trait metadata alignment; pending decision.
- 2026-01-01: Started code health work; fixed DeviceIdentityTrait metadata lookup to handle type_url key variations.
- 2026-01-01: Deduplicated trait filtering/extraction helpers in coordinator; observer and fallback paths now share the same logic.
- 2026-01-01: Added base entity coordinator update helper to reduce per-entity boilerplate.
- 2026-01-01: Centralized battery trait parsing helpers for lock attributes and the battery sensor.
- 2026-01-01: Simplified device_info update flow with shared helpers to reduce branching.
- 2026-01-01: Reduced routine trait update logs to DEBUG and added last-command status to diagnostics output.
- 2026-01-01: Completed code health review follow-ups for refactor readiness.
- 2026-01-01: Removed hardcoded fallback device name to align with HA naming expectations.
- 2026-01-10: LocatedAnnotationsTrait returned location catalog, not device names; switched plan to LabelSettingsTrait.
- 2026-01-10: Added LabelSettingsTrait device name parsing and registry sync update.
- 2026-01-10: Switched LabelSettingsTrait decoding to manual parsing after invalid proto descriptor caused import errors.
- 2026-01-10: Added DeviceLocatedSettingsTrait mapping as fallback to resolve lock names from location catalog when label settings are missing.
- 2026-01-10: Decode DeviceLocatedSettingsTrait whereLabel/fixtureNameLabel to match the app's "Where" field when present.
- 2026-01-10: Prefer fixtureNameLabel for device names and expose whereLabel as suggested area.
- 2026-01-10: Decode DeviceLocatedSettingsTrait fixture/where annotation IDs and map fixture IDs to custom annotations for lock names.
- 2026-01-11: Parse CustomLocatedAnnotationsTrait fixture labels and update suggested_area in the device registry.
- 2026-01-11: Drop suggested_area updates per HA deprecation; prefer custom fixture labels over fixtureNameLabel.
- 2026-01-11: Add legacy app_launch name override step after fixture labels still did not match the Nest app device name.
- 2026-01-11: Preserve LabelSettingsTrait as the top priority by not overwriting it with fixture labels.
- 2026-01-11: Extend app_launch parsing to carry device/serial hints through nested payloads for better name mapping.
- 2026-01-11: Plan to harden LabelSettingsTrait decoding using protobuf unpack with manual fallback.
- 2026-01-15: Prefer confirmed trait states for naming/location to avoid stale accepted values; guard LabelSettingsTrait protobuf unpack to avoid missing-class errors.
- 2026-01-15: Allow CustomLocatedAnnotationsTrait through v2 parsing and prefer custom fixture labels when the current name looks like a location label.
- 2026-02-13: Fixed naming precedence so auth/app_launch fallbacks no longer overwrite resolved trait names, addressing stale generic lock names in HA.
- 2026-02-13: Added guest passcode services (`set_guest_passcode`, `delete_guest_passcode`) using UserPincodesSettingsTrait command requests with device-aware passcode validation.
- 2026-02-13: Fixed b1 regression by merging protobuf map fields correctly and filtering lock discovery to `DEVICE_*` ids only; stale `USER_*` registry artifacts are now cleaned up during setup.
- 2026-02-13: Expanded registry cleanup to remove legacy non-`DEVICE_*` entity/device IDs once canonical `DEVICE_*` IDs are present, preventing duplicate lock devices like generic “Nest Yale”.
- 2026-02-13: Hardened app_launch name parser and override behavior so location labels are not misattributed as lock names and app-side renames propagate to HA.
- 2026-02-13: Added fallback user-id discovery for app_launch refresh (access-token claims + observed pincode trait user ids) so name sync still works when id_token is absent.
- 2026-02-13: Triggered throttled app_launch refresh on lock updates (even when stream `user_id` stays unset), added `USER_*` suffix candidate attempts for app_launch requests, and corrected non-lock v2 trait merge order so confirmed naming states win over accepted.
- 2026-02-13: Added explicit `door_label` + `label_name` naming components and composed lock name as `door_label (label_name)` while keeping `where_label` as placement; app_launch overrides are fallback-only when trait label is missing.
