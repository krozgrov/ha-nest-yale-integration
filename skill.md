# Skill Plan: HA alignment improvements

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
