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

Validation approach
- Manual HA test after each step.
- Keep pre-releases for each step to isolate regressions.

Status updates
- 2025-12-31: No plan changes; b42 includes HA 2025.12 compatibility fix for entity naming guard.
- 2025-12-31: Completed reauth flow and prepared for b43 pre-release.
- 2025-12-31: Filter trait cache to lock-only devices plus structure/user metadata to reduce unrelated device bleed-through.
- 2025-12-31: Sync coordinator device data on entity add to avoid unknown values until the next observer update.
