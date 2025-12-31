# Skill Plan: HA alignment improvements

Goal
- Improve HA best-practice alignment and UX without introducing regressions.

Constraints
- Prefer low-risk changes first.
- Keep changes small and reversible.

Prioritized plan (least impactful -> most impactful)
1) Localization + entity names via translations (done)
   - Add translation keys for switch/sensor/select/binary_sensor.
   - Entity names now come from translations (no behavior change).

2) Diagnostics-only IDs (remove from state attrs)
   - Move user_id/structure_id to diagnostics only.
   - Optional debug toggle if needed for troubleshooting.
   - Mild risk: attribute removal may affect existing dashboards.

3) Options flow (optional tuning)
   - Add options for stale timeout / debug attrs / extra logging.
   - Medium risk: new config path, but default behavior unchanged.

4) Reauth flow
   - Raise ConfigEntryAuthFailed on auth/cookie expiration.
   - Add reauth step to config flow.
   - Higher risk: impacts setup path and user flows.

Validation approach
- Manual HA test after each step.
- Keep pre-releases for each step to isolate regressions.
