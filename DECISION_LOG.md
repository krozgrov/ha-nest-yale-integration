# Decision Log

Purpose
- Canonical decision-rationale file for this repository.
- Captures design intent and behavior decisions for continuity across refactors and releases.

## Structured Decisions

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

### 2026-02-13: Support app-launch name sync when `id_token` is missing
Why
- Some auth responses do not include `id_token`, leaving `user_id` unset and blocking app-launch name refresh.

Decision
- Derive user-id candidates from Nest JWT claims, auth payload fields, and observed pincode trait cache.
- Avoid setting app-launch refresh throttle timestamps when no user-id candidates are available.

Impact
- Non-breaking reliability improvement.
- Increases probability of correct name propagation after startup.

Validation
- Manual verification through debug logs and HA device-name propagation checks.

### 2026-02-13: Keep lock naming fresh when stream actor IDs are absent
Why
- Some accounts only emit physical actor updates, so stream `user_id` remains unset and legacy app-launch refresh was not retriggered after trait cache warm-up.
- V2 trait merge ordering for non-lock traits could apply stale accepted states over confirmed states.

Decision
- Trigger throttled app-launch name refresh whenever lock updates are processed (not only when stream `user_id` changes).
- For `USER_*` app-launch candidates, also try the suffix without the `USER_` prefix (including hex IDs).
- Apply non-lock v2 trait merges in rank order that leaves confirmed state authoritative.
- Expand LabelSettingsTrait patch scanning to prefer nested `Any` payloads with known type URLs and value data.

Impact
- Non-breaking behavior fix.
- Improves probability that HA lock name reflects the current Nest app label (`Garage door`/custom label) instead of stale location defaults.

Validation
- Manual HA verification using debug logs for:
  - app-launch refresh attempts after observer updates with `user_id=None`
  - parsed lock `name` switching away from stale `Front door` values when app data differs.

### 2026-02-13: Compose lock name from door label and app label
Why
- Placement (`where_label`) and lock-facing door label are separate concepts in Nest.
- Users requested final HA naming that keeps door context while still reflecting app label text.

Decision
- Persist `door_label` (door/fixture name) separately from `where_label` (placement).
- Persist app label as `label_name`.
- Compute display name as `door_label (label_name)` when both are present; otherwise use whichever exists.
- Treat app_launch overrides as fallback when trait-derived `label_name` is missing.
- Keep `door_label` literal from Nest-provided values only (no synthesized suffixes or fixture-type-derived naming).
- Normalize flagged annotation IDs (for example `ANNOTATION_0000000001000007`) back to canonical annotation IDs so door/placement mappings resolve to current Nest values.

Impact
- Non-breaking behavior change to naming format.
- Device name now includes both door context and label context (example: `Garage door (Test1)`).

Validation
- Manual HA verification via observer logs and state attributes:
  - `where_label` remains placement (example: `Entryway`)
  - `door_label` reflects door context (example: `Garage door`)
  - `label_name` reflects Nest label (example: `Test1`)
  - `name` resolves to composed value.

### 2026-02-13: Seed first-time HA lock naming from placement label
Why
- Users requested initial lock add behavior to use placement (`where_id` -> label) as the name source in Home Assistant.

Decision
- During first-time entity creation, if `where_label` is present, use it as the initial lock `name` seed.
- Keep parsing/composition traits intact for runtime state attributes.

Impact
- Non-breaking.
- Affects initial HA entity/device naming (and resulting initial entity_id generation) at add time.

Validation
- Manual HA add/re-add validation confirms first-created lock entity name is placement-derived.

## Historical Decision Timeline (migrated from `DEV_NOTES.md` on 2026-02-13)
- 2025-12-30: Use gRPC v1 SendCommand/BatchUpdateState requests (legacy-style) for lock commands/settings while keeping v2 Observe for state/traits to improve command reliability and retain richer trait updates.
- 2025-12-30: Removed bolt lock actor originator IDs from command payloads to align with legacy behavior and avoid INTERNAL errors on lock/unlock.
- 2025-12-30: Prefer confirmed v2 trait state for non-lock traits (e.g., auto-relock settings) and suppress transient last_action updates while bolt is moving to avoid "Other" flicker.
- 2025-12-30: Restore protobuf update headers (request-id, structure/user ids) and allow v2 structure_id for auto-relock settings to improve Nest app sync.
- 2025-12-30: Add EnhancedBoltLockSettingsTrait observation and optional update path to better align Auto-Lock changes with Nest app behavior.
- 2025-12-30: Guard nest-trait BoltLockSettingsTrait updates because the current nest security proto lacks that message; keep enhanced trait path only.
- 2025-12-30: Prefer updating EnhancedBoltLockSettingsTrait when available and log per-trait BatchUpdateState statuses to diagnose Nest app Auto-Lock sync failures.
- 2025-12-30: Update both weave BoltLockSettingsTrait and enhanced bolt lock settings in BatchUpdateState to keep Nest app auto-lock in sync with HA changes.
- 2025-12-30: Send BoltLockSettingsTrait updates with FieldMask to avoid clearing unrelated enhanced auto-lock fields that can disable relock behavior.
- 2025-12-31: Prefer per-trait BatchUpdateState statuses to avoid false INTERNAL errors on successful auto-lock updates.
- 2025-12-31: Ignore BatchUpdateState top-level status when per-trait statuses succeed to prevent false service failures.
- 2025-12-31: Treat INTERNAL on auto-lock updates as transient to avoid failing HA service calls when Nest responds with internal status despite applying changes.
- 2025-12-31: Treat UUID-style structure IDs from StructureInfoTrait legacy_id as v2 IDs so update requests include X-Nest-Structure-Id.
- 2025-12-31: Preserve legacy STRUCTURE_ hex IDs alongside v2 UUIDs so BatchUpdateState headers use the legacy structure id (avoids INTERNAL errors).
- 2025-12-31: Fix STRUCTURE_ parsing to overwrite default None so legacy structure ids actually persist for headers.
- 2025-12-31: Revert auto-lock updates to legacy-only BoltLockSettingsTrait (no enhanced trait, no field mask, no extra headers) to match nest_legacy and avoid INTERNAL errors.
- 2025-12-31: Add enhanced auto-lock update (separate request, no field mask) while retaining weave update to keep Nest app and lock behavior in sync.
- 2025-12-31: Treat missing autoRelockOn in settings traits as false to stop HA auto-lock switches from flipping back on after disable.
- 2025-12-31: Use translation keys for entity names so UI labels are localized and avoid hardcoded English.
- 2025-12-31: Reset per-entry added entity trackers on setup to avoid stale rediscovery state after remove/re-add.
- 2025-12-31: Only apply device metadata name to entities that opt out of entity naming so sub-entities use translated labels.
- 2025-12-31: Always set device registry name from metadata (when user hasn’t overridden) so sub-entities don’t appear as “Unnamed device.”
- 2025-12-31: Use entity descriptions with translation keys so sub-entity names render correctly in HA UI.
- 2025-12-31: Reapply class-level _attr_has_entity_name after CoordinatorEntity init so sub-entity names use translation-based labels instead of device name.
- 2025-12-31: Promote entity_description.translation_key to _attr_translation_key for entity-named sub-entities so translations render consistently.
- 2025-12-31: Set _attr_has_entity_name before CoordinatorEntity init so HA computes entity names with translation behavior.
- 2025-12-31: Explicitly set _attr_translation_key as class attributes in all entity classes (sensor, binary_sensor, switch, select) to ensure Home Assistant properly applies translations from strings.json.
- 2025-12-31: Improve translation key extraction in base entity class to check both instance and class attributes for entity_description, ensuring translation keys are properly extracted and applied.
- 2025-12-31: Keep device registry identifiers stable (device_id only) and store serial_number separately to prevent duplicate/orphaned devices when trait data arrives.
- 2025-12-31: Do not set _attr_name for entity-named sub-entities because HA’s name resolver skips translations when _attr_name exists; ensure registry name normalization runs by keeping a single async_added_to_hass.
- 2025-12-31: Only assign _attr_translation_key for entity-named entities when the value is a string to avoid property-object serialization errors that can drop the lock entity.
- 2025-12-31: Remove user_id/structure_id from state attributes and keep them in diagnostics-only output.
- 2025-12-31: Mask structure_id in diagnostics alongside user_id to align with HA privacy guidance.
- 2025-12-31: Add an options flow to tune stale state timeout and expose masked debug identifiers when explicitly enabled.
- 2025-12-31: Avoid importing UNDEFINED (missing in HA 2025.12) and skip registry name normalization when the computed name is not a non-empty string to prevent entity registry serialization errors.
- 2025-12-31: Add reauth flow by raising ConfigEntryAuthFailed on cookie/auth expiration and starting reauth from coordinator when authentication fails.
- 2025-12-31: Filter cached trait data to lock-only device IDs plus structure/user traits to reduce unrelated device metadata bleed-through in HA UI/logs.
- 2025-12-31: Sync latest coordinator device data when entities are added so battery/traits don’t stay unknown until the next update.
- 2025-12-31: Merge cached trait data into fallback refreshes and persist all_traits from refresh_state to avoid firmware/battery showing unknown until a new observer update.
- 2026-01-01: Capture code health review findings (trait key mismatch in metadata lookup, duplicated trait filtering/extraction helpers, repeated entity update boilerplate, complex device_info update flow) to guide refactors without changing runtime behavior yet.
- 2026-01-01: Begin code health work by making DeviceIdentityTrait metadata lookup tolerant of type_url key variations.
- 2026-01-01: Deduplicate coordinator trait filtering/extraction helpers to keep observer and fallback paths in sync.
- 2026-01-01: Add a base entity helper for coordinator updates to reduce duplicate update boilerplate across entity platforms.
- 2026-01-01: Centralize battery trait parsing helpers to keep lock attributes and battery sensor values aligned.
- 2026-01-01: Simplify device_info updates with shared helpers to reduce branching while preserving registry update behavior.
- 2026-01-01: Queue log-level tweak for routine trait updates and diagnostics-only last command status to reduce log noise and aid troubleshooting.
- 2026-01-01: Lower routine trait update logging to DEBUG and expose last command status in diagnostics output.
- 2026-01-01: Complete code health refactor set (trait helpers, entity updates, battery parsing, device_info, logging/diagnostics) in preparation for stable promotion.
- 2026-01-01: Remove hardcoded "Front Door Lock" fallback name so HA can use actual API names or user-provided names.
- 2026-01-10: LocatedAnnotationsTrait returned location catalog instead of device names; switch to LabelSettingsTrait for lock naming and ignore placeholder values (like "undefined") so device registry names stay accurate; allow registry name updates when users have not overridden names.
- 2026-01-10: LabelSettingsTrait proto descriptor was invalid; replace with manual label decoding to avoid import errors.
- 2026-01-10: Add DeviceLocatedSettingsTrait mapping to resolve lock names from location catalog when label settings are missing.
- 2026-01-10: Decode DeviceLocatedSettingsTrait whereLabel/fixtureNameLabel to use the app's "Where" value when available.
- 2026-01-10: Prefer fixtureNameLabel for device names while storing whereLabel as suggested area.
- 2026-01-10: Decode DeviceLocatedSettingsTrait fixture/where annotation IDs and map fixture IDs to custom annotations for lock names.
- 2026-01-11: Parse CustomLocatedAnnotationsTrait fixture labels for lock naming and update device registry suggested_area from where labels instead of using where labels as device names.
- 2026-01-11: Prefer custom fixture labels over fixtureNameLabel when available and drop suggested_area updates due to Home Assistant deprecation.
- 2026-01-11: Add legacy app_launch name overrides (throttled) to align lock names with Nest app labels when protobuf naming sources disagree.
- 2026-01-11: Preserve LabelSettingsTrait names by only using fixture labels when no name is already set.
- 2026-01-11: Improve app_launch name parsing by carrying device/serial hints through nested structures to better map labels to lock IDs.
- 2026-01-11: Prefer protobuf unpack for LabelSettingsTrait with manual fallback to improve device name accuracy.
- 2026-01-15: Guard LabelSettingsTrait protobuf unpack behind presence checks; fall back to manual decode when the proto class is unavailable.
- 2026-01-15: Prefer confirmed trait states for name/location traits; accepted state can lag and surface stale labels.
- 2026-01-15: Parse CustomLocatedAnnotationsTrait in v2 observe and use custom fixture labels to override generic location names when available.
- 2026-02-13: Treat auth_data device names as true fallback only so trait/device-stream names are not overwritten by stale generic labels (fixes persistent "Front door lock" naming regressions).
- 2026-02-13: Apply legacy app_launch name overrides only when a lock currently has no resolved name so fallback data cannot clobber trait-derived Nest app labels.
- 2026-02-13: Add guest passcode service support via UserPincodesSettingsTrait set/delete commands; require explicit guest user ids for safety and validate passcode length against observed capabilities when available.
- 2026-02-13: Handle protobuf map fields during trait merge (`MessageMapContainer`) so observe/refresh no longer crash when UserPincodes map updates arrive.
- 2026-02-13: Restrict lock discovery to `DEVICE_*` resource ids and clean stale `USER_*` registry entries to prevent duplicate ghost devices (e.g., generic “Nest Yale”) after passcode trait parsing.
- 2026-02-13: Expand startup registry cleanup to remove legacy non-`DEVICE_*` entities/devices (e.g., old serial-based IDs) when canonical `DEVICE_*` entries exist, eliminating duplicate lock devices in HA.
- 2026-02-13: Harden app_launch name extraction to avoid inheriting device IDs into nested location nodes, and allow app_launch overrides to update differing existing names so Nest app label changes (e.g., Garage door) propagate in HA.
- 2026-02-13: When id_token is missing, derive user id candidates from the Nest JWT and observed pincode trait cache so app_launch name refresh still runs; avoid throttling cache updates when no candidates were available.
