# Decision Log

Purpose
- Canonical decision-rationale file for this repository.
- Captures design intent and behavior decisions for continuity across refactors and releases.

## Structured Decisions

### 2026-02-16: Improve passcode service UX for Home Assistant UI mode
Why
- Passcode services required explicit `guest_user_id`, which is difficult to discover and use in HA action UI mode.
- Users need a practical workflow to update existing guest passcodes without manually hunting resource IDs each time.

Decision
- Allow passcode services to accept either `guest_user_id` or `slot`.
- Resolve `guest_user_id` automatically from current lock slot mappings when `slot` is provided.
- Expose non-sensitive slot/user metadata (`guest_user_ids`, `guest_users`) on lock attributes for in-UI discovery.
- Keep guest identity creation out-of-scope for now; new identities are still created in the Nest app.

Impact
- Backward-compatible service enhancement.
- Improves automation UI workflow and reduces manual ID entry errors.

Validation
- `python -m compileall custom_components/nest_yale_lock`
- Manual HA validation:
  - set/delete passcode by `guest_user_id`
  - set/delete passcode by `slot`
  - verify `guest_user_ids` and `guest_users` appear on lock attributes.

### 2026-02-16: Resolve door names from fixture IDs on located-only stream updates
Why
- Door changes in the Nest app were not propagating reliably when observe updates only carried `DeviceLocatedSettingsTrait`.
- In these deltas, embedded `fixture_label` text could remain stale (`Front door`) while the fixture annotation ID changed.

Decision
- Persist located annotation catalogs in parser memory across stream frames.
- Resolve `door_label` from fixture annotation IDs first, then fall back to embedded fixture label text only when ID lookup is unavailable.
- Normalize known flagged fixture-ID variants (including the `0x01008000` preset bucket) to canonical annotation IDs before lookup.
- Normalize resolved door labels to `... door` formatting for HA display consistency.

Impact
- Non-breaking behavior fix with user-visible naming updates.
- `door_label` and lock `name` should now follow app-side Door selection more consistently during incremental updates.

Validation
- `python -m compileall custom_components/nest_yale_lock`
- Manual HA verification via observer logs and entity/device name updates after changing Door selections in the Nest app.

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

### 2026-02-14: Align lock naming schema with reference behavior
Why
- Users requested behavior parity with the reference naming behavior.
- Previous composed naming (`door_label (label_name)`) and add-time placement seeding diverged from that schema.

Decision
- Use `LabelSettingsTrait` as the canonical lock base name (`name`), with fallback `Lock` when label is missing.
- Keep location (`where_label`) separate from the base lock name.
- Compose Home Assistant device display name as `<where_label> <name>` when location is available.
- Remove add-time seeding that forced initial lock `name` from `where_label`.

Impact
- Non-breaking behavior change to lock naming format.
- Device names now match reference semantics (location prefix + label-based lock name), rather than door/label composition.

Validation
- Manual HA verification after observer updates and integration reload:
  - `name` tracks label-first lock naming.
  - `where_label` remains placement/location.
  - Device name in registry reflects `<where_label> <name>` when location is known.

### 2026-02-15: Make `door_label` the canonical HA lock name
Why
- User requirement changed: the lock entry in HA must reflect Nest app door selection (`door_label`) directly.
- Placement (`where_label`) should remain location metadata only, and app label (`label_name`) should not drive HA lock naming.

Decision
- Compose lock `name` as `door_label` first, then `label_name` fallback, then `Lock`.
- Stop composing HA device/entry name as `<where_label> <name>`; use lock-facing name only.
- Keep `where_label` as placement metadata and expose app label as `label_name` attribute.

Impact
- Non-breaking behavior change to naming.
- Existing entities keep stable IDs; displayed lock name now follows door selection from Nest app.

Validation
- Manual HA verification:
  - lock name resolves to `door_label` (example: `Front door`)
  - `where_label` reflects placement (example: `Basement`)
  - `label_name` remains attribute-only (example: `Test1`)

### 2026-02-15: Re-align naming with reference semantics
Why
- Device naming still appeared inconsistent for some accounts after `door_label`-first behavior.
- User requested strict alignment with the reference naming behavior to reduce custom mapping drift.

Decision
- Revert lock naming to `LabelSettingsTrait`-first (`name`), fallback `Lock`.
- Keep location in `where_label` and compose HA display name as `<where_label> <name>`.
- Retain `door_label`/`label_name` as attributes for diagnostics/context, not canonical name composition.
- Keep parser robustness improvements so located-only updates and cross-device catalog overwrites are handled more safely.

Impact
- Non-breaking behavior change (display naming only).
- HA naming now follows the reference schema consistently.

Validation
- Manual HA verification:
  - `name` follows `LabelSettingsTrait` value (`Test1`)
  - HA display/device name resolves to `<where_label> <name>` when location is present
  - `door_label` remains an attribute and does not override canonical naming

### 2026-02-15: Finalize lock mapping as Door->Name, Where->Area, Label->Attribute
Why
- User requirement changed to prioritize direct app semantics:
  - Door selection should be the HA lock/device name.
  - Where selection should drive HA area placement.
  - Label should be retained for context as an attribute only.

Decision
- Compose canonical lock `name` from `door_label` first (with `label_name` fallback only when door is unavailable).
- Do not prefix display names with location.
- Keep `where_label` in entity attributes and sync it into Home Assistant device area.
- Keep `label_name` as an attribute and do not use it as the primary display name when door is present.

Impact
- Non-breaking behavior change to name/area mapping.
- Existing entity IDs remain stable; lock/device display names and area placement now follow app Door/Where semantics.

Validation
- Manual HA verification:
  - lock/device name matches app Door value
  - device area matches app Where value
  - `label_name` is visible in attributes

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
- 2025-12-31: Revert auto-lock updates to legacy-only BoltLockSettingsTrait (no enhanced trait, no field mask, no extra headers) to match the reference legacy behavior and avoid INTERNAL errors.
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
- 2026-02-14: For `DeviceLocatedSettingsTrait`, prefer label-bearing payload bytes from the best state rank (confirmed over accepted) so stale accepted snapshots do not pin `door_label` to old values after Nest app door changes.
- 2026-02-14: Preserve literal trait-provided `fixture_label` as primary `door_label`, and only use annotation-id lookup as fallback (with fixture-map lookup last) to avoid stale/custom mapping precedence over current app values.
- 2026-02-14: Treat partial varints in observe stream framing as normal chunk-boundary behavior and stop logging them per-chunk at DEBUG to reduce noise; keep only true varint errors.
- 2026-02-15: Allow post-pass annotation-ID resolution to overwrite stale early `where_label`/`door_label` values when annotation catalogs arrive later in the same observe batch, preventing lock labels from sticking to another device's earlier location text.
