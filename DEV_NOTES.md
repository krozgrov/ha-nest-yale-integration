# Development Notes

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
