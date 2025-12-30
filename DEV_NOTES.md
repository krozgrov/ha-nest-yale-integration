# Development Notes

- 2025-12-30: Use gRPC v1 SendCommand/BatchUpdateState requests (legacy-style) for lock commands/settings while keeping v2 Observe for state/traits to improve command reliability and retain richer trait updates.
- 2025-12-30: Removed bolt lock actor originator IDs from command payloads to align with legacy behavior and avoid INTERNAL errors on lock/unlock.
- 2025-12-30: Prefer confirmed v2 trait state for non-lock traits (e.g., auto-relock settings) and suppress transient last_action updates while bolt is moving to avoid "Other" flicker.
- 2025-12-30: Restore protobuf update headers (request-id, structure/user ids) and allow v2 structure_id for auto-relock settings to improve Nest app sync.
- 2025-12-30: Add EnhancedBoltLockSettingsTrait observation and optional update path to better align Auto-Lock changes with Nest app behavior.
- 2025-12-30: Apply nest-trait BoltLockSettingsTrait updates when label is available to mirror nest_legacy behavior and improve Auto-Lock sync.
