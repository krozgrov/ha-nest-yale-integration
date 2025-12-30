# Development Notes

- 2025-12-30: Use gRPC v1 SendCommand/BatchUpdateState requests (legacy-style) for lock commands/settings while keeping v2 Observe for state/traits to improve command reliability and retain richer trait updates.
