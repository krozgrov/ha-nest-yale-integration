[![GitHub release](https://img.shields.io/github/release/krozgrov/ha-nest-yale-integration.svg)](https://github.com/krozgrov/ha-nest-yale-integration/releases)
[![GitHub stars](https://img.shields.io/github/stars/krozgrov/ha-nest-yale-integration.svg)](https://github.com/krozgrov/ha-nest-yale-integration/stargazers)
![GitHub License](https://img.shields.io/github/license/krozgrov/ha-nest-yale-integration)

# Google Nest x Yale Lock Integration for Home Assistant

An integration for Home Assistant that connects your Google Nest x Yale Lock, enabling control directly from Home Assistant using reverse-engineered protobuf messaging.

## Sponsor

A lot of effort is going into this integration. So if you can afford it and want to support me:

<a href="https://www.buymeacoffee.com/krozgrov" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" style="height: 60px !important;width: 217px !important;" ></a>

## Features

- Real-time Yale lock state via Nest Observe stream (with fallback refresh)
- Manual lock / unlock commands
- Battery level sensor with percentage display
- Last action sensor (Physical/Keypad/Remote, etc.)
- Auto-Lock switch and Auto-Lock duration selector
- Tamper binary sensor
- Serial number and firmware shown in the Device Info card
- Options: stale state timeout + masked debug attributes
- Translated entity names (no hardcoded English labels)
- Guest passcode services (`set_guest_passcode`, `delete_guest_passcode`)

## Status

Core lock and unlock commands work reliably, and state updates are handled via an Observe stream with automatic reconnection, fallback refresh, and reauthentication support.

> **Note**: This integration depends on reverse-engineered protobuf messages from the [Homebridge Nest Plugin](https://github.com/chrisjshull/homebridge-nest). While the core functionality is stable, some advanced features may be limited due to incomplete protobuf message mappings.

Latest stable release: `2026.03.28`.

Pre-release testing: `2026.04.04b1` fixes the native Home Assistant Nest import collision caused by vendored `google.rpc` descriptors so HACS beta testers can validate coexistence before the next stable cut.

## Release 2026.03.28 - Area ownership and reliability fixes (latest stable)

- Home Assistant now owns final area placement for Nest Yale devices.
- The integration no longer creates Home Assistant areas or reassigns devices from Nest `where_label`.
- Shared protobuf imports now avoid duplicate descriptor collisions when another custom integration ships the same Nest/Weave schemas.
- Native Nest coexistence with `google.rpc` descriptors is fixed in prerelease `2026.04.04b1`; `2026.03.28` does not include that hotfix.
- Firmware metadata now normalizes additional field aliases so the Home Assistant Device Info card shows the correct firmware version.
- Companion entities now populate faster at startup and avoid lingering temporary unavailable states.

## Current Area Behavior

- Home Assistant owns final area assignment for Nest Yale devices.
- The integration does not create Home Assistant areas or overwrite manual area placement from Nest `where_label`.
- Nest `where_label` remains available in entity attributes so the app-side location is still visible for reference.

## Known Limitations

- Logs may show `DecodeError in StreamBody: Error parsing message with type 'nest.rpc.StreamBody'` due to incomplete protobuf decoding. This is **harmless** and does not affect functionality.
- API response formats and authentication flows may change, potentially causing breaking updates.

## Installation

You can install the **Google Nest x Yale Lock** integration either via **HACS** or by **manual copy**.

### Option 1 — Install via HACS (Recommended)

1. **Add the Custom Repository**
   - In Home Assistant, open **HACS → Integrations → ⋮ (three dots) → Custom Repositories**.
   - Add the repository URL:
     ```
     https://github.com/krozgrov/ha-nest-yale-integration
     ```
   - Select **Integration** as the category and click **Add**.

2. **Install the Integration**
   - Search for **Nest Yale Lock** in HACS and click **Download**.
   - Once installed, restart Home Assistant.

### Option 2 — Manual Installation

1. Copy the custom component folder into your Home Assistant configuration directory:
2. Restart Home Assistant to load the integration.

### Configuration

1. Go to **Settings → Devices & Services → Add Integration → Google Nest x Yale Lock**.
2. Provide:
- **Issue token URL** – the `iframerpc?action=issueToken` URL captured from your Nest web session.
- **Cookies** – the raw cookie header string copied from your browser (e.g.  
  `__Secure-3PSID=…; __Host-3PLSID=…`).
3. Complete the setup wizard.

The integration will automatically reuse the same headers and protobuf payloads as the standalone test client.

### Options (Optional)

After setup, open the integration options to:
- Configure the stale-state timeout (unavailable after inactivity)
- Enable masked debug attributes (diagnostics only)

### Verify Installation

After onboarding:
- Ensure the lock entity appears under **Devices & Services**.
- Test operation using:
- `lock.lock`
- `lock.unlock`
service calls.
 - Verify entities: Battery sensor, Last Action sensor, Tamper binary sensor, Auto-Lock switch, Auto-Lock Duration select.

### Guest Passcode Services

Guest passcode management is available via Home Assistant services:

- `nest_yale_lock.set_guest_passcode`
- `nest_yale_lock.delete_guest_passcode`

Inputs:

- `guest_user_id` (required): Nest guest/user resource id (for example `USER_123...`)
- `passcode` (required for set): numeric code; length is validated against lock capabilities when available
- `device_id` (optional): required when multiple locks are present
- `entry_id` (optional): target a specific config entry

Notes:

- This integration currently requires the guest user id instead of creating guest identities automatically.
- Passcode data is never exposed as entity attributes; only non-sensitive capability/slot metadata is stored.

## Maintainer Prerelease Workflow

1. Copy the release-notes template:
   ```bash
   cp release-notes/TEMPLATE.md release-notes/<tag>.md
   ```
2. Make the first non-empty line in `release-notes/<tag>.md` a plain-text HACS summary.
3. Update `custom_components/nest_yale_lock/manifest.json` so `version` matches `<tag>`.
4. Cut the GitHub prerelease from the release-candidate branch:
   ```bash
   scripts/cut_prerelease.sh <tag> release-notes/<tag>.md <target_branch>
   ```

## License

This project is licensed under the MIT License.

## Acknowledgements

- Thanks to [@chrisjshull](https://github.com/chrisjshull) and contributors of the [Homebridge Nest Plugin](https://github.com/chrisjshull/homebridge-nest) for foundational protocol insights.
- Thanks to [BarelyFunctionalCode](https://github.com/BarelyFunctionalCode) for the time spent decoding the Nest protobuf streams—this integration would not function without that reverse-engineering work.
