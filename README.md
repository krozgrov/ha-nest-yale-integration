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

Pre-release testing: `2026.02.21b15` broadens `ApplicationKeysTrait` source collection (including non-lock device sources) and merges all per-resource key entries before passcode validation, while suppressing excessive validation-mismatch debug spam.

## Release 2026.02.16 - Door/Where/Label mapping stabilization (latest stable)

- Door selection in the Nest app now drives the HA lock entry name
- Where selection in the Nest app now drives the HA area assignment
- Label selection remains exposed as an entity attribute (`label_name`)
- Door/Where/Label changes now auto-update in Home Assistant when edited in the Nest app
- Fixed stale door labels on located-only stream updates by resolving fixture annotation IDs first

## Maintainer Prerelease Workflow (HACS Description Required)

To prevent empty/missing HACS release descriptions, use the release helper script:

1. Copy the template:
   - `cp release-notes/TEMPLATE.md release-notes/<tag>.md`
2. Edit `release-notes/<tag>.md`:
   - The first non-empty line must be a plain one-line summary. This is the HACS-visible description.
3. Update the integration version in:
   - `custom_components/nest_yale_lock/manifest.json`
4. Create the prerelease:
   - `scripts/cut_prerelease.sh <tag> release-notes/<tag>.md <target_branch>`
   - The script sets a descriptive release title from the first summary line and enforces release retention.

The script fails if:
- The notes file is missing/empty
- The first line is missing, too short, or a markdown header
- `manifest.json` version does not match the tag

Retention policy enforced by script:
- Keep latest `HA_RETAIN_BETA` pre-releases (default `3`)
- Keep latest `HA_RETAIN_STABLE` stable releases (default `2`)

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

### Using A Google Account (Issue Token + Cookies)

Google Accounts are fully supported and required for newer Nest device setups.

Note:
- Older guides may mention two Google auth methods (refresh token and cookies).
- The refresh token method is no longer reliable due to Google-side changes (October 2022).
- Use the cookies method only.

Equivalent values in other tooling are often shown like:

```json
"platform": "Nest",
"googleAuth": {
  "issueToken": "https://accounts.google.com/o/oauth2/iframerpc?action=issueToken...",
  "cookies": "OCAK=...; SID=...; HSID=...; ...; SIDCC=..."
}
```

In this Home Assistant integration, paste these into:
- **Issue token URL**
- **Cookies**

You only need to collect these once, as long as you remain logged in and cookies stay valid.

Important:
- If you experience frequent disconnections after using an Incognito/Private window, try generating the token/cookies from a normal browser window instead.

#### Chrome Steps

1. Open a Chrome tab in Incognito Mode (or clear cache in a normal profile).
2. Open Developer Tools (`View` -> `Developer` -> `Developer Tools`).
3. Open the `Network` tab and enable `Preserve log`.
4. In the Network filter, enter `issueToken`.
5. Go to `home.nest.com`.
6. If prompted, click the eye icon in the address bar and allow third-party cookies for the site.
7. Click `Sign in with Google` and log in.
8. Find the `iframerpc` network request.
9. Open it and copy the full `Request URL` (starts with `https://accounts.google.com...`). This is your **Issue token URL**.
10. Change the filter to `oauth2/iframe`.
11. Open the latest `iframe` request.
12. Under `Request Headers`, copy the full cookie header value (all key/value pairs; do not include the literal `cookie:` header name). This is your **Cookies** value.
13. Do not sign out of `home.nest.com`; just close the tab.

#### Safari Steps

1. Open a Safari Private Browsing tab.
2. Enable Developer tools if needed: `Safari` -> `Settings` -> `Advanced` -> `Show features for web developers`.
3. Open Web Inspector (`Develop` -> `Show JavaScript Console`), then open `Network`.
4. Enable `Preserve Log` (second filter icon near the `All` dropdown).
5. In the filter box, enter `issueToken`.
6. Go to `home.nest.com`, click `Sign in with Google`, and log in.
7. Open the `iframerpc` request and copy the full URL from `Headers` -> `Summary`. This is your **Issue token URL**.
8. Change the filter to `oauth2/iframe`.
9. Open the latest `iframe` request.
10. Under `Headers` -> `Request`, copy the full cookie header value (all key/value pairs; do not include the literal `cookie:` name). This is your **Cookies** value.
11. Do not sign out of `home.nest.com`; just close the tab.

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

- `guest_user_id` (optional): Nest guest/user resource id (for example `USER_123...`)
- `slot` (optional): existing lock slot number to resolve `guest_user_id` automatically
- `passcode` (required for set): numeric code; length is validated against lock capabilities when available
- `device_id` (optional): required when multiple locks are present
- `entry_id` (optional): target a specific config entry

Notes:

- Provide either `guest_user_id` or `slot` for set/delete actions.
- You can discover known guest ids and slot mappings from lock attributes: `guest_user_ids` and `guest_users`.
- The set action now tries both device-level and structure-level user pincode targets before failing.
- The set action auto-attempts encryption key discovery from `ApplicationKeysTrait`. If Nest does not expose usable root key material for your account, set one of these Home Assistant environment variables: `NEST_YALE_CLIENT_ROOT_KEY_HEX` (32-byte hex), `NEST_YALE_FABRIC_SECRET_HEX` (36-byte hex), or `NEST_YALE_SERVICE_ROOT_KEY_HEX` (32-byte hex).
- For safety, unvalidated encryption candidates are blocked by default to avoid silent passcode clears in the Nest app. You can force unvalidated attempts only for debugging by setting `NEST_YALE_ALLOW_UNVALIDATED_PASSCODE_MATERIAL=1`.
- Some lock/account combinations still reject plaintext passcode updates because Nest expects encrypted pincode payloads.
- This integration updates/deletes passcodes for existing Nest guest identities; creating new guest identities still needs to be done in the Nest app.
- Passcode data is never exposed as entity attributes; only non-sensitive capability/slot metadata is stored.

Automation examples (UI action or YAML):

```yaml
action: nest_yale_lock.set_guest_passcode
data:
  device_id: DEVICE_00177A0000060303
  slot: 3
  passcode: "482615"
  enabled: true
```

```yaml
action: nest_yale_lock.delete_guest_passcode
data:
  device_id: DEVICE_00177A0000060303
  slot: 3
```

```yaml
action: nest_yale_lock.set_guest_passcode
data:
  device_id: DEVICE_00177A0000060303
  guest_user_id: USER_015EBA4EB04FAC56
  passcode: "482615"
  enabled: true
```

## License

This project is licensed under the MIT License.

## Acknowledgements

- Thanks to [@chrisjshull](https://github.com/chrisjshull) and contributors of the [Homebridge Nest Plugin](https://github.com/chrisjshull/homebridge-nest) for foundational protocol insights.
- Thanks to [BarelyFunctionalCode](https://github.com/BarelyFunctionalCode) for the time spent decoding the Nest protobuf streams—this integration would not function without that reverse-engineering work.
