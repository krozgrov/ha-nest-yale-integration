[![GitHub release](https://img.shields.io/github/release/krozgrov/ha-nest-yale-integration.svg)](https://github.com/krozgrov/ha-nest-yale-integration/releases)
[![GitHub stars](https://img.shields.io/github/stars/krozgrov/ha-nest-yale-integration.svg)](https://github.com/krozgrov/ha-nest-yale-integration/stargazers)
![GitHub License](https://img.shields.io/github/license/krozgrov/ha-nest-yale-integration)

# Google Nest x Yale Lock Integration for Home Assistant

An integration for Home Assistant that connects your Google Nest x Yale Lock, enabling control directly from Home Assistant using reversed-enginered protobuf messaging protocol.

## Sponsor

A lot of effort is going into this integration. So if you can afford it and want to support me:

<a href="https://www.buymeacoffee.com/krozgrov" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" style="height: 60px !important;width: 217px !important;" ></a>

## Features

- Real-time Yale lock state via Nest Observe stream
- Manual lock / unlock commands
- Battery level sensor entity with percentage display
- Serial number, firmware, and device information in Device Info card
- Device attributes (battery status, device ID, structure ID, etc.) 

## Status

Core lock and unlock commands work reliably, and state updates are handled via a observe stream with automatic reconnection and authentication renewal.

> **Note**: This integration depends on reverse-engineered protobuf messages from the [Homebridge Nest Plugin](https://github.com/chrisjshull/homebridge-nest). While the core functionality is stable, some advanced features may be limited due to incomplete protobuf message mappings.

## Pre-release 2025.11.30b37 - Faster State Clear (beta)

- Reverts the long optimistic timer and clears “locking/unlocking” after ~5s if no observer update arrives, while still clearing immediately when updates come in.
- Keeps early ID capture, instant seed, capped initial refresh (5s), 15-minute sticky availability, streaming timeouts, and partial buffering from prior betas.

> To test via HACS: enable “Show beta versions” for this repository in HACS and select version `2025.11.30b37`.


## Known Limitations

- Logs may show `DecodeError in StreamBody: Error parsing message with type 'nest.rpc.StreamBody'` due to incomplete protobuf decoding. This is **harmless** and does not affect functionality.
- Additional message types beyond the basic lock trait are unmapped, limiting advanced diagnostics and telemetry.
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

### Verify Installation

After onboarding:
- Ensure the lock entity appears under **Devices & Services**.
- Test operation using:
- `lock.lock`
- `lock.unlock`
service calls.

## Community Help Needed

This project is open to contributions from the community.  
If you have experience with:

- Protocol Buffers (Protobuf)

Your input would be incredibly valuable!

You can contribute by:

- Submitting pull requests
- Opening issues with logs or analysis
- Reverse engineering additional messages and formats

## License

This project is licensed under the MIT License.

## Acknowledgements

- Thanks to [@chrisjshull](https://github.com/chrisjshull) and contributors of the [Homebridge Nest Plugin](https://github.com/chrisjshull/homebridge-nest) for foundational protocol insights.
- Thanks to [BarelyFunctionalCode](https://github.com/BarelyFunctionalCode) for the time spent decoding the Nest protobuf streams—this integration would not function without that reverse-engineering work.
