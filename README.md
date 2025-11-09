# Google Nest x Yale Lock Integration for Home Assistant

An integration for Home Assistant that connects your Google Nest x Yale Lock, enabling control directly from Home Assistant using reversed-enginered protobuf messaging protocol.

## Features

- Real-time Yale lock state via Nest Observe stream
- Manual lock / unlock commands
- Battery level sensor entity with percentage display
- Serial number, firmware, and device information in Device Info card
- Comprehensive device attributes (battery status, device ID, structure ID, etc.) 

## Status

The integration is now stable and production-ready. Core lock and unlock commands work reliably, and real-time state updates are handled via a persistent observe stream with automatic reconnection and authentication renewal.

> **Note**: This integration depends on reverse-engineered protobuf messages from the [Homebridge Nest Plugin](https://github.com/chrisjshull/homebridge-nest). While the core functionality is stable, some advanced features may be limited due to incomplete protobuf message mappings.


## Known Limitations

- Logs may show `DecodeError in StreamBody: Error parsing message with type 'nest.rpc.StreamBody'` due to incomplete protobuf decoding. This is **harmless** and does not affect functionality.
- Additional message types beyond the basic lock trait are unmapped, limiting advanced diagnostics and telemetry.
- API response formats and authentication flows may change, potentially causing breaking updates.

## Features

- **Long-running observe stream**: Maintains a persistent connection to the Nest API for real-time updates
- **Automatic reconnection**: Connection failures are automatically detected and the stream reconnects with exponential backoff
- **Automatic authentication renewal**: JWT tokens are automatically refreshed when they expire, eliminating the need for manual reloads
- **Push-based updates**: State changes are pushed in real-time via the observe stream instead of polling
- **Robust error handling**: Comprehensive error recovery and connection health monitoring


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
- Thanks to [BarelyFunctionalCode](https://github.com/BarelyFunctionalCode) for his time spent decoding the Nest protobuf streams—this integration would not function without that reverse-engineering work.
