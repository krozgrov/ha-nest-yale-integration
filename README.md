# Google Nest x Yale Lock Integration for Home Assistant

**Custom Home Assistant integration for Google Nest x Yale Locks.**  
This integration enables basic monitoring and limited control of Nest x Yale smart locks within Home Assistant.

---

## 🔧 Features

- Real-time Yale lock state via Nest Observe stream
- Manual lock / unlock commands
- Serial number, firmware, and basic diagnostics attributes 

---

## 🚧 Beta Status

> ⚠️ **Heads-up: this integration is in beta and still under active development.**

The core lock and unlock commands are now working, and real-time state updates are generally reliable.  
However, the integration still depends on partially reversed protobuf messages taken from the [Homebridge Nest Plugin](https://github.com/chrisjshull/homebridge-nest), so gaps remain and rough edges are expected.

---

## ⚠️ Known Limitations

- Logs may show `DecodeError in StreamBody: Error parsing message with type 'nest.rpc.StreamBody'` due to incomplete protobuf decoding. This is **harmless** and does not affect functionality.
- Additional message types beyond the basic lock trait are unmapped, limiting advanced diagnostics and telemetry.
- API response formats and authentication flows may change, potentially causing breaking updates.

To suppress error messages, add this to your `configuration.yaml`:

```yaml
logger:
  logs:
    custom_components.nest_yale_lock.protobuf_handler: 
```

---

## ⚙️ Getting Started

You can install the **Google Nest x Yale Lock** integration either via **HACS** or by **manual copy**.

---

### 🧩 Option 1 — Install via HACS (Recommended)

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

---

### 📁 Option 2 — Manual Installation

1. Copy the custom component folder into your Home Assistant configuration directory:
2. Restart Home Assistant to load the integration.

---

### ⚙️ Configuration

1. Go to **Settings → Devices & Services → Add Integration → Google Nest x Yale Lock**.
2. Provide:
- **Issue token URL** – the `iframerpc?action=issueToken` URL captured from your Nest web session.
- **Cookies** – the raw cookie header string copied from your browser (e.g.  
  `__Secure-3PSID=…; __Host-3PLSID=…`).
3. Complete the setup wizard.

The integration will automatically reuse the same headers and protobuf payloads as the standalone test client.

---

### ✅ Verify Installation

After onboarding:
- Ensure the lock entity appears under **Devices & Services**.
- Test operation using:
- `lock.lock`
- `lock.unlock`
service calls.

---

## 🔍 Logging

- UI toggle (quick): Settings → Devices & Services → Google Nest x Yale → … → Enable debug logging. This enables DEBUG for this integration and its submodules for about 30 minutes. The manifest lists all module loggers so the toggle covers them automatically.
- configuration.yaml (persistent):

```yaml
logger:
  default: warning
  logs:
    custom_components.nest_yale_lock: debug
    # Optional: narrow or raise specific modules
    # custom_components.nest_yale_lock.api_client: debug
    # custom_components.nest_yale_lock.connection: debug
    # custom_components.nest_yale_lock.protobuf_handler: debug
```
---

## 🧠 Community Help Needed

This project is open to contributions from the community.  
If you have experience with:

- Protocol Buffers (Protobuf)

Your input would be incredibly valuable!

You can contribute by:

- Submitting pull requests
- Opening issues with logs or analysis
- Reverse engineering additional messages and formats

---

## 📄 License

This project is licensed under the MIT License.

---

## 🙌 Acknowledgements

- Thanks to [@chrisjshull](https://github.com/chrisjshull) and contributors of the [Homebridge Nest Plugin](https://github.com/chrisjshull/homebridge-nest) for foundational protocol insights.
- Thanks to [BarelyFunctionalCode](https://github.com/BarelyFunctionalCode) for his time spent decoding the Nest protobuf streams—this integration would not function without that reverse-engineering work.
