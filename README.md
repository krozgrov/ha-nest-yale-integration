# Google Nest x Yale Lock Intergration for Home Assistant

**Custom Home Assistant integration for Google Nest x Yale Locks.**  
This integration enables basic monitoring and limited control of Nest x Yale smart locks within Home Assistant.

---

## 🔧 Features

- Real-time Yale lock state via Nest Observe stream
- Manual lock / unlock commands
- Serial number, firmware, and basic diagnostics attributes 
- Battery telemetry scaffolding (parity with test harness; values may be absent)

---

## 🚧 Beta Status

> ⚠️ **Heads-up: this integration is in beta and still under active development.**

The core lock and unlock commands are now working, and real-time state updates are generally reliable.  
However, the integration still depends on partially reversed protobuf messages taken from the [Homebridge Nest Plugin](https://github.com/chrisjshull/homebridge-nest), so gaps remain and rough edges are expected.

---

## ⚠️ Known Limitations

- You will continue to see `DecodeError in StreamBody: Error parsing message with type 'nest.rpc.StreamBody'` in the logs because the full protobuf surface is not decoded yet.
- Additional message types beyond the basic lock trait remain unmapped, so advanced diagnostics and telemetry may be unavailable.
- API response formats and authentication flows can change at any time; expect breaking updates.

---

## ⚙️ Getting Started

1. Install the custom component into `<config>/custom_components/nest_yale_lock/`.
2. Restart Home Assistant to load the integration.
3. Start the config flow (Settings → Devices & Services → Add Integration → **Nest Yale**).
4. Provide:
   - **Issue token URL** – the `iframerpc?action=issueToken` URL captured from the Nest web session.
   - **Cookies** – the raw cookie header string copied from the browser (e.g. `__Secure-3PSID=…; __Host-3PLSID=…`).
5. Finish the wizard. The integration now reuses the same headers / protobuf payloads as the standalone test client.


After onboarding, verify the lock entity appears and that `lock.lock` / `lock.unlock` service calls succeed.

---

---

## 🧠 Community Help Needed

This project is open to contributions from the community.  
If you have experience with:

- Home Assistant custom component development
- Reverse engineering APIs and embedded devices
- Protocol Buffers (Protobuf)
- General debugging of smart home integrations

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
- Thanks to [BarelyFunctionalCode](https://github.com/BarelyFunctionalCode) for his time spent decoding the Nest protobuf streams—this integration  would not function without that reverse-engineering work.
