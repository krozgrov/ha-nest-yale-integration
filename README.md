# Nest x Yale Intergration for Home Assistant

**Custom Home Assistant integration for Nest x Yale door locks.**  
This integration enables basic monitoring and limited control of Nest x Yale smart locks within Home Assistant.

---

## 🔧 Features

- Real-time Yale lock state via Nest Observe stream
- Manual lock / unlock commands
- Serial number, firmware, and basic diagnostics attributes
- Battery telemetry scaffolding (parity with test harness; values may be absent)

---

## ⚠️ Experimental Plugin

> ⚠️ **Warning: This integration is experimental and not ready for production use.**

This project is an early-stage prototype attempting to reverse engineer the Nest x Yale lock protocol.  
It is based on the amazing reverse engineering work done in the [Homebridge Nest Plugin](https://github.com/chrisjshull/homebridge-nest).

At present, only **three message types** have been decoded—just enough to show basic lock status and telemetry.  
Most functionality, including full control and feedback, is incomplete or non-functional.

---

## 🚫 Do Not Use In Production

- Do **NOT** install this on your production Home Assistant instance.
- Many core features are still under development or unreliable.
- Expect bugs, incomplete features, and breaking changes.

---

## ⚙️ Getting Started (Test / Dev Only)

1. Install the custom component into `<config>/custom_components/nest_yale/`.
2. Restart Home Assistant to load the integration.
3. Start the config flow (Settings → Devices & Services → Add Integration → **Nest Yale**).
4. Provide:
   - **Issue token URL** – the `iframerpc?action=issueToken` URL captured from the Nest web session (same one used by the `yalenestlocktest` script).
   - **Cookies** – the raw cookie header string copied from the browser (e.g. `__Secure-3PSID=…; __Host-3PLSID=…`).
5. Finish the wizard. The integration now reuses the same headers / protobuf payloads as the standalone test client.

> ✅ **API key no longer required:** the auth flow matches the test repo – only issue token + cookies are needed. If you had an older entry with an API key, it is ignored.

After onboarding, verify the lock entity appears and that `lock.lock` / `lock.unlock` service calls succeed. For troubleshooting, compare Home Assistant logs with the `main.py` output in the `yalenestlocktest` repo; both now share the same Observe payload, stream framing, and protobuf decoders.

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
- Enormous thanks to [BarelyFunctionalCode](https://github.com/BarelyFunctionalCode) for the countless hours spent decoding the Nest protobuf streams—this integration simply would not function without that reverse-engineering work.
