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

At present, only **three message types** have been decoded—just enough to show basic lock status, send lock & unlock commands and telemetry.  
Some functionality is incomplete or non-functional.

---

## 🚫 Do Not Use In Production

- Do **NOT** install this on your production Home Assistant instance.
- Many core features are still under development or unreliable.
- Expect bugs, error messages, incomplete features, and breaking changes.

---

## ⚙️ Getting Started (Test / Dev Only)

1. Install the custom component into `<config>/custom_components/nest_yale_lock/`.
2. Restart Home Assistant to load the integration.
3. Start the config flow (Settings → Devices & Services → Add Integration → **Nest Yale**).
4. Provide:
   - **Issue token URL** – the `iframerpc?action=issueToken` URL captured from the Nest web session.
   - **Cookies** – the raw cookie header string copied from the browser (e.g. `__Secure-3PSID=…; __Host-3PLSID=…`).
5. Finish the wizard. The integration now reuses the same headers / protobuf payloads as the standalone test client.

> ✅ **API key no longer required:** the auth flow requires issue token + cookies are needed. If you had an older entry with an API key, it is ignored.

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
