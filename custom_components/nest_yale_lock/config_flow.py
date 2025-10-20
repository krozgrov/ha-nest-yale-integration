import logging
import json
import voluptuous as vol
from homeassistant import config_entries
from homeassistant.core import callback
from .api_client import NestAPIClient
from .const import DOMAIN, CONF_ISSUE_TOKEN, CONF_COOKIES

_LOGGER = logging.getLogger(__name__)

class NestYaleConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Nest Yale integration."""

    VERSION = 1

    async def async_step_user(self, user_input=None):
        """Handle the initial step."""
        errors = {}

        # Enforce single instance of this integration
        if self._async_current_entries():
            return self.async_abort(reason="single_instance_allowed")

        if user_input is not None:
            working_input = dict(user_input)
            har_json = working_input.get("har_json")
            if har_json:
                try:
                    issue_token, cookies = self._extract_from_har(har_json)
                    if not issue_token or not cookies:
                        errors["har_json"] = "missing_values"
                    else:
                        working_input[CONF_ISSUE_TOKEN] = issue_token
                        working_input[CONF_COOKIES] = cookies
                        _LOGGER.debug("Extracted credentials from HAR for validation")
                except ValueError:
                    errors["har_json"] = "invalid_har"
                except Exception as e:
                    _LOGGER.error("HAR parse error: %s", e)
                    errors["har_json"] = "invalid_har"

            if not errors and working_input:
                if not working_input.get(CONF_ISSUE_TOKEN) or not working_input.get(CONF_COOKIES):
                    errors["base"] = "auth_failure"
                else:
                    try:
                        await self._validate_credentials(working_input)
                        data = {
                            CONF_ISSUE_TOKEN: working_input[CONF_ISSUE_TOKEN],
                            CONF_COOKIES: working_input[CONF_COOKIES],
                        }
                        return self.async_create_entry(title="Nest Yale", data=data)
                    except ValueError as e:
                        _LOGGER.error("Invalid credentials: %s", e)
                        errors["base"] = "auth_failure"
                    except Exception as e:
                        _LOGGER.error("Unexpected config flow error: %s", e)
                        errors["base"] = "unknown_error"

        return self.async_show_form(
            step_id="user",
            data_schema=self._get_schema(),
            errors=errors,
        )

    async def _validate_credentials(self, user_input):
        """Validate API credentials asynchronously."""
        api_client = NestAPIClient(
            self.hass,
            issue_token=user_input[CONF_ISSUE_TOKEN],
            api_key=None,
            cookies=user_input[CONF_COOKIES]
        )

        try:
            await api_client.authenticate()
        finally:
            await api_client.close()  # Ensure session is properly closed

    @staticmethod
    @callback
    def _get_schema():
        """Return the data schema for the config flow form."""
        return vol.Schema(
            {
                vol.Optional("har_json", default=""): str,
                vol.Optional(CONF_ISSUE_TOKEN, default=""): str,
                vol.Optional(CONF_COOKIES, default=""): str,
            }
        )

    def _extract_from_har(self, har_text: str):
        """Extract issueToken URL and Cookie header from a HAR export."""
        try:
            data = json.loads(har_text)
        except Exception as e:
            raise ValueError("Invalid JSON") from e

        log = data.get("log") or {}
        entries = log.get("entries") or []
        issue_token_url = None
        oauth_cookie = None

        def _headers_to_dict(headers):
            d = {}
            for h in headers or []:
                name = str(h.get("name", ""))
                value = h.get("value")
                if name:
                    d[name.lower()] = value
            return d

        # Find issueToken URL
        for entry in entries:
            req = entry.get("request", {})
            url = req.get("url", "")
            if "iframerpc" in url and "action=issueToken" in url:
                issue_token_url = url
                break

        # Find last oauth2/iframe cookie header
        for entry in entries:
            req = entry.get("request", {})
            url = req.get("url", "")
            if "oauth2/iframe" in url:
                headers = _headers_to_dict(req.get("headers", []))
                cookie_header = headers.get("cookie")
                if cookie_header:
                    oauth_cookie = cookie_header

        return issue_token_url, oauth_cookie
