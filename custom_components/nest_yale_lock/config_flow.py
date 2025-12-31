import logging
import voluptuous as vol
from homeassistant import config_entries
from homeassistant.core import callback
from .api_client import NestAPIClient
from .const import (
    DOMAIN,
    CONF_ISSUE_TOKEN,
    CONF_COOKIES,
    CONF_DEBUG_ATTRIBUTES,
    CONF_STALE_STATE_MAX_SECONDS,
    DEFAULT_DEBUG_ATTRIBUTES,
    DEFAULT_STALE_STATE_MAX_SECONDS,
)

_LOGGER = logging.getLogger(__name__)

class NestYaleConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Nest Yale integration."""

    VERSION = 1

    @staticmethod
    @callback
    def async_get_options_flow(config_entry):
        """Return the options flow handler."""
        return NestYaleOptionsFlow(config_entry)

    async def async_step_user(self, user_input=None):
        """Handle the initial step."""
        errors = {}

        # Enforce single instance of this integration
        if self._async_current_entries():
            return self.async_abort(reason="single_instance_allowed")

        if user_input is not None:
            try:
                # Validate credentials asynchronously
                await self._validate_credentials(user_input)

                return self.async_create_entry(title="Nest Yale", data=user_input)

            except ValueError as e:
                _LOGGER.error(f"Invalid credentials: {e}")
                errors["base"] = "auth_failure"
            except Exception as e:
                _LOGGER.error(f"Unexpected config flow error: {e}")
                errors["base"] = "unknown_error"

        return self.async_show_form(
            step_id="user",
            data_schema=self._get_schema(),
            errors=errors
        )

    async def async_step_reauth(self, user_input=None):
        """Handle re-authentication when credentials expire."""
        errors = {}
        entry_id = self.context.get("entry_id")
        reauth_entry = self.hass.config_entries.async_get_entry(entry_id) if entry_id else None
        if not reauth_entry:
            _LOGGER.error("Reauth requested but no entry found (entry_id=%s)", entry_id)
            return self.async_abort(reason="unknown_error")

        if user_input is not None:
            try:
                await self._validate_credentials(user_input)
                self.hass.config_entries.async_update_entry(
                    reauth_entry,
                    data={**reauth_entry.data, **user_input},
                )
                await self.hass.config_entries.async_reload(reauth_entry.entry_id)
                return self.async_abort(reason="reauth_successful")
            except ValueError as err:
                _LOGGER.error("Invalid credentials during reauth: %s", err)
                errors["base"] = "auth_failure"
            except Exception as err:
                _LOGGER.error("Unexpected reauth error: %s", err)
                errors["base"] = "unknown_error"

        return self.async_show_form(
            step_id="reauth",
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
            # Keep validation fast: authenticate should only verify credentials and obtain a token.
            # Device discovery happens later via the coordinator's Observe stream.
            await api_client.authenticate()
        finally:
            await api_client.close()  # Ensure session is properly closed

    @staticmethod
    @callback
    def _get_schema():
        """Return the data schema for the config flow form."""
        return vol.Schema(
            {
                vol.Required(CONF_ISSUE_TOKEN): str,
                vol.Required(CONF_COOKIES): str,
            }
        )


class NestYaleOptionsFlow(config_entries.OptionsFlow):
    """Handle options for the Nest Yale integration."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        """Initialize options flow."""
        self._config_entry = config_entry

    async def async_step_init(self, user_input=None):
        """Manage the options flow."""
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        options = self._config_entry.options
        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Optional(
                        CONF_DEBUG_ATTRIBUTES,
                        default=options.get(CONF_DEBUG_ATTRIBUTES, DEFAULT_DEBUG_ATTRIBUTES),
                    ): bool,
                    vol.Optional(
                        CONF_STALE_STATE_MAX_SECONDS,
                        default=options.get(
                            CONF_STALE_STATE_MAX_SECONDS, DEFAULT_STALE_STATE_MAX_SECONDS
                        ),
                    ): vol.All(vol.Coerce(int), vol.Range(min=60, max=86400)),
                }
            ),
        )
