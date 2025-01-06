import voluptuous as vol
from homeassistant import config_entries
from homeassistant.const import CONF_NAME

from .const import DOMAIN, CONF_API_KEY, CONF_ISSUE_TOKEN, CONF_COOKIES

# Define the configuration options
CONFIG_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_NAME, default="Nest Yale Lock"): str,
        vol.Required(CONF_ISSUE_TOKEN): str,
        vol.Required(CONF_API_KEY): str,
        vol.Required(CONF_COOKIES): str,
    }
)

class NestYaleConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle the configuration flow for the Nest Yale Lock integration."""

    VERSION = 1

    async def async_step_user(self, user_input=None):
        """Handle the initial step."""
        errors = {}
        if user_input is not None:
            # Validate the user input
            try:
                await self.validate_input(user_input)
            except ValueError as e:
                errors["base"] = str(e)
            else:
                # Save the configuration and create the entry
                return self.async_create_entry(
                    title=user_input[CONF_NAME], data=user_input
                )

        return self.async_show_form(
            step_id="user", data_schema=CONFIG_SCHEMA, errors=errors
        )

    async def validate_input(self, data):
        """Validate the input provided by the user."""
        # Example: Test the API credentials (optional step)
        if not data[CONF_ISSUE_TOKEN] or not data[CONF_API_KEY]:
            raise ValueError("Missing API credentials")

        # Validate cookies format
        if not data[CONF_COOKIES].startswith("__Secure-3PSID"):
            raise ValueError("Invalid cookies")

        # Perform an optional API call here to validate credentials
        return True