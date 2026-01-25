"""Config flow for JellyHA integration."""
from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.core import callback
from homeassistant.data_entry_flow import FlowResult
from homeassistant.helpers import selector
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import (
    JellyfinApiClient,
    JellyfinApiError,
    JellyfinAuthError,
    JellyfinConnectionError,
)
from .const import (
    CONF_API_KEY,
    CONF_AUTH_METHOD,
    CONF_DEVICE_NAME,
    CONF_LIBRARIES,
    CONF_PASSWORD,
    CONF_REFRESH_INTERVAL,
    CONF_SERVER_URL,
    CONF_USER_ID,
    CONF_USERNAME,
    DEFAULT_DEVICE_NAME,
    DEFAULT_REFRESH_INTERVAL,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)


class JellyHAConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for JellyHA."""

    VERSION = 1

    def __init__(self) -> None:
        """Initialize the config flow."""
        """Initialize the config flow."""
        self._server_url: str | None = None
        self._api_key: str | None = None
        self._username: str | None = None
        self._password: str | None = None
        self._users: list[dict[str, Any]] = []
        self._user_id: str | None = None
        self._libraries: list[dict[str, Any]] = []
        self._api: JellyfinApiClient | None = None

    async def async_step_reauth(
        self, entry_data: dict[str, Any]
    ) -> FlowResult:
        """Handle re-authentication with Jellyfin."""
        self._server_url = entry_data[CONF_SERVER_URL]
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Confirm re-authentication."""
        errors: dict[str, str] = {}

        if user_input is not None:
            self._server_url = user_input[CONF_SERVER_URL].rstrip("/")
            auth_method = user_input[CONF_AUTH_METHOD]

            if auth_method == "API Key":
                return await self.async_step_auth_api_key()
            return await self.async_step_auth_login()

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_SERVER_URL, default=self._server_url
                    ): str,
                    vol.Required(CONF_AUTH_METHOD, default="API Key"): selector.SelectSelector(
                        selector.SelectSelectorConfig(
                            options=["API Key", "Username/Password"],
                            mode=selector.SelectSelectorMode.DROPDOWN,
                        )
                    ),
                }
            ),
            errors=errors,
        )

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the initial step - server URL and auth method."""
        errors: dict[str, str] = {}

        if self._async_current_entries():
            return self.async_abort(reason="single_instance_allowed")

        if user_input is not None:
            self._server_url = user_input[CONF_SERVER_URL].rstrip("/")
            auth_method = user_input[CONF_AUTH_METHOD]

            if auth_method == "API Key":
                return await self.async_step_auth_api_key()
            return await self.async_step_auth_login()

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_SERVER_URL): str,
                    vol.Required(CONF_AUTH_METHOD, default="API Key"): selector.SelectSelector(
                        selector.SelectSelectorConfig(
                            options=["API Key", "Username/Password"],
                            mode=selector.SelectSelectorMode.DROPDOWN,
                        )
                    ),
                }
            ),
            errors=errors,
        )

    async def async_step_auth_api_key(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle API Key authentication."""
        errors: dict[str, str] = {}

        if user_input is not None:
            self._api_key = user_input[CONF_API_KEY]
            session = async_get_clientsession(self.hass)
            self._api = JellyfinApiClient(self._server_url, self._api_key, session)

            try:
                await self._api.validate_connection()
                
                # Check if this is a reauth flow
                if self.context.get("source") == config_entries.SOURCE_REAUTH:
                     return await self._async_update_existing_entry()
                     
                self._users = await self._api.get_users()
                return await self.async_step_user_select()
            except JellyfinAuthError:
                errors["base"] = "invalid_auth"
            except JellyfinConnectionError:
                errors["base"] = "cannot_connect"
            except JellyfinApiError:
                errors["base"] = "unknown"

        return self.async_show_form(
            step_id="auth_api_key",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_API_KEY): str,
                }
            ),
            errors=errors,
        )

    async def async_step_auth_login(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle Username/Password authentication."""
        errors: dict[str, str] = {}

        if user_input is not None:
            self._username = user_input[CONF_USERNAME]
            self._password = user_input[CONF_PASSWORD]
            
            session = async_get_clientsession(self.hass)
            # Initialize without API key first
            self._api = JellyfinApiClient(self._server_url, session=session)

            try:
                auth_data = await self._api.authenticate(self._username, self._password)
                self._api_key = auth_data.get("AccessToken")
                # User ID might be returned in auth data, but we still fetch users list for selection consistency
                # or we could skip specific user selection if we want to bind to the logged-in user.
                # For now, let's keep the user selection step to allow picking specific managed users if admin,
                # or just to verify we can list users.
                
                # Fetch users to proceed to selection
                self._users = await self._api.get_users()
                
                # OPTIONAL: If we want to auto-select the logged-in user:
                # logged_in_id = auth_data.get("User", {}).get("Id")
                # if logged_in_id:
                #     self._user_id = logged_in_id
                #     self._libraries = await self._api.get_libraries(self._user_id)
                #     return await self.async_step_library_select()
                
                # Check if this is a reauth flow
                if self.context.get("source") == config_entries.SOURCE_REAUTH:
                     return await self._async_update_existing_entry()

                return await self.async_step_user_select()
                
            except JellyfinAuthError:
                errors["base"] = "invalid_auth"
            except JellyfinConnectionError:
                errors["base"] = "cannot_connect"
            except JellyfinApiError:
                errors["base"] = "unknown"

        return self.async_show_form(
            step_id="auth_login",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_USERNAME): str,
                    vol.Required(CONF_PASSWORD): str,
                }
            ),
            errors=errors,
        )

    async def async_step_user_select(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle user selection step."""
        errors: dict[str, str] = {}

        if user_input is not None:
            self._user_id = user_input[CONF_USER_ID]
            try:
                self._libraries = await self._api.get_libraries(self._user_id)
                return await self.async_step_library_select()
            except JellyfinApiError:
                errors["base"] = "unknown"

        user_options = {user["Id"]: user["Name"] for user in self._users}

        return self.async_show_form(
            step_id="user_select",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_USER_ID): selector.SelectSelector(
                        selector.SelectSelectorConfig(
                            options=[
                                selector.SelectOptionDict(value=uid, label=name)
                                for uid, name in user_options.items()
                            ],
                            mode=selector.SelectSelectorMode.DROPDOWN,
                        )
                    ),
                }
            ),
            errors=errors,
        )

    async def async_step_library_select(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle library selection step."""
        if user_input is not None:
            # Get user name for title
            user_name = next(
                (u["Name"] for u in self._users if u["Id"] == self._user_id),
                "Jellyfin",
            )

            return self.async_create_entry(
                title=f"JellyHA ({user_name})",
                data={
                    CONF_SERVER_URL: self._server_url,
                    CONF_API_KEY: self._api_key,
                    CONF_USER_ID: self._user_id,
                    CONF_LIBRARIES: user_input.get(CONF_LIBRARIES, []),
                    CONF_DEVICE_NAME: DEFAULT_DEVICE_NAME,
                },
                options={
                    CONF_REFRESH_INTERVAL: user_input.get(CONF_REFRESH_INTERVAL, DEFAULT_REFRESH_INTERVAL),
                },
            )

        # Filter to only show movie/series libraries
        library_options = [
            selector.SelectOptionDict(value=lib["Id"], label=lib["Name"])
            for lib in self._libraries
            if lib.get("CollectionType") in ("movies", "tvshows", None)
        ]

        return self.async_show_form(
            step_id="library_select",
            data_schema=vol.Schema(
                {
                    vol.Optional(CONF_LIBRARIES): selector.SelectSelector(
                        selector.SelectSelectorConfig(
                            options=library_options,
                            mode=selector.SelectSelectorMode.DROPDOWN,
                            multiple=True,
                        )
                    ),
                    vol.Optional(
                        CONF_REFRESH_INTERVAL,
                        default=DEFAULT_REFRESH_INTERVAL,
                    ): selector.NumberSelector(
                        selector.NumberSelectorConfig(
                            min=60,
                            max=3600,
                            step=60,
                            unit_of_measurement="seconds",
                            mode=selector.NumberSelectorMode.SLIDER,
                        )
                    ),
                }
            ),
            description_placeholders={
                "hint": "Leave libraries empty to include all",
            },
        )
        
    async def _async_update_existing_entry(self) -> FlowResult:
        """Update existing entry with new credentials."""
        entry_id = self.context.get("entry_id")
        if entry_id:
            entry = self.hass.config_entries.async_get_entry(entry_id)
            if entry:
                self.hass.config_entries.async_update_entry(
                    entry,
                    data={
                        **entry.data,
                        CONF_SERVER_URL: self._server_url,
                        CONF_API_KEY: self._api_key,
                    },
                )
                await self.hass.config_entries.async_reload(entry.entry_id)
                return self.async_abort(reason="reauth_successful")
        
        return self.async_abort(reason="reauth_failed")

    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: config_entries.ConfigEntry,
    ) -> config_entries.OptionsFlow:
        """Get the options flow for this handler."""
        return JellyHAOptionsFlowHandler(config_entry)


class JellyHAOptionsFlowHandler(config_entries.OptionsFlow):
    """Handle options flow for JellyHA."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        """Initialize options flow."""
        self._config_entry = config_entry
        self._server_url = config_entry.data.get(CONF_SERVER_URL)
        self._api_key = config_entry.data.get(CONF_API_KEY)
        self._username: str | None = None
        self._password: str | None = None

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Manage the options."""
        if user_input is not None:
            # Update generic options
            new_data = dict(self._config_entry.data)
            new_options = dict(self._config_entry.options)
            
            # Update Server URL if changed
            if CONF_SERVER_URL in user_input:
                self._server_url = user_input[CONF_SERVER_URL]
                new_data[CONF_SERVER_URL] = self._server_url
            
            if CONF_REFRESH_INTERVAL in user_input:
                new_options[CONF_REFRESH_INTERVAL] = user_input[CONF_REFRESH_INTERVAL]

            # Update the entry with these preliminary changes
            self.hass.config_entries.async_update_entry(
                self._config_entry,
                data=new_data,
                options=new_options
            )

            # Check if user wants to update credentials
            if user_input.get("update_credentials"):
                return await self.async_step_auth_method()
            
                return self.async_abort(reason="configuration_saved")

        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_SERVER_URL,
                        default=self._config_entry.data.get(CONF_SERVER_URL, ""),
                    ): selector.TextSelector(
                        selector.TextSelectorConfig(
                            type=selector.TextSelectorType.URL,
                        )
                    ),
                    vol.Optional(
                        CONF_REFRESH_INTERVAL,
                        default=self._config_entry.options.get(
                            CONF_REFRESH_INTERVAL, DEFAULT_REFRESH_INTERVAL
                        ),
                    ): selector.NumberSelector(
                        selector.NumberSelectorConfig(
                            min=60,
                            max=3600,
                            step=60,
                            unit_of_measurement="seconds",
                            mode=selector.NumberSelectorMode.SLIDER,
                        )
                    ),
                    vol.Optional("update_credentials", default=False): selector.BooleanSelector(),
                }
            ),
        )

    async def async_step_auth_method(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Step to select authentication method."""
        if user_input is not None:
            auth_method = user_input[CONF_AUTH_METHOD]
            if auth_method == "API Key":
                return await self.async_step_auth_api_key()
            return await self.async_step_auth_login()

        return self.async_show_form(
            step_id="auth_method",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_AUTH_METHOD, default="Username/Password"): selector.SelectSelector(
                        selector.SelectSelectorConfig(
                            options=["API Key", "Username/Password"],
                            mode=selector.SelectSelectorMode.DROPDOWN,
                        )
                    ),
                }
            ),
        )

    async def async_step_auth_api_key(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle API Key update."""
        errors: dict[str, str] = {}
        if user_input is not None:
             # Validate
             api = JellyfinApiClient(self._server_url, user_input[CONF_API_KEY], async_get_clientsession(self.hass))
             try:
                 await api.validate_connection()
                 # Verify auth works by fetching users
                 await api.get_users()
                 
                 # Success - update entry
                 new_data = dict(self._config_entry.data)
                 new_data[CONF_API_KEY] = user_input[CONF_API_KEY]
                 
                 self.hass.config_entries.async_update_entry(self._config_entry, data=new_data)
                 # Reload to apply changes
                 await self.hass.config_entries.async_reload(self._config_entry.entry_id)
                 return self.async_abort(reason="configuration_saved")
                 
             except (JellyfinAuthError, JellyfinConnectionError):
                 errors["base"] = "invalid_auth"

        return self.async_show_form(
            step_id="auth_api_key",
            data_schema=vol.Schema({vol.Required(CONF_API_KEY): str}),
            errors=errors
        )

    async def async_step_auth_login(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle Username/Password update."""
        errors: dict[str, str] = {}
        if user_input is not None:
             session = async_get_clientsession(self.hass)
             api = JellyfinApiClient(self._server_url, session=session)
             try:
                 auth_data = await api.authenticate(user_input[CONF_USERNAME], user_input[CONF_PASSWORD])
                 new_token = auth_data.get("AccessToken")
                 
                 # Success - update entry
                 new_data = dict(self._config_entry.data)
                 new_data[CONF_API_KEY] = new_token
                 
                 self.hass.config_entries.async_update_entry(self._config_entry, data=new_data)
                 # Reload to apply changes
                 await self.hass.config_entries.async_reload(self._config_entry.entry_id)
                 return self.async_abort(reason="configuration_saved")
                 
             except (JellyfinAuthError, JellyfinConnectionError):
                 errors["base"] = "invalid_auth"

        return self.async_show_form(
            step_id="auth_login",
            data_schema=vol.Schema({
                vol.Required(CONF_USERNAME): str,
                vol.Required(CONF_PASSWORD): str
            }),
            errors=errors
        )
