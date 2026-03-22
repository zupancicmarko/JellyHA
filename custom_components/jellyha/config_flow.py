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
    CONF_EXTERNAL_URL,
    CONF_INSTANCE_LABEL,
    CONF_USER_ID,
    CONF_USERNAME,
    DEFAULT_DEVICE_NAME,
    DEFAULT_REFRESH_INTERVAL,
    DOMAIN,
    REFRESH_INTERVAL_OPTIONS,
    migrate_refresh_interval,
)

_LOGGER = logging.getLogger(__name__)





async def async_probe_url(hass, url: str) -> str:
    """Probe the URL to determine correct scheme and validity."""
    url = url.strip().rstrip("/")
    urls_to_try = []

    if url.startswith(("http://", "https://")):
        urls_to_try.append(url)
    else:
        urls_to_try.append(f"https://{url}")
        urls_to_try.append(f"http://{url}")

    session = async_get_clientsession(hass)

    for try_url in urls_to_try:
        api = JellyfinApiClient(try_url, session=session)
        try:
            await api.validate_connection()
            return try_url
        except (JellyfinConnectionError, JellyfinApiError):
            continue
    
    raise JellyfinConnectionError("Cannot connect to server")


def _build_device_name(label: str) -> str:
    """Build device name with guaranteed JellyHA prefix."""
    label = label.strip()
    if not label:
        return "JellyHA"
    # Smart dedup: remove leading "JellyHA" if user typed it
    cleaned = label
    if cleaned.lower().startswith("jellyha"):
        cleaned = cleaned[7:].strip()
        # Edge case: user only typed "JellyHA" with nothing after
        if not cleaned:
            return "JellyHA"
    return f"JellyHA {cleaned}"


class JellyHAConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for JellyHA."""

    VERSION = 1

    def __init__(self) -> None:
        """Initialize the config flow."""

        self._server_url: str | None = None
        self._external_url: str | None = None
        self._api_key: str | None = None
        self._username: str | None = None
        self._password: str | None = None
        self._users: list[dict[str, Any]] = []
        self._user_id: str | None = None
        self._libraries: list[dict[str, Any]] = []
        self._api: JellyfinApiClient | None = None
        self._server_id: str | None = None

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
            try:
                self._server_url = await async_probe_url(self.hass, user_input[CONF_SERVER_URL])
                auth_method = user_input[CONF_AUTH_METHOD]

                if auth_method == "API Key":
                    return await self.async_step_auth_api_key()
                return await self.async_step_auth_login()
            except JellyfinConnectionError:
                errors["base"] = "cannot_connect"
            except Exception:  # pylint: disable=broad-except
                _LOGGER.exception("Unexpected exception")
                errors["base"] = "unknown"

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

        if user_input is not None:
            try:
                self._server_url = await async_probe_url(self.hass, user_input[CONF_SERVER_URL])
                self._external_url = user_input.get(CONF_EXTERNAL_URL, "")
                auth_method = user_input[CONF_AUTH_METHOD]

                if auth_method == "API Key":
                    return await self.async_step_auth_api_key()
                return await self.async_step_auth_login()
            except JellyfinConnectionError:
                errors["base"] = "cannot_connect"
            except Exception:  # pylint: disable=broad-except
                _LOGGER.exception("Unexpected exception")
                errors["base"] = "unknown"

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_SERVER_URL): str,
                    vol.Optional(CONF_EXTERNAL_URL, default=""): str,
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
            self._api = JellyfinApiClient(self._server_url, session=session, api_key=self._api_key)

            try:
                server_info = await self._api.validate_connection()
                
                # Store Server ID for later validation
                if unique_id := server_info.get("Id"):
                    self._server_id = unique_id
                
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
                
                # Store Server ID
                if unique_id := auth_data.get("ServerId"):
                     self._server_id = unique_id

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
            except JellyfinApiError as e:
                _LOGGER.error("Jellyfin API error getting libraries: %s", e)
                errors["base"] = "unknown"
            except Exception as e:
                _LOGGER.error("Unexpected error getting libraries: %s", e, exc_info=True)
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

            # Set unique ID using Server ID + User ID + Instance Label
            if self._server_id and self._user_id:
                instance_label = user_input.get(CONF_INSTANCE_LABEL, "").strip()
                unique_id = f"{self._server_id}_{self._user_id}"
                if instance_label:
                    # Only append label if provided, leaving empty legacy unchanged
                    unique_id = f"{unique_id}_{instance_label.lower().replace(' ', '_')}"
                
                await self.async_set_unique_id(unique_id)
                self._abort_if_unique_id_configured()

            # Build the smart device name
            instance_label = user_input.get(CONF_INSTANCE_LABEL, "")
            device_name = _build_device_name(instance_label)

            return self.async_create_entry(
                title=f"{device_name} ({user_name})",
                data={
                    CONF_SERVER_URL: self._server_url,
                    CONF_API_KEY: self._api_key,
                    CONF_USER_ID: self._user_id,
                    CONF_LIBRARIES: user_input.get(CONF_LIBRARIES, []),
                    CONF_DEVICE_NAME: device_name,
                    CONF_INSTANCE_LABEL: instance_label,
                },
                options={
                    CONF_REFRESH_INTERVAL: int(user_input.get(CONF_REFRESH_INTERVAL, DEFAULT_REFRESH_INTERVAL)),
                    CONF_EXTERNAL_URL: self._external_url or "",
                },
            )

        # Filter to only show movie/series/mixed libraries
        library_options = [
            selector.SelectOptionDict(value=lib["Id"], label=lib.get("Name", "Unknown"))
            for lib in self._libraries
            if lib.get("CollectionType") in ("movies", "tvshows", "mixed", "musicvideos", "homevideos", "music", "photos", None)
        ]

        if not library_options:
            library_options = [
                selector.SelectOptionDict(value="none", label="No compatible libraries found")
            ]

        return self.async_show_form(
            step_id="library_select",
            data_schema=vol.Schema(
                {
                    vol.Optional(CONF_INSTANCE_LABEL, default=""): str,
                    vol.Optional(CONF_LIBRARIES): selector.SelectSelector(
                        selector.SelectSelectorConfig(
                            options=library_options,
                            mode=selector.SelectSelectorMode.DROPDOWN,
                            multiple=True,
                        )
                    ),
                    vol.Optional(
                        CONF_REFRESH_INTERVAL,
                        default=str(DEFAULT_REFRESH_INTERVAL),
                    ): selector.SelectSelector(
                        selector.SelectSelectorConfig(
                            options=[
                                selector.SelectOptionDict(value=str(v), label=label)
                                for label, v in REFRESH_INTERVAL_OPTIONS
                            ],
                            mode=selector.SelectSelectorMode.DROPDOWN,
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
        self._users: list[dict[str, Any]] = []
        self._user_id: str | None = None
        self._libraries: list[dict[str, Any]] = []

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Manage the options."""
        errors: dict[str, str] = {}
        
        # Fetch available libraries for the dropdown
        library_options = []
        user_id = self._config_entry.data.get(CONF_USER_ID)
        current_libraries = self._config_entry.data.get(CONF_LIBRARIES, [])
        
        if self._server_url and self._api_key and user_id:
            try:
                session = async_get_clientsession(self.hass)
                api = JellyfinApiClient(self._server_url, session=session, api_key=self._api_key)
                libraries = await api.get_libraries(user_id)
                library_options = [
                    selector.SelectOptionDict(value=lib["Id"], label=lib.get("Name", "Unknown"))
                    for lib in libraries
                    if lib.get("CollectionType") in ("movies", "tvshows", "mixed", "musicvideos", "homevideos", "music", "photos", None)
                ]
            except Exception as err:
                _LOGGER.error("Failed to fetch Jellyfin libraries for Options Flow: %s", err)

        if not library_options:
            library_options = [
                selector.SelectOptionDict(value="none", label="No compatible libraries found")
            ]
        
        if user_input is not None:
            # Update generic options
            new_data = dict(self._config_entry.data)
            new_options = dict(self._config_entry.options)
            
            # Update Server URL if changed
            if CONF_SERVER_URL in user_input:
                try:
                    self._server_url = await async_probe_url(self.hass, user_input[CONF_SERVER_URL])
                    new_data[CONF_SERVER_URL] = self._server_url
                except JellyfinConnectionError:
                    errors["base"] = "cannot_connect"
            
                if CONF_REFRESH_INTERVAL in user_input:
                    new_options[CONF_REFRESH_INTERVAL] = int(user_input[CONF_REFRESH_INTERVAL])

                if CONF_EXTERNAL_URL in user_input:
                    new_options[CONF_EXTERNAL_URL] = user_input[CONF_EXTERNAL_URL]

                if CONF_LIBRARIES in user_input:
                    new_data[CONF_LIBRARIES] = user_input[CONF_LIBRARIES]

                # Update the entry with these preliminary changes
                self.hass.config_entries.async_update_entry(
                    self._config_entry,
                    data=new_data,
                    options=new_options
                )

                # Check if user wants to update credentials
                if user_input.get("update_credentials"):
                    return await self.async_step_auth_method()
                
                # Check if user wants an immediate refresh
                if user_input.get("trigger_library_refresh"):
                    await self.hass.config_entries.async_reload(self._config_entry.entry_id)

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
                        CONF_EXTERNAL_URL,
                        description={"suggested_value": self._config_entry.options.get(CONF_EXTERNAL_URL, "")},
                    ): selector.TextSelector(
                        selector.TextSelectorConfig(
                            type=selector.TextSelectorType.URL,
                        )
                    ),
                    vol.Optional(
                        CONF_LIBRARIES,
                        default=current_libraries,
                    ): selector.SelectSelector(
                        selector.SelectSelectorConfig(
                            options=library_options,
                            multiple=True,
                            mode=selector.SelectSelectorMode.DROPDOWN,
                        )
                    ),
                    vol.Optional(
                        CONF_REFRESH_INTERVAL,
                        default=str(migrate_refresh_interval(
                            int(self._config_entry.options.get(
                                CONF_REFRESH_INTERVAL, DEFAULT_REFRESH_INTERVAL
                            ))
                        ))
                    ): selector.SelectSelector(
                        selector.SelectSelectorConfig(
                            options=[
                                selector.SelectOptionDict(value=str(v), label=label)
                                for label, v in REFRESH_INTERVAL_OPTIONS
                            ],
                            mode=selector.SelectSelectorMode.DROPDOWN,
                        )
                    ),
                    vol.Optional("trigger_library_refresh", default=False): selector.BooleanSelector(),
                    vol.Optional("update_credentials", default=False): selector.BooleanSelector(),
                }
            ),
            errors=errors
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
             api = JellyfinApiClient(
                 self._server_url, 
                 session=async_get_clientsession(self.hass), 
                 api_key=user_input[CONF_API_KEY]
             )
             try:
                 await api.validate_connection()
                 # Verify auth works by fetching users
                 self._api_key = user_input[CONF_API_KEY]
                 self._users = await api.get_users()
                 
                 return await self.async_step_user_select()
                 
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
                 self._api_key = auth_data.get("AccessToken")
                 self._users = await api.get_users()
                 
                 return await self.async_step_user_select()
                 
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

    async def async_step_user_select(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Step to select user."""
        errors: dict[str, str] = {}
        if user_input is not None:
            self._user_id = user_input[CONF_USER_ID]
            
            # Fetch libraries for the new user
            session = async_get_clientsession(self.hass)
            api = JellyfinApiClient(self._server_url, session=session, api_key=self._api_key)
            try:
                self._libraries = await api.get_libraries(self._user_id)
                return await self.async_step_library_select()
            except Exception as err:
                _LOGGER.error("Error fetching libraries: %s", err)
                errors["base"] = "unknown"

        user_options = [
            selector.SelectOptionDict(value=user["Id"], label=user.get("Name", "Unknown"))
            for user in self._users
        ]

        if not user_options:
            errors["base"] = "unknown"

        return self.async_show_form(
            step_id="user_select",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_USER_ID): selector.SelectSelector(
                        selector.SelectSelectorConfig(
                            options=user_options,
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
        """Step to select libraries specific to the user."""
        if user_input is not None:
            new_data = dict(self._config_entry.data)
            new_data[CONF_API_KEY] = self._api_key
            new_data[CONF_USER_ID] = self._user_id
            new_data[CONF_LIBRARIES] = user_input.get(CONF_LIBRARIES, [])
            
            self.hass.config_entries.async_update_entry(self._config_entry, data=new_data)
            await self.hass.config_entries.async_reload(self._config_entry.entry_id)
            return self.async_abort(reason="configuration_saved")

        library_options = [
            selector.SelectOptionDict(value=lib["Id"], label=lib.get("Name", "Unknown"))
            for lib in self._libraries
            if lib.get("CollectionType") in ("movies", "tvshows", "mixed", "musicvideos", "homevideos", "music", "photos", None)
        ]

        if not library_options:
            library_options = [
                selector.SelectOptionDict(value="none", label="No compatible libraries found")
            ]

        return self.async_show_form(
            step_id="library_select",
            data_schema=vol.Schema(
                {
                    vol.Optional(
                        CONF_LIBRARIES,
                        default=[],
                    ): selector.SelectSelector(
                        selector.SelectSelectorConfig(
                            options=library_options,
                            multiple=True,
                            mode=selector.SelectSelectorMode.DROPDOWN,
                        )
                    ),
                }
            )
        )
