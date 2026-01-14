"""Config flow for JellyHA integration."""
from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.core import callback
from homeassistant.data_entry_flow import FlowResult
from homeassistant.helpers import selector

from .api import (
    JellyfinApiClient,
    JellyfinApiError,
    JellyfinAuthError,
    JellyfinConnectionError,
)
from .const import (
    CONF_API_KEY,
    CONF_ITEM_LIMIT,
    CONF_LIBRARIES,
    CONF_REFRESH_INTERVAL,
    CONF_SERVER_URL,
    CONF_USER_ID,
    DEFAULT_ITEM_LIMIT,
    DEFAULT_REFRESH_INTERVAL,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)


class JellyHAConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for JellyHA."""

    VERSION = 1

    def __init__(self) -> None:
        """Initialize the config flow."""
        self._server_url: str | None = None
        self._api_key: str | None = None
        self._users: list[dict[str, Any]] = []
        self._user_id: str | None = None
        self._libraries: list[dict[str, Any]] = []
        self._api: JellyfinApiClient | None = None

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the initial step - server URL and API key."""
        errors: dict[str, str] = {}

        if user_input is not None:
            self._server_url = user_input[CONF_SERVER_URL].rstrip("/")
            self._api_key = user_input[CONF_API_KEY]

            self._api = JellyfinApiClient(self._server_url, self._api_key)

            try:
                await self._api.validate_connection()
                self._users = await self._api.get_users()
                return await self.async_step_user_select()
            except JellyfinAuthError:
                errors["base"] = "invalid_auth"
            except JellyfinConnectionError:
                errors["base"] = "cannot_connect"
            except JellyfinApiError:
                errors["base"] = "unknown"

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_SERVER_URL): str,
                    vol.Required(CONF_API_KEY): str,
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
                },
                options={
                    CONF_REFRESH_INTERVAL: user_input.get(CONF_REFRESH_INTERVAL, DEFAULT_REFRESH_INTERVAL),
                    CONF_ITEM_LIMIT: user_input.get(CONF_ITEM_LIMIT, DEFAULT_ITEM_LIMIT),
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
                    vol.Optional(
                        CONF_ITEM_LIMIT,
                        default=DEFAULT_ITEM_LIMIT,
                    ): selector.NumberSelector(
                        selector.NumberSelectorConfig(
                            min=5,
                            max=100,
                            step=5,
                            mode=selector.NumberSelectorMode.SLIDER,
                        )
                    ),
                }
            ),
            description_placeholders={
                "hint": "Leave empty to include all libraries",
            },
        )

    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: config_entries.ConfigEntry,
    ) -> config_entries.OptionsFlow:
        """Get the options flow for this handler."""
        return JellyHAOptionsFlowHandler()


class JellyHAOptionsFlowHandler(config_entries.OptionsFlow):
    """Handle options flow for JellyHA."""

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Manage the options."""
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Optional(
                        CONF_REFRESH_INTERVAL,
                        default=self.config_entry.options.get(
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
                    vol.Optional(
                        CONF_ITEM_LIMIT,
                        default=self.config_entry.options.get(
                            CONF_ITEM_LIMIT, DEFAULT_ITEM_LIMIT
                        ),
                    ): selector.NumberSelector(
                        selector.NumberSelectorConfig(
                            min=5,
                            max=100,
                            step=5,
                            mode=selector.NumberSelectorMode.SLIDER,
                        )
                    ),
                }
            ),
        )
