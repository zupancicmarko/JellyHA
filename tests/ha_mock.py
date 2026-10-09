"""Shared Home Assistant mock environment for standalone unit testing."""
import sys
import types
from unittest.mock import MagicMock

class AutoMockModule(types.ModuleType):
    def __init__(self, name):
        super().__init__(name)
        self.__path__ = []

    def __getattr__(self, name):
        val = MagicMock()
        setattr(self, name, val)
        return val

HA_MODULES = [
    "homeassistant",
    "homeassistant.config_entries",
    "homeassistant.const",
    "homeassistant.core",
    "homeassistant.exceptions",
    "homeassistant.helpers",
    "homeassistant.helpers.aiohttp_client",
    "homeassistant.helpers.update_coordinator",
    "homeassistant.helpers.event",
    "homeassistant.helpers.issue_registry",
    "homeassistant.helpers.device_registry",
    "homeassistant.helpers.storage",
    "homeassistant.helpers.config_validation",
    "homeassistant.helpers.dispatcher",
    "homeassistant.helpers.network",
    "homeassistant.loader",
    "homeassistant.util",
    "homeassistant.components",
    "homeassistant.components.diagnostics",
    "homeassistant.components.http",
    "homeassistant.components.http.auth",
    "homeassistant.components.frontend",
    "homeassistant.data_entry_flow",
    "homeassistant.helpers.selector",
    "homeassistant.components.media_player",
    "homeassistant.components.media_player.const",
    "homeassistant.components.websocket_api",
]

for mod_name in HA_MODULES:
    if mod_name not in sys.modules:
        sys.modules[mod_name] = AutoMockModule(mod_name)

# Link parent-child attributes
for mod_name in list(sys.modules.keys()):
    if mod_name.startswith("homeassistant."):
        parts = mod_name.split(".")
        parent = ".".join(parts[:-1])
        if parent in sys.modules:
            setattr(sys.modules[parent], parts[-1], sys.modules[mod_name])

class MockHomeAssistantView:
    requires_auth = False

sys.modules["homeassistant.components.http"].HomeAssistantView = MockHomeAssistantView

class MockConfigFlow:
    def __init_subclass__(cls, domain=None, **kwargs):
        super().__init_subclass__(**kwargs)
        cls.domain = domain

    def __init__(self):
        self.hass = None
        self.context = {}

    def async_show_form(self, step_id=None, data_schema=None, errors=None, description_placeholders=None):
        return {
            "type": "form",
            "step_id": step_id,
            "data_schema": data_schema,
            "errors": errors or {},
            "description_placeholders": description_placeholders,
        }

    def async_create_entry(self, title="", data=None, options=None):
        return {
            "type": "create_entry",
            "title": title,
            "data": data or {},
            "options": options or {},
        }

sys.modules["homeassistant.config_entries"].ConfigFlow = MockConfigFlow
sys.modules["homeassistant.config_entries"].SOURCE_REAUTH = "reauth"
sys.modules["homeassistant.config_entries"].SOURCE_USER = "user"

class MockDataUpdateCoordinator:
    def __init__(self, hass, logger=None, name=None, update_interval=None, **kwargs):
        self.hass = hass
        self.data = None

    def __class_getitem__(cls, item):
        return cls

sys.modules["homeassistant.helpers.update_coordinator"].DataUpdateCoordinator = MockDataUpdateCoordinator

auth_mod = sys.modules["homeassistant.components.http.auth"]
auth_mod.async_sign_path = lambda hass, path, expiration=None: f"{path}{'&' if '?' in path else '?'}authSig=mock_sig"

ws_mod = sys.modules["homeassistant.components.websocket_api"]
ws_mod.async_response = lambda func: func
ws_mod.websocket_command = lambda schema: lambda func: func
ws_mod.ERR_NOT_FOUND = "not_found"
ws_mod.ERR_INVALID_FORMAT = "invalid_format"
ws_mod.ERR_UNKNOWN_ERROR = "unknown_error"
