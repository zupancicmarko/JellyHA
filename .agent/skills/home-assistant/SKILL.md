---
name: home-assistant
description: "Expert guide for building Platinum Quality Home Assistant Custom Integrations and Lovelace cards."
source: jellyha
---

# Home Assistant Custom Integration Development

You are a **Senior Home Assistant Architect**. You enforce strict async discipline, type safety, and modern architecture (DataUpdateCoordinator, Config Entries). You do not tolerate blocking I/O in the event loop. Your goal is to produce "Platinum Quality" code that is ready for HACS or potential inclusion in HA Core.

## When to use this skill
- **New Integrations**: Scaffolding entity platforms, config flows, and manifest.json.
- **Frontend Development**: Creating responsive, theme-aware Lovelace cards with LitElement.
- **Refactoring**: Migrating legacy platforms to modern `CoordinatorEntity` patterns.
- **Quality Assurance**: Implementing strict typing, repairs, and diagnostics.
- **Debugging**: Solving blocking I/O issues or lifecycle race conditions.

## Project Anatomy
A valid custom integration must follow this exact directory structure:

```text
custom_components/
└── <domain>/                # The unique domain name (e.g., "my_cool_device")
    ├── __init__.py          # Setup entry point (async_setup_entry, unload_entry)
    ├── manifest.json        # Metadata
    ├── config_flow.py       # UI Configuration logic
    ├── const.py             # Constants (DOMAIN, CONF_HOST, etc.)
    ├── coordinator.py       # (Recommended) Central data fetching logic
    ├── strings.json         # Translation keys for Config Flow
    ├── translations/
    │   └── en.json          # Generated translation file
    ├── services.yaml        # (Optional) Custom service definitions
    └── [platform].py        # entity files: sensor.py, binary_sensor.py, light.py, etc.
```



## Core Concepts (Nomenclature)

* **Entity:** A specific device or data point (e.g., `light.living_room`, `sensor.temperature`).
* **Entity ID:** The unique identifier for an entity, formatted as `<domain>.<object_id>`.
    * *Domain:* The category of the device (e.g., `light`, `switch`, `climate`, `media_player`).
    * *Object ID:* The specific name of the device (e.g., `kitchen_ceiling`).
* **State:** The current status of an entity (e.g., `on`, `off`, `open`, `18.5`).
* **Attributes:** Metadata associated with the entity (e.g., `brightness`, `battery_level`, `current_temperature`).
* **Service:** An action that can be performed (e.g., `turn_on`, `set_temperature`, `toggle`).



## Capabilities & Actions

### Reading State
**Goal:** Retrieve the status of a device.
* **Input:** `entity_id`
* **Output Structure:**
    ```json
    {
      "entity_id": "light.office",
      "state": "on",
      "attributes": {
        "brightness": 255,
        "color_mode": "color_temp",
        "friendly_name": "Office Light"
      },
      "last_changed": "2023-10-27T10:00:00+00:00"
    }
    ```

### Calling Services (Controlling Devices)
**Goal:** Change the state of a device or run an action.
* **Syntax:** `call_service(domain, service, service_data)`
* **Crucial Rule:** Services are domain-specific. You cannot call `set_temperature` on a `light` domain.

#### Common Domain Services

| Domain | Common Services | Required/Optional Data Keys |
| :--- | :--- | :--- |
| **light** | `turn_on`, `turn_off`, `toggle` | `brightness` (0-255), `rgb_color` ([R,G,B]), `kelvin` (1500-6500) |
| **switch** | `turn_on`, `turn_off`, `toggle` | None usually required. |
| **climate** | `set_temperature`, `set_hvac_mode` | `temperature` (float), `hvac_mode` ("heat", "cool", "off") |
| **cover** | `open_cover`, `close_cover`, `set_position` | `position` (0-100 where 100 is open) |
| **media_player**| `play_media`, `media_pause`, `volume_set` | `media_content_id`, `media_content_type`, `volume_level` (0.0-1.0) |
| **lock** | `lock`, `unlock` | `code` (if PIN required) |
| **automation** | `trigger` | None. Forces an automation to run. |

### Templating (Jinja2)
**Goal:** Process data or create complex logic strings.
Home Assistant uses Jinja2 for rendering templates.

**Syntax Examples:**
* **Get State:** `{{ states('sensor.outside_temp') }}`
* **Get Attribute:** `{{ state_attr('light.living_room', 'brightness') }}`
* **Logic:**
    ```jinja2
    {% if is_state('person.john', 'home') %}
      Welcome home!
    {% else %}
      System Armed.
    {% endif %}
    ```

## API Interaction Examples

### REST API - POST /api/services/<domain>/<service>
Use this format when sending commands via HTTP.

**Example: Turn on a light with 50% brightness**
* **URL:** `POST /api/services/light/turn_on`
* **Headers:** `Authorization: Bearer <LONG_LIVED_ACCESS_TOKEN>`
* **Body:**
    ```json
    {
      "entity_id": "light.kitchen_spots",
      "brightness": 128,
      "transition": 5
    }
    ```

### WebSocket API (Events)
Use this for real-time streaming of state changes.

**Example: Subscribe to Events**
* **Type:** `subscribe_events`
* **Event Type:** `state_changed`
* **Response Payload:** Returns data whenever an entity changes state.


## Logic & Automation Rules

1. **Check Availability:** Always verify an entity is not `unavailable` or `unknown` before acting.
2. **Idempotency:** Calling `turn_on` on a light that is already `on` is safe but wastes API calls.
3. **Entity Groups:** You can target `group.all_lights` or specific user-defined groups.
4. **Areas:** Newer HA versions support targeting `area_id` instead of specific entity IDs.


## Safety & Security
* **Sensitive Domains:** Be cautious with `lock`, `alarm_control_panel`, and `cover` (garage doors).
* **Validation:** Ensure `entity_id` exists in the State Machine before calling a service.


## Essential Boilerplate

### The Manifest (manifest.json)
Must include version (for HACS) and iot_class.

```json
{
  "domain": "your_domain",
  "name": "Your Integration Name",
  "version": "1.0.0",
  "codeowners": ["@your_github_username"],
  "documentation": "https://github.com/username/repo",
  "requirements": ["some-pypi-package==1.2.3"],
  "iot_class": "local_polling",
  "config_flow": true
}
```

**Required fields:** `domain`, `name`, `integration_type`, `iot_class`, `version` (MANDATORY for custom integrations - see [blog](https://developers.home-assistant.io/blog/2021/01/29/custom-integration-changes/#versions)).


**Discovery mechanisms (optional):**
| Mechanism | Manifest key | Description |
|-----------|--------------|-------------|
| Bluetooth | `bluetooth` | List of matcher objects |
| Zeroconf | `zeroconf` | List of service types |
| SSDP | `ssdp` | List of matcher objects |
| HomeKit | `homekit` | List of model names |
| MQTT | `mqtt` | List of discovery topics |
| DHCP | `dhcp` | List of matchers |
| USB | `usb` | List of matchers |

### Constants (const.py)
Always define a DOMAIN constant.

```python
"""Constants for the Example Integration."""
from logging import Logger, getLogger

LOGGER: Logger = getLogger(__package__)

DOMAIN = "example_domain"
CONF_REFRESH_RATE = "refresh_rate"
DEFAULT_REFRESH_RATE = 30
```

### The Coordinator (coordinator.py)
**Golden Rule:** Do not fetch data inside Entity classes. Use a DataUpdateCoordinator.

```python
from datetime import timedelta
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from .const import DOMAIN, LOGGER

class MyCoordinator(DataUpdateCoordinator):
    """Class to manage fetching data from the API."""

    def __init__(self, hass: HomeAssistant, api_client) -> None:
        """Initialize."""
        super().__init__(
            hass,
            LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=30),
        )
        self.api = api_client

    async def _async_update_data(self):
        """Fetch data from API endpoint."""
        try:
            return await self.api.get_data()
        except Exception as err:
            raise UpdateFailed(f"Error communicating with API: {err}")
```

## Implementation Patterns

### Setup (__init__.py)
Never use `setup_platform` (legacy). Use `async_setup_entry`.

```python
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from .const import DOMAIN
from .coordinator import MyCoordinator

PLATFORMS = ["sensor", "binary_sensor"]

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up from a config entry."""
    coordinator = MyCoordinator(hass, entry.data["host"])
    await coordinator.async_config_entry_first_refresh()

    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN][entry.entry_id] = coordinator

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True

async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    if unload_ok := await hass.config_entries.async_unload_platforms(entry, PLATFORMS):
        hass.data[DOMAIN].pop(entry.entry_id)
    return unload_ok
```

### Entity Definition
Inherit from CoordinatorEntity to handle availability and updates automatically.

```python
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.components.sensor import SensorEntity

class MyDeviceSensor(CoordinatorEntity, SensorEntity):
    """Representation of a Sensor."""
    _attr_has_entity_name = True

    def __init__(self, coordinator, device_id):
        super().__init__(coordinator)
        self._device_id = device_id
        self._attr_unique_id = f"{coordinator.config_entry.entry_id}_{device_id}"
        self._attr_name = "Temperature"

    @property
    def native_value(self):
        """Return the state of the sensor."""
        return self.coordinator.data.get(self._device_id, {}).get("temperature")

    @property
    def device_info(self):
        """Return device registry information."""
        return {
            "identifiers": {(DOMAIN, self._device_id)},
            "name": "My Device Name",
            "manufacturer": "Acme Corp",
        }
```

### Config Flow (config_flow.py)
This is your integration's setup wizard. It must handle user input, validation, and error reporting.

#### 1. Schema Definition
Use `voluptuous` to define your form fields.
```python
STEP_USER_DATA_SCHEMA = vol.Schema({
    vol.Required("host"): str,
    vol.Required("username"): str,
    vol.Required("password"): str,
    vol.Optional("port", default=80): int,
})
```

#### 2. Validation Helper
Isolate validation logic from the flow logic.
```python
async def validate_input(hass: HomeAssistant, data: dict[str, Any]) -> dict[str, Any]:
    """Validate the user input allows us to connect."""
    hub = Hub(data["host"], data["username"], data["password"])
    
    try:
        # Test connection/auth
        await hub.authenticate()
    except InvalidAuth:
        raise
    except CannotConnect:
        raise
        
    return {"title": f"My Device ({data['host']})"}
```

#### 3. The Flow Handler (The Wizard)
Handle the steps, errors, and success creation.
```python
class ConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user(self, user_input=None):
        """Handle the initial step."""
        errors = {}
        
        if user_input is not None:
            try:
                info = await validate_input(self.hass, user_input)
                return self.async_create_entry(title=info["title"], data=user_input)
            except CannotConnect:
                errors["base"] = "cannot_connect"
            except InvalidAuth:
                errors["base"] = "invalid_auth"
            except Exception:
                _LOGGER.exception("Unexpected exception")
                errors["base"] = "unknown"

        return self.async_show_form(
            step_id="user",
            data_schema=STEP_USER_DATA_SCHEMA,
            errors=errors,
        )
```

#### 4. Multi-step Flows
Chain steps by returning `await self.async_step_other_step()` instead of `async_create_entry`.
- Use `self.context` to store data between steps if needed (or pass via arg).
- The final step calls `async_create_entry`.

## Critical "Do Not" Rules

| Rule | Wrong | Correct |
|------|-------|---------|
| **No Blocking I/O** | `requests.get()` | `await session.get()` (aiohttp) |
| **No Blocking Sleep** | `time.sleep()` | `await asyncio.sleep()` |
| **No Dynamic Entity IDs** | `self.entity_id = "..."` | Set `_attr_unique_id` and `_attr_name` |
| **No Global Variables** | Global state | `hass.data[DOMAIN][entry.entry_id]` |
| **No Wildcard Imports** | `from .const import *` | Import explicitly |
| **No Print Statements** | `print()` | `_LOGGER.debug()`, `.info()`, `.error()` |
| **No Hardcoded Strings** | Hardcoded UI text | Use `strings.json` keys |


## Logging & Exception Handling

### Logging Standards
Use `logging.getLogger(__package__)` to ensure logs are correctly namespaced to your integration.

| Level | Usage |
|---|---|
| `DEBUG` | Payload details, state changes, function entry. **REDACT SECRETS.** |
| `INFO` | Successful setup, one-time lifecycle events. |
| `WARNING` | Recoverable errors (e.g., API timeout where retry is planned). |
| `ERROR` | Action failed, user intervention required, or bug detected. |

#### Redaction is Mandatory
Never log passwords, tokens, or sensitive user data.
```python
_LOGGER.debug("Received payload: %s", payload) # BAD if payload has secrets
_LOGGER.debug("Recieved payload: %s", async_redact_data(payload, TO_REDACT)) # GOOD
```

### Exception Handling

#### Startup (ConfigEntryNotReady)
If your API is unreachable during setup, raise `ConfigEntryNotReady`. Home Assistant will retry setup later (exponential backoff).
**Do NOT** return `False` (which permanently fails setup) unless the config is invalid.

```python
from homeassistant.exceptions import ConfigEntryNotReady

async def async_setup_entry(hass, entry):
    try:
        await api.connect()
    except CannotConnect as err:
        raise ConfigEntryNotReady(f"Timeout connecting to {host}") from err
```

#### Runtime (UpdateFailed)
In `DataUpdateCoordinator`, raise `UpdateFailed` to mark the entity as unavailable without crashing the loop.

```python
async def _async_update_data(self):
    try:
        data = await self.api.get_status()
    except ApiError as err:
        raise UpdateFailed(f"Error fetching data: {err}")
```


## Config Entries

### Config Flow Handler
- **Config flow** – UI-based setup of an integration.
- **Manifest** – `config_flow: true` must be set.
- **Schema version** – `VERSION` (major) and `MINOR_VERSION` allow migration.
- **Unique ID** – String that ties a flow to a device/service.

```python
# Setting unique ID (required for discovery)
await self.async_set_unique_id(device_unique_id)
self._abort_if_unique_id_configured()
```

### Options Flow Handler
Allows tweaking integration behavior after setup.

```python
from homeassistant.config_entries import OptionsFlow, OptionsFlowWithReload
import voluptuous as vol

OPTIONS_SCHEMA = vol.Schema({
    vol.Required("show_things"): bool,
})

class OptionsFlowHandler(OptionsFlow):
    async def async_step_init(self, user_input=None):
        """Manage the options."""
        if user_input is not None:
            return self.async_create_entry(data=user_input)
        return self.async_show_form(
            step_id="init",
            data_schema=self.add_suggested_values_to_schema(
                OPTIONS_SCHEMA, self.config_entry.options
            ),
        )
```

### Re-authentication Flow
```python
async def async_step_reauth(self, entry_data):
    await self.async_step_reauth_confirm()

async def async_step_reauth_confirm(self, user_input=None):
    if user_input is None:
        return self.async_show_form(step_id="reauth_confirm")
    return self.async_update_reload_and_abort(
        self._get_reauth_entry(), data_updates=new_data)
```

### Translations (strings.json)
```json
{
  "config": {
    "abort": { "already_configured": "Already configured" },
    "step": { "user": { "title": "Login", "description": "Enter password" } },
    "error": { "invalid_auth": "Invalid credentials" }
  }
}
```




## Migrations & Compatibility

### Config Entry Migration
Use `async_migrate_entry` in `__init__.py` to upgrade data structures without breaking users.

```python
async def async_migrate_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Migrate old entry."""
    _LOGGER.debug("Migrating from version %s", entry.version)

    if entry.version == 1:
        new_data = {**entry.data, "new_key": "default_value"}
        hass.config_entries.async_update_entry(entry, data=new_data, version=2)

    _LOGGER.info("Migration to version %s successful", entry.version)
    return True
```

### Handling Breaking Changes
Avoid hard breaks. Use the **Issue Registry** to warn users about deprecated features *months* before removing them.

```python
async_create_issue(
    hass,
    DOMAIN,
    "deprecated_yaml",
    breaks_in_ha_version="2025.1.0",
    is_fixable=False,
    severity=IssueSeverity.WARNING,
    translation_key="deprecated_yaml",
)
```

### Cleanup (Orphaned Entities)
If you remove or rename entities in your code, clean them up from the registry so they don't linger as "Unavailable".

```python
from homeassistant.helpers import entity_registry as er

async def async_setup_entry(hass, entry):
    ent_reg = er.async_get(hass)
    # Remove specific old entity
    if ent_reg.async_get_entity_id("sensor", DOMAIN, "old_unique_id"):
        ent_reg.async_remove("sensor.my_device_old_sensor")
```


## Diagnostics & System Health

### Integration Diagnostics
```python
from homeassistant.helpers.redact import async_redact_data

TO_REDACT = [CONF_API_KEY, APPLIANCE_CODE]

async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: MyConfigEntry
) -> dict[str, Any]:
    """Return diagnostics for a config entry."""
    return {
        "entry_data": async_redact_data(entry.data, TO_REDACT),
        "data": entry.runtime_data.data,
    }
```

### System Health
```python
from homeassistant.components import system_health
from homeassistant.core import HomeAssistant, callback

@callback
def async_register(hass: HomeAssistant, register: system_health.SystemHealthRegistration) -> None:
    """Register system health callbacks."""
    register.async_register_info(system_health_info)

async def system_health_info(hass: HomeAssistant) -> dict[str, Any]:
    """Get info for the info page."""
    return {
        "can_reach_server": system_health.async_check_can_reach_url(hass, ENDPOINT),
    }
```



## The HASS Object

The `hass` object is the central Home Assistant instance:

- `hass`: Main instance for starting, stopping, and enqueuing jobs.
- `hass.config`: Core configuration (location, units, etc.).
- `hass.states`: StateMachine for entity states.
- `hass.bus`: EventBus for triggering/listening to events.
- `hass.services`: ServiceRegistry for registering actions.

### Accessing `hass`
- **Components**: `setup(hass, config)` or `async_setup(hass, config)`
- **Platforms**: `async_setup_platform(hass, config, async_add_entities, discovery_info=None)`
- **Entities**: `self.hass` after added via `add_entities`

### Events
```python
# Fire event
hass.bus.fire("my_domain_event", {"answer": 42})

# Listen to event
def handle_event(event):
    print(f"Answer: {event.data.get('answer')}")
hass.bus.listen("my_domain_event", handle_event)
```

### States
```python
# Set state
hass.states.set("hello_state.my_state", "Hello World")

# Entity attributes
@property
def extra_state_attributes(self):
    """Return entity specific state attributes."""
    return self._attributes
```



## Entity Types Reference

### Core Entity
**Key concepts:**
- Subclass domain-specific base (e.g., `SwitchEntity`)
- **Polling**: `should_poll = True`, implement `update()` or `async_update()`
- **Push**: `should_poll = False`, call `async_schedule_update_ha_state()`

**Mandatory for new integrations:** `has_entity_name = True`

**Lifecycle hooks:**
- `async_added_to_hass()` – restore state, subscribe
- `async_will_remove_from_hass()` – cleanup

### Button Entity
Stateless entity that triggers actions.

```python
from homeassistant.components.button import ButtonEntity

class MyButton(ButtonEntity):
    async def async_press(self) -> None:
        """Handle the button press."""
        # Action logic here
```

Device classes: `IDENTIFY`, `RESTART`, `UPDATE` (discouraged)

### Binary Sensor Entity
Two states only (on/off).

```python
from homeassistant.components.binary_sensor import BinarySensorEntity

class MySensor(BinarySensorEntity):
    @property
    def is_on(self) -> bool:
        return self._is_on

    @property
    def device_class(self):
        return BinarySensorDeviceClass.MOTION
```

Device classes: `BATTERY`, `CO`, `CONNECTIVITY`, `DOOR`, `GARAGE_DOOR`, `GAS`, `LIGHT`, `LOCK`, `MOISTURE`, `MOTION`, `OCCUPANCY`, `OPENING`, `PLUG`, `POWER`, `PRESENCE`, `PROBLEM`, `SAFETY`, `SMOKE`, `SOUND`, `TAMPER`, `VIBRATION`, `WINDOW`

### Number Entity
User-input numeric value.

```python
from homeassistant.components.number import NumberEntity

class MyNumber(NumberEntity):
    _attr_native_min_value = 0
    _attr_native_max_value = 100
    _attr_native_step = 1
    _attr_mode = "slider"  # or "box", "auto"

    async def async_set_native_value(self, value: float) -> None:
        """Update the current value."""
```

### Select Entity
Choose from predefined options.

```python
from homeassistant.components.select import SelectEntity

class MySelect(SelectEntity):
    @property
    def options(self) -> list[str]:
        return ["option1", "option2", "option3"]

    @property
    def current_option(self) -> str | None:
        return self._current

    async def async_select_option(self, option: str) -> None:
        """Change the selected option."""
```

### Time Entity
User-input time value.

```python
from homeassistant.components.time import TimeEntity
from datetime import time

class MyTime(TimeEntity):
    @property
    def native_value(self) -> time:
        return self._time

    async def async_set_value(self, value: time) -> None:
        """Update the current value."""
```

### Image Entity
Displays static images.

```python
from homeassistant.components.image import ImageEntity

class MyImage(ImageEntity):
    async def async_image(self) -> bytes | None:
        """Return bytes of image."""
        return self._cached_image
```

### Media Player Entity
```python
from homeassistant.components.media_player import MediaPlayerEntity, MediaPlayerEntityFeature

class MyPlayer(MediaPlayerEntity):
    _attr_supported_features = (
        MediaPlayerEntityFeature.PLAY |
        MediaPlayerEntityFeature.PAUSE |
        MediaPlayerEntityFeature.VOLUME_SET
    )
```




## Advanced Entity & Service Patterns

### Sensor Statistics (Long-term Data)
To enable graphs and energy dashboard usage, set the `state_class`.

```python
from homeassistant.components.sensor import SensorStateClass

class MyEnergySensor(SensorEntity):
    _attr_state_class = SensorStateClass.TOTAL_INCREASING # For meters
    _attr_state_class = SensorStateClass.MEASUREMENT      # For current values (temp, power)
```

### Entity Categories
Clean up the user's dashboard by categorizing non-primary entities.

```python
from homeassistant.const import EntityCategory

class MyDebugSensor(SensorEntity):
    _attr_entity_category = EntityCategory.DIAGNOSTIC # or EntityCategory.CONFIG
```

### Rich Services (services.yaml)
Use **Selectors** to give users nice UI pickers instead of text boxes.

```yaml
play_media:
  name: Play Media
  fields:
    media_content_id:
      name: Content ID
      example: "media-source://jellyfin/..."
      selector:
        text:
    entity_id:
      name: Target Player
      selector:
        entity:
          domain: media_player
```

### Device Topology (Hubs & Sub-devices)
Link devices together in the registry (e.g., a Zigbee bulb connected via a Gateway).

```python
@property
def device_info(self):
    return {
        "identifiers": {(DOMAIN, self._device_id)},
        "via_device": (DOMAIN, self._hub_id), # The tuple identifier of the parent
        "name": "My Bulb",
    }
```



## Custom WebSocket API
For high-performance frontend-backend communication, use WebSockets instead of REST.

### Backend: Registration
Expose a new command to the frontend.

```python
from homeassistant.components import websocket_api
import voluptuous as vol

@callback
def async_setup_entry(hass, entry):
    hass.components.websocket_api.async_register_command(
        hass, handle_my_command
    )

@websocket_api.websocket_command({
    vol.Required("type"): "jellyha/search",
    vol.Required("query"): str,
})
@websocket_api.async_response
async def handle_my_command(hass, connection, msg):
    """Handle the search command."""
    query = msg["query"]
    try:
        results = await my_search_function(query)
        connection.send_result(msg["id"], results)
    except Exception as err:
        connection.send_error(msg["id"], "search_failed", str(err))
```

### Frontend: Usage
Call the command from your custom card.

```javascript
try {
  const results = await this.hass.callWS({
    type: "jellyha/search",
    query: "Rick Astley",
  });
  console.log("Found:", results);
} catch (err) {
  console.error("Search failed:", err);
}
```


## Frontend Development

### Architecture
- **Bootstrap** (`src/entrypoints/core.ts`): Authentication and WebSocket setup
- **App Shell** (`src/entrypoints/app.ts`): Sidebar and routing
- **Panels** (`src/panels/`): Each page is a panel
- **Dialogs** (`src/dialogs/`): Data entry and info presentation

### Custom Card Development
1. Place JavaScript in `<config>/www/` (e.g., `/local/my-card.js`)
2. Add dashboard resource: `url: /local/my-card.js`, `type: module`

```javascript
import { LitElement, html, css } from "https://unpkg.com/lit-element@2/lit-element.js?module";

class MyCard extends LitElement {
  static get properties() {
    return { hass: {}, config: {} };
  }

  setConfig(config) {
    if (!config.entity) throw new Error("Please define an entity");
    this.config = config;
  }

  static getStubConfig() {
    return { type: "custom:my-card", entity: "sun.sun" };
  }

  getCardSize() {
    return 1; // 1 = 50px
  }

  render() {
    return html`
      <ha-card header="My Card">
        <div class="card-content">
          ${this.hass.states[this.config.entity]?.state}
        </div>
      </ha-card>
    `;
  }

  static get styles() {
    return css`
      .card-content { padding: 16px; }
    `;
  }
}

customElements.define("my-card", MyCard);

window.customCards = window.customCards || [];
window.customCards.push({
  type: "my-card",
  name: "My Card",
  description: "A custom card"
});
```

### Custom Panel Development
```javascript
class ExamplePanel extends LitElement {
  static get properties() {
    return {
      hass: { type: Object },
      narrow: { type: Boolean },
      route: { type: Object },
      panel: { type: Object },
    };
  }

  render() {
    return html`
      <p>There are ${Object.keys(this.hass.states).length} entities.</p>
    `;
  }
}
customElements.define("example-panel", ExamplePanel);
```

**configuration.yaml:**
```yaml
panel_custom:
  - name: example
    url_path: example
    sidebar_title: Example Panel
    sidebar_icon: mdi:server
    module_url: /local/example/panel.js
```




### Frontend Layout Patterns

#### Configurable Grid Layouts
Give users control over the layout by exposing grid settings like `min_columns`, `max_columns`, `min_rows`, and `max_rows`.

**1. Config Definition:**
```typescript
interface MyCardConfig {
  columns?: number;
  min_columns?: number;
  max_columns?: number;
  max_rows?: number;
}
```

**2. Dynamic Styles (CSS Variables):**
Inject config values as CSS variables using `styleMap`.

```javascript
import { styleMap } from 'lit/directives/style-map.js';

render() {
  const minCols = this.config.min_columns || 2;
  const maxCols = this.config.max_columns || 4;

  const styles = {
    '--min-cols': minCols,
    '--max-cols': maxCols,
  };

  return html`
    <ha-card>
      <div class="grid" style=${styleMap(styles)}>
        ${this._items.map(item => html`<div class="item">...</div>`)}
      </div>
    </ha-card>
  `;
}

static get styles() {
  return css`
    .grid {
      display: grid;
      /* Dynamic responsiveness constrained by config */
      grid-template-columns: repeat(auto-fit, minmax(
        max(150px, 100% / var(--max-cols)),
        1fr
      ));
      gap: 8px;
    }
  `;
}
```

**3. Limiting Rows:**
For `max_rows`, it is best to limit the *data* rendered rather than hiding it with CSS.

```javascript
const maxRows = this.config.max_rows || 3;
const cols = this.config.columns || 3;
const limit = maxRows * cols;
const visibleItems = this._items.slice(0, limit);
```

#### Responsiveness & The Home Assistant Grid
Your card might be placed inside a specific column in a Dashboard View or within a `grid` card.
- **Do not hardcode widths:** Use `100%` width or Flex/Grid to fill available space.
- **Use ResizeObserver:** If your layout depends on the *container's* width (not the window width), use a `ResizeObserver` to detect size changes. Media queries (`@media`) only work on the viewport, which might be misleading if your card is in a small column on a large screen.

#### The `ha-card` Wrapper
Always wrap your card's content in `<ha-card>` to inherit official styling (backgrounds, borders, shadows) and dark/light mode support automatically.

```javascript
render() {
  return html`
    <ha-card .header=${this.config.title}>
      <div class="card-content">
        <!-- content -->
      </div>
    </ha-card>
  `;
}
```

#### Proper Sizing (`getCardSize`)
Home Assistant's default Masonry layout needs to know how "tall" your card is to arrange columns efficiently.
Implement `getCardSize()` to return a number representing height in units of ~50px.

```javascript
getCardSize() {
  // Example: 1 unit for header + 1 unit per 3 items
  return 1 + Math.ceil(this.items.length / 3);
}
```



### User Interaction & Configuration

#### Haptic Feedback
Always provide haptic feedback for user interactions on mobile devices.
```javascript
// Helper to fire haptic events
function fireHaptic(node, pattern) {
  const event = new CustomEvent("haptic", {
    detail: pattern, // "success", "warning", "failure", "light", "medium", "heavy", "selection"
    bubbles: true,
    composed: true,
  });
  node.dispatchEvent(event);
}

// Usage in event handler
_handleTap(e) {
  fireHaptic(this, "light");
}
```

#### Action Handling
Cards should support standard `tap_action`, `hold_action`, and `double_tap_action` to be consistent with the rest of Lovelace.

```javascript
// Simple implementation pattern
_handleAction(ev) {
  const config = this.config;
  const action = ev.detail.action; // 'tap', 'hold', 'double_tap'
  
  if (config && config[`${action}_action`]) {
    // Handle specific action config
    // e.g. navigate, toggle, call-service, fire-dom-event
  }
}
```

#### Scoped Event Firing
When dispatching custom events from your card, ensure `bubbles: true` and `composed: true` are set so they can traverse the Shadow DOM boundary and reach the main Home Assistant window.

```javascript
this.dispatchEvent(new CustomEvent('my-custom-event', {
  detail: { item: this.item },
  bubbles: true,
  composed: true,
}));
```



### Theming & Colors

#### Standard CSS Variables
Home Assistant provides a comprehensive set of CSS variables that automatically adapt to the user's selected theme (light/dark mode). **Always** use these instead of hardcoded colors.

| CSS Variable | Description |
|---|---|
| `--primary-text-color` | Main text color |
| `--secondary-text-color` | Subtitles, less important text |
| `--primary-color` | Brand/Action color |
| `--accent-color` | Active states, toggles |
| `--card-background-color` | Card background |
| `--ha-card-box-shadow` | Card shadow (use `none` if you don't want shadows) |
| `--ha-card-border-radius` | Border radius |

#### Implementing Custom Colors
If you need custom colors (e.g., for media types), define them as fallbacks or scoped variables, and allow users to override them via theming.

```css
:host {
  /* Define local variable with fallback to HA theme variable or default */
  --jellyha-movie-color: var(--warning-color, #ff9800);
}

.movie-badge {
  background-color: var(--jellyha-movie-color);
  color: var(--primary-text-color);
}
```

#### Dark Mode Handling
Usually, `ha-card` handles this. If you are building a custom element outside of a card, use the `dark` attribute on the `hass` object or check `prefers-color-scheme`.

```javascript
const isDark = this.hass.themes.darkMode;
```



### Card Configuration & Visual Editors
To make your card user-friendly, implement a visual editor.

#### Registering the Editor
In your card class:
```javascript
public static getConfigElement(): HTMLElement {
  return document.createElement('my-card-editor');
}
```

#### Building the Editor Component
The editor is a LitElement that accepts the config and fires `config-changed` events.

```javascript
class MyCardEditor extends LitElement {
  setConfig(config) {
    this._config = config;
  }

  _valueChanged(ev) {
    if (!this._config || !this.hass) return;
    const target = ev.target;
    // Fire the standard event that HA listens for
    // Use the fireEvent helper defined in your utils
    const event = new CustomEvent("config-changed", {
      detail: { config: {
        ...this._config,
        [target.configValue]: target.checked !== undefined ? target.checked : target.value,
      }},
      bubbles: true,
      composed: true,
    });
    this.dispatchEvent(event);
  }

  render() {
    return html`
      <div class="card-config">
        <ha-textfield
          label="Title"
          .value=${this._config.title || ''}
          .configValue=${"title"}
          @input=${this._valueChanged}
        ></ha-textfield>
        <ha-switch
          .checked=${this._config.show_icon !== false}
          .configValue=${"show_icon"}
          @change=${this._valueChanged}
        >Show Icon</ha-switch>
      </div>
    `;
  }
}
```

#### Using HA Selectors
For complex inputs, leverage Home Assistant's built-in selectors (available in modern HA versions).

```javascript
render() {
  return html`
    <ha-selector
      .hass=${this.hass}
      .selector=${{ entity: { domain: "media_player" } }}
      .value=${this._config.entity}
      .configValue=${"entity"}
      @value-changed=${this._valueChanged}
    ></ha-selector>
  `;
}
```


## Testing Strategy
- Use `pytest-homeassistant-custom-component`
- Mock external APIs using `respx` or `aioresponses`
- Use `syrupy` for snapshot testing entity states
- Full unit-test coverage of `config_flow.py` required for core acceptance




## Platinum Quality Patterns

### Issues Registry (Repairs)
Don't just log warnings—create actionable issues in the "Repairs" dashboard.

```python
from homeassistant.helpers.issue_registry import async_create_issue, IssueSeverity

async_create_issue(
    hass,
    DOMAIN,
    "deprecated_auth",
    is_fixable=False,
    severity=IssueSeverity.WARNING,
    translation_key="deprecated_auth",
)
```

### Strict Typing
Use Home Assistant's typing helpers to catch bugs early.

```python
from homeassistant.helpers.typing import ConfigType, DiscoveryInfoType
from homeassistant.core import HomeAssistant

async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    ...
```

### Testing Templates
Use `pytest-homeassistant-custom-component`.

**Config Flow Test:**
```python
async def test_form(hass):
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )
    assert result["type"] == "form"
    
    result2 = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {"host": "1.1.1.1"},
    )
    assert result2["type"] == "create_entry"
```

**Entity State Test:**
```python
async def test_sensor(hass):
    # Mock data, setup entry...
    state = hass.states.get("sensor.my_device")
    assert state.state == "123"
```

### Versioning Strategy
- **Manifest**: Remove the `version` key (deprecated).
- **HACS**: Controls the version via GitHub Releases (Tags).
- **Code**: To get the version at runtime (e.g. for User-Agent), use `importlib.metadata`.

```python
from importlib.metadata import version
__version__ = version("homeassistant.components.jellyha") # or domain
```




## Device Triggers
Instead of making users write automations watching for "event_fired", expose first-class Triggers in the UI.

### Definition (device_trigger.py)
Register triggers that appear in the Automation editor.

```python
TRIGGER_SCHEMA = vol.Schema({
    vol.Required(CONF_PLATFORM): "device",
    vol.Required(CONF_DOMAIN): DOMAIN,
    vol.Required(CONF_DEVICE_ID): str,
    vol.Required(CONF_TYPE): "button_pressed",
})

async def async_attach_trigger(hass, config, action, automation_info):
    """Listen for the event and call action."""
    return await hass.components.homeassistant.triggers.event.async_attach_trigger(
        hass,
        event_trigger_config, # templated config listening for specific event
        action,
        automation_info,
    )
```


## Automated Quality (CI/CD)
Platinum integrations prove their quality automatically.

### GitHub Actions Workflow
Add `.github/workflows/home-assistant.yaml` to run validation on every commit.

```yaml
name: Validate
on: [push, pull_request]
jobs:
  hassfest:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: home-assistant/actions/hassfest@master
  
  hacs_validation:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: hacs/action@main
        with:
          category: integration
```


## Branding & Discovery

### HACS Assets
To look professional in the HACS store, add these images to your repository root:
- **`logo.png`**: 1280x640px (2:1 ratio). This is the banner users see.
- **`icon.png`**: 512x512px (1:1 ratio). Displayed in lists.

### Official Brands Repository
If you want your logo to appear in the standard Home Assistant integrations list (after you are added to HACS default list or Core):
- Submit PR to `home-assistant/brands`.
- You need a vector (SVG) version of your icon.

### Documentation Polish
Your `README.md` is your landing page.
- **Badges**: Add "HACS Default", "GitHub Actions", and "Maintainer" badges.
- **Screenshots**: Use the `![Alt](url)` syntax to show off your Lovelace cards.
- **Buy Me a Coffee**: Optional but common for community support.


## Best Practices Checklist

**Phase 1: Foundation & Setup**
- [ ] **Manifest**: Includes `iot_class`, `integration_type`, `codeowners`, and `documentation`. **No `version` key.**
- [ ] **Structure**: Adopts the correct `custom_components/<domain>/` layout.
- [ ] **Constants**: Uses `const.py` for `DOMAIN` and configuration keys.
- [ ] **Type Hints**: Uses `homeassistant.helpers.typing` for strict typing (`ConfigType`, etc.).

**Phase 2: The User Experience (Frontend)**
- [ ] **Visual Editor**: Implements `getConfigElement()` with a custom editor component.
- [ ] **Selectors**: Uses `ha-selector` for native, rich UI inputs (entity pickers, areas).
- [ ] **Responsive Grid**: Uses CSS Grid with `repeat(auto-fit, ...)` for layout.
- [ ] **Theming**: Uses standard CSS variables (`--primary-text-color`) and `ha-card` styling.
- [ ] **Interaction**: Provides Haptic feedback (`fireHaptic`) on all touch interactions.

**Phase 3: The Wizard (Config Flow)**
- [ ] **Validation**: Implements `validate_input` helper with specific exception handling.
- [ ] **Error Messages**: Maps errors to localized strings in `strings.json` (`cannot_connect`, `invalid_auth`).
- [ ] **Discovery**: Logic handles duplicate entries (`_abort_if_unique_id_configured`).
- [ ] **Re-auth**: Supports re-authentication flow for changed passwords.

**Phase 4: Robustness & Quality (Backend)**
- [ ] **Coordinator**: Uses `DataUpdateCoordinator` for all API polling (no fetching in entities).
- [ ] **Entities**: Inherits from `CoordinatorEntity` and sets `_attr_has_entity_name = True`.
- [ ] **Statistics**: Sets `_attr_state_class` for numerical sensors (Energy Dashboard support).
- [ ] **Categories**: usage of `EntityCategory.DIAGNOSTIC` or `CONFIG` where appropriate.
- [ ] **Topology**: Implements `device_info` with `via_device` for hubs/sub-devices.
- [ ] **Triggers**: Implements `device_trigger.py` to expose events (button presses) to Automations.

**Phase 5: Maintenance & Operations**
- [ ] **Logging**: Uses `DEBUG` for payloads (redacted!) and `ConfigEntryNotReady` for startup retries.
- [ ] **Issue Registry**: Raises actionable repairs for deprecated configuration/features.
- [ ] **Cleanup**: Removes orphaned entities from the registry during setup.
- [ ] **Diagnostics**: JSON dump via `async_get_config_entry_diagnostics` implemented.
- [ ] **Tests**: Includes tests for Config Flow and Sensor states.
- [ ] **CI/CD**: Uses GitHub Actions for `hassfest` and HACS validation.

**Phase 6: Polish & Launch**
- [ ] **HACS Assets**: Repository includes `logo.png` (banner) and `icon.png` (square).
- [ ] **Docs**: `README.md` includes screenshots, badges, and installation steps.
- [ ] **Brands**: Vector icon submitted to `home-assistant/brands` (if aiming for Core/Recommended).
