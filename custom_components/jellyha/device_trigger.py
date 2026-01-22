"""Device automation triggers for JellyHA."""
from __future__ import annotations

import voluptuous as vol

from homeassistant.const import (
    CONF_DEVICE_ID,
    CONF_DOMAIN,
    CONF_PLATFORM,
    CONF_TYPE,
)
from homeassistant.core import CALLBACK_TYPE, HomeAssistant
from homeassistant.helpers import config_validation as cv, device_registry as dr
from homeassistant.helpers.trigger import TriggerActionType, TriggerInfo
from homeassistant.helpers.typing import ConfigType

from .const import DOMAIN

# Define trigger types
TRIGGER_TYPE_PLAY = "media_play"
TRIGGER_TYPE_PAUSE = "media_pause"
TRIGGER_TYPE_STOP = "media_stop"

TRIGGER_TYPES = {
    TRIGGER_TYPE_PLAY,
    TRIGGER_TYPE_PAUSE,
    TRIGGER_TYPE_STOP,
}

TRIGGER_SCHEMA = cv.TRIGGER_BASE_SCHEMA.extend(
    {
        vol.Required(CONF_TYPE): vol.In(TRIGGER_TYPES),
        vol.Required(CONF_DEVICE_ID): cv.string,  # We target the specific user sensor device?
        # Actually session updates are global, but we can target specific Media Player entities
        # or we can target the SERVICE device if we want global "any user" triggers.
        # Let's keep it simple: Device triggers usually attach to a 'device'. 
        # Our entities (Sensors) belong to the main JellyHA device.
    }
)


async def async_get_triggers(
    hass: HomeAssistant, device_id: str
) -> list[dict[str, str]]:
    """List device triggers for JellyHA devices."""
    device_registry = dr.async_get(hass)
    device = device_registry.async_get(device_id)
    
    # Verify this is our device and has our config entry
    if device is None:
        return []
    
    # Simple check: does this device belong to our domain?
    # A device can belong to multiple entries, check identifiers
    is_jelly_device = False
    for identifier in device.identifiers:
        if identifier[0] == DOMAIN:
            is_jelly_device = True
            break
            
    if not is_jelly_device:
        return []

    return [
        {
            CONF_PLATFORM: "device",
            CONF_DEVICE_ID: device_id,
            CONF_DOMAIN: DOMAIN,
            CONF_TYPE: trigger_type,
        }
        for trigger_type in TRIGGER_TYPES
    ]


async def async_attach_trigger(
    hass: HomeAssistant,
    config: ConfigType,
    action: TriggerActionType,
    trigger_info: TriggerInfo,
) -> CALLBACK_TYPE:
    """Attach a trigger."""
    # Logic: We need to listen to our own internal event or state changes.
    # Since we don't have a dedicated event bus for this yet in coordinator,
    # the simplest way for "Platinum" show-off is to map these triggers 
    # to state changes of the user sensors if possible, or emit an HA event.
    
    # For this implementation, we will assume we are firing 
    # `jellyha_media_status` events from the coordinator/websocket logic.
    # If not present, we should add that to the coordinator!
    
    event_config = {
        "event_type": f"{DOMAIN}_event",
        "event_data": {
            "type": config[CONF_TYPE],
            "device_id": config[CONF_DEVICE_ID],
        }
    }
    
    return await hass.components.homeassistant.triggers.event.async_attach_trigger(
        hass, event_config, action, trigger_info, platform_type="device"
    )
