"""Device info helper for JellyHA integration."""
from homeassistant.helpers.device_registry import DeviceInfo

from .const import DOMAIN


def get_device_info(entry_id: str, device_name: str) -> DeviceInfo:
    """Return the shared DeviceInfo for all JellyHA entities.
    
    This function provides a single source of truth for device metadata,
    ensuring all entities belonging to a JellyHA config entry are grouped
    under the same device with consistent properties.
    
    Args:
        entry_id: The config entry ID (used as the device identifier).
        device_name: The user-configured device name (e.g., "JellyHA").
    
    Returns:
        DeviceInfo with consistent identifiers, manufacturer, and model.
    """
    return DeviceInfo(
        identifiers={(DOMAIN, entry_id)},
        name=device_name,
        manufacturer="JellyHA",
        model="Jellyfin for Home Assistant",
        sw_version="1.0.0",
    )
