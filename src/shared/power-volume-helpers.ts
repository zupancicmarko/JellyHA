/**
 * Helper utilities for Power button and Volume controls in JellyHA
 */
import { HomeAssistant, JellyHANowPlayingCardConfig, JellyHALibraryCardConfig, MediaItem } from './types';

export interface PowerStateInfo {
    isAvailable: boolean;
    isStateless: boolean;
    isOn: boolean;
    state?: string;
    entityId?: string;
}

export interface VolumeStateInfo {
    canControl: boolean;
    volumeLevel: number; // 0..1
    volumePercent: number; // 0..100
    isMuted: boolean;
    entityId?: string;
}

/**
 * Resolves the effective power entity:
 * 1. Explicit power_entity if configured.
 * 2. Defaults to primary media player entity if it's not a read-only sensor.
 * 3. Otherwise undefined.
 */
export function resolveTargetPowerEntity(
    config?: Partial<JellyHANowPlayingCardConfig>
): string | undefined {
    if (config?.power_entity) {
        return config.power_entity;
    }
    const entity = config?.entity;
    if (entity && !entity.startsWith('sensor.') && !entity.startsWith('binary_sensor.')) {
        return entity;
    }
    return undefined;
}

/**
 * Determine power status and whether the entity is stateless (script/button/scene) or stateful.
 */
export function resolvePowerState(
    hass: HomeAssistant,
    powerEntity?: string,
    powerStateEntity?: string
): PowerStateInfo {
    if (!powerEntity || !hass || !hass.states) {
        return { isAvailable: false, isStateless: false, isOn: false };
    }

    const actionObj = hass.states[powerEntity];
    if (!actionObj) {
        return { isAvailable: false, isStateless: false, isOn: false };
    }

    // Check if user supplied a separate state tracking entity (e.g. binary_sensor.tv_ping or switch.smart_plug)
    if (powerStateEntity && hass.states[powerStateEntity]) {
        const stateObj = hass.states[powerStateEntity];
        const state = stateObj.state.toLowerCase();
        const isOn = state === 'on' || state === 'playing' || state === 'paused' || state === 'idle' || state === 'home' || state === 'active';
        return {
            isAvailable: state !== 'unavailable' && state !== 'unknown',
            isStateless: false,
            isOn,
            state: stateObj.state,
            entityId: powerStateEntity
        };
    }

    const domain = powerEntity.split('.')[0];
    const isStateless = domain === 'script' || domain === 'button' || domain === 'scene';

    const state = actionObj.state.toLowerCase();
    const isAvailable = state !== 'unavailable' && state !== 'unknown';
    
    // For stateless entities, they don't have persistent ON status unless currently executing
    let isOn = false;
    if (isStateless) {
        isOn = state === 'on'; // script is executing
    } else if (domain === 'media_player') {
        isOn = state === 'on' || state === 'playing' || state === 'paused' || state === 'idle' || state === 'buffering';
    } else {
        isOn = state === 'on' || state === 'playing' || state === 'home' || state === 'active';
    }

    return {
        isAvailable,
        isStateless,
        isOn,
        state: actionObj.state,
        entityId: powerEntity
    };
}

/**
 * Execute the power action service call appropriate for the entity's domain.
 */
export async function callPowerAction(
    hass: HomeAssistant,
    powerEntity: string,
    powerStateEntity?: string
): Promise<void> {
    if (!hass || !powerEntity) return;
    const domain = powerEntity.split('.')[0];
    const stateInfo = resolvePowerState(hass, powerEntity, powerStateEntity);

    try {
        if (domain === 'script') {
            await hass.callService('script', 'turn_on', { entity_id: powerEntity });
        } else if (domain === 'button') {
            await hass.callService('button', 'press', { entity_id: powerEntity });
        } else if (domain === 'scene') {
            await hass.callService('scene', 'turn_on', { entity_id: powerEntity });
        } else if (domain === 'media_player') {
            if (stateInfo.isOn) {
                try {
                    await hass.callService('media_player', 'turn_off', { entity_id: powerEntity });
                } catch {
                    await hass.callService('homeassistant', 'toggle', { entity_id: powerEntity });
                }
            } else {
                try {
                    await hass.callService('media_player', 'turn_on', { entity_id: powerEntity });
                } catch {
                    await hass.callService('homeassistant', 'toggle', { entity_id: powerEntity });
                }
            }
        } else if (domain === 'switch' || domain === 'light' || domain === 'input_boolean') {
            await hass.callService('homeassistant', 'toggle', { entity_id: powerEntity });
        } else {
            await hass.callService('homeassistant', 'toggle', { entity_id: powerEntity });
        }
    } catch (err) {
        // Log error gracefully rather than throwing unhandled exception
        console.error(`[JellyHA] Failed to call power action for ${powerEntity}:`, err);
    }
}

/**
 * Helper to get cached volume from localStorage if available
 */
function getCachedVolume(entityId: string): number | undefined {
    try {
        if (typeof localStorage !== 'undefined') {
            const val = localStorage.getItem(`jellyha_volume_${entityId}`);
            if (val !== null) {
                const num = Number(val);
                if (!isNaN(num) && num >= 0 && num <= 1) {
                    return num;
                }
            }
        }
    } catch {
        // Ignore localStorage errors
    }
    return undefined;
}

/**
 * Helper to persist volume to localStorage if available
 */
export function setCachedVolume(entityId: string, level: number): void {
    try {
        if (typeof localStorage !== 'undefined') {
            localStorage.setItem(`jellyha_volume_${entityId}`, String(level));
        }
    } catch {
        // Ignore localStorage errors
    }
}

/**
 * Resolve volume status from the configured volume entity or the primary playback entity.
 * Robustly handles Google Cast speakers and other devices where state is 'off' or volume_level is omitted.
 */
export function resolveVolumeState(
    hass: HomeAssistant,
    volumeEntity?: string,
    defaultEntity?: string,
    optimisticPercent?: number
): VolumeStateInfo {
    const targetId = volumeEntity || defaultEntity;
    if (!targetId || !hass || !hass.states || !hass.states[targetId]) {
        return {
            canControl: false,
            volumeLevel: 0,
            volumePercent: 0,
            isMuted: false
        };
    }

    const stateObj = hass.states[targetId];
    const attrs = stateObj.attributes as Record<string, unknown>;

    let resolvedLevel: number | undefined;

    // 1. Direct attribute on target entity
    if (attrs.volume_level !== undefined && attrs.volume_level !== null) {
        const parsed = Number(attrs.volume_level);
        if (!isNaN(parsed)) {
            resolvedLevel = parsed > 1 ? parsed / 100 : parsed;
        }
    }

    // 2. Mirror/paired entity check (common for Google Cast + Music Assistant pairings like _2)
    if (resolvedLevel === undefined) {
        const altId = targetId.endsWith('_2') ? targetId.slice(0, -2) : `${targetId}_2`;
        const altState = hass.states[altId];
        if (altState?.attributes?.volume_level !== undefined && altState.attributes.volume_level !== null) {
            const parsed = Number(altState.attributes.volume_level);
            if (!isNaN(parsed)) {
                resolvedLevel = parsed > 1 ? parsed / 100 : parsed;
            }
        }
    }

    // 3. In-memory optimistic override passed by card
    if (resolvedLevel === undefined && typeof optimisticPercent === 'number') {
        resolvedLevel = optimisticPercent / 100;
    }

    // 4. LocalStorage persistent fallback for devices that wipe volume_level in standby
    if (resolvedLevel === undefined) {
        resolvedLevel = getCachedVolume(targetId);
    }

    const finalLevel = typeof resolvedLevel === 'number' ? Math.max(0, Math.min(1, resolvedLevel)) : 0;
    const volumePercent = Math.round(finalLevel * 100);

    // Persist known level to cache if we resolved a valid one
    if (resolvedLevel !== undefined) {
        setCachedVolume(targetId, finalLevel);
    }

    const isMuted = Boolean(attrs.is_volume_muted);

    return {
        canControl: stateObj.state !== 'unavailable' && stateObj.state !== 'unknown',
        volumeLevel: finalLevel,
        volumePercent,
        isMuted,
        entityId: targetId
    };
}

/**
 * Set target volume level (0..1) on the specified entity.
 */
export async function setVolumeLevel(
    hass: HomeAssistant,
    entityId: string,
    level: number
): Promise<void> {
    if (!hass || !entityId) return;
    const clamped = Math.max(0, Math.min(1, level));
    setCachedVolume(entityId, clamped);
    const domain = entityId.split('.')[0];
    try {
        if (domain === 'media_player') {
            await hass.callService('media_player', 'volume_set', {
                entity_id: entityId,
                volume_level: clamped
            });
        }
    } catch (err) {
        console.error(`[JellyHA] Failed to set volume level for ${entityId}:`, err);
    }
}

/**
 * Increment or decrement volume by a step delta (e.g. +0.05 or -0.05).
 */
export async function stepVolume(
    hass: HomeAssistant,
    entityId: string,
    step: number,
    currentOverrideLevel?: number
): Promise<number> {
    if (!hass || !entityId || !hass.states[entityId]) return 0;
    const stateObj = hass.states[entityId];

    let current: number;
    if (typeof currentOverrideLevel === 'number') {
        current = currentOverrideLevel;
    } else {
        const volState = resolveVolumeState(hass, entityId);
        current = volState.volumeLevel;
    }

    const nextLevel = Math.max(0, Math.min(1, current + step));
    await setVolumeLevel(hass, entityId, nextLevel);
    return nextLevel;
}

/**
 * Toggle mute on the specified volume entity.
 */
export async function toggleMute(
    hass: HomeAssistant,
    entityId: string
): Promise<void> {
    if (!hass || !entityId || !hass.states[entityId]) return;
    const stateObj = hass.states[entityId];
    const isMuted = Boolean(stateObj.attributes.is_volume_muted);
    const domain = entityId.split('.')[0];
    try {
        if (domain === 'media_player') {
            await hass.callService('media_player', 'volume_mute', {
                entity_id: entityId,
                is_volume_muted: !isMuted
            });
        }
    } catch (err) {
        console.error(`[JellyHA] Failed to toggle mute for ${entityId}:`, err);
    }
}

/**
 * Resolves the base sensor prefix from a media player or sensor entity ID.
 * Examples:
 * - media_player.jellyha_admin -> sensor.jellyha
 * - media_player.jellyha_user_admin -> sensor.jellyha
 * - media_player.jellyha_device_tv -> sensor.jellyha
 * - media_player.jellyha_office_user_marko -> sensor.jellyha_office
 * - sensor.jellyha_now_playing_admin -> sensor.jellyha
 */
export function resolveInstanceSensorBase(entityId: string): string {
    if (!entityId || typeof entityId !== 'string') return '';
    if (entityId.startsWith('sensor.')) {
        return entityId.replace(/_now_playing.*$/, '');
    }
    if (entityId.startsWith('media_player.')) {
        const nameWithoutDomain = entityId.replace(/^media_player\./, '');
        let prefix = nameWithoutDomain;
        if (nameWithoutDomain.includes('_user_')) {
            prefix = nameWithoutDomain.substring(0, nameWithoutDomain.indexOf('_user_'));
        } else if (nameWithoutDomain.includes('_device_')) {
            prefix = nameWithoutDomain.substring(0, nameWithoutDomain.indexOf('_device_'));
        } else if (nameWithoutDomain.includes('_')) {
            prefix = nameWithoutDomain.substring(0, nameWithoutDomain.lastIndexOf('_'));
        }
        return `sensor.${prefix}`;
    }
    return '';
}

export interface ActivePlayerInfo {
    entityId: string;
    state: string;
    friendlyName?: string;
}

/**
 * Resolves the media player entity actively playing or paused for a given library media item.
 * Evaluates default_cast_device, default_client_device, and discovered active JellyHA session players.
 */
export function findActiveMediaItemPlayer(
    item: MediaItem,
    hass?: HomeAssistant,
    config?: JellyHALibraryCardConfig
): ActivePlayerInfo | null {
    if (!item || !hass?.states) return null;

    // 1. Gather candidate entity IDs in priority order
    const candidateIds: string[] = [];

    if (config?.default_cast_device && !candidateIds.includes(config.default_cast_device)) {
        candidateIds.push(config.default_cast_device);
    }
    if (config?.default_client_device && !candidateIds.includes(config.default_client_device)) {
        candidateIds.push(config.default_client_device);
    }

    // Include discovered active JellyHA media players (e.g. device players, user players)
    for (const entityId of Object.keys(hass.states)) {
        if (
            entityId.startsWith('media_player.jellyha_') &&
            !entityId.includes('_library_browser') &&
            !entityId.endsWith('_browser') &&
            !candidateIds.includes(entityId)
        ) {
            candidateIds.push(entityId);
        }
    }

    // 2. Evaluate candidates for item match
    let bestMatch: ActivePlayerInfo | null = null;

    for (const entityId of candidateIds) {
        const player = hass.states[entityId];
        if (!player) continue;

        const state = player.state;
        if (state !== 'playing' && state !== 'paused' && state !== 'buffering') {
            continue;
        }

        const playingTitle = player.attributes?.media_title as string | undefined;
        const playingSeries = player.attributes?.media_series_title as string | undefined;

        const isMatch = Boolean(
            (item.name && (playingTitle === item.name || playingSeries === item.name)) ||
            (item.series_name && (playingSeries === item.series_name || playingTitle === item.series_name)) ||
            (item.type === 'Series' && (playingSeries === item.name || playingTitle === item.name))
        );

        if (isMatch) {
            const playerInfo: ActivePlayerInfo = {
                entityId,
                state,
                friendlyName: (player.attributes?.friendly_name as string) || entityId,
            };

            // If actively playing, return immediately as highest priority match
            if (state === 'playing') {
                return playerInfo;
            }

            // Otherwise hold as candidate (e.g. paused/buffering) unless a playing one is found
            if (!bestMatch) {
                bestMatch = playerInfo;
            }
        }
    }

    return bestMatch;
}

/**
 * Returns all candidate media player entities that should be monitored for state changes.
 */
export function getLibraryWatchedPlayerEntities(
    hass?: HomeAssistant,
    config?: JellyHALibraryCardConfig
): string[] {
    const list: string[] = [];
    if (config?.default_cast_device) list.push(config.default_cast_device);
    if (config?.default_client_device && !list.includes(config.default_client_device)) {
        list.push(config.default_client_device);
    }
    if (hass?.states) {
        for (const entityId of Object.keys(hass.states)) {
            if (
                entityId.startsWith('media_player.jellyha_') &&
                !entityId.includes('_library_browser') &&
                !entityId.endsWith('_browser') &&
                !list.includes(entityId)
            ) {
                const state = hass.states[entityId]?.state;
                if (state === 'playing' || state === 'paused' || state === 'buffering') {
                    list.push(entityId);
                }
            }
        }
    }
    return list;
}

/**
 * Stops playback on a target media player.
 * For Jellyfin client devices (e.g. media_player.jellyha_* or default_client_device)
 * or players that do not support turn_off, calls media_player.media_stop.
 * For cast devices or players that support turn_off, calls media_player.turn_off.
 */
export async function stopMediaPlayback(
    hass: HomeAssistant,
    entityId: string,
    config?: JellyHALibraryCardConfig
): Promise<void> {
    if (!hass || !entityId) return;

    const stateObj = hass.states?.[entityId];
    const supportedFeatures = (stateObj?.attributes?.supported_features as number) || 0;
    const supportsTurnOff = Boolean(supportedFeatures & 256);

    const isJellyfinClient =
        entityId.startsWith('media_player.jellyha_') ||
        Boolean(config?.default_client_device && entityId === config.default_client_device);

    if (isJellyfinClient || !supportsTurnOff) {
        await hass.callService('media_player', 'media_stop', { entity_id: entityId });
    } else {
        await hass.callService('media_player', 'turn_off', { entity_id: entityId });
    }
}


