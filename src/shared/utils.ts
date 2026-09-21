import { HomeAssistant, MediaItem } from './types';

export function isNewItem(item: MediaItem, newBadgeDays: number): boolean {
    if (!newBadgeDays || !item.date_added) {
        return false;
    }
    const addedDate = new Date(item.date_added);
    const now = new Date();
    const diffDays = (now.getTime() - addedDate.getTime()) / (1000 * 60 * 60 * 24);
    return diffDays <= newBadgeDays;
}

export function formatDate(dateString: string, locale: string = 'en'): string {
    try {
        const date = new Date(dateString);
        const formatter = new Intl.DateTimeFormat(locale, {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
        });
        return formatter.format(date);
    } catch {
        return dateString;
    }
}

export function formatRuntime(minutes: number): string {
    if (minutes < 60) {
        return `${minutes}m`;
    }
    const hours = Math.floor(minutes / 60);
    const mins = minutes % 60;
    return mins > 0 ? `${hours}h ${mins}m` : `${hours}h`;
}

/**
 * Add width param to a signed URL.
 * Appended at the end (after authSig) - not part of the signature.
 * Format defaults to webp in the backend.
 */
export function addImageParams(url: string, width: number): string {
    if (!url) return url;
    if (url.includes('width=')) return url;
    const separator = url.includes('?') ? '&' : '?';
    return `${url}${separator}width=${width}`;
}

/**
 * Resolves the friendly display name for a Home Assistant script or service target.
 * Looks up the entity's friendly_name attribute from hass.states,
 * or formats the entity ID cleanly (e.g. "script.play_on_apple_tv" -> "Play on Apple TV").
 */
export function getScriptDefaultName(hass?: HomeAssistant, serviceId?: string): string {
    if (!serviceId) return 'Run Script';

    const entityId = serviceId.includes('.') ? serviceId : `script.${serviceId}`;
    const name1 = hass?.states?.[entityId]?.attributes?.friendly_name;
    if (typeof name1 === 'string' && name1.trim()) {
        return name1;
    }
    if (serviceId.includes('.')) {
        const name2 = hass?.states?.[serviceId]?.attributes?.friendly_name;
        if (typeof name2 === 'string' && name2.trim()) {
            return name2;
        }
    }

    const rawName = serviceId.includes('.') ? serviceId.split('.').slice(1).join('.') : serviceId;
    return rawName
        .split('_')
        .map(word => {
            if (['on', 'in', 'at', 'to', 'for', 'a', 'an', 'the', 'and', 'or', 'of'].includes(word.toLowerCase())) {
                return word.toLowerCase();
            }
            if (word.toLowerCase() === 'tv') return 'TV';
            return word.charAt(0).toUpperCase() + word.slice(1);
        })
        .join(' ')
        .replace(/^\w/, c => c.toUpperCase());
}


