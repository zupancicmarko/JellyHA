import { MediaItem } from './types';

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
