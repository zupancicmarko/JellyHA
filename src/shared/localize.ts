/**
 * Localization helper for JellyHA Library Card
 */

const translations: Record<string, Record<string, string>> = {
    en: {
        loading: 'Loading…',
        no_media: 'No recent media found',
        error: 'Error loading media',
        new: 'New',
        minutes: 'min',
    },
    de: {
        loading: 'Laden…',
        no_media: 'Keine neuen Medien gefunden',
        error: 'Fehler beim Laden der Medien',
        new: 'Neu',
        minutes: 'Min',
    },
    fr: {
        loading: 'Chargement…',
        no_media: 'Aucun média récent trouvé',
        error: 'Erreur lors du chargement des médias',
        new: 'Nouveau',
        minutes: 'min',
    },
    es: {
        loading: 'Cargando…',
        no_media: 'No se encontraron medios recientes',
        error: 'Error al cargar medios',
        new: 'Nuevo',
        minutes: 'min',
    },
    it: {
        loading: 'Caricamento…',
        no_media: 'Nessun media recente trovato',
        error: 'Errore durante il caricamento dei media',
        new: 'Nuovo',
        minutes: 'min',
    },
    nl: {
        loading: 'Laden…',
        no_media: 'Geen recente media gevonden',
        error: 'Fout bij het laden van media',
        new: 'Nieuw',
        minutes: 'min',
    },
};

/**
 * Get localized string
 * @param language - Language code (e.g., 'en', 'de')
 * @param key - Translation key
 * @returns Translated string or key if not found
 */
export function localize(language: string, key: string): string {
    const lang = language.split('-')[0].toLowerCase();

    // Try exact language
    if (translations[lang]?.[key]) {
        return translations[lang][key];
    }

    // Fallback to English
    if (translations.en?.[key]) {
        return translations.en[key];
    }

    // Return key if nothing found
    return key;
}
