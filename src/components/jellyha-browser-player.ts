import { LitElement, html, render, nothing, TemplateResult } from 'lit';
import { customElement, property, state } from 'lit/decorators.js';
import { HomeAssistant } from 'custom-card-helpers';
import { MediaItem, MediaStreamInfo } from '../shared/types';

export interface BrowserPlayerParams {
    hass: HomeAssistant;
    item: MediaItem;
    configEntryId?: string;
    serverEntityId?: string;
    subtitleMode?: 'auto' | 'none' | 'forced_only' | 'custom' | string;
    subtitleLanguage?: string;
}

export interface BrowserPlayerSubtitleTrack {
    index: number;
    label: string;
    lang: string;
    url: string;
    isDefault: boolean;
}

const TEXT_SUBTITLE_CODECS = new Set([
    'subrip', 'srt', 'vtt', 'webvtt', 'mov_text', 'ass', 'ssa', 'text', 'ttml'
]);

const LANG_3_TO_2: Record<string, string> = {
    slv: 'sl',
    eng: 'en',
    deu: 'de',
    ger: 'de',
    fre: 'fr',
    fra: 'fr',
    spa: 'es',
    ita: 'it',
    dut: 'nl',
    nld: 'nl',
    hrv: 'hr',
    srp: 'sr',
    bos: 'bs',
    rus: 'ru',
    pol: 'pl',
    ces: 'cs',
    cze: 'cs',
    hun: 'hu',
    jpn: 'ja',
    zho: 'zh',
    chi: 'zh',
};

function matchSubtitleLanguage(streamLang?: string, streamTitle?: string, targetLang?: string): boolean {
    if (!targetLang) return false;
    const target = targetLang.trim().toLowerCase();
    if (!target) return false;

    const baseGroups: Set<string>[] = [
        new Set(['sl', 'slv', 'slovenian', 'slovenski']),
        new Set(['en', 'eng', 'english']),
        new Set(['de', 'ger', 'deu', 'german', 'deutsch']),
        new Set(['fr', 'fre', 'fra', 'french', 'francais', 'français']),
        new Set(['es', 'spa', 'spanish', 'espanol', 'español']),
        new Set(['it', 'ita', 'italian', 'italiano']),
        new Set(['nl', 'dut', 'nld', 'dutch', 'nederlands']),
        new Set(['hr', 'hrv', 'croatian', 'hrvatski']),
        new Set(['sr', 'srp', 'serbian', 'srpski']),
        new Set(['bs', 'bos', 'bosnian', 'bosanski']),
        new Set(['ru', 'rus', 'russian']),
        new Set(['pl', 'pol', 'polish', 'polski']),
        new Set(['cs', 'cze', 'ces', 'czech']),
        new Set(['hu', 'hun', 'hungarian', 'magyar']),
        new Set(['ja', 'jpn', 'japanese']),
        new Set(['zh', 'zho', 'chi', 'chinese', 'zhs', 'zht']),
    ];

    const sLang = (streamLang || '').trim().toLowerCase();
    const sTitle = (streamTitle || '').trim().toLowerCase();

    let targetGroup: Set<string> | undefined;
    for (const group of baseGroups) {
        if (group.has(target)) {
            targetGroup = group;
            break;
        }
    }

    if (targetGroup) {
        if (targetGroup.has(sLang)) return true;
        if (sTitle && Array.from(targetGroup).some(t => sTitle.includes(t))) return true;
    } else {
        if (sLang === target || sLang.startsWith(target)) return true;
        if (sTitle.includes(target)) return true;
    }

    return false;
}

@customElement('jellyha-browser-player')
export class JellyHABrowserPlayer extends LitElement {
    @property({ attribute: false }) public hass!: HomeAssistant;
    @state() private _open = false;
    @state() private _loading = false;
    @state() private _error?: string;
    @state() private _streamUrl?: string;
    @state() private _mimeType = 'video/mp4';
    @state() private _item?: MediaItem;
    @state() private _subtitleTracks: BrowserPlayerSubtitleTrack[] = [];

    private _portalContainer: HTMLElement | null = null;

    public connectedCallback(): void {
        super.connectedCallback();
        window.addEventListener('keydown', this._handleKeyDown);
    }

    public disconnectedCallback(): void {
        super.disconnectedCallback();
        window.removeEventListener('keydown', this._handleKeyDown);
        this._destroyPortal();
    }

    private _handleKeyDown = (e: KeyboardEvent) => {
        if (e.key === 'Escape' && this._open) {
            this.close();
            e.stopPropagation();
        }
    };

    public async play(params: BrowserPlayerParams): Promise<void> {
        this.hass = params.hass;
        this._item = params.item;
        this._open = true;
        this._loading = true;
        this._error = undefined;
        this._streamUrl = undefined;
        this._subtitleTracks = [];
        this._mimeType = params.item.type === 'Audio' ? 'audio/mp4' : 'video/mp4';

        this._ensurePortal();
        this._renderPortal();

        try {
            let playItem = params.item;
            let entryId = params.configEntryId || playItem.config_entry_id || (playItem as any).entry_id;
            if (!entryId && params.serverEntityId && params.hass.states[params.serverEntityId]) {
                entryId = params.hass.states[params.serverEntityId]?.attributes?.config_entry_id;
            }
            if (!entryId) {
                const foundEntity = Object.values(params.hass.states).find(
                    s => s.entity_id.startsWith('sensor.jellyha') && s.attributes?.config_entry_id
                );
                if (foundEntity) {
                    entryId = foundEntity.attributes.config_entry_id;
                }
            }

            // If series, resolve next up episode first if possible
            if (playItem.type === 'Series' || playItem.type === 'Season') {
                try {
                    const nextUpRes = await params.hass.callWS<{ item: MediaItem | null }>({
                        type: 'jellyha/get_next_up',
                        series_id: playItem.id,
                        ...(entryId ? { config_entry_id: entryId } : {}),
                        ...(params.serverEntityId ? { server_entity_id: params.serverEntityId } : {}),
                    });
                    if (nextUpRes?.item) {
                        playItem = nextUpRes.item;
                        this._item = playItem;
                    }
                } catch (e) {
                    console.debug('JellyHA: Could not resolve next up episode for series', e);
                }
            }

            // If video item and media_streams is missing or empty, fetch details via jellyha/get_item
            if (playItem.type !== 'Audio' && (!playItem.media_streams || playItem.media_streams.length === 0)) {
                try {
                    const itemRes = await params.hass.callWS<{ item: MediaItem | null }>({
                        type: 'jellyha/get_item',
                        item_id: playItem.id,
                        ...(entryId ? { config_entry_id: entryId } : {}),
                        ...(params.serverEntityId ? { server_entity_id: params.serverEntityId } : {}),
                    });
                    if (itemRes?.item?.media_streams) {
                        playItem = { ...playItem, media_streams: itemRes.item.media_streams };
                        this._item = playItem;
                    }
                } catch (e) {
                    console.debug('JellyHA: Could not fetch detailed media_streams for item', e);
                }
            }

            const streamInfo = await this._resolveStream({ ...params, item: playItem });
            if (!this._open) return; // Dialog was closed while resolving

            this._streamUrl = streamInfo.url;
            this._mimeType = streamInfo.mimeType;

            if (entryId) {
                const rawTracks = this._resolveSubtitles(playItem, entryId, params);
                // Sign each subtitle track URL so Home Assistant authorizes the browser's track request
                this._subtitleTracks = await Promise.all(
                    rawTracks.map(async (t) => {
                        try {
                            const signRes = await params.hass.callWS<{ path: string }>({
                                type: 'auth/sign_path',
                                path: t.url,
                                expires: 86400,
                            });
                            if (signRes?.path) {
                                return { ...t, url: signRes.path };
                            }
                        } catch (e) {
                            console.warn('JellyHA: Failed to sign subtitle path', t.url, e);
                        }
                        return t;
                    })
                );
            } else {
                this._subtitleTracks = [];
            }

            this._loading = false;
            this._renderPortal();
            this._activateDefaultSubtitle();
        } catch (err: any) {
            console.error('JellyHA: Failed to resolve media stream for browser playback', err);
            if (!this._open) return;
            this._loading = false;
            this._error = err?.message || 'Failed to resolve media stream';
            this._renderPortal();
        }
    }

    private _resolveSubtitles(item: MediaItem, entryId: string, params: BrowserPlayerParams): BrowserPlayerSubtitleTrack[] {
        if (item.type === 'Audio') return [];

        const subStreams = (item.media_streams || []).filter(
            s => s.Type === 'Subtitle' && (s.IsExternal || !s.Codec || TEXT_SUBTITLE_CODECS.has(s.Codec.toLowerCase()))
        );

        if (!subStreams || subStreams.length === 0) return [];

        const mode = (params.subtitleMode || 'auto').toLowerCase();
        const priorityLangs = (params.subtitleLanguage || '')
            .split(',')
            .map(l => l.trim().toLowerCase())
            .filter(Boolean);

        let defaultIndex = -1;

        const findBest = (targetLang: string, forcedOnly = false) => {
            const matches = subStreams.filter(s => {
                if (forcedOnly && !s.IsForced) return false;
                return matchSubtitleLanguage(s.Language, s.DisplayTitle || s.Title, targetLang);
            });
            if (matches.length === 0) return undefined;
            // Prefer non-SDH / non-hearing-impaired tracks
            const nonSdh = matches.find(s => {
                const title = (s.DisplayTitle || s.Title || '').toLowerCase();
                return !s.IsHearingImpaired && !title.includes('sdh') && !title.includes('hearing impaired');
            });
            return nonSdh || matches[0];
        };

        if (mode === 'none') {
            defaultIndex = -1;
        } else if (mode === 'forced_only') {
            // Find forced track matching priority language or any forced track
            for (const lang of priorityLangs) {
                const match = findBest(lang, true);
                if (match) {
                    defaultIndex = match.Index;
                    break;
                }
            }
            if (defaultIndex === -1) {
                const anyForced = subStreams.find(s => s.IsForced);
                if (anyForced) defaultIndex = anyForced.Index;
            }
        } else {
            // Mode is 'auto' or 'custom'
            // 1. Try matching priority languages in order
            for (const lang of priorityLangs) {
                const match = findBest(lang);
                if (match) {
                    defaultIndex = match.Index;
                    break;
                }
            }

            // 2. If no match and mode === 'auto', try user's HA language
            if (defaultIndex === -1 && mode === 'auto') {
                const userLang = (params.hass?.language || '').split('-')[0].toLowerCase();
                if (userLang) {
                    const match = findBest(userLang);
                    if (match) defaultIndex = match.Index;
                }
            }

            // 3. If still no match and mode === 'auto', check for Jellyfin default track
            if (defaultIndex === -1 && mode === 'auto') {
                const defaultStream = subStreams.find(s => s.IsDefault);
                if (defaultStream) defaultIndex = defaultStream.Index;
            }
        }

        const msId = (item as any).media_source_id || (item as any).MediaSources?.[0]?.Id || item.id;
        return subStreams.map(s => {
            const rawLang = (s.Language || 'en').trim().toLowerCase();
            const cleanLang = rawLang.length === 3 ? (LANG_3_TO_2[rawLang] || rawLang) : rawLang;
            const label = s.DisplayTitle || s.Title || (cleanLang ? cleanLang.toUpperCase() : `Subtitle ${s.Index}`);
            const url = `/api/jellyha/subtitles/${entryId}/${item.id}/${s.Index}/stream.vtt?media_source_id=${encodeURIComponent(msId)}`;

            return {
                index: s.Index,
                label,
                lang: cleanLang,
                url,
                isDefault: s.Index === defaultIndex,
            };
        });
    }

    private _setupTextTrackListener(video: HTMLVideoElement): void {
        if ((video as any)._hasJellyHaTrackListener || !video.textTracks) return;
        (video as any)._hasJellyHaTrackListener = true;

        let lock = false;
        video.textTracks.addEventListener('change', () => {
            if (lock) return;
            lock = true;
            try {
                let showingCount = 0;
                for (let i = 0; i < video.textTracks.length; i++) {
                    const t = video.textTracks[i];
                    if (t.mode === 'showing') {
                        showingCount++;
                        if (showingCount > 1) {
                            t.mode = 'disabled';
                        }
                    }
                }
            } finally {
                lock = false;
            }
        });
    }

    private _activateDefaultSubtitle(): void {
        if (!this._portalContainer || !this._subtitleTracks || this._subtitleTracks.length === 0) return;
        const defaultTrack = this._subtitleTracks.find(t => t.isDefault);

        requestAnimationFrame(() => {
            const video = this._portalContainer?.querySelector('video') as HTMLVideoElement | null;
            if (!video || !video.textTracks) return;

            this._setupTextTrackListener(video);

            const targetId = defaultTrack ? `jellyha-track-${defaultTrack.index}` : null;
            let activated = false;
            for (let i = 0; i < video.textTracks.length; i++) {
                const t = video.textTracks[i];
                const isTarget = !!(targetId && (t.id ? t.id === targetId : t.label === defaultTrack?.label));
                if (isTarget && !activated) {
                    t.mode = 'showing';
                    activated = true;
                } else {
                    t.mode = 'disabled';
                }
            }
        });
    }

    public close = () => {
        this._open = false;
        this._loading = false;
        this._error = undefined;

        // Stop any running media
        if (this._portalContainer) {
            const video = this._portalContainer.querySelector('video') as HTMLVideoElement | null;
            if (video) {
                video.pause();
                video.src = '';
                video.load();
            }
            const audio = this._portalContainer.querySelector('audio') as HTMLAudioElement | null;
            if (audio) {
                audio.pause();
                audio.src = '';
                audio.load();
            }
        }

        this._streamUrl = undefined;
        this._subtitleTracks = [];
        this._item = undefined;
        this._renderPortal();
    };

    private async _resolveStream(params: BrowserPlayerParams): Promise<{ url: string; mimeType: string }> {
        const item = params.item;
        const hass = params.hass;

        // 1. Determine config entry ID
        let entryId = params.configEntryId || item.config_entry_id || (item as any).entry_id;
        if (!entryId && params.serverEntityId && hass.states[params.serverEntityId]) {
            entryId = hass.states[params.serverEntityId]?.attributes?.config_entry_id;
        }
        if (!entryId) {
            const foundEntity = Object.values(hass.states).find(
                s => s.entity_id.startsWith('sensor.jellyha') && s.attributes?.config_entry_id
            );
            if (foundEntity) {
                entryId = foundEntity.attributes.config_entry_id;
            }
        }

        let resolvedUrl: string | undefined;
        let mime = item.type === 'Audio' ? 'audio/mp4' : 'video/mp4';

        // 2. Resolve via Home Assistant media_source WebSocket command (Media Browser parity)
        if (entryId) {
            let category = 'video';
            if (item.type === 'Movie') category = 'movie';
            else if (item.type === 'Episode') category = 'episode';
            else if (item.type === 'Series') category = 'series';
            else if (item.type === 'Season') category = 'season';
            else if (item.type === 'Audio') category = 'track';

            const mediaContentId = `media-source://jellyha/${entryId}/${category}/${item.id}`;
            try {
                const res = await hass.callWS<{ url: string; mime_type?: string }>({
                    type: 'media_source/resolve_media',
                    media_content_id: mediaContentId,
                });
                if (res?.url) {
                    resolvedUrl = res.url;
                    if (res.mime_type) mime = res.mime_type;
                }
            } catch (wsErr) {
                console.warn('JellyHA: WebSocket media_source/resolve_media failed, trying direct proxy route', wsErr);
            }
        }

        // 3. Fallback: Directly use authenticated JellyHA stream proxy endpoint
        if (!resolvedUrl && entryId) {
            const mediaType = item.type === 'Audio' ? 'Audio' : 'Videos';
            resolvedUrl = `/api/jellyha/stream/${entryId}/${item.id}?media_type=${mediaType}`;
        }

        if (!resolvedUrl) {
            throw new Error('Unable to determine Jellyfin media stream endpoint.');
        }

        return { url: resolvedUrl, mimeType: mime };
    }

    private _ensurePortal(): void {
        if (!this._portalContainer) {
            this._portalContainer = document.createElement('div');
            this._portalContainer.id = 'jellyha-browser-player-portal';
            document.body.appendChild(this._portalContainer);
        }
    }

    private _destroyPortal(): void {
        if (this._portalContainer) {
            this._portalContainer.remove();
            this._portalContainer = null;
        }
    }

    private _getPortalStyles(): TemplateResult {
        return html`
        <style>
            .jellyha-player-scrim {
                position: fixed;
                inset: 0;
                z-index: 100000;
                background: rgba(0, 0, 0, 0.45);
                backdrop-filter: blur(3px);
                -webkit-backdrop-filter: blur(3px);
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 16px;
                box-sizing: border-box;
                animation: jellyhaFadeIn 0.2s ease-out;
            }

            @keyframes jellyhaFadeIn {
                from { opacity: 0; }
                to { opacity: 1; }
            }

            @keyframes jellyhaScaleIn {
                from { transform: scale(0.96); opacity: 0; }
                to { transform: scale(1); opacity: 1; }
            }

            .jellyha-player-surface {
                position: relative;
                display: flex;
                flex-direction: column;
                background: #14161f;
                color: #ffffff;
                box-sizing: border-box;
                border-radius: 20px;
                border: var(--ha-card-border, var(--ha-card-border-width, 1px) solid var(--ha-card-border-color, var(--divider-color, rgba(255, 255, 255, 0.14))));
                box-shadow: 0 24px 72px rgba(0, 0, 0, 0.85);
                width: min(960px, 95vw);
                max-height: min(92vh, 880px);
                overflow: hidden;
                animation: jellyhaScaleIn 0.22s cubic-bezier(0.16, 1, 0.3, 1);
            }

            .jellyha-player-header {
                display: flex;
                align-items: center;
                justify-content: space-between;
                padding: 14px 20px;
                background: rgba(255, 255, 255, 0.03);
                border-bottom: 1px solid rgba(255, 255, 255, 0.08);
                gap: 12px;
            }

            .jellyha-player-title-wrap {
                display: flex;
                flex-direction: column;
                min-width: 0;
            }

            .jellyha-player-subtitle {
                font-size: 0.78rem;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 0.04em;
                color: #03a9f4;
                white-space: nowrap;
                overflow: hidden;
                text-overflow: ellipsis;
            }

            .jellyha-player-title {
                font-size: 1.05rem;
                font-weight: 700;
                color: #ffffff;
                white-space: nowrap;
                overflow: hidden;
                text-overflow: ellipsis;
            }

            .jellyha-player-close-btn {
                background: rgba(255, 255, 255, 0.1);
                backdrop-filter: blur(8px);
                -webkit-backdrop-filter: blur(8px);
                border: 1px solid rgba(255, 255, 255, 0.2);
                border-radius: 50%;
                width: 34px;
                height: 34px;
                display: flex;
                align-items: center;
                justify-content: center;
                cursor: pointer;
                color: #ffffff;
                transition: all 0.2s ease;
                padding: 0;
                flex-shrink: 0;
            }

            .jellyha-player-close-btn:hover {
                background: rgba(255, 255, 255, 0.2);
                transform: scale(1.06);
            }

            .jellyha-player-content {
                display: flex;
                flex-direction: column;
                align-items: center;
                justify-content: center;
                padding: 0;
                background: #000000;
                min-height: 240px;
            }

            .jellyha-player-video {
                width: 100%;
                max-height: min(78vh, 640px);
                aspect-ratio: 16/9;
                background: #000000;
                outline: none;
                display: block;
            }

            .jellyha-player-audio-wrap {
                display: flex;
                flex-direction: column;
                align-items: center;
                justify-content: center;
                padding: 32px 24px;
                width: 100%;
                box-sizing: border-box;
                gap: 20px;
                background: linear-gradient(180deg, #181b28 0%, #10121a 100%);
            }

            .jellyha-player-audio-poster {
                width: 140px;
                height: 140px;
                border-radius: 16px;
                object-fit: cover;
                box-shadow: 0 12px 32px rgba(0, 0, 0, 0.6);
            }

            .jellyha-player-audio {
                width: min(500px, 90%);
                outline: none;
            }

            .jellyha-player-loading,
            .jellyha-player-error {
                display: flex;
                flex-direction: column;
                align-items: center;
                justify-content: center;
                padding: 48px 24px;
                gap: 16px;
                color: rgba(255, 255, 255, 0.85);
                text-align: center;
            }

            .jellyha-spinner {
                width: 36px;
                height: 36px;
                border: 3px solid rgba(255, 255, 255, 0.15);
                border-top-color: #03a9f4;
                border-radius: 50%;
                animation: jellyhaSpin 0.8s linear infinite;
            }

            @keyframes jellyhaSpin {
                to { transform: rotate(360deg); }
            }
        </style>
        `;
    }

    private _renderPortal(): void {
        if (!this._portalContainer) return;

        if (!this._open) {
            render(html``, this._portalContainer);
            return;
        }

        const item = this._item;
        const isAudio = item?.type === 'Audio';

        let subtitleText = '';
        let titleText = item?.name || 'Playing Media';

        if (item?.type === 'Episode') {
            subtitleText = item.series_name || '';
            const epNum = item.season != null && item.episode != null ? `S${item.season}:E${item.episode} • ` : '';
            titleText = `${epNum}${item.name || 'Episode'}`;
        } else if (item?.type === 'Movie' && item?.year) {
            subtitleText = `${item.year}`;
        } else if (isAudio && item?.artist_name) {
            subtitleText = item.artist_name;
        }

        const portalTemplate = html`
            ${this._getPortalStyles()}
            <div class="jellyha-player-scrim" @click=${this.close}>
                <div class="jellyha-player-surface" @click=${(e: Event) => e.stopPropagation()}>
                    <div class="jellyha-player-header">
                        <div class="jellyha-player-title-wrap">
                            ${subtitleText ? html`<span class="jellyha-player-subtitle">${subtitleText}</span>` : nothing}
                            <span class="jellyha-player-title" title="${titleText}">${titleText}</span>
                        </div>
                        <button class="jellyha-player-close-btn" @click=${this.close} aria-label="Close" title="Close">
                            <ha-icon icon="mdi:close"></ha-icon>
                        </button>
                    </div>

                    <div class="jellyha-player-content">
                        ${this._loading ? html`
                            <div class="jellyha-player-loading">
                                <div class="jellyha-spinner"></div>
                                <span>Loading stream...</span>
                            </div>
                        ` : this._error ? html`
                            <div class="jellyha-player-error">
                                <ha-icon icon="mdi:alert-circle-outline" style="--mdc-icon-size: 40px; color: #ff5252;"></ha-icon>
                                <span>${this._error}</span>
                            </div>
                        ` : isAudio ? html`
                            <div class="jellyha-player-audio-wrap">
                                ${item?.poster_url ? html`
                                    <img class="jellyha-player-audio-poster" src="${item.poster_url}" alt="" />
                                ` : nothing}
                                <audio class="jellyha-player-audio" controls autoplay>
                                    <source src="${this._streamUrl}" type="${this._mimeType}">
                                    Audio format not supported.
                                </audio>
                            </div>
                        ` : html`
                            <video class="jellyha-player-video" controls autoplay playsinline crossorigin="anonymous" @loadedmetadata=${() => this._activateDefaultSubtitle()}>
                                <source src="${this._streamUrl}" type="${this._mimeType}">
                                ${this._subtitleTracks.map(track => html`
                                    <track
                                        id="jellyha-track-${track.index}"
                                        kind="subtitles"
                                        label="${track.label}"
                                        srclang="${track.lang}"
                                        src="${track.url}"
                                    >
                                `)}
                                Video format not supported.
                            </video>
                        `}
                    </div>
                </div>
            </div>
        `;

        render(portalTemplate, this._portalContainer);
    }

    protected render(): TemplateResult | typeof nothing {
        return nothing;
    }
}

// Global helper for opening the browser player
let _globalPlayerInstance: JellyHABrowserPlayer | null = null;

export async function showJellyHABrowserPlayer(params: BrowserPlayerParams): Promise<void> {
    if (!_globalPlayerInstance || !document.body.contains(_globalPlayerInstance)) {
        _globalPlayerInstance = document.createElement('jellyha-browser-player') as JellyHABrowserPlayer;
        document.body.appendChild(_globalPlayerInstance);
    }
    await _globalPlayerInstance.play(params);
}

declare global {
    interface HTMLElementTagNameMap {
        'jellyha-browser-player': JellyHABrowserPlayer;
    }
}
