import { LitElement, html, TemplateResult, css, PropertyValues, nothing } from 'lit';
import { customElement, property, state } from 'lit/decorators.js';
import {
    HomeAssistant,
    JellyHANowPlayingCardConfig,
    NowPlayingSensorData
} from '../shared/types';
import { localize } from '../shared/localize';
import { formatRuntime } from '../shared/utils';

// Import editor for side effects
import '../editors/jellyha-now-playing-editor';

// Register card in the custom cards array
(window as any).customCards = (window as any).customCards || [];
(window as any).customCards.push({
    type: 'jellyha-now-playing-card',
    name: 'JellyHA Now Playing',
    description: 'Display currently playing media from Jellyfin',
    preview: true,
});

@customElement('jellyha-now-playing-card')
export class JellyHANowPlayingCard extends LitElement {
    @property({ attribute: false }) public hass!: HomeAssistant;
    @state() private _config!: JellyHANowPlayingCardConfig;
    @state() private _rewindActive: boolean = false;
    @state() private _overflowState: number = 0; // 0=All, 1=Hide Genres, 2=Hide Meta
    private _resizeObserver?: ResizeObserver;

    public setConfig(config: JellyHANowPlayingCardConfig): void {
        this._config = {
            show_title: true,
            show_media_type_badge: true,
            show_year: true,
            show_client: true,
            show_background: true,
            show_genres: true,
            show_ratings: true,
            show_runtime: true,
            ...config,
        };
    }

    public static getConfigElement(): HTMLElement {
        return document.createElement('jellyha-now-playing-editor');
    }

    public static getStubConfig(hass: HomeAssistant): Partial<JellyHANowPlayingCardConfig> {
        const entities = Object.keys(hass.states);
        const entity = entities.find((e) => e.startsWith('sensor.jellyha_now_playing_')) || '';
        return {
            entity,
            show_title: true,
            show_media_type_badge: true,
            show_year: true,
            show_client: true,
            show_background: true,
            show_genres: true,
            show_ratings: true,
            show_runtime: true,
        };
    }

    public getCardSize(): number {
        return 3;
    }

    public getLayoutOptions() {
        return {
            grid_rows: 3,
            grid_columns: 12,
        };
    }

    public getGridOptions() {
        return {
            columns: 12,
            rows: 3,
            min_columns: 6,
            min_rows: 3,
            max_rows: 5
        };
    }

    protected render(): TemplateResult {
        if (!this.hass || !this._config) {
            return html``;
        }

        const entityId = this._config.entity;
        if (!entityId) {
            return this._renderError('Please configure a JellyHA Now Playing sensor entity');
        }

        const stateObj = this.hass.states[entityId];
        if (!stateObj) {
            return this._renderError(localize(this.hass.language, 'entity_not_found') || 'Entity not found');
        }

        const attributes = stateObj.attributes as unknown as NowPlayingSensorData;
        const isPlaying = !!attributes.item_id;

        if (!isPlaying) {
            return this._renderEmpty();
        }

        const progressPercent = attributes.progress_percent || 0;
        const imageUrl = attributes.image_url;

        const backdropUrl = attributes.backdrop_url;
        const showBackground = this._config.show_background && backdropUrl;
        const isPaused = attributes.is_paused;

        return html`
            <ha-card class="jellyha-now-playing ${showBackground ? 'has-background' : ''} ${this._config.title ? 'has-title' : ''}">
                ${showBackground ? html`
                    <div class="card-background" style="background-image: url('${backdropUrl}')"></div>
                    <div class="card-overlay"></div>
                ` : nothing}
                
                <div class="card-content">
                    ${this._config.title ? html`
                        <div class="card-header">${this._config.title}</div>
                    ` : nothing}
                    
                    <div class="main-container">
                        ${imageUrl ? html`
                            <div class="poster-container" @click=${this._handlePosterRewind}>
                                <img src="${imageUrl}" alt="${attributes.title}" />
                                ${this._rewindActive ? html`
                                    <div class="rewind-overlay">
                                        <span>REWINDING</span>
                                    </div>
                                ` : nothing}
                            </div>
                        ` : nothing}
                        
                        <div class="info-container">
                            <div class="info-top">
                                <div class="header">
                                    ${this._config.show_title !== false ? html`<div class="title">${attributes.title}</div>` : nothing}
                                    ${attributes.series_title ? html`<div class="series">${attributes.series_title}</div>` : nothing}
                                    ${this._config.show_client !== false ? html`
                                        <div class="device-info">
                                            <span>${attributes.device_name} (${attributes.client})</span>
                                        </div>
                                    ` : nothing}
                                </div>

                                ${this._overflowState < 2 ? html`
                                    <div class="meta-container">
                                        ${this._config.show_media_type_badge !== false ? html`
                                            <span class="badge meta-priority-4 ${attributes.media_type?.toLowerCase()}">${attributes.media_type}</span>
                                        ` : nothing}
                                        ${this._config.show_year !== false && attributes.year ? html`
                                            <span class="meta-item meta-priority-3">${attributes.year}</span>
                                        ` : nothing}
                                        ${this._config.show_runtime && attributes.runtime_minutes ? html`
                                            <span class="meta-item meta-priority-2">${formatRuntime(attributes.runtime_minutes)}</span>
                                        ` : nothing}
                                        ${this._config.show_ratings && attributes.community_rating ? html`
                                            <span class="meta-item external-rating meta-priority-1">
                                                <ha-icon icon="mdi:star"></ha-icon>
                                                <span>${attributes.community_rating.toFixed(1)}</span>
                                            </span>
                                        ` : nothing}
                                    </div>
                                ` : nothing}

                                ${this._overflowState < 1 && this._config.show_genres && attributes.genres?.length ? html`
                                    <div class="genres-container meta-priority-0">
                                        <div class="genres">${attributes.genres.join(', ')}</div>
                                    </div>
                                ` : nothing}
                            </div>

                            <div class="info-bottom">
                                <div class="controls-container">
                                    ${this._config.show_client !== false ? html`
                                        <div class="device-info bottom-device-info">
                                            <span>${attributes.device_name} (${attributes.client})</span>
                                        </div>
                                    ` : nothing}

                                    <div class="playback-controls">
                                        ${this._rewindActive ? html`
                                            <ha-icon-button class="spinning" .label=${'Loading'}>
                                                <ha-icon icon="mdi:loading"></ha-icon>
                                            </ha-icon-button>
                                        ` : isPaused ? html`
                                            <ha-icon-button .label=${'Play'} @click=${() => this._handleControl('Unpause')}>
                                                <ha-icon icon="mdi:play"></ha-icon>
                                            </ha-icon-button>
                                        ` : html`
                                            <ha-icon-button .label=${'Pause'} @click=${() => this._handleControl('Pause')}>
                                                <ha-icon icon="mdi:pause"></ha-icon>
                                            </ha-icon-button>
                                        `}
                                        <ha-icon-button .label=${'Stop'} @click=${() => this._handleControl('Stop')}>
                                            <ha-icon icon="mdi:stop"></ha-icon>
                                        </ha-icon-button>
                                    </div>
                                </div>

                                <div class="progress-container" @click=${this._handleSeek}>
                                    <div class="progress-bar">
                                        <div class="progress-fill" style="width: ${progressPercent}%"></div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </ha-card>
        `;
    }

    private _phrases: string[] = [];

    private async _fetchPhrases(): Promise<void> {
        if (this._phrases.length > 0) return;
        try {
            const response = await fetch('/jellyha_static/now_playing_phrases.json');
            if (response.ok) {
                this._phrases = await response.json();
            }
        } catch (e) {
            console.warn('JellyHA: Could not fetch phrases.json', e);
        }
    }

    private _renderEmpty(): TemplateResult {
        this._fetchPhrases(); // Trigger async fetch

        const isDarkMode = this.hass.themes?.darkMode;
        const logoUrl = isDarkMode
            ? 'https://raw.githubusercontent.com/home-assistant/brands/master/custom_integrations/jellyha/dark_logo.png'
            : 'https://raw.githubusercontent.com/home-assistant/brands/master/custom_integrations/jellyha/logo.png';
        const iconUrl = 'https://raw.githubusercontent.com/home-assistant/brands/master/custom_integrations/jellyha/icon.png';

        let phrase = "Nothing is currently playing";

        if (this._phrases.length > 0) {
            const daySeed = Math.floor(Date.now() / (1000 * 60 * 60 * 24));
            const phraseIndex = daySeed % this._phrases.length;
            phrase = this._phrases[phraseIndex];

            // Get unwatched number - look for any sensor ending in _unwatched
            const unwatchedSensor = Object.keys(this.hass.states).find(e => e.startsWith('sensor.') && e.endsWith('_unwatched'));
            const count = unwatchedSensor ? this.hass.states[unwatchedSensor].state : "0";

            phrase = phrase.replace(/\[number\]/g, count);
        }

        return html`
            <ha-card class="jellyha-now-playing empty-state">
                <div class="card-content">
                    <div class="logo-container full-logo">
                        <img src="${logoUrl}" alt="JellyHA Logo" />
                    </div>
                    <div class="logo-container mini-icon">
                        <img src="${iconUrl}" alt="JellyHA Icon" />
                    </div>
                    <p>${phrase}</p>
                </div>
            </ha-card>
        `;
    }

    private _renderError(error: string): TemplateResult {
        return html`
            <ha-card class="error-state">
                <div class="card-content">
                    <p>${error}</p>
                </div>
            </ha-card>
        `;
    }

    private async _handleControl(command: string): Promise<void> {
        const stateObj = this.hass.states[this._config.entity];
        const sessionId = stateObj?.attributes.session_id;

        if (!sessionId) return;

        await this.hass.callService('jellyha', 'session_control', {
            session_id: sessionId,
            command: command
        });
    }

    private async _handleSeek(e: MouseEvent): Promise<void> {
        const rect = (e.currentTarget as HTMLElement).getBoundingClientRect();
        const percent = (e.clientX - rect.left) / rect.width;

        const stateObj = this.hass.states[this._config.entity];
        if (!stateObj) return;

        const attributes = stateObj.attributes as unknown as NowPlayingSensorData;
        const sessionId = attributes.session_id;
        const positionTicks = attributes.position_ticks || 0;
        const progressPercent = attributes.progress_percent || 1;
        const durationTicks = (positionTicks / progressPercent) * 100;

        if (!sessionId || !durationTicks) return;

        const seekTicks = Math.round(durationTicks * percent);

        await this.hass.callService('jellyha', 'session_seek', {
            session_id: sessionId,
            position_ticks: seekTicks
        });
    }

    private async _handlePosterRewind(): Promise<void> {
        const stateObj = this.hass.states[this._config.entity];
        if (!stateObj) return;

        const attributes = stateObj.attributes as unknown as NowPlayingSensorData;
        const sessionId = attributes.session_id;
        const positionTicks = attributes.position_ticks || 0;

        if (!sessionId) return;

        // Visual feedback
        this._rewindActive = true;
        setTimeout(() => {
            this._rewindActive = false;
        }, 1000);

        // Haptic feedback
        const event = new CustomEvent('haptic', {
            detail: 'selection',
            bubbles: true,
            composed: true,
        });
        this.dispatchEvent(event);

        // Calculate rewind position (20 seconds = 200,000,000 ticks)
        const rewindTicks = 20 * 10000000; // 20 seconds in ticks
        const newPositionTicks = Math.max(0, positionTicks - rewindTicks);

        await this.hass.callService('jellyha', 'session_seek', {
            session_id: sessionId,
            position_ticks: newPositionTicks
        });
    }

    public connectedCallback(): void {
        super.connectedCallback();
        this._resizeObserver = new ResizeObserver(() => {
            this._checkLayout();
        });
        this._resizeObserver.observe(this);
    }

    public disconnectedCallback(): void {
        super.disconnectedCallback();
        if (this._resizeObserver) {
            this._resizeObserver.disconnect();
        }
    }

    protected updated(changedProps: PropertyValues): void {
        super.updated(changedProps);
        if (changedProps.has('hass')) {
            this._checkLayout();
        }
    }

    private _checkLayout(): void {
        // Use requestAnimationFrame to ensure DOM is rendered
        requestAnimationFrame(() => {
            this._doLayoutCheck();
        });
    }

    private _doLayoutCheck(): void {
        const titleEl = this.shadowRoot?.querySelector('.title') as HTMLElement;
        const bottomEl = this.shadowRoot?.querySelector('.info-bottom') as HTMLElement;

        if (!titleEl || !bottomEl) return;

        const cardRect = this.getBoundingClientRect();
        const titleRect = titleEl.getBoundingClientRect();
        const bottomRect = bottomEl.getBoundingClientRect();

        // Calculate dynamic threshold based on where controls actually start
        const bottomSectionTop = bottomRect.top - cardRect.top;

        // Add a small buffer to ensure visual separation
        const SAFE_THRESHOLD = bottomSectionTop - 8;

        // Estimated heights
        const PROJECTED_META_HEIGHT = 28;
        const PROJECTED_GENRE_HEIGHT = 22;

        const titleBottomRel = titleRect.bottom - cardRect.top;

        const projectedMetaBottom = titleBottomRel + PROJECTED_META_HEIGHT;
        const projectedGenreBottom = projectedMetaBottom + PROJECTED_GENRE_HEIGHT;

        let newState = 0;

        // Check Logic (Applies to ALL card sizes):
        if (projectedGenreBottom > SAFE_THRESHOLD) {
            newState = 1; // Hide Genre
        }

        // If even meta row overlaps, hide it too
        if (projectedMetaBottom > SAFE_THRESHOLD) {
            newState = 2; // Hide Meta + Genre
        }

        if (this._overflowState !== newState) {
            this._overflowState = newState;
        }
    }

    static styles = css`
        :host {
            display: block;
            height: 100%;
            overflow: hidden;
        }
        ha-card {
            height: 100%;
            overflow: hidden;
        }
        .jellyha-now-playing {
            overflow: hidden;
            position: relative;
            background: var(--ha-card-background, var(--card-background-color, #fff));
            border-radius: var(--ha-card-border-radius, 12px);
            transition: all 0.3s ease-out;
            container-type: size;
            container-name: now-playing;
            height: 100%;
            display: flex;
            flex-direction: column;
            box-sizing: border-box;
            min-height: 0;
            padding: 0;
        }
        .jellyha-now-playing.has-background {
            background: transparent;
            color: white;
        }
        .jellyha-now-playing.has-background .title,
        .jellyha-now-playing.has-background .series,
        .jellyha-now-playing.has-background .device-info,
        .jellyha-now-playing.has-background .meta-item,
        .jellyha-now-playing.has-background .genres,
        .jellyha-now-playing.has-background .card-header,
        .jellyha-now-playing.has-background ha-icon-button {
            color: #fff !important;
            text-shadow: 0 1px 4px rgba(0,0,0,0.5);
        }
        .jellyha-now-playing.has-background .badge {
            box-shadow: 0 2px 4px rgba(0,0,0,0.3);
        }
        .jellyha-now-playing.has-background .playback-controls ha-icon-button {
            background: rgba(255, 255, 255, 0.15);
        }
        .jellyha-now-playing.has-background .playback-controls ha-icon-button:hover {
            background: rgba(255, 255, 255, 0.25);
        }
        /* Further increase padding when background is on for better balance */
        .jellyha-now-playing.has-background .card-content {
            padding: 24px 20px 12px !important;
        }
        .card-background {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-size: cover;
            background-position: center;
            filter: blur(5px) brightness(0.6);
            transform: scale(1.02);
            z-index: 0;
            transition: background-image 0.5s ease-in-out;
        }
        .card-overlay {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: linear-gradient(to bottom, rgba(0,0,0,0.2) 0%, rgba(0,0,0,0.6) 100%);
            z-index: 1;
        }
        .card-content {
            position: relative;
            z-index: 2;
            padding: 20px !important;
            display: flex;
            flex-direction: column;
            gap: 16px;
            height: 100%;
            box-sizing: border-box;
            overflow: visible; /* Allow poster pop-out */
        }
        .card-header {
            font-size: 1.25rem;
            font-weight: 500;
            color: var(--primary-text-color);
            line-height: 1.2;
            flex: 0 0 auto;
        }
        .main-container {
            display: flex;
            gap: 20px;
            align-items: flex-start;
            flex: 1;
            min-height: 0; /* Crucial for nested flex scrolling/hiding */
            overflow: visible;
        }
        .poster-container {
            flex: 0 0 auto;
            height: 100%;
            aspect-ratio: 2 / 3;
            max-height: 100%;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 8px 16px rgba(0,0,0,0.4);
            transition: transform 0.2s ease-in-out;
            position: relative;
            cursor: pointer;
        }
        .poster-container:hover {
            transform: scale(1.02);
        }
        .poster-container img {
            width: 100%;
            height: 100%;
            object-fit: cover;
        }
        .rewind-overlay {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.4);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 10;
            animation: fadeIn 0.2s ease-out;
        }
        .rewind-overlay span {
            color: white;
            font-weight: 700;
            font-size: 0.8rem; /* Small fixed size */
            letter-spacing: 0.5px;
            background: var(--primary-color);
            padding: 2px 6px;
            border-radius: 4px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.3);
            transform: translateY(-8px);
            white-space: nowrap; /* Prevent wrapping */
        }
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
        @keyframes spin {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }
        .playback-controls .spinning ha-icon {
            animation: spin 1s linear infinite;
        }
        .info-container {
            flex: 1;
            display: flex;
            flex-direction: column;
            height: 100%;
            min-height: 0; /* Crucial */
            min-width: 0;
            overflow: hidden;
        }
        .info-top {
            flex: 1 1 auto; /* Can shrink and grow */
            min-height: 0; /* Allows shrinking below content size */
            overflow: visible; /* Hide overflow content */
            display: flex;
            flex-direction: column;
            margin-bottom: 0;
            padding-bottom: 4px; /* Prevent text clipping at bottom */
        }
        .header {
            margin-bottom: 0px;
            flex-shrink: 0; /* Don't squash the title too easily if possible */
        }
        .title {
            font-size: 1.4rem;
            font-weight: 700;
            line-height: 1.2;
            color: var(--primary-text-color);
            margin-bottom: 2px;
        }
        .series {
            font-size: 1.1rem;
            color: var(--secondary-text-color);
            font-weight: 500;
        }
        .device-info {
            display: flex;
            align-items: center;
            gap: 6px;
            font-size: 0.95rem;
            color: var(--secondary-text-color);
            margin-top: 8px;
            opacity: 0.8;
        }
        .device-info ha-icon {
            --mdc-icon-size: 18px;
        }
        .meta-container {
            display: flex;
            flex-wrap: nowrap;
            gap: 12px;
            align-items: center;
            white-space: nowrap;
        }

        .bottom-device-info {
            display: flex;
            align-items: center;
            gap: 6px;
            font-size: 0.8rem;
            color: var(--secondary-text-color);
            margin-right: auto; /* Push controls to right */
            opacity: 0.8;
        }

        /* Default: Hide top device info, show bottom device info */
        .info-top .device-info {
            display: none;
        }
        
        /* Ensure controls spread out when bottom info is present */
        .controls-container {
            justify-content: space-between;
            align-items: center;
        }
        
        /* When card is too narrow, HIDE bottom device info to prevent crowding */
        @container now-playing (max-width: 350px) {
            .bottom-device-info {
                display: none !important;
            }
            .controls-container {
                justify-content: flex-end; /* Revert to right align */
            }
        }
        
        /* For 5+ row cards, hide device info sooner to prevent overflow */
        @container now-playing (min-height: 300px) and (max-width: 430px) {
            .bottom-device-info {
                display: none !important;
            }
        }
        
        /* Progressive metadata hiding based on priority */
        /* Hide genres first (priority 0) */
        @container now-playing (max-width: 400px) {
            .meta-priority-0 {
                display: none !important;
            }
        }
        
        /* Hide rating (priority 1) */
        @container now-playing (max-width: 370px) {
            .meta-priority-1 {
                display: none !important;
            }
        }
        
        /* Hide runtime (priority 2) */
        @container now-playing (max-width: 320px) {
            .meta-priority-2 {
                display: none !important;
            }
        }
        
        /* Hide year (priority 3) */
        @container now-playing (max-width: 260px) {
            .meta-priority-3 {
                display: none !important;
            }
        }
        
        /* Hide badge last (priority 4) - only in ultra-compact mode */
        @container now-playing (max-width: 220px) {
            .meta-priority-4 {
                display: none !important;
            }
        }
        
        /* Hide badge when card has title AND is short AND narrow (3 rows × 6 columns) to prevent overlap with controls */
        .has-title .meta-priority-4 {
            /* Default: show the badge */
        }
        @container now-playing (max-height: 180px) and (max-width: 320px) {
            .has-title .meta-priority-4 {
                display: none !important;
            }
        }

        /* When card is tall enough (4+ rows ≈ 240px), enable wrapping instead of hiding */
        @container now-playing (min-height: 240px) {
            .meta-container {
                flex-wrap: wrap;
                white-space: normal;
            }
            .info-top {
                overflow: visible;
            }
        }
        
        /* When tall AND narrow, show items that would normally hide (they'll wrap instead) */
        @container now-playing (min-height: 240px) and (max-width: 400px) {
            .meta-priority-0 {
                display: block !important;
            }
        }
        @container now-playing (min-height: 240px) and (max-width: 370px) {
            .meta-priority-1 {
                display: flex !important;
            }
        }
        @container now-playing (min-height: 240px) and (max-width: 320px) {
            .meta-priority-2 {
                display: flex !important;
            }
        }
        @container now-playing (min-height: 240px) and (max-width: 260px) {
            .meta-priority-3 {
                display: flex !important;
            }
        }
        .badge {
            padding: 2px 8px 1px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 800;
            background: var(--primary-color);
            color: white;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            flex-shrink: 0; /* Prevent badge from shrinking */
            overflow: visible; /* Ensure rounded corners aren't clipped */
        }
        .badge.movie { background-color: #AA5CC3; }
        .badge.series { background-color: #F2A218; }
        .badge.episode { background-color: #F59E0B; }

        .meta-item {
            color: var(--secondary-text-color);
            font-size: 0.9rem;
            font-weight: 500;
        }
        .meta-item.external-rating {
            display: flex;
            align-items: center;
            gap: 4px;
            background: rgba(var(--rgb-primary-text-color), 0.08);
            padding: 2px 0px;
            border-radius: 4px;
            border: 1px solid rgba(var(--rgb-primary-text-color), 0.1);
        }
        .meta-item.external-rating ha-icon {
            --mdc-icon-size: 14px;
            color: #F59E0B;
        }
        .genres-container {
            flex-shrink: 0;
            overflow: visible;
            margin-bottom: -4px;
            position: relative;
            z-index: 4; /* Ensure it stays above other elements if needed */
        }
        .genres {
            font-size: 0.95rem;
            color: var(--secondary-text-color);
            margin: 0;
            font-style: italic;
            opacity: 0.7;
            white-space: nowrap;
            text-overflow: ellipsis;
            overflow: hidden;
        }
        .info-bottom {
            flex: 0 0 auto; /* Never shrink */
            width: 100%;
            margin-top: auto;
            z-index: 5;
        }
        .controls-container {
            display: flex;
            justify-content: flex-end;
            margin-bottom: 6px;
        }
        .playback-controls {
            display: flex;
            gap: 12px;
            align-items: center;
        }
        .playback-controls ha-icon-button {
            --mdc-icon-button-size: 40px;
            --mdc-icon-size: 28px;
            color: var(--primary-text-color);
            background: rgba(var(--rgb-primary-text-color), 0.05);
            border-radius: 50%;
            transition: background 0.2s;
        }
        .playback-controls ha-icon-button:hover {
            background: rgba(var(--rgb-primary-text-color), 0.1);
        }
        .playback-controls ha-icon-button ha-icon {
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .progress-container {
            height: 6px;
            background: rgba(var(--rgb-primary-text-color), 0.15); /* Slightly darker for visibility */
            cursor: pointer;
            position: relative;
            border-radius: 3px;
            overflow: hidden;
            width: 100%;
        }
        .has-background .progress-container {
            background: rgba(255, 255, 255, 0.2); /* Much clearer on backdrop */
        }
        .progress-bar {
            height: 100%;
            width: 100%;
        }
        .progress-fill {
            height: 100%;
            background: var(--primary-color);
            transition: width 1s linear;
        }
        .empty-state, .error-state {
            text-align: center;
            padding: 20px;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            height: 100%;
            box-sizing: border-box;
        }
        .empty-state .card-content {
            padding: 0 !important;
            gap: 8px;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            overflow: visible;
            height: auto;
        }
        .empty-state .logo-container.mini-icon {
            display: none;
        }
        .empty-state .logo-container.full-logo {
            display: flex;
            justify-content: center;
            opacity: 0.9;
            margin-bottom: 4px;
        }
        .empty-state img {
            max-width: 200px;
            height: auto;
        }
        .empty-state p {
            margin: 0;
            color: var(--secondary-text-color);
            font-size: 0.9rem;
            opacity: 0.7;
        }

        /* Container Queries for Responsive Information Throttling */
        @container now-playing (max-width: 250px) {
            .empty-state .logo-container.full-logo {
                display: none;
            }
            .empty-state .logo-container.mini-icon {
                display: flex;
                opacity: 0.9;
                margin-bottom: 12px;
            }
            .empty-state img {
                max-width: 80px;
            }
            .empty-state p {
                font-size: 0.9rem;
            }
        }

        /* Standard Tier Hiding (Width based) */
        @container now-playing (max-width: 320px) {
            .genres, .device-info {
                display: none !important;
            }
            .title {
                font-size: 1.25rem;
                margin-bottom: 2px;
            }
        }

        /* Vertical Tier Hiding (Height based - for very short cards) */
        @container now-playing (max-height: 160px) {
            .genres, .device-info {
                display: none !important;
            }
            .meta-container, .card-header {
                display: none !important;
            }
            .meta-container {
                margin-top: 4px;
            }
            .title {
                font-size: 1.2rem;
                line-height: 1.1;
                margin-bottom: 2px;
            }
            .main-container {
                gap: 12px;
            }
            .card-content {
                gap: 8px;
            }
            .info-top {
                justify-content: center;
            }
        }

        @container now-playing (max-width: 280px) {
           .main-container {
                gap: 12px;
            }
            .poster-container {
                flex: 0 0 80px;
                height: 120px;
            }
            .title {
                font-size: 1.1rem;
                display: -webkit-box;
                -webkit-line-clamp: 2;
                -webkit-box-orient: vertical;
                overflow: hidden;
            }
        }

        /* Ultra-Compact Micro Mode (Overlay controls on poster) */
        @container now-playing (max-width: 220px) {
            .card-header, .info-top {
                display: none !important;
            }
            .card-content {
                padding: 10px !important;
                justify-content: center;
                gap: 0;
            }
            .main-container {
                justify-content: center;
                gap: 0;
                position: relative;
                width: 100%;
            }
            .poster-container {
                flex: 0 0 auto !important;
                height: 100% !important;
                aspect-ratio: 2 / 3;
                box-shadow: 0 4px 12px rgba(0,0,0,0.5);
            }
            .info-container {
                position: absolute;
                top: 0;
                left: 50%;
                transform: translateX(-50%);
                width: auto;
                height: 100%;
                aspect-ratio: 2 / 3;
                background: linear-gradient(to bottom, transparent 30%, rgba(0,0,0,0.6) 80%, rgba(0,0,0,0.85) 100%);
                display: flex;
                flex-direction: column;
                justify-content: flex-end;
                border-radius: 8px;
                padding: 10px;
                box-sizing: border-box;
                pointer-events: none;
                z-index: 5;
                overflow: visible;
            }
            .info-bottom {
                pointer-events: auto;
                flex: 0 0 auto;
            }
            .controls-container {
                justify-content: center;
                margin-bottom: 8px;
            }
            .playback-controls ha-icon-button {
                --mdc-icon-button-size: 40px;
                --mdc-icon-size: 28px;
                background: rgba(255, 255, 255, 0.2);
                color: white !important;
            }
            .progress-container {
                height: 4px;
                background: rgba(255, 255, 255, 0.3);
            }
            .progress-fill {
                background: #18BCF2;
            }
            .rewind-overlay span {
                font-size: 0.75rem !important;
                padding: 2px 5px !important;
                white-space: nowrap;
            }
        }

        /* Height-Based Compact Mode (Overlay controls when vertically constrained) */
        @container now-playing (max-height: 180px) {
            .card-header, .info-top {
                display: none !important;
            }
            .card-content {
                padding: 10px !important;
                justify-content: center;
                gap: 0;
            }
            .main-container {
                justify-content: center;
                gap: 0;
                position: relative;
                width: 100%;
            }
            .poster-container {
                flex: 0 0 auto !important;
                height: 100% !important;
                aspect-ratio: 2 / 3;
                box-shadow: 0 4px 12px rgba(0,0,0,0.5);
            }
            .info-container {
                position: absolute;
                top: 0;
                left: 50%;
                transform: translateX(-50%);
                width: auto;
                height: 100%;
                aspect-ratio: 2 / 3;
                background: linear-gradient(to bottom, transparent 30%, rgba(0,0,0,0.6) 80%, rgba(0,0,0,0.85) 100%);
                display: flex;
                flex-direction: column;
                justify-content: flex-end;
                border-radius: 8px;
                padding: 10px;
                box-sizing: border-box;
                pointer-events: none;
                z-index: 5;
                overflow: visible;
            }
            .info-bottom {
                pointer-events: auto;
                flex: 0 0 auto;
            }
            .controls-container {
                justify-content: center;
                margin-bottom: 8px;
            }
            .playback-controls ha-icon-button {
                --mdc-icon-button-size: 40px;
                --mdc-icon-size: 28px;
                background: rgba(255, 255, 255, 0.2);
                color: white !important;
            }
            .progress-container {
                height: 4px;
                background: rgba(255, 255, 255, 0.3);
            }
            .progress-fill {
                background: #18BCF2;
            }
            .rewind-overlay span {
                font-size: 0.75rem !important;
                padding: 2px 5px !important;
                white-space: nowrap;
            }
        }

        /* Tall but Narrow Mode - When card is 4+ rows but too narrow for side layout */
        @container now-playing (min-height: 240px) and (max-width: 300px) {
            .card-header, .info-top {
                display: none !important;
            }
            .card-content {
                padding: 10px !important;
                justify-content: center;
                gap: 0;
            }
            .main-container {
                justify-content: center;
                gap: 0;
                position: relative;
                width: 100%;
            }
            .poster-container {
                flex: 0 0 auto !important;
                height: 100% !important;
                aspect-ratio: 2 / 3;
                box-shadow: 0 4px 12px rgba(0,0,0,0.5);
            }
            .info-container {
                position: absolute;
                top: 0;
                left: 50%;
                transform: translateX(-50%);
                width: auto;
                height: 100%;
                aspect-ratio: 2 / 3;
                background: linear-gradient(to bottom, transparent 30%, rgba(0,0,0,0.6) 80%, rgba(0,0,0,0.85) 100%);
                display: flex;
                flex-direction: column;
                justify-content: flex-end;
                border-radius: 8px;
                padding: 10px;
                box-sizing: border-box;
                pointer-events: none;
                z-index: 5;
                overflow: visible;
            }
            .info-bottom {
                pointer-events: auto;
                flex: 0 0 auto;
            }
            .controls-container {
                justify-content: center;
                margin-bottom: 8px;
            }
            .playback-controls ha-icon-button {
                --mdc-icon-button-size: 40px;
                --mdc-icon-size: 28px;
                background: rgba(255, 255, 255, 0.2);
                color: white !important;
            }
            .progress-container {
                height: 4px;
                background: rgba(255, 255, 255, 0.3);
            }
            .progress-fill {
                background: #18BCF2;
            }
            .rewind-overlay span {
                font-size: 0.75rem !important;
                padding: 2px 5px !important;
                white-space: nowrap;
            }
        }

        /* Very Tall but Narrow Mode - When card is 5+ rows and < 9 columns */
        @container now-playing (min-height: 300px) and (max-width: 350px) {
            .card-header, .info-top {
                display: none !important;
            }
            .card-content {
                padding: 10px !important;
                justify-content: center;
                gap: 0;
            }
            .main-container {
                justify-content: center;
                gap: 0;
                position: relative;
                width: 100%;
            }
            .poster-container {
                flex: 0 0 auto !important;
                height: 100% !important;
                aspect-ratio: 2 / 3;
                box-shadow: 0 4px 12px rgba(0,0,0,0.5);
            }
            .info-container {
                position: absolute;
                top: 0;
                left: 50%;
                transform: translateX(-50%);
                width: auto;
                height: 100%;
                aspect-ratio: 2 / 3;
                background: linear-gradient(to bottom, transparent 30%, rgba(0,0,0,0.6) 80%, rgba(0,0,0,0.85) 100%);
                display: flex;
                flex-direction: column;
                justify-content: flex-end;
                border-radius: 8px;
                padding: 10px;
                box-sizing: border-box;
                pointer-events: none;
                z-index: 5;
                overflow: visible;
            }
            .info-bottom {
                pointer-events: auto;
                flex: 0 0 auto;
            }
            .controls-container {
                justify-content: center;
                margin-bottom: 8px;
            }
            .playback-controls ha-icon-button {
                --mdc-icon-button-size: 40px;
                --mdc-icon-size: 28px;
                background: rgba(255, 255, 255, 0.2);
                color: white !important;
            }
            .progress-container {
                height: 4px;
                background: rgba(255, 255, 255, 0.3);
            }
            .progress-fill {
                background: #18BCF2;
            }
            /* Scale down rewind overlay for compact mode */
            .rewind-overlay span {
                font-size: 0.75rem !important;
                padding: 2px 5px !important;
                white-space: nowrap;
            }
        }
    `;

}
