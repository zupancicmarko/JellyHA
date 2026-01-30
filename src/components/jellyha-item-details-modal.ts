
import { LitElement, html, css, nothing, TemplateResult, render } from 'lit';
import { customElement, property, state, query } from 'lit/decorators.js';
import { HomeAssistant, MediaItem } from '../shared/types';

@customElement('jellyha-item-details-modal')
export class JellyHAItemDetailsModal extends LitElement {
    @property({ attribute: false }) public hass!: HomeAssistant;
    @state() private _item?: MediaItem;
    @state() private _nextUpItem?: MediaItem;
    @state() private _defaultCastDevice?: string;
    @state() private _open = false;
    @state() private _confirmDelete = false;

    // View States
    @state() private _viewMode: 'default' | 'episodes' = 'default';
    @state() private _episodes: MediaItem[] = [];

    // Swipe to close state
    @state() private _touchStartY = 0;
    @state() private _currentTranslateY = 0;
    @state() private _isDragging = false;
    private _swipeClosingThreshold = 100;

    private _portalContainer: HTMLElement | null = null;

    public connectedCallback(): void {
        super.connectedCallback();
        this._portalContainer = document.createElement('div');
        this._portalContainer.id = 'jellyha-modal-portal';
        document.body.appendChild(this._portalContainer);
    }

    public disconnectedCallback(): void {
        super.disconnectedCallback();
        if (this._portalContainer) {
            this._portalContainer.remove();
            this._portalContainer = null;
        }
    }

    public async showDialog(params: { item: MediaItem; hass: HomeAssistant; defaultCastDevice?: string }): Promise<void> {
        this._item = params.item;
        this.hass = params.hass;
        this._defaultCastDevice = params.defaultCastDevice;
        this._open = true;
        this._open = true;
        this._nextUpItem = undefined; // Reset
        this._viewMode = 'default';
        this._episodes = [];

        if (this._item.type === 'Series') {
            this._fetchNextUp(this._item);
        }

        // Fetch full details (MediaStreams, Backdrops) on demand
        this._fetchFullDetails(this._item.id);

        await this.updateComplete;
    }

    public closeDialog = () => {
        this._open = false;
        this._confirmDelete = false;
        this.dispatchEvent(new CustomEvent('closed', { bubbles: true, composed: true }));
        this.requestUpdate();
    }

    private async _fetchFullDetails(itemId: string): Promise<void> {
        try {
            // Fetch fresh details from backend (includes MediaStreams, Backdrops, etc.)
            // Using callWS instead of callService to properly handle return_response
            const response: any = await this.hass.callWS({
                type: 'call_service',
                domain: 'jellyha',
                service: 'get_item',
                service_data: {
                    item_id: itemId,
                    config_entry_id: this._item?.config_entry_id
                },
                return_response: true
            });

            // Access nested response from service call
            const serviceResponse = response?.response || response;

            if (serviceResponse && serviceResponse.item) {
                // Merge details into existing item
                this._item = { ...this._item!, ...serviceResponse.item };
                this.requestUpdate();
            }
        } catch (err) {
            console.warn('Failed to fetch full item details:', JSON.stringify(err, null, 2));
        }
    }

    private async _fetchNextUp(series: MediaItem): Promise<void> {
        // Find a valid entity_id for the WS call (we need the JellyHA sensor entity ID)
        // We can try to find one from hass states that matches our integration
        const entities = Object.keys(this.hass.states).filter(eid =>
            this.hass.states[eid].attributes.integration === 'jellyha' ||
            eid.startsWith('sensor.jellyha_') // Fallback convention
        );

        // Use the first one found, or if passed via config in card we could use that.
        // But here we rely on the sensor being present.
        const entityId = entities.length > 0 ? entities[0] : 'sensor.jellyha_library';

        try {
            const result = await this.hass.callWS<{ item: MediaItem | null }>({
                type: 'jellyha/get_next_up',
                entity_id: entityId,
                series_id: series.id
            });

            if (result && result.item) {
                this._nextUpItem = result.item;
            }
        } catch (err) {
            console.warn('Failed to fetch Next Up:', err);
        }
    }

    private async _fetchEpisodes(): Promise<void> {
        if (!this._item || this._item.type !== 'Series' || !this._nextUpItem) return;

        // Use the season from Next Up as the context
        // If Next Up is s01e01, we fetch Season 1
        const season = this._nextUpItem.season || 1;

        // Find entity ID like in Next Up
        const entities = Object.keys(this.hass.states).filter(eid =>
            this.hass.states[eid].attributes.integration === 'jellyha' ||
            eid.startsWith('sensor.jellyha_')
        );
        const entityId = entities.length > 0 ? entities[0] : 'sensor.jellyha_library';

        try {
            const result = await this.hass.callWS<{ items: MediaItem[] }>({
                type: 'jellyha/get_episodes',
                entity_id: entityId,
                series_id: this._item.id,
                season: season
            });

            if (result && result.items) {
                this._episodes = result.items;
                this._viewMode = 'episodes'; // Switch view once loaded
                this.requestUpdate();
            }
        } catch (err) {
            console.warn('Failed to fetch episodes:', err);
        }
    }

    private _toggleEpisodesView = (e?: Event) => {
        if (e) {
            e.stopPropagation();
            e.preventDefault();
        }
        if (this._viewMode === 'default') {
            this._fetchEpisodes();
        } else {
            this._viewMode = 'default';
        }
    }


    protected updated(): void {
        if (this._portalContainer) {
            render(this._renderDialogContent(), this._portalContainer);

            // Manually attach non-passive listeners to content
            const content = this._portalContainer.querySelector('.content');
            if (content) {
                // Remove old (deduping)
                content.removeEventListener('touchstart', this._handleModalTouchStart as any);
                content.removeEventListener('touchmove', this._handleModalTouchMove as any);
                content.removeEventListener('touchend', this._handleModalTouchEnd as any);

                // Add new
                content.addEventListener('touchstart', this._handleModalTouchStart as any, { passive: true });
                content.addEventListener('touchmove', this._handleModalTouchMove as any, { passive: false }); // Key fix
                content.addEventListener('touchend', this._handleModalTouchEnd as any, { passive: true });
            }
        }
    }

    protected render(): TemplateResult {
        return html``;
    }


    static styles = css`
        /* Styles handled in _getPortalStyles */
    `;

    private _getPortalStyles() {
        return html`
        <style>
             ha-dialog {
                --mdc-dialog-z-index: 9999;
                --mdc-dialog-min-width: 400px;
                --mdc-dialog-max-width: 90vw;
                --mdc-theme-surface: transparent; 
                --ha-dialog-background: transparent;
                --mdc-dialog-box-shadow: none;
                --dialog-content-padding: 0;
                --mdc-dialog-content-padding: 0;
                --dialog-surface-margin: 0;
             }

            .content {
                display: flex; /* Flex container for children scrollers */
                flex-direction: column;
                
                transform-origin: top center;
                will-change: transform;
                background: var(--ha-card-background, var(--card-background-color, #1c1c1c));
                border-radius: 20px;
                box-shadow: 0 10px 40px rgba(0,0,0,0.5); /* Card shadow */
                padding: 24px;
                max-height: 80vh;
                overscroll-behavior-y: contain; /* Prevent browser overscroll/refresh */
                
                /* Hide scrollbar on the container itself */
                scrollbar-width: none; 
                -ms-overflow-style: none; 
                overflow: hidden; /* Clip content to rounded corners */
            }
            
            /* Episodes View specific */
            .content.episodes {
                overflow: hidden !important; 
                padding-right: 24px; 
            }

            .content::-webkit-scrollbar {
                display: none; 
                width: 0px !important;
                height: 0px !important;
                background: transparent;
            }

            /* Inner Layouts (Default View) */
            .default-layout {
                display: block; /* Mobile default */
                overflow-y: auto;
                height: 100%;
                width: 100%;
                padding-right: 4px; /* Space for scrollbar */
                
                /* Inset Scrollbar */
                scrollbar-width: thin; 
                scrollbar-color: rgba(255, 255, 255, 0.2) transparent;
            }
            .default-layout::-webkit-scrollbar {
                display: block;
                width: 6px !important;
                height: 6px !important;
            }
            .default-layout::-webkit-scrollbar-thumb {
                background: rgba(255, 255, 255, 0.2);
                border-radius: 3px;
            }
            .default-layout::-webkit-scrollbar-track {
                background: transparent;
            }

            /* Desktop Grid */
            @media (min-width: 601px) {
                .default-layout {
                    display: grid;
                    grid-template-columns: 300px 1fr;
                    gap: 24px;
                    overflow-y: auto; 
                }
                .content.episodes {
                    max-height: 80vh;
                }
            }

            .poster-col {
                display: flex;
                flex-direction: column;
                gap: 16px;
            }

            .poster-img {
                width: 100%;
                aspect-ratio: 2/3;
                object-fit: cover;
                border-radius: 12px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.3);
            }

            .actions-col {
                display: flex;
                flex-direction: row;
                gap: 0;
                justify-content: space-between;
                align-items: center;
                min-height: 44px; /* Maintain height for delete confirmation */
                width: 100%;
            }

            .details-col {
                display: flex;
                flex-direction: column;
                gap: 16px;
            }

            .header-group h1 {
                margin: 0;
                font-size: 2rem;
                font-weight: 700;
                line-height: 1.2;
                color: var(--primary-text-color);
            }

            .header-sub {
                display: flex;
                gap: 12px;
                align-items: center;
                margin-top: 8px;
                color: var(--secondary-text-color);
                font-size: 1rem;
            }

            .badge {
                padding: 4px 8px;
                border-radius: 6px;
                background: rgba(var(--rgb-primary-text-color), 0.1);
                font-size: 0.85rem;
                font-weight: 600;
                text-transform: uppercase;
            }

            .stats-row {
                display: flex;
                flex-wrap: wrap;
                gap: 8px; /* Tighter gap for chips */
                padding: 4px 0; /* Minimal vertical padding */
                /* Remove container background for native look */
                background: transparent;
                border-radius: 0;
            }

            .stat-item {
                display: flex;
                gap: 6px;
                align-items: center;
                /* Native Chip Styling */
                border: 1px solid var(--divider-color);
                border-radius: 18px;
                padding: 6px 12px;
                font-size: 0.9rem;
                font-weight: 500;
                color: var(--primary-text-color);
                background: transparent; 
            }

            .description {
                font-size: 1rem;
                line-height: 1.6;
                color: var(--primary-text-color);
                white-space: pre-wrap;
            }

            .genres-list {
                display: flex;
                flex-wrap: wrap;
                gap: 8px;
            }

            .genre-tag {
                background: rgba(var(--rgb-primary-color), 0.15);
                color: var(--primary-color);
                padding: 4px 12px;
                border-radius: 16px;
                font-size: 0.85rem;
                border: 1px solid rgba(var(--rgb-primary-color), 0.3);
            }

            .divider {
                height: 1px;
                background: var(--divider-color);
                margin: 8px 0;
            }

            .media-info-grid {
                display: grid;
                grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
                gap: 12px;
                font-size: 0.85rem;
                color: var(--secondary-text-color);
            }

            .info-pair b {
                color: var(--primary-text-color);
                display: block;
                margin-bottom: 2px;
            }

            .action-btn {
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 10px;
                border-radius: 50%; /* Circle shape */
                border: none;
                cursor: pointer;
                background: transparent;
                color: var(--secondary-text-color);
                width: 44px;
                height: 44px;
                box-sizing: border-box;
                transition: background 0.2s, color 0.2s;
            }

            .action-btn:hover {
                background: rgba(255, 255, 255, 0.1);
                color: var(--primary-text-color);
            }

            .action-btn.active {
                color: var(--primary-color);
            }
            .favorite-btn.active {
                color: #F44336;
            }

            .action-btn ha-icon {
                --mdc-icon-size: 26px;
            }

            .btn-danger {
                color: var(--error-color, #f44336);
            }
            .btn-danger:hover {
                background: rgba(244, 67, 54, 0.15);
            }

            .confirmation-box {
                display: flex;
                gap: 12px;
                align-items: center;
                justify-content: center;
                width: 100%;
                background: rgba(244, 67, 54, 0.1);
                border-radius: 8px;
                padding: 4px 8px;
            }
            
            .confirm-btn {
                background: none;
                border: none;
                cursor: pointer;
                color: var(--primary-text-color);
                font-weight: 600;
                padding: 8px 16px;
                border-radius: 4px;
            }
            .confirm-btn:hover {
                 background: rgba(255,255,255,0.1);
            }
            .confirm-yes {
                color: var(--error-color);
            }



            /* Next Up Section */
            .next-up-card {
                background: var(--secondary-background-color, rgba(0, 0, 0, 0.1));
                border-radius: 12px;
                padding: 12px;
                display: flex;
                gap: 16px;
                align-items: center;
                margin-top: 16px;
                border: 1px solid var(--divider-color);
                cursor: pointer;
                transition: background 0.2s, transform 0.1s;
                position: relative;
                overflow: hidden;
            }
            .next-up-card:hover {
                background: rgba(var(--rgb-primary-text-color), 0.05);
            }
            .next-up-card:active {
                background: rgba(var(--rgb-primary-text-color), 0.1);
                transform: scale(0.98); /* Button press effect */
            }
            .next-up-thumb {
                width: 120px;
                aspect-ratio: 16/9;
                object-fit: cover;
                border-radius: 8px;
            }
            .next-up-info {
                flex: 1;
                display: flex;
                flex-direction: column;
                gap: 4px;
            }
            .next-up-label {
                font-size: 0.75rem;
                text-transform: uppercase;
                letter-spacing: 0.5px;
                color: var(--primary-color);
                font-weight: 700;
            }
            .next-up-title {
                font-size: 1.1rem;
                font-weight: 600;
                color: var(--primary-text-color);
                margin: 0;
            }
            .next-up-meta {
                font-size: 0.9rem;
                color: var(--secondary-text-color);
            }

            @media (max-width: 600px) {
                .poster-col { max-width: 350px; margin: 0 auto; width: 100%; margin-bottom: 24px; }
            }

            /* Episode List Styles */
            .episodes-header {
                 display: flex;
                 align-items: center;
                 gap: 12px;
                 margin-bottom: 16px;
            }
            .back-btn {
                background: none;
                border: none;
                color: var(--primary-text-color);
                cursor: pointer;
                padding: 8px;
                border-radius: 50%;
                display: flex; /* Fix icon alignment */
            }
            .back-btn:hover {
                background: rgba(255,255,255,0.1);
            }
            .episodes-title {
                margin: 0;
                font-size: 1.5rem;
                font-weight: 600;
            }
            .episodes-list {
                display: flex;
                flex-direction: column;
                gap: 12px;
                overflow-y: auto;
                flex: 1; /* Take remaining height */
                min-height: 0; /* Flexbox scroll fix */
                padding-right: 4px; /* Space for scrollbar */
                
                /* Re-enable scrollbars for this list */
                scrollbar-width: thin; 
                scrollbar-color: rgba(255, 255, 255, 0.2) transparent;
            }
            .episodes-list::-webkit-scrollbar {
                display: block;
                width: 6px !important;
                height: 6px !important;
            }
            .episodes-list::-webkit-scrollbar-thumb {
                background: rgba(255, 255, 255, 0.2);
                border-radius: 3px;
            }
            .episodes-list::-webkit-scrollbar-track {
                background: transparent;
            }
            .episode-row {
                display: flex;
                gap: 16px;
                padding: 12px;
                background: rgba(255,255,255,0.03);
                border-radius: 12px;
                align-items: center;
                transition: background 0.2s;
            }
            .episode-row:hover {
                background: rgba(255,255,255,0.08); /* Slightly lighter on hover */
            }
            .episode-row.next-up-highlight {
                background: rgba(var(--rgb-primary-color), 0.1);
                border-left: 3px solid var(--primary-color);
            }
            .episode-content {
                flex: 1;
                min-width: 0;
                display: flex;
                flex-direction: column;
                justify-content: center;
                gap: 4px;
            }
            .episode-footer {
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            .episode-actions {
                display: flex;
                gap: 12px;
            }
            .episode-thumb {
                width: 100px;
                aspect-ratio: 16/9;
                object-fit: cover;
                border-radius: 8px;
                flex-shrink: 0; 
                background: var(--secondary-background-color); /* Skeleton placeholder */
                border: 1px solid rgba(255, 255, 255, 0.5);
            }
            .episode-info {
                flex: 1;
                min-width: 0; /* truncate text */
            }
            .episode-title {
                margin: 0;
                font-size: 1rem;
                font-weight: 500;
                line-height: 1.2;
                color: var(--primary-text-color);
            }
            .episode-meta {
                font-size: 0.85rem;
                color: var(--secondary-text-color);
                display: flex;
                align-items: center;
            }
            .play-episode-btn {
                background: transparent;
                border: none;
                color: var(--primary-color);
                border-radius: 50%; /* Keep radius for hover effect */
                width: 36px;
                height: 36px;
                display: flex;
                align-items: center;
                justify-content: center;
                cursor: pointer;
                transition: all 0.2s;
            }
            .play-episode-btn:hover {
                background: rgba(255, 255, 255, 0.15);
                color: var(--primary-color);
            }
            /* Specific override for the checkmark button */
            .watched-btn {
                color: var(--secondary-text-color);
                opacity: 0.6;
            }
            .watched-btn:hover {
                opacity: 1;
            }
            .watched-btn.active {
                color: var(--primary-color);
                opacity: 1;
            }
        </style>
        `;
    }

    private _renderDialogContent(): TemplateResult {
        if (!this._open || !this._item) return html``;

        return html`
            ${this._getPortalStyles()}
            <ha-dialog
                open
                .escapeKeyAction=${"close"}
                .scrimClickAction=${"close"}
                @closed=${this.closeDialog}
                hideActions
                .heading=${""} 
            >
                <ha-card 
                    class="content ${this._viewMode}"
                    style="${this._isDragging || this._currentTranslateY > 0 ? `transform: translateY(${this._currentTranslateY}px); transition: ${this._isDragging ? 'none' : 'transform 0.3s ease-out'}` : ''}"
                >
                    ${this._viewMode === 'episodes' ? this._renderEpisodesContent() : this._renderDefaultContent()}
                </ha-card>
            </ha-dialog>
        `;
    }

    private _renderDefaultContent(): TemplateResult {
        if (!this._item) return html``;
        const item = this._item;
        const isSeries = item.type === 'Series';
        const year = item.year || (item.date_added ? new Date(item.date_added).getFullYear() : '');

        return html`
        <div class="default-layout">
            <div class="poster-col">
                <img class="poster-img" src="${item.poster_url}" alt="${item.name}" />

                <div class="actions-col">
                    ${this._confirmDelete
                ? html`
                        <div class="confirmation-box">
                            <span>Delete?</span>
                            <button class="confirm-btn confirm-yes" @click=${this._handleDeleteConfirm}>Yes</button>
                            <button class="confirm-btn" @click=${() => this._confirmDelete = false}>No</button>
                        </div>
                        `
                : html`
                        <button class="action-btn" @click=${this._handlePlay} title="Play on Chromecast">
                            <ha-icon icon="mdi:cast"></ha-icon>
                        </button>
                        
                        ${isSeries && this._nextUpItem ? html`
                                <button class="action-btn" @click=${(e: Event) => { this._haptic(); this._toggleEpisodesView(e); }} title="View All Episodes" type="button">
                                <ha-icon icon="mdi:format-list-bulleted"></ha-icon>
                                </button>
                        ` : nothing}

                        ${item.trailer_url ? html`
                            <button class="action-btn" @click=${this._handleWatchTrailer} title="Watch Trailer">
                                <ha-icon icon="mdi:filmstrip"></ha-icon>
                        ` : nothing}

                        <button class="action-btn ${item.is_played ? 'active' : ''}" @click=${this._handleWatched} title="${item.is_played ? 'Mark Unwatched' : 'Mark Watched'}">
                            <ha-icon icon="mdi:check"></ha-icon>
                        </button>

                        <button class="action-btn favorite-btn ${item.is_favorite ? 'active' : ''}" @click=${this._handleFavorite} title="${item.is_favorite ? 'Remove Favorite' : 'Add to Favorites'}">
                                <ha-icon icon="${item.is_favorite ? 'mdi:heart' : 'mdi:heart-outline'}"></ha-icon>
                        </button>

                        <a href="${item.jellyfin_url}" class="action-btn" target="_blank" title="Open in Jellyfin" @click=${() => this._haptic()}>
                            <ha-icon icon="mdi:popcorn"></ha-icon>
                        </a>

                        <button class="action-btn" @click=${() => { this._haptic(); this._confirmDelete = true; }} title="Delete Item">
                            <ha-icon icon="mdi:trash-can-outline"></ha-icon>
                        </button>
                        
                    `}
                </div>
            </div>

            <div class="details-col">
                <div class="header-group">
                    <h1>${item.name}</h1>
                    <div class="header-sub">
                        ${year ? html`<span>${year}</span>` : nothing}
                        <span class="badge">${item.type}</span>
                        ${item.official_rating ? html`<span class="badge">${item.official_rating}</span>` : nothing}
                    </div>
                </div>
                
                ${this._nextUpItem ? html`
                    <div class="next-up-card" @click=${this._playNextUp}>
                        <img class="next-up-thumb" src="${this._nextUpItem.backdrop_url || this._nextUpItem.poster_url}" />
                        <div class="next-up-info">
                            <span class="next-up-label">Next Up</span>
                            <h3 class="next-up-title">${this._nextUpItem.name}</h3>
                            <span class="next-up-meta">S${this._nextUpItem.season} : E${this._nextUpItem.episode} • ${this._formatRuntime(this._nextUpItem.runtime_minutes)}</span>
                        </div>
                        <ha-icon icon="mdi:cast" style="font-size: 36px; color: var(--primary-color); opacity: 1;"></ha-icon>
                    </div>
                ` : nothing}

                <div class="stats-row">
                    <div class="stat-item">
                        <ha-icon icon="mdi:star" style="color: #FBC02D;"></ha-icon>
                        <span>${item.rating ? item.rating.toFixed(1) : 'N/A'}</span>
                    </div>
                    ${isSeries ? html`
                        <div class="stat-item">
                            <ha-icon icon="mdi:television-classic"></ha-icon>
                            <span>${item.unplayed_count !== undefined ? item.unplayed_count + ' Unplayed' : ''}</span>
                        </div>
                        ` : html`
                        <div class="stat-item">
                            <ha-icon icon="mdi:clock-outline"></ha-icon>
                            <span>${this._formatRuntime(item.runtime_minutes)}</span>
                        </div>
                        `}
                </div>

                    ${item.description ? html`<div class="description">${item.description}</div>` : nothing}

                    ${item.genres && item.genres.length > 0 ? html`
                    <div class="genres-list">
                        ${item.genres.map(g => html`<span class="genre-tag">${g}</span>`)}
                    </div>
                    ` : nothing}
                
                    <div class="divider"></div>

                    <div class="media-info-grid">
                    ${this._renderMediaDetails(isSeries && this._nextUpItem ? this._nextUpItem : item)}
                    </div>
            </div>
        </div>
        `;
    }

    private _renderEpisodesContent(): TemplateResult {
        if (!this._item || !this._nextUpItem) return html``;

        // Prefer explicit season name, fallback to "Season X"
        const title = this._item.name;

        // Use full height wrapper for sticky header + scrollable list
        return html`
            <div style="display: flex; flex-direction: column; height: 100%; overflow: hidden;">
                <div class="episodes-header">
                    <button class="back-btn" @click=${(e: Event) => this._toggleEpisodesView(e)} type="button">
                        <ha-icon icon="mdi:arrow-left"></ha-icon>
                    </button>
                    <h2 class="episodes-title">${title}</h2>
                </div>
                
                <div class="episodes-list">
                    ${this._episodes.map(ep => html`
                        <div class="episode-row ${this._nextUpItem && ep.id === this._nextUpItem.id ? 'next-up-highlight' : ''}" @click=${(e: Event) => { e.stopPropagation(); this._handlePlayEpisode(ep); }}>
                            <img class="episode-thumb" src="${ep.backdrop_url || ep.poster_url || this._item!.backdrop_url}" />
                            
                            <div class="episode-content">
                                <h4 class="episode-title">
                                    ${ep.episode || ep.index_number}. ${ep.name}
                                    ${this._nextUpItem && ep.id === this._nextUpItem.id ? html`<span style="font-size: 0.7em; background: var(--primary-color); color: white; padding: 2px 6px; border-radius: 4px; margin-left: 8px; vertical-align: middle; white-space: nowrap;">NEXT UP</span>` : nothing}
                                </h4>
                                
                                <div class="episode-footer">
                                    <div class="episode-meta">
                                        <span>${this._formatRuntime(ep.runtime_minutes)}</span>
                                        ${ep.rating !== undefined ? html` <ha-icon icon="mdi:star" style="--mdc-icon-size: 14px; color: #FBC02D; margin-left: 6px; transform: translateY(-1px);"></ha-icon> ${ep.rating.toFixed(1)}` : nothing}
                                    </div>

                                    <div class="episode-actions">
                                        <button class="play-episode-btn watched-btn ${ep.is_played ? 'active' : ''}" @click=${(e: Event) => { e.stopPropagation(); this._handleMarkEpisodeWatched(ep); }} type="button" title="${ep.is_played ? 'Mark Unwatched' : 'Mark Watched'}">
                                            <ha-icon icon="mdi:check"></ha-icon>
                                        </button>

                                        <button class="play-episode-btn" @click=${(e: Event) => { e.stopPropagation(); this._handlePlayEpisode(ep); }} type="button">
                                            <ha-icon icon="mdi:cast"></ha-icon>
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    `)}
                </div>
            </div>
        `;
    }

    private _formatRuntime(minutes?: number): string {
        if (!minutes) return '';
        const hours = Math.floor(minutes / 60);
        const mins = minutes % 60;
        if (hours > 0) return `${hours}h ${mins}m`;
        return `${mins} min`;
    }

    private _renderMediaDetails(item: MediaItem): TemplateResult[] {
        const details: TemplateResult[] = [];
        const streams = item.media_streams || [];

        // Find Video Stream
        const videoStream = streams.find(s => s.Type?.toLowerCase() === 'video');
        if (videoStream) {
            if (videoStream.Codec) details.push(html`<div class="info-pair"><b>Video</b><span>${videoStream.Codec.toUpperCase()}</span></div>`);
            if (videoStream.Width && videoStream.Height) details.push(html`<div class="info-pair"><b>Resolution</b><span>${videoStream.Width}x${videoStream.Height}</span></div>`);
        }

        // Find Primary Audio Stream (Default or First)
        const audioStream = streams.find(s => s.Type?.toLowerCase() === 'audio' && !!s.IsDefault) ||
            streams.find(s => s.Type?.toLowerCase() === 'audio');

        if (audioStream) {
            if (audioStream.Codec) details.push(html`<div class="info-pair"><b>Audio</b><span>${audioStream.Codec.toUpperCase()}</span></div>`);
            if (audioStream.Channels) details.push(html`<div class="info-pair"><b>Channels</b><span>${audioStream.Channels} ch</span></div>`);
        }
        return details;
    }


    private _handlePlayEpisode = async (episode: MediaItem) => {
        this._haptic();
        if (!this._defaultCastDevice) {
            this.dispatchEvent(new CustomEvent('hass-notification', {
                detail: { message: 'No Chromecast device selected. Please configure a cast device in the card editor.' },
                bubbles: true,
                composed: true
            }));
            return;
        }
        try {
            await this.hass.callService('jellyha', 'play_on_chromecast', {
                entity_id: this._defaultCastDevice,
                item_id: episode.id,
            });
            this.closeDialog();
        } catch (err) {
            console.error('Failed to cast episode', err);
            this.dispatchEvent(new CustomEvent('hass-notification', {
                detail: { message: 'Failed to cast episode. Check logs.' },
                bubbles: true,
                composed: true
            }));
        }
    }

    private _handlePlay = async () => {
        this._haptic();
        if (!this._item || !this._defaultCastDevice) {
            if (!this._defaultCastDevice) {
                this.dispatchEvent(new CustomEvent('hass-notification', {
                    detail: { message: 'No Chromecast device selected. Please configure a cast device in the card editor.' },
                    bubbles: true,
                    composed: true
                }));
            }
            return;
        }
        try {
            await this.hass.callService('jellyha', 'play_on_chromecast', {
                entity_id: this._defaultCastDevice,
                item_id: this._item.id,
            });
            this.closeDialog();
        } catch (err) {
            console.error('Failed to cast', err);
        }
    }

    private _haptic(type: 'selection' | 'light' | 'medium' | 'heavy' | 'success' | 'warning' | 'failure' = 'selection') {
        const event = new CustomEvent('haptic', {
            detail: type,
            bubbles: true,
            composed: true
        });
        this.dispatchEvent(event);
    }

    private _playNextUp = async () => {
        this._haptic();

        if (!this._nextUpItem || !this._defaultCastDevice) {
            if (!this._defaultCastDevice) {
                this.dispatchEvent(new CustomEvent('hass-notification', {
                    detail: { message: 'No Chromecast device selected. Please configure a cast device in the card editor.' },
                    bubbles: true,
                    composed: true
                }));
            }
            return;
        }
        try {
            await this.hass.callService('jellyha', 'play_on_chromecast', {
                entity_id: this._defaultCastDevice,
                item_id: this._nextUpItem.id,
            });
            this.closeDialog();
        } catch (err) {
            console.error('Failed to cast next up', err);
        }
    }

    private _handleFavorite = async () => {
        if (!this._item) return;
        this._haptic(); // Feedback
        const newStatus = !this._item.is_favorite;
        this._item = { ...this._item, is_favorite: newStatus };

        await this.hass.callService('jellyha', 'update_favorite', {
            item_id: this._item.id,
            is_favorite: newStatus,
        });
        this.requestUpdate();
    }

    private _handleWatched = async () => {
        if (!this._item) return;
        this._haptic(); // Feedback
        const newStatus = !this._item.is_played;
        this._item = { ...this._item, is_played: newStatus };

        await this.hass.callService('jellyha', 'mark_watched', {
            item_id: this._item.id,
            is_played: newStatus,
        });
        this.requestUpdate();
    }

    private _handleDeleteConfirm = async () => {
        if (!this._item) return;
        this._haptic(); // Feedback
        const itemId = this._item.id;
        this.closeDialog();

        await this.hass.callService('jellyha', 'delete_item', {
            item_id: itemId,
        });
    }

    private _handleWatchTrailer = () => {
        this._haptic();
        const item = this._item;
        if (!item?.trailer_url) return;
        const url = item.trailer_url;

        // Extract YouTube ID if possible
        // Standard formats: youtube.com/watch?v=ID, youtu.be/ID
        let youtubeId = '';
        try {
            const urlObj = new URL(url);
            if (urlObj.hostname.includes('youtube.com')) {
                youtubeId = urlObj.searchParams.get('v') || '';
            } else if (urlObj.hostname.includes('youtu.be')) {
                youtubeId = urlObj.pathname.slice(1);
            }
        } catch (e) {
            // ignore invalid urls for now, will just open as is
        }

        if (youtubeId) {
            const ua = navigator.userAgent || navigator.vendor || (window as any).opera;
            const isAndroid = /android/i.test(ua);

            if (isAndroid) {
                window.open(`vnd.youtube:${youtubeId}`, '_blank');
                return;
            }
        }

        window.open(url, '_blank');
    }

    private _handleMarkEpisodeWatched = async (episode: MediaItem) => {
        this._haptic();
        const newStatus = !episode.is_played;

        // Optimistic Update
        this._episodes = this._episodes.map(ep =>
            ep.id === episode.id ? { ...ep, is_played: newStatus, unplayed_count: newStatus ? 0 : 1 } : ep
        );

        // Dynamic Next Up Highlight Rotation
        if (newStatus && this._nextUpItem && episode.id === this._nextUpItem.id) {
            // Find index of current episode
            const currentIndex = this._episodes.findIndex(ep => ep.id === episode.id);
            if (currentIndex !== -1 && currentIndex < this._episodes.length - 1) {
                // Move Next Up to the immediate next episode
                this._nextUpItem = this._episodes[currentIndex + 1];
            }
        } else if (!newStatus && this._nextUpItem && episode.id !== this._nextUpItem.id) {
            // If marking unwatched, check if this episode is *before* the current next up.
            // If so, it should strictly become the new next up (first unwatched).
            const currentIndex = this._episodes.findIndex(ep => ep.id === episode.id);
            const nextUpIndex = this._episodes.findIndex(ep => ep.id === this._nextUpItem!.id);

            if (currentIndex !== -1 && nextUpIndex !== -1 && currentIndex < nextUpIndex) {
                this._nextUpItem = this._episodes[currentIndex];
            }
        }

        this.requestUpdate();

        await this.hass.callService('jellyha', 'mark_watched', {
            item_id: episode.id,
            is_played: newStatus,
        });
    }


    /* Swipe to Close Logic */
    private _getScrollParent(node: HTMLElement | null): HTMLElement | null {
        if (!node) return null;

        let parent = node;
        while (parent && parent !== this._portalContainer && parent !== document.body) {
            // Optimization: The '.content' element is our main scroll container.
            // Check it explicitly to avoid costly getComputedStyle in loop if possible.
            if (parent.classList?.contains('content')) {
                if (parent.scrollHeight > parent.clientHeight) {
                    return parent;
                }
                // If content fits, it's not scrolling, so we can swipe locally
                return null;
            }

            // Fallback for nested scrollables (e.g. strict verify)
            // Accessing scrollHeight forces reflow, but unavoidable if we want to know if it scrolls.
            // accessing getComputedStyle forces style recalc. 
            // We can skip getComputedStyle if we assume standard block elements aren't scrollable without it?
            // But let's keep it safe but maybe break early?
            const { overflowY } = window.getComputedStyle(parent);
            if ((overflowY === 'auto' || overflowY === 'scroll') && parent.scrollHeight > parent.clientHeight) {
                return parent;
            }

            parent = parent.parentElement as HTMLElement;
        }
        return null;
    }

    private _handleModalTouchStart = (e: TouchEvent): void => {
        const target = e.target as HTMLElement;
        const scrollParent = this._getScrollParent(target);

        // If we found a scrollable parent and it is scrolled down, disable swipe to close
        if (scrollParent && scrollParent.scrollTop > 0) {
            return;
        }

        this._touchStartY = e.touches[0].clientY;
        this._isDragging = true;
    }

    private _handleModalTouchMove = (e: TouchEvent): void => {
        if (!this._isDragging) return;

        const deltaY = e.touches[0].clientY - this._touchStartY;

        // Only allow pulling down (positive delta)
        // If driving up (negative delta), we let native scroll handle it
        if (deltaY > 0) {
            // We are pulling down from top
            if (e.cancelable) e.preventDefault();
            this._currentTranslateY = deltaY;
        } else {
            // User is scrolling down (moving finger up), we let native scroll handle it
            this._isDragging = false; // Stop tracking as a drag close
        }
    }

    private _handleModalTouchEnd = (e: TouchEvent): void => {
        if (!this._isDragging) return;
        this._isDragging = false;

        if (this._currentTranslateY > this._swipeClosingThreshold) {
            // Close
            this.closeDialog();
            // Reset after a moment to keep UI clean ensuring dialog is gone
            setTimeout(() => {
                this._currentTranslateY = 0;
            }, 300);
        } else {
            // Reset (snap back)
            this._currentTranslateY = 0;
        }
    }
}

declare global {
    interface HTMLElementTagNameMap {
        'jellyha-item-details-modal': JellyHAItemDetailsModal;
    }
}
