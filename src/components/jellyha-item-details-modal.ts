
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
        this._nextUpItem = undefined; // Reset

        if (this._item.type === 'Series') {
            this._fetchNextUp(this._item);
        }

        await this.updateComplete;
    }

    public closeDialog = () => {
        this._open = false;
        this._confirmDelete = false;
        this.dispatchEvent(new CustomEvent('closed', { bubbles: true, composed: true }));
        this.requestUpdate();
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


    protected updated(): void {
        if (this._portalContainer) {
            render(this._renderDialogContent(), this._portalContainer);
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
             }

            .content {
                display: grid;
                grid-template-columns: 300px 1fr;
                gap: 24px;
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
                flex-direction: column;
                gap: 12px;
            }

            .details-col {
                display: flex;
                flex-direction: column;
                gap: 16px;
                overflow-y: auto;
                max-height: 60vh;
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
                gap: 16px;
                padding: 12px;
                border-radius: 8px;
                font-size: 0.95rem;
                background: var(--secondary-background-color, rgba(0,0,0,0.2));
            }

            .stat-item {
                display: flex;
                gap: 6px;
                align-items: center;
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
                gap: 8px;
                padding: 10px;
                border-radius: 8px;
                border: none;
                cursor: pointer;
                font-weight: 600;
                font-size: 0.95rem;
                text-decoration: none;
                width: 100%;
                box-sizing: border-box;
            }

            .btn-primary {
                background: var(--primary-color);
                color: var(--text-primary-color, white);
            }

            .btn-secondary {
                background: var(--secondary-background-color);
                color: var(--primary-text-color);
                border: 1px solid var(--divider-color);
            }

            .btn-danger {
                background: var(--error-color, #f44336);
                color: white;
            }
            .btn-danger.small, .btn-secondary.small {
                font-size: 0.85rem;
                padding: 6px 12px;
            }

            .confirmation-box {
                background: rgba(244, 67, 54, 0.1);
                border: 1px solid var(--error-color);
                padding: 12px;
                border-radius: 8px;
                display: flex;
                flex-direction: column;
                gap: 8px;
                align-items: center;
                text-align: center;
            }
            
            .confirm-actions {
                display: flex;
                gap: 8px;
                width: 100%;
            }
            
            .confirm-actions .action-btn {
               flex: 1;
            }

            /* Next Up Section */
            .next-up-card {
                background: rgba(0,0,0,0.2);
                border-radius: 12px;
                padding: 16px;
                display: flex;
                gap: 16px;
                align-items: center;
                margin-top: 16px;
                border: 1px solid var(--divider-color);
                cursor: pointer;
                transition: background 0.2s;
            }
            .next-up-card:hover {
                background: rgba(0,0,0,0.4);
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
                .content { grid-template-columns: 1fr; }
                .poster-col { max-width: 200px; margin: 0 auto; width: 100%; }
            }
        </style>
        `;
    }

    private _renderDialogContent(): TemplateResult {
        if (!this._open || !this._item) return html``;

        const item = this._item;
        const isSeries = item.type === 'Series';
        const year = item.year || (item.date_added ? new Date(item.date_added).getFullYear() : '');

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
                <div class="content">
                    <div class="poster-col">
                        <img class="poster-img" src="${item.poster_url}" alt="${item.name}" />

                        <div class="actions-col">
                            <button class="action-btn btn-primary" @click=${this._handlePlay}>
                                <ha-icon icon="mdi:play"></ha-icon> Play on Chromecast
                            </button>
                            
                            <button class="action-btn btn-secondary" @click=${this._handleFavorite}>
                                <ha-icon icon="${item.is_favorite ? 'mdi:heart' : 'mdi:heart-outline'}" 
                                         style="color: ${item.is_favorite ? '#F44336' : 'inherit'}">
                                </ha-icon> 
                                ${item.is_favorite ? 'Favorite' : 'Add to Favorites'}
                            </button>
                            
                            <button class="action-btn btn-secondary" @click=${this._handleWatched}>
                                <ha-icon icon="mdi:check"
                                         style="color: ${item.is_played ? 'var(--primary-color)' : 'inherit'}">
                                </ha-icon>
                                ${item.is_played ? 'Watched' : 'Mark Watched'}
                            </button>

                            <a href="${item.jellyfin_url}" class="action-btn btn-secondary" target="_blank">
                                <ha-icon icon="mdi:open-in-new"></ha-icon> Open in Jellyfin
                            </a>

                            ${this._confirmDelete
                ? html`
                                <div class="confirmation-box">
                                    <span>Are you sure?</span>
                                    <div class="confirm-actions">
                                        <button class="action-btn btn-danger small" @click=${this._handleDeleteConfirm}>Delete</button>
                                        <button class="action-btn btn-secondary small" @click=${() => this._confirmDelete = false}>Cancel</button>
                                    </div>
                                </div>
                              `
                : html`
                             <button class="action-btn btn-danger" @click=${() => this._confirmDelete = true}>
                                <ha-icon icon="mdi:delete"></ha-icon> Delete Item
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
                                <ha-icon icon="mdi:play-circle-outline" style="font-size: 32px; opacity: 0.8;"></ha-icon>
                            </div>
                        ` : nothing}

                        <div class="stats-row">
                            <div class="stat-item">
                                <ha-icon icon="mdi:star" style="color: #FFD700;"></ha-icon>
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
                            ${this._renderMediaDetails(item)}
                         </div>
                    </div>
                </div>
            </ha-dialog>
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

        streams.forEach(stream => {
            if (stream.Type === 'Video') {
                details.push(html`<div class="info-pair"><b>Video</b><span>${stream.Codec?.toUpperCase()}</span></div>`);
                details.push(html`<div class="info-pair"><b>Resolution</b><span>${stream.Width}x${stream.Height}</span></div>`);
            } else if (stream.Type === 'Audio' && stream.Index === 1) {
                details.push(html`<div class="info-pair"><b>Audio</b><span>${stream.Codec?.toUpperCase()}</span></div>`);
                details.push(html`<div class="info-pair"><b>Channels</b><span>${stream.Channels} ch</span></div>`);
            }
        });
        return details;
    }

    private _handlePlay = async () => {
        if (!this._item || !this._defaultCastDevice) {
            if (!this._defaultCastDevice) {
                alert('No default cast device configured.');
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

    private _playNextUp = async () => {
        if (!this._nextUpItem || !this._defaultCastDevice) {
            if (!this._defaultCastDevice) alert('No default cast device configured.');
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
        const itemId = this._item.id;
        this.closeDialog();

        await this.hass.callService('jellyha', 'delete_item', {
            item_id: itemId,
        });
    }
}

declare global {
    interface HTMLElementTagNameMap {
        'jellyha-item-details-modal': JellyHAItemDetailsModal;
    }
}
