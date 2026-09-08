
import { LitElement, html, css, nothing, TemplateResult, render } from 'lit';
import { customElement, property, state, query } from 'lit/decorators.js';
import { HomeAssistant, MediaItem } from '../shared/types';

@customElement('jellyha-item-details-modal')
export class JellyHAItemDetailsModal extends LitElement {
    @property({ attribute: false }) public hass!: HomeAssistant;
    @state() private _item?: MediaItem;
    @state() private _nextUpItem?: MediaItem;
    @state() private _defaultCastDevice?: string;
    @state() private _serverEntityId?: string;
    @state() private _open = false;
    @state() private _confirmDelete = false;

    // View States
    @state() private _viewMode: 'default' | 'episodes' = 'default';
    @state() private _episodes: MediaItem[] = [];
    @state() private _selectedSeason: number | 'all' = 'all';

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
        window.addEventListener('keydown', this._handleKeyDown);
    }

    public disconnectedCallback(): void {
        super.disconnectedCallback();
        window.removeEventListener('keydown', this._handleKeyDown);
        if (this._portalContainer) {
            this._portalContainer.remove();
            this._portalContainer = null;
        }
        document.body.style.overflow = '';
    }

    private _handleKeyDown = (e: KeyboardEvent) => {
        if (e.key === 'Escape' && this._open) {
            this.closeDialog();
        }
    }

    public async showDialog(params: { item: MediaItem; hass: HomeAssistant; defaultCastDevice?: string; serverEntityId?: string }): Promise<void> {
        this._item = params.item;
        this.hass = params.hass;
        this._defaultCastDevice = params.defaultCastDevice;
        this._serverEntityId = params.serverEntityId;
        this._open = true;
        this._nextUpItem = undefined; // Reset
        this._viewMode = 'default';
        this._episodes = [];
        this._selectedSeason = 'all';
        document.body.style.overflow = 'hidden';

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
        document.body.style.overflow = '';
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
                    entity_id: this._serverEntityId,
                    server_entity_id: this._serverEntityId,
                    config_entry_id: this._item?.config_entry_id
                },
                return_response: true
            });

            // Access nested response from service call (WebSocket or REST format)
            const serviceResponse = response?.response || response?.service_response || response;

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
        // Find a valid entity_id for the WS call (we need a JellyHA sensor with entry_id)
        const entities = Object.keys(this.hass.states).filter(eid =>
            (this.hass.states[eid].attributes.integration === 'jellyha' ||
             eid.startsWith('sensor.jellyha_')) &&
            this.hass.states[eid].attributes.entry_id
        );

        // Use the passed server entity or fallback
        const entityId = this._serverEntityId || (entities.length > 0 ? entities[0] : 'sensor.jellyha_library');

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
        if (!this._item || this._item.type !== 'Series') return;

        // Find valid entity ID that has entry_id
        const entities = Object.keys(this.hass.states).filter(eid =>
            (this.hass.states[eid].attributes.integration === 'jellyha' ||
             eid.startsWith('sensor.jellyha_')) &&
            this.hass.states[eid].attributes.entry_id
        );
        const entityId = this._serverEntityId || (entities.length > 0 ? entities[0] : 'sensor.jellyha_library');

        try {
            this._viewMode = 'episodes'; // Switch view immediately for better UX responsiveness
            this.requestUpdate();

            let result: { items: MediaItem[] } | null = null;
            try {
                // Try fetching without season to get all episodes across all seasons
                result = await this.hass.callWS<{ items: MediaItem[] }>({
                    type: 'jellyha/get_episodes',
                    entity_id: entityId,
                    series_id: this._item.id
                });
            } catch (wsErr) {
                // Fallback for older backend versions that required the season parameter
                const fallbackSeason = this._nextUpItem?.season || 1;
                result = await this.hass.callWS<{ items: MediaItem[] }>({
                    type: 'jellyha/get_episodes',
                    entity_id: entityId,
                    series_id: this._item.id,
                    season: fallbackSeason
                });
            }

            if (result && result.items) {
                this._episodes = result.items;
            } else {
                this._episodes = [];
            }
            this.requestUpdate();
        } catch (err) {
            console.warn('Failed to fetch episodes:', err);
            this._episodes = [];
            this.requestUpdate();
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

            // Manually attach non-passive listeners to surface
            const content = this._portalContainer.querySelector('.jellyha-modal-surface');
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
            .jellyha-modal-scrim {
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                z-index: 99999;
                background: rgba(0, 0, 0, 0.72);
                backdrop-filter: blur(8px);
                -webkit-backdrop-filter: blur(8px);
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

            @keyframes jellyhaSlideUp {
                from { transform: scale(0.96) translateY(16px); opacity: 0; }
                to { transform: scale(1) translateY(0); opacity: 1; }
            }

            .jellyha-modal-surface {
                position: relative;
                display: flex;
                flex-direction: column;
                transform-origin: center center;
                will-change: transform;
                background: #14161f;
                color: #ffffff;
                border-radius: 24px;
                box-shadow: 0 24px 72px rgba(0, 0, 0, 0.8), 0 0 0 1px rgba(255, 255, 255, 0.1);
                width: min(840px, 94vw);
                max-height: min(90vh, 880px);
                overscroll-behavior-y: contain;
                scrollbar-width: none; 
                -ms-overflow-style: none; 
                overflow: hidden;
                animation: jellyhaSlideUp 0.25s cubic-bezier(0.16, 1, 0.3, 1);
            }

            .jellyha-modal-surface::-webkit-scrollbar {
                display: none; 
                width: 0px !important;
                height: 0px !important;
                background: transparent;
            }

            /* Top-Right Circular Close Button */
            .modal-close-btn {
                position: absolute;
                top: 16px;
                right: 16px;
                z-index: 20;
                background: rgba(255, 255, 255, 0.1);
                backdrop-filter: blur(8px);
                -webkit-backdrop-filter: blur(8px);
                border: 1px solid rgba(255, 255, 255, 0.2);
                border-radius: 50%;
                width: 38px;
                height: 38px;
                display: flex;
                align-items: center;
                justify-content: center;
                cursor: pointer;
                color: #ffffff;
                transition: all 0.2s ease;
                padding: 0;
            }
            .modal-close-btn:hover {
                background: rgba(255, 255, 255, 0.25);
                border-color: rgba(255, 255, 255, 0.4);
                transform: scale(1.08);
            }
            .modal-close-btn ha-icon {
                --mdc-icon-size: 20px;
            }

            /* Backdrop Hero Fanart */
            .backdrop-hero {
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                height: 320px;
                pointer-events: none;
                overflow: hidden;
                mask-image: linear-gradient(to bottom, rgba(0,0,0,1) 0%, rgba(0,0,0,0.65) 50%, rgba(0,0,0,0) 100%);
                -webkit-mask-image: linear-gradient(to bottom, rgba(0,0,0,1) 0%, rgba(0,0,0,0.65) 50%, rgba(0,0,0,0) 100%);
                z-index: 0;
            }

            .backdrop-img {
                width: 100%;
                height: 100%;
                object-fit: cover;
                object-position: center 25%;
                opacity: 0.35;
                filter: saturate(1.2) brightness(0.9);
            }

            /* Inner Layouts (Default View) */
            .default-layout {
                position: relative;
                z-index: 1;
                display: block;
                overflow-y: auto;
                height: 100%;
                width: 100%;
                box-sizing: border-box;
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
                    grid-template-columns: 240px 1fr;
                    gap: 28px;
                    padding: 28px;
                    overflow-y: auto; 
                }
                .poster-col {
                    width: 240px;
                }
            }

            @media (max-width: 600px) {
                .default-layout {
                    display: flex;
                    flex-direction: column;
                    gap: 20px;
                    padding: 20px;
                }
                .poster-col {
                    max-width: 240px;
                    margin: 0 auto;
                    width: 100%;
                }
            }

            .poster-col {
                display: flex;
                flex-direction: column;
                gap: 14px;
                position: relative;
                z-index: 1;
            }

            .poster-img {
                width: 100%;
                aspect-ratio: 2/3;
                object-fit: cover;
                border-radius: 14px;
                box-shadow: 0 10px 30px rgba(0, 0, 0, 0.6);
                border: 1px solid rgba(255, 255, 255, 0.12);
            }

            .poster-actions {
                display: flex;
                flex-direction: column;
                gap: 10px;
                width: 100%;
            }

            .primary-play-btn {
                display: flex;
                align-items: center;
                justify-content: center;
                gap: 8px;
                width: 100%;
                padding: 11px 16px;
                box-sizing: border-box;
                background: linear-gradient(135deg, #0288d1 0%, #00acc1 100%);
                color: #ffffff;
                border: none;
                border-radius: 24px;
                font-size: 0.95rem;
                font-weight: 600;
                cursor: pointer;
                box-shadow: 0 4px 16px rgba(2, 136, 209, 0.45);
                transition: all 0.2s ease;
            }
            .primary-play-btn:hover {
                filter: brightness(1.12);
                box-shadow: 0 6px 20px rgba(2, 136, 209, 0.6);
                transform: translateY(-1px);
            }
            .primary-play-btn:active {
                transform: scale(0.98);
            }
            .primary-play-btn ha-icon {
                --mdc-icon-size: 20px;
            }

            .actions-icon-row {
                display: flex;
                flex-wrap: wrap;
                gap: 6px;
                justify-content: center;
                align-items: center;
                width: 100%;
            }

            .action-btn {
                display: flex;
                align-items: center;
                justify-content: center;
                border-radius: 50%;
                border: 1px solid rgba(255, 255, 255, 0.16);
                cursor: pointer;
                background: rgba(255, 255, 255, 0.08);
                color: #d0d4e0;
                width: 34px;
                height: 34px;
                padding: 0;
                box-sizing: border-box;
                text-decoration: none;
                transition: all 0.2s ease;
            }
            .action-btn:hover {
                background: rgba(255, 255, 255, 0.2);
                color: #ffffff;
                border-color: rgba(255, 255, 255, 0.35);
                transform: translateY(-1px);
            }
            .action-btn.active {
                color: #03a9f4;
                border-color: #03a9f4;
                background: rgba(3, 169, 244, 0.2);
            }
            .action-btn.favorite-btn.active {
                color: #ff5252;
                border-color: #ff5252;
                background: rgba(255, 82, 82, 0.2);
            }
            .action-btn ha-icon {
                --mdc-icon-size: 18px;
            }

            .btn-danger {
                color: #ff5252;
                border-color: rgba(255, 82, 82, 0.35);
            }
            .btn-danger:hover {
                background: rgba(255, 82, 82, 0.25);
                border-color: #ff5252;
            }

            .confirmation-box {
                display: flex;
                gap: 8px;
                align-items: center;
                justify-content: center;
                width: 100%;
                background: rgba(255, 82, 82, 0.15);
                border: 1px solid rgba(255, 82, 82, 0.35);
                border-radius: 12px;
                padding: 8px;
                box-sizing: border-box;
                font-size: 0.85rem;
                color: #ffffff;
            }
            .confirm-btn {
                background: rgba(255, 255, 255, 0.12);
                border: none;
                cursor: pointer;
                color: #ffffff;
                font-weight: 600;
                padding: 5px 12px;
                border-radius: 6px;
                transition: background 0.2s;
            }
            .confirm-btn:hover {
                 background: rgba(255, 255, 255, 0.22);
            }
            .confirm-yes {
                background: #e53935;
                color: #ffffff;
            }
            .confirm-yes:hover {
                background: #d32f2f;
            }

            .details-col {
                display: flex;
                flex-direction: column;
                gap: 16px;
                position: relative;
                z-index: 1;
                min-width: 0;
            }

            .header-group {
                padding-right: 52px;
            }

            .header-group h1 {
                margin: 0;
                font-size: 2.1rem;
                font-weight: 700;
                line-height: 1.2;
                color: #ffffff;
                letter-spacing: -0.5px;
            }

            .header-sub {
                display: flex;
                flex-wrap: wrap;
                gap: 10px;
                align-items: center;
                margin-top: 8px;
                color: #9ea4b5;
                font-size: 0.95rem;
            }

            .badge {
                padding: 3px 8px;
                border-radius: 6px;
                background: rgba(255, 255, 255, 0.1);
                color: #ffffff;
                font-size: 0.8rem;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 0.4px;
                border: 1px solid rgba(255, 255, 255, 0.15);
            }

            .stats-row {
                display: flex;
                flex-wrap: wrap;
                gap: 10px;
                padding: 2px 0;
            }

            .stat-item {
                display: inline-flex;
                gap: 6px;
                align-items: center;
                border: 1px solid rgba(255, 255, 255, 0.14);
                background: rgba(255, 255, 255, 0.07);
                border-radius: 18px;
                padding: 5px 14px;
                font-size: 0.9rem;
                font-weight: 500;
                color: #e2e4ea;
            }
            .stat-item ha-icon {
                --mdc-icon-size: 16px;
            }

            .description {
                font-size: 0.95rem;
                line-height: 1.65;
                color: #c4c8d4;
                white-space: pre-wrap;
            }

            .genres-list {
                display: flex;
                flex-wrap: wrap;
                gap: 8px;
            }

            .genre-tag {
                background: rgba(3, 169, 244, 0.15);
                color: #4fc3f7;
                padding: 4px 12px;
                border-radius: 14px;
                font-size: 0.8rem;
                font-weight: 500;
                border: 1px solid rgba(3, 169, 244, 0.3);
            }

            .divider {
                height: 1px;
                background: rgba(255, 255, 255, 0.1);
                margin: 4px 0;
            }

            .tech-specs-row {
                display: flex;
                flex-wrap: wrap;
                gap: 8px;
                align-items: center;
                margin-top: 2px;
            }

            .tech-chip {
                display: inline-flex;
                align-items: center;
                gap: 5px;
                background: rgba(255, 255, 255, 0.08);
                border: 1px solid rgba(255, 255, 255, 0.16);
                border-radius: 6px;
                padding: 4px 10px;
                font-size: 0.75rem;
                font-weight: 600;
                letter-spacing: 0.6px;
                color: #c0c5d4;
                text-transform: uppercase;
            }
            .tech-chip ha-icon {
                --mdc-icon-size: 14px;
                color: #9ea4b5;
            }

            /* Next Up Modern Card */
            .next-up-card {
                background: rgba(255, 255, 255, 0.06);
                border: 1px solid rgba(255, 255, 255, 0.14);
                border-radius: 16px;
                padding: 12px 16px;
                display: flex;
                gap: 16px;
                align-items: center;
                cursor: pointer;
                transition: all 0.2s ease;
                position: relative;
                overflow: hidden;
                width: 100%;
                box-sizing: border-box;
            }
            .next-up-card:hover {
                background: rgba(255, 255, 255, 0.1);
                border-color: rgba(255, 255, 255, 0.28);
                transform: translateY(-1px);
            }
            .next-up-card:active {
                transform: scale(0.99);
            }
            .next-up-thumb-wrap {
                position: relative;
                width: 140px;
                flex-shrink: 0;
                aspect-ratio: 16/9;
                border-radius: 10px;
                overflow: hidden;
                background: rgba(0, 0, 0, 0.5);
                border: 1px solid rgba(255, 255, 255, 0.12);
            }
            .next-up-thumb {
                width: 100%;
                height: 100%;
                object-fit: cover;
                display: block;
            }
            .next-up-play-overlay {
                position: absolute;
                inset: 0;
                background: rgba(0, 0, 0, 0.4);
                display: flex;
                align-items: center;
                justify-content: center;
                opacity: 0;
                transition: opacity 0.2s ease;
            }
            .next-up-card:hover .next-up-play-overlay {
                opacity: 1;
            }
            .next-up-play-overlay ha-icon {
                --mdc-icon-size: 32px;
                color: #ffffff;
            }
            .next-up-info {
                flex: 1;
                min-width: 0;
                display: flex;
                flex-direction: column;
                gap: 4px;
            }
            .next-up-header-row {
                display: flex;
                align-items: center;
                gap: 8px;
            }
            .next-up-badge {
                font-size: 0.7rem;
                font-weight: 700;
                letter-spacing: 0.5px;
                color: #03a9f4;
                background: rgba(3, 169, 244, 0.16);
                padding: 2px 7px;
                border-radius: 4px;
                border: 1px solid rgba(3, 169, 244, 0.25);
            }
            .next-up-ep-code {
                font-size: 0.8rem;
                font-weight: 600;
                color: #9ea4b5;
            }
            .next-up-title {
                margin: 0;
                font-size: 1.15rem;
                font-weight: 600;
                color: #ffffff;
                white-space: nowrap;
                overflow: hidden;
                text-overflow: ellipsis;
            }
            .next-up-sub {
                display: flex;
                align-items: center;
                gap: 8px;
                font-size: 0.85rem;
                color: #9ea4b5;
            }
            .next-up-rating {
                display: inline-flex;
                align-items: center;
                gap: 3px;
                color: #FBC02D;
            }
            .next-up-rating ha-icon {
                --mdc-icon-size: 14px;
            }
            .next-up-cast-btn {
                background: rgba(3, 169, 244, 0.15);
                color: #03a9f4;
                border: 1px solid rgba(3, 169, 244, 0.3);
                border-radius: 50%;
                width: 42px;
                height: 42px;
                display: flex;
                align-items: center;
                justify-content: center;
                cursor: pointer;
                flex-shrink: 0;
                transition: all 0.2s ease;
                padding: 0;
            }
            .next-up-cast-btn:hover {
                background: #03a9f4;
                color: #ffffff;
                box-shadow: 0 0 12px rgba(3, 169, 244, 0.5);
                transform: scale(1.05);
            }
            .next-up-cast-btn ha-icon {
                --mdc-icon-size: 20px;
            }

            /* Episodes View specific */
            .jellyha-modal-surface.episodes {
                overflow: hidden !important; 
                padding: 28px;
                max-height: min(90vh, 880px);
                box-sizing: border-box;
            }

            /* Episode List Styles */
            .episodes-header {
                 display: flex;
                 align-items: center;
                 gap: 14px;
                 margin-bottom: 18px;
                 padding-right: 52px;
            }
            .back-btn {
                background: rgba(255, 255, 255, 0.08);
                border: 1px solid rgba(255, 255, 255, 0.15);
                color: #ffffff;
                cursor: pointer;
                width: 38px;
                height: 38px;
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 0;
                transition: all 0.2s ease;
            }
            .back-btn:hover {
                background: rgba(255, 255, 255, 0.2);
                border-color: rgba(255, 255, 255, 0.35);
                transform: scale(1.06);
            }
            .episodes-title {
                margin: 0;
                font-size: 1.6rem;
                font-weight: 700;
                color: #ffffff;
            }
            .season-selector {
                display: flex;
                gap: 8px;
                margin-bottom: 16px;
                overflow-x: auto;
                padding-bottom: 4px;
                scrollbar-width: none;
            }
            .season-selector::-webkit-scrollbar {
                display: none;
            }
            .season-tab {
                background: rgba(255, 255, 255, 0.08);
                border: 1px solid rgba(255, 255, 255, 0.15);
                color: rgba(255, 255, 255, 0.8);
                padding: 6px 14px;
                border-radius: 20px;
                cursor: pointer;
                font-size: 0.85rem;
                font-weight: 500;
                transition: all 0.2s ease;
                white-space: nowrap;
            }
            .season-tab:hover {
                background: rgba(255, 255, 255, 0.15);
                color: #ffffff;
            }
            .season-tab.active {
                background: var(--primary-color, #03a9f4);
                border-color: var(--primary-color, #03a9f4);
                color: #ffffff;
                font-weight: 600;
            }
            .episodes-list {
                display: flex;
                flex-direction: column;
                gap: 12px;
                overflow-y: auto;
                flex: 1;
                min-height: 0;
                padding-right: 4px;
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
                padding: 12px 16px;
                background: rgba(255, 255, 255, 0.04);
                border: 1px solid rgba(255, 255, 255, 0.08);
                border-radius: 14px;
                align-items: center;
                transition: all 0.2s ease;
                cursor: pointer;
            }
            .episode-row:hover {
                background: rgba(255, 255, 255, 0.09);
                border-color: rgba(255, 255, 255, 0.2);
            }
            .episode-row.next-up-highlight {
                background: rgba(3, 169, 244, 0.12);
                border-left: 4px solid #03a9f4;
            }
            .episode-thumb {
                width: 120px;
                aspect-ratio: 16/9;
                object-fit: cover;
                border-radius: 8px;
                flex-shrink: 0; 
                background: rgba(0, 0, 0, 0.4);
                border: 1px solid rgba(255, 255, 255, 0.12);
            }
            .episode-content {
                flex: 1;
                min-width: 0;
                display: flex;
                flex-direction: column;
                justify-content: center;
                gap: 4px;
            }
            .episode-title {
                margin: 0;
                font-size: 1rem;
                font-weight: 600;
                line-height: 1.3;
                color: #ffffff;
            }
            .episode-footer {
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            .episode-meta {
                font-size: 0.85rem;
                color: #9ea4b5;
                display: flex;
                align-items: center;
            }
            .episode-actions {
                display: flex;
                gap: 8px;
            }
            .play-episode-btn {
                background: rgba(255, 255, 255, 0.08);
                border: 1px solid rgba(255, 255, 255, 0.15);
                color: #03a9f4;
                border-radius: 50%;
                width: 34px;
                height: 34px;
                display: flex;
                align-items: center;
                justify-content: center;
                cursor: pointer;
                transition: all 0.2s;
                padding: 0;
            }
            .play-episode-btn:hover {
                background: rgba(255, 255, 255, 0.2);
                transform: scale(1.08);
            }
            .play-episode-btn ha-icon {
                --mdc-icon-size: 18px;
            }
            .watched-btn {
                color: #9ea4b5;
            }
            .watched-btn.active {
                color: #03a9f4;
                background: rgba(3, 169, 244, 0.2);
                border-color: #03a9f4;
            }
        </style>
        `;
    }

    private _renderDialogContent(): TemplateResult {
        if (!this._open || !this._item) return html``;

        return html`
            ${this._getPortalStyles()}
            <div class="jellyha-modal-scrim" @click=${this.closeDialog}>
                <div 
                    class="jellyha-modal-surface ${this._viewMode}" 
                    @click=${(e: Event) => e.stopPropagation()}
                    style="${this._isDragging || this._currentTranslateY > 0 ? `transform: translateY(${this._currentTranslateY}px); transition: ${this._isDragging ? 'none' : 'transform 0.3s ease-out'}` : ''}"
                >
                    <button class="modal-close-btn" @click=${this.closeDialog} aria-label="Close" title="Close">
                        <ha-icon icon="mdi:close"></ha-icon>
                    </button>
                    ${(() => {
                        const backdrop = this._item.backdrop_url || (this._item.type === 'Episode' ? (this._item.series_poster_url || this._item.poster_url) : this._item.poster_url);
                        return backdrop ? html`
                            <div class="backdrop-hero">
                                <img class="backdrop-img" src="${backdrop}" alt="" />
                            </div>
                        ` : nothing;
                    })()}
                    ${this._viewMode === 'episodes' ? this._renderEpisodesContent() : this._renderDefaultContent()}
                </div>
            </div>
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

                <div class="poster-actions">
                    ${this._confirmDelete
                        ? html`
                            <div class="confirmation-box">
                                <span>Delete item?</span>
                                <button class="confirm-btn confirm-yes" @click=${this._handleDeleteConfirm}>Yes</button>
                                <button class="confirm-btn" @click=${() => this._confirmDelete = false}>No</button>
                            </div>
                        `
                        : html`
                            <!-- Primary Play / Cast Button -->
                            <button class="primary-play-btn" @click=${this._handlePlay} title="Play on Chromecast">
                                <ha-icon icon="mdi:cast"></ha-icon>
                                <span>Play on Cast</span>
                            </button>

                            <!-- Secondary Action Icons Toolbar -->
                            <div class="actions-icon-row">
                                ${isSeries ? html`
                                    <button class="action-btn" @click=${(e: Event) => { this._haptic(); this._toggleEpisodesView(e); }} title="View All Episodes" type="button">
                                        <ha-icon icon="mdi:format-list-bulleted"></ha-icon>
                                    </button>
                                ` : nothing}

                                ${item.trailer_url ? html`
                                    <button class="action-btn" @click=${this._handleWatchTrailer} title="Watch Trailer">
                                        <ha-icon icon="mdi:filmstrip"></ha-icon>
                                    </button>
                                ` : nothing}

                                <button class="action-btn ${item.is_played ? 'active' : ''}" @click=${this._handleWatched} title="${item.is_played ? 'Mark Unwatched' : 'Mark Watched'}">
                                    <ha-icon icon="mdi:check"></ha-icon>
                                </button>

                                <button class="action-btn favorite-btn ${item.is_favorite ? 'active' : ''}" @click=${this._handleFavorite} title="${item.is_favorite ? 'Remove Favorite' : 'Add to Favorites'}">
                                    <ha-icon icon="${item.is_favorite ? 'mdi:heart' : 'mdi:heart-outline'}"></ha-icon>
                                </button>

                                <a href="javascript:void(0)" class="action-btn" title="Open in Jellyfin" @click=${(e: Event) => { e.preventDefault(); this._haptic(); this._openExternalUrl(item.jellyfin_url); }}>
                                    <ha-icon icon="mdi:open-in-new"></ha-icon>
                                </a>

                                <button class="action-btn btn-danger" @click=${() => { this._haptic(); this._confirmDelete = true; }} title="Delete Item">
                                    <ha-icon icon="mdi:trash-can-outline"></ha-icon>
                                </button>
                            </div>
                        `}
                </div>
            </div>

            <div class="details-col">
                <div class="header-group">
                    <h1>${item.name}</h1>
                    <div class="header-sub">
                        ${item.series_name ? html`<span>${item.series_name}</span>` : nothing}
                        ${item.type === 'Episode' && item.season != null && item.episode != null ? html`<span class="badge">S${String(item.season).padStart(2, '0')}E${String(item.episode).padStart(2, '0')}</span>` : nothing}
                        ${year ? html`<span>${year}</span>` : nothing}
                        <span class="badge">${item.type}</span>
                        ${item.official_rating ? html`<span class="badge">${item.official_rating}</span>` : nothing}
                    </div>
                </div>
                
                ${this._nextUpItem ? html`
                    <div class="next-up-card" @click=${this._playNextUp}>
                        <div class="next-up-thumb-wrap">
                            <img class="next-up-thumb" src="${this._nextUpItem.poster_url || this._nextUpItem.backdrop_url || this._item.poster_url}" alt="${this._nextUpItem.name}" />
                            <div class="next-up-play-overlay">
                                <ha-icon icon="mdi:play"></ha-icon>
                            </div>
                        </div>
                        <div class="next-up-info">
                            <div class="next-up-header-row">
                                <span class="next-up-badge">NEXT UP</span>
                                ${this._nextUpItem.season != null && this._nextUpItem.episode != null ? html`
                                    <span class="next-up-ep-code">S${this._nextUpItem.season}:E${this._nextUpItem.episode}</span>
                                ` : nothing}
                            </div>
                            <h3 class="next-up-title">${this._nextUpItem.name}</h3>
                            <div class="next-up-sub">
                                ${this._nextUpItem.runtime_minutes ? html`<span>${this._formatRuntime(this._nextUpItem.runtime_minutes)}</span>` : nothing}
                                ${this._nextUpItem.rating ? html`
                                    <span>•</span>
                                    <span class="next-up-rating"><ha-icon icon="mdi:star"></ha-icon> ${this._nextUpItem.rating.toFixed(1)}</span>
                                ` : nothing}
                            </div>
                        </div>
                        <button class="next-up-cast-btn" title="Cast Next Up" @click=${(e: Event) => { e.stopPropagation(); this._playNextUp(); }}>
                            <ha-icon icon="mdi:cast"></ha-icon>
                        </button>
                    </div>
                ` : nothing}

                <div class="stats-row">
                    ${item.rating ? html`
                        <div class="stat-item">
                            <ha-icon icon="mdi:star" style="color: #FBC02D;"></ha-icon>
                            <span>${item.rating.toFixed(1)}</span>
                        </div>
                    ` : nothing}
                    ${isSeries ? html`
                        ${item.unplayed_count !== undefined ? html`
                            <div class="stat-item">
                                <ha-icon icon="mdi:television-classic"></ha-icon>
                                <span>${item.unplayed_count} Unplayed</span>
                            </div>
                        ` : nothing}
                    ` : html`
                        ${item.runtime_minutes ? html`
                            <div class="stat-item">
                                <ha-icon icon="mdi:clock-outline"></ha-icon>
                                <span>${this._formatRuntime(item.runtime_minutes)}</span>
                            </div>
                        ` : nothing}
                    `}
                </div>

                ${item.description ? html`<div class="description">${item.description}</div>` : nothing}

                ${item.genres && item.genres.length > 0 ? html`
                    <div class="genres-list">
                        ${item.genres.map(g => html`<span class="genre-tag">${g}</span>`)}
                    </div>
                ` : nothing}

                ${this._renderMediaDetails(isSeries && this._nextUpItem ? this._nextUpItem : item)}
            </div>
        </div>
        `;
    }

    private _renderEpisodesContent(): TemplateResult {
        if (!this._item) return html``;

        // Prefer explicit season name, fallback to series name
        const title = this._item.name;

        // Collect available seasons
        const seasons = Array.from(
            new Set(
                this._episodes
                    .map(ep => ep.season)
                    .filter((s): s is number => typeof s === 'number' && !isNaN(s))
            )
        ).sort((a, b) => a - b);

        const displayedEpisodes = this._selectedSeason && this._selectedSeason !== 'all'
            ? this._episodes.filter(ep => ep.season === this._selectedSeason)
            : this._episodes;

        // Use full height wrapper for sticky header + scrollable list
        return html`
            <div style="display: flex; flex-direction: column; height: 100%; overflow: hidden; position: relative; z-index: 1;">
                <div class="episodes-header">
                    <button class="back-btn" @click=${(e: Event) => this._toggleEpisodesView(e)} type="button" title="Back to Details">
                        <ha-icon icon="mdi:arrow-left"></ha-icon>
                    </button>
                    <h2 class="episodes-title">${title}</h2>
                </div>

                ${seasons.length > 1 ? html`
                    <div class="season-selector">
                        <button class="season-tab ${this._selectedSeason === 'all' || !this._selectedSeason ? 'active' : ''}" @click=${() => { this._selectedSeason = 'all'; this.requestUpdate(); }}>All</button>
                        ${seasons.map(s => html`
                            <button class="season-tab ${this._selectedSeason === s ? 'active' : ''}" @click=${() => { this._selectedSeason = s; this.requestUpdate(); }}>Season ${s}</button>
                        `)}
                    </div>
                ` : nothing}
                
                <div class="episodes-list">
                    ${displayedEpisodes.length === 0 ? html`
                        <div style="text-align: center; color: rgba(255,255,255,0.6); padding: 40px 20px;">
                            No episodes found.
                        </div>
                    ` : displayedEpisodes.map(ep => html`
                        <div class="episode-row ${this._nextUpItem && ep.id === this._nextUpItem.id ? 'next-up-highlight' : ''}" @click=${(e: Event) => { e.stopPropagation(); this._handlePlayEpisode(ep); }}>
                            <img class="episode-thumb" src="${ep.poster_url || ep.backdrop_url || this._item!.poster_url}" alt="${ep.name || ''}" />
                            
                            <div class="episode-content">
                                <h4 class="episode-title">
                                    ${ep.season ? `S${ep.season}:E${ep.episode || ep.index_number || ''}` : `${ep.episode || ep.index_number || ''}`}. ${ep.name || 'Episode'}
                                    ${this._nextUpItem && ep.id === this._nextUpItem.id ? html`<span style="font-size: 0.7em; background: var(--primary-color, #03a9f4); color: white; padding: 2px 6px; border-radius: 4px; margin-left: 8px; vertical-align: middle; white-space: nowrap;">NEXT UP</span>` : nothing}
                                </h4>
                                
                                <div class="episode-footer">
                                    <div class="episode-meta">
                                        <span>${this._formatRuntime(ep.runtime_minutes)}</span>
                                        ${ep.rating ? html` <ha-icon icon="mdi:star" style="--mdc-icon-size: 14px; color: #FBC02D; margin-left: 6px; transform: translateY(-1px);"></ha-icon> ${ep.rating.toFixed(1)}` : nothing}
                                    </div>

                                    <div class="episode-actions">
                                        <button class="play-episode-btn watched-btn ${ep.is_played ? 'active' : ''}" @click=${(e: Event) => { e.stopPropagation(); this._handleMarkEpisodeWatched(ep); }} type="button" title="${ep.is_played ? 'Mark Unwatched' : 'Mark Watched'}">
                                            <ha-icon icon="mdi:check"></ha-icon>
                                        </button>

                                        <button class="play-episode-btn" @click=${(e: Event) => { e.stopPropagation(); this._handlePlayEpisode(ep); }} type="button" title="Play Episode">
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

    private _renderMediaDetails(item: MediaItem): TemplateResult {
        const chips: TemplateResult[] = [];
        const streams = item.media_streams || [];

        // Find Video Stream
        const videoStream = streams.find(s => s.Type?.toLowerCase() === 'video');
        if (videoStream) {
            if (videoStream.Width && videoStream.Height) {
                let resLabel = '';
                if (videoStream.Width >= 3800 || videoStream.Height >= 2000) {
                    resLabel = '4K UHD';
                } else if (videoStream.Height >= 1000 || videoStream.Width >= 1900) {
                    resLabel = '1080p';
                } else if (videoStream.Height >= 700 || videoStream.Width >= 1200) {
                    resLabel = '720p';
                } else {
                    resLabel = `${videoStream.Width}x${videoStream.Height}`;
                }
                chips.push(html`<span class="tech-chip"><ha-icon icon="mdi:video-outline"></ha-icon>${resLabel}</span>`);
            }
            if (videoStream.Codec) {
                chips.push(html`<span class="tech-chip">${videoStream.Codec.toUpperCase()}</span>`);
            }
        }

        // Find Primary Audio Stream (Default or First)
        const audioStream = streams.find(s => s.Type?.toLowerCase() === 'audio' && !!s.IsDefault) ||
            streams.find(s => s.Type?.toLowerCase() === 'audio');

        if (audioStream) {
            if (audioStream.Codec) {
                chips.push(html`<span class="tech-chip"><ha-icon icon="mdi:volume-high"></ha-icon>${audioStream.Codec.toUpperCase()}</span>`);
            }
            if (audioStream.Channels) {
                let chLabel = `${audioStream.Channels} ch`;
                if (audioStream.Channels === 6) chLabel = '5.1';
                else if (audioStream.Channels === 8) chLabel = '7.1';
                else if (audioStream.Channels === 2) chLabel = 'Stereo';
                chips.push(html`<span class="tech-chip">${chLabel}</span>`);
            }
        }

        if (chips.length === 0) return html``;

        return html`
            <div class="divider"></div>
            <div class="tech-specs-row">
                ${chips}
            </div>
        `;
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
                server_entity_id: this._serverEntityId,
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
        const targetItem = (this._item?.type === 'Series' && this._nextUpItem) ? this._nextUpItem : this._item;
        if (!targetItem || !this._defaultCastDevice) {
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
                item_id: targetItem.id,
                server_entity_id: this._serverEntityId,
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
                server_entity_id: this._serverEntityId,
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

        const serviceData: any = {
            item_id: this._item.id,
            is_favorite: newStatus,
        };
        if (this._serverEntityId) {
            serviceData.entity_id = this._serverEntityId;
            serviceData.server_entity_id = this._serverEntityId;
        }

        await this.hass.callService('jellyha', 'update_favorite', serviceData);
        this.requestUpdate();
    }

    private _handleWatched = async () => {
        if (!this._item) return;
        this._haptic(); // Feedback
        const newStatus = !this._item.is_played;
        this._item = { ...this._item, is_played: newStatus };

        const serviceData: any = {
            item_id: this._item.id,
            is_played: newStatus,
        };
        if (this._serverEntityId) {
            serviceData.entity_id = this._serverEntityId;
            serviceData.server_entity_id = this._serverEntityId;
        }

        await this.hass.callService('jellyha', 'mark_watched', serviceData);
        this.requestUpdate();
    }

    private _handleDeleteConfirm = async () => {
        if (!this._item) return;
        this._haptic(); // Feedback
        const itemId = this._item.id;
        this.closeDialog();

        const serviceData: any = {
            item_id: itemId,
        };
        if (this._serverEntityId) {
            serviceData.entity_id = this._serverEntityId;
            serviceData.server_entity_id = this._serverEntityId;
        }

        await this.hass.callService('jellyha', 'delete_item', serviceData);
    }

    private _handleWatchTrailer = () => {
        this._haptic();
        const item = this._item;
        if (!item?.trailer_url) return;
        let url = item.trailer_url.trim();
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            url = 'https://' + url;
        }

        // Extract YouTube ID if possible
        // Standard formats: youtube.com/watch?v=ID, youtu.be/ID, youtube.com/embed/ID, youtube.com/shorts/ID
        let youtubeId = '';
        try {
            const urlObj = new URL(url);
            if (urlObj.hostname.includes('youtube.com')) {
                if (urlObj.searchParams.has('v')) {
                    youtubeId = urlObj.searchParams.get('v') || '';
                } else if (urlObj.pathname.startsWith('/embed/')) {
                    youtubeId = urlObj.pathname.split('/embed/')[1]?.split('/')[0] || '';
                } else if (urlObj.pathname.startsWith('/shorts/')) {
                    youtubeId = urlObj.pathname.split('/shorts/')[1]?.split('/')[0] || '';
                }
            } else if (urlObj.hostname.includes('youtu.be')) {
                youtubeId = urlObj.pathname.replace(/^\/+/, '').split('/')[0] || '';
            }
        } catch (e) {
            // ignore invalid urls
        }

        if (youtubeId) {
            const ua = navigator.userAgent || navigator.vendor || (window as any).opera;
            const isAndroid = /android/i.test(ua);

            if (isAndroid) {
                window.open(`vnd.youtube:${youtubeId}`, '_blank');
                return;
            }
            window.open(`https://www.youtube.com/watch?v=${youtubeId}`, '_blank');
            return;
        }

        // Directly open the trailer URL in a new window (never rewrite through Jellyfin external URL!)
        window.open(url, '_blank');
    }

    private _openExternalUrl(url: string | undefined): void {
        if (!url) return;

        // Never rewrite YouTube or external third-party video services
        try {
            const parsed = new URL(url);
            if (parsed.hostname.includes('youtube.com') || parsed.hostname.includes('youtu.be') || parsed.hostname.includes('vimeo.com')) {
                window.open(url, '_blank');
                return;
            }
        } catch (e) {
            // ignore
        }

        // Try to get external configure URL if we have an item.
        // We need to look up the entity state.
        // In the modal, we don't directly have access to the entity ID that launched it, 
        // but we can try to find ANY JellyHA sensor, or rely on the frontend to pass it down.
        // For simplicity, find the first jellyha_library sensor or let the user click standard.
        // Actually, we can get it from the `item` potentially, but it's not saved there.
        // Let's check all states for `config_external_url`. They should all be the same for one server.
        let externalUrl: string | undefined;
        if (this.hass && this.hass.states) {
            for (const entityId in this.hass.states) {
                if (entityId.startsWith('sensor.') && this.hass.states[entityId].attributes?.config_external_url) {
                    externalUrl = this.hass.states[entityId].attributes.config_external_url as string;
                    break;
                }
            }
        }

        if (externalUrl && externalUrl.trim() !== '') {
            try {
                const originalUrlObj = new URL(url);
                const externalUrlObj = new URL(externalUrl);

                originalUrlObj.protocol = externalUrlObj.protocol;
                originalUrlObj.host = externalUrlObj.host;
                originalUrlObj.port = externalUrlObj.port || '';

                const extPath = externalUrlObj.pathname === '/' ? '' : externalUrlObj.pathname;
                if (extPath && !originalUrlObj.pathname.startsWith(extPath)) {
                    originalUrlObj.pathname = extPath + originalUrlObj.pathname;
                }

                window.open(originalUrlObj.toString(), '_blank');
                return;
            } catch (e) {
                console.warn('JellyHA: Failed to parse URLs to inject external URL override', e);
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

        const serviceData: any = {
            item_id: episode.id,
            is_played: newStatus,
        };
        if (this._serverEntityId) {
            serviceData.entity_id = this._serverEntityId;
            serviceData.server_entity_id = this._serverEntityId;
        }

        await this.hass.callService('jellyha', 'mark_watched', serviceData);
    }


    /* Swipe to Close Logic */
    private _getScrollParent(node: HTMLElement | null): HTMLElement | null {
        if (!node) return null;

        let parent = node;
        while (parent && parent !== this._portalContainer && parent !== document.body) {
            // Optimization: The '.jellyha-modal-surface' element or layout is our main scroll container.
            if (parent.classList?.contains('jellyha-modal-surface') || parent.classList?.contains('default-layout') || parent.classList?.contains('episodes-list')) {
                if (parent.scrollHeight > parent.clientHeight) {
                    return parent;
                }
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
