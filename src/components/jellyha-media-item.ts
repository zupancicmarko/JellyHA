import { LitElement, html, nothing, TemplateResult } from 'lit';
import { customElement, property, state } from 'lit/decorators.js';
import { HomeAssistant, MediaItem, JellyHALibraryCardConfig } from '../shared/types';
import { isNewItem, formatDate, formatRuntime } from '../shared/utils';
import { localize } from '../shared/localize';
import { cardStyles } from '../styles/jellyha-library-styles';

@customElement('jellyha-media-item')
export class JellyHAMediaItem extends LitElement {
  @property({ attribute: false }) hass!: HomeAssistant;
  @property({ attribute: false }) config!: JellyHALibraryCardConfig;
  @property({ attribute: false }) item!: MediaItem;
  @property({ type: String }) layout: 'grid' | 'list' = 'grid';

  @state() private _pressStartTime: number = 0;
  @state() private _holdTimer?: number;
  @state() private _isHoldActive: boolean = false;
  @state() private _itemTouchStartX: number = 0;
  @state() private _itemTouchStartY: number = 0;

  // Local state for rewind animation
  @state() private _rewindActive: boolean = false;

  static styles = cardStyles;

  protected render(): TemplateResult {
    if (!this.item || !this.config || !this.hass) return html``;

    if (this.layout === 'list') {
      return this._renderListItem();
    }
    return this._renderMediaItem();
  }

  private _renderListItem(): TemplateResult {
    const item = this.item;
    const isNew = isNewItem(item, this.config.new_badge_days || 0);
    const rating = this._getRating(item);
    const showMediaTypeBadge = this.config.show_media_type_badge !== false;
    const isPlaying = this._isItemPlaying(item);

    return html`
      <div
        class="media-item list-item ${isPlaying ? 'playing' : ''} ${!this.config.show_title ? 'no-title' : ''} ${this.config.metadata_position === 'above' ? 'metadata-above' : ''}"
        tabindex="0"
        role="button"
        aria-label="${item.name}"
        @mousedown="${this._handleMouseDown}"
        @mouseup="${this._handleMouseUp}"
        @touchstart="${this._handleTouchStart}"
        @touchmove="${this._handleTouchMove}"
        @touchend="${this._handleTouchEnd}"
        @touchcancel="${this._handleTouchEnd}"
        @keydown="${this._handleKeydown}"
      >
        <div class="list-poster-wrapper">
          ${this.config.metadata_position === 'above' && this.config.show_date_added && item.date_added
        ? html`<p class="list-date-added">${formatDate(item.date_added, this.hass?.language)}</p>`
        : nothing}
          <div class="poster-container" id="poster-${item.id}">
            <div class="poster-inner">
              <img
                class="poster"
                src="${item.poster_url}&width=300&format=webp"
                alt="${item.name}"
                width="80"
                height="120"
                loading="lazy"
                decoding="async"
                @load="${this._handleImageLoad}"
                @error="${this._handleImageError}"
              />
              <div class="poster-skeleton"></div>
              
              ${showMediaTypeBadge && !isPlaying
        ? html`<span class="list-type-badge ${item.type === 'Movie' ? 'movie' : 'series'}">
                    ${item.type === 'Movie' ? 'Movie' : 'Series'}
                  </span>`
        : nothing}
              
              ${!isPlaying ? this._renderStatusBadge(item, isNew) : nothing}
              ${this._renderNowPlayingOverlay(item)}
            </div>
          </div>
          ${this.config.metadata_position !== 'above' && this.config.show_date_added && item.date_added
        ? html`<p class="list-date-added">${formatDate(item.date_added, this.hass?.language)}</p>`
        : nothing}
        </div>
        
        <div class="list-info">
          ${this.config.show_title
        ? html`<h3 class="list-title">${item.name}</h3>`
        : nothing}
          
          <div class="list-metadata">
            ${showMediaTypeBadge && !isPlaying
        ? html`<span class="list-type-badge ${item.type === 'Movie' ? 'movie' : 'series'}">
                  ${item.type === 'Movie' ? 'Movie' : 'Series'}
                </span>`
        : nothing}
            ${this.config.show_year && item.year
        ? html`<span class="list-year">${item.year}</span>`
        : nothing}
            ${this.config.show_ratings && rating
        ? html`<span class="list-rating">
                  <ha-icon icon="mdi:star"></ha-icon>
                  ${rating.toFixed(1)}
                </span>`
        : nothing}
            ${this.config.show_runtime && item.runtime_minutes
        ? html`<span class="list-runtime">
                  <ha-icon icon="mdi:clock-outline"></ha-icon>
                  ${formatRuntime(item.runtime_minutes)}
                </span>`
        : nothing}
          </div>
          
          ${this.config.show_genres && item.genres && item.genres.length > 0
        ? html`<p class="list-genres">${item.genres.slice(0, 3).join(', ')}</p>`
        : nothing}
          
          ${this.config.show_description_on_hover !== false && item.description
        ? html`<p class="list-description">${item.description}</p>`
        : nothing}
        </div>
      </div>
    `;
  }

  private _renderMediaItem(): TemplateResult {
    const item = this.item;
    const isNew = isNewItem(item, this.config.new_badge_days || 0);
    const rating = this._getRating(item);
    const showMediaTypeBadge = this.config.show_media_type_badge !== false;
    const isPlaying = this._isItemPlaying(item);

    return html`
      <div
        class="media-item ${isPlaying ? 'playing' : ''}"
        tabindex="0"
        role="button"
        aria-label="${item.name}"
        @mousedown="${this._handleMouseDown}"
        @mouseup="${this._handleMouseUp}"
        @touchstart="${this._handleTouchStart}"
        @touchmove="${this._handleTouchMove}"
        @touchend="${this._handleTouchEnd}"
        @touchcancel="${this._handleTouchEnd}"
        @keydown="${this._handleKeydown}"
      >
        ${this.config.metadata_position === 'above'
        ? html`
              <div class="media-info-above">
                ${this.config.show_title
            ? html`<p class="media-title">${item.name}</p>`
            : nothing}
                ${this.config.show_year && item.year
            ? html`<p class="media-year">${item.year}</p>`
            : nothing}
                ${this.config.show_date_added && item.date_added
            ? html`<p class="media-date-added">${formatDate(item.date_added, this.hass?.language)}</p>`
            : nothing}
              </div>
            `
        : nothing}
        <div class="poster-container" id="poster-${item.id}">
          <div class="poster-inner">
            <img
              class="poster"
              src="${item.poster_url}&width=300&format=webp"
              alt="${item.name}"
              width="140"
              height="210"
              loading="lazy"
              decoding="async"
              @load="${this._handleImageLoad}"
              @error="${this._handleImageError}"
            />
            <div class="poster-skeleton"></div>
            
            ${showMediaTypeBadge && !isPlaying
        ? html`<span class="media-type-badge ${item.type === 'Movie' ? 'movie' : 'series'}">
                  ${item.type === 'Movie' ? 'Movie' : 'Series'}
                </span>`
        : nothing}
            
            ${!isPlaying ? this._renderStatusBadge(item, isNew) : nothing}
            
            ${this.config.show_ratings && rating && !isPlaying
        ? html`
                  <span class="rating">
                    <ha-icon icon="mdi:star"></ha-icon>
                    ${rating.toFixed(1)}
                  </span>
                `
        : nothing}
            
            ${this.config.show_runtime && item.runtime_minutes && !isPlaying
        ? html`
                  <span class="runtime">
                    <ha-icon icon="mdi:clock-outline"></ha-icon>
                    ${formatRuntime(item.runtime_minutes)}
                  </span>
                `
        : nothing}
            
            ${!isPlaying ? html`
            <div class="hover-overlay">
              ${item.year ? html`<span class="overlay-year">${item.year}</span>` : nothing}
              <h3 class="overlay-title">${item.name}</h3>
              ${this.config.show_genres && item.genres && item.genres.length > 0
          ? html`<span class="overlay-genres">${item.genres.slice(0, 3).join(', ')}</span>`
          : nothing}
              ${this.config.show_description_on_hover !== false && item.description
          ? html`<p class="overlay-description">${item.description}</p>`
          : nothing}
            </div>` : nothing}

            ${this._renderNowPlayingOverlay(item)}
          </div>
        </div>
        
        ${this.config.metadata_position === 'below'
        ? html`
              <div class="media-info-below">
                ${this.config.show_title
            ? html`<p class="media-title">${item.name}</p>`
            : nothing}
                ${this.config.show_year && item.year
            ? html`<p class="media-year">${item.year}</p>`
            : nothing}
                ${this.config.show_date_added && item.date_added
            ? html`<p class="media-date-added">${formatDate(item.date_added, this.hass?.language)}</p>`
            : nothing}
              </div>
            `
        : nothing}
      </div>
    `;
  }

  private _renderStatusBadge(item: MediaItem, isNew: boolean): TemplateResult {
    const showWatched = this.config.show_watched_status !== false;

    if (showWatched && item.is_played) {
      return html`
        <div class="status-badge watched">
          <ha-icon icon="mdi:check-bold"></ha-icon>
        </div>
      `;
    }

    if (showWatched && item.type === 'Series' && (item.unplayed_count || 0) > 0) {
      return html`
        <div class="status-badge unplayed">
          ${item.unplayed_count}
        </div>
      `;
    }

    if (isNew) {
      return html`<span class="new-badge">${localize(this.hass.language, 'new')}</span>`;
    }

    return html``;
  }

  private _renderNowPlayingOverlay(item: MediaItem): TemplateResult | typeof nothing {
    if (!this.config.show_now_playing || !this._isItemPlaying(item)) {
      return nothing;
    }

    const player = this.hass.states[this.config.default_cast_device!];

    return html`
      <div 
        class="now-playing-overlay" 
        @click="${() => this._handleRewind(this.config.default_cast_device!)}"
        @mousedown="${this._stopPropagation}"
        @mouseup="${this._stopPropagation}"
        @touchstart="${this._stopPropagation}"
        @touchend="${this._stopPropagation}"
        @touchcancel="${this._stopPropagation}"
        role="button"
        tabindex="0"
      >
        <span class="now-playing-status">
          ${this._rewindActive ? 'REWINDING' : player.state}
        </span>
        <div class="now-playing-controls">
          <ha-icon-button
            class="${this._rewindActive ? 'spinning' : ''}"
            .label=${'Play/Pause'}
            @click="${(e: Event) => { e.stopPropagation(); this._handlePlayPause(this.config.default_cast_device!); }}"
          >
            <ha-icon icon="${this._rewindActive ? 'mdi:loading' : (player.state === 'playing' ? 'mdi:pause' : 'mdi:play')}"></ha-icon>
          </ha-icon-button>
          <ha-icon-button
            class="stop"
            .label=${'Stop'}
            @click="${(e: Event) => { e.stopPropagation(); this._handleStop(this.config.default_cast_device!); }}"
          >
            <ha-icon icon="mdi:stop"></ha-icon>
          </ha-icon-button>
        </div>
      </div>
    `;
  }

  /* --- Helpers --- */

  private _isItemPlaying(item: MediaItem): boolean {
    if (!this.config.default_cast_device || !this.hass) return false;

    const player = this.hass.states[this.config.default_cast_device];
    if (!player || (player.state !== 'playing' && player.state !== 'paused' && player.state !== 'buffering')) {
      return false;
    }

    const playingTitle = player.attributes.media_title as string;
    const playingSeries = player.attributes.media_series_title as string;

    return (
      (item.name && (playingTitle === item.name || playingSeries === item.name)) ||
      (item.type === 'Series' && playingSeries === item.name)
    );
  }

  private _getRating(item: MediaItem): number | null {
    if (this.config.rating_source === 'auto') {
      return item.rating || null;
    }
    return item.rating || null;
  }

  /* --- Event Handlers --- */

  private _fireAction(type: 'click' | 'hold'): void {
    const event = new CustomEvent('jellyha-action', {
      detail: { type, item: this.item },
      bubbles: true,
      composed: true,
    });
    this.dispatchEvent(event);
  }

  private _startHoldTimer(): void {
    this._pressStartTime = Date.now();
    this._isHoldActive = false;
    this._holdTimer = window.setTimeout(() => {
      this._isHoldActive = true;
      this._fireAction('hold');
    }, 500);
  }

  private _clearHoldTimer(): void {
    if (this._holdTimer) {
      clearTimeout(this._holdTimer);
      this._holdTimer = undefined;
    }
  }

  private _handleMouseDown(e: MouseEvent): void {
    if (e.button !== 0) return;
    this._startHoldTimer();
  }

  private _handleMouseUp(e: MouseEvent): void {
    if (this._isHoldActive) {
      e.preventDefault();
      e.stopPropagation();
    } else {
      const duration = Date.now() - this._pressStartTime;
      if (duration < 500) {
        this._fireAction('click');
      }
    }
    this._clearHoldTimer();
  }

  private _handleTouchStart(e: TouchEvent): void {
    if (e.touches.length > 0) {
      this._itemTouchStartX = e.touches[0].clientX;
      this._itemTouchStartY = e.touches[0].clientY;

      const target = e.currentTarget as HTMLElement;
      target.classList.add('active-press');
    }
    this._startHoldTimer();
  }

  private _handleTouchMove(e: TouchEvent): void {
    if (e.touches.length > 0) {
      const diffX = Math.abs(e.touches[0].clientX - this._itemTouchStartX);
      const diffY = Math.abs(e.touches[0].clientY - this._itemTouchStartY);

      if (diffX > 10 || diffY > 10) {
        this._clearHoldTimer();
        const target = e.currentTarget as HTMLElement;
        target.classList.remove('active-press');
      }
    }
  }

  private _handleTouchEnd(e: TouchEvent): void {
    const target = e.currentTarget as HTMLElement;
    target.classList.remove('active-press');

    this._clearHoldTimer();

    let dist = 0;
    if (e.changedTouches.length > 0) {
      const diffX = e.changedTouches[0].clientX - this._itemTouchStartX;
      const diffY = e.changedTouches[0].clientY - this._itemTouchStartY;
      dist = Math.sqrt(diffX * diffX + diffY * diffY);
    }

    e.preventDefault();

    if (this._isHoldActive) {
      this._isHoldActive = false;
      return;
    }

    if (dist > 10) {
      return;
    }

    this._fireAction('click');
  }

  private _handleKeydown(e: KeyboardEvent): void {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      this._fireAction('click');
    }
  }

  private _handleImageLoad(e: Event): void {
    const img = e.target as HTMLImageElement;
    img.classList.add('loaded');
  }

  private _handleImageError(e: Event): void {
    const img = e.target as HTMLImageElement;
    img.style.display = 'none';
  }

  /* --- Playback Control Handlers --- */

  private _stopPropagation(e: Event): void {
    e.stopPropagation();
  }

  private _handlePlayPause(entityId: string): void {
    this._dispatchHaptic();
    this.hass.callService('media_player', 'media_play_pause', { entity_id: entityId });
  }

  private _handleStop(entityId: string): void {
    this._dispatchHaptic();
    this.hass.callService('media_player', 'turn_off', { entity_id: entityId });
  }

  private _handleRewind(entityId: string): void {
    this._rewindActive = true;
    setTimeout(() => {
      this._rewindActive = false;
    }, 2000);

    this._dispatchHaptic();

    const player = this.hass.states[entityId];
    if (player && player.attributes.media_position) {
      const position = player.attributes.media_position as number;
      const validTime = player.attributes.media_position_updated_at as string;
      let currentPosition = position;

      if (validTime) {
        const now = new Date().getTime();
        const updated = new Date(validTime).getTime();
        const diff = (now - updated) / 1000;
        if (player.state === 'playing') {
          currentPosition += diff;
        }
      }

      const newPosition = Math.max(0, currentPosition - 20);

      this.hass.callService('media_player', 'media_seek', {
        entity_id: entityId,
        seek_position: newPosition
      });
    }
  }

  private _dispatchHaptic(): void {
    const event = new CustomEvent('haptic', {
      detail: 'selection',
      bubbles: true,
      composed: true,
    });
    this.dispatchEvent(event);
  }
}
