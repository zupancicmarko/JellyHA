import { LitElement, html, nothing, TemplateResult, PropertyValues } from 'lit';
import { customElement, property, state } from 'lit/decorators.js';
import { HomeAssistant, MediaItem, JellyHALibraryCardConfig } from '../shared/types';
import { isNewItem, formatDate, formatRuntime, addImageParams } from '../shared/utils';
import { localize } from '../shared/localize';
import { cardStyles } from '../styles/jellyha-library-styles';
import { findActiveMediaItemPlayer, stopMediaPlayback } from '../shared/power-volume-helpers';

@customElement('jellyha-media-item')
export class JellyHAMediaItem extends LitElement {
  @property({ attribute: false }) hass!: HomeAssistant;
  @property({ attribute: false }) config!: JellyHALibraryCardConfig;
  @property({ attribute: false }) item!: MediaItem;
  @property({ type: String }) layout: 'grid' | 'list' | 'featured-hero' | 'featured-queue' = 'grid';
  @property({ type: Boolean }) isNextUpHighlight = false;
  @property({ type: Boolean }) isCramped?: boolean;

  @state() private _pressStartTime: number = 0;
  @state() private _holdTimer?: number;
  @state() private _isHoldActive: boolean = false;
  @state() private _itemTouchStartX: number = 0;
  @state() private _itemTouchStartY: number = 0;
  @state() private _clickTimer?: number;

  // Local state for rewind animation and hold-to-stop
  @state() private _rewindActive: boolean = false;
  @state() private _longPressProgress: number = 0;
  @state() private _stopPulse: boolean = false;
  private _longPressRaf: number | null = null;
  private _longPressConsumed: boolean = false;
  private _metaResizeObserver?: ResizeObserver;

  static styles = cardStyles;

  firstUpdated(changedProps: PropertyValues): void {
    super.firstUpdated(changedProps);
    if (typeof ResizeObserver !== 'undefined') {
      this._metaResizeObserver = new ResizeObserver(() => {
        this._checkMetaWrap();
      });
      const metaRow = this.shadowRoot?.querySelector('.list-meta-row');
      if (metaRow) {
        this._metaResizeObserver.observe(metaRow);
      }
    }
  }

  disconnectedCallback(): void {
    super.disconnectedCallback();
    this._metaResizeObserver?.disconnect();
    if (this._longPressRaf) {
      cancelAnimationFrame(this._longPressRaf);
      this._longPressRaf = null;
    }
  }

  updated(changedProps: PropertyValues): void {
    super.updated(changedProps);
    this._checkMetaWrap();
    const metaRow = this.shadowRoot?.querySelector('.list-meta-row');
    if (metaRow && this._metaResizeObserver) {
      this._metaResizeObserver.observe(metaRow);
    }
  }

  private _checkMetaWrap(): void {
    const metaRow = this.shadowRoot?.querySelector('.list-meta-row') as HTMLElement | null;
    const card = this.shadowRoot?.querySelector('.media-item.list-item') as HTMLElement | null;
    if (metaRow && card) {
      const isWrapped = metaRow.offsetHeight > 22;
      card.classList.toggle('meta-wrapped', isWrapped);
    }
  }

  protected render(): TemplateResult {
    if (!this.item || !this.config || !this.hass) return html``;

    if (this.layout === 'list' || this.layout === 'featured-queue') {
      return this._renderListItem();
    }
    if (this.layout === 'featured-hero') {
      return this._renderFeaturedHero();
    }
    return this._renderMediaItem();
  }

  private _renderListItem(): TemplateResult {
    const item = this.item;
    const isNew = isNewItem(item, this.config.new_badge_days || 0);
    const rating = this._getRating(item);
    const showMediaTypeBadge = this.config.show_media_type_badge !== false;
    const isPlaying = this._isItemPlaying(item);
    const showRatings = (this.config as any).show_ratings !== false && (this.config as any).show_rating !== false;
    const ratingStr = showRatings && rating ? rating.toFixed(1) : '';
    const yearVal = item.year ?? (item.date_added ? new Date(item.date_added).getFullYear() : undefined);
    const yearStr = this.config.show_year !== false && yearVal ? String(yearVal) : '';
    const runtimeStr = this._isRuntimeVisible() && item.runtime_minutes
      ? formatRuntime(item.runtime_minutes)
      : '';
    const showDateAdded = this.config.show_date_added === true;
    const dateAddedStr = showDateAdded && item.date_added
      ? formatDate(item.date_added, this.hass?.locale?.language || this.hass?.language)
      : '';
    const badgeText = item.series_name && item.season != null && item.episode != null && !isNaN(Number(item.season)) && !isNaN(Number(item.episode))
      ? `S${String(Number(item.season)).padStart(2, '0')}E${String(Number(item.episode)).padStart(2, '0')}`
      : (item.type === 'Movie' ? 'MOVIE' : 'SERIES');
    const badgeTypeClass = item.series_name ? 'series' : (item.type === 'Movie' ? 'movie' : 'series');

    const showSubtitle = (this.config as any).show_subtitle !== false;
    const isEpisode = item.type === 'Episode' || Boolean(item.series_name && item.name !== item.series_name);
    const subtitle = showSubtitle && isEpisode && item.series_name && item.name !== item.series_name
      ? item.series_name
      : '';

    const genres = this.config.show_genres !== false && item.genres && item.genres.length > 0
      ? item.genres.slice(0, 3)
      : [];
    const hasGenres = genres.length > 0;
    const showBackdrop = this.config.show_card_backdrop !== undefined
      ? Boolean(this.config.show_card_backdrop)
      : (this.config.featured_queue_backdrop !== false);
    const backdropSrc = showBackdrop
      ? addImageParams(
          item.backdrop_url || (this.config.use_series_image && item.series_poster_url ? item.series_poster_url : item.poster_url),
          600
        )
      : '';

    const showWatched = this.config.show_watched_status !== false;
    const isWatched = showWatched && item.is_played;
    const isUnplayedSeries = showWatched && item.type === 'Series' && (item.unplayed_count || 0) > 0;
    const hasStatusBadge = isNew || isWatched || isUnplayedSeries;
    const hasBadges = (showMediaTypeBadge || hasStatusBadge) && !isPlaying;

    const isCramped = this.layout === 'featured-queue' && (this.isCramped !== undefined
      ? this.isCramped
      : (Boolean(this.classList?.contains('cramped')) || (this.config.columns || 1) >= 3));

    return html`
      <div
        class="media-item list-item ${this.layout === 'featured-queue' ? 'featured-queue-item' : ''} ${showBackdrop ? 'has-backdrop' : ''} ${isPlaying ? 'playing' : ''} ${this.config.show_title === false ? 'no-title' : ''} ${subtitle ? 'has-subtitle' : ''} ${isCramped ? 'cramped' : ''}"
        tabindex="0"
        role="button"
        aria-label="${item.name}"
        @mousedown="${this._handleMouseDown}"
        @mouseup="${this._handleMouseUp}"
        @mouseleave="${this._handleMouseLeave}"
        @touchstart="${this._handleTouchStart}"
        @touchmove="${this._handleTouchMove}"
        @touchend="${this._handleTouchEnd}"
        @touchcancel="${this._handleTouchEnd}"
        @keydown="${this._handleKeydown}"
        @contextmenu="${this._handleContextMenu}"
      >
        ${showBackdrop ? html`
          <div class="grid-card-backdrop-container">
            <img
              class="grid-card-backdrop"
              src="${backdropSrc}"
              alt=""
              loading="lazy"
              decoding="async"
              @load="${this._handleImageLoad}"
              @error="${this._handleImageError}"
            />
            <div class="list-card-backdrop-scrim"></div>
          </div>
        ` : nothing}
        <div class="list-poster-wrapper">
          <div class="poster-container" id="poster-${item.id}">
            <div class="poster-inner">
              <img
                class="poster"
                src="${addImageParams(
          this.config.use_series_image && item.series_poster_url
            ? item.series_poster_url
            : item.poster_url,
          240
        )}"
                alt="${item.name}"
                width="76"
                height="114"
                loading="lazy"
                decoding="async"
                @load="${this._handleImageLoad}"
                @error="${this._handleImageError}"
              />
              <div class="poster-skeleton"></div>
              
              ${item.series_name && !isPlaying
        ? html`
            <div class="censor-bar list-bar ${this.isNextUpHighlight ? 'highlight' : ''}">
              <span>${item.series_name}</span>
            </div>
              `
        : nothing}
              
              ${this._renderNowPlayingOverlay(item)}
            </div>
          </div>
        </div>
        
        <div class="list-info">
          <div class="list-header">
            <div class="list-title-container">
              ${this.config.show_title !== false
            ? html`<h3 class="list-title" title="${item.name}">${item.name}</h3>`
            : nothing}
              ${subtitle
            ? html`<p class="list-subtitle" title="${subtitle}">${subtitle}</p>`
            : nothing}
            </div>
            ${hasBadges ? html`
              <div class="list-badges ${isCramped ? 'cramped-badges' : ''}">
                ${showMediaTypeBadge
                  ? html`<span class="media-type-badge list-type-badge ${badgeTypeClass}">${badgeText}</span>`
                  : nothing}
                ${isNew
                  ? html`<span class="new-badge inline-badge">${localize(this.hass?.locale?.language || this.hass?.language, 'new')}</span>`
                  : nothing}
                ${showWatched && item.is_played
                  ? html`<div class="status-badge watched inline-badge"><ha-icon icon="mdi:check-bold"></ha-icon></div>`
                  : nothing}
                ${showWatched && item.type === 'Series' && (item.unplayed_count || 0) > 0
                  ? html`<div class="status-badge unplayed inline-badge">${item.unplayed_count}</div>`
                  : nothing}
              </div>
            ` : nothing}
          </div>
          
          <div class="list-metadata">
            ${yearStr || runtimeStr || dateAddedStr ? html`
              <div class="idle-meta-row list-meta-row">
                ${yearStr
            ? html`<span class="idle-meta-text meta-text meta-year list-year">${yearStr}</span>`
            : nothing}
                ${yearStr && runtimeStr
            ? html`<span class="idle-dot meta-dot">•</span>`
            : nothing}
                ${runtimeStr
            ? html`<span class="idle-meta-text meta-text meta-runtime list-runtime">${runtimeStr}</span>`
            : nothing}
                ${(yearStr || runtimeStr) && dateAddedStr
            ? html`<span class="idle-dot meta-dot">•</span>`
            : nothing}
                ${dateAddedStr
            ? html`<span class="idle-meta-text meta-text meta-date-added list-date-added">${dateAddedStr}</span>`
            : nothing}
              </div>
            ` : nothing}

            ${ratingStr || hasGenres ? html`
              <div class="idle-meta-row list-meta-pills">
                ${ratingStr
            ? html`<span class="idle-rating-pill rating-pill list-rating">
                      <ha-icon icon="mdi:star"></ha-icon>
                      <span>${ratingStr}</span>
                    </span>`
            : nothing}
                ${genres.map(g => html`<span class="genre-pill idle-genre-pill list-genre-pill" title="${g}"><span>${g}</span></span>`)}
              </div>
            ` : nothing}
          </div>
          
          ${this.config.show_description_on_hover !== false && (item.description || (item as any).overview) && !isCramped
            ? html`<p class="list-description" title="${item.description || (item as any).overview}">${item.description || (item as any).overview}</p>`
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
    const hasYear = this.config.show_year !== false && Boolean(item.year ?? (item.date_added ? new Date(item.date_added).getFullYear() : undefined));
    const hasDateAdded = Boolean(this.config.show_date_added && item.date_added);
    const hasTitle = this.config.show_title !== false;
    const hasInfoBelow = hasTitle || hasYear || hasDateAdded;

    return html`
      <div
        class="media-item ${isPlaying ? 'playing' : ''}"
        tabindex="0"
        role="button"
        aria-label="${item.name}"
        @mousedown="${this._handleMouseDown}"
        @mouseup="${this._handleMouseUp}"
        @mouseleave="${this._handleMouseLeave}"
        @touchstart="${this._handleTouchStart}"
        @touchmove="${this._handleTouchMove}"
        @touchend="${this._handleTouchEnd}"
        @touchcancel="${this._handleTouchEnd}"
        @keydown="${this._handleKeydown}"
        @contextmenu="${this._handleContextMenu}"
      >
        <div class="poster-container" id="poster-${item.id}">
          <div class="poster-inner">
            <img
              class="poster"
              src="${addImageParams(
          this.config.use_series_image && item.series_poster_url
            ? item.series_poster_url
            : item.poster_url,
          300
        )}"
              alt="${item.name}"
              width="140"
              height="210"
              loading="auto"
              decoding="async"
              @load="${this._handleImageLoad}"
              @error="${this._handleImageError}"
            />
            <div class="poster-skeleton"></div>
            
            ${showMediaTypeBadge && !isPlaying
        ? html`
            <span class="media-type-badge ${item.series_name ? 'series' : (item.type === 'Movie' ? 'movie' : 'series')}">
              ${item.series_name && item.season !== undefined && item.episode !== undefined
            ? `S${String(item.season).padStart(2, '0')}E${String(item.episode).padStart(2, '0')}`
            : (item.type === 'Movie' ? 'Movie' : 'Series')}
            </span>
          `
        : nothing}

            ${item.series_name && !isPlaying
        ? html`
            <div class="censor-bar ${this.isNextUpHighlight ? 'highlight' : ''}">
              <span>${item.series_name}</span>
            </div>
              `
        : nothing}
            
            ${!isPlaying ? this._renderStatusBadge(item, isNew) : nothing}
            
            ${((this.config as any).show_ratings !== false && (this.config as any).show_rating !== false) && rating && !isPlaying
        ? html`
                  <span class="rating rating-pill">
                    <ha-icon icon="mdi:star"></ha-icon>
                    <span>${rating.toFixed(1)}</span>
                  </span>
                `
        : nothing}
            
            ${this._isRuntimeVisible() && item.runtime_minutes && !isPlaying
        ? html`
                  <span class="runtime genre-pill">
                    <span>${formatRuntime(item.runtime_minutes)}</span>
                  </span>
                `
        : nothing}
            
            ${!isPlaying ? html`
            <div class="hover-overlay">
              ${this.config.show_year !== false && (item.year ?? (item.date_added ? new Date(item.date_added).getFullYear() : undefined))
            ? html`<span class="overlay-year">${item.year ?? new Date(item.date_added).getFullYear()}</span>`
            : nothing}
              ${this.config.show_title !== false
            ? html`<h3 class="overlay-title" title="${item.name}">${item.name}</h3>`
            : nothing}
              ${this.config.show_genres !== false && item.genres && item.genres.length > 0
            ? html`<span class="overlay-genres">${item.genres.slice(0, 3).join(', ')}</span>`
            : nothing}
              ${this.config.show_description_on_hover !== false && item.description
            ? html`<p class="overlay-description" title="${item.description}">${item.description}</p>`
            : nothing}
            </div>` : nothing}

            ${this._renderNowPlayingOverlay(item)}
          </div>
        </div>
        
        ${hasInfoBelow ? html`
          <div class="media-info-below">
            ${hasTitle ? html`<p class="media-title" title="${item.name}">${item.name}</p>` : nothing}
            ${hasYear ? html`<p class="media-year">${item.year ?? new Date(item.date_added!).getFullYear()}</p>` : nothing}
            ${hasDateAdded ? html`<p class="media-date-added">${formatDate(item.date_added!, this.hass?.locale?.language || this.hass?.language)}</p>` : nothing}
          </div>
        ` : nothing}
      </div>
    `;
  }

  private _renderStatusBadge(item: MediaItem, isNew: boolean, isInline: boolean = false): TemplateResult {
    const showWatched = this.config.show_watched_status !== false;
    const inlineClass = isInline ? 'inline-badge' : '';

    if (showWatched && item.is_played) {
      return html`
        <div class="status-badge watched ${inlineClass}">
          <ha-icon icon="mdi:check-bold"></ha-icon>
        </div>
      `;
    }

    if (showWatched && item.type === 'Series' && (item.unplayed_count || 0) > 0) {
      return html`
        <div class="status-badge unplayed ${inlineClass}">
          ${item.unplayed_count}
        </div>
      `;
    }

    if (isNew) {
      return html`<span class="new-badge ${inlineClass}">${localize(this.hass?.locale?.language || this.hass?.language, 'new')}</span>`;
    }

    return html``;
  }

  private _renderNowPlayingOverlay(item: MediaItem): TemplateResult | typeof nothing {
    if (!this.config.show_now_playing) {
      return nothing;
    }

    const activePlayer = findActiveMediaItemPlayer(item, this.hass, this.config);
    if (!activePlayer) {
      return nothing;
    }

    const isPaused = activePlayer.state === 'paused';
    const ringRadius = 18;
    const ringCircumference = 2 * Math.PI * ringRadius;
    const ringOffset = ringCircumference * (1 - this._longPressProgress);

    return html`
      <div 
        class="now-playing-overlay" 
        @click="${(e: Event) => { e.stopPropagation(); this._handleRewind(activePlayer.entityId); }}"
        @mousedown="${this._stopPropagation}"
        @mouseup="${this._stopPropagation}"
        @touchstart="${this._stopPropagation}"
        @touchend="${this._stopPropagation}"
        @touchcancel="${this._stopPropagation}"
        role="button"
        tabindex="0"
      >
        <div class="now-playing-controls">
          <div 
            class="play-pause-wrapper ${this._stopPulse ? 'stop-pulse' : ''}"
            @pointerdown="${(e: PointerEvent) => { e.stopPropagation(); this._startLongPress(activePlayer.entityId); }}"
            @pointerup="${(e: PointerEvent) => { e.stopPropagation(); this._endLongPress(); }}"
            @pointerleave="${() => this._endLongPress()}"
            @pointercancel="${() => this._endLongPress()}"
            @contextmenu="${(e: Event) => { e.preventDefault(); e.stopPropagation(); }}"
          >
            ${this._rewindActive ? html`
              <ha-icon-button
                class="play-pause-btn spinning"
                .label=${localize(this.hass?.locale?.language || this.hass?.language, 'loading') || 'Loading'}
              >
                <ha-icon icon="mdi:loading"></ha-icon>
              </ha-icon-button>
            ` : isPaused ? html`
              <ha-icon-button
                class="play-pause-btn"
                .label=${localize(this.hass?.locale?.language || this.hass?.language, 'play') || 'Play'}
                @click="${(e: Event) => {
                  e.stopPropagation();
                  if (this._longPressConsumed) {
                    this._longPressConsumed = false;
                    return;
                  }
                  this._handlePlayPause(activePlayer.entityId);
                }}"
              >
                <ha-icon icon="mdi:play"></ha-icon>
              </ha-icon-button>
            ` : html`
              <ha-icon-button
                class="play-pause-btn"
                .label=${localize(this.hass?.locale?.language || this.hass?.language, 'pause') || 'Pause'}
                @click="${(e: Event) => {
                  e.stopPropagation();
                  if (this._longPressConsumed) {
                    this._longPressConsumed = false;
                    return;
                  }
                  this._handlePlayPause(activePlayer.entityId);
                }}"
              >
                <ha-icon icon="mdi:pause"></ha-icon>
              </ha-icon-button>
            `}
            ${this._longPressProgress > 0 ? html`
              <svg class="stop-ring" viewBox="0 0 40 40">
                <circle cx="20" cy="20" r="18"
                  stroke="#ef4444" stroke-width="2.5" fill="none"
                  stroke-dasharray="${ringCircumference}"
                  stroke-dashoffset="${ringOffset}"
                  stroke-linecap="round"
                  transform="rotate(-90 20 20)" />
              </svg>
            ` : nothing}
          </div>
        </div>
      </div>
    `;
  }

  /* --- Helpers --- */

  private _isItemPlaying(item: MediaItem): boolean {
    return Boolean(findActiveMediaItemPlayer(item, this.hass, this.config));
  }

  private _getRating(item: MediaItem): number | null {
    if (this.config.rating_source === 'imdb' && item.rating_imdb) {
      const parsed = parseFloat(item.rating_imdb);
      if (!isNaN(parsed)) return parsed;
    }
    if (this.config.rating_source === 'tmdb' && item.rating_tmdb) {
      const parsed = parseFloat(item.rating_tmdb);
      if (!isNaN(parsed)) return parsed;
    }
    return item.rating ?? item.community_rating ?? null;
  }

  /* --- Event Handlers --- */

  private _fireAction(type: 'click' | 'hold' | 'double_tap'): void {
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
    const setTimer = typeof window !== 'undefined' ? window.setTimeout : setTimeout;
    this._holdTimer = setTimer(() => {
      this._isHoldActive = true;

      // Trigger visual pulse
      const poster = this.shadowRoot?.querySelector(`#poster-${this.item.id}`);
      if (poster) {
        poster.classList.add('hold-pulse');
        // Remove class after animation completes to allow re-triggering
        setTimeout(() => {
          poster.classList.remove('hold-pulse');
        }, 300);
      }

      this._dispatchHaptic('medium');
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
    const target = e.currentTarget as HTMLElement;
    target.classList.add('active-press');
    this._startHoldTimer();
  }

  private _handleMouseUp(e: MouseEvent): void {
    const target = e.currentTarget as HTMLElement;
    target.classList.remove('active-press');
    if (this._isHoldActive) {
      e.preventDefault();
      e.stopPropagation();
    } else {
      const duration = Date.now() - this._pressStartTime;
      if (duration < 500) {
        this._handleTap();
      }
    }
    this._clearHoldTimer();
  }

  private _handleMouseLeave(e: MouseEvent): void {
    const target = e.currentTarget as HTMLElement;
    target.classList.remove('active-press');
    this._clearHoldTimer();
  }

  private _handleTap(): void {
    const doubleTapAction = this.config.double_tap_action || 'none';

    // If no double tap action is configured, trigger click immediately
    if (doubleTapAction === 'none') {
      this._dispatchHaptic('light');
      this._fireAction('click');
      return;
    }

    if (this._clickTimer) {
      // Double tap detected
      clearTimeout(this._clickTimer);
      this._clickTimer = undefined;
      this._dispatchHaptic('medium');
      this._fireAction('double_tap');
    } else {
      // First tap, start timer
      const setTimer = typeof window !== 'undefined' ? window.setTimeout : setTimeout;
      this._clickTimer = setTimer(() => {
        this._clickTimer = undefined;
        this._dispatchHaptic('light');
        this._fireAction('click');
      }, 250);
    }
  }

  private _handleContextMenu(e: Event): void {
    e.preventDefault();
    e.stopPropagation();
    return;
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

    if (e.cancelable) e.preventDefault();

    if (this._isHoldActive) {
      this._isHoldActive = false;
      return;
    }

    if (dist > 10) {
      return;
    }

    this._handleTap();
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
    // Hide the broken image but let the skeleton/placeholder stay visible
    img.style.opacity = '0';
    img.style.position = 'absolute';
    // Show fallback icon on the skeleton
    const skeleton = img.nextElementSibling as HTMLElement;
    if (skeleton && skeleton.classList.contains('poster-skeleton')) {
      skeleton.classList.add('error');
    }
  }

  /* --- Playback Control Handlers --- */

  private _stopPropagation(e: Event): void {
    e.stopPropagation();
  }

  private _handlePlayPause(entityId: string): void {
    if (!this.hass) return;
    this._dispatchHaptic();
    this.hass.callService('media_player', 'media_play_pause', { entity_id: entityId });
  }

  private _handleStop(entityId: string): void {
    if (!this.hass) return;
    this._dispatchHaptic();
    stopMediaPlayback(this.hass, entityId, this.config);
  }

  private _startLongPress(entityId: string): void {
    if (this._longPressRaf) {
      cancelAnimationFrame(this._longPressRaf);
      this._longPressRaf = null;
    }
    this._longPressConsumed = false;
    const start = Date.now();
    const duration = 800; // ms to hold before stopping

    this._dispatchHaptic('selection');

    const animate = () => {
      const elapsed = Date.now() - start;
      this._longPressProgress = Math.min(elapsed / duration, 1);

      if (this._longPressProgress >= 1) {
        this._longPressConsumed = true;
        this._handleStop(entityId);
        this._dispatchHaptic('success');
        if (typeof navigator !== 'undefined' && navigator.vibrate) {
          navigator.vibrate(50);
        }
        this._stopPulse = true;
        setTimeout(() => {
          this._stopPulse = false;
        }, 600);
        this._endLongPress();
        return;
      }
      this._longPressRaf = requestAnimationFrame(animate);
    };

    this._longPressRaf = requestAnimationFrame(animate);
  }

  private _endLongPress(): void {
    if (this._longPressRaf) {
      cancelAnimationFrame(this._longPressRaf);
      this._longPressRaf = null;
    }
    this._longPressProgress = 0;
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

  private _dispatchHaptic(type: 'selection' | 'light' | 'medium' | 'heavy' | 'success' | 'warning' | 'failure' = 'selection'): void {
    const event = new CustomEvent('haptic', {
      detail: type,
      bubbles: true,
      composed: true,
    });
    this.dispatchEvent(event);
  }

  private _renderMetaLine(item: MediaItem, rating?: number): TemplateResult | typeof nothing {
    const showYear = this.config.show_year !== false;
    const showRuntime = this._isRuntimeVisible();
    const showDateAdded = this.config.show_date_added === true;
    const showRatings = (this.config as any).show_ratings !== false && (this.config as any).show_rating !== false;
    const showGenres = this.config.show_genres !== false;

    let yearValue = item.year;
    if (!yearValue && item.date_added) {
      const d = new Date(item.date_added);
      if (!isNaN(d.getFullYear())) {
        yearValue = d.getFullYear();
      }
    }

    const yearStr = showYear && yearValue ? String(yearValue) : '';
    const runtimeStr = showRuntime && item.runtime_minutes ? formatRuntime(item.runtime_minutes) : '';
    const dateAddedStr = showDateAdded && item.date_added
      ? formatDate(item.date_added, this.hass?.locale?.language || this.hass?.language)
      : '';
    const ratingStr = showRatings && rating && !this._isItemPlaying(item) ? rating.toFixed(1) : '';
    const genres = showGenres && item.genres && item.genres.length > 0 ? item.genres.slice(0, 2) : [];
    const hasGenres = genres.length > 0;

    const textParts: { text: string; className: string }[] = [];
    if (yearStr) textParts.push({ text: yearStr, className: 'meta-year' });
    if (runtimeStr) textParts.push({ text: runtimeStr, className: 'meta-runtime' });
    if (dateAddedStr) textParts.push({ text: dateAddedStr, className: 'meta-date-added' });

    const hasText = textParts.length > 0;
    const hasPills = !!ratingStr || hasGenres;

    if (!hasText && !hasPills) {
      return nothing;
    }

    return html`
      <div class="meta-line">
        ${hasText ? html`
          <div class="meta-text-row">
            ${textParts.map((part, idx) => html`
              ${idx > 0 ? html`<span class="idle-dot meta-dot">•</span>` : nothing}
              <span class="idle-meta-text meta-text ${part.className}">${part.text}</span>
            `)}
          </div>
        ` : nothing}
        ${hasPills ? html`
          <div class="meta-pills-row">
            ${ratingStr ? html`
              <span class="idle-rating-pill rating-pill">
                <ha-icon icon="mdi:star"></ha-icon>
                <span>${ratingStr}</span>
              </span>
            ` : nothing}
            ${hasGenres ? genres.map(g => html`<span class="genre-pill idle-genre-pill">${g}</span>`) : nothing}
          </div>
        ` : nothing}
      </div>
    `;
  }

  private _isRuntimeVisible(): boolean {
    const mediaType = this.config?.media_type;
    const tvContent = this.config?.tv_content || 'series';
    if (mediaType === 'series' && tvContent === 'series') {
      return false;
    }
    return this.config?.show_runtime !== false;
  }

  private _renderFeaturedHero(): TemplateResult {
    const item = this.item;
    const isNew = isNewItem(item, this.config.new_badge_days || 0);
    const rating = this._getRating(item);
    const showMediaTypeBadge = this.config.show_media_type_badge !== false;
    const isPlaying = this._isItemPlaying(item);
    const showTitle = this.config.show_title !== false;

    return html`
      <div
        class="media-item featured-hero ${isPlaying ? 'playing' : ''}"
        tabindex="0"
        role="button"
        aria-label="${item.name}"
        @mousedown="${this._handleMouseDown}"
        @mouseup="${this._handleMouseUp}"
        @mouseleave="${this._handleMouseLeave}"
        @touchstart="${this._handleTouchStart}"
        @touchmove="${this._handleTouchMove}"
        @touchend="${this._handleTouchEnd}"
        @touchcancel="${this._handleTouchEnd}"
        @keydown="${this._handleKeydown}"
        @contextmenu="${this._handleContextMenu}"
      >
        <div class="poster-container featured-hero-poster" id="poster-${item.id}">
          <div class="poster-inner">
            <img
              class="poster"
              src="${addImageParams(
                this.config.use_series_image && item.series_poster_url
                  ? item.series_poster_url
                  : item.poster_url,
                600
              )}"
              alt="${item.name}"
              width="240"
              height="360"
              loading="auto"
              decoding="async"
              @load="${this._handleImageLoad}"
              @error="${this._handleImageError}"
            />
            <div class="poster-skeleton"></div>

            ${showMediaTypeBadge && !isPlaying
              ? html`
                <span class="media-type-badge ${item.series_name ? 'series' : (item.type === 'Movie' ? 'movie' : 'series')}">
                  ${item.series_name && item.season != null && item.episode != null && !isNaN(Number(item.season)) && !isNaN(Number(item.episode))
                    ? `S${String(Number(item.season)).padStart(2, '0')}E${String(Number(item.episode)).padStart(2, '0')}`
                    : (item.type === 'Movie' ? 'MOVIE' : 'SERIES')}
                </span>
              ` : nothing}

            ${!isPlaying ? this._renderStatusBadge(item, isNew) : nothing}

            ${item.series_name && !isPlaying
              ? html`
                <div class="censor-bar ${this.isNextUpHighlight ? 'highlight' : ''}">
                  <span>${item.series_name}</span>
                </div>
              ` : nothing}

            <div class="featured-hero-scrim">
              ${showTitle
                ? html`<h3 class="featured-hero-title" title="${item.name}">${item.name}</h3>`
                : nothing}
              ${showTitle && item.series_name && item.name !== item.series_name
                ? html`<p class="featured-hero-subtitle" title="${item.series_name}">${item.series_name}</p>`
                : nothing}
              ${this._renderMetaLine(item, rating)}
            </div>

            ${this._renderNowPlayingOverlay(item)}
          </div>
        </div>
      </div>
    `;
  }

  private _renderFeaturedQueue(): TemplateResult {
    return this._renderListItem();
  }
}

