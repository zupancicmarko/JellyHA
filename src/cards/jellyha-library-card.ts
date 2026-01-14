/**
 * JellyHA Library Card for Home Assistant
 * 
 * A Lovelace card that displays media from your Jellyfin server
 */

import { LitElement, html, nothing, PropertyValues, TemplateResult } from 'lit';
import { customElement, property, state } from 'lit/decorators.js';

import { JellyHALibraryCardConfig, MediaItem, SensorData, HomeAssistant } from '../shared/types';
import { cardStyles } from '../shared/styles';
import { localize } from '../shared/localize';

// Import editor for side effects
import '../editors/jellyha-library-editor';

// Register card in the custom cards array
const CARD_VERSION = '1.0.0';

console.info(
  `%c JELLYHA-LIBRARY-CARD %c v${CARD_VERSION} `,
  'color: white; background: #00a4dc; font-weight: bold;',
  'color: #00a4dc; background: white; font-weight: bold;'
);

// Register card for picker
(window as any).customCards = (window as any).customCards || [];
(window as any).customCards.push({
  type: 'jellyha-library-card',
  name: 'JellyHA Library',
  description: 'Display media from Jellyfin',
  preview: true,
});

const DEFAULT_CONFIG: Partial<JellyHALibraryCardConfig> = {
  title: 'Jellyfin Library',
  layout: 'carousel',
  media_type: 'both',
  items_per_page: 3,
  max_pages: 5,
  auto_swipe_interval: 0, // 0 = disabled, otherwise seconds
  columns: 4,
  show_title: true,
  show_year: true,
  show_runtime: true,
  show_ratings: true,
  show_media_type_badge: true,
  show_genres: true,
  show_description_on_hover: true,
  show_pagination: true,
  metadata_position: 'below',
  rating_source: 'auto',
  new_badge_days: 3,
  click_action: 'jellyfin',
  image_quality: 90,
  image_height: 300,
  theme: 'auto',
};

// Helper function to fire events (replaces custom-card-helpers)
function fireEvent(
  node: EventTarget,
  type: string,
  detail?: Record<string, unknown>
): void {
  const event = new CustomEvent(type, {
    bubbles: true,
    composed: true,
    detail,
  });
  node.dispatchEvent(event);
}

@customElement('jellyha-library-card')
export class JellyHALibraryCard extends LitElement {
  @property({ attribute: false }) hass!: HomeAssistant;
  @state() private _config!: JellyHALibraryCardConfig;
  @state() private _currentPage = 0;
  @state() private _itemsPerPage = 5;

  private _resizeObserver?: ResizeObserver;
  private _resizeHandler?: () => void;
  private _containerWidth = 0;
  private readonly ITEM_WIDTH = 148; // 140px poster + 8px gap - tighter packing
  private readonly LIST_ITEM_MIN_WIDTH = 380; // Minimum width per list column
  private _autoSwipeTimer?: number;
  private _effectiveListColumns = 1; // Calculated based on container width

  // Touch/swipe state
  private _touchStartX = 0;
  private _touchStartY = 0;
  private _isSwiping = false;

  // Scroll indicator state (for non-paginated scrollable content)
  @state() private _scrollProgress = 0; // 0-1 representing scroll position
  @state() private _hasScrollableContent = false;
  private readonly SCROLL_INDICATOR_DOTS = 5; // Number of dots in scroll indicator

  static styles = cardStyles;

  constructor() {
    super();
    this._onDotClick = this._onDotClick.bind(this);
    this._handleTouchStart = this._handleTouchStart.bind(this);
    this._handleTouchMove = this._handleTouchMove.bind(this);
    this._handleTouchEnd = this._handleTouchEnd.bind(this);
    // Pointer events for Android Companion App
    this._handlePointerDown = this._handlePointerDown.bind(this);
    this._handlePointerMove = this._handlePointerMove.bind(this);
    this._handlePointerUp = this._handlePointerUp.bind(this);
    // Scroll handler for elastic indicator
    this._handleScroll = this._handleScroll.bind(this);
  }

  connectedCallback(): void {
    super.connectedCallback();
    this._setupResizeHandler();
    this._setupAutoSwipe();
  }

  disconnectedCallback(): void {
    super.disconnectedCallback();
    this._resizeObserver?.disconnect();
    if (this._resizeHandler) {
      window.removeEventListener('resize', this._resizeHandler);
    }
    this._clearAutoSwipe();
  }

  private _setupAutoSwipe(): void {
    this._clearAutoSwipe();
    const interval = this._config?.auto_swipe_interval;
    if (interval && interval > 0) {
      this._autoSwipeTimer = window.setInterval(() => {
        this._nextPage();
      }, interval * 1000);
    }
  }

  private _clearAutoSwipe(): void {
    if (this._autoSwipeTimer) {
      clearInterval(this._autoSwipeTimer);
      this._autoSwipeTimer = undefined;
    }
  }

  private _nextPage(): void {
    if (!this._config || !this.hass) return;

    const entity = this.hass.states[this._config.entity];
    if (!entity) return;

    const attributes = entity.attributes as unknown as SensorData;
    const items = this._filterItems(attributes.items || []);

    const itemsPerPage = this._config?.items_per_page || this._itemsPerPage;
    const maxPages = this._config?.max_pages || 10;
    const totalPages = Math.min(Math.ceil(items.length / itemsPerPage), maxPages);

    if (totalPages > 1) {
      this._currentPage = (this._currentPage + 1) % totalPages;
      this.requestUpdate();
    }
  }

  private _prevPage(): void {
    if (!this._config || !this.hass) return;

    const entity = this.hass.states[this._config.entity];
    if (!entity) return;

    const attributes = entity.attributes as unknown as SensorData;
    const items = this._filterItems(attributes.items || []);

    const itemsPerPage = this._config?.items_per_page || this._itemsPerPage;
    const maxPages = this._config?.max_pages || 10;
    const totalPages = Math.min(Math.ceil(items.length / itemsPerPage), maxPages);

    if (totalPages > 1) {
      this._currentPage = (this._currentPage - 1 + totalPages) % totalPages;
      this.requestUpdate();
    }
  }

  // Touch/Swipe handlers
  private _handleTouchStart(e: TouchEvent): void {
    this._touchStartX = e.touches[0].clientX;
    this._touchStartY = e.touches[0].clientY;
    this._isSwiping = false;
  }

  private _handleTouchMove(e: TouchEvent): void {
    if (!this._touchStartX) return;
    const diffX = e.touches[0].clientX - this._touchStartX;
    const diffY = e.touches[0].clientY - this._touchStartY;

    // Only swipe if horizontal movement > vertical (not scrolling)
    if (Math.abs(diffX) > Math.abs(diffY) && Math.abs(diffX) > 30) {
      this._isSwiping = true;
      e.preventDefault(); // Prevent scroll when swiping horizontally
    }
  }

  private _handleTouchEnd(e: TouchEvent): void {
    if (!this._isSwiping) {
      this._touchStartX = 0;
      return;
    }

    const diffX = e.changedTouches[0].clientX - this._touchStartX;
    const threshold = 50; // Minimum swipe distance

    if (diffX < -threshold) {
      this._nextPage();
    } else if (diffX > threshold) {
      this._prevPage();
    }

    this._touchStartX = 0;
    this._isSwiping = false;
  }

  // Pointer events for Android Companion App (uses same logic as touch)
  private _handlePointerDown(e: PointerEvent): void {
    if (e.pointerType === 'mouse') return; // Skip mouse, only handle touch/pen
    this._touchStartX = e.clientX;
    this._touchStartY = e.clientY;
    this._isSwiping = false;
    // Capture pointer for better tracking on Android
    (e.target as HTMLElement).setPointerCapture?.(e.pointerId);
  }

  private _handlePointerMove(e: PointerEvent): void {
    if (e.pointerType === 'mouse' || !this._touchStartX) return;
    const diffX = e.clientX - this._touchStartX;
    const diffY = e.clientY - this._touchStartY;
    if (Math.abs(diffX) > Math.abs(diffY) && Math.abs(diffX) > 30) {
      this._isSwiping = true;
      e.preventDefault(); // Prevent scroll when swiping horizontally
    }
  }

  private _handlePointerUp(e: PointerEvent): void {
    // Release pointer capture
    (e.target as HTMLElement).releasePointerCapture?.(e.pointerId);

    if (e.pointerType === 'mouse' || !this._isSwiping) {
      this._touchStartX = 0;
      return;
    }
    const diffX = e.clientX - this._touchStartX;
    const threshold = 50;
    if (diffX < -threshold) {
      this._nextPage();
    } else if (diffX > threshold) {
      this._prevPage();
    }
    this._touchStartX = 0;
    this._isSwiping = false;
  }

  // Scroll handler for elastic dot indicator
  private _handleScroll(e: Event): void {
    const target = e.target as HTMLElement;
    const scrollWidth = target.scrollWidth;
    const clientWidth = target.clientWidth;
    const scrollLeft = target.scrollLeft;

    // Check if content is scrollable
    const isScrollable = scrollWidth > clientWidth + 10; // 10px buffer
    if (isScrollable !== this._hasScrollableContent) {
      this._hasScrollableContent = isScrollable;
    }

    // Calculate scroll progress (0 to 1)
    if (isScrollable) {
      const maxScroll = scrollWidth - clientWidth;
      let progress = scrollLeft / maxScroll;
      // Round to 1 when close to end (within 10px or 2%)
      if (maxScroll - scrollLeft < 10 || progress > 0.98) {
        progress = 1;
      }
      // Round to 0 when at start
      if (scrollLeft < 10 || progress < 0.02) {
        progress = 0;
      }
      progress = Math.min(1, Math.max(0, progress));
      // Always update - no threshold, ensures smooth tracking
      this._scrollProgress = progress;
    }
  }

  // Render scroll indicator for non-paginated scrollable content
  private _renderScrollIndicator(): TemplateResult {
    if (!this._hasScrollableContent) return html``;

    const numDots = this.SCROLL_INDICATOR_DOTS;
    const progress = this._scrollProgress;

    // Use round for immediate snapping to nearest dot (consistent in both directions)
    const activeIndex = Math.round(progress * (numDots - 1));

    return html`
      <div class="scroll-indicator">
        ${Array.from({ length: numDots }, (_, i) => {
      const isActive = i === activeIndex;
      // Pill shape at start (first dot when at 0) or end (last dot when at 1)
      const isPill = (i === 0 && progress < 0.1) || (i === numDots - 1 && progress > 0.9);

      return html`
        <span 
          class="scroll-dot ${isActive ? 'active' : ''} ${isPill ? 'pill' : ''}"
        ></span>
      `;
    })}
      </div>
    `;
  }

  private _setupResizeHandler(): void {
    // Create resize handler function
    this._resizeHandler = () => {
      const rect = this.getBoundingClientRect();
      const width = rect.width - 32; // Subtract padding

      if (width < 100) return;
      if (width !== this._containerWidth) {
        this._containerWidth = width;
        const newItemsPerPage = Math.max(2, Math.floor(width / this.ITEM_WIDTH));
        if (newItemsPerPage !== this._itemsPerPage) {
          this._itemsPerPage = newItemsPerPage;
          this._currentPage = 0;
          this.requestUpdate();
        }

        // Calculate effective list columns
        if (this._config) {
          const configColumns = this._config.columns || 1;
          if (configColumns > 1) {
            const maxFitColumns = Math.max(1, Math.floor(width / this.LIST_ITEM_MIN_WIDTH));
            const newEffectiveColumns = Math.min(configColumns, maxFitColumns);
            if (newEffectiveColumns !== this._effectiveListColumns) {
              this._effectiveListColumns = newEffectiveColumns;
              this.requestUpdate();
            }
          } else if (this._effectiveListColumns !== 1) {
            this._effectiveListColumns = 1;
            this.requestUpdate();
          }
        }
      }
    };

    // Call once initially after a short delay (to ensure element is rendered)
    setTimeout(() => this._resizeHandler?.(), 100);

    // Add window resize listener
    window.addEventListener('resize', this._resizeHandler);
  }

  private _handleDotClick(page: number): void {
    if (page !== this._currentPage) {
      this._currentPage = page;
      this.requestUpdate();
    }
  }

  private _onDotClick(e: Event): void {
    e.stopPropagation();
    e.preventDefault();
    const target = e.currentTarget as HTMLButtonElement;
    const page = parseInt(target.dataset.page || '0', 10);
    this._handleDotClick(page);
  }

  /**
   * Set card configuration
   */
  public setConfig(config: JellyHALibraryCardConfig): void {
    if (!config.entity) {
      throw new Error('Please define an entity');
    }

    this._config = { ...DEFAULT_CONFIG, ...config };
    // Initialize effective list columns from config
    this._effectiveListColumns = this._config.columns || 1;
  }

  /**
   * Return the card editor element
   */
  public static getConfigElement(): HTMLElement {
    return document.createElement('jellyha-library-editor');
  }

  /**
   * Return default stub config for card picker
   */
  public static getStubConfig(): Partial<JellyHALibraryCardConfig> {
    return {
      entity: '',
      ...DEFAULT_CONFIG,
    };
  }

  /**
   * Get card size for layout
   */
  public getCardSize(): number {
    return this._config?.layout === 'list' ? 5 : 3;
  }

  /**
   * Determine if component should update
   */
  protected shouldUpdate(changedProps: PropertyValues): boolean {
    if (!this._config) {
      return false;
    }

    // Always update if internal carousel state changes
    if (changedProps.has('_currentPage') || changedProps.has('_itemsPerPage')) {
      return true;
    }

    // Update if scroll indicator state changes
    if (changedProps.has('_scrollProgress') || changedProps.has('_hasScrollableContent')) {
      return true;
    }

    if (changedProps.has('hass')) {
      const oldHass = changedProps.get('hass') as HomeAssistant | undefined;
      if (oldHass) {
        const oldState = oldHass.states[this._config.entity];
        const newState = this.hass.states[this._config.entity];
        return oldState !== newState;
      }
    }

    return changedProps.has('_config');
  }

  /**
   * Called after update - check for scrollable content
   */
  protected updated(changedProps: PropertyValues): void {
    super.updated(changedProps);

    // Check if carousel/grid/list is scrollable after render
    if (!this._config.show_pagination) {
      requestAnimationFrame(() => {
        const scrollable = this.shadowRoot?.querySelector('.carousel.scrollable, .grid-wrapper, .list-wrapper') as HTMLElement;
        if (scrollable) {
          const isScrollable = scrollable.scrollWidth > scrollable.clientWidth + 10;
          if (isScrollable !== this._hasScrollableContent) {
            this._hasScrollableContent = isScrollable;
          }
        }
      });
    }
  }

  /**
   * Render the card
   */
  protected render(): TemplateResult {
    if (!this._config || !this.hass) {
      return html``;
    }

    const entity = this.hass.states[this._config.entity];

    if (!entity) {
      return this._renderError(`Entity not found: ${this._config.entity}`);
    }

    const attributes = entity.attributes as unknown as SensorData;
    const items = this._filterItems(attributes.items || []);

    return html`
      <ha-card>
        ${this._config.title
        ? html`
              <div class="card-header">
                <h2>${this._config.title}</h2>
              </div>
            `
        : nothing}
        <div class="card-content">
          ${items.length === 0
        ? this._renderEmpty()
        : this._renderLayout(items)}
        </div>
      </ha-card>
    `;
  }

  /**
   * Filter items based on config
   */
  private _filterItems(items: MediaItem[]): MediaItem[] {
    let filtered = items;

    // Filter by media type
    if (this._config.media_type === 'movies') {
      filtered = filtered.filter((item) => item.type === 'Movie');
    } else if (this._config.media_type === 'series') {
      filtered = filtered.filter((item) => item.type === 'Series');
    }

    // Apply limit based on items_per_page * max_pages
    const limit = (this._config.items_per_page || 5) * (this._config.max_pages || 5);
    filtered = filtered.slice(0, limit);

    return filtered;
  }

  /**
   * Render layout based on config
   */
  private _renderLayout(items: MediaItem[]): TemplateResult {
    const layout = this._config.layout || 'carousel';
    const showPagination = this._config.show_pagination !== false;

    if (layout === 'carousel') {
      return this._renderCarousel(items, showPagination);
    }

    if (layout === 'list') {
      return this._renderList(items, showPagination);
    }

    if (layout === 'grid') {
      return this._renderGrid(items, showPagination);
    }

    return html`
      <div class="${layout}">
        ${items.map((item) => this._renderMediaItem(item))}
      </div>
    `;
  }

  /**
   * Render carousel with optional pagination
   */
  private _renderCarousel(items: MediaItem[], showPagination: boolean): TemplateResult {
    const itemsPerPage = this._config.items_per_page || this._itemsPerPage;
    const maxPages = this._config.max_pages || 10;
    const totalPages = Math.min(Math.ceil(items.length / itemsPerPage), maxPages);
    const startIdx = this._currentPage * itemsPerPage;
    const visibleItems = showPagination
      ? items.slice(startIdx, startIdx + itemsPerPage)
      : items;

    return html`
      <div 
        class="carousel-wrapper ${this._config.horizontal_alignment !== 'left' ? 'align-center' : ''}"
        @touchstart="${this._handleTouchStart}"
        @touchmove="${this._handleTouchMove}"
        @touchend="${this._handleTouchEnd}"
        @pointerdown="${this._handlePointerDown}"
        @pointermove="${this._handlePointerMove}"
        @pointerup="${this._handlePointerUp}"
      >
        <div 
          class="carousel ${showPagination ? 'paginated' : 'scrollable'}"
          @scroll="${!showPagination ? this._handleScroll : nothing}"
        >
          ${visibleItems.map((item) => this._renderMediaItem(item))}
        </div>
        ${showPagination && totalPages > 1
        ? html`
              <div class="pagination-dots">
                ${Array.from({ length: totalPages }, (_, i) => html`
                  <button
                    type="button"
                    class="pagination-dot ${i === this._currentPage ? 'active' : ''}"
                    data-page="${i}"
                    @click="${this._onDotClick}"
                    aria-label="Go to page ${i + 1}"
                  ></button>
                `)}
              </div>
            `
        : nothing}
        ${!showPagination ? this._renderScrollIndicator() : nothing}
      </div>
    `;
  }

  /**
   * Render list with optional pagination
   */
  private _renderList(items: MediaItem[], showPagination: boolean): TemplateResult {
    const itemsPerPage = this._config.items_per_page || this._itemsPerPage;
    const maxPages = this._config.max_pages || 10;
    const totalPages = Math.min(Math.ceil(items.length / itemsPerPage), maxPages);
    const startIdx = this._currentPage * itemsPerPage;
    const visibleItems = showPagination
      ? items.slice(startIdx, startIdx + itemsPerPage)
      : items;
    // Use effective columns (calculated based on container width)
    const columns = this._effectiveListColumns;
    const isSingleColumn = columns === 1;

    return html`
      <div 
        class="list-wrapper"
        @touchstart="${this._handleTouchStart}"
        @touchmove="${this._handleTouchMove}"
        @touchend="${this._handleTouchEnd}"
        @pointerdown="${this._handlePointerDown}"
        @pointermove="${this._handlePointerMove}"
        @pointerup="${this._handlePointerUp}"
      >
        <div 
          class="list ${showPagination ? 'paginated' : ''} ${isSingleColumn ? 'single-column' : ''}"
          style="--jf-list-columns: ${columns}"
        >
          ${visibleItems.map((item) => this._renderListItem(item))}
        </div>
        ${showPagination && totalPages > 1
        ? html`
              <div class="pagination-dots">
                ${Array.from({ length: totalPages }, (_, i) => html`
                  <button
                    type="button"
                    class="pagination-dot ${i === this._currentPage ? 'active' : ''}"
                    data-page="${i}"
                    @click="${this._onDotClick}"
                    aria-label="Go to page ${i + 1}"
                  ></button>
                `)}
              </div>
            `
        : nothing}
      </div>
    `;
  }
  /**
   * Render grid with optional pagination
   */
  private _renderGrid(items: MediaItem[], showPagination: boolean): TemplateResult {
    const itemsPerPage = this._config.items_per_page || this._itemsPerPage;
    const maxPages = this._config.max_pages || 10;
    const totalPages = Math.min(Math.ceil(items.length / itemsPerPage), maxPages);
    const startIdx = this._currentPage * itemsPerPage;
    const visibleItems = showPagination
      ? items.slice(startIdx, startIdx + itemsPerPage)
      : items;
    const columns = this._config.columns || 1;
    const isAutoColumns = columns === 1;

    return html`
      <div class="grid-outer">
        <div 
          class="grid-wrapper"
          @touchstart="${this._handleTouchStart}"
          @touchmove="${this._handleTouchMove}"
          @touchend="${this._handleTouchEnd}"
          @pointerdown="${this._handlePointerDown}"
          @pointermove="${this._handlePointerMove}"
          @pointerup="${this._handlePointerUp}"
          @scroll="${!showPagination ? this._handleScroll : nothing}"
        >
          <div
            class="grid ${showPagination ? 'paginated' : ''} ${isAutoColumns ? 'auto-columns' : ''}"
            style="--jf-columns: ${columns}"
          >
            ${visibleItems.map((item) => this._renderMediaItem(item))}
          </div>
        </div>
        ${showPagination && totalPages > 1
        ? html`
              <div class="pagination-dots">
                ${Array.from({ length: totalPages }, (_, i) => html`
                  <button
                    type="button"
                    class="pagination-dot ${i === this._currentPage ? 'active' : ''}"
                    data-page="${i}"
                    @click="${this._onDotClick}"
                    aria-label="Go to page ${i + 1}"
                  ></button>
                `)}
              </div>
            `
        : nothing}
        ${!showPagination ? this._renderScrollIndicator() : nothing}
      </div>
    `;
  }

  /**
   * Render individual list item (horizontal layout with metadata outside poster)
   */
  private _renderListItem(item: MediaItem): TemplateResult {
    const isNew = this._isNewItem(item);
    const rating = this._getRating(item);
    const showMediaTypeBadge = this._config.show_media_type_badge !== false;

    return html`
      <div
        class="media-item list-item ${!this._config.show_title ? 'no-title' : ''} ${this._config.metadata_position === 'above' ? 'metadata-above' : ''}"
        tabindex="0"
        role="button"
        aria-label="${item.name}"
        @click="${() => this._handleClick(item)}"
        @keydown="${(e: KeyboardEvent) => this._handleKeydown(e, item)}"
      >
        <div class="list-poster-wrapper">
          ${this._config.metadata_position === 'above' && this._config.show_date_added && item.date_added
        ? html`<p class="list-date-added">${this._formatDate(item.date_added)}</p>`
        : nothing}
          <div class="poster-container">
            <div class="poster-inner">
              <img
                class="poster"
                src="${item.poster_url}"
                alt="${item.name}"
                loading="lazy"
                @load="${this._handleImageLoad}"
                @error="${this._handleImageError}"
              />
              <div class="poster-skeleton"></div>
              
              ${isNew
        ? html`<span class="new-badge">${localize(this.hass.language, 'new')}</span>`
        : nothing}
            </div>
          </div>
          ${this._config.metadata_position !== 'above' && this._config.show_date_added && item.date_added
        ? html`<p class="list-date-added">${this._formatDate(item.date_added)}</p>`
        : nothing}
        </div>
        
        <div class="list-info">
          ${this._config.show_title
        ? html`<h3 class="list-title">${item.name}</h3>`
        : nothing}
          
          <div class="list-metadata">
            ${showMediaTypeBadge
        ? html`<span class="list-type-badge ${item.type === 'Movie' ? 'movie' : 'series'}">
                  ${item.type === 'Movie' ? 'Movie' : 'Series'}
                </span>`
        : nothing}
            ${this._config.show_year && item.year
        ? html`<span class="list-year">${item.year}</span>`
        : nothing}
            ${this._config.show_ratings && rating
        ? html`<span class="list-rating">
                  <ha-icon icon="mdi:star"></ha-icon>
                  ${rating.toFixed(1)}
                </span>`
        : nothing}
            ${this._config.show_runtime && item.runtime_minutes
        ? html`<span class="list-runtime">
                  <ha-icon icon="mdi:clock-outline"></ha-icon>
                  ${this._formatRuntime(item.runtime_minutes)}
                </span>`
        : nothing}
          </div>
          
          ${this._config.show_genres && item.genres && item.genres.length > 0
        ? html`<p class="list-genres">${item.genres.slice(0, 3).join(', ')}</p>`
        : nothing}
          
          ${this._config.show_description_on_hover !== false && item.description
        ? html`<p class="list-description">${item.description}</p>`
        : nothing}
        </div>
      </div>
    `;
  }

  /**
   * Render individual media item
   */
  private _renderMediaItem(item: MediaItem): TemplateResult {
    const isNew = this._isNewItem(item);
    const rating = this._getRating(item);
    const showMediaTypeBadge = this._config.show_media_type_badge !== false;
    const showHoverOverlay = this._config.show_description_on_hover !== false;

    return html`
      <div
        class="media-item"
        tabindex="0"
        role="button"
        aria-label="${item.name}"
        @click="${() => this._handleClick(item)}"
        @keydown="${(e: KeyboardEvent) => this._handleKeydown(e, item)}"
      >
        ${this._config.metadata_position === 'above'
        ? html`
              <div class="media-info-above">
                ${this._config.show_title
            ? html`<p class="media-title">${item.name}</p>`
            : nothing}
                ${this._config.show_year && item.year
            ? html`<p class="media-year">${item.year}</p>`
            : nothing}
                ${this._config.show_date_added && item.date_added
            ? html`<p class="media-date-added">${this._formatDate(item.date_added)}</p>`
            : nothing}
              </div>
            `
        : nothing}
        <div class="poster-container">
          <div class="poster-inner">
            <img
              class="poster"
              src="${item.poster_url}"
              alt="${item.name}"
              loading="lazy"
              @load="${this._handleImageLoad}"
              @error="${this._handleImageError}"
            />
            <div class="poster-skeleton"></div>
            
            ${showMediaTypeBadge
        ? html`<span class="media-type-badge ${item.type === 'Movie' ? 'movie' : 'series'}">
                  ${item.type === 'Movie' ? 'Movie' : 'Series'}
                </span>`
        : nothing}
            
            ${isNew
        ? html`<span class="new-badge">${localize(this.hass.language, 'new')}</span>`
        : nothing}
            
            ${this._config.show_ratings && rating
        ? html`
                  <span class="rating">
                    <ha-icon icon="mdi:star"></ha-icon>
                    ${rating.toFixed(1)}
                  </span>
                `
        : nothing}
            
            ${this._config.show_runtime && item.runtime_minutes
        ? html`
                  <span class="runtime">
                    <ha-icon icon="mdi:clock-outline"></ha-icon>
                    ${this._formatRuntime(item.runtime_minutes)}
                  </span>
                `
        : nothing}
            
            <div class="hover-overlay">
                    ${item.year ? html`<span class="overlay-year">${item.year}</span>` : nothing}
                    <h3 class="overlay-title">${item.name}</h3>
                    ${this._config.show_genres && item.genres && item.genres.length > 0
        ? html`<span class="overlay-genres">${item.genres.slice(0, 3).join(', ')}</span>`
        : nothing}
                    ${this._config.show_description_on_hover !== false && item.description
        ? html`<p class="overlay-description">${item.description}</p>`
        : nothing}
                  </div>
          </div>
        </div>
        
        ${this._config.metadata_position === 'below'
        ? html`
              <div class="media-info-below">
                ${this._config.show_title
            ? html`<p class="media-title">${item.name}</p>`
            : nothing}
                ${this._config.show_year && item.year
            ? html`<p class="media-year">${item.year}</p>`
            : nothing}
                ${this._config.show_date_added && item.date_added
            ? html`<p class="media-date-added">${this._formatDate(item.date_added)}</p>`
            : nothing}
              </div>
            `
        : nothing}
      </div>
    `;
  }

  /**
   * Get rating based on config (IMDB for movies, TMDB for TV)
   */
  private _getRating(item: MediaItem): number | null {
    if (this._config.rating_source === 'auto') {
      // Auto: IMDB for movies, TMDB for TV
      return item.rating || null;
    }
    return item.rating || null;
  }

  /**
   * Format date using Home Assistant's locale
   */
  private _formatDate(dateString: string): string {
    try {
      const date = new Date(dateString);
      // Use Home Assistant's language if available
      const locale = this.hass?.language || 'en';
      return date.toLocaleDateString(locale, {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
      });
    } catch {
      return dateString;
    }
  }

  /**
   * Format runtime in hours and minutes
   */
  private _formatRuntime(minutes: number): string {
    if (minutes < 60) {
      return `${minutes}m`;
    }
    const hours = Math.floor(minutes / 60);
    const mins = minutes % 60;
    return mins > 0 ? `${hours}h ${mins}m` : `${hours}h`;
  }

  /**
   * Check if item was added within new_badge_days
   */
  private _isNewItem(item: MediaItem): boolean {
    if (!this._config.new_badge_days || !item.date_added) {
      return false;
    }
    const addedDate = new Date(item.date_added);
    const now = new Date();
    const diffDays = (now.getTime() - addedDate.getTime()) / (1000 * 60 * 60 * 24);
    return diffDays <= this._config.new_badge_days;
  }

  /**
   * Handle click on media item
   */
  private _handleClick(item: MediaItem): void {
    switch (this._config.click_action) {
      case 'jellyfin':
        window.open(item.jellyfin_url, '_blank');
        break;
      case 'more-info':
        fireEvent(this as unknown as EventTarget, 'hass-more-info', {
          entityId: this._config.entity,
        });
        break;
      case 'none':
      default:
        break;
    }
  }

  /**
   * Handle keyboard navigation
   */
  private _handleKeydown(e: KeyboardEvent, item: MediaItem): void {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      this._handleClick(item);
    }
  }

  /**
   * Handle image load - add loaded class for transition
   */
  private _handleImageLoad(e: Event): void {
    const img = e.target as HTMLImageElement;
    img.classList.add('loaded');
  }

  /**
   * Handle image error - could show placeholder
   */
  private _handleImageError(e: Event): void {
    const img = e.target as HTMLImageElement;
    img.style.display = 'none';
  }

  /**
   * Render empty state
   */
  private _renderEmpty(): TemplateResult {
    return html`
      <div class="empty">
        <ha-icon icon="mdi:movie-open-outline"></ha-icon>
        <p>${localize(this.hass.language, 'no_media')}</p>
      </div>
    `;
  }

  /**
   * Render error state
   */
  private _renderError(message: string): TemplateResult {
    return html`
      <ha-card>
        <div class="error">
          <ha-icon icon="mdi:alert-circle"></ha-icon>
          <p>${message}</p>
        </div>
      </ha-card>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    'jellyha-library-card': JellyHALibraryCard;
  }
}

