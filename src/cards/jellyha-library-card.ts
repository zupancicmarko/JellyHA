/**
 * JellyHA Library Card for Home Assistant
 * 
 * A Lovelace card that displays media from your Jellyfin server
 */

import { LitElement, html, nothing, PropertyValues, TemplateResult } from 'lit';
import { customElement, property, state, query } from 'lit/decorators.js';

import { HomeAssistant, LovelaceCard, MediaItem, SensorData, JellyHALibraryCardConfig } from '../shared/types';
import { JellyHAItemDetailsModal } from '../components/jellyha-item-details-modal';
import { cardStyles } from '../shared/styles';
import { localize } from '../shared/localize';

// Import modal for side effects (registration)
import '../components/jellyha-item-details-modal';

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
  theme: 'auto',
  show_watched_status: true,
  click_action: 'jellyfin',
  hold_action: 'cast',
  default_cast_device: '',
  show_now_playing: true,
  filter_favorites: false,
  filter_unwatched: false,
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
  @state() private _pressStartTime: number = 0;
  @state() private _holdTimer?: number;
  @state() private _isHoldActive: boolean = false;
  @state() private _rewindActive: boolean = false;
  @state() private _items: MediaItem[] = [];
  @state() private _error?: string;
  @state() private _lastUpdate: string = '';
  @query('jellyha-item-details-modal') private _modal!: JellyHAItemDetailsModal;

  private _touchStartX: number = 0;
  private _touchStartY: number = 0;
  private _isOverscrolling: boolean = false;
  private _elasticAnchorX: number = 0;
  private _itemTouchStartX: number = 0;
  private _itemTouchStartY: number = 0;

  private _resizeObserver?: ResizeObserver;
  private _resizeHandler?: () => void;
  private _containerWidth = 0;
  private readonly ITEM_WIDTH = 148; // 140px poster + 8px gap - tighter packing
  private readonly LIST_ITEM_MIN_WIDTH = 380; // Minimum width per list column
  private _autoSwipeTimer?: number;
  private _effectiveListColumns = 1; // Calculated based on container width

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

  /* Pagination Handlers */
  private async _nextPage(): Promise<void> {
    if (!this._config?.entity || !this.hass) return;
    const entity = this.hass.states[this._config.entity];
    if (!entity) return;

    // Get items directly as per previous implementation logic
    // Use _items fetched from WebSocket
    const items = this._filterItems(this._items || []);

    const itemsPerPage = this._config.items_per_page || this._itemsPerPage;
    const maxPages = this._config.max_pages || 10;
    const totalPages = Math.min(Math.ceil(items.length / itemsPerPage), maxPages);

    if (this._currentPage < totalPages - 1) {
      await this._animatePageChange('next', () => {
        this._currentPage++;
      });
    }
  }

  private async _prevPage(): Promise<void> {
    if (this._currentPage > 0) {
      await this._animatePageChange('prev', () => {
        this._currentPage--;
      });
    }
  }

  /**
   * Helper to set scroll position after page change
   */
  private _setScrollPosition(position: 'start' | 'end'): void {
    const scrollContainer = this.shadowRoot?.querySelector('.carousel, .grid-wrapper');
    if (scrollContainer) {
      if (position === 'start') {
        scrollContainer.scrollLeft = 0;
      } else {
        // Set to max scroll width to jump to end
        scrollContainer.scrollLeft = scrollContainer.scrollWidth;
      }
    }
  }

  /**
   * Helper to animate page changes (Slide & Fade)
   **/
  private async _animatePageChange(direction: 'next' | 'prev', updateState: () => void): Promise<void> {
    const scrollContainer = this.shadowRoot?.querySelector('.carousel, .grid-wrapper') as HTMLElement;
    if (!scrollContainer) {
      updateState();
      return;
    }

    // Phase 1: Exit
    const exitTranslate = direction === 'next' ? '-30px' : '30px';
    scrollContainer.style.transition = 'transform 0.2s ease-out, opacity 0.2s ease-out';
    scrollContainer.style.transform = `translateX(${exitTranslate})`;
    scrollContainer.style.opacity = '0';

    // Wait for exit animation
    await new Promise(resolve => setTimeout(resolve, 200));

    // Phase 2: Update State & Reset properties
    updateState();
    await this.updateComplete;

    // Reset scroll position based on direction
    this._setScrollPosition(direction === 'next' ? 'start' : 'end');

    // Phase 3: Prepare Enter
    const enterTranslate = direction === 'next' ? '30px' : '-30px';
    scrollContainer.style.transition = 'none';
    scrollContainer.style.opacity = '0';
    scrollContainer.style.transform = `translateX(${enterTranslate})`;

    // Force reflow
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const _ = scrollContainer.offsetHeight;

    // Phase 4: Enter Animation
    scrollContainer.style.transition = 'transform 0.25s ease-out, opacity 0.25s ease-out';
    scrollContainer.style.transform = 'translateX(0)';
    scrollContainer.style.opacity = '1';

    // Cleanup after animation
    await new Promise(resolve => setTimeout(resolve, 250));
    scrollContainer.style.transition = '';
    scrollContainer.style.transform = '';
    scrollContainer.style.opacity = '';
  }

  /**
   * Helper to get total pages (used for elastic check)
   */
  private _getTotalPages(): number {
    if (!this._config?.entity || !this.hass) return 1;
    const entity = this.hass.states[this._config.entity];
    if (!entity) return 1;

    // Quick estimation logic as per _nextPage
    // Use _items fetched from WebSocket
    const items = this._filterItems(this._items || []);
    const itemsPerPage = this._config.items_per_page || this._itemsPerPage;
    const maxPages = this._config.max_pages || 10;
    return Math.min(Math.ceil(items.length / itemsPerPage), maxPages);
  }

  // Touch/Swipe handlers
  private _handleTouchStart(e: TouchEvent): void {
    this._touchStartX = e.touches[0].clientX;
    this._touchStartY = e.touches[0].clientY;
    this._isSwiping = false;
    this._isOverscrolling = false;
    this._elasticAnchorX = 0;
  }

  private _handleTouchMove(e: TouchEvent): void {
    if (!this._touchStartX) return;
    const diffX = e.touches[0].clientX - this._touchStartX;
    const diffY = e.touches[0].clientY - this._touchStartY;

    // Only swipe/scroll logic if horizontal movement > vertical
    if (Math.abs(diffX) > Math.abs(diffY)) {
      // Elastic Scroll Effect Logic
      const scrollContainer = this.shadowRoot?.querySelector('.carousel, .grid-wrapper') as HTMLElement;
      if (scrollContainer && Math.abs(diffX) > 0) {
        const { scrollLeft, scrollWidth, clientWidth } = scrollContainer;
        const maxScroll = scrollWidth - clientWidth;
        const isStart = scrollLeft <= 5;
        const isEnd = scrollLeft >= maxScroll - 5;
        const showPagination = this._config.show_pagination !== false;

        let shouldElastic = false;

        if (showPagination) {
          // If paginated: only elastic on FIRST page (left pull) or LAST page (right pull)
          const totalPages = this._getTotalPages();
          if (isStart && diffX > 0 && this._currentPage === 0) shouldElastic = true;
          if (isEnd && diffX < 0 && this._currentPage >= totalPages - 1) shouldElastic = true;
        } else {
          // If not paginated: elastic on both ends
          if (isStart && diffX > 0) shouldElastic = true;
          if (isEnd && diffX < 0) shouldElastic = true;
        }

        if (shouldElastic) {
          if (!this._isOverscrolling) {
            // First frame of overscroll - anchor here
            this._isOverscrolling = true;
            this._elasticAnchorX = diffX;
          }

          e.preventDefault(); // Stop native scroll to control transform manually
          // Apply resistance (0.3 factor) to the delta from anchor
          const resistance = 0.3;
          const elasticDiff = diffX - this._elasticAnchorX;

          scrollContainer.style.transition = 'none'; // Follow finger exactly
          scrollContainer.style.transform = `translateX(${elasticDiff * resistance}px)`;
          return;
        }
      }

      if (Math.abs(diffX) > 30) {
        this._isSwiping = true;
        // Allow native scroll to happen otherwise
      }
    }
  }

  private _handleTouchEnd(e: TouchEvent): void {
    // Handle Elastic Reset
    if (this._isOverscrolling) {
      const scrollContainer = this.shadowRoot?.querySelector('.carousel, .grid-wrapper') as HTMLElement;
      if (scrollContainer) {
        scrollContainer.style.transition = 'transform 0.4s cubic-bezier(0.25, 0.8, 0.5, 1)';
        scrollContainer.style.transform = '';
      }
      this._isOverscrolling = false;
      this._elasticAnchorX = 0;
      this._touchStartX = 0;
      this._isSwiping = false;
      return; // Stop here, do not trigger page switch
    }

    if (!this._isSwiping) {
      this._touchStartX = 0;
      return;
    }

    // If pagination is disabled, don't switch pages
    if (this._config.show_pagination === false) {
      this._touchStartX = 0;
      this._isSwiping = false;
      return;
    }

    const diffX = e.changedTouches[0].clientX - this._touchStartX;
    const threshold = 50; // Minimum swipe distance
    // Check for either carousel or grid wrapper (whichever is active)
    const scrollContainer = this.shadowRoot?.querySelector('.carousel, .grid-wrapper');

    if (diffX < -threshold) {
      // Swipe Left (Next Page)
      // Only switch if we are at the end of scroll
      if (scrollContainer) {
        const { scrollLeft, scrollWidth, clientWidth } = scrollContainer;
        if (scrollLeft + clientWidth >= scrollWidth - 10) {
          this._nextPage();
        }
      } else {
        this._nextPage();
      }
    } else if (diffX > threshold) {
      // Swipe Right (Prev Page)
      // Only switch if we are at the start of scroll
      if (scrollContainer) {
        if (scrollContainer.scrollLeft <= 10) {
          this._prevPage();
        }
      } else {
        this._prevPage();
      }
    }

    this._touchStartX = 0;
    this._isSwiping = false;
  }

  // Pointer events for Android Companion App (uses same logic as touch)
  // Pointer events for Android Companion App (uses same logic as touch)
  private _handlePointerDown(e: PointerEvent): void {
    if (e.pointerType === 'mouse') return; // Skip mouse, only handle touch/pen
    this._touchStartX = e.clientX;
    this._touchStartY = e.clientY;
    this._isSwiping = false;
    this._isOverscrolling = false;
    this._elasticAnchorX = 0;
    // Capture pointer for better tracking on Android
    (e.target as HTMLElement).setPointerCapture?.(e.pointerId);
  }

  private _handlePointerMove(e: PointerEvent): void {
    if (e.pointerType === 'mouse' || !this._touchStartX) return;
    const diffX = e.clientX - this._touchStartX;
    const diffY = e.clientY - this._touchStartY;

    // Only swipe/scroll logic if horizontal movement > vertical
    if (Math.abs(diffX) > Math.abs(diffY)) {
      // Elastic Scroll Effect Logic
      const scrollContainer = this.shadowRoot?.querySelector('.carousel, .grid-wrapper') as HTMLElement;
      if (scrollContainer && Math.abs(diffX) > 0) {
        const { scrollLeft, scrollWidth, clientWidth } = scrollContainer;
        const maxScroll = scrollWidth - clientWidth;
        const isStart = scrollLeft <= 5;
        const isEnd = scrollLeft >= maxScroll - 5;
        const showPagination = this._config.show_pagination !== false;

        let shouldElastic = false;

        if (showPagination) {
          const totalPages = this._getTotalPages();
          if (isStart && diffX > 0 && this._currentPage === 0) shouldElastic = true;
          if (isEnd && diffX < 0 && this._currentPage >= totalPages - 1) shouldElastic = true;
        } else {
          if (isStart && diffX > 0) shouldElastic = true;
          if (isEnd && diffX < 0) shouldElastic = true;
        }

        if (shouldElastic) {
          if (!this._isOverscrolling) {
            this._isOverscrolling = true;
            this._elasticAnchorX = diffX;
          }

          e.preventDefault();
          const resistance = 0.3;
          const elasticDiff = diffX - this._elasticAnchorX;

          scrollContainer.style.transition = 'none';
          scrollContainer.style.transform = `translateX(${elasticDiff * resistance}px)`;
          return;
        }
      }

      if (Math.abs(diffX) > 30) {
        this._isSwiping = true;
      }
    }
  }

  private _handlePointerUp(e: PointerEvent): void {
    // Release pointer capture
    (e.target as HTMLElement).releasePointerCapture?.(e.pointerId);

    // Handle Elastic Reset
    if (this._isOverscrolling) {
      const scrollContainer = this.shadowRoot?.querySelector('.carousel, .grid-wrapper') as HTMLElement;
      if (scrollContainer) {
        scrollContainer.style.transition = 'transform 0.4s cubic-bezier(0.25, 0.8, 0.5, 1)';
        scrollContainer.style.transform = '';
      }
      this._isOverscrolling = false;
      this._elasticAnchorX = 0;
      this._touchStartX = 0;
      this._isSwiping = false;
      return;
    }

    if (e.pointerType === 'mouse' || !this._isSwiping) {
      this._touchStartX = 0;
      return;
    }

    // If pagination is disabled, don't switch pages
    if (this._config.show_pagination === false) {
      this._touchStartX = 0;
      this._isSwiping = false;
      return;
    }

    const diffX = e.clientX - this._touchStartX;
    const threshold = 50;
    const scrollContainer = this.shadowRoot?.querySelector('.carousel, .grid-wrapper');

    if (diffX < -threshold) {
      if (scrollContainer) {
        const { scrollLeft, scrollWidth, clientWidth } = scrollContainer;
        if (scrollLeft + clientWidth >= scrollWidth - 10) {
          this._nextPage();
        }
      } else {
        this._nextPage();
      }
    } else if (diffX > threshold) {
      if (scrollContainer) {
        if (scrollContainer.scrollLeft <= 10) {
          this._prevPage();
        }
      } else {
        this._prevPage();
      }
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
      const width = rect.width;

      // If width is 0 (hidden), don't update layout yet
      if (width === 0) return;

      const contentWidth = Math.max(0, width - 32); // Subtract padding

      if (contentWidth !== this._containerWidth) {
        this._containerWidth = contentWidth;
        // Logic for items per page based on ITEM_WIDTH constant (e.g. 150px)
        const ITEM_WIDTH = 160;
        const newItemsPerPage = Math.max(2, Math.floor(contentWidth / ITEM_WIDTH));

        if (newItemsPerPage !== this._itemsPerPage) {
          this._itemsPerPage = newItemsPerPage;
          // Only reset page if drastic change? Or just ensure valid page
          // this._currentPage = 0; // Don't reset page on resize, annoying
          this.requestUpdate();
        }

        // Calculate effective list columns
        if (this._config) {
          const configColumns = this._config.columns || 1;
          const LIST_ITEM_MIN_WIDTH = 300;
          if (configColumns > 1) {
            const maxFitColumns = Math.max(1, Math.floor(contentWidth / LIST_ITEM_MIN_WIDTH));
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

    // Use ResizeObserver for robust detection
    try {
      this._resizeObserver = new ResizeObserver(() => {
        // Debounce slightly if needed, or just call handler
        if (this._resizeHandler) {
          window.requestAnimationFrame(() => this._resizeHandler!());
        }
      });
      this._resizeObserver.observe(this);
    } catch (e) {
      // Fallback for very old browsers (unlikely in HA)
      console.warn('ResizeObserver not supported, falling back to window resize', e);
      window.addEventListener('resize', this._resizeHandler);
    }

    // Call once initially
    this._resizeHandler();
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
      entity: 'sensor.jellyha_library',
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

    // Always update if internal carousel state changes or items change
    if (changedProps.has('_currentPage') || changedProps.has('_itemsPerPage') || changedProps.has('_items') || changedProps.has('_error')) {
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

        // Also check default cast device state
        const castEntity = this._config.default_cast_device;
        if (castEntity) {
          const oldCastState = oldHass.states[castEntity];
          const newCastState = this.hass.states[castEntity];
          if (oldCastState !== newCastState) return true;
        }

        return oldState !== newState;
      }
    }

    return changedProps.has('_config');
  }

  /**
   * Fetch items from WebSocket
   */
  private async _fetchItems(): Promise<void> {
    if (!this._config || !this.hass) return;

    const entityState = this.hass.states[this._config.entity];
    if (!entityState) return;

    this._error = undefined; // Reset error

    try {
      const result = await this.hass.callWS<{ items: MediaItem[] }>({
        type: 'jellyha/get_items',
        entity_id: this._config.entity
      });

      if (result && result.items) {
        this._items = result.items;
      }
    } catch (err) {
      console.error('Error fetching JellyHA items:', err);
      this._error = `Error fetching items: ${err}`;
    }
  }

  /**
   * Called after update - check for scrollable content and fetch data
   */
  protected updated(changedProps: PropertyValues): void {
    super.updated(changedProps);

    // Check if we need to fetch items
    if (changedProps.has('hass') || changedProps.has('_config')) {
      const entity = this.hass?.states[this._config?.entity];
      if (entity) {
        const entryId = (entity.attributes as unknown as SensorData).entry_id;
        const lastUpdated = (entity.attributes as unknown as SensorData).last_updated;

        // If entry_id changed or last_updated changed, fetch items
        // Also fetch if we haven't fetched yet (empty items)
        if (lastUpdated !== this._lastUpdate || (this._items.length === 0 && entryId)) {
          this._lastUpdate = lastUpdated;
          this._fetchItems();
        }
      }
    }

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

    if (this._error) {
      return this._renderError(this._error);
    }


    const items = this._filterItems(this._items || []);

    return html`
      <ha-card>
        <div class="card-inner">
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
        </div>
        <jellyha-item-details-modal .hass=${this.hass}></jellyha-item-details-modal>
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

    // Filter by favorites
    if (this._config.filter_favorites) {
      filtered = filtered.filter((item) => item.is_favorite === true);
    }

    // Filter by unwatched
    if (this._config.filter_unwatched) {
      filtered = filtered.filter((item) => !item.is_played);
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
    const isPlaying = this._isItemPlaying(item);

    return html`
      <div
        class="media-item list-item ${isPlaying ? 'playing' : ''} ${!this._config.show_title ? 'no-title' : ''} ${this._config.metadata_position === 'above' ? 'metadata-above' : ''}"
        tabindex="0"
        role="button"
        aria-label="${item.name}"
        @mousedown="${(e: MouseEvent) => this._handleMouseDown(e, item)}"
        @mouseup="${(e: MouseEvent) => this._handleMouseUp(e, item)}"
        @touchstart="${(e: TouchEvent) => this._handleTouchStartItem(e, item)}"
        @touchmove="${(e: TouchEvent) => this._handleTouchMoveItem(e, item)}"
        @touchend="${(e: TouchEvent) => this._handleTouchEndItem(e, item)}"
        @touchcancel="${(e: TouchEvent) => this._handleTouchEndItem(e, item)}"
        @keydown="${(e: KeyboardEvent) => this._handleKeydown(e, item)}"
      >
        <div class="list-poster-wrapper">
          ${this._config.metadata_position === 'above' && this._config.show_date_added && item.date_added
        ? html`<p class="list-date-added">${this._formatDate(item.date_added)}</p>`
        : nothing}
          <div class="poster-container" id="poster-${item.id}">
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
              
              ${showMediaTypeBadge && !isPlaying
        ? html`<span class="list-type-badge ${item.type === 'Movie' ? 'movie' : 'series'}">
                  ${item.type === 'Movie' ? 'Movie' : 'Series'}
                </span>`
        : nothing}
              
              ${!isPlaying ? this._renderStatusBadge(item, isNew) : nothing}
              ${this._renderNowPlayingOverlay(item)}
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
            ${showMediaTypeBadge && !isPlaying
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
   * Render status badge (watched checkmark, unplayed count, or new badge)
   */
  private _renderStatusBadge(item: MediaItem, isNew: boolean): TemplateResult {
    const showWatched = this._config.show_watched_status !== false;

    // 1. Watched Checkmark
    if (showWatched && item.is_played) {
      return html`
        <div class="status-badge watched">
          <ha-icon icon="mdi:check-bold"></ha-icon>
        </div>
      `;
    }

    // 2. Unplayed Count (Series only)
    if (showWatched && item.type === 'Series' && (item.unplayed_count || 0) > 0) {
      return html`
        <div class="status-badge unplayed">
          ${item.unplayed_count}
        </div>
      `;
    }

    // 3. New Badge (Fallback)
    if (isNew) {
      return html`<span class="new-badge">${localize(this.hass.language, 'new')}</span>`;
    }

    return html``;
  }

  /**
   * Render individual media item
   */
  private _renderMediaItem(item: MediaItem): TemplateResult {
    const isNew = this._isNewItem(item);
    const rating = this._getRating(item);
    const showMediaTypeBadge = this._config.show_media_type_badge !== false;
    const isPlaying = this._isItemPlaying(item);

    return html`
      <div
        class="media-item ${isPlaying ? 'playing' : ''}"
        tabindex="0"
        role="button"
        aria-label="${item.name}"
        @mousedown="${(e: MouseEvent) => this._handleMouseDown(e, item)}"
        @mouseup="${(e: MouseEvent) => this._handleMouseUp(e, item)}"
        @touchstart="${(e: TouchEvent) => this._handleTouchStartItem(e, item)}"
        @touchmove="${(e: TouchEvent) => this._handleTouchMoveItem(e, item)}"
        @touchend="${(e: TouchEvent) => this._handleTouchEndItem(e, item)}"
        @touchcancel="${(e: TouchEvent) => this._handleTouchEndItem(e, item)}"
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
        <div class="poster-container" id="poster-${item.id}">
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
            
            ${showMediaTypeBadge && !isPlaying
        ? html`<span class="media-type-badge ${item.type === 'Movie' ? 'movie' : 'series'}">
                  ${item.type === 'Movie' ? 'Movie' : 'Series'}
                </span>`
        : nothing}
            
            ${!isPlaying ? this._renderStatusBadge(item, isNew) : nothing}
            
            ${this._config.show_ratings && rating && !isPlaying
        ? html`
                  <span class="rating">
                    <ha-icon icon="mdi:star"></ha-icon>
                    ${rating.toFixed(1)}
                  </span>
                `
        : nothing}
            
            ${this._config.show_runtime && item.runtime_minutes && !isPlaying
        ? html`
                  <span class="runtime">
                    <ha-icon icon="mdi:clock-outline"></ha-icon>
                    ${this._formatRuntime(item.runtime_minutes)}
                  </span>
                `
        : nothing}
            
            ${!isPlaying ? html`
            <div class="hover-overlay">
                    ${item.year ? html`<span class="overlay-year">${item.year}</span>` : nothing}
                    <h3 class="overlay-title">${item.name}</h3>
                    ${this._config.show_genres && item.genres && item.genres.length > 0
          ? html`<span class="overlay-genres">${item.genres.slice(0, 3).join(', ')}</span>`
          : nothing}
                    ${this._config.show_description_on_hover !== false && item.description
          ? html`<p class="overlay-description">${item.description}</p>`
          : nothing}
            </div>` : nothing}

            ${this._renderNowPlayingOverlay(item)}
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
   * Start hold timer
   */
  private _startHoldTimer(item: MediaItem): void {
    this._pressStartTime = Date.now();
    this._isHoldActive = false;
    this._holdTimer = window.setTimeout(() => {
      this._isHoldActive = true;
      this._performAction(item, 'hold');
    }, 500); // 500ms for long press
  }

  /**
   * Clear hold timer
   */
  private _clearHoldTimer(): void {
    if (this._holdTimer) {
      clearTimeout(this._holdTimer);
      this._holdTimer = undefined;
    }
  }

  /**
   * Handle mouse down on media item
   */
  private _handleMouseDown(e: MouseEvent, item: MediaItem): void {
    if (e.button !== 0) return; // Only left click
    this._startHoldTimer(item);
  }

  /**
   * Handle mouse up on media item
   */
  private _handleMouseUp(e: MouseEvent, item: MediaItem): void {
    if (this._isHoldActive) {
      e.preventDefault();
      e.stopPropagation();
    } else {
      const duration = Date.now() - this._pressStartTime;
      if (duration < 500) {
        this._performAction(item, 'click');
      }
    }
    this._clearHoldTimer();
  }

  /**
   * Handle touch start on media item
   */
  private _handleTouchStartItem(e: TouchEvent, item: MediaItem): void {
    if (e.touches.length > 0) {
      this._itemTouchStartX = e.touches[0].clientX;
      this._itemTouchStartY = e.touches[0].clientY;

      // Add visual feedback class
      const target = e.currentTarget as HTMLElement;
      target.classList.add('active-press');
    }
    this._startHoldTimer(item);
  }

  private _handleTouchMoveItem(e: TouchEvent, _item: MediaItem): void {
    if (e.touches.length > 0) {
      const diffX = Math.abs(e.touches[0].clientX - this._itemTouchStartX);
      const diffY = Math.abs(e.touches[0].clientY - this._itemTouchStartY);

      // If moved more than 10px, cancel hold
      if (diffX > 10 || diffY > 10) {
        this._clearHoldTimer();
        const target = e.currentTarget as HTMLElement;
        target.classList.remove('active-press');
      }
    }
  }

  private _handleTouchEndItem(e: TouchEvent, item: MediaItem): void {
    // Remove visual feedback class
    const target = e.currentTarget as HTMLElement;
    target.classList.remove('active-press');

    if (this._holdTimer) {
      clearTimeout(this._holdTimer);
      this._holdTimer = undefined;
    }

    // Calculate movement distance
    let dist = 0;
    if (e.changedTouches.length > 0) {
      const diffX = e.changedTouches[0].clientX - this._itemTouchStartX;
      const diffY = e.changedTouches[0].clientY - this._itemTouchStartY;
      dist = Math.sqrt(diffX * diffX + diffY * diffY);
    }

    e.preventDefault(); // Prevent ghost clicks

    // If long press triggered, do nothing (action already performed)
    if (this._isHoldActive) {
      this._isHoldActive = false;
      return;
    }

    // If moved significantly, treat as scroll/swipe and ignore
    if (dist > 10) {
      return;
    }

    // Otherwise, it's a short press
    this._performAction(item, 'click');
  }

  /**
   * Check if item is currently playing
   */
  private _isItemPlaying(item: MediaItem): boolean {
    if (!this._config.default_cast_device || !this.hass) return false;

    const player = this.hass.states[this._config.default_cast_device];
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

  /**
   * Perform configured action
   */
  private _performAction(item: MediaItem, type: 'click' | 'hold'): void {
    // Haptic feedback
    const event = new CustomEvent('haptic', {
      detail: 'selection',
      bubbles: true,
      composed: true,
    });
    this.dispatchEvent(event);

    const action = type === 'click' ? this._config.click_action : this._config.hold_action;
    console.log('JellyHA: performAction', { type, action, config: this._config, item });

    switch (action) {
      case 'jellyfin':
        window.open(item.jellyfin_url, '_blank');
        break;
      case 'cast':
        this._castMedia(item);
        break;
      case 'more-info':
        this._showItemDetails(item);
        break;
      case 'none':
      default:
        break;
    }
  }

  /**
   * Cast media to default device
   */
  private async _castMedia(item: MediaItem): Promise<void> {
    const entityId = this._config.default_cast_device;
    if (!entityId) {
      // If no default device, show more-info of the card to let user know or just log error
      console.warn('JellyHA: No default cast device configured');
      return;
    }

    try {
      await this.hass.callService('jellyha', 'play_on_chromecast', {
        entity_id: entityId,
        item_id: item.id,
      });
    } catch (err) {
      console.error('JellyHA: Failed to cast media', err);
    }
  }

  /**
   * Handle click on media item (for accessibility)
   */
  private _handleClick(item: MediaItem): void {
    // If not using mouse/touch events (e.g. keyboard), perform default click action
    this._performAction(item, 'click');
  }

  /**
   * Handle keyboard navigation
   */
  private _handleKeydown(e: KeyboardEvent, item: MediaItem): void {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      this._performAction(item, 'click');
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
   * Render Now Playing overlay if item matches currently playing media
   */
  private _renderNowPlayingOverlay(item: MediaItem): TemplateResult | typeof nothing {
    if (!this._config.show_now_playing || !this._isItemPlaying(item)) {
      return nothing;
    }

    const player = this.hass.states[this._config.default_cast_device!];

    return html`
      <div 
        class="now-playing-overlay" 
        @click="${() => this._handleRewind(this._config.default_cast_device!)}"
        @mousedown="${this._stopPropagation}"
        @mouseup="${this._stopPropagation}"
        @touchstart="${this._stopPropagation}"
        @touchend="${this._stopPropagation}"
        @touchcancel="${this._stopPropagation}"
      >
        <span class="now-playing-status">
          ${this._rewindActive ? 'REWINDING' : player.state}
        </span>
        <div class="now-playing-controls">
          <ha-icon
            class="${this._rewindActive ? 'spinning' : ''}"
            icon="${this._rewindActive ? 'mdi:loading' : (player.state === 'playing' ? 'mdi:pause' : 'mdi:play')}"
            @click="${(e: Event) => { e.stopPropagation(); this._handlePlayPause(this._config.default_cast_device!); }}"
          ></ha-icon>
          <ha-icon
            class="stop"
            icon="mdi:stop"
            @click="${(e: Event) => { e.stopPropagation(); this._handleStop(this._config.default_cast_device!); }}"
          ></ha-icon>
        </div>
      </div>
    `;
  }

  private _stopPropagation(e: Event): void {
    e.stopPropagation();
  }

  /**
   * Toggle play/pause on player
   */
  private _handlePlayPause(entityId: string): void {
    // Haptic feedback
    const event = new CustomEvent('haptic', {
      detail: 'selection',
      bubbles: true,
      composed: true,
    });
    this.dispatchEvent(event);

    this.hass.callService('media_player', 'media_play_pause', { entity_id: entityId });
  }

  /**
   * Stop playback on player
   */
  private _handleStop(entityId: string): void {
    // Haptic feedback
    const event = new CustomEvent('haptic', {
      detail: 'selection',
      bubbles: true,
      composed: true,
    });
    this.dispatchEvent(event);

    this.hass.callService('media_player', 'turn_off', { entity_id: entityId });
  }

  /**
   * Handle rewind on overlay click
   */
  private _handleRewind(entityId: string): void {
    // Stop propagation if called from event
    // (In template we pass string, but if needed we can handle event)

    // Visual feedback
    this._rewindActive = true;
    setTimeout(() => {
      this._rewindActive = false;
    }, 2000);

    // Haptic feedback
    const event = new CustomEvent('haptic', {
      detail: 'selection',
      bubbles: true,
      composed: true,
    });
    this.dispatchEvent(event);

    // Calculate seek position
    const player = this.hass.states[entityId];
    if (player && player.attributes.media_position) {
      const position = player.attributes.media_position as number;
      const validTime = player.attributes.media_position_updated_at as string;
      let currentPosition = position;

      // If we have a timestamp, calculate elapsed time
      if (validTime) {
        const now = new Date().getTime();
        const updated = new Date(validTime).getTime();
        const diff = (now - updated) / 1000;
        // Only add diff if playing
        if (player.state === 'playing') {
          currentPosition += diff;
        }
      }

      // Seek back 20 seconds, ensuring we don't go below 0
      const newPosition = Math.max(0, currentPosition - 20);

      this.hass.callService('media_player', 'media_seek', {
        entity_id: entityId,
        seek_position: newPosition
      });
    }
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
  private _showItemDetails(item: MediaItem): void {
    if (this._modal) {
      this._modal.showDialog({
        item,
        hass: this.hass,
        defaultCastDevice: this._config.default_cast_device
      });
    }
  }
}

declare global {
  interface HTMLElementTagNameMap {
    'jellyha-library-card': JellyHALibraryCard;
  }
}

