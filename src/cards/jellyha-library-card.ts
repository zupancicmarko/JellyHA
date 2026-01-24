/**
 * JellyHA Library Card for Home Assistant
 * 
 * A Lovelace card that displays media from your Jellyfin server
 */

import { LitElement, html, nothing, PropertyValues, TemplateResult } from 'lit';
import { customElement, property, state, query } from 'lit/decorators.js';

import { HomeAssistant, LovelaceCard, MediaItem, SensorData, JellyHALibraryCardConfig } from '../shared/types';
import { isNewItem } from '../shared/utils';
import { JellyHAItemDetailsModal } from '../components/jellyha-item-details-modal';
import { cardStyles } from '../styles/jellyha-library-styles';
import { localize } from '../shared/localize';

// Import modal for side effects (registration)
import '../components/jellyha-item-details-modal';

// Import editor for side effects
import '../editors/jellyha-library-editor';

// Import media item for side effects
import '../components/jellyha-media-item';

// Register card in the custom cards array
const CARD_VERSION = '1.0.0';

console.info(
  `%c JELLYHA-LIBRARY-CARD %c v${CARD_VERSION} `,
  'color: white; background: #00a4dc; font-weight: bold;',
  'color: #00a4dc; background: white; font-weight: bold;'
);

// Register card for picker
window.customCards = window.customCards || [];
window.customCards.push({
  type: 'jellyha-library-card',
  name: 'JellyHA Library',
  description: 'Display media from Jellyfin',
  preview: true,
});

const DEFAULT_CONFIG: Partial<JellyHALibraryCardConfig> = {
  title: '',
  layout: 'carousel',
  media_type: 'both',
  items_per_page: 3,
  max_pages: 5,
  auto_swipe_interval: 0, // 0 = disabled, otherwise seconds
  columns: 2,
  show_title: true,
  show_year: true,
  show_runtime: true,
  show_ratings: true,
  show_media_type_badge: true,
  show_genres: true,
  show_description_on_hover: true,
  enable_pagination: true,
  metadata_position: 'below',
  show_date_added: false,
  rating_source: 'auto',
  new_badge_days: 3,
  theme: 'auto',
  show_watched_status: true,
  click_action: 'more-info',
  hold_action: 'jellyfin',
  default_cast_device: '',
  show_now_playing: true,
  filter_favorites: false,
  status_filter: 'all',
  filter_newly_added: false,
  sort_option: 'date_added_desc',
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
  @state() private _mostRecentNextUpItemId?: string;
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
  private _autoSwipePaused = false;
  private _animationFrameId?: number;
  private _lastFrameTime = 0;
  private _scrollAccumulator = 0;

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
    // Add interaction listeners for auto-swipe
    this.addEventListener('mouseenter', this._handleMouseEnter);
    this.addEventListener('mouseleave', this._handleMouseLeave);
    this.addEventListener('touchstart', this._handleTouchStartInteraction, { passive: true });
    this.addEventListener('touchend', this._handleTouchEndInteraction);
    this._setupAutoSwipe();
  }

  disconnectedCallback(): void {
    super.disconnectedCallback();
    this._resizeObserver?.disconnect();
    if (this._resizeHandler) {
      window.removeEventListener('resize', this._resizeHandler);
    }
    this.removeEventListener('mouseenter', this._handleMouseEnter);
    this.removeEventListener('mouseleave', this._handleMouseLeave);
    this.removeEventListener('touchstart', this._handleTouchStartInteraction);
    this.removeEventListener('touchend', this._handleTouchEndInteraction);
    this._clearAutoSwipe();
  }

  private _setupAutoSwipe(): void {
    this._clearAutoSwipe();
    const interval = this._config?.auto_swipe_interval;
    if (!interval || interval <= 0) return;

    if (this._config.enable_pagination !== false) {
      // Version 1: Paginated (Interval-based)
      this._autoSwipeTimer = window.setInterval(() => {
        if (!this._autoSwipePaused) {
          this._handleAutoSwipePage();
        }
      }, interval * 1000);
    } else {
      // Version 2: Continuous Scroll (RAF-based)
      this._startContinuousScroll();
    }
  }

  private _clearAutoSwipe(): void {
    if (this._autoSwipeTimer) {
      clearInterval(this._autoSwipeTimer);
      this._autoSwipeTimer = undefined;
    }
    if (this._animationFrameId) {
      cancelAnimationFrame(this._animationFrameId);
      this._animationFrameId = undefined;
    }
  }

  /* Interaction Handlers for Pausing */
  private _handleMouseEnter = (): void => { this._autoSwipePaused = true; };
  private _handleMouseLeave = (): void => { this._autoSwipePaused = false; };
  private _handleTouchStartInteraction = (): void => { this._autoSwipePaused = true; };
  // Resume after a delay on touch end to let momentum settle (if any) or just resume
  private _handleTouchEndInteraction = (): void => {
    setTimeout(() => { this._autoSwipePaused = false; }, 2000);
  };

  /* Continuous Scroll Logic */
  private _startContinuousScroll(): void {
    const scrollFn = (timestamp: number) => {
      if (!this._lastFrameTime) this._lastFrameTime = timestamp;
      const deltaTime = timestamp - this._lastFrameTime;
      this._lastFrameTime = timestamp;

      if (!this._autoSwipePaused && this._config.auto_swipe_interval) {
        const scrollContainer = this.shadowRoot?.querySelector('.carousel, .grid-wrapper, .list-wrapper') as HTMLElement;

        if (scrollContainer) {
          const { scrollLeft, scrollWidth, clientWidth } = scrollContainer;

          // Sync accumulator if it's way off (e.g. user manually scrolled)
          // We allow small drift, but if user drags, we need to re-sync
          // Initialize if 0 (first run) or drift > 10
          if (Math.abs(this._scrollAccumulator - scrollLeft) > 10) {
            this._scrollAccumulator = scrollLeft;
          }

          // Calculate speed: We want to scroll 'clientWidth' pixels in 'interval' seconds
          // pixelsPerMs = clientWidth / (interval * 1000)
          const pxPerMs = clientWidth / (this._config.auto_swipe_interval * 1000);
          const scrollStep = pxPerMs * deltaTime;

          // Infinite Scroll Reset Logic
          // We assume content is duplicated. Loop point is approx half scrollWidth.
          const resetThreshold = scrollWidth / 2;

          this._scrollAccumulator += scrollStep;

          if (this._scrollAccumulator >= resetThreshold) {
            // Seamlessly jump back
            this._scrollAccumulator = this._scrollAccumulator - resetThreshold;
            scrollContainer.scrollLeft = this._scrollAccumulator;
          } else {
            // Normal scroll
            // Use the accumulated value for precise sub-pixel tracking
            scrollContainer.scrollLeft = this._scrollAccumulator;
          }
        }
      }

      this._animationFrameId = requestAnimationFrame(scrollFn);
    };

    this._animationFrameId = requestAnimationFrame(scrollFn);
  }

  /* Pagination Auto Swipe Logic */
  private async _handleAutoSwipePage(): Promise<void> {
    // Determine if we need to loop
    // Re-calculate basic stats
    const items = this._items || []; // Use cached items
    const itemsPerPage = this._config.items_per_page || this._itemsPerPage;
    const maxPages = this._config.max_pages || 10;
    const totalPages = Math.min(Math.ceil(items.length / itemsPerPage), maxPages);

    if (this._currentPage >= totalPages - 1) {
      // Loop back to start
      await this._animatePageChange('next', () => { // Animate direction 'next' usually feels like forward movement even when looping
        this._currentPage = 0;
      });
    } else {
      // Normal next page
      this._nextPage();
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

    // Force reflow using getComputedStyle (batched read, safer)
    void scrollContainer.offsetHeight;

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
    if (!this._hasScrollableContent || this._config.show_pagination_dots === false) return html``;

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

  public getLayoutOptions() {
    return {
      grid_rows: 6,
      grid_columns: 12,
    };
  }

  public getGridOptions() {
    return {
      columns: 12,
      rows: 6,
      min_columns: 12,
      min_rows: 5,
    };
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
      let result;
      if (this._config.media_type === 'next_up') {
        result = await this.hass.callWS<{ items: MediaItem[] }>({
          type: 'jellyha/get_user_next_up',
          entity_id: this._config.entity
        });
      } else {
        result = await this.hass.callWS<{ items: MediaItem[] }>({
          type: 'jellyha/get_items',
          entity_id: this._config.entity
        });
      }

      if (result && result.items) {
        this._items = result.items;
        // For Next Up media type, the default API sort is DatePlayed Descending.
        // So the first item in the raw list is the most recently watched series' next episode.
        // We capture this ID to consistently highlight it regardless of frontend sorting.
        if (this._config.media_type === 'next_up' && this._items.length > 0) {
          this._mostRecentNextUpItemId = this._items[0].id;
        } else {
          this._mostRecentNextUpItemId = undefined;
        }
      } else {
        // Fallback or empty
        this._items = [];
        this._mostRecentNextUpItemId = undefined;
      }
    } catch (err) {
      console.error('Error fetching JellyHA items:', err);
      // For Next Up, if WS fails (e.g. old backend), we might just show error or empty
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
    if (!this._config.enable_pagination) {

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
    } else if (this._config.media_type === 'next_up') {
      // Next Up items are already filtered by backend
      // But we might want to ensure they are valid
    }

    // Filter by favorites
    if (this._config.filter_favorites) {
      filtered = filtered.filter((item) => item.is_favorite === true);
    }

    // Filter by unwatched
    // Filter by watch status
    const statusFilter = this._config.status_filter || 'all';
    if (statusFilter === 'unwatched') {
      filtered = filtered.filter((item) => !item.is_played);
    } else if (statusFilter === 'watched') {
      filtered = filtered.filter((item) => item.is_played === true);
    }
    // Filter by newly added
    if (this._config.filter_newly_added) {
      filtered = filtered.filter((item) => isNewItem(item, this._config.new_badge_days || 0));
    }

    // Sorting
    const sortOption = this._config.sort_option || 'date_added_desc';
    filtered.sort((a, b) => {
      switch (sortOption) {
        case 'date_added_asc':
          return (a.date_added || '').localeCompare(b.date_added || '');
        case 'date_added_desc':
          return (b.date_added || '').localeCompare(a.date_added || '');

        case 'title_asc':
          return (a.name || '').localeCompare(b.name || '');
        case 'title_desc':
          return (b.name || '').localeCompare(a.name || '');

        case 'year_asc':
          return (a.year || 0) - (b.year || 0);
        case 'year_desc':
          return (b.year || 0) - (a.year || 0);

        case 'last_played_asc':
          return (a.last_played_date || '').localeCompare(b.last_played_date || '');
        case 'last_played_desc':
          return (b.last_played_date || '').localeCompare(a.last_played_date || '');

        default:
          return 0;
      }
    });

    // Apply limit based on items_per_page * max_pages
    const maxPages = this._config.max_pages;
    if (maxPages !== undefined && maxPages !== null && maxPages > 0) {
      const limit = (this._config.items_per_page || 5) * maxPages;
      filtered = filtered.slice(0, limit);
    }

    return filtered;
  }

  /**
   * Render media item action handler
   */
  private _handleItemAction(e: CustomEvent): void {
    const { type, item } = e.detail;
    this._performAction(item, type);
  }

  /**
   * Render layout based on config
   */
  private _renderLayout(items: MediaItem[]): TemplateResult {
    const layout = this._config.layout || 'carousel';
    const enablePagination = this._config.enable_pagination !== false;

    if (layout === 'carousel') {
      return this._renderCarousel(items, enablePagination);
    }

    if (layout === 'list') {
      return this._renderList(items, enablePagination);
    }

    if (layout === 'grid') {
      return this._renderGrid(items, enablePagination);
    }

    return html`
      <div class="${layout}">
        ${items.map((item) => html`
            <jellyha-media-item
                .hass=${this.hass}
                .config=${this._config}
                .item=${item}
                .layout=${'grid'}
                @jellyha-action=${this._handleItemAction}
            ></jellyha-media-item>
        `)}
      </div>
    `;
  }

  /**
   * Render carousel with optional pagination
   */
  private _renderCarousel(items: MediaItem[], showPagination: boolean): TemplateResult {
    const itemsPerPage = this._config.items_per_page || this._itemsPerPage;
    const rawMaxPages = this._config.max_pages;
    const maxPagesNum = rawMaxPages ? Number(rawMaxPages) : 0;
    const effectiveMaxPages = (maxPagesNum > 0) ? maxPagesNum : Infinity;
    const totalPages = Math.min(Math.ceil(items.length / itemsPerPage), effectiveMaxPages);

    const startIdx = this._currentPage * itemsPerPage;
    // For Infinite Scroll (no pagination), duplicate items ONLY if auto swipe is enabled
    const shouldDuplicate = !showPagination && (this._config.auto_swipe_interval || 0) > 0;
    const visibleItems = showPagination
      ? items.slice(startIdx, startIdx + itemsPerPage)
      : (shouldDuplicate ? [...items, ...items] : items);

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
          ${visibleItems.map((item) => html`
            <jellyha-media-item
                .hass=${this.hass}
                .config=${this._config}
                .item=${item}
                .layout=${'grid'}
                .isNextUpHighlight=${this._config.media_type === 'next_up' && item.id === this._mostRecentNextUpItemId}
                @jellyha-action=${this._handleItemAction}
            ></jellyha-media-item>
          `)}
        </div>
        ${showPagination && totalPages > 1
        ? this._renderPagination(totalPages)
        : nothing}
        ${!showPagination ? this._renderScrollIndicator() : nothing}
      </div>
    `;
  }

  /**
   * Render list with optional pagination
   */
  private _renderList(items: MediaItem[], enablePagination: boolean): TemplateResult {
    const itemsPerPage = this._config.items_per_page || this._itemsPerPage;
    const rawMaxPages = this._config.max_pages;
    const maxPagesNum = rawMaxPages ? Number(rawMaxPages) : 0;
    const effectiveMaxPages = (maxPagesNum > 0) ? maxPagesNum : Infinity;
    const totalPages = Math.min(Math.ceil(items.length / itemsPerPage), effectiveMaxPages);

    const startIdx = this._currentPage * itemsPerPage;
    // For Infinite Scroll (no pagination), duplicate items ONLY if auto swipe is enabled
    const shouldDuplicate = !enablePagination && (this._config.auto_swipe_interval || 0) > 0;
    const visibleItems = enablePagination
      ? items.slice(startIdx, startIdx + itemsPerPage)
      : (shouldDuplicate ? [...items, ...items] : items);

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
          class="list ${enablePagination ? 'paginated' : ''} ${isSingleColumn ? 'single-column' : ''}"
          style="--jf-list-columns: ${columns}"
        >
          ${visibleItems.map((item) => html`
            <jellyha-media-item
                .hass=${this.hass}
                .config=${this._config}
                .item=${item}
                .layout=${'list'}
                .isNextUpHighlight=${this._config.media_type === 'next_up' && item.id === this._mostRecentNextUpItemId}
                @jellyha-action=${this._handleItemAction}
            ></jellyha-media-item>
          `)}
        </div>
        ${enablePagination && totalPages > 1
        ? this._renderPagination(totalPages)
        : nothing}
      </div>
    `;
  }
  /**
   * Render grid with optional pagination
   */
  private _renderGrid(items: MediaItem[], enablePagination: boolean): TemplateResult {
    const itemsPerPage = this._config.items_per_page || this._itemsPerPage;
    const rawMaxPages = this._config.max_pages;
    const maxPagesNum = rawMaxPages ? Number(rawMaxPages) : 0;
    const effectiveMaxPages = (maxPagesNum > 0) ? maxPagesNum : Infinity;
    const totalPages = Math.min(Math.ceil(items.length / itemsPerPage), effectiveMaxPages);

    const startIdx = this._currentPage * itemsPerPage;
    // For Infinite Scroll (no pagination), duplicate items ONLY if auto swipe is enabled
    const shouldDuplicate = !enablePagination && (this._config.auto_swipe_interval || 0) > 0;
    const visibleItems = enablePagination
      ? items.slice(startIdx, startIdx + itemsPerPage)
      : (shouldDuplicate ? [...items, ...items] : items);

    const columns = this._config.columns || 1;
    const isAutoColumns = columns === 1;
    const isHorizontal = !enablePagination && (this._config.auto_swipe_interval || 0) > 0;

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
          @scroll="${!enablePagination ? this._handleScroll : nothing}"
        >
          <div
            class="grid ${enablePagination ? 'paginated' : ''} ${isAutoColumns ? 'auto-columns' : ''} ${isHorizontal ? 'horizontal' : ''}"
            style="--jf-columns: ${columns}; --jf-grid-rows: ${columns}"
          >
            ${visibleItems.map((item) => html`
                <jellyha-media-item
                    .hass=${this.hass}
                    .config=${this._config}
                    .item=${item}
                    .layout=${'grid'}
                    .isNextUpHighlight=${this._config.media_type === 'next_up' && item.id === this._mostRecentNextUpItemId}
                    @jellyha-action=${this._handleItemAction}
                ></jellyha-media-item>
            `)}
          </div>
        </div>
        ${enablePagination && totalPages > 1
        ? this._renderPagination(totalPages)
        : nothing}
        ${!enablePagination ? this._renderScrollIndicator() : nothing}
      </div>
    `;
  }

  /**
   * Main Pagination Render Dispatcher
   * Decides between standard and smart pagination based on page count
   */
  private _renderPagination(totalPages: number): TemplateResult {
    if (this._config.show_pagination_dots === false) return html``;

    // Hybrid Approach: Use standard simple dots for small counts
    if (totalPages <= 5) {
      return this._renderStandardPagination(totalPages);
    }
    // Use Smart Sliding Dots for larger counts
    return this._renderSmartPagination(totalPages);
  }

  /**
   * Render Standard Pagination (Existing Logic preserved)
   */
  private _renderStandardPagination(totalPages: number): TemplateResult {
    return html`
      <div class="pagination-dots">
        ${Array.from({ length: totalPages }, (_, i) => html`
          <button
            type="button"
            class="pagination-dot ${i === this._currentPage ? 'active' : ''}"
            data-page="${i}"
            @click="${this._onDotClick}"
            aria-label="${i === this._currentPage ? `Page ${i + 1}, current page` : `Go to page ${i + 1}`}"
            aria-current="${i === this._currentPage ? 'true' : 'false'}"
          ></button>
        `)}
      </div>
    `;
  }

  /**
   * Render Smart Sliding Pagination (iOS Style)
   */
  private _renderSmartPagination(totalPages: number): TemplateResult {
    const DOT_SIZE = 8; // width/height
    const GAP = 8;      // gap
    const VISIBLE_DOTS = 5;

    // Calculate translate X to center the current page
    // Window Width = (VISIBLE_DOTS * (DOT_SIZE + GAP)) - GAP
    // 5 * 16 - 8 = 72px

    // Center of Window = 72 / 2 = 36px
    // Center of First Dot (Index 0) = DOT_SIZE/2 = 4px

    // If Page 0 is active:
    // We want Dot 0 center (4px) to be at Window Center (36px).
    // Shift needed = 36 - 4 = 32px to the right.

    // General Formula:
    // Track Position = - (currentPage * (DOT_SIZE + GAP)) + CenterOffset
    // CenterOffset = (WindowWidth / 2) - (DOT_SIZE / 2)

    const singleDotSpace = DOT_SIZE + GAP;
    const windowWidth = (VISIBLE_DOTS * singleDotSpace) - GAP;
    const centerOffset = (windowWidth / 2) - (DOT_SIZE / 2);

    const trackShift = -(this._currentPage * singleDotSpace) + centerOffset;

    return html`
      <div class="pagination-container smart" style="width: ${windowWidth}px">
        <div 
          class="pagination-track" 
          style="transform: translateX(${trackShift}px); width: ${totalPages * singleDotSpace}px"
        >
          ${Array.from({ length: totalPages }, (_, i) => {
      const distance = Math.abs(i - this._currentPage);
      let classes = 'smart-dot';
      if (i === this._currentPage) classes += ' active';
      else if (distance > 2) classes += ' hidden'; // Hide far dots (> 2 steps away)
      else if (distance === 2) classes += ' small'; // Edge dots (2 steps away)

      return html`
              <button
                type="button"
                class="${classes}"
                data-page="${i}"
                @click="${this._onDotClick}"
                aria-label="${i === this._currentPage ? `Page ${i + 1} of ${totalPages}, current page` : `Go to page ${i + 1} of ${totalPages}`}"
                aria-current="${i === this._currentPage ? 'true' : 'false'}"
              ></button>
            `;
    })}
        </div>
      </div>
    `;
  }






  /**
   * Perform configured action
   */
  private _performAction(item: MediaItem, type: 'click' | 'hold'): void {
    const action = type === 'click' ? this._config.click_action : this._config.hold_action;
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
      case 'trailer':
        if (item.trailer_url) {
          window.open(item.trailer_url, '_blank');
        } else {
          fireEvent(this, 'hass-notification', {
            message: localize(this.hass.locale?.language || this.hass.language, 'no_trailer'),
          });
        }
        break;
      case 'none':
      default:
        break;
    }
  }

  private async _castMedia(item: MediaItem): Promise<void> {
    const entityId = this._config.default_cast_device;
    if (!entityId) {
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
   * Render empty state
   */
  private _renderEmpty(): TemplateResult {
    return html`
      <div class="empty">
        <ha-icon icon="mdi:movie-open-outline"></ha-icon>
        <p>${localize(this.hass.locale?.language || this.hass.language, 'no_media')}</p>
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

