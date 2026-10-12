import { css } from 'lit';


export const cardStyles = css`
  :host {
    display: block;
    height: 100%;
    width: 100%;
    background: none !important;
    position: relative;
    z-index: 1;
    --jf-card-bg: var(--ha-card-background, var(--card-background-color, #1c1c1c));
    --jf-primary: var(--primary-color, #18BCF2);
    --jf-text: var(--primary-text-color, #fff);
    --jf-text-secondary: var(--secondary-text-color, rgba(255, 255, 255, 0.7));
    --jf-divider: var(--divider-color, rgba(255, 255, 255, 0.12));
    --jf-poster-radius: var(--jellyha-poster-border-radius, 12px);
    --jf-transition: 0.2s ease-out;
    --jf-movie-badge: #AA5CC3;
    --jf-series-badge: #F2A218;
    --jf-border-color: var(--divider-color, rgba(255, 255, 255, 0.15));
    --jf-highlight: var(--primary-color, #18BCF2);
  }

  ha-card {
    background: var(--jf-card-bg);
    border-radius: var(--ha-card-border-radius, 12px);
    position: relative;
    z-index: 1; /* Lift slightly to ensure shadow is consistent */
    box-shadow: var(--ha-card-box-shadow, none);
    border: var(--ha-card-border, 1px solid var(--ha-card-border-color, var(--divider-color, #e0e0e0)));
    overflow: hidden;
    display: flex;
    flex-direction: column;
    height: 100%;
    width: 100%;
    margin: 0;
    box-sizing: border-box;
  }

  .card-inner {
    border-radius: inherit; /* Inherit from ha-card to match theme */
    overflow: hidden;
    position: relative;
    z-index: 1;
    display: flex;
    flex-direction: column;
    height: 100%;
  }

  .card-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 16px 16px 8px;
  }

  .card-header h2 {
    margin: 0;
    font-size: 1.25rem;
    font-weight: 500;
    color: var(--jf-text);
  }

  /* Search Bar Styles */
  .search-container {
    padding: 16px 16px 8px 16px; /* Increased top padding */
    display: flex;
    gap: 12px;
    align-items: center;
  }

  .search-input-wrapper,
  .search-select-wrapper {
    position: relative;
    display: flex;
    align-items: center;
  }

  .search-input-wrapper {
    flex: 1; /* Title search takes remaining space */
  }

  .search-select-wrapper {
    flex: 0 0 160px; /* Wider genre picker */
  }

  .search-input,
  .search-select {
    width: 100%;
    /* Use theme-aware transparent background */
    background: color-mix(in srgb, var(--jf-text), transparent 93%);
    border: 1px solid color-mix(in srgb, var(--jf-text), transparent 85%);
    border-radius: 20px; /* More round edges */
    padding: 8px 32px 8px 36px;
    color: var(--primary-text-color);
    font-size: 1rem;
    font-family: var(--mdc-typography-body1-font-family, var(--mdc-typography-font-family, Roboto, sans-serif)); /* Match HA font */
    outline: none;
    transition: background 0.2s, border-color 0.2s, box-shadow 0.2s;
    height: 42px; /* Ensure same height */
    appearance: none;
    -webkit-appearance: none;
    box-sizing: border-box; /* Ensure padding doesn't affect height width calculation */
  }

  .search-select {
    padding-right: 32px;
    padding-left: 16px;
    cursor: pointer;
  }

  .search-select option {
    /* Use solid background from theme to avoid transparency issues in darker themes */
    background: var(--paper-listbox-background-color, var(--primary-background-color, #1c1c1c));
    color: var(--primary-text-color);
  }

  .search-input:focus,
  .search-select:focus {
    background: color-mix(in srgb, var(--jf-text), transparent 90%);
    border-color: var(--primary-color);
    box-shadow: 0 0 0 1px var(--primary-color); /* Highlight focus */
  }

  .search-icon {
    position: absolute;
    left: 12px; /* Adjusted for rounded corners */
    color: var(--secondary-text-color);
    pointer-events: none;
    --mdc-icon-size: 20px;
  }

  .select-icon {
    position: absolute;
    right: 12px;
    color: var(--secondary-text-color);
    pointer-events: none;
    --mdc-icon-size: 20px;
  }

  .clear-search {
    position: absolute;
    right: 8px;
    background: none;
    border: none;
    color: var(--secondary-text-color);
    cursor: pointer;
    padding: 4px;
    display: flex;
    align-items: center;
    border-radius: 50%;
    transition: color 0.2s;
  }

  .clear-search:hover {
    color: var(--primary-text-color);
    background: rgba(var(--rgb-primary-text-color), 0.1);
  }

  .clear-search ha-icon {
    --mdc-icon-size: 18px;
  }

  /* Theme currently playing title */
  .media-item.playing .media-title,
  .media-item.playing .list-title {
    color: var(--jf-primary);
  }

  .card-content {
    padding: 0;
    padding-top: 12px;
    overflow: hidden;
    flex: 1; /* Allow content to fill remaining space */
    display: flex; /* Ensure children can fill height */
    flex-direction: column;
    min-height: 0; /* Critical for scrolling inside flex items */
  }

  /* Carousel Layout - Responsive with auto-fit */
  .carousel-wrapper {
    position: relative;
    overflow: hidden;
    touch-action: pan-y; /* Allow vertical scroll, handle horizontal swipe ourselves */
  }

  /* Center alignment uses text-align on wrapper + inline-flex on carousel */
  .carousel-wrapper.align-center {
    text-align: center;
  }

  .carousel {
    display: flex;
    gap: 16px;
    padding: 8px 16px 16px 16px;
    transition: transform 0.3s ease;
    justify-content: flex-start;
  }

  /* Center alignment: inline-flex shrinks to content, max-width allows scroll when needed */
  .carousel-wrapper.align-center .carousel {
    display: inline-flex;
    text-align: left;
    max-width: 100%;
    overflow-x: auto;
    scrollbar-width: none;
    -ms-overflow-style: none;
    padding-left: 0;
    padding-right: 0;
  }

  .carousel-wrapper.align-center .carousel::-webkit-scrollbar {
    display: none;
  }

  /* Spacers inside scrollable area for balanced centering */
  .carousel-wrapper.align-center .carousel::before,
  .carousel-wrapper.align-center .carousel::after {
    content: '';
  }

  .carousel.scrollable {
    overflow-x: auto;
    scrollbar-width: none;
    -ms-overflow-style: none;
  }

  .carousel.scrollable::-webkit-scrollbar {
    display: none;
  }

  .carousel.paginated {
    overflow-x: auto;
    scrollbar-width: none;
    -ms-overflow-style: none;
    -webkit-overflow-scrolling: touch;
    overscroll-behavior-x: none; /* Disable native browser navigation/rubber-banding to use custom */
  }

  .carousel.paginated::-webkit-scrollbar {
    display: none;
  }

  .carousel .media-item {
    flex: 0 0 auto;
  }

  /* Pagination Dots */
  .pagination-dots {
    display: flex;
    justify-content: center;
    gap: 8px;
    padding: 8px 0 12px;
  }

  .pagination-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--jf-text);
    opacity: 0.25;
    border: none;
    cursor: pointer;
    padding: 0;
    transition: background var(--jf-transition), transform var(--jf-transition), opacity var(--jf-transition);
    pointer-events: auto;
    z-index: 100;
  }

  .pagination-dot:hover {
    opacity: 0.5;
  }

  .pagination-dot.active {
    background: var(--jf-primary);
    opacity: 1;
    transform: scale(1.2);
  }

  /* Scroll Indicator - Elastic pill that stretches between dots */
  .scroll-indicator {
    display: flex;
    justify-content: center;
    align-items: center;
    gap: 6px;
    padding: 8px 0 12px;
    position: relative;
    z-index: 1; /* Below hovered media items */
  }

  /* Base scroll element */
  .scroll-dot {
    width: 8px;
    height: 8px;
    border-radius: 4px;
    background: var(--jf-text);
    opacity: 0.25;
    transition: width 0.15s ease-out, background 0.15s ease-out, border-radius 0.15s ease-out, opacity 0.15s ease-out;
  }

  /* Active dot */
  .scroll-dot.active {
    background: var(--jf-primary);
    opacity: 1;
  }

  /* Pill shape at start/end positions */
  .scroll-dot.pill {
    width: 20px;
  }

  /* Grid outer container to hold scrollable area + fixed indicator */
  .grid-outer {
    position: relative;
  }

  /* Grid Layout */
  .grid {
    display: grid;
    grid-template-columns: repeat(var(--jf-columns, 4), 1fr);
    gap: 16px;
    justify-items: center;
    padding: 8px 16px 16px 16px;
    min-width: fit-content;
  }

  /* Auto-fill responsive grid when columns = 1 (Auto) */
  .grid.auto-columns {
    grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
    justify-items: center;
    justify-content: center;
  }

  /* Horizontal Grid Mode (Infinite Scroll) */
  .grid.horizontal {
    display: grid;
    grid-auto-flow: column;
    grid-template-columns: auto; /* Let columns grow as needed */
    grid-template-rows: repeat(var(--jf-grid-rows, 2), auto);
    min-width: max-content; /* Force container to grow horizontally */
    gap: 16px;
    padding: 8px 16px 16px 16px;
  }

  /* List Wrapper for pagination */
  .list-wrapper {
    position: relative;
    overflow-y: auto; /* Enable vertical scrolling */
    height: 100%; /* Fill available space */
    touch-action: pan-y;
  }

  /* Grid Wrapper for pagination */
  .grid-wrapper {
    position: relative;
    overflow-x: auto;
    overflow-y: hidden;
    scrollbar-width: none;
    -ms-overflow-style: none;
    touch-action: auto; /* Allow both vertical and horizontal touch scrolling */
    -webkit-overflow-scrolling: touch; /* Smooth scrolling on iOS */
    overscroll-behavior-x: none;
  }

  .grid-wrapper::-webkit-scrollbar {
    display: none;
  }

  /* List Layout - supports 1-8 columns, responsive collapse when cramped */
  .list {
    display: grid;
    /* Uses exact column count, each item has min-width so they wrap naturally */
    grid-template-columns: repeat(var(--jf-list-columns, 1), 1fr);
    gap: 16px;
    padding: 8px 16px 20px 16px;
  }

  /* List item min-width handled via JavaScript ResizeObserver */

  /* Single column uses flex for better layout */
  .list.single-column {
    display: flex;
    flex-direction: column;
  }
  
  .list.single-column .media-item {
    min-width: 0;
  }

  /* Extra bottom padding when pagination is enabled */
  .list.paginated {
    padding-bottom: 8px;
  }

  /* =========================================================================
     Featured Layout (Concept 1: Spotlight Hero)
     ========================================================================= */
  .featured-wrapper {
    position: relative;
    width: 100%;
    touch-action: pan-y;
    container-type: inline-size;
  }

  .featured {
    display: flex;
    align-items: stretch;
    gap: 16px;
    padding: 8px 16px 16px 16px;
    box-sizing: border-box;
    width: 100%;
    max-height: 400px;
  }

  .featured.single {
    justify-content: center;
  }

  .featured.single .featured-hero-container {
    flex: 0 0 auto;
    max-width: 250px;
    width: 100%;
    max-height: 380px;
    margin: 0 auto;
  }

  .featured-hero-container {
    flex: 0 0 42%;
    max-width: 260px;
    min-width: 180px;
    max-height: 380px;
    display: flex;
    flex-direction: column;
  }

  .featured.multi-column .featured-hero-container {
    flex: 0 0 auto;
    width: clamp(200px, 30%, 250px);
    max-width: 250px;
    max-height: 380px;
  }

  .featured.rows-2 .featured-hero-container {
    max-height: 250px;
    max-width: 175px;
    width: clamp(140px, 25%, 175px);
  }

  .featured.rows-2 .poster-container.featured-hero-poster {
    max-height: 250px;
  }

  .featured-hero-container .featured-main {
    width: 100%;
    height: 100%;
    display: flex;
    flex-direction: column;
  }

  .media-item.featured-hero {
    width: 100%;
    height: 100%;
    display: flex;
    flex-direction: column;
    cursor: pointer;
    position: relative;
    z-index: 1;
    user-select: none;
    -webkit-user-select: none;
  }

  .media-item.featured-hero:hover {
    z-index: 10;
  }

  .poster-container.featured-hero-poster {
    width: 100% !important;
    height: 100% !important;
    max-height: 380px;
    flex: 1;
    aspect-ratio: 2/3;
    border-radius: var(--jf-poster-radius, 12px);
    overflow: visible;
    position: relative;
    border: none;
    box-shadow: none;
    background: transparent;
  }

  .poster-container.featured-hero-poster .poster-inner {
    position: absolute;
    inset: 0;
    width: 100%;
    height: 100%;
    border-radius: var(--jf-poster-radius, 12px);
    overflow: hidden;
    border: 1px solid var(--ha-card-border-color, var(--jf-border-color));
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.4);
    transition: transform var(--jf-transition), box-shadow var(--jf-transition), border-color var(--jf-transition);
    transform-origin: center center;
    transform: translate3d(0, 0, 0);
    will-change: transform;
    z-index: 1;
    box-sizing: border-box;
  }

  .media-item.featured-hero:hover .poster-inner {
    transform: scale(1.02);
    border-color: rgba(255, 255, 255, 0.45);
    box-shadow: 
      0 0 6px rgba(255, 255, 255, 0.08),
      0 8px 22px rgba(0, 0, 0, 0.5);
    z-index: 10;
  }

  .poster-container.featured-hero-poster .poster {
    width: 100%;
    height: 100%;
    object-fit: cover;
    border-radius: inherit;
  }


  .featured-hero-scrim {
    position: absolute;
    inset: auto 0 0 0;
    padding: 40px 14px 14px 14px;
    background: linear-gradient(
      to top,
      rgba(0, 0, 0, 0.95) 0%,
      rgba(0, 0, 0, 0.75) 50%,
      rgba(0, 0, 0, 0.3) 80%,
      transparent 100%
    );
    display: flex;
    flex-direction: column;
    gap: 3px;
    z-index: 5;
    pointer-events: none;
  }

  .featured-hero-title {
    margin: 0;
    font-size: 1.15rem;
    font-weight: 700;
    color: #fff;
    line-height: 1.25;
    display: -webkit-box;
    -webkit-line-clamp: 2;
    -webkit-box-orient: vertical;
    overflow: hidden;
    text-overflow: ellipsis;
    text-shadow: 0 2px 6px rgba(0, 0, 0, 0.9);
  }

  .featured-hero-subtitle {
    margin: 0;
    font-size: 0.85rem;
    font-weight: 500;
    color: rgba(255, 255, 255, 0.9);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    text-shadow: 0 1px 4px rgba(0, 0, 0, 0.9);
  }

  /* Metadata Line & Now Playing Style Pills */
  .meta-line {
    display: flex;
    flex-direction: column;
    gap: 3px;
    font-size: 0.8rem;
    line-height: 1;
    margin-top: 2px;
  }

  .meta-text-row {
    display: flex;
    align-items: center;
    gap: 6px;
    row-gap: 2px;
    flex-wrap: wrap;
    line-height: 1;
  }

  .meta-pills-row {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 4px 6px;
    line-height: 1;
  }

  .meta-text {
    display: inline-flex;
    align-items: center;
    height: 20px;
    line-height: 1;
    font-size: 0.78rem;
    font-weight: 500;
    color: var(--jf-text-secondary);
    white-space: nowrap;
  }

  .meta-dot {
    opacity: 0.5;
    font-size: 0.7rem;
    color: var(--jf-text-secondary);
    display: inline-flex;
    align-items: center;
    height: 20px;
    line-height: 1;
  }

  .rating-pill {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 3px;
    background: rgba(245, 158, 11, 0.2);
    border: 1px solid rgba(245, 158, 11, 0.45);
    color: #fbbf24;
    height: 20px;
    padding: 0 5px;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 700;
    line-height: 1;
    box-sizing: border-box;
    flex-shrink: 0;
  }

  .rating-pill ha-icon {
    --mdc-icon-size: 11px;
    width: 11px;
    height: 11px;
    display: flex;
    align-items: center;
    justify-content: center;
    transform: translateY(-0.5px);
    margin: 0;
    padding: 0;
    flex-shrink: 0;
  }

  .rating-pill span {
    display: inline-flex;
    align-items: center;
    line-height: 1;
  }

  .genre-pill {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    background: color-mix(in srgb, var(--jf-text), transparent 90%);
    border: 1px solid color-mix(in srgb, var(--jf-text), transparent 80%);
    height: 20px;
    padding: 0 6px;
    border-radius: 4px;
    font-size: 0.75rem;
    color: var(--jf-text);
    font-weight: 500;
    line-height: 1;
    box-sizing: border-box;
    flex-shrink: 0;
    white-space: nowrap;
  }

  /* Scrim overrides for hero poster metadata */
  .featured-hero-scrim .meta-text {
    color: rgba(255, 255, 255, 0.9);
    text-shadow: 0 1px 3px rgba(0, 0, 0, 0.85);
  }

  .featured-hero-scrim .meta-dot {
    color: rgba(255, 255, 255, 0.6);
  }

  .featured-hero-scrim .rating-pill {
    background: rgba(245, 158, 11, 0.25);
    border: 1px solid rgba(245, 158, 11, 0.5);
    color: #fbbf24;
    text-shadow: 0 1px 2px rgba(0, 0, 0, 0.8);
  }

  .featured-hero-scrim .genre-pill {
    background: rgba(255, 255, 255, 0.14);
    border: 1px solid rgba(255, 255, 255, 0.24);
    color: #ffffff;
    text-shadow: 0 1px 2px rgba(0, 0, 0, 0.8);
  }

  /* Featured Queue (Side items) */
  .featured-side {
    flex: 1;
    min-width: 0;
    display: grid;
    grid-template-columns: repeat(var(--jf-featured-columns, 1), minmax(0, 1fr));
    grid-template-rows: repeat(var(--jf-featured-rows, 3), 1fr);
    grid-auto-flow: column;
    gap: 10px;
  }

  .featured-side jellyha-media-item {
    display: flex;
    min-height: 0;
    min-width: 0;
    width: 100%;
    height: 100%;
  }

  .media-item.featured-queue-item {
    flex: 1;
    width: 100%;
    height: 100%;
    min-height: 104px;
    display: flex;
    flex-direction: row;
    align-items: center;
    gap: 12px;
    padding: 7px 12px;
    background: color-mix(in srgb, var(--jf-text), transparent 96%);
    border: 1px solid var(--ha-card-border-color, rgba(255, 255, 255, 0.16));
    border-radius: var(--jf-poster-radius, 12px) !important;
    overflow: hidden;
    position: relative;
    box-sizing: border-box;
    box-shadow: 0 3px 10px rgba(0, 0, 0, 0.3);
    transition: transform 0.24s cubic-bezier(0.2, 0.8, 0.2, 1), border-color 0.24s ease, box-shadow 0.24s ease, background 0.24s ease;
    cursor: pointer;
  }

  .media-item.featured-queue-item:hover,
  .media-item.featured-queue-item:focus-visible {
    background: color-mix(in srgb, var(--jf-text), transparent 90%);
    border-color: rgba(255, 255, 255, 0.35);
    transform: translateX(4px);
    box-shadow: 
      0 0 4px rgba(255, 255, 255, 0.04),
      0 4px 14px rgba(0, 0, 0, 0.3);
  }

  .media-item.featured-queue-item:hover .poster-container.featured-queue-poster .poster-inner {
    transform: none !important;
    box-shadow: none !important;
    border: none !important;
  }

  .media-item.featured-queue-item.playing {
    border-color: var(--jf-primary);
    background: color-mix(in srgb, var(--jf-primary), transparent 90%);
  }

  .featured-queue-poster-wrapper {
    flex-shrink: 0;
  }

  .poster-container.featured-queue-poster {
    width: 60px !important;
    height: 90px !important;
    aspect-ratio: 2/3;
    border-radius: 6px;
    overflow: hidden;
    border: 1px solid var(--jf-border-color);
    position: relative;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
  }

  .poster-container.featured-queue-poster .poster-inner {
    border-radius: 6px;
    width: 100%;
    height: 100%;
    position: relative;
    overflow: hidden;
  }

  .poster-container.featured-queue-poster .poster {
    width: 100%;
    height: 100%;
    object-fit: cover;
    border-radius: 6px;
  }

  .poster-container.featured-queue-poster .media-type-badge {
    font-size: 0.65rem;
    padding: 1px 5px;
    top: 4px;
    left: 4px;
    border-radius: 3px;
    letter-spacing: 0.2px;
  }

  .poster-container.featured-queue-poster .new-badge {
    font-size: 0.65rem;
    padding: 1px 5px;
    top: 4px;
    right: 4px;
    border-radius: 3px;
    letter-spacing: 0.2px;
  }

  .poster-container.featured-queue-poster .status-badge.watched {
    top: 4px;
    right: 4px;
    padding: 1px 5px;
    border-radius: 3px;
    font-size: 0.65rem;
  }

  .poster-container.featured-queue-poster .status-badge.watched ha-icon {
    --mdc-icon-size: 11px;
    margin: 0;
  }

  .poster-container.featured-queue-poster .status-badge.unplayed {
    top: 4px;
    right: 4px;
    padding: 1px 5px;
    border-radius: 3px;
    font-size: 0.65rem;
  }

  .featured-queue-info {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    justify-content: center;
    gap: 3px;
    overflow: hidden;
  }

  .featured-queue-info .meta-text-row {
    flex-wrap: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .featured-queue-info .meta-pills-row {
    flex-wrap: nowrap;
    overflow: hidden;
  }

  .featured-queue-badges {
    position: absolute;
    top: 8px;
    right: 10px;
    z-index: 4;
    display: flex;
    align-items: center;
    gap: 5px;
    pointer-events: none;
  }

  .media-item.featured-queue-item:not(.cramped) .featured-queue-badges {
    position: static;
    float: right;
    display: inline-flex;
    align-items: center;
    gap: 4px;
    margin-left: 8px;
    margin-bottom: 2px;
    line-height: 1;
    z-index: 4;
    pointer-events: none;
  }

  .featured-queue-subtitle,
  .featured-queue-series {
    margin: 0;
    font-size: 0.78rem;
    font-weight: 500;
    color: var(--jf-text-secondary);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    line-height: 1.2;
    box-sizing: border-box;
  }

  .featured-queue-title {
    margin: 0;
    font-size: 0.95rem;
    font-weight: 600;
    color: var(--jf-text);
    line-height: 1.25;
    max-height: 2.55em;
    overflow: hidden;
    word-break: break-word;
    transition: color 0.2s;
    box-sizing: border-box;
  }

  .media-item.featured-queue-item:hover .featured-queue-title {
    color: var(--jf-primary);
  }

  /* Cramped / Compact queue card layout (for 2+ columns) */
  .media-item.featured-queue-item.cramped {
    flex-direction: column !important;
    justify-content: center !important;
    align-items: center !important;
    padding: 6px 8px !important;
    gap: 0 !important;
    height: 100% !important;
    min-height: 110px !important;
    box-sizing: border-box !important;
  }

  .media-item.featured-queue-item.cramped .featured-queue-info {
    display: none !important;
  }

  .media-item.featured-queue-item.cramped .featured-queue-poster-wrapper {
    margin: 0 auto !important;
    display: flex !important;
    justify-content: center !important;
    align-items: center !important;
    height: calc(100% - 10px) !important;
    max-height: 100px !important;
    z-index: 3 !important;
  }

  .media-item.featured-queue-item.cramped .poster-container.featured-queue-poster {
    width: auto !important;
    max-width: 72px !important;
    height: 100% !important;
    max-height: 100px !important;
    aspect-ratio: 2/3 !important;
    border-radius: var(--jf-poster-radius, 8px) !important;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.6) !important;
    border: 1px solid rgba(255, 255, 255, 0.25) !important;
    margin: 0 auto !important;
    flex-shrink: 0 !important;
  }

  .media-item.featured-queue-item.cramped .poster-container.featured-queue-poster .poster {
    width: 100%;
    height: 100%;
    object-fit: cover;
    border-radius: inherit;
  }

  .media-item.featured-queue-item.cramped .featured-queue-badges {
    position: absolute !important;
    top: 6px !important;
    right: 6px !important;
    float: none !important;
    max-width: calc(100% - 12px) !important;
    gap: 3px !important;
    flex-wrap: wrap !important;
    justify-content: flex-end !important;
    z-index: 4 !important;
  }

  .media-item.featured-queue-item.cramped .featured-queue-action {
    position: absolute !important;
    bottom: 6px !important;
    right: 6px !important;
    z-index: 4 !important;
  }

  .media-item.featured-queue-item.cramped .featured-queue-backdrop-scrim {
    background: linear-gradient(
      180deg,
      rgba(0, 0, 0, 0.5) 0%,
      rgba(0, 0, 0, 0.25) 50%,
      rgba(0, 0, 0, 0.65) 100%
    ) !important;
  }

  .media-item.featured-queue-item.cramped:hover,
  .media-item.featured-queue-item.cramped:focus-visible {
    transform: translateY(-2px) !important;
    border-color: rgba(255, 255, 255, 0.4) !important;
    box-shadow: 
      0 0 6px rgba(255, 255, 255, 0.08),
      0 6px 18px rgba(0, 0, 0, 0.4) !important;
  }

  /* Backdrop Fanart Background for Featured Queue Cards */
  .media-item.featured-queue-item.has-backdrop {
    background: #111;
    border: 1px solid var(--ha-card-border-color, rgba(255, 255, 255, 0.18));
  }

  .featured-queue-backdrop-container {
    position: absolute;
    inset: 0;
    width: 100%;
    height: 100%;
    border-radius: inherit;
    overflow: hidden;
    z-index: 1;
    pointer-events: none;
  }

  .featured-queue-backdrop {
    position: absolute;
    inset: 0;
    width: 100%;
    height: 100%;
    object-fit: cover;
    object-position: center 25%;
    filter: brightness(1.05) saturate(1.05);
    transition: transform 0.4s cubic-bezier(0.2, 0.8, 0.2, 1), filter 0.3s ease;
  }

  .media-item.featured-queue-item:hover .featured-queue-backdrop {
    transform: scale(1.008);
    filter: brightness(1.08) saturate(1.04);
  }

  .media-item.featured-queue-item:hover .featured-queue-poster .poster-inner {
    transform: none;
    box-shadow: none;
    border-color: transparent;
  }

  .featured-queue-backdrop-scrim {
    position: absolute;
    inset: 0;
    background: linear-gradient(
      90deg,
      rgba(0, 0, 0, 0.88) 0%,
      rgba(0, 0, 0, 0.72) 38%,
      rgba(0, 0, 0, 0.32) 75%,
      rgba(0, 0, 0, 0.1) 100%
    );
    z-index: 2;
    pointer-events: none;
  }

  .media-item.featured-queue-item.has-backdrop .featured-queue-poster-wrapper {
    position: relative;
    z-index: 3;
  }

  .media-item.featured-queue-item.has-backdrop .poster-container.featured-queue-poster {
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.7);
    border: 1px solid rgba(255, 255, 255, 0.22);
  }

  .media-item.featured-queue-item .featured-queue-info {
    position: relative;
    z-index: 3;
    display: flex;
    flex-direction: column;
    justify-content: center;
    gap: 3px;
    flex: 1;
    min-width: 0;
  }

  .featured-queue-header-row {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
    line-height: 1;
    margin-bottom: 2px;
  }

  .media-type-badge.inline-badge {
    position: static !important;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    height: 19px;
    padding: 0 6px;
    border-radius: 4px;
    font-size: 0.68rem;
    font-weight: 800;
    text-transform: uppercase;
    letter-spacing: 0.3px;
    line-height: 1;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.4);
    text-shadow: 0 1px 3px rgba(0, 0, 0, 0.5);
    flex-shrink: 0;
    box-sizing: border-box;
  }

  .new-badge.inline-badge {
    position: static !important;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    height: 19px;
    padding: 0 6px;
    border-radius: 4px;
    font-size: 0.68rem;
    font-weight: 800;
    text-transform: uppercase;
    letter-spacing: 0.3px;
    line-height: 1;
    background: #009ac7;
    color: #fff;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.4);
    text-shadow: 0 1px 3px rgba(0, 0, 0, 0.5);
    flex-shrink: 0;
    box-sizing: border-box;
  }

  .status-badge.inline-badge {
    position: static !important;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    height: 19px;
    padding: 0 5px;
    border-radius: 4px;
    font-size: 0.68rem;
    font-weight: 800;
    line-height: 1;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.4);
    flex-shrink: 0;
    box-sizing: border-box;
  }

  .status-badge.inline-badge ha-icon {
    --mdc-icon-size: 13px;
    margin: 0;
  }

  .featured-queue-subtitle,
  .featured-queue-series {
    margin: 0;
    font-size: 0.76rem;
    font-weight: 500;
    color: var(--jf-text-secondary);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .media-item.featured-queue-item.has-backdrop .featured-queue-subtitle,
  .media-item.featured-queue-item.has-backdrop .featured-queue-series {
    color: rgba(255, 255, 255, 0.85);
    text-shadow: 0 1px 3px rgba(0, 0, 0, 0.85);
  }

  .media-item.featured-queue-item.has-backdrop .featured-queue-title {
    color: #ffffff;
    text-shadow: 0 1px 4px rgba(0, 0, 0, 0.9);
  }

  .media-item.featured-queue-item.has-backdrop .meta-text {
    color: rgba(255, 255, 255, 0.9);
    text-shadow: 0 1px 3px rgba(0, 0, 0, 0.85);
  }

  .media-item.featured-queue-item.has-backdrop .meta-dot {
    color: rgba(255, 255, 255, 0.6);
  }

  .media-item.featured-queue-item.has-backdrop .rating-pill {
    background: rgba(245, 158, 11, 0.25);
    border: 1px solid rgba(245, 158, 11, 0.5);
    color: #fbbf24;
    text-shadow: 0 1px 2px rgba(0, 0, 0, 0.8);
  }

  .media-item.featured-queue-item.has-backdrop .genre-pill {
    background: rgba(255, 255, 255, 0.14);
    border: 1px solid rgba(255, 255, 255, 0.24);
    color: #ffffff;
    text-shadow: 0 1px 2px rgba(0, 0, 0, 0.8);
  }

  .media-item.featured-queue-item.has-backdrop .featured-queue-action {
    position: relative;
    z-index: 3;
  }

  .media-item.featured-queue-item.has-backdrop:hover,
  .media-item.featured-queue-item.has-backdrop:focus-visible {
    border-color: rgba(255, 255, 255, 0.35);
    box-shadow: 
      0 0 4px rgba(255, 255, 255, 0.04),
      0 4px 14px rgba(0, 0, 0, 0.3);
    transform: translateX(4px);
  }

  .media-item.featured-queue-item.has-backdrop.playing {
    border-color: var(--jf-primary);
    box-shadow: 0 0 14px color-mix(in srgb, var(--jf-primary), transparent 60%);
  }

  .featured-queue-action {
    flex-shrink: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    padding-right: 4px;
  }

  .featured-queue-playing-icon {
    --mdc-icon-size: 20px;
    color: var(--jf-primary);
    animation: pulse 1.5s infinite ease-in-out;
  }

  /* Responsive Stacking: On screens under 640px, stack hero and side cleanly */
  @media (max-width: 640px) {
    .featured {
      flex-direction: column;
      align-items: center;
      gap: 16px;
      padding: 12px 14px 16px 14px;
      max-height: none;
    }

    .featured-hero-container {
      flex: 0 0 auto;
      max-width: 250px;
      width: 100%;
      height: 375px;
      max-height: 380px;
    }

    .featured.multi-column .featured-hero-container {
      width: 100%;
      max-width: 250px;
      height: 375px;
      max-height: 380px;
    }

    .featured-side {
      width: 100%;
      gap: 10px;
      display: grid !important;
      grid-template-columns: repeat(var(--jf-featured-columns, 1), minmax(0, 1fr)) !important;
      grid-template-rows: repeat(3, auto) !important;
      grid-auto-flow: column;
    }

    .featured-side jellyha-media-item {
      flex: 0 0 auto;
      width: 100%;
    }

    .media-item.featured-queue-item {
      flex: 0 0 auto;
      min-height: 110px;
      padding: 8px 12px;
    }
  }

  .media-item.list-item {
    flex-direction: row;
    align-items: flex-start;
    gap: 16px;
  }

  /* Specific override for List view */
  .media-item.list-item .poster-container {
    width: 100px !important;
    flex-shrink: 0;
  }

  /* List poster wrapper for date */
  .list-poster-wrapper {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .list-date-added {
    margin: 0 0 -1px 0;
    font-size: 0.9rem;
    font-weight: 500;
    color: var(--jf-text-secondary);
    text-align: center;
    opacity: 0.8;
    transition: transform 0.2s ease, font-weight 0.2s ease;
  }

  /* Vertical alignment when title is hidden - align with poster top */
  .list-item.no-title .list-info {
    padding-top: 7px;
  }

  /* List info container */
  .list-info {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 8px;
    min-width: 0;
    padding-top: 0;
    justify-content: flex-start;
  }

  /* When metadata is BELOW poster (default), align info with poster top */
  .list-item:not(.metadata-above) .list-info {
    padding-top: 7px;
  }

  /* When metadata is ABOVE poster, align info with the date text above poster */
  .list-item.metadata-above .list-info {
    padding-top: 31px;
  }

  .list-title {
    margin: 0 0 3px 0;
    font-size: 1.1rem;
    font-weight: 600;
    color: var(--jf-text);
    line-height: 1.3;
  }

  .list-metadata {
    display: flex;
    align-items: center;
    gap: 12px;
    flex-wrap: wrap;
  }

  .list-year {
    font-size: 0.9rem;
    color: var(--jf-text-secondary);
    font-weight: 500;
  }

  .list-type-badge {
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 0.8rem;
    font-weight: 800;
    text-transform: uppercase;
    letter-spacing: 0.3px;
    color: #fff;
    text-shadow: 0 1px 4px rgba(0, 0, 0, 0.5);
  }

  .list-type-badge.movie {
    background: var(--jf-movie-badge);
  }

  .list-type-badge.series {
    background: var(--jf-series-badge);
  }

  .list-runtime {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    font-size: 0.85rem;
    font-weight: 500;
    color: var(--jf-text-secondary);
  }

  .list-runtime ha-icon {
    --mdc-icon-size: 14px;
    margin-top: -2px;
  }

  .list-rating {
    display: inline-flex;
    align-items: center;
    gap: 2px;
    font-size: 0.85rem;
    color: var(--jf-series-badge);
    font-weight: 600;
  }

  .list-rating ha-icon {
    --mdc-icon-size: 14px;
    color: var(--jf-series-badge);
    margin-top: -2px;
  }



  .list-genres {
    margin: 0;
    font-size: 0.85rem;
    color: var(--jf-text-secondary);
    line-height: 1.4;
  }

  .list-description {
    margin: 0;
    font-size: 0.85rem;
    color: var(--jf-text-secondary);
    line-height: 1.5;
    display: -webkit-box;
    -webkit-line-clamp: 3;
    -webkit-box-orient: vertical;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  /* Remove hover overlay for list layout */
  .media-item.list-item .hover-overlay {
    display: none;
  }

  /* Keep badges visible in list layout */
  .media-item.list-item:hover .rating,
  .media-item.list-item:hover .runtime {
    opacity: 1;
  }

  /* Emphasize metadata on hover */
  .media-item.list-item:hover .list-title {
    color: var(--jf-primary);
  }

  .media-item.list-item:hover .list-info {
    transform: translateX(2px);
    transition: transform 0.2s ease;
  }

  .media-item.list-item:hover .list-date-added {
    font-weight: 600;
  }

  /* Move date up when it's above poster */
  .media-item.list-item:hover .list-poster-wrapper .list-date-added:first-child {
    transform: translateY(-2px);
  }

  /* Move date down when it's below poster */
  .media-item.list-item:hover .list-poster-wrapper .list-date-added:last-child {
    transform: translateY(2px);
  }

  .media-item.list-item:hover .list-year,
  .media-item.list-item:hover .list-runtime,
  .media-item.list-item:hover .list-rating {
    font-weight: 700;
  }

  /* Media Item Container - NO MOVEMENT on hover */
  .media-item {
    position: relative;
    display: flex;
    flex-direction: column;
    cursor: pointer;
    width: auto;
    z-index: 1;
    user-select: none;
    -webkit-user-select: none;
    -webkit-touch-callout: none;
  }

  .media-item:hover {
    z-index: 10; /* Bring hovered item forward so shadow shows above other elements */
  }

  .media-item:focus {
    outline: none;
  }

  .media-item:focus-visible {
    outline: 2px solid var(--jf-primary);
    outline-offset: 2px;
  }

  /* Poster Container with border */
  .poster-container {
    position: relative;
    width: 140px;
    aspect-ratio: 2/3;
    border-radius: var(--jf-poster-radius);
    overflow: visible;
    background: var(--jf-divider);
    border: 1px solid var(--jf-border-color);
    transition: border-color var(--jf-transition);
  }

  /* Brighter border on hover for dark theme */
  .poster-container:hover {
    border-color: rgba(255, 255, 255, 0.7);
  }

  /* Theme border for currently playing item */
  .media-item.playing .poster-container {
    border-color: var(--jf-primary);
  }

  .poster-inner {
    position: absolute;
    inset: 0;
    border-radius: var(--jf-poster-radius);
    overflow: hidden;
    transition: transform var(--jf-transition), box-shadow var(--jf-transition);
    z-index: 1;
    transform-origin: center center;
    transform: translate3d(0, 0, 0);
    will-change: transform;
    backface-visibility: hidden;
    -webkit-backface-visibility: hidden;
    image-rendering: high-quality;
    image-rendering: -webkit-optimize-contrast;
    filter: blur(0);
    -webkit-filter: blur(0);
  }

  /* Only the poster pops out on hover, stays in place */
  .media-item:hover .poster-inner {
    transform: scale(1.05);
    /* Dual shadow: white glow for dark themes, dark shadow for light themes */
    box-shadow: 
      0 0 10px rgba(255, 255, 255, 0.15),
      0 4px 8px rgba(0, 0, 0, 0.25);
    z-index: 10; /* Above scroll indicator */
    border: 1px solid rgba(255, 255, 255, 0.5);
    border-radius: var(--jf-poster-radius);
  }

  /* Press effect for mobile/touch */
  /* Pulse animation for confirming hold action */
  @keyframes holdPulse {
    0% { transform: scale(0.96); }
    50% { transform: scale(0.92); }
    100% { transform: scale(0.96); }
  }

  .poster-container.hold-pulse {
    animation: holdPulse 0.3s ease-in-out;
  }
  .media-item.active-press .poster-container,
  .media-item:active .poster-container {
    transform: scale(0.96);
    transition: transform 0.1s ease-out;
  }

  /* Vignette overlay for list items on hover */
  .media-item.list-item .poster-inner::after {
    content: '';
    position: absolute;
    inset: 0;
    border-radius: var(--jf-poster-radius);
    background: radial-gradient(
      ellipse at center,
      transparent 50%,
      rgba(0, 0, 0, 0.15) 100%
    );
    opacity: 0;
    transition: opacity var(--jf-transition);
    pointer-events: none;
  }

  .media-item.list-item:hover .poster-inner::after {
    opacity: 1;
  }

  .poster {
    width: 100%;
    height: 100%;
    object-fit: cover;
    opacity: 0;
    transition: opacity var(--jf-transition);
  }

  .poster.loaded {
    opacity: 1;
  }

  /* Skeleton loader */
  .poster-skeleton {
    position: absolute;
    inset: 0;
    background: linear-gradient(
      90deg,
      var(--jf-divider) 25%,
      rgba(255, 255, 255, 0.1) 50%,
      var(--jf-divider) 75%
    );
    background-size: 200% 100%;
    animation: skeleton-loading 1.5s infinite;
  }

  .poster.loaded + .poster-skeleton {
    display: none;
  }

  @keyframes skeleton-loading {
    0% { background-position: 200% 0; }
    100% { background-position: -200% 0; }
  }

  /* Error fallback - stop animation and show placeholder icon */
  .poster-skeleton.error {
    animation: none;
    background: var(--jf-divider);
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .poster-skeleton.error::after {
    content: '🎬';
    font-size: 2rem;
    opacity: 0.4;
  }

  /* Media Type Badge (MOVIE/SERIES) - Top Left - matches new-badge style */
  .media-type-badge {
    position: absolute;
    top: 6px;
    left: 6px;
    padding: 2px 8px 1px 8px;
    border-radius: 4px;
    font-size: 0.8rem;
    font-weight: 800;
    text-transform: uppercase;
    letter-spacing: 0.3px;
    color: #fff;
    z-index: 5;
    box-shadow: 0 2px 4px rgba(0,0,0,0.3);
    text-shadow: 0 1px 4px rgba(0, 0, 0, 0.5);
  }

  .media-type-badge.movie {
    background: var(--jf-movie-badge);
  }

  .media-type-badge.series {
    background: var(--jf-series-badge);
  }

  /* New Badge - Top Right */
  .new-badge {
    position: absolute;
    top: 6px;
    right: 6px;
    background: #009ac7;
    color: #fff;
    padding: 2px 8px 1px 8px;
    border-radius: 4px;
    font-size: 0.8rem;
    font-weight: 800;
    text-transform: uppercase;
    letter-spacing: 0.3px;
    z-index: 5;
    box-shadow: 0 2px 4px rgba(0,0,0,0.3);
    text-shadow: 0 1px 4px rgba(0, 0, 0, 0.5);
  }

  /* Status Badge (Watched/Unplayed) - Top Right */
  .status-badge {
    position: absolute;
    top: 6px;
    right: 6px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    z-index: 5;
    box-shadow: 0 2px 4px rgba(0,0,0,0.3);
  }

  /* Watched Checkmark - Rectangular Green */
  .status-badge.watched {
    padding: 2px 8px 1px 8px;
    font-weight: 800;    
    border-radius: 4px;
    background: #14B8A6;
    color: #fff;
    font-size: 0.8rem;
    text-shadow: 0 1px 4px rgba(0, 0, 0, 0.5);
  }

  .status-badge.watched ha-icon {
    --mdc-icon-size: 14px;
    margin-top: -1px;
  }

  /* Unplayed Count - Theme Colored Badge */
  .status-badge.unplayed {
    padding: 2px 8px 1px 8px;
    border-radius: 4px;
    background: #009ac7;
    color: #fff;
    font-size: 0.8rem;
    font-weight: 800;
    text-shadow: 0 1px 4px rgba(0, 0, 0, 0.5);
  }

  /* Rating Badge - Bottom Right */
  .rating {
    position: absolute;
    bottom: 6px;
    right: 6px;
    display: inline-flex;
    align-items: center;
    gap: 2px;
    background: rgba(0, 0, 0, 0.6);
    color: #F59E0B;
    padding: 3px 6px;
    border-radius: 4px;
    font-weight: 600;
    font-size: 0.8rem;
    z-index: 5;
    transition: opacity var(--jf-transition);
    text-shadow: 0 1px 4px rgba(0, 0, 0, 0.5);
  }

  .rating ha-icon {
    --mdc-icon-size: 13px;
    color: #F59E0B;
    margin-top: -1px;
  }

  .media-item:hover .rating {
    opacity: 0;
  }

  /* Runtime Badge (bottom-left, gray) */
  .runtime {
    position: absolute;
    bottom: 6px;
    left: 6px;
    display: inline-flex;
    align-items: center;
    gap: 2px;
    background: rgba(0, 0, 0, 0.6);
    color: rgba(255, 255, 255, 0.85);
    padding: 3px 6px;
    border-radius: 4px;
    font-weight: 600;
    font-size: 0.8rem;
    z-index: 5;
    transition: opacity var(--jf-transition);
    text-shadow: 0 1px 4px rgba(0, 0, 0, 0.5);
  }

  .runtime ha-icon {
    --mdc-icon-size: 12px;
    color: rgba(255, 255, 255, 0.85);
    margin-top: -1px;
  }

  .media-item:hover .runtime {
    opacity: 0;
  }

  /* Hover Overlay with bottom gradient - FORCE WHITE TEXT */
  .hover-overlay {
    position: absolute;
    inset: 0;
    background: linear-gradient(
      to top,
      rgba(0, 0, 0, 0.95) 0%,
      rgba(0, 0, 0, 0.85) 25%,
      rgba(0, 0, 0, 0.5) 50%,
      transparent 100%
    );
    display: flex;
    flex-direction: column;
    justify-content: flex-end;
    padding: 10px;
    opacity: 0;
    transition: opacity var(--jf-transition);
    border-radius: var(--jf-poster-radius);
    z-index: 7;
  }

  .media-item:hover .hover-overlay {
    opacity: 1;
  }

  .hover-overlay .overlay-year {
    font-size: 0.85rem;
    font-weight: 600;
    color: #fff !important;
    margin-bottom: 2px;
  }

  .hover-overlay .overlay-title {
    font-size: 0.9rem;
    font-weight: 600;
    color: #fff !important;
    margin: 0 0 6px 0;
    line-height: 1.2;
  }

  .hover-overlay .overlay-description {
    font-size: 0.7rem;
    color: rgba(255, 255, 255, 0.9) !important;
    margin: 0;
    line-height: 1.3;
    display: -webkit-box;
    -webkit-line-clamp: 3;
    -webkit-box-orient: vertical;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .hover-overlay .overlay-genres {
    font-size: 0.65rem;
    color: rgba(255, 255, 255, 0.65) !important;
    margin: 2px 0 4px 0;
    line-height: 1.3;
    overflow: hidden;
    text-overflow: ellipsis;
    display: -webkit-box;
    -webkit-line-clamp: 2;
    -webkit-box-orient: vertical;
  }

  /* Censor Bar Overlay - Aggressive Style */
  .censor-bar {
    position: absolute;
    top: 50%;
    left: -4%;
    right: -2%;
    transform: translateY(calc(-50%)) rotate(-5deg);
    background: #000;
    color: #fff;
    padding: 4px 4px;
    text-align: center;
    z-index: 6;
    box-shadow: 0 4px 10px rgba(0,0,0,0.5);
    border-top: 2px solid white;
    border-bottom: 2px solid white;
    width: 105%;
    display: flex;
    justify-content: center;
    align-items: center;
  }

  .censor-bar span {
    font-family: 'Impact', 'Arial Black', sans-serif;
    font-size: 1.4rem;
    font-weight: 900;
    text-transform: uppercase;
    line-height: 1.1;
    letter-spacing: 0.8px; /* Slightly increased for better readability */
    text-shadow: 2px 2px 0px #000;
    display: -webkit-box;
    -webkit-line-clamp: 2;
    -webkit-box-orient: vertical;
    overflow: hidden;
    max-width: 85%; /* Ensure text stays within visible poster area since bar is wider */
  }

  /* Highlight Style for Next Up */
  .censor-bar.highlight {
    background: var(--jf-series-badge);
    border-color: rgba(255, 255, 255, 0.95);
    box-shadow: 0 4px 12px rgba(0,0,0,0.6);
    z-index: 7;
    transform: translateY(calc(-50%)) rotate(-6deg) scale(1.05);
  }
  
  /* List specific adjustments for Censor Bar */
  .censor-bar.list-bar {
    padding: 2px 2px;
    /* Adjust position for smaller poster */
    transform: translateY(calc(-50%)) rotate(-3deg);
  }

  .censor-bar.list-bar span {
    font-size: 0.9rem; /* Smaller text for list view */
    letter-spacing: 0.3px;
  }

  /* Metadata Below Image (Default View) */
  .media-info-below {
    padding: 6px 2px 0;
    text-align: center;
    max-width: 140px;
    transition: transform var(--jf-transition);
  }

  /* Metadata Above Image */
  .media-info-above {
    padding: 0 2px 4px;
    text-align: center;
    max-width: 140px;
    transition: transform var(--jf-transition);
  }

  .media-info-above .media-title {
    font-size: 0.9rem;
    font-weight: 600;
    color: var(--jf-text);
    margin: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    line-height: 1.3;
  }

  .media-info-above .media-year {
    font-size: 0.9rem;
    font-weight: 500;
    color: var(--jf-text-secondary);
    margin: 2px 0 0 0;
  }

  .media-info-above .media-date-added {
    font-size: 0.9rem;
    font-weight: 500;
    color: var(--jf-text-secondary);
    margin: 0;
    opacity: 0.8;
    transition: font-weight var(--jf-transition);
  }

  .media-item:hover .media-info-above .media-date-added {
    font-weight: 600;
  }

  .media-item:hover .media-info-above {
    transform: translateY(-4px);
  }

  .media-item:hover .media-info-above .media-title {
    font-weight: 700;
    color: var(--jf-primary);
  }

  .media-item:hover .media-info-above .media-year {
    font-weight: 600;
  }

  .media-item:hover .media-info-below {
    transform: translateY(4px);
  }

  .media-info-below .media-title {
    font-size: 0.9rem;
    font-weight: 600;
    color: var(--jf-text);
    margin: 0 0 2px 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    line-height: 1.3;
    transition: font-weight var(--jf-transition), color var(--jf-transition);
  }

  .media-item:hover .media-info-below .media-title {
    font-weight: 700;
    color: var(--jf-primary);
  }

  .media-info-below .media-year {
    font-size: 0.9rem;
    font-weight: 500;
    color: var(--jf-text-secondary);
    margin: 2px 0 0 0;
    transition: font-weight var(--jf-transition);
  }

  .media-item:hover .media-info-below .media-year {
    font-weight: 600;
  }

  .media-info-below .media-date-added {
    font-size: 0.9rem;
    font-weight: 500;
    color: var(--jf-text-secondary);
    margin: 0;
    opacity: 0.8;
    transition: font-weight var(--jf-transition);
  }

  .media-item:hover .media-info-below .media-date-added {
    font-weight: 600;
  }

  /* Now Playing Overlay on Poster */
  .now-playing-overlay {
    position: absolute;
    inset: 0;
    background: rgba(0, 0, 0, 0.4);
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
    gap: 12px;
    z-index: 10;
    border-radius: var(--jf-poster-radius);
    animation: fadeIn 0.3s ease-out;
  }

  .now-playing-controls {
    display: flex;
    gap: 16px;
    align-items: center;
  }

  .now-playing-controls ha-icon-button {
    --mdc-icon-button-size: 40px;
    --mdc-icon-size: 28px;
    --mdc-ripple-color: transparent;
    color: #fff;
    background: rgba(255, 255, 255, 0.15) !important;
    border-radius: 50% !important;
    transition: background 0.2s;
    overflow: hidden;
  }

  .now-playing-controls ha-icon-button:hover {
    background: rgba(255, 255, 255, 0.25) !important;
  }

  .now-playing-controls ha-icon-button ha-icon {
    display: flex;
    align-items: center;
    justify-content: center;
    color: #fff;
  }

  .now-playing-status {
    color: rgba(255, 255, 255, 0.95);
    font-weight: 700;
    font-size: 0.8rem;
    line-height: 1;
    letter-spacing: 0.5px;
    background: rgba(255, 255, 255, 0.15);
    backdrop-filter: blur(4px);
    -webkit-backdrop-filter: blur(4px);
    padding: 7px 10px 5px;
    border-radius: 20px;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.2);
    white-space: nowrap;
    text-transform: uppercase;
  }
  @keyframes fadeIn {
    from { opacity: 0; }
    to { opacity: 1; }
  }
  /* Loading state */
  .loading {
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 200px;
    color: var(--jf-text-secondary);
  }

  /* Error state */
  .error {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    min-height: 200px;
    padding: 16px;
    text-align: center;
    color: var(--error-color, #F25C54);
  }

  .error ha-icon {
    --mdc-icon-size: 48px;
    margin-bottom: 8px;
  }

  /* Empty state */
  .empty {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    min-height: 200px;
    padding: 16px;
    text-align: center;
    color: var(--jf-text-secondary);
  }

  .empty ha-icon {
    --mdc-icon-size: 48px;
    margin-bottom: 8px;
    opacity: 0.5;
  }

  /* Responsive - smaller screens */
  @media (max-width: 600px) {
    .poster-container {
      width: 120px;
    }

    .media-info-below {
      max-width: 120px;
    }

    .hover-overlay .overlay-description {
      -webkit-line-clamp: 2;
    }
  }
  @keyframes spin {
    from { transform: rotate(0deg); }
    to { transform: rotate(360deg); }
  }

  .spinning {
    animation: spin 1s linear infinite;
    transform-origin: center;
  }

  /* Smart Pagination (Sliding Window) - iOS Style */
  .pagination-container.smart {
    overflow: hidden !important;
    max-width: 80px; /* Approx 5 dots (8px + 8px gap * 5) */
    margin: 0 auto;
    padding: 8px 0 12px;
    position: relative;
    z-index: 100;
  }

  .pagination-track {
    display: flex;
    gap: 8px; /* Match standard gap */
    transition: transform 0.3s cubic-bezier(0.25, 0.8, 0.25, 1);
    will-change: transform;
    justify-content: flex-start;
    padding-left: 0;
  }

  /* Smart Dot - Clone of .pagination-dot to ensure visual match */
  .smart-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--jf-text);
    opacity: 0.25;
    border: none;
    cursor: pointer;
    padding: 0;
    transition: background var(--jf-transition), transform 0.3s ease, opacity 0.3s ease;
    pointer-events: auto;
    flex-shrink: 0;
  }

  .smart-dot:hover {
    opacity: 0.5;
  }

  .smart-dot.active {
    background: var(--jf-primary);
    opacity: 1;
    transform: scale(1.2);
  }

  /* Smart Dot Specific Modifiers */
  .smart-dot.small {
    transform: scale(0.6);
    opacity: 0.6;
  }

  .smart-dot.hidden {
    transform: scale(0);
    opacity: 0;
    pointer-events: none;
  }


  /* Touch Action Optimization - Prevent double-tap zoom delay */
  .pagination-dot,
  .smart-dot,
  .media-item,
  ha-icon-button {
    touch-action: manipulation;
  }

  /* Reduced Motion Support - Respect user preference */
  @media (prefers-reduced-motion: reduce) {
    *,
    *::before,
    *::after {
      animation-duration: 0.01ms !important;
      animation-iteration-count: 1 !important;
      transition-duration: 0.01ms !important;
    }

    /* Disable skeleton animation */
    .poster-skeleton {
      animation: none;
      background: var(--jf-divider);
    }

    /* Keep transforms for layout but remove transitions */
    .carousel,
    .pagination-dot,
    .scroll-dot,
    .poster-inner,
    .hover-overlay,
    .media-item {
      transition: none !important;
    }
  }
`;