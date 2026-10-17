import { css } from 'lit';

/**
 * Centralized metadata row styles shared across JellyHA cards:
 * - JellyHA Now Playing Card (idle poster view, active playback, idle showcase)
 * - JellyHA Library Card (list view, featured hero view)
 *
 * Ensures 1:1 optical alignment, 22px baseline height, and glassmorphic
 * aesthetics for media type badges, metadata text, separator dots, rating pills,
 * and genre pills.
 */
export const sharedMetaRowStyles = css`
  .list-metadata {
    display: flex !important;
    flex-direction: column !important;
    align-items: flex-start !important;
    gap: 3px;
    margin: 1px 0 2px 0 !important;
  }

  .idle-meta-row,
  .meta-line.idle-meta-row,
  .list-meta-row,
  .list-meta-pills {
    display: flex !important;
    flex-direction: row !important;
    align-items: center !important;
    flex-wrap: wrap !important;
    gap: 6px 8px;
    font-size: 12px;
    color: #ffffff;
    text-shadow: 0 1px 3px rgba(0, 0, 0, 0.65);
    margin: 0 !important;
    line-height: 1;
  }

  .list-meta-row {
    gap: 2px 6px !important;
  }

  .meta-line.idle-meta-row .media-type-badge.inline-badge,
  .idle-meta-row .media-type-badge.inline-badge,
  .list-metadata .media-type-badge.inline-badge,
  .media-type-badge.inline-badge {
    position: static !important;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    height: 22px;
    box-sizing: border-box;
    border-radius: 4px;
    font-size: 0.78rem;
    font-weight: 800;
    letter-spacing: 0.3px;
    text-transform: uppercase;
    padding: 1.5px 8px 0.5px 8px;
    line-height: 1;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.4);
    text-shadow: 0 1px 4px rgba(0, 0, 0, 0.5) !important;
    pointer-events: none;
    flex-shrink: 0;
  }

  .new-badge.inline-badge {
    position: static !important;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    height: 22px;
    box-sizing: border-box;
    border-radius: 4px;
    font-size: 0.78rem;
    font-weight: 800;
    letter-spacing: 0.3px;
    text-transform: uppercase;
    padding: 1.5px 8px 0.5px 8px;
    line-height: 1;
    background: #009ac7;
    color: #fff;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.4);
    text-shadow: 0 1px 4px rgba(0, 0, 0, 0.5) !important;
    pointer-events: none;
    flex-shrink: 0;
  }

  .status-badge.inline-badge {
    position: static !important;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    height: 22px;
    box-sizing: border-box;
    border-radius: 4px;
    font-size: 0.78rem;
    font-weight: 800;
    line-height: 1;
    padding: 0 6px;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.4);
    text-shadow: 0 1px 4px rgba(0, 0, 0, 0.5) !important;
    pointer-events: none;
    flex-shrink: 0;
  }

  .status-badge.inline-badge ha-icon {
    --mdc-icon-size: 14px;
    margin: 0;
  }

  .idle-meta-text,
  .meta-text {
    display: inline-flex;
    align-items: center;
    height: 22px;
    line-height: 1;
    font-size: 12px;
    font-weight: 500;
    color: #ffffff;
    white-space: nowrap;
    text-shadow: 0 1px 3px rgba(0, 0, 0, 0.65);
    transform: translateY(1px);
  }

  .list-metadata .meta-text,
  .list-year,
  .list-runtime,
  .list-date-added {
    display: inline-flex;
    align-items: center;
    height: 16px;
    line-height: 1;
    font-size: 11px !important;
    font-weight: 500;
    color: #ffffff;
    white-space: nowrap;
    text-shadow: 0 1px 3px rgba(0, 0, 0, 0.65);
    transform: translateY(0.5px);
  }

  .idle-dot,
  .meta-dot {
    opacity: 0.6;
    font-size: 12px;
    color: #ffffff;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    height: 22px;
    line-height: 1;
    transform: translateY(0.5px);
  }

  .list-metadata .meta-dot {
    opacity: 0.6;
    font-size: 11px !important;
    color: #ffffff;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    height: 16px;
    line-height: 1;
    transform: translateY(0.5px);
  }

  .idle-rating-pill,
  .rating-pill,
  .poster-badge.rating-pill,
  .rating.rating-pill,
  .list-metadata .rating-pill {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 3px;
    background: rgba(245, 158, 11, 0.25);
    border: 1px solid rgba(245, 158, 11, 0.45);
    backdrop-filter: blur(4px);
    -webkit-backdrop-filter: blur(4px);
    color: #fbbf24;
    height: 22px;
    padding: 1px 6px 0 6px;
    border-radius: 4px;
    font-size: 12px;
    font-weight: 700;
    line-height: 1;
    box-sizing: border-box;
    flex-shrink: 0;
    text-shadow: 0 1px 2px rgba(0, 0, 0, 0.8);
  }

  .featured-hero-scrim .rating-pill,
  .featured-hero-scrim .genre-pill,
  .featured-side .rating-pill,
  .featured-side .genre-pill,
  .list-metadata .rating-pill,
  .list-metadata .genre-pill,
  .media-item.list-item .rating-pill,
  .media-item.list-item .genre-pill {
    font-size: 11px !important;
  }

  .idle-rating-pill ha-icon,
  .rating-pill ha-icon,
  .poster-badge.rating-pill ha-icon,
  .rating.rating-pill ha-icon,
  .list-metadata .rating-pill ha-icon {
    --mdc-icon-size: 12px;
    width: 12px;
    height: 12px;
    display: flex;
    align-items: center;
    justify-content: center;
    transform: translateY(-1px);
    margin: 0;
    padding: 0;
    flex-shrink: 0;
    color: #fbbf24;
  }

  .idle-rating-pill span,
  .rating-pill span,
  .poster-badge.rating-pill span,
  .rating.rating-pill span,
  .list-metadata .rating-pill span {
    display: inline-flex;
    align-items: center;
    line-height: 1;
    transform: translateY(-0.5px);
  }

  .idle-genre-pill,
  .genre-pill.idle-genre-pill,
  .genre-pill,
  .poster-badge.genre-pill,
  .runtime.genre-pill,
  .list-metadata .genre-pill {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    background: rgba(255, 255, 255, 0.14);
    border: 1px solid rgba(255, 255, 255, 0.24);
    backdrop-filter: blur(4px);
    -webkit-backdrop-filter: blur(4px);
    height: 22px;
    padding: 0 7px !important;
    border-radius: 4px;
    font-size: 12px;
    color: #ffffff;
    font-weight: 500;
    line-height: 1 !important;
    box-sizing: border-box;
    flex-shrink: 0;
    text-shadow: 0 1px 2px rgba(0, 0, 0, 0.8);
  }

  .idle-genre-pill span,
  .genre-pill span,
  .poster-badge.genre-pill span,
  .runtime.genre-pill span,
  .list-metadata .genre-pill span {
    display: inline-flex;
    align-items: center;
    line-height: 1;
  }
`;
