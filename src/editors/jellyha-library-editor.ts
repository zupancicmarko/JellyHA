/**
 * Graphical editor for JellyHA Library Card
 */

import { LitElement, html, TemplateResult, css } from 'lit';
import { customElement, property, state } from 'lit/decorators.js';
import { JellyHALibraryCardConfig, HomeAssistant } from '../shared/types';

// Helper function to fire events
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

@customElement('jellyha-library-editor')
export class JellyHALibraryEditor extends LitElement {
  @property({ attribute: false }) hass!: HomeAssistant;
  @state() private _config!: JellyHALibraryCardConfig;

  static styles = css`
    .form-row {
      margin-bottom: 16px;
    }
    .form-row ha-textfield,
    .form-row ha-select,
    .form-row ha-entity-picker,
    .form-row ha-selector {
      width: 100%;
    }
    .checkbox-row {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 8px;
    }
  `;

  public setConfig(config: JellyHALibraryCardConfig): void {
    this._config = config;
  }

  protected render(): TemplateResult {
    if (!this.hass || !this._config) {
      return html``;
    }

    const clickAction = this._config.click_action || 'more-info';
    const holdAction = this._config.hold_action || 'jellyfin';

    return html`
      <div class="card-config">
        <div class="form-row">
          <ha-selector
            .hass=${this.hass}
            .selector=${{ entity: { domain: 'sensor' } }}
            .value=${this._config.entity}
            label="Entity"
            @value-changed=${this._entityChanged}
          ></ha-selector>
        </div>

        <div class="form-row">
          <ha-textfield
            label="Title"
            .value=${this._config.title || ''}
            @input=${this._titleChanged}
          ></ha-textfield>
        </div>

        <div class="form-row">
          <ha-select
            label="Layout"
            .value=${this._config.layout || 'carousel'}
            @selected=${this._layoutChanged}
            @closed=${(e: Event) => e.stopPropagation()}
          >
            <mwc-list-item value="carousel">Carousel</mwc-list-item>
            <mwc-list-item value="grid">Grid</mwc-list-item>
            <mwc-list-item value="list">List</mwc-list-item>
          </ha-select>
        </div>

        ${this._config.layout === 'grid' || this._config.layout === 'list'
        ? html`
              <div class="form-row">
                <ha-slider
                  labeled
                  min="1"
                  max="${this._config.layout === 'list' ? 8 : 12}"
                  .value=${this._config.columns || 1}
                  @change=${this._columnsChanged}
                ></ha-slider>
                <span>Columns: ${(this._config.columns || 1) === 1 ? 'Auto' : this._config.columns}</span>
              </div>
            `
        : ''}

        <div class="form-row">
          <ha-select
            label="Media Type"
            .value=${this._config.media_type || 'both'}
            @selected=${this._mediaTypeChanged}
            @closed=${(e: Event) => e.stopPropagation()}
          >
            <mwc-list-item value="both">Movies & TV Shows</mwc-list-item>
            <mwc-list-item value="movies">Movies Only</mwc-list-item>
            <mwc-list-item value="series">TV Shows Only</mwc-list-item>
          </ha-select>
        </div>

        <div class="form-row">
          <ha-textfield
            label="Items Per Page"
            type="number"
            min="1"
            required
            .value=${this._config.items_per_page !== undefined ? String(this._config.items_per_page) : ''}
            @input=${this._itemsPerPageChanged}
          ></ha-textfield>
        </div>

        <div class="form-row">
          <ha-textfield
            label="Max Pages (0 or blank = no limit)"
            type="number"
            min="0"
            max="20"
            .value=${this._config.max_pages !== undefined && this._config.max_pages !== null ? String(this._config.max_pages) : ''}
            @input=${this._maxPagesChanged}
          ></ha-textfield>
        </div>

        <div class="form-row">
          <ha-textfield
            label="Auto Swipe Interval (seconds, 0 = off)"
            type="number"
            min="0"
            max="60"
            .value=${String(this._config.auto_swipe_interval || 0)}
            @input=${this._autoSwipeIntervalChanged}
          ></ha-textfield>
        </div>

        <div class="form-row">
          <ha-textfield
            label="New Badge Days (0 or blank = off)"
            type="number"
            min="0"
            max="30"
            .value=${this._config.new_badge_days !== undefined && this._config.new_badge_days !== null ? String(this._config.new_badge_days) : ''}
            @input=${this._newBadgeDaysChanged}
          ></ha-textfield>
        </div>

        <div class="form-row">
          <ha-select
            label="Short Press (Click) Action"
            .value=${clickAction}
            @selected=${this._clickActionChanged}
            @closed=${(e: Event) => e.stopPropagation()}
          >
            <mwc-list-item value="jellyfin">Open in Jellyfin</mwc-list-item>
            <mwc-list-item value="cast">Cast to Chromecast</mwc-list-item>
            <mwc-list-item value="more-info">More Information</mwc-list-item>
            <mwc-list-item value="none">No Action</mwc-list-item>
          </ha-select>
        </div>

        <div class="form-row">
          <ha-select
            label="Long Press (Hold) Action"
            .value=${holdAction}
            @selected=${this._holdActionChanged}
            @closed=${(e: Event) => e.stopPropagation()}
          >
            <mwc-list-item value="jellyfin">Open in Jellyfin</mwc-list-item>
            <mwc-list-item value="cast">Cast to Chromecast</mwc-list-item>
            <mwc-list-item value="more-info">More Information</mwc-list-item>
            <mwc-list-item value="none">No Action</mwc-list-item>
          </ha-select>
        </div>

        ${clickAction === 'cast' || holdAction === 'cast'
        ? html`
              <div class="form-row">
                <ha-selector
                  .hass=${this.hass}
                  .selector=${{ entity: { domain: 'media_player' } }}
                  .value=${this._config.default_cast_device}
                  label="Default Cast Device"
                  @value-changed=${this._defaultCastDeviceChanged}
                ></ha-selector>
              </div>
              <div class="checkbox-row">
                <ha-switch
                  .checked=${this._config.show_now_playing !== false}
                  @change=${this._showNowPlayingChanged}
                ></ha-switch>
                <span>Show "Now Playing" Overlay on Posters</span>
              </div>
            `
        : ''}

    <div class="checkbox-row">
      <ha-switch
        .checked=${this._config.show_title !== false}
        @change=${this._showTitleChanged}
      ></ha-switch>
      <span>Show Title</span>
    </div>

    <div class="checkbox-row">
      <ha-switch
        .checked=${this._config.show_year !== false}
        @change=${this._showYearChanged}
      ></ha-switch>
      <span>Show Year</span>
    </div>

    <div class="checkbox-row">
      <ha-switch
        .checked=${this._config.show_date_added === true}
        @change=${this._showDateAddedChanged}
      ></ha-switch>
      <span>Show Date Added</span>
    </div>

    <div class="checkbox-row">
      <ha-switch
        .checked=${this._config.show_ratings !== false}
        @change=${this._showRatingsChanged}
      ></ha-switch>
      <span>Show Ratings</span>
    </div>

    <div class="checkbox-row">
      <ha-switch
        .checked=${this._config.show_runtime === true}
        @change=${this._showRuntimeChanged}
      ></ha-switch>
      <span>Show Runtime</span>
    </div>

    <div class="checkbox-row">
      <ha-switch
        .checked=${this._config.show_media_type_badge !== false}
        @change=${this._showMediaTypeBadgeChanged}
      ></ha-switch>
      <span>Show Media Type Badge (Movie/Series)</span>
    </div>

    <div class="checkbox-row">
      <ha-switch
        .checked=${this._config.show_watched_status !== false}
        @change=${this._showWatchedStatusChanged}
      ></ha-switch>
      <span>Show Watched Status</span>
    </div>

    <div class="checkbox-row">
      <ha-switch
        .checked=${this._config.show_genres === true}
        @change=${this._showGenresChanged}
      ></ha-switch>
      <span>Show Genres</span>
    </div>

    <div class="checkbox-row">
      <ha-switch
        .checked=${this._config.show_description_on_hover !== false}
        @change=${this._showDescriptionOnHoverChanged}
      ></ha-switch>
      <span>Show Description</span>
    </div>

    <div class="form-row">
      <ha-select
        label="Metadata Position"
        .value=${this._config.metadata_position || 'below'}
        @selected=${this._metadataPositionChanged}
        @closed=${(e: Event) => e.stopPropagation()}
      >
        <mwc-list-item value="below">Below</mwc-list-item>
        <mwc-list-item value="above">Above</mwc-list-item>
      </ha-select>
    </div>

    <div class="checkbox-row">
      <ha-switch
        .checked=${this._config.show_pagination !== false}
        @change=${this._showPaginationChanged}
      ></ha-switch>
      <span>Show Pagination Dots</span>
    </div>

    <div class="checkbox-row">
      <ha-switch
        .checked=${this._config.filter_favorites === true}
        @change=${this._filterFavoritesChanged}
      ></ha-switch>
      <span>Show Only Favorites</span>
    </div>

    <div class="form-row">
      <ha-select
        label="Watch Status"
        .value=${this._config.status_filter || 'all'}
        @selected=${this._statusFilterChanged}
        @closed=${(e: Event) => e.stopPropagation()}
      >
        <mwc-list-item value="all">All</mwc-list-item>
        <mwc-list-item value="unwatched">Unwatched</mwc-list-item>
        <mwc-list-item value="watched">Watched</mwc-list-item>
      </ha-select>
    </div>

    <div class="checkbox-row">
      <ha-switch
        .checked=${this._config.filter_newly_added === true}
        @change=${this._filterNewlyAddedChanged}
      ></ha-switch>
      <span>Show New Items Only</span>
    </div>

    <div class="form-row">
      <ha-select
        label="Sort Order"
        .value=${this._config.sort_option || 'date_added_desc'}
        @selected=${this._sortOptionChanged}
        @closed=${(e: Event) => e.stopPropagation()}
      >
        <mwc-list-item value="date_added_desc">Date Added (Newest First)</mwc-list-item>
        <mwc-list-item value="date_added_asc">Date Added (Oldest First)</mwc-list-item>
        <mwc-list-item value="title_asc">Title (A-Z)</mwc-list-item>
        <mwc-list-item value="title_desc">Title (Z-A)</mwc-list-item>
        <mwc-list-item value="year_desc">Year (Newest First)</mwc-list-item>
        <mwc-list-item value="year_asc">Year (Oldest First)</mwc-list-item>
        <mwc-list-item value="last_played_desc">Last Played (Newest First)</mwc-list-item>
        <mwc-list-item value="last_played_asc">Last Played (Oldest First)</mwc-list-item>
      </ha-select>
    </div>
  </div>
`;
  }

  private _entityChanged(e: CustomEvent): void {
    this._updateConfig('entity', e.detail.value);
  }

  private _titleChanged(e: Event): void {
    const target = e.target as HTMLInputElement;
    this._updateConfig('title', target.value);
  }

  private _layoutChanged(e: Event): void {
    const target = e.target as HTMLSelectElement;
    this._updateConfig('layout', target.value);
  }

  private _columnsChanged(e: Event): void {
    const target = e.target as HTMLInputElement;
    this._updateConfig('columns', Number(target.value));
  }

  private _mediaTypeChanged(e: Event): void {
    const target = e.target as HTMLSelectElement;
    this._updateConfig('media_type', target.value);
  }

  private _itemsPerPageChanged(e: Event): void {
    const target = e.target as HTMLInputElement;
    const value = target.value.trim();
    if (value !== '') {
      this._updateConfig('items_per_page', Number(value));
    } else {
      // Revert to default if cleared
      this._updateConfig('items_per_page', 5);
      target.value = '5';
    }
  }

  private _maxPagesChanged(e: Event): void {
    const target = e.target as HTMLInputElement;
    const value = target.value;
    if (value === '' || value === null) {
      this._updateConfig('max_pages', null);
    } else {
      this._updateConfig('max_pages', Number(value));
    }
  }

  private _autoSwipeIntervalChanged(e: Event): void {
    const target = e.target as HTMLInputElement;
    this._updateConfig('auto_swipe_interval', Number(target.value));
  }

  private _newBadgeDaysChanged(e: Event): void {
    const target = e.target as HTMLInputElement;
    const value = target.value;
    if (value === '' || value === null) {
      this._updateConfig('new_badge_days', null);
    } else {
      this._updateConfig('new_badge_days', Number(value));
    }
  }

  private _clickActionChanged(e: Event): void {
    const target = e.target as HTMLSelectElement;
    this._updateConfig('click_action', target.value);
  }

  private _holdActionChanged(e: Event): void {
    const target = e.target as HTMLSelectElement;
    this._updateConfig('hold_action', target.value);
  }

  private _defaultCastDeviceChanged(e: CustomEvent): void {
    this._updateConfig('default_cast_device', e.detail.value);
  }

  private _showNowPlayingChanged(e: Event): void {
    const target = e.target as HTMLInputElement;
    this._updateConfig('show_now_playing', target.checked);
  }

  private _showTitleChanged(e: Event): void {
    const target = e.target as HTMLInputElement;
    this._updateConfig('show_title', target.checked);
  }

  private _showYearChanged(e: Event): void {
    const target = e.target as HTMLInputElement;
    this._updateConfig('show_year', target.checked);
  }

  private _showRatingsChanged(e: Event): void {
    const target = e.target as HTMLInputElement;
    this._updateConfig('show_ratings', target.checked);
  }

  private _showRuntimeChanged(e: Event): void {
    const target = e.target as HTMLInputElement;
    this._updateConfig('show_runtime', target.checked);
  }

  private _showMediaTypeBadgeChanged(e: Event): void {
    const target = e.target as HTMLInputElement;
    this._updateConfig('show_media_type_badge', target.checked);
  }

  private _showWatchedStatusChanged(e: Event): void {
    const target = e.target as HTMLInputElement;
    this._updateConfig('show_watched_status', target.checked);
  }

  private _showGenresChanged(e: Event): void {
    const target = e.target as HTMLInputElement;
    this._updateConfig('show_genres', target.checked);
  }

  private _showDateAddedChanged(e: Event): void {
    const target = e.target as HTMLInputElement;
    this._updateConfig('show_date_added', target.checked);
  }

  private _showDescriptionOnHoverChanged(e: Event): void {
    const target = e.target as HTMLInputElement;
    this._updateConfig('show_description_on_hover', target.checked);
  }

  private _metadataPositionChanged(e: Event): void {
    const target = e.target as HTMLSelectElement;
    this._updateConfig('metadata_position', target.value);
  }

  private _horizontalAlignmentChanged(e: Event): void {
    const target = e.target as HTMLSelectElement;
    this._updateConfig('horizontal_alignment', target.value);
  }

  private _showPaginationChanged(e: Event): void {
    const target = e.target as HTMLInputElement;
    this._updateConfig('show_pagination', target.checked);
  }

  private _filterFavoritesChanged(e: Event): void {
    const target = e.target as HTMLInputElement;
    this._updateConfig('filter_favorites', target.checked);
  }

  private _statusFilterChanged(e: Event): void {
    const target = e.target as HTMLSelectElement;
    this._updateConfig('status_filter', target.value);
  }

  private _filterNewlyAddedChanged(e: Event): void {
    const target = e.target as HTMLInputElement;
    this._updateConfig('filter_newly_added', target.checked);
  }

  private _sortOptionChanged(e: Event): void {
    const target = e.target as HTMLSelectElement;
    this._updateConfig('sort_option', target.value);
  }

  private _updateConfig(key: string, value: unknown): void {
    if (!this._config) {
      return;
    }

    const newConfig = { ...this._config, [key]: value };
    this._config = newConfig;

    fireEvent(this as unknown as EventTarget, 'config-changed', { config: newConfig });
  }
}

declare global {
  interface HTMLElementTagNameMap {
    'jellyha-library-editor': JellyHALibraryEditor;
  }
}

