/**
 * Graphical editor for JellyHA Library Card
 */

import { LitElement, html, TemplateResult, css } from 'lit';
import { customElement, property, state } from 'lit/decorators.js';
import { JellyHALibraryCardConfig, HomeAssistant } from '../shared/types';
import { localize } from '../shared/localize';

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
    .side-by-side {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 16px;
      margin-bottom: 16px;
    }
    .side-by-side > .form-row {
      margin-bottom: 0;
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
    const doubleTapAction = this._config.double_tap_action || 'none';

    const lang = this.hass.locale?.language || this.hass.language;

    // Determine label for columns/rows slider
    const isHorizontalGrid = this._config.layout === 'grid' &&
      this._config.enable_pagination === false &&
      (this._config.auto_swipe_interval || 0) > 0;
    const columnsLabel = isHorizontalGrid ? localize(lang, 'editor.rows') : localize(lang, 'editor.columns');

    return html`
      <div class="card-config">
        <div class="form-row">
          <ha-selector
            .hass=${this.hass}
            .selector=${{ entity: { domain: 'sensor' } }}
            .value=${this._config.entity}
            label="${localize(lang, 'editor.entity')}"
            @value-changed=${this._entityChanged}
          ></ha-selector>
        </div>

        <div class="form-row">
          <ha-textfield
            label="${localize(lang, 'editor.title')}"
            .value=${this._config.title || ''}
            @input=${this._titleChanged}
          ></ha-textfield>
        </div>

        <div class="side-by-side">
          <div class="form-row">
            <ha-select
              label="${localize(lang, 'editor.layout')}"
              .value=${this._config.layout || 'carousel'}
              @selected=${this._layoutChanged}
              @closed=${(e: Event) => e.stopPropagation()}
            >
              <mwc-list-item value="carousel">${localize(lang, 'editor.layout_carousel')}</mwc-list-item>
              <mwc-list-item value="grid">${localize(lang, 'editor.layout_grid')}</mwc-list-item>
              <mwc-list-item value="list">${localize(lang, 'editor.layout_list')}</mwc-list-item>
            </ha-select>
          </div>

          <div class="form-row">
            <ha-select
              label="${localize(lang, 'editor.media_type')}"
              .value=${this._config.media_type || 'both'}
              @selected=${this._mediaTypeChanged}
              @closed=${(e: Event) => e.stopPropagation()}
            >
              <mwc-list-item value="both">${localize(lang, 'editor.media_type_both')}</mwc-list-item>
              <mwc-list-item value="movies">${localize(lang, 'editor.media_type_movies')}</mwc-list-item>
              <mwc-list-item value="series">${localize(lang, 'editor.media_type_series')}</mwc-list-item>
              <mwc-list-item value="next_up">${localize(lang, 'editor.media_type_next_up')}</mwc-list-item>
            </ha-select>
          </div>
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
                <span>${columnsLabel}: ${(this._config.columns || 1) === 1 ? localize(lang, 'editor.auto') : this._config.columns}</span>
              </div>
            `
        : ''}

        <div class="side-by-side">
          <div class="form-row">
            <ha-textfield
              label="${localize(lang, 'editor.items_per_page')}"
              type="number"
              min="1"
              required
              .value=${this._config.items_per_page !== undefined && this._config.items_per_page !== null ? String(this._config.items_per_page) : ''}
              @input=${this._itemsPerPageChanged}
            ></ha-textfield>
          </div>

          <div class="form-row">
            <ha-textfield
              label="${localize(lang, 'editor.max_pages')}"
              type="number"
              min="0"
              max="20"
              .value=${this._config.max_pages !== undefined && this._config.max_pages !== null ? String(this._config.max_pages) : ''}
              @input=${this._maxPagesChanged}
            ></ha-textfield>
          </div>
        </div>

        <div class="side-by-side">
          <div class="form-row">
            <ha-textfield
              label="${localize(lang, 'editor.auto_swipe')}"
              type="number"
              min="0"
              max="60"
              .value=${String(this._config.auto_swipe_interval || 0)}
              @input=${this._autoSwipeIntervalChanged}
            ></ha-textfield>
          </div>

          <div class="form-row">
            <ha-textfield
              label="${localize(lang, 'editor.new_badge_days')}"
              type="number"
              min="0"
              max="30"
              .value=${this._config.new_badge_days !== undefined && this._config.new_badge_days !== null ? String(this._config.new_badge_days) : ''}
              @input=${this._newBadgeDaysChanged}
            ></ha-textfield>
          </div>
        </div>

        <div class="side-by-side">
          <div class="form-row">
            <ha-select
              label="${localize(lang, 'editor.click_action')}"
              .value=${clickAction}
              @selected=${this._clickActionChanged}
              @closed=${(e: Event) => e.stopPropagation()}
            >
              <mwc-list-item value="jellyfin">${localize(lang, 'editor.action_jellyfin')}</mwc-list-item>
              <mwc-list-item value="cast">${localize(lang, 'editor.action_cast')}</mwc-list-item>
              <mwc-list-item value="more-info">${localize(lang, 'editor.action_more_info')}</mwc-list-item>
              <mwc-list-item value="trailer">${localize(lang, 'editor.action_trailer')}</mwc-list-item>
              <mwc-list-item value="none">${localize(lang, 'editor.action_none')}</mwc-list-item>
            </ha-select>
          </div>

          <div class="form-row">
            <ha-select
              label="${localize(lang, 'editor.hold_action')}"
              .value=${holdAction}
              @selected=${this._holdActionChanged}
              @closed=${(e: Event) => e.stopPropagation()}
            >
              <mwc-list-item value="jellyfin">${localize(lang, 'editor.action_jellyfin')}</mwc-list-item>
              <mwc-list-item value="cast">${localize(lang, 'editor.action_cast')}</mwc-list-item>
              <mwc-list-item value="more-info">${localize(lang, 'editor.action_more_info')}</mwc-list-item>
              <mwc-list-item value="trailer">${localize(lang, 'editor.action_trailer')}</mwc-list-item>
              <mwc-list-item value="none">${localize(lang, 'editor.action_none')}</mwc-list-item>
            </ha-select>
          </div>
        
        <div class="side-by-side">
          <div class="form-row">
            <ha-select
              label="${localize(lang, 'editor.double_tap_action')}"
              .value=${doubleTapAction}
              @selected=${this._doubleTapActionChanged}
              @closed=${(e: Event) => e.stopPropagation()}
            >
              <mwc-list-item value="jellyfin">${localize(lang, 'editor.action_jellyfin')}</mwc-list-item>
              <mwc-list-item value="cast">${localize(lang, 'editor.action_cast')}</mwc-list-item>
              <mwc-list-item value="more-info">${localize(lang, 'editor.action_more_info')}</mwc-list-item>
              <mwc-list-item value="trailer">${localize(lang, 'editor.action_trailer')}</mwc-list-item>
              <mwc-list-item value="none">${localize(lang, 'editor.action_none')}</mwc-list-item>
            </ha-select>
          </div>
        </div>
        </div>

        ${clickAction === 'cast' || holdAction === 'cast'
        ? html`
              <div class="form-row">
                <ha-selector
                  .hass=${this.hass}
                  .selector=${{ entity: { domain: 'media_player' } }}
                  .value=${this._config.default_cast_device}
                  label="${localize(lang, 'editor.default_cast_device')}"
                  @value-changed=${this._defaultCastDeviceChanged}
                ></ha-selector>
              </div>
              <div class="checkbox-row">
                <ha-switch
                  .checked=${this._config.show_now_playing !== false}
                  @change=${this._showNowPlayingChanged}
                ></ha-switch>
                <span>${localize(lang, 'editor.show_now_playing_overlay')}</span>
              </div>
            `
        : ''}

    <div class="checkbox-row">
      <ha-switch
        .checked=${this._config.show_title !== false}
        @change=${this._showTitleChanged}
      ></ha-switch>
      <span>${localize(lang, 'editor.show_title')}</span>
    </div>

    <div class="checkbox-row">
      <ha-switch
        .checked=${this._config.show_year !== false}
        @change=${this._showYearChanged}
      ></ha-switch>
      <span>${localize(lang, 'editor.show_year')}</span>
    </div>

    <div class="checkbox-row">
      <ha-switch
        .checked=${this._config.show_ratings !== false}
        @change=${this._showRatingsChanged}
      ></ha-switch>
      <span>${localize(lang, 'editor.show_rating')}</span>
    </div>

    <div class="checkbox-row">
      <ha-switch
        .checked=${this._config.show_runtime === true}
        @change=${this._showRuntimeChanged}
      ></ha-switch>
      <span>${localize(lang, 'editor.show_runtime')}</span>
    </div>

    <div class="checkbox-row">
      <ha-switch
        .checked=${this._config.show_date_added === true}
        @change=${this._showDateAddedChanged}
      ></ha-switch>
      <span>${localize(lang, 'editor.show_date_added')}</span>
    </div>

    <div class="checkbox-row">
      <ha-switch
        .checked=${this._config.show_genres === true}
        @change=${this._showGenresChanged}
      ></ha-switch>
      <span>${localize(lang, 'editor.show_genres')}</span>
    </div>

    <div class="checkbox-row">
      <ha-switch
        .checked=${this._config.show_description_on_hover !== false}
        @change=${this._showDescriptionOnHoverChanged}
      ></ha-switch>
      <span>${localize(lang, 'editor.show_description')}</span>
    </div>

    <div class="checkbox-row">
      <ha-switch
        .checked=${this._config.show_media_type_badge !== false}
        @change=${this._showMediaTypeBadgeChanged}
      ></ha-switch>
      <span>${localize(lang, 'editor.show_media_type_badge')}</span>
    </div>

    <div class="checkbox-row">
      <ha-switch
        .checked=${this._config.show_watched_status !== false}
        @change=${this._showWatchedStatusChanged}
      ></ha-switch>
      <span>${localize(lang, 'editor.show_watched_status')}</span>
    </div>

    <div class="side-by-side">
      <div class="form-row">
        <ha-select
          label="${localize(lang, 'editor.metadata_position')}"
          .value=${this._config.metadata_position || 'below'}
          @selected=${this._metadataPositionChanged}
          @closed=${(e: Event) => e.stopPropagation()}
        >
          <mwc-list-item value="below">${localize(lang, 'editor.metadata_below')}</mwc-list-item>
          <mwc-list-item value="above">${localize(lang, 'editor.metadata_above')}</mwc-list-item>
        </ha-select>
      </div>

      <div class="form-row">
        <ha-select
          label="${localize(lang, 'editor.sort_order')}"
          .value=${this._config.sort_option || 'date_added_desc'}
          @selected=${this._sortOptionChanged}
          @closed=${(e: Event) => e.stopPropagation()}
        >
          <mwc-list-item value="date_added_desc">${localize(lang, 'editor.sort_date_added_desc')}</mwc-list-item>
          <mwc-list-item value="date_added_asc">${localize(lang, 'editor.sort_date_added_asc')}</mwc-list-item>
          <mwc-list-item value="title_asc">${localize(lang, 'editor.sort_title_asc')}</mwc-list-item>
          <mwc-list-item value="title_desc">${localize(lang, 'editor.sort_title_desc')}</mwc-list-item>
          <mwc-list-item value="year_desc">${localize(lang, 'editor.sort_year_desc')}</mwc-list-item>
          <mwc-list-item value="year_asc">${localize(lang, 'editor.sort_year_asc')}</mwc-list-item>
          <mwc-list-item value="last_played_desc">${localize(lang, 'editor.sort_last_played_desc')}</mwc-list-item>
          <mwc-list-item value="last_played_asc">${localize(lang, 'editor.sort_last_played_asc')}</mwc-list-item>
        </ha-select>
      </div>
    </div>

    <div class="side-by-side">
      <div class="checkbox-row">
        <ha-switch
          .checked=${this._config.enable_pagination !== false}
          @change=${this._enablePaginationChanged}
        ></ha-switch>
        <span>${localize(lang, 'editor.enable_pagination')}</span>
      </div>

      <div class="checkbox-row">
        <ha-switch
          .checked=${this._config.show_pagination_dots !== false}
          @change=${this._showPaginationDotsChanged}
        ></ha-switch>
        <span>${localize(lang, 'editor.show_pagination_dots')}</span>
      </div>
    </div>

    <div class="form-row">
      <ha-select
        label="${localize(lang, 'editor.filter_watch_status')}"
        .value=${this._config.status_filter || 'all'}
        @selected=${this._statusFilterChanged}
        @closed=${(e: Event) => e.stopPropagation()}
      >
        <mwc-list-item value="all">${localize(lang, 'editor.filter_all')}</mwc-list-item>
        <mwc-list-item value="unwatched">${localize(lang, 'editor.filter_unwatched')}</mwc-list-item>
        <mwc-list-item value="watched">${localize(lang, 'editor.filter_watched')}</mwc-list-item>
      </ha-select>
    </div>

    <div class="side-by-side">
      <div class="checkbox-row">
        <ha-switch
          .checked=${this._config.filter_favorites === true}
          @change=${this._filterFavoritesChanged}
        ></ha-switch>
        <span>${localize(lang, 'editor.filter_favorites')}</span>
      </div>

      <div class="checkbox-row">
        <ha-switch
          .checked=${this._config.filter_newly_added === true}
          @change=${this._filterNewlyAddedChanged}
        ></ha-switch>
        <span>${localize(lang, 'editor.filter_new_items')}</span>
      </div>
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
      // Allow clearing (will use default later or in card)
      this._updateConfig('items_per_page', null);
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

  private _doubleTapActionChanged(e: Event): void {
    const target = e.target as HTMLSelectElement;
    this._updateConfig('double_tap_action', target.value);
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

  private _enablePaginationChanged(e: Event): void {
    const target = e.target as HTMLInputElement;
    this._updateConfig('enable_pagination', target.checked);
  }

  private _showPaginationDotsChanged(e: Event): void {
    const target = e.target as HTMLInputElement;
    this._updateConfig('show_pagination_dots', target.checked);
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

