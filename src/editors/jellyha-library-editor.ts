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
          <ha-selector
            .hass=${this.hass}
            .selector=${{ text: {} }}
            .value=${this._config.title || ''}
            .label=${localize(lang, 'editor.title')}
            label="${localize(lang, 'editor.title')}"
            @value-changed=${this._titleChanged}
          ></ha-selector>
        </div>

        <div class="side-by-side">
          <div class="form-row">
            <ha-selector
              .hass=${this.hass}
              .selector=${{
                select: {
                  mode: 'dropdown',
                  options: [
                    { value: 'carousel', label: localize(lang, 'editor.layout_carousel') },
                    { value: 'grid', label: localize(lang, 'editor.layout_grid') },
                    { value: 'list', label: localize(lang, 'editor.layout_list') },
                  ],
                },
              }}
              .value=${this._config.layout || 'carousel'}
              .label=${localize(lang, 'editor.layout')}
              label="${localize(lang, 'editor.layout')}"
              @value-changed=${this._layoutChanged}
            ></ha-selector>
          </div>

          <div class="form-row">
            <ha-selector
              .hass=${this.hass}
              .selector=${{
                select: {
                  mode: 'dropdown',
                  options: [
                    { value: 'both', label: localize(lang, 'editor.media_type_both') },
                    { value: 'movies', label: localize(lang, 'editor.media_type_movies') },
                    { value: 'series', label: localize(lang, 'editor.media_type_series') },
                    { value: 'next_up', label: localize(lang, 'editor.media_type_next_up') },
                  ],
                },
              }}
              .value=${this._config.media_type || 'both'}
              .label=${localize(lang, 'editor.media_type')}
              label="${localize(lang, 'editor.media_type')}"
              @value-changed=${this._mediaTypeChanged}
            ></ha-selector>
          </div>
        </div>

        ${this._config.layout === 'grid' || this._config.layout === 'list'
        ? html`
              <div class="form-row">
                <ha-selector
                  .hass=${this.hass}
                  .selector=${{
                    number: {
                      min: 1,
                      max: this._config.layout === 'list' ? 8 : 12,
                      mode: 'slider',
                    },
                  }}
                  .value=${this._config.columns || 1}
                  .label=${`${columnsLabel}: ${(this._config.columns || 1) === 1 ? localize(lang, 'editor.auto') : this._config.columns}`}
                  label="${`${columnsLabel}: ${(this._config.columns || 1) === 1 ? localize(lang, 'editor.auto') : this._config.columns}`}"
                  @value-changed=${this._columnsChanged}
                ></ha-selector>
              </div>
            `
        : ''}

        <div class="side-by-side">
          <div class="form-row">
            <ha-selector
              .hass=${this.hass}
              .selector=${{
                number: {
                  min: 1,
                  max: 50,
                  mode: 'box',
                },
              }}
              .value=${this._config.items_per_page !== undefined && this._config.items_per_page !== null ? this._config.items_per_page : 5}
              .label=${localize(lang, 'editor.items_per_page')}
              label="${localize(lang, 'editor.items_per_page')}"
              @value-changed=${this._itemsPerPageChanged}
            ></ha-selector>
          </div>

          <div class="form-row">
            <ha-selector
              .hass=${this.hass}
              .selector=${{
                number: {
                  min: 0,
                  max: 20,
                  mode: 'box',
                },
              }}
              .value=${this._config.max_pages !== undefined && this._config.max_pages !== null ? this._config.max_pages : 5}
              .label=${localize(lang, 'editor.max_pages')}
              label="${localize(lang, 'editor.max_pages')}"
              @value-changed=${this._maxPagesChanged}
            ></ha-selector>
          </div>
        </div>

        <div class="side-by-side">
          <div class="form-row">
            <ha-selector
              .hass=${this.hass}
              .selector=${{
                number: {
                  min: 0,
                  max: 60,
                  mode: 'box',
                  unit_of_measurement: 's',
                },
              }}
              .value=${this._config.auto_swipe_interval !== undefined && this._config.auto_swipe_interval !== null ? this._config.auto_swipe_interval : 0}
              .label=${localize(lang, 'editor.auto_swipe')}
              label="${localize(lang, 'editor.auto_swipe')}"
              @value-changed=${this._autoSwipeIntervalChanged}
            ></ha-selector>
          </div>

          <div class="form-row">
            <ha-selector
              .hass=${this.hass}
              .selector=${{
                number: {
                  min: 0,
                  max: 30,
                  mode: 'box',
                  unit_of_measurement: 'days',
                },
              }}
              .value=${this._config.new_badge_days !== undefined && this._config.new_badge_days !== null ? this._config.new_badge_days : 3}
              .label=${localize(lang, 'editor.new_badge_days')}
              label="${localize(lang, 'editor.new_badge_days')}"
              @value-changed=${this._newBadgeDaysChanged}
            ></ha-selector>
          </div>
        </div>

        <div class="side-by-side">
          <div class="form-row">
            <ha-selector
              .hass=${this.hass}
              .selector=${{
                select: {
                  mode: 'dropdown',
                  options: [
                    { value: 'jellyfin', label: localize(lang, 'editor.action_jellyfin') },
                    { value: 'cast', label: localize(lang, 'editor.action_cast') },
                    { value: 'more-info', label: localize(lang, 'editor.action_more_info') },
                    { value: 'trailer', label: localize(lang, 'editor.action_trailer') },
                    { value: 'none', label: localize(lang, 'editor.action_none') },
                  ],
                },
              }}
              .value=${clickAction}
              .label=${localize(lang, 'editor.click_action')}
              label="${localize(lang, 'editor.click_action')}"
              @value-changed=${this._clickActionChanged}
            ></ha-selector>
          </div>

          <div class="form-row">
            <ha-selector
              .hass=${this.hass}
              .selector=${{
                select: {
                  mode: 'dropdown',
                  options: [
                    { value: 'jellyfin', label: localize(lang, 'editor.action_jellyfin') },
                    { value: 'cast', label: localize(lang, 'editor.action_cast') },
                    { value: 'more-info', label: localize(lang, 'editor.action_more_info') },
                    { value: 'trailer', label: localize(lang, 'editor.action_trailer') },
                    { value: 'none', label: localize(lang, 'editor.action_none') },
                  ],
                },
              }}
              .value=${holdAction}
              .label=${localize(lang, 'editor.hold_action')}
              label="${localize(lang, 'editor.hold_action')}"
              @value-changed=${this._holdActionChanged}
            ></ha-selector>
          </div>
        </div>

        <div class="side-by-side">
          <div class="form-row">
            <ha-selector
              .hass=${this.hass}
              .selector=${{
                select: {
                  mode: 'dropdown',
                  options: [
                    { value: 'jellyfin', label: localize(lang, 'editor.action_jellyfin') },
                    { value: 'cast', label: localize(lang, 'editor.action_cast') },
                    { value: 'more-info', label: localize(lang, 'editor.action_more_info') },
                    { value: 'trailer', label: localize(lang, 'editor.action_trailer') },
                    { value: 'none', label: localize(lang, 'editor.action_none') },
                  ],
                },
              }}
              .value=${doubleTapAction}
              .label=${localize(lang, 'editor.double_tap_action')}
              label="${localize(lang, 'editor.double_tap_action')}"
              @value-changed=${this._doubleTapActionChanged}
            ></ha-selector>
          </div>

          ${clickAction === 'cast' || holdAction === 'cast' || doubleTapAction === 'cast'
        ? html`
                <div class="form-row">
                  <ha-entity-picker
                    .hass=${this.hass}
                    .value=${this._config.default_cast_device}
                    .includeDomains=${['media_player']}
                    @value-changed=${this._defaultCastDeviceChanged}
                  ></ha-entity-picker>
                </div>
              `
        : html`<div></div>`}
        </div>

        ${clickAction === 'cast' || holdAction === 'cast' || doubleTapAction === 'cast'
        ? html`
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

    <div class="checkbox-row">
      <ha-switch
        .checked=${this._config.show_search === true}
        @change=${this._showSearchChanged}
      ></ha-switch>
      <span>${localize(lang, 'editor.show_search')}</span>
    </div>

    <div class="side-by-side">
      <div class="form-row">
        <ha-selector
          .hass=${this.hass}
          .selector=${{
            select: {
              mode: 'dropdown',
              options: [
                { value: 'below', label: localize(lang, 'editor.metadata_below') },
                { value: 'above', label: localize(lang, 'editor.metadata_above') },
              ],
            },
          }}
          .value=${this._config.metadata_position || 'below'}
          .label=${localize(lang, 'editor.metadata_position')}
          label="${localize(lang, 'editor.metadata_position')}"
          @value-changed=${this._metadataPositionChanged}
        ></ha-selector>
      </div>

      <div class="form-row">
        ${this._config.media_type !== 'next_up'
        ? html`
            <ha-selector
              .hass=${this.hass}
              .selector=${{
                select: {
                  mode: 'dropdown',
                  options: [
                    { value: 'date_added_desc', label: localize(lang, 'editor.sort_date_added_desc') },
                    { value: 'date_added_asc', label: localize(lang, 'editor.sort_date_added_asc') },
                    { value: 'title_asc', label: localize(lang, 'editor.sort_title_asc') },
                    { value: 'title_desc', label: localize(lang, 'editor.sort_title_desc') },
                    { value: 'year_desc', label: localize(lang, 'editor.sort_year_desc') },
                    { value: 'year_asc', label: localize(lang, 'editor.sort_year_asc') },
                    { value: 'last_played_desc', label: localize(lang, 'editor.sort_last_played_desc') },
                    { value: 'last_played_asc', label: localize(lang, 'editor.sort_last_played_asc') },
                  ],
                },
              }}
              .value=${this._config.sort_option || 'date_added_desc'}
              .label=${localize(lang, 'editor.sort_order')}
              label="${localize(lang, 'editor.sort_order')}"
              @value-changed=${this._sortOptionChanged}
            ></ha-selector>
        `
        : html`<div></div>`}
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
      <ha-selector
        .hass=${this.hass}
        .selector=${{
          select: {
            mode: 'dropdown',
            options: [
              { value: 'all', label: localize(lang, 'editor.filter_all') },
              { value: 'unwatched', label: localize(lang, 'editor.filter_unwatched') },
              { value: 'watched', label: localize(lang, 'editor.filter_watched') },
            ],
          },
        }}
        .value=${this._config.status_filter || 'all'}
        .label=${localize(lang, 'editor.filter_watch_status')}
        label="${localize(lang, 'editor.filter_watch_status')}"
        @value-changed=${this._statusFilterChanged}
      ></ha-selector>
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

    ${this._config.media_type === 'next_up'
        ? html`
          <div class=\"checkbox-row\">
            <ha-switch
              .checked=${this._config.use_series_image === true}
              @change=${this._useSeriesImageChanged}
            ></ha-switch>
            <span>${localize(lang, 'editor.use_series_image')}</span>
          </div>
        `
        : ''}


  </div>
`;
  }

  private _entityChanged(e: CustomEvent): void {
    this._updateConfig('entity', e.detail.value);
  }

  private _titleChanged(e: CustomEvent): void {
    const value = e.detail?.value !== undefined ? e.detail.value : (e.target as any)?.value;
    this._updateConfig('title', value);
  }

  private _layoutChanged(e: CustomEvent): void {
    const value = e.detail?.value !== undefined ? e.detail.value : (e.target as any)?.value;
    if (value !== undefined) {
      this._updateConfig('layout', value);
    }
  }

  private _columnsChanged(e: CustomEvent): void {
    const raw = e.detail?.value !== undefined ? e.detail.value : (e.target as any)?.value;
    this._updateConfig('columns', Number(raw));
  }

  private _mediaTypeChanged(e: CustomEvent): void {
    const value = e.detail?.value !== undefined ? e.detail.value : (e.target as any)?.value;
    if (value !== undefined) {
      this._updateConfig('media_type', value);
    }
  }

  private _itemsPerPageChanged(e: CustomEvent): void {
    const raw = e.detail?.value !== undefined ? e.detail.value : (e.target as any)?.value;
    if (raw !== '' && raw !== null && raw !== undefined) {
      this._updateConfig('items_per_page', Number(raw));
    } else {
      this._updateConfig('items_per_page', null);
    }
  }

  private _maxPagesChanged(e: CustomEvent): void {
    const raw = e.detail?.value !== undefined ? e.detail.value : (e.target as any)?.value;
    if (raw === '' || raw === null || raw === undefined) {
      this._updateConfig('max_pages', null);
    } else {
      this._updateConfig('max_pages', Number(raw));
    }
  }

  private _autoSwipeIntervalChanged(e: CustomEvent): void {
    const raw = e.detail?.value !== undefined ? e.detail.value : (e.target as any)?.value;
    this._updateConfig('auto_swipe_interval', Number(raw || 0));
  }

  private _newBadgeDaysChanged(e: CustomEvent): void {
    const raw = e.detail?.value !== undefined ? e.detail.value : (e.target as any)?.value;
    if (raw === '' || raw === null || raw === undefined) {
      this._updateConfig('new_badge_days', null);
    } else {
      this._updateConfig('new_badge_days', Number(raw));
    }
  }

  private _clickActionChanged(e: CustomEvent): void {
    const value = e.detail?.value !== undefined ? e.detail.value : (e.target as any)?.value;
    if (value !== undefined) {
      this._updateConfig('click_action', value);
    }
  }

  private _holdActionChanged(e: CustomEvent): void {
    const value = e.detail?.value !== undefined ? e.detail.value : (e.target as any)?.value;
    if (value !== undefined) {
      this._updateConfig('hold_action', value);
    }
  }

  private _doubleTapActionChanged(e: CustomEvent): void {
    const value = e.detail?.value !== undefined ? e.detail.value : (e.target as any)?.value;
    if (value !== undefined) {
      this._updateConfig('double_tap_action', value);
    }
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

  private _metadataPositionChanged(e: CustomEvent): void {
    const value = e.detail?.value !== undefined ? e.detail.value : (e.target as any)?.value;
    if (value !== undefined) {
      this._updateConfig('metadata_position', value);
    }
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

  private _statusFilterChanged(e: CustomEvent): void {
    const value = e.detail?.value !== undefined ? e.detail.value : (e.target as any)?.value;
    if (value !== undefined) {
      this._updateConfig('status_filter', value);
    }
  }

  private _filterNewlyAddedChanged(e: Event): void {
    const target = e.target as HTMLInputElement;
    this._updateConfig('filter_newly_added', target.checked);
  }

  private _showSearchChanged(e: Event): void {
    const target = e.target as HTMLInputElement;
    this._updateConfig('show_search', target.checked);
  }

  private _sortOptionChanged(e: CustomEvent): void {
    const value = e.detail?.value !== undefined ? e.detail.value : (e.target as any)?.value;
    if (value !== undefined) {
      this._updateConfig('sort_option', value);
    }
  }

  private _useSeriesImageChanged(e: Event): void {
    const target = e.target as HTMLInputElement;
    this._updateConfig('use_series_image', target.checked);
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

