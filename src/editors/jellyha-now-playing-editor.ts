/**
 * Graphical editor for JellyHA Now Playing Card
 */

import { LitElement, html, TemplateResult, css } from 'lit';
import { customElement, property, state } from 'lit/decorators.js';
import { JellyHANowPlayingCardConfig, HomeAssistant } from '../shared/types';
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

@customElement('jellyha-now-playing-editor')
export class JellyHANowPlayingEditor extends LitElement {
  @property({ attribute: false }) hass!: HomeAssistant;
  @state() private _config!: JellyHANowPlayingCardConfig;

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
    .checkbox-pair {
      display: flex;
      gap: 16px;
      margin-bottom: 8px;
    }
    .checkbox-pair .checkbox-row {
      margin-bottom: 0;
      flex: 1;
    }
  `;

  public setConfig(config: JellyHANowPlayingCardConfig): void {
    this._config = config;
  }

  protected render(): TemplateResult {
    if (!this.hass || !this._config) {
      return html``;
    }

    // Available JellyHA entities: media_player (preferred) and legacy now playing sensors
    const mediaPlayers = Object.keys(this.hass.states).filter(
      (entity) =>
        entity.startsWith('media_player.jellyha_') &&
        !entity.includes('_library_browser') &&
        !entity.endsWith('_browser')
    );
    const legacySensors = Object.keys(this.hass.states).filter(
      (entity) =>
        entity.startsWith('sensor.jellyha_') &&
        entity.includes('now_playing')
    );

    const availableEntities = [
      ...mediaPlayers.map((e) => ({
        entity: e,
        label: `${this.hass.states[e]?.attributes.friendly_name || e} (Media Player)`,
      })),
      ...legacySensors.map((e) => ({
        entity: e,
        label: `${this.hass.states[e]?.attributes.friendly_name || e} (Legacy Sensor)`,
      })),
    ];

    // Ensure currently configured entity is always present
    if (this._config.entity && !availableEntities.some((e) => e.entity === this._config.entity)) {
      availableEntities.unshift({
        entity: this._config.entity,
        label: this.hass.states[this._config.entity]?.attributes.friendly_name || this._config.entity,
      });
    }

    const lang = this.hass.locale?.language || this.hass.language;
    const labelText = localize(lang, 'editor.media_player') || 'Media Player';

    return html`
      <div class="card-config">
        <div class="form-row">
          <ha-selector
            .hass=${this.hass}
            .selector=${{
              select: {
                mode: 'dropdown',
                custom_value: true,
                options: availableEntities.map((item) => ({
                  value: item.entity,
                  label: item.label,
                })),
              },
            }}
            .value=${this._config.entity || ''}
            .label=${labelText}
            label="${labelText}"
            @value-changed=${this._entityChanged}
          ></ha-selector>
        </div>

        <div class="form-row">
          <ha-selector
            .hass=${this.hass}
            .selector=${{ text: {} }}
            .value=${this._config.title || ''}
            .label="${localize(lang, 'editor.title')} (Optional)"
            label="${localize(lang, 'editor.title')} (Optional)"
            @value-changed=${this._titleChanged}
          ></ha-selector>
        </div>

        <div class="checkbox-pair">
          <div class="checkbox-row">
            <ha-switch
              .checked=${this._config.show_title !== false}
              @change=${this._showTitleChanged}
            ></ha-switch>
            <span>${localize(lang, 'editor.show_title')}</span>
          </div>
          <div class="checkbox-row">
            <ha-switch
              .checked=${this._config.show_subtitle !== false}
              @change=${this._showSubtitleChanged}
            ></ha-switch>
            <span>${localize(lang, 'editor.show_subtitle')}</span>
          </div>
        </div>

        <div class="checkbox-row">
          <ha-switch
            .checked=${this._config.show_media_type_badge !== false}
            @change=${this._showMediaTypeBadgeChanged}
          ></ha-switch>
          <span>${localize(lang, 'editor.show_media_type_badge')}</span>
        </div>

        <div class="checkbox-pair">
          <div class="checkbox-row">
            <ha-switch
              .checked=${this._config.show_year !== false}
              @change=${this._showYearChanged}
            ></ha-switch>
            <span>${localize(lang, 'editor.show_year')}</span>
          </div>
          <div class="checkbox-row">
            <ha-switch
              .checked=${this._config.show_genres === true}
              @change=${this._showGenresChanged}
            ></ha-switch>
            <span>${localize(lang, 'editor.show_genres')}</span>
          </div>
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
            .checked=${this._config.show_ratings === true}
            @change=${this._showRatingsChanged}
          ></ha-switch>
          <span>${localize(lang, 'editor.show_rating')}</span>
        </div>

        <div class="checkbox-pair">
          <div class="checkbox-row">
            <ha-switch
              .checked=${this._config.show_user !== false}
              @change=${this._showUserChanged}
            ></ha-switch>
            <span>${localize(lang, 'editor.show_user')}</span>
          </div>
          <div class="checkbox-row">
            <ha-switch
              .checked=${this._config.show_client !== false}
              @change=${this._showClientChanged}
            ></ha-switch>
            <span>${localize(lang, 'editor.show_client')}</span>
          </div>
        </div>

        <div class="checkbox-row">
          <ha-switch
            .checked=${this._config.show_time === true}
            @change=${this._showTimeChanged}
          ></ha-switch>
          <span>${localize(lang, 'editor.show_time')}</span>
        </div>

        <div class="checkbox-row">
          <ha-switch
            .checked=${this._config.show_background === true}
            @change=${this._showBackgroundChanged}
          ></ha-switch>
          <span>${localize(lang, 'editor.show_background')}</span>
        </div>

        <div class="checkbox-row">
          <ha-switch
            .checked=${this._config.use_series_image === true}
            @change=${this._useSeriesImageChanged}
          ></ha-switch>
          <span>${localize(lang, 'editor.use_series_image')}</span>
        </div>
      </div>
    `;
  }

  private _entityChanged(e: CustomEvent): void {
    const value = e.detail?.value !== undefined ? e.detail.value : (e.target as any)?.value;
    if (value !== undefined) {
      this._updateConfig('entity', value);
    }
  }

  private _titleChanged(e: CustomEvent): void {
    const value = e.detail?.value !== undefined ? e.detail.value : (e.target as any)?.value;
    this._updateConfig('title', value);
  }

  private _showTitleChanged(e: Event): void {
    const target = e.target as HTMLInputElement;
    this._updateConfig('show_title', target.checked);
  }

  private _showSubtitleChanged(e: Event): void {
    const target = e.target as HTMLInputElement;
    this._updateConfig('show_subtitle', target.checked);
  }

  private _showMediaTypeBadgeChanged(e: Event): void {
    const target = e.target as HTMLInputElement;
    this._updateConfig('show_media_type_badge', target.checked);
  }

  private _showYearChanged(e: Event): void {
    const target = e.target as HTMLInputElement;
    this._updateConfig('show_year', target.checked);
  }

  private _showGenresChanged(e: Event): void {
    const target = e.target as HTMLInputElement;
    this._updateConfig('show_genres', target.checked);
  }

  private _showRatingsChanged(e: Event): void {
    const target = e.target as HTMLInputElement;
    this._updateConfig('show_ratings', target.checked);
  }

  private _showRuntimeChanged(e: Event): void {
    const target = e.target as HTMLInputElement;
    this._updateConfig('show_runtime', target.checked);
  }

  private _showUserChanged(e: Event): void {
    const target = e.target as HTMLInputElement;
    this._updateConfig('show_user', target.checked);
  }

  private _showClientChanged(e: Event): void {
    const target = e.target as HTMLInputElement;
    this._updateConfig('show_client', target.checked);
  }

  private _showTimeChanged(e: Event): void {
    const target = e.target as HTMLInputElement;
    this._updateConfig('show_time', target.checked);
  }

  private _showBackgroundChanged(e: Event): void {
    const target = e.target as HTMLInputElement;
    this._updateConfig('show_background', target.checked);
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
    'jellyha-now-playing-editor': JellyHANowPlayingEditor;
  }
}
