/**
 * Graphical editor for JellyHA Now Playing Card
 */

import { LitElement, html, TemplateResult, css } from 'lit';
import { customElement, property, state } from 'lit/decorators.js';
import { JellyHANowPlayingCardConfig, HomeAssistant } from '../shared/types';

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
  `;

  public setConfig(config: JellyHANowPlayingCardConfig): void {
    this._config = config;
  }

  protected render(): TemplateResult {
    if (!this.hass || !this._config) {
      return html``;
    }

    // Filter for JellyHA Now Playing sensors
    const nowPlayingSensors = Object.keys(this.hass.states).filter(
      (entity) => entity.startsWith('sensor.jellyha_now_playing_')
    );

    return html`
      <div class="card-config">
        <div class="form-row">
          <ha-select
            label="Now Playing Sensor"
            .value=${this._config.entity || ''}
            @selected=${this._entityChanged}
            @closed=${(e: Event) => e.stopPropagation()}
          >
            ${nowPlayingSensors.map(
      (entity) => html`
                <mwc-list-item .value=${entity}>
                  ${this.hass.states[entity].attributes.friendly_name || entity}
                </mwc-list-item>
              `
    )}
          </ha-select>
        </div>

        <div class="form-row">
          <ha-textfield
            label="Title (Optional)"
            .value=${this._config.title || ''}
            @input=${this._titleChanged}
          ></ha-textfield>
        </div>

        <div class="checkbox-row">
          <ha-switch
            .checked=${this._config.show_title !== false}
            @change=${this._showTitleChanged}
          ></ha-switch>
          <span>Show Title</span>
        </div>

        <div class="checkbox-row">
          <ha-switch
            .checked=${this._config.show_media_type_badge !== false}
            @change=${this._showMediaTypeBadgeChanged}
          ></ha-switch>
          <span>Show Media Type Badge</span>
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
            .checked=${this._config.show_runtime === true}
            @change=${this._showRuntimeChanged}
          ></ha-switch>
          <span>Show Runtime</span>
        </div>

        <div class="checkbox-row">
          <ha-switch
            .checked=${this._config.show_ratings === true}
            @change=${this._showRatingsChanged}
          ></ha-switch>
          <span>Show Rating</span>
        </div>

        <div class="checkbox-row">
          <ha-switch
            .checked=${this._config.show_genres === true}
            @change=${this._showGenresChanged}
          ></ha-switch>
          <span>Show Genre</span>
        </div>

        <div class="checkbox-row">
          <ha-switch
            .checked=${this._config.show_client !== false}
            @change=${this._showClientChanged}
          ></ha-switch>
          <span>Show Jellyfin Client</span>
        </div>

        <div class="checkbox-row">
          <ha-switch
            .checked=${this._config.show_background === true}
            @change=${this._showBackgroundChanged}
          ></ha-switch>
          <span>Show Background</span>
        </div>
      </div>
    `;
  }

  private _entityChanged(e: Event): void {
    const target = e.target as HTMLSelectElement;
    this._updateConfig('entity', target.value);
  }

  private _titleChanged(e: Event): void {
    const target = e.target as HTMLInputElement;
    this._updateConfig('title', target.value);
  }

  private _showTitleChanged(e: Event): void {
    const target = e.target as HTMLInputElement;
    this._updateConfig('show_title', target.checked);
  }

  private _showMediaTypeBadgeChanged(e: Event): void {
    const target = e.target as HTMLInputElement;
    this._updateConfig('show_media_type_badge', target.checked);
  }

  private _showRatingsChanged(e: Event): void {
    const target = e.target as HTMLInputElement;
    this._updateConfig('show_ratings', target.checked);
  }

  private _showRuntimeChanged(e: Event): void {
    const target = e.target as HTMLInputElement;
    this._updateConfig('show_runtime', target.checked);
  }

  private _showGenresChanged(e: Event): void {
    const target = e.target as HTMLInputElement;
    this._updateConfig('show_genres', target.checked);
  }

  private _showYearChanged(e: Event): void {
    const target = e.target as HTMLInputElement;
    this._updateConfig('show_year', target.checked);
  }

  private _showClientChanged(e: Event): void {
    const target = e.target as HTMLInputElement;
    this._updateConfig('show_client', target.checked);
  }

  private _showBackgroundChanged(e: Event): void {
    const target = e.target as HTMLInputElement;
    this._updateConfig('show_background', target.checked);
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
