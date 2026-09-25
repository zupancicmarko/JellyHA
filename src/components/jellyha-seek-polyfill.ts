/**
 * JellyHA Browser Media Player Seek Polyfill
 * 
 * In Home Assistant versions prior to 2026.10 (specifically 2026.9.x), the built-in
 * ha-bar-media-player has an upstream bug:
 * 1. It hardcodes `?disabled=${isBrowser || !supportsFeature(stateObj, MediaPlayerEntityFeature.SEEK)}`
 *    which causes the progress slider to be permanently disabled/grayed out for the "Web browser" player.
 * 2. It hardcodes `if (this.entityId === BROWSER_PLAYER) return;` in `_handleMediaSeekChanged`,
 *    dropping all seek requests when playing via the browser.
 * 3. BrowserMediaPlayer.toStateObj() omits MediaPlayerEntityFeature.SEEK from supported_features.
 * 
 * This polyfill patches `ha-bar-media-player` and `BrowserMediaPlayer` to enable full seek functionality
 * in Home Assistant's Media Browser panel when streaming audio from JellyHA.
 */

function fixSlider(inst: any): void {
    const root = inst.shadowRoot;
    if (!root) return;

    const slider = root.querySelector('.progress-slider') as any;
    if (!slider) return;

    // 1. Un-disable the slider element
    if (slider.hasAttribute('disabled') || slider.disabled) {
        slider.removeAttribute('disabled');
        slider.disabled = false;
    }
    slider.style.pointerEvents = 'auto';
    slider.style.cursor = 'pointer';

    // 2. Un-disable any internal shadow elements (webawesome / material slider)
    if (slider.shadowRoot) {
        const innerDisabled = slider.shadowRoot.querySelectorAll('[disabled]');
        innerDisabled.forEach((el: any) => {
            el.removeAttribute('disabled');
            el.disabled = false;
        });
        const innerSlider = slider.shadowRoot.querySelector('#slider');
        if (innerSlider && innerSlider.classList.contains('disabled')) {
            innerSlider.classList.remove('disabled');
        }
    }

    // 3. Set max duration from browser player
    const player = inst._browserPlayer?.player;
    if (player && Number.isFinite(player.duration) && player.duration > 0) {
        slider.max = player.duration;
    }

    // 4. Ensure BrowserMediaPlayer prototype has .seek()
    if (inst._browserPlayer) {
        const bmpCls = inst._browserPlayer.constructor;
        if (bmpCls && !bmpCls.prototype.seek) {
            bmpCls.prototype.seek = function (pos: number) {
                if (this.player) {
                    this.player.currentTime = pos;
                }
            };
        }
    }

    // 5. Setup MutationObserver to immediately strip disabled if Lit re-renders
    if (!slider._jellyhaObserver) {
        const obs = new MutationObserver((mutations) => {
            for (const m of mutations) {
                if (m.type === 'attributes' && m.attributeName === 'disabled') {
                    if (slider.hasAttribute('disabled')) {
                        slider.removeAttribute('disabled');
                        slider.disabled = false;
                    }
                    if (slider.shadowRoot) {
                        const inner = slider.shadowRoot.querySelector('#slider');
                        if (inner && inner.classList.contains('disabled')) {
                            inner.classList.remove('disabled');
                        }
                    }
                }
            }
        });
        obs.observe(slider, { attributes: true, attributeFilter: ['disabled'] });
        slider._jellyhaObserver = obs;
    }

    // 6. Attach drag and seek events
    if (!slider._jellyhaEventsAttached) {
        slider._jellyhaEventsAttached = true;
        let isDragging = false;
        slider._isJellyHaDragging = () => isDragging;

        const onDragStart = () => {
            isDragging = true;
        };

        const onDragEnd = (e: any) => {
            if (!isDragging) return;
            isDragging = false;
            const targetVal = Number(e.detail?.value ?? slider.value ?? e.target?.value);
            if (Number.isFinite(targetVal) && inst._browserPlayer?.player) {
                inst._browserPlayer.player.currentTime = targetVal;
            }
        };

        slider.addEventListener('pointerdown', onDragStart, { passive: true });
        slider.addEventListener('touchstart', onDragStart, { passive: true });
        slider.addEventListener('mousedown', onDragStart, { passive: true });

        slider.addEventListener('pointerup', onDragEnd, { passive: true });
        slider.addEventListener('touchend', onDragEnd, { passive: true });
        slider.addEventListener('mouseup', onDragEnd, { passive: true });

        slider.addEventListener('change', (e: any) => {
            const targetVal = Number(e.detail?.value ?? slider.value ?? e.target?.value);
            if (Number.isFinite(targetVal) && inst._browserPlayer?.player) {
                inst._browserPlayer.player.currentTime = targetVal;
            }
        });

        slider.addEventListener('click', (e: any) => {
            queueMicrotask(() => {
                const targetVal = Number(slider.value ?? e.detail?.value ?? e.target?.value);
                if (Number.isFinite(targetVal) && inst._browserPlayer?.player) {
                    inst._browserPlayer.player.currentTime = targetVal;
                }
            });
        });

        slider.addEventListener('input', (e: any) => {
            const targetVal = Number(e.detail?.value ?? slider.value ?? e.target?.value);
            if (Number.isFinite(targetVal)) {
                const curr = inst.shadowRoot?.querySelector('#CurrentProgress');
                if (curr) {
                    const mins = Math.floor(targetVal / 60);
                    const secs = Math.floor(targetVal % 60);
                    curr.innerHTML = `${mins}:${secs < 10 ? '0' : ''}${secs}`;
                }
            }
        });
    }
}

function patchBarMediaPlayer(Cls: any): void {
    if (!Cls || Cls._jellyhaSeekPatched) return;
    Cls._jellyhaSeekPatched = true;

    // A. Patch _handleMediaSeekChanged
    const origSeek = Cls.prototype._handleMediaSeekChanged;
    Cls.prototype._handleMediaSeekChanged = function (e: any) {
        if (this.entityId === 'browser' && this._browserPlayer?.player) {
            const targetVal = Number(e.detail?.value ?? e.target?.value);
            if (Number.isFinite(targetVal)) {
                this._browserPlayer.player.currentTime = targetVal;
                if (this._currentProgress) {
                    const mins = Math.floor(targetVal / 60);
                    const secs = Math.floor(targetVal % 60);
                    this._currentProgress.innerHTML = `${mins}:${secs < 10 ? '0' : ''}${secs}`;
                }
            }
            return;
        }
        if (origSeek) {
            origSeek.call(this, e);
        }
    };

    // B. Patch _stateObj getter to include MediaPlayerEntityFeature.SEEK (2)
    const stateObjDesc = Object.getOwnPropertyDescriptor(Cls.prototype, '_stateObj');
    if (stateObjDesc && stateObjDesc.get) {
        const origGetStateObj = stateObjDesc.get;
        Object.defineProperty(Cls.prototype, '_stateObj', {
            get() {
                const stateObj = origGetStateObj.call(this);
                if (this.entityId === 'browser' && stateObj) {
                    if (!stateObj.attributes) stateObj.attributes = {};
                    stateObj.attributes.supported_features = (stateObj.attributes.supported_features || 0) | 2;
                }
                return stateObj;
            },
            configurable: true,
            enumerable: true,
        });
    }

    // C. Patch _updateProgressBar to prevent overwriting value during user drag
    const origUpdateProgress = Cls.prototype._updateProgressBar;
    Cls.prototype._updateProgressBar = function () {
        const slider = this._progressBar as any;
        if (slider?._isJellyHaDragging && slider._isJellyHaDragging()) {
            return;
        }
        if (origUpdateProgress) {
            origUpdateProgress.call(this);
        }
        if (this.entityId === 'browser') {
            fixSlider(this);
        }
    };

    // D. Patch updated() to un-disable slider after Lit renders
    const origUpdated = Cls.prototype.updated;
    Cls.prototype.updated = function (changedProps: any) {
        if (origUpdated) {
            origUpdated.call(this, changedProps);
        }
        if (this.entityId === 'browser') {
            fixSlider(this);
        }
    };

    // E. Patch render() to schedule slider fix immediately after render
    const origRender = Cls.prototype.render;
    if (origRender) {
        Cls.prototype.render = function () {
            const res = origRender.call(this);
            if (this.entityId === 'browser') {
                queueMicrotask(() => fixSlider(this));
                requestAnimationFrame(() => fixSlider(this));
            }
            return res;
        };
    }

    // F. Patch _progressBar getter so accessing _progressBar automatically fixes slider
    const progressBarDesc = Object.getOwnPropertyDescriptor(Cls.prototype, '_progressBar');
    if (progressBarDesc && progressBarDesc.get) {
        const origProgressBarGetter = progressBarDesc.get;
        Object.defineProperty(Cls.prototype, '_progressBar', {
            get() {
                const slider = origProgressBarGetter.call(this);
                if (this.entityId === 'browser' && slider) {
                    fixSlider(this);
                }
                return slider;
            },
            configurable: true,
            enumerable: true,
        });
    }

    console.info('JellyHA: Successfully installed ha-bar-media-player seek polyfill.');
}

// Intercept customElements registration safely
const existing = customElements.get('ha-bar-media-player');
if (existing) {
    patchBarMediaPlayer(existing);
} else {
    customElements.whenDefined('ha-bar-media-player').then(() => {
        const el = customElements.get('ha-bar-media-player');
        if (el) patchBarMediaPlayer(el);
    });

    if (!(customElements.define as any).__jellyha_bar_patched) {
        // Take define and get from the same registry. If this runs before HA's scoped
        // custom element registry polyfill (es5 build, or a cached reload on the modern
        // build), the polyfill picks up this wrapper as its "native" define and replaces
        // window.customElements with its own registry. A lazy customElements.get() would
        // then see the polyfill's registry, which already has the name, and the native
        // define would never run.
        const registry = customElements;
        const origDefine = registry.define.bind(registry);
        const origGet = registry.get.bind(registry);
        const patchedDefine = function (name: string, constructor: any, options?: ElementDefinitionOptions) {
            // Strictly guard: pass through immediately for any tag that is not ha-bar-media-player
            if (name !== 'ha-bar-media-player') {
                return origDefine(name, constructor, options);
            }
            if (origGet(name)) {
                patchBarMediaPlayer(constructor);
                return;
            }
            origDefine(name, constructor, options);
            patchBarMediaPlayer(constructor);
        };
        (patchedDefine as any).__jellyha_bar_patched = true;
        customElements.define = patchedDefine;
    }
}

// Periodic check for any existing DOM instance
function scanAndFix(): void {
    const bars = document.querySelectorAll('ha-bar-media-player');
    bars.forEach((bar: any) => {
        if (bar.entityId === 'browser') {
            fixSlider(bar);
        }
    });
}

if (typeof window !== 'undefined') {
    window.addEventListener('location-changed', () => setTimeout(scanAndFix, 150));
    window.addEventListener('popstate', () => setTimeout(scanAndFix, 150));
}
