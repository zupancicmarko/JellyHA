/**
 * JellyHA Safe Custom Elements Registration Guard & Scoped Registry Sync
 * 
 * 1. Duplicate Define Prevention (SPA Reloads):
 * In Home Assistant's SPA, when Lovelace resources are updated or cache-busted,
 * the browser loads new code into an existing window where tags may already be defined.
 * Duplicate define() calls throw a fatal DOMException unless guarded.
 * 
 * 2. Scoped Custom Element Registry Polyfill Sync (HA 2026.10+ & Modern Core Builds):
 * When JellyHA is injected early via add_extra_js_url, it may evaluate before HA's core app.js.
 * Shortly thereafter, app.js replaces window.customElements with a new ScopedCustomElementRegistry
 * polyfill instance (with empty internal maps). If elements were registered on the native registry
 * prior to this replacement, customElements.get('jellyha-...') returns undefined in Lovelace,
 * causing "Custom element doesn't exist: jellyha-library-card".
 * 
 * This module tracks all defined jellyha-* elements and automatically re-synchronizes them
 * whenever window.customElements is replaced or when Home Assistant finishes frontend bootstrap.
 */

interface ElementRegistration {
  constructor: CustomElementConstructor;
  options?: ElementDefinitionOptions;
}

if (typeof window !== 'undefined') {
  // Use a window-level cache so even multiple script evaluations share registrations
  const win = window as any;
  win.__jellyha_element_cache = win.__jellyha_element_cache || new Map<string, ElementRegistration>();
  const cache: Map<string, ElementRegistration> = win.__jellyha_element_cache;

  /**
   * Synchronize all cached JellyHA custom elements onto the given registry.
   */
  const syncRegistry = (target: CustomElementRegistry | undefined): void => {
    if (!target || typeof target.define !== 'function' || typeof target.get !== 'function') {
      return;
    }
    for (const [name, record] of cache.entries()) {
      if (!target.get(name)) {
        try {
          target.define(name, record.constructor, record.options);
        } catch {
          // Native registry may throw if already registered there; safe to ignore
        }
      }
    }
  };

  /**
   * Wrap a CustomElementRegistry instance with JellyHA guards.
   */
  const wrapRegistry = (reg: CustomElementRegistry | undefined): void => {
    if (!reg || (reg as any).__jellyha_wrapped) {
      return;
    }
    (reg as any).__jellyha_wrapped = true;

    const origDefine = reg.define.bind(reg);
    const origGet = reg.get.bind(reg);

    reg.define = function (name: string, constructor: CustomElementConstructor, options?: ElementDefinitionOptions): void {
      if (typeof name === 'string' && name.startsWith('jellyha-')) {
        cache.set(name.toLowerCase(), { constructor, options });
        if (origGet(name)) {
          return;
        }
      }
      return origDefine(name, constructor, options);
    };

    reg.get = function (name: string): CustomElementConstructor | undefined {
      const existing = origGet(name);
      if (existing) {
        return existing;
      }
      if (typeof name === 'string' && name.startsWith('jellyha-')) {
        const cached = cache.get(name.toLowerCase());
        if (cached) {
          try {
            origDefine(name, cached.constructor, cached.options);
          } catch {
            // Safe to ignore if already defined
          }
          return origGet(name) || cached.constructor;
        }
      }
      return undefined;
    };
  };

  // 1. Wrap the initial customElements registry (if available)
  if (typeof window.customElements !== 'undefined') {
    wrapRegistry(window.customElements);
  }

  // 2. Intercept Object.defineProperty on window to catch app.js replacing window.customElements
  if (!win.__jellyha_def_hooked) {
    win.__jellyha_def_hooked = true;
    const origDefineProperty = Object.defineProperty;
    Object.defineProperty = function (obj: any, prop: PropertyKey, descriptor: PropertyDescriptor): any {
      const result = origDefineProperty.call(Object, obj, prop, descriptor);
      if (obj === window && prop === 'customElements' && descriptor && descriptor.value) {
        wrapRegistry(descriptor.value);
        syncRegistry(descriptor.value);
      }
      return result;
    };
  }

  // 3. Listen for core Home Assistant element definitions as an async fallback
  const watchTags = ['home-assistant', 'hc-main'];
  watchTags.forEach((tag) => {
    if (typeof window.customElements !== 'undefined' && typeof window.customElements.whenDefined === 'function') {
      window.customElements.whenDefined(tag).then(() => {
        if (typeof window.customElements !== 'undefined') {
          wrapRegistry(window.customElements);
          syncRegistry(window.customElements);
        }
      }).catch(() => {});
    }
  });

  // 4. Fallback polling for the first few seconds after load to catch any unexpected registry reset
  [100, 500, 1500, 3000].forEach((delay) => {
    setTimeout(() => {
      if (typeof window.customElements !== 'undefined') {
        wrapRegistry(window.customElements);
        syncRegistry(window.customElements);
      }
    }, delay);
  });
}
