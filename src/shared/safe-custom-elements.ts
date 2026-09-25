/**
 * JellyHA Safe Custom Elements Registration Guard
 * 
 * In Home Assistant's SPA (Single Page Application), when Lovelace resources are updated
 * or cache-busted (e.g. ?v=1.4.1.x), the browser loads the new module into an existing
 * window context where custom element tags are already registered.
 * 
 * Calling customElements.define() with an existing tag name throws a fatal:
 * "Failed to execute 'define' on 'CustomElementRegistry': the name '...' has already been used"
 * 
 * This guard ensures that duplicate define() calls on existing tag names exit cleanly
 * without throwing an uncaught exception.
 */

if (typeof window !== 'undefined' && typeof window.customElements !== 'undefined') {
  const ce = window.customElements;
  if (!(ce.define as any).__jellyha_safe) {
    const origDefine = ce.define.bind(ce);
    const safeDefine = function (name: string, constructor: CustomElementConstructor, options?: ElementDefinitionOptions): void {
      if (name.startsWith('jellyha-')) {
        if (ce.get(name)) {
          return;
        }
      }
      return origDefine(name, constructor, options);
    };
    (safeDefine as any).__jellyha_safe = true;
    ce.define = safeDefine;
  }
}
