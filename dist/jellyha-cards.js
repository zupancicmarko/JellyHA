/**
 * @license
 * Copyright 2019 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const X = globalThis, K = X.ShadowRoot && (X.ShadyCSS === void 0 || X.ShadyCSS.nativeShadow) && "adoptedStyleSheets" in Document.prototype && "replace" in CSSStyleSheet.prototype, Z = Symbol(), st = /* @__PURE__ */ new WeakMap();
let _t = class {
  constructor(t, i, a) {
    if (this._$cssResult$ = !0, a !== Z) throw Error("CSSResult is not constructable. Use `unsafeCSS` or `css` instead.");
    this.cssText = t, this.t = i;
  }
  get styleSheet() {
    let t = this.o;
    const i = this.t;
    if (K && t === void 0) {
      const a = i !== void 0 && i.length === 1;
      a && (t = st.get(i)), t === void 0 && ((this.o = t = new CSSStyleSheet()).replaceSync(this.cssText), a && st.set(i, t));
    }
    return t;
  }
  toString() {
    return this.cssText;
  }
};
const $t = (e) => new _t(typeof e == "string" ? e : e + "", void 0, Z), N = (e, ...t) => {
  const i = e.length === 1 ? e[0] : t.reduce((a, o, s) => a + ((n) => {
    if (n._$cssResult$ === !0) return n.cssText;
    if (typeof n == "number") return n;
    throw Error("Value passed to 'css' function must be a 'css' function result: " + n + ". Use 'unsafeCSS' to pass non-literal values, but take care to ensure page security.");
  })(o) + e[s + 1], e[0]);
  return new _t(i, e, Z);
}, Ct = (e, t) => {
  if (K) e.adoptedStyleSheets = t.map((i) => i instanceof CSSStyleSheet ? i : i.styleSheet);
  else for (const i of t) {
    const a = document.createElement("style"), o = X.litNonce;
    o !== void 0 && a.setAttribute("nonce", o), a.textContent = i.cssText, e.appendChild(a);
  }
}, nt = K ? (e) => e : (e) => e instanceof CSSStyleSheet ? ((t) => {
  let i = "";
  for (const a of t.cssRules) i += a.cssText;
  return $t(i);
})(e) : e;
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const { is: kt, defineProperty: St, getOwnPropertyDescriptor: Pt, getOwnPropertyNames: At, getOwnPropertySymbols: jt, getPrototypeOf: Et } = Object, q = globalThis, rt = q.trustedTypes, Tt = rt ? rt.emptyScript : "", zt = q.reactiveElementPolyfillSupport, z = (e, t) => e, F = { toAttribute(e, t) {
  switch (t) {
    case Boolean:
      e = e ? Tt : null;
      break;
    case Object:
    case Array:
      e = e == null ? e : JSON.stringify(e);
  }
  return e;
}, fromAttribute(e, t) {
  let i = e;
  switch (t) {
    case Boolean:
      i = e !== null;
      break;
    case Number:
      i = e === null ? null : Number(e);
      break;
    case Object:
    case Array:
      try {
        i = JSON.parse(e);
      } catch {
        i = null;
      }
  }
  return i;
} }, Q = (e, t) => !kt(e, t), lt = { attribute: !0, type: String, converter: F, reflect: !1, useDefault: !1, hasChanged: Q };
Symbol.metadata ??= Symbol("metadata"), q.litPropertyMetadata ??= /* @__PURE__ */ new WeakMap();
let P = class extends HTMLElement {
  static addInitializer(t) {
    this._$Ei(), (this.l ??= []).push(t);
  }
  static get observedAttributes() {
    return this.finalize(), this._$Eh && [...this._$Eh.keys()];
  }
  static createProperty(t, i = lt) {
    if (i.state && (i.attribute = !1), this._$Ei(), this.prototype.hasOwnProperty(t) && ((i = Object.create(i)).wrapped = !0), this.elementProperties.set(t, i), !i.noAccessor) {
      const a = Symbol(), o = this.getPropertyDescriptor(t, a, i);
      o !== void 0 && St(this.prototype, t, o);
    }
  }
  static getPropertyDescriptor(t, i, a) {
    const { get: o, set: s } = Pt(this.prototype, t) ?? { get() {
      return this[i];
    }, set(n) {
      this[i] = n;
    } };
    return { get: o, set(n) {
      const d = o?.call(this);
      s?.call(this, n), this.requestUpdate(t, d, a);
    }, configurable: !0, enumerable: !0 };
  }
  static getPropertyOptions(t) {
    return this.elementProperties.get(t) ?? lt;
  }
  static _$Ei() {
    if (this.hasOwnProperty(z("elementProperties"))) return;
    const t = Et(this);
    t.finalize(), t.l !== void 0 && (this.l = [...t.l]), this.elementProperties = new Map(t.elementProperties);
  }
  static finalize() {
    if (this.hasOwnProperty(z("finalized"))) return;
    if (this.finalized = !0, this._$Ei(), this.hasOwnProperty(z("properties"))) {
      const i = this.properties, a = [...At(i), ...jt(i)];
      for (const o of a) this.createProperty(o, i[o]);
    }
    const t = this[Symbol.metadata];
    if (t !== null) {
      const i = litPropertyMetadata.get(t);
      if (i !== void 0) for (const [a, o] of i) this.elementProperties.set(a, o);
    }
    this._$Eh = /* @__PURE__ */ new Map();
    for (const [i, a] of this.elementProperties) {
      const o = this._$Eu(i, a);
      o !== void 0 && this._$Eh.set(o, i);
    }
    this.elementStyles = this.finalizeStyles(this.styles);
  }
  static finalizeStyles(t) {
    const i = [];
    if (Array.isArray(t)) {
      const a = new Set(t.flat(1 / 0).reverse());
      for (const o of a) i.unshift(nt(o));
    } else t !== void 0 && i.push(nt(t));
    return i;
  }
  static _$Eu(t, i) {
    const a = i.attribute;
    return a === !1 ? void 0 : typeof a == "string" ? a : typeof t == "string" ? t.toLowerCase() : void 0;
  }
  constructor() {
    super(), this._$Ep = void 0, this.isUpdatePending = !1, this.hasUpdated = !1, this._$Em = null, this._$Ev();
  }
  _$Ev() {
    this._$ES = new Promise((t) => this.enableUpdating = t), this._$AL = /* @__PURE__ */ new Map(), this._$E_(), this.requestUpdate(), this.constructor.l?.forEach((t) => t(this));
  }
  addController(t) {
    (this._$EO ??= /* @__PURE__ */ new Set()).add(t), this.renderRoot !== void 0 && this.isConnected && t.hostConnected?.();
  }
  removeController(t) {
    this._$EO?.delete(t);
  }
  _$E_() {
    const t = /* @__PURE__ */ new Map(), i = this.constructor.elementProperties;
    for (const a of i.keys()) this.hasOwnProperty(a) && (t.set(a, this[a]), delete this[a]);
    t.size > 0 && (this._$Ep = t);
  }
  createRenderRoot() {
    const t = this.shadowRoot ?? this.attachShadow(this.constructor.shadowRootOptions);
    return Ct(t, this.constructor.elementStyles), t;
  }
  connectedCallback() {
    this.renderRoot ??= this.createRenderRoot(), this.enableUpdating(!0), this._$EO?.forEach((t) => t.hostConnected?.());
  }
  enableUpdating(t) {
  }
  disconnectedCallback() {
    this._$EO?.forEach((t) => t.hostDisconnected?.());
  }
  attributeChangedCallback(t, i, a) {
    this._$AK(t, a);
  }
  _$ET(t, i) {
    const a = this.constructor.elementProperties.get(t), o = this.constructor._$Eu(t, a);
    if (o !== void 0 && a.reflect === !0) {
      const s = (a.converter?.toAttribute !== void 0 ? a.converter : F).toAttribute(i, a.type);
      this._$Em = t, s == null ? this.removeAttribute(o) : this.setAttribute(o, s), this._$Em = null;
    }
  }
  _$AK(t, i) {
    const a = this.constructor, o = a._$Eh.get(t);
    if (o !== void 0 && this._$Em !== o) {
      const s = a.getPropertyOptions(o), n = typeof s.converter == "function" ? { fromAttribute: s.converter } : s.converter?.fromAttribute !== void 0 ? s.converter : F;
      this._$Em = o;
      const d = n.fromAttribute(i, s.type);
      this[o] = d ?? this._$Ej?.get(o) ?? d, this._$Em = null;
    }
  }
  requestUpdate(t, i, a, o = !1, s) {
    if (t !== void 0) {
      const n = this.constructor;
      if (o === !1 && (s = this[t]), a ??= n.getPropertyOptions(t), !((a.hasChanged ?? Q)(s, i) || a.useDefault && a.reflect && s === this._$Ej?.get(t) && !this.hasAttribute(n._$Eu(t, a)))) return;
      this.C(t, i, a);
    }
    this.isUpdatePending === !1 && (this._$ES = this._$EP());
  }
  C(t, i, { useDefault: a, reflect: o, wrapped: s }, n) {
    a && !(this._$Ej ??= /* @__PURE__ */ new Map()).has(t) && (this._$Ej.set(t, n ?? i ?? this[t]), s !== !0 || n !== void 0) || (this._$AL.has(t) || (this.hasUpdated || a || (i = void 0), this._$AL.set(t, i)), o === !0 && this._$Em !== t && (this._$Eq ??= /* @__PURE__ */ new Set()).add(t));
  }
  async _$EP() {
    this.isUpdatePending = !0;
    try {
      await this._$ES;
    } catch (i) {
      Promise.reject(i);
    }
    const t = this.scheduleUpdate();
    return t != null && await t, !this.isUpdatePending;
  }
  scheduleUpdate() {
    return this.performUpdate();
  }
  performUpdate() {
    if (!this.isUpdatePending) return;
    if (!this.hasUpdated) {
      if (this.renderRoot ??= this.createRenderRoot(), this._$Ep) {
        for (const [o, s] of this._$Ep) this[o] = s;
        this._$Ep = void 0;
      }
      const a = this.constructor.elementProperties;
      if (a.size > 0) for (const [o, s] of a) {
        const { wrapped: n } = s, d = this[o];
        n !== !0 || this._$AL.has(o) || d === void 0 || this.C(o, void 0, s, d);
      }
    }
    let t = !1;
    const i = this._$AL;
    try {
      t = this.shouldUpdate(i), t ? (this.willUpdate(i), this._$EO?.forEach((a) => a.hostUpdate?.()), this.update(i)) : this._$EM();
    } catch (a) {
      throw t = !1, this._$EM(), a;
    }
    t && this._$AE(i);
  }
  willUpdate(t) {
  }
  _$AE(t) {
    this._$EO?.forEach((i) => i.hostUpdated?.()), this.hasUpdated || (this.hasUpdated = !0, this.firstUpdated(t)), this.updated(t);
  }
  _$EM() {
    this._$AL = /* @__PURE__ */ new Map(), this.isUpdatePending = !1;
  }
  get updateComplete() {
    return this.getUpdateComplete();
  }
  getUpdateComplete() {
    return this._$ES;
  }
  shouldUpdate(t) {
    return !0;
  }
  update(t) {
    this._$Eq &&= this._$Eq.forEach((i) => this._$ET(i, this[i])), this._$EM();
  }
  updated(t) {
  }
  firstUpdated(t) {
  }
};
P.elementStyles = [], P.shadowRootOptions = { mode: "open" }, P[z("elementProperties")] = /* @__PURE__ */ new Map(), P[z("finalized")] = /* @__PURE__ */ new Map(), zt?.({ ReactiveElement: P }), (q.reactiveElementVersions ??= []).push("2.1.2");
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const tt = globalThis, ct = (e) => e, Y = tt.trustedTypes, dt = Y ? Y.createPolicy("lit-html", { createHTML: (e) => e }) : void 0, vt = "$lit$", b = `lit$${Math.random().toFixed(9).slice(2)}$`, wt = "?" + b, Mt = `<${wt}>`, C = document, M = () => C.createComment(""), D = (e) => e === null || typeof e != "object" && typeof e != "function", et = Array.isArray, Dt = (e) => et(e) || typeof e?.[Symbol.iterator] == "function", G = `[ 	
\f\r]`, T = /<(?:(!--|\/[^a-zA-Z])|(\/?[a-zA-Z][^>\s]*)|(\/?$))/g, ht = /-->/g, pt = />/g, x = RegExp(`>|${G}(?:([^\\s"'>=/]+)(${G}*=${G}*(?:[^ 	
\f\r"'\`<>=]|("|')|))|$)`, "g"), gt = /'/g, ut = /"/g, yt = /^(?:script|style|textarea|title)$/i, It = (e) => (t, ...i) => ({ _$litType$: e, strings: t, values: i }), r = It(1), A = Symbol.for("lit-noChange"), l = Symbol.for("lit-nothing"), ft = /* @__PURE__ */ new WeakMap(), $ = C.createTreeWalker(C, 129);
function bt(e, t) {
  if (!et(e) || !e.hasOwnProperty("raw")) throw Error("invalid template strings array");
  return dt !== void 0 ? dt.createHTML(t) : t;
}
const Ot = (e, t) => {
  const i = e.length - 1, a = [];
  let o, s = t === 2 ? "<svg>" : t === 3 ? "<math>" : "", n = T;
  for (let d = 0; d < i; d++) {
    const c = e[d];
    let p, g, h = -1, u = 0;
    for (; u < c.length && (n.lastIndex = u, g = n.exec(c), g !== null); ) u = n.lastIndex, n === T ? g[1] === "!--" ? n = ht : g[1] !== void 0 ? n = pt : g[2] !== void 0 ? (yt.test(g[2]) && (o = RegExp("</" + g[2], "g")), n = x) : g[3] !== void 0 && (n = x) : n === x ? g[0] === ">" ? (n = o ?? T, h = -1) : g[1] === void 0 ? h = -2 : (h = n.lastIndex - g[2].length, p = g[1], n = g[3] === void 0 ? x : g[3] === '"' ? ut : gt) : n === ut || n === gt ? n = x : n === ht || n === pt ? n = T : (n = x, o = void 0);
    const v = n === x && e[d + 1].startsWith("/>") ? " " : "";
    s += n === T ? c + Mt : h >= 0 ? (a.push(p), c.slice(0, h) + vt + c.slice(h) + b + v) : c + b + (h === -2 ? d : v);
  }
  return [bt(e, s + (e[i] || "<?>") + (t === 2 ? "</svg>" : t === 3 ? "</math>" : "")), a];
};
class I {
  constructor({ strings: t, _$litType$: i }, a) {
    let o;
    this.parts = [];
    let s = 0, n = 0;
    const d = t.length - 1, c = this.parts, [p, g] = Ot(t, i);
    if (this.el = I.createElement(p, a), $.currentNode = this.el.content, i === 2 || i === 3) {
      const h = this.el.content.firstChild;
      h.replaceWith(...h.childNodes);
    }
    for (; (o = $.nextNode()) !== null && c.length < d; ) {
      if (o.nodeType === 1) {
        if (o.hasAttributes()) for (const h of o.getAttributeNames()) if (h.endsWith(vt)) {
          const u = g[n++], v = o.getAttribute(h).split(b), W = /([.?@])?(.*)/.exec(u);
          c.push({ type: 1, index: s, name: W[2], strings: v, ctor: W[1] === "." ? Nt : W[1] === "?" ? Ht : W[1] === "@" ? Ut : J }), o.removeAttribute(h);
        } else h.startsWith(b) && (c.push({ type: 6, index: s }), o.removeAttribute(h));
        if (yt.test(o.tagName)) {
          const h = o.textContent.split(b), u = h.length - 1;
          if (u > 0) {
            o.textContent = Y ? Y.emptyScript : "";
            for (let v = 0; v < u; v++) o.append(h[v], M()), $.nextNode(), c.push({ type: 2, index: ++s });
            o.append(h[u], M());
          }
        }
      } else if (o.nodeType === 8) if (o.data === wt) c.push({ type: 2, index: s });
      else {
        let h = -1;
        for (; (h = o.data.indexOf(b, h + 1)) !== -1; ) c.push({ type: 7, index: s }), h += b.length - 1;
      }
      s++;
    }
  }
  static createElement(t, i) {
    const a = C.createElement("template");
    return a.innerHTML = t, a;
  }
}
function j(e, t, i = e, a) {
  if (t === A) return t;
  let o = a !== void 0 ? i._$Co?.[a] : i._$Cl;
  const s = D(t) ? void 0 : t._$litDirective$;
  return o?.constructor !== s && (o?._$AO?.(!1), s === void 0 ? o = void 0 : (o = new s(e), o._$AT(e, i, a)), a !== void 0 ? (i._$Co ??= [])[a] = o : i._$Cl = o), o !== void 0 && (t = j(e, o._$AS(e, t.values), o, a)), t;
}
class Rt {
  constructor(t, i) {
    this._$AV = [], this._$AN = void 0, this._$AD = t, this._$AM = i;
  }
  get parentNode() {
    return this._$AM.parentNode;
  }
  get _$AU() {
    return this._$AM._$AU;
  }
  u(t) {
    const { el: { content: i }, parts: a } = this._$AD, o = (t?.creationScope ?? C).importNode(i, !0);
    $.currentNode = o;
    let s = $.nextNode(), n = 0, d = 0, c = a[0];
    for (; c !== void 0; ) {
      if (n === c.index) {
        let p;
        c.type === 2 ? p = new H(s, s.nextSibling, this, t) : c.type === 1 ? p = new c.ctor(s, c.name, c.strings, this, t) : c.type === 6 && (p = new Lt(s, this, t)), this._$AV.push(p), c = a[++d];
      }
      n !== c?.index && (s = $.nextNode(), n++);
    }
    return $.currentNode = C, o;
  }
  p(t) {
    let i = 0;
    for (const a of this._$AV) a !== void 0 && (a.strings !== void 0 ? (a._$AI(t, a, i), i += a.strings.length - 2) : a._$AI(t[i])), i++;
  }
}
class H {
  get _$AU() {
    return this._$AM?._$AU ?? this._$Cv;
  }
  constructor(t, i, a, o) {
    this.type = 2, this._$AH = l, this._$AN = void 0, this._$AA = t, this._$AB = i, this._$AM = a, this.options = o, this._$Cv = o?.isConnected ?? !0;
  }
  get parentNode() {
    let t = this._$AA.parentNode;
    const i = this._$AM;
    return i !== void 0 && t?.nodeType === 11 && (t = i.parentNode), t;
  }
  get startNode() {
    return this._$AA;
  }
  get endNode() {
    return this._$AB;
  }
  _$AI(t, i = this) {
    t = j(this, t, i), D(t) ? t === l || t == null || t === "" ? (this._$AH !== l && this._$AR(), this._$AH = l) : t !== this._$AH && t !== A && this._(t) : t._$litType$ !== void 0 ? this.$(t) : t.nodeType !== void 0 ? this.T(t) : Dt(t) ? this.k(t) : this._(t);
  }
  O(t) {
    return this._$AA.parentNode.insertBefore(t, this._$AB);
  }
  T(t) {
    this._$AH !== t && (this._$AR(), this._$AH = this.O(t));
  }
  _(t) {
    this._$AH !== l && D(this._$AH) ? this._$AA.nextSibling.data = t : this.T(C.createTextNode(t)), this._$AH = t;
  }
  $(t) {
    const { values: i, _$litType$: a } = t, o = typeof a == "number" ? this._$AC(t) : (a.el === void 0 && (a.el = I.createElement(bt(a.h, a.h[0]), this.options)), a);
    if (this._$AH?._$AD === o) this._$AH.p(i);
    else {
      const s = new Rt(o, this), n = s.u(this.options);
      s.p(i), this.T(n), this._$AH = s;
    }
  }
  _$AC(t) {
    let i = ft.get(t.strings);
    return i === void 0 && ft.set(t.strings, i = new I(t)), i;
  }
  k(t) {
    et(this._$AH) || (this._$AH = [], this._$AR());
    const i = this._$AH;
    let a, o = 0;
    for (const s of t) o === i.length ? i.push(a = new H(this.O(M()), this.O(M()), this, this.options)) : a = i[o], a._$AI(s), o++;
    o < i.length && (this._$AR(a && a._$AB.nextSibling, o), i.length = o);
  }
  _$AR(t = this._$AA.nextSibling, i) {
    for (this._$AP?.(!1, !0, i); t !== this._$AB; ) {
      const a = ct(t).nextSibling;
      ct(t).remove(), t = a;
    }
  }
  setConnected(t) {
    this._$AM === void 0 && (this._$Cv = t, this._$AP?.(t));
  }
}
class J {
  get tagName() {
    return this.element.tagName;
  }
  get _$AU() {
    return this._$AM._$AU;
  }
  constructor(t, i, a, o, s) {
    this.type = 1, this._$AH = l, this._$AN = void 0, this.element = t, this.name = i, this._$AM = o, this.options = s, a.length > 2 || a[0] !== "" || a[1] !== "" ? (this._$AH = Array(a.length - 1).fill(new String()), this.strings = a) : this._$AH = l;
  }
  _$AI(t, i = this, a, o) {
    const s = this.strings;
    let n = !1;
    if (s === void 0) t = j(this, t, i, 0), n = !D(t) || t !== this._$AH && t !== A, n && (this._$AH = t);
    else {
      const d = t;
      let c, p;
      for (t = s[0], c = 0; c < s.length - 1; c++) p = j(this, d[a + c], i, c), p === A && (p = this._$AH[c]), n ||= !D(p) || p !== this._$AH[c], p === l ? t = l : t !== l && (t += (p ?? "") + s[c + 1]), this._$AH[c] = p;
    }
    n && !o && this.j(t);
  }
  j(t) {
    t === l ? this.element.removeAttribute(this.name) : this.element.setAttribute(this.name, t ?? "");
  }
}
class Nt extends J {
  constructor() {
    super(...arguments), this.type = 3;
  }
  j(t) {
    this.element[this.name] = t === l ? void 0 : t;
  }
}
class Ht extends J {
  constructor() {
    super(...arguments), this.type = 4;
  }
  j(t) {
    this.element.toggleAttribute(this.name, !!t && t !== l);
  }
}
class Ut extends J {
  constructor(t, i, a, o, s) {
    super(t, i, a, o, s), this.type = 5;
  }
  _$AI(t, i = this) {
    if ((t = j(this, t, i, 0) ?? l) === A) return;
    const a = this._$AH, o = t === l && a !== l || t.capture !== a.capture || t.once !== a.once || t.passive !== a.passive, s = t !== l && (a === l || o);
    o && this.element.removeEventListener(this.name, this, a), s && this.element.addEventListener(this.name, this, t), this._$AH = t;
  }
  handleEvent(t) {
    typeof this._$AH == "function" ? this._$AH.call(this.options?.host ?? this.element, t) : this._$AH.handleEvent(t);
  }
}
class Lt {
  constructor(t, i, a) {
    this.element = t, this.type = 6, this._$AN = void 0, this._$AM = i, this.options = a;
  }
  get _$AU() {
    return this._$AM._$AU;
  }
  _$AI(t) {
    j(this, t);
  }
}
const Wt = tt.litHtmlPolyfillSupport;
Wt?.(I, H), (tt.litHtmlVersions ??= []).push("3.3.2");
const xt = (e, t, i) => {
  const a = i?.renderBefore ?? t;
  let o = a._$litPart$;
  if (o === void 0) {
    const s = i?.renderBefore ?? null;
    a._$litPart$ = o = new H(t.insertBefore(M(), s), s, void 0, i ?? {});
  }
  return o._$AI(e), o;
};
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const it = globalThis;
class w extends P {
  constructor() {
    super(...arguments), this.renderOptions = { host: this }, this._$Do = void 0;
  }
  createRenderRoot() {
    const t = super.createRenderRoot();
    return this.renderOptions.renderBefore ??= t.firstChild, t;
  }
  update(t) {
    const i = this.render();
    this.hasUpdated || (this.renderOptions.isConnected = this.isConnected), super.update(t), this._$Do = xt(i, this.renderRoot, this.renderOptions);
  }
  connectedCallback() {
    super.connectedCallback(), this._$Do?.setConnected(!0);
  }
  disconnectedCallback() {
    super.disconnectedCallback(), this._$Do?.setConnected(!1);
  }
  render() {
    return A;
  }
}
w._$litElement$ = !0, w.finalized = !0, it.litElementHydrateSupport?.({ LitElement: w });
const Bt = it.litElementPolyfillSupport;
Bt?.({ LitElement: w });
(it.litElementVersions ??= []).push("4.2.2");
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const U = (e) => (t, i) => {
  i !== void 0 ? i.addInitializer(() => {
    customElements.define(e, t);
  }) : customElements.define(e, t);
};
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const Xt = { attribute: !0, type: String, converter: F, reflect: !1, hasChanged: Q }, Ft = (e = Xt, t, i) => {
  const { kind: a, metadata: o } = i;
  let s = globalThis.litPropertyMetadata.get(o);
  if (s === void 0 && globalThis.litPropertyMetadata.set(o, s = /* @__PURE__ */ new Map()), a === "setter" && ((e = Object.create(e)).wrapped = !0), s.set(i.name, e), a === "accessor") {
    const { name: n } = i;
    return { set(d) {
      const c = t.get.call(this);
      t.set.call(this, d), this.requestUpdate(n, c, e, !0, d);
    }, init(d) {
      return d !== void 0 && this.C(n, void 0, e, d), d;
    } };
  }
  if (a === "setter") {
    const { name: n } = i;
    return function(d) {
      const c = this[n];
      t.call(this, d), this.requestUpdate(n, c, e, !0, d);
    };
  }
  throw Error("Unsupported decorator location: " + a);
};
function E(e) {
  return (t, i) => typeof i == "object" ? Ft(e, t, i) : ((a, o, s) => {
    const n = o.hasOwnProperty(s);
    return o.constructor.createProperty(s, a), n ? Object.getOwnPropertyDescriptor(o, s) : void 0;
  })(e, t, i);
}
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
function f(e) {
  return E({ ...e, state: !0, attribute: !1 });
}
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const Yt = (e, t, i) => (i.configurable = !0, i.enumerable = !0, Reflect.decorate && typeof t != "object" && Object.defineProperty(e, t, i), i);
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
function qt(e, t) {
  return (i, a, o) => {
    const s = (n) => n.renderRoot?.querySelector(e) ?? null;
    return Yt(i, a, { get() {
      return s(this);
    } });
  };
}
const Jt = N`
  :host {
    display: block;
    --jf-card-bg: var(--card-background-color, #1c1c1c);
    --jf-primary: var(--primary-color, #18BCF2);
    --jf-text: var(--primary-text-color, #fff);
    --jf-text-secondary: var(--secondary-text-color, rgba(255, 255, 255, 0.7));
    --jf-divider: var(--divider-color, rgba(255, 255, 255, 0.12));
    --jf-poster-radius: 10px;
    --jf-transition: 0s;
    --jf-movie-badge: #AA5CC3;
    --jf-series-badge: #F2A218;
    --jf-border-color: var(--divider-color, rgba(255, 255, 255, 0.15));
  }

  ha-card {
    background: var(--jf-card-bg);
    border-radius: 12px;
    /* overflow: hidden; Removed to allow modal to escape */
    position: relative;
    z-index: 0;
  }

  .card-inner {
    border-radius: 12px;
    overflow: hidden;
    position: relative;
    z-index: 0;
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

  /* Theme currently playing title */
  .media-item.playing .media-title,
  .media-item.playing .list-title {
    color: var(--jf-primary);
  }

  .card-content {
    padding: 0;
    padding-top: 12px;
    overflow: hidden;
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
    padding: 8px 16px 18px 16px; /* Extra bottom padding for shadow */
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
    background: var(--jf-divider);
    border: none;
    cursor: pointer;
    padding: 0;
    transition: background var(--jf-transition), transform var(--jf-transition);
    pointer-events: auto;
    z-index: 100;
  }

  .pagination-dot:hover {
    background: var(--jf-text-secondary);
  }

  .pagination-dot.active {
    background: var(--jf-primary);
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
    background: var(--jf-divider);
    transition: width 0.15s ease-out, background 0.15s ease-out, border-radius 0.15s ease-out;
  }

  /* Active dot */
  .scroll-dot.active {
    background: var(--jf-primary);
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
    padding: 8px 16px 18px 16px; /* Extra bottom padding for shadow */
    min-width: fit-content;
  }

  /* Auto-fill responsive grid when columns = 1 (Auto) */
  .grid.auto-columns {
    grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
    justify-items: center;
    justify-content: center;
  }

  /* List Wrapper for pagination */
  .list-wrapper {
    position: relative;
    overflow: hidden;
    touch-action: pan-y; /* Allow vertical scroll, handle horizontal swipe ourselves */
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

  .list .media-item {
    flex-direction: row;
    align-items: flex-start;
    gap: 16px;
  }

  .list .poster-container {
    width: 100px;
    min-width: 100px;
    height: 150px;
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
    border-radius: 6px;
    font-size: 0.7rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.3px;
    color: #fff;
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
  .list .hover-overlay {
    display: none;
  }

  /* Keep badges visible in list layout */
  .list .media-item:hover .rating,
  .list .media-item:hover .runtime {
    opacity: 1;
  }

  /* Emphasize metadata on hover */
  .list .media-item:hover .list-title {
    color: var(--jf-primary);
  }

  .list .media-item:hover .list-info {
    transform: translateX(2px);
    transition: transform 0.2s ease;
  }

  .list .media-item:hover .list-date-added {
    font-weight: 600;
  }

  /* Move date up when it's above poster */
  .list .media-item:hover .list-poster-wrapper .list-date-added:first-child {
    transform: translateY(-2px);
  }

  /* Move date down when it's below poster */
  .list .media-item:hover .list-poster-wrapper .list-date-added:last-child {
    transform: translateY(2px);
  }

  .list .media-item:hover .list-year,
  .list .media-item:hover .list-runtime,
  .list .media-item:hover .list-rating {
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
  .media-item.active-press .poster-container,
  .media-item:active .poster-container {
    transform: scale(0.96);
    transition: transform 0.1s ease-out;
  }

  /* Vignette overlay for list items on hover */
  .list .poster-inner::after {
    content: '';
    position: absolute;
    inset: 0;
    border-radius: var(--jf-poster-radius);
    background: radial-gradient(
      ellipse at center,
      transparent 50%,
      rgba(0, 0, 0, 0.4) 100%
    );
    opacity: 0;
    transition: opacity var(--jf-transition);
    pointer-events: none;
  }

  .list .media-item:hover .poster-inner::after {
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

  /* Media Type Badge (MOVIE/SERIES) - Top Left - matches new-badge style */
  .media-type-badge {
    position: absolute;
    top: 6px;
    left: 6px;
    padding: 2px 8px 1px 8px;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 800;
    text-transform: uppercase;
    letter-spacing: 0.3px;
    color: #fff;
    z-index: 5;
    box-shadow: 0 2px 4px rgba(0,0,0,0.3);
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
    background: var(--jf-primary);
    color: #fff;
    padding: 2px 8px 1px 8px;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 800;
    text-transform: uppercase;
    letter-spacing: 0.3px;
    z-index: 5;
    box-shadow: 0 2px 4px rgba(0,0,0,0.3);
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
    font-size: 0.75rem;
  }

  .status-badge.watched ha-icon {
    --mdc-icon-size: 14px;
    margin-top: -1px;
  }

  /* Unplayed Count - Theme Colored Badge */
  .status-badge.unplayed {
    padding: 2px 8px 1px 8px;
    border-radius: 4px;
    background: var(--jf-primary);
    color: #fff;
    font-size: 0.75rem;
    font-weight: 800;
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
    z-index: 4;
  }

  .media-item:hover .hover-overlay {
    opacity: 1;
  }

  .hover-overlay .overlay-year {
    font-size: 0.85rem;
    font-weight: 600;
    color: var(--jf-primary) !important;
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
    background: rgba(0, 0, 0, 0.2);
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
    color: white;
    font-weight: 700;
    font-size: 0.8rem;
    letter-spacing: 0.5px;
    background: var(--primary-color);
    padding: 2px 6px;
    border-radius: 4px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.3);
    transform: translateY(-8px);
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
    background: var(--jf-divider);
    border: none;
    cursor: pointer;
    padding: 0;
    transition: background var(--jf-transition), transform 0.3s ease, opacity 0.3s ease;
    pointer-events: auto;
    flex-shrink: 0;
  }

  .smart-dot:hover {
    background: var(--jf-text-secondary);
  }

  .smart-dot.active {
    background: var(--jf-primary);
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
`, B = {
  en: {
    loading: "Loading…",
    no_media: "No recent media found",
    error: "Error loading media",
    new: "New",
    minutes: "min"
  },
  de: {
    loading: "Laden…",
    no_media: "Keine neuen Medien gefunden",
    error: "Fehler beim Laden der Medien",
    new: "Neu",
    minutes: "Min"
  },
  fr: {
    loading: "Chargement…",
    no_media: "Aucun média récent trouvé",
    error: "Erreur lors du chargement des médias",
    new: "Nouveau",
    minutes: "min"
  },
  es: {
    loading: "Cargando…",
    no_media: "No se encontraron medios recientes",
    error: "Error al cargar medios",
    new: "Nuevo",
    minutes: "min"
  },
  it: {
    loading: "Caricamento…",
    no_media: "Nessun media recente trovato",
    error: "Errore durante il caricamento dei media",
    new: "Nuovo",
    minutes: "min"
  },
  nl: {
    loading: "Laden…",
    no_media: "Geen recente media gevonden",
    error: "Fout bij het laden van media",
    new: "Nieuw",
    minutes: "min"
  }
};
function V(e, t) {
  const i = e.split("-")[0].toLowerCase();
  return B[i]?.[t] ? B[i][t] : B.en?.[t] ? B.en[t] : t;
}
var Gt = Object.defineProperty, Vt = Object.getOwnPropertyDescriptor, S = (e, t, i, a) => {
  for (var o = a > 1 ? void 0 : a ? Vt(t, i) : t, s = e.length - 1, n; s >= 0; s--)
    (n = e[s]) && (o = (a ? n(t, i, o) : n(o)) || o);
  return a && o && Gt(t, i, o), o;
};
let y = class extends w {
  constructor() {
    super(...arguments), this._open = !1, this._confirmDelete = !1, this._portalContainer = null, this.closeDialog = () => {
      this._open = !1, this._confirmDelete = !1, this.dispatchEvent(new CustomEvent("closed", { bubbles: !0, composed: !0 })), this.requestUpdate();
    }, this._handlePlay = async () => {
      if (!this._item || !this._defaultCastDevice) {
        this._defaultCastDevice || alert("No default cast device configured.");
        return;
      }
      try {
        await this.hass.callService("jellyha", "play_on_chromecast", {
          entity_id: this._defaultCastDevice,
          item_id: this._item.id
        }), this.closeDialog();
      } catch (e) {
        console.error("Failed to cast", e);
      }
    }, this._playNextUp = async () => {
      if (!this._nextUpItem || !this._defaultCastDevice) {
        this._defaultCastDevice || alert("No default cast device configured.");
        return;
      }
      try {
        await this.hass.callService("jellyha", "play_on_chromecast", {
          entity_id: this._defaultCastDevice,
          item_id: this._nextUpItem.id
        }), this.closeDialog();
      } catch (e) {
        console.error("Failed to cast next up", e);
      }
    }, this._handleFavorite = async () => {
      if (!this._item) return;
      const e = !this._item.is_favorite;
      this._item = { ...this._item, is_favorite: e }, await this.hass.callService("jellyha", "update_favorite", {
        item_id: this._item.id,
        is_favorite: e
      }), this.requestUpdate();
    }, this._handleWatched = async () => {
      if (!this._item) return;
      const e = !this._item.is_played;
      this._item = { ...this._item, is_played: e }, await this.hass.callService("jellyha", "mark_watched", {
        item_id: this._item.id,
        is_played: e
      }), this.requestUpdate();
    }, this._handleDeleteConfirm = async () => {
      if (!this._item) return;
      const e = this._item.id;
      this.closeDialog(), await this.hass.callService("jellyha", "delete_item", {
        item_id: e
      });
    }, this._handleWatchTrailer = () => {
      const e = this._item;
      if (!e?.trailer_url) return;
      const t = e.trailer_url;
      let i = "";
      try {
        const a = new URL(t);
        a.hostname.includes("youtube.com") ? i = a.searchParams.get("v") || "" : a.hostname.includes("youtu.be") && (i = a.pathname.slice(1));
      } catch {
      }
      if (i) {
        const a = navigator.userAgent || navigator.vendor || window.opera, o = /android/i.test(a), s = /iPad|iPhone|iPod/.test(a) && !window.MSStream;
        if (o) {
          window.open(`vnd.youtube:${i}`, "_blank");
          return;
        }
        if (s) {
          window.open(`youtube://${i}`, "_blank");
          return;
        }
      }
      window.open(t, "_blank");
    };
  }
  connectedCallback() {
    super.connectedCallback(), this._portalContainer = document.createElement("div"), this._portalContainer.id = "jellyha-modal-portal", document.body.appendChild(this._portalContainer);
  }
  disconnectedCallback() {
    super.disconnectedCallback(), this._portalContainer && (this._portalContainer.remove(), this._portalContainer = null);
  }
  async showDialog(e) {
    this._item = e.item, this.hass = e.hass, this._defaultCastDevice = e.defaultCastDevice, this._open = !0, this._nextUpItem = void 0, this._item.type === "Series" && this._fetchNextUp(this._item), await this.updateComplete;
  }
  async _fetchNextUp(e) {
    const t = Object.keys(this.hass.states).filter(
      (a) => this.hass.states[a].attributes.integration === "jellyha" || a.startsWith("sensor.jellyha_")
      // Fallback convention
    ), i = t.length > 0 ? t[0] : "sensor.jellyha_library";
    try {
      const a = await this.hass.callWS({
        type: "jellyha/get_next_up",
        entity_id: i,
        series_id: e.id
      });
      a && a.item && (this._nextUpItem = a.item);
    } catch (a) {
      console.warn("Failed to fetch Next Up:", a);
    }
  }
  updated() {
    this._portalContainer && xt(this._renderDialogContent(), this._portalContainer);
  }
  render() {
    return r``;
  }
  _getPortalStyles() {
    return r`
        <style>
             ha-dialog {
                --mdc-dialog-z-index: 9999;
                --mdc-dialog-min-width: 400px;
                --mdc-dialog-max-width: 90vw;
             }

            .content {
                display: grid;
                grid-template-columns: 300px 1fr;
                gap: 24px;
            }

            .poster-col {
                display: flex;
                flex-direction: column;
                gap: 16px;
            }

            .poster-img {
                width: 100%;
                aspect-ratio: 2/3;
                object-fit: cover;
                border-radius: 12px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.3);
            }

            .actions-col {
                display: flex;
                flex-direction: row;
                gap: 0;
                justify-content: space-between;
                align-items: center;
                min-height: 44px; /* Maintain height for delete confirmation */
                width: 100%;
            }

            .details-col {
                display: flex;
                flex-direction: column;
                gap: 16px;
                overflow-y: auto;
                max-height: 60vh;
            }

            .header-group h1 {
                margin: 0;
                font-size: 2rem;
                font-weight: 700;
                line-height: 1.2;
                color: var(--primary-text-color);
            }

            .header-sub {
                display: flex;
                gap: 12px;
                align-items: center;
                margin-top: 8px;
                color: var(--secondary-text-color);
                font-size: 1rem;
            }

            .badge {
                padding: 4px 8px;
                border-radius: 6px;
                background: rgba(var(--rgb-primary-text-color), 0.1);
                font-size: 0.85rem;
                font-weight: 600;
                text-transform: uppercase;
            }

            .stats-row {
                display: flex;
                flex-wrap: wrap;
                gap: 16px;
                padding: 12px;
                border-radius: 8px;
                font-size: 0.95rem;
                background: var(--secondary-background-color, rgba(0,0,0,0.2));
            }

            .stat-item {
                display: flex;
                gap: 6px;
                align-items: center;
            }

            .description {
                font-size: 1rem;
                line-height: 1.6;
                color: var(--primary-text-color);
                white-space: pre-wrap;
            }

            .genres-list {
                display: flex;
                flex-wrap: wrap;
                gap: 8px;
            }

            .genre-tag {
                background: rgba(var(--rgb-primary-color), 0.15);
                color: var(--primary-color);
                padding: 4px 12px;
                border-radius: 16px;
                font-size: 0.85rem;
                border: 1px solid rgba(var(--rgb-primary-color), 0.3);
            }

            .divider {
                height: 1px;
                background: var(--divider-color);
                margin: 8px 0;
            }

            .media-info-grid {
                display: grid;
                grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
                gap: 12px;
                font-size: 0.85rem;
                color: var(--secondary-text-color);
            }

            .info-pair b {
                color: var(--primary-text-color);
                display: block;
                margin-bottom: 2px;
            }

            .action-btn {
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 10px;
                border-radius: 50%; /* Circle shape */
                border: none;
                cursor: pointer;
                background: transparent;
                color: var(--secondary-text-color);
                width: 44px;
                height: 44px;
                box-sizing: border-box;
                transition: background 0.2s, color 0.2s;
            }

            .action-btn:hover {
                background: rgba(255, 255, 255, 0.1);
                color: var(--primary-text-color);
            }

            .action-btn.active {
                color: var(--primary-color);
            }
            .favorite-btn.active {
                color: #F44336;
            }

            .action-btn ha-icon {
                --mdc-icon-size: 26px;
            }

            .btn-danger {
                color: var(--error-color, #f44336);
            }
            .btn-danger:hover {
                background: rgba(244, 67, 54, 0.15);
            }

            .confirmation-box {
                display: flex;
                gap: 12px;
                align-items: center;
                justify-content: center;
                width: 100%;
                background: rgba(244, 67, 54, 0.1);
                border-radius: 8px;
                padding: 4px 8px;
            }
            
            .confirm-btn {
                background: none;
                border: none;
                cursor: pointer;
                color: var(--primary-text-color);
                font-weight: 600;
                padding: 8px 16px;
                border-radius: 4px;
            }
            .confirm-btn:hover {
                 background: rgba(255,255,255,0.1);
            }
            .confirm-yes {
                color: var(--error-color);
            }



            /* Next Up Section */
            .next-up-card {
                background: rgba(0,0,0,0.2);
                border-radius: 12px;
                padding: 16px;
                display: flex;
                gap: 16px;
                align-items: center;
                margin-top: 16px;
                border: 1px solid var(--divider-color);
                cursor: pointer;
                transition: background 0.2s;
            }
            .next-up-card:hover {
                background: rgba(0,0,0,0.4);
            }
            .next-up-thumb {
                width: 120px;
                aspect-ratio: 16/9;
                object-fit: cover;
                border-radius: 8px;
            }
            .next-up-info {
                flex: 1;
                display: flex;
                flex-direction: column;
                gap: 4px;
            }
            .next-up-label {
                font-size: 0.75rem;
                text-transform: uppercase;
                letter-spacing: 0.5px;
                color: var(--primary-color);
                font-weight: 700;
            }
            .next-up-title {
                font-size: 1.1rem;
                font-weight: 600;
                color: var(--primary-text-color);
                margin: 0;
            }
            .next-up-meta {
                font-size: 0.9rem;
                color: var(--secondary-text-color);
            }

            @media (max-width: 600px) {
                .content { grid-template-columns: 1fr; }
                .poster-col { max-width: 350px; margin: 0 auto; width: 100%; }
            }
        </style>
        `;
  }
  _renderDialogContent() {
    if (!this._open || !this._item) return r``;
    const e = this._item, t = e.type === "Series", i = e.year || (e.date_added ? new Date(e.date_added).getFullYear() : "");
    return r`
            ${this._getPortalStyles()}
            <ha-dialog
                open
                .escapeKeyAction=${"close"}
                .scrimClickAction=${"close"}
                @closed=${this.closeDialog}
                hideActions
                .heading=${""} 
            >
                <div class="content">
                    <div class="poster-col">
                        <img class="poster-img" src="${e.poster_url}" alt="${e.name}" />

                        <div class="actions-col">
                            ${this._confirmDelete ? r`
                                <div class="confirmation-box">
                                    <span>Delete?</span>
                                    <button class="confirm-btn confirm-yes" @click=${this._handleDeleteConfirm}>Yes</button>
                                    <button class="confirm-btn" @click=${() => this._confirmDelete = !1}>No</button>
                                </div>
                              ` : r`
                                <button class="action-btn" @click=${this._handlePlay} title="Play on Chromecast">
                                    <ha-icon icon="mdi:play"></ha-icon>
                                </button>
                                
                                ${e.trailer_url ? r`
                                    <button class="action-btn" @click=${this._handleWatchTrailer} title="Watch Trailer">
                                        <ha-icon icon="mdi:filmstrip"></ha-icon>
                                    </button>
                                ` : l}

                                <button class="action-btn ${e.is_played ? "active" : ""}" @click=${this._handleWatched} title="${e.is_played ? "Mark Unwatched" : "Mark Watched"}">
                                    <ha-icon icon="mdi:check"></ha-icon>
                                </button>

                                <button class="action-btn favorite-btn ${e.is_favorite ? "active" : ""}" @click=${this._handleFavorite} title="${e.is_favorite ? "Remove Favorite" : "Add to Favorites"}">
                                     <ha-icon icon="${e.is_favorite ? "mdi:heart" : "mdi:heart-outline"}"></ha-icon>
                                </button>

                                <a href="${e.jellyfin_url}" class="action-btn" target="_blank" title="Open in Jellyfin">
                                    <ha-icon icon="mdi:popcorn"></ha-icon>
                                </a>

                                <button class="action-btn" @click=${() => this._confirmDelete = !0} title="Delete Item">
                                    <ha-icon icon="mdi:trash-can-outline"></ha-icon>
                                </button>
                            `}
                        </div>
                    </div>

                    <div class="details-col">
                        <div class="header-group">
                            <h1>${e.name}</h1>
                            <div class="header-sub">
                                ${i ? r`<span>${i}</span>` : l}
                                <span class="badge">${e.type}</span>
                                ${e.official_rating ? r`<span class="badge">${e.official_rating}</span>` : l}
                            </div>
                        </div>
                        
                        ${this._nextUpItem ? r`
                            <div class="next-up-card" @click=${this._playNextUp}>
                                <img class="next-up-thumb" src="${this._nextUpItem.backdrop_url || this._nextUpItem.poster_url}" />
                                <div class="next-up-info">
                                    <span class="next-up-label">Next Up</span>
                                    <h3 class="next-up-title">${this._nextUpItem.name}</h3>
                                    <span class="next-up-meta">S${this._nextUpItem.season} : E${this._nextUpItem.episode} • ${this._formatRuntime(this._nextUpItem.runtime_minutes)}</span>
                                </div>
                                <ha-icon icon="mdi:play-circle-outline" style="font-size: 32px; opacity: 0.8;"></ha-icon>
                            </div>
                        ` : l}

                        <div class="stats-row">
                            <div class="stat-item">
                                <ha-icon icon="mdi:star" style="color: #FBC02D;"></ha-icon>
                                <span>${e.rating ? e.rating.toFixed(1) : "N/A"}</span>
                            </div>
                            ${t ? r`
                                <div class="stat-item">
                                    <ha-icon icon="mdi:television-classic"></ha-icon>
                                    <span>${e.unplayed_count !== void 0 ? e.unplayed_count + " Unplayed" : ""}</span>
                                </div>
                             ` : r`
                                <div class="stat-item">
                                    <ha-icon icon="mdi:clock-outline"></ha-icon>
                                    <span>${this._formatRuntime(e.runtime_minutes)}</span>
                                </div>
                             `}
                        </div>

                         ${e.description ? r`<div class="description">${e.description}</div>` : l}

                         ${e.genres && e.genres.length > 0 ? r`
                            <div class="genres-list">
                                ${e.genres.map((a) => r`<span class="genre-tag">${a}</span>`)}
                            </div>
                          ` : l}
                        
                         <div class="divider"></div>

                         <div class="media-info-grid">
                            ${this._renderMediaDetails(e)}
                         </div>
                    </div>
                </div>
            </ha-dialog>
        `;
  }
  _formatRuntime(e) {
    if (!e) return "";
    const t = Math.floor(e / 60), i = e % 60;
    return t > 0 ? `${t}h ${i}m` : `${i} min`;
  }
  _renderMediaDetails(e) {
    const t = [];
    return (e.media_streams || []).forEach((a) => {
      a.Type === "Video" ? (t.push(r`<div class="info-pair"><b>Video</b><span>${a.Codec?.toUpperCase()}</span></div>`), t.push(r`<div class="info-pair"><b>Resolution</b><span>${a.Width}x${a.Height}</span></div>`)) : a.Type === "Audio" && a.Index === 1 && (t.push(r`<div class="info-pair"><b>Audio</b><span>${a.Codec?.toUpperCase()}</span></div>`), t.push(r`<div class="info-pair"><b>Channels</b><span>${a.Channels} ch</span></div>`));
    }), t;
  }
};
y.styles = N`
        /* Styles handled in _getPortalStyles */
    `;
S([
  E({ attribute: !1 })
], y.prototype, "hass", 2);
S([
  f()
], y.prototype, "_item", 2);
S([
  f()
], y.prototype, "_nextUpItem", 2);
S([
  f()
], y.prototype, "_defaultCastDevice", 2);
S([
  f()
], y.prototype, "_open", 2);
S([
  f()
], y.prototype, "_confirmDelete", 2);
y = S([
  U("jellyha-item-details-modal")
], y);
var Kt = Object.defineProperty, Zt = Object.getOwnPropertyDescriptor, at = (e, t, i, a) => {
  for (var o = a > 1 ? void 0 : a ? Zt(t, i) : t, s = e.length - 1, n; s >= 0; s--)
    (n = e[s]) && (o = (a ? n(t, i, o) : n(o)) || o);
  return a && o && Kt(t, i, o), o;
};
function Qt(e, t, i) {
  const a = new CustomEvent(t, {
    bubbles: !0,
    composed: !0,
    detail: i
  });
  e.dispatchEvent(a);
}
let O = class extends w {
  setConfig(e) {
    this._config = e;
  }
  render() {
    if (!this.hass || !this._config)
      return r``;
    const e = this._config.click_action || "more-info", t = this._config.hold_action || "jellyfin";
    return r`
      <div class="card-config">
        <div class="form-row">
          <ha-selector
            .hass=${this.hass}
            .selector=${{ entity: { domain: "sensor" } }}
            .value=${this._config.entity}
            label="Entity"
            @value-changed=${this._entityChanged}
          ></ha-selector>
        </div>

        <div class="form-row">
          <ha-textfield
            label="Title"
            .value=${this._config.title || ""}
            @input=${this._titleChanged}
          ></ha-textfield>
        </div>

        <div class="form-row">
          <ha-select
            label="Layout"
            .value=${this._config.layout || "carousel"}
            @selected=${this._layoutChanged}
            @closed=${(i) => i.stopPropagation()}
          >
            <mwc-list-item value="carousel">Carousel</mwc-list-item>
            <mwc-list-item value="grid">Grid</mwc-list-item>
            <mwc-list-item value="list">List</mwc-list-item>
          </ha-select>
        </div>

        ${this._config.layout === "grid" || this._config.layout === "list" ? r`
              <div class="form-row">
                <ha-slider
                  labeled
                  min="1"
                  max="${this._config.layout === "list" ? 8 : 12}"
                  .value=${this._config.columns || 1}
                  @change=${this._columnsChanged}
                ></ha-slider>
                <span>Columns: ${(this._config.columns || 1) === 1 ? "Auto" : this._config.columns}</span>
              </div>
            ` : ""}

        <div class="form-row">
          <ha-select
            label="Media Type"
            .value=${this._config.media_type || "both"}
            @selected=${this._mediaTypeChanged}
            @closed=${(i) => i.stopPropagation()}
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
            .value=${this._config.items_per_page !== void 0 ? String(this._config.items_per_page) : ""}
            @input=${this._itemsPerPageChanged}
          ></ha-textfield>
        </div>

        <div class="form-row">
          <ha-textfield
            label="Max Pages (0 or blank = no limit)"
            type="number"
            min="0"
            max="20"
            .value=${this._config.max_pages !== void 0 && this._config.max_pages !== null ? String(this._config.max_pages) : ""}
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
            .value=${this._config.new_badge_days !== void 0 && this._config.new_badge_days !== null ? String(this._config.new_badge_days) : ""}
            @input=${this._newBadgeDaysChanged}
          ></ha-textfield>
        </div>

        <div class="form-row">
          <ha-select
            label="Short Press (Click) Action"
            .value=${e}
            @selected=${this._clickActionChanged}
            @closed=${(i) => i.stopPropagation()}
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
            .value=${t}
            @selected=${this._holdActionChanged}
            @closed=${(i) => i.stopPropagation()}
          >
            <mwc-list-item value="jellyfin">Open in Jellyfin</mwc-list-item>
            <mwc-list-item value="cast">Cast to Chromecast</mwc-list-item>
            <mwc-list-item value="more-info">More Information</mwc-list-item>
            <mwc-list-item value="none">No Action</mwc-list-item>
          </ha-select>
        </div>

        ${e === "cast" || t === "cast" ? r`
              <div class="form-row">
                <ha-selector
                  .hass=${this.hass}
                  .selector=${{ entity: { domain: "media_player" } }}
                  .value=${this._config.default_cast_device}
                  label="Default Cast Device"
                  @value-changed=${this._defaultCastDeviceChanged}
                ></ha-selector>
              </div>
              <div class="checkbox-row">
                <ha-switch
                  .checked=${this._config.show_now_playing !== !1}
                  @change=${this._showNowPlayingChanged}
                ></ha-switch>
                <span>Show "Now Playing" Overlay on Posters</span>
              </div>
            ` : ""}

    <div class="checkbox-row">
      <ha-switch
        .checked=${this._config.show_title !== !1}
        @change=${this._showTitleChanged}
      ></ha-switch>
      <span>Show Title</span>
    </div>

    <div class="checkbox-row">
      <ha-switch
        .checked=${this._config.show_year !== !1}
        @change=${this._showYearChanged}
      ></ha-switch>
      <span>Show Year</span>
    </div>

    <div class="checkbox-row">
      <ha-switch
        .checked=${this._config.show_date_added === !0}
        @change=${this._showDateAddedChanged}
      ></ha-switch>
      <span>Show Date Added</span>
    </div>

    <div class="checkbox-row">
      <ha-switch
        .checked=${this._config.show_ratings !== !1}
        @change=${this._showRatingsChanged}
      ></ha-switch>
      <span>Show Ratings</span>
    </div>

    <div class="checkbox-row">
      <ha-switch
        .checked=${this._config.show_runtime === !0}
        @change=${this._showRuntimeChanged}
      ></ha-switch>
      <span>Show Runtime</span>
    </div>

    <div class="checkbox-row">
      <ha-switch
        .checked=${this._config.show_media_type_badge !== !1}
        @change=${this._showMediaTypeBadgeChanged}
      ></ha-switch>
      <span>Show Media Type Badge (Movie/Series)</span>
    </div>

    <div class="checkbox-row">
      <ha-switch
        .checked=${this._config.show_watched_status !== !1}
        @change=${this._showWatchedStatusChanged}
      ></ha-switch>
      <span>Show Watched Status</span>
    </div>

    <div class="checkbox-row">
      <ha-switch
        .checked=${this._config.show_genres === !0}
        @change=${this._showGenresChanged}
      ></ha-switch>
      <span>Show Genres</span>
    </div>

    <div class="checkbox-row">
      <ha-switch
        .checked=${this._config.show_description_on_hover !== !1}
        @change=${this._showDescriptionOnHoverChanged}
      ></ha-switch>
      <span>Show Description</span>
    </div>

    <div class="form-row">
      <ha-select
        label="Metadata Position"
        .value=${this._config.metadata_position || "below"}
        @selected=${this._metadataPositionChanged}
        @closed=${(i) => i.stopPropagation()}
      >
        <mwc-list-item value="below">Below</mwc-list-item>
        <mwc-list-item value="above">Above</mwc-list-item>
      </ha-select>
    </div>

    <div class="checkbox-row">
      <ha-switch
        .checked=${this._config.show_pagination !== !1}
        @change=${this._showPaginationChanged}
      ></ha-switch>
      <span>Show Pagination Dots</span>
    </div>

    <div class="checkbox-row">
      <ha-switch
        .checked=${this._config.filter_favorites === !0}
        @change=${this._filterFavoritesChanged}
      ></ha-switch>
      <span>Show Only Favorites</span>
    </div>

    <div class="form-row">
      <ha-select
        label="Watch Status"
        .value=${this._config.status_filter || "all"}
        @selected=${this._statusFilterChanged}
        @closed=${(i) => i.stopPropagation()}
      >
        <mwc-list-item value="all">All</mwc-list-item>
        <mwc-list-item value="unwatched">Unwatched</mwc-list-item>
        <mwc-list-item value="watched">Watched</mwc-list-item>
      </ha-select>
    </div>

    <div class="checkbox-row">
      <ha-switch
        .checked=${this._config.filter_newly_added === !0}
        @change=${this._filterNewlyAddedChanged}
      ></ha-switch>
      <span>Show New Items Only</span>
    </div>

    <div class="form-row">
      <ha-select
        label="Sort Order"
        .value=${this._config.sort_option || "date_added_desc"}
        @selected=${this._sortOptionChanged}
        @closed=${(i) => i.stopPropagation()}
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
  _entityChanged(e) {
    this._updateConfig("entity", e.detail.value);
  }
  _titleChanged(e) {
    const t = e.target;
    this._updateConfig("title", t.value);
  }
  _layoutChanged(e) {
    const t = e.target;
    this._updateConfig("layout", t.value);
  }
  _columnsChanged(e) {
    const t = e.target;
    this._updateConfig("columns", Number(t.value));
  }
  _mediaTypeChanged(e) {
    const t = e.target;
    this._updateConfig("media_type", t.value);
  }
  _itemsPerPageChanged(e) {
    const t = e.target, i = t.value.trim();
    i !== "" ? this._updateConfig("items_per_page", Number(i)) : (this._updateConfig("items_per_page", 5), t.value = "5");
  }
  _maxPagesChanged(e) {
    const i = e.target.value;
    i === "" || i === null ? this._updateConfig("max_pages", null) : this._updateConfig("max_pages", Number(i));
  }
  _autoSwipeIntervalChanged(e) {
    const t = e.target;
    this._updateConfig("auto_swipe_interval", Number(t.value));
  }
  _newBadgeDaysChanged(e) {
    const i = e.target.value;
    i === "" || i === null ? this._updateConfig("new_badge_days", null) : this._updateConfig("new_badge_days", Number(i));
  }
  _clickActionChanged(e) {
    const t = e.target;
    this._updateConfig("click_action", t.value);
  }
  _holdActionChanged(e) {
    const t = e.target;
    this._updateConfig("hold_action", t.value);
  }
  _defaultCastDeviceChanged(e) {
    this._updateConfig("default_cast_device", e.detail.value);
  }
  _showNowPlayingChanged(e) {
    const t = e.target;
    this._updateConfig("show_now_playing", t.checked);
  }
  _showTitleChanged(e) {
    const t = e.target;
    this._updateConfig("show_title", t.checked);
  }
  _showYearChanged(e) {
    const t = e.target;
    this._updateConfig("show_year", t.checked);
  }
  _showRatingsChanged(e) {
    const t = e.target;
    this._updateConfig("show_ratings", t.checked);
  }
  _showRuntimeChanged(e) {
    const t = e.target;
    this._updateConfig("show_runtime", t.checked);
  }
  _showMediaTypeBadgeChanged(e) {
    const t = e.target;
    this._updateConfig("show_media_type_badge", t.checked);
  }
  _showWatchedStatusChanged(e) {
    const t = e.target;
    this._updateConfig("show_watched_status", t.checked);
  }
  _showGenresChanged(e) {
    const t = e.target;
    this._updateConfig("show_genres", t.checked);
  }
  _showDateAddedChanged(e) {
    const t = e.target;
    this._updateConfig("show_date_added", t.checked);
  }
  _showDescriptionOnHoverChanged(e) {
    const t = e.target;
    this._updateConfig("show_description_on_hover", t.checked);
  }
  _metadataPositionChanged(e) {
    const t = e.target;
    this._updateConfig("metadata_position", t.value);
  }
  _horizontalAlignmentChanged(e) {
    const t = e.target;
    this._updateConfig("horizontal_alignment", t.value);
  }
  _showPaginationChanged(e) {
    const t = e.target;
    this._updateConfig("show_pagination", t.checked);
  }
  _filterFavoritesChanged(e) {
    const t = e.target;
    this._updateConfig("filter_favorites", t.checked);
  }
  _statusFilterChanged(e) {
    const t = e.target;
    this._updateConfig("status_filter", t.value);
  }
  _filterNewlyAddedChanged(e) {
    const t = e.target;
    this._updateConfig("filter_newly_added", t.checked);
  }
  _sortOptionChanged(e) {
    const t = e.target;
    this._updateConfig("sort_option", t.value);
  }
  _updateConfig(e, t) {
    if (!this._config)
      return;
    const i = { ...this._config, [e]: t };
    this._config = i, Qt(this, "config-changed", { config: i });
  }
};
O.styles = N`
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
at([
  E({ attribute: !1 })
], O.prototype, "hass", 2);
at([
  f()
], O.prototype, "_config", 2);
O = at([
  U("jellyha-library-editor")
], O);
var te = Object.defineProperty, ee = Object.getOwnPropertyDescriptor, _ = (e, t, i, a) => {
  for (var o = a > 1 ? void 0 : a ? ee(t, i) : t, s = e.length - 1, n; s >= 0; s--)
    (n = e[s]) && (o = (a ? n(t, i, o) : n(o)) || o);
  return a && o && te(t, i, o), o;
};
const ie = "1.0.0";
console.info(
  `%c JELLYHA-LIBRARY-CARD %c v${ie} `,
  "color: white; background: #00a4dc; font-weight: bold;",
  "color: #00a4dc; background: white; font-weight: bold;"
);
window.customCards = window.customCards || [];
window.customCards.push({
  type: "jellyha-library-card",
  name: "JellyHA Library",
  description: "Display media from Jellyfin",
  preview: !0
});
const mt = {
  title: "Jellyfin Library",
  layout: "carousel",
  media_type: "both",
  items_per_page: 3,
  max_pages: 5,
  auto_swipe_interval: 0,
  // 0 = disabled, otherwise seconds
  columns: 3,
  show_title: !0,
  show_year: !0,
  show_runtime: !0,
  show_ratings: !0,
  show_media_type_badge: !0,
  show_genres: !0,
  show_description_on_hover: !0,
  show_pagination: !0,
  metadata_position: "below",
  rating_source: "auto",
  new_badge_days: 3,
  theme: "auto",
  show_watched_status: !0,
  click_action: "more-info",
  hold_action: "jellyfin",
  default_cast_device: "",
  show_now_playing: !0,
  filter_favorites: !1,
  status_filter: "all",
  filter_newly_added: !1,
  sort_option: "date_added_desc"
};
let m = class extends w {
  constructor() {
    super(), this._currentPage = 0, this._itemsPerPage = 5, this._pressStartTime = 0, this._isHoldActive = !1, this._rewindActive = !1, this._items = [], this._lastUpdate = "", this._touchStartX = 0, this._touchStartY = 0, this._isOverscrolling = !1, this._elasticAnchorX = 0, this._itemTouchStartX = 0, this._itemTouchStartY = 0, this._containerWidth = 0, this.ITEM_WIDTH = 148, this.LIST_ITEM_MIN_WIDTH = 380, this._effectiveListColumns = 1, this._isSwiping = !1, this._scrollProgress = 0, this._hasScrollableContent = !1, this.SCROLL_INDICATOR_DOTS = 5, this._onDotClick = this._onDotClick.bind(this), this._handleTouchStart = this._handleTouchStart.bind(this), this._handleTouchMove = this._handleTouchMove.bind(this), this._handleTouchEnd = this._handleTouchEnd.bind(this), this._handlePointerDown = this._handlePointerDown.bind(this), this._handlePointerMove = this._handlePointerMove.bind(this), this._handlePointerUp = this._handlePointerUp.bind(this), this._handleScroll = this._handleScroll.bind(this);
  }
  connectedCallback() {
    super.connectedCallback(), this._setupResizeHandler(), this._setupAutoSwipe();
  }
  disconnectedCallback() {
    super.disconnectedCallback(), this._resizeObserver?.disconnect(), this._resizeHandler && window.removeEventListener("resize", this._resizeHandler), this._clearAutoSwipe();
  }
  _setupAutoSwipe() {
    this._clearAutoSwipe();
    const e = this._config?.auto_swipe_interval;
    e && e > 0 && (this._autoSwipeTimer = window.setInterval(() => {
      this._nextPage();
    }, e * 1e3));
  }
  _clearAutoSwipe() {
    this._autoSwipeTimer && (clearInterval(this._autoSwipeTimer), this._autoSwipeTimer = void 0);
  }
  /* Pagination Handlers */
  async _nextPage() {
    if (!this._config?.entity || !this.hass || !this.hass.states[this._config.entity]) return;
    const t = this._filterItems(this._items || []), i = this._config.items_per_page || this._itemsPerPage, a = this._config.max_pages || 10, o = Math.min(Math.ceil(t.length / i), a);
    this._currentPage < o - 1 && await this._animatePageChange("next", () => {
      this._currentPage++;
    });
  }
  async _prevPage() {
    this._currentPage > 0 && await this._animatePageChange("prev", () => {
      this._currentPage--;
    });
  }
  /**
   * Helper to set scroll position after page change
   */
  _setScrollPosition(e) {
    const t = this.shadowRoot?.querySelector(".carousel, .grid-wrapper");
    t && (e === "start" ? t.scrollLeft = 0 : t.scrollLeft = t.scrollWidth);
  }
  /**
   * Helper to animate page changes (Slide & Fade)
   **/
  async _animatePageChange(e, t) {
    const i = this.shadowRoot?.querySelector(".carousel, .grid-wrapper");
    if (!i) {
      t();
      return;
    }
    const a = e === "next" ? "-30px" : "30px";
    i.style.transition = "transform 0.2s ease-out, opacity 0.2s ease-out", i.style.transform = `translateX(${a})`, i.style.opacity = "0", await new Promise((s) => setTimeout(s, 200)), t(), await this.updateComplete, this._setScrollPosition(e === "next" ? "start" : "end");
    const o = e === "next" ? "30px" : "-30px";
    i.style.transition = "none", i.style.opacity = "0", i.style.transform = `translateX(${o})`, i.offsetHeight, i.style.transition = "transform 0.25s ease-out, opacity 0.25s ease-out", i.style.transform = "translateX(0)", i.style.opacity = "1", await new Promise((s) => setTimeout(s, 250)), i.style.transition = "", i.style.transform = "", i.style.opacity = "";
  }
  /**
   * Helper to get total pages (used for elastic check)
   */
  _getTotalPages() {
    if (!this._config?.entity || !this.hass || !this.hass.states[this._config.entity]) return 1;
    const t = this._filterItems(this._items || []), i = this._config.items_per_page || this._itemsPerPage, a = this._config.max_pages || 10;
    return Math.min(Math.ceil(t.length / i), a);
  }
  // Touch/Swipe handlers
  _handleTouchStart(e) {
    this._touchStartX = e.touches[0].clientX, this._touchStartY = e.touches[0].clientY, this._isSwiping = !1, this._isOverscrolling = !1, this._elasticAnchorX = 0;
  }
  _handleTouchMove(e) {
    if (!this._touchStartX) return;
    const t = e.touches[0].clientX - this._touchStartX, i = e.touches[0].clientY - this._touchStartY;
    if (Math.abs(t) > Math.abs(i)) {
      const a = this.shadowRoot?.querySelector(".carousel, .grid-wrapper");
      if (a && Math.abs(t) > 0) {
        const { scrollLeft: o, scrollWidth: s, clientWidth: n } = a, d = s - n, c = o <= 5, p = o >= d - 5, g = this._config.show_pagination !== !1;
        let h = !1;
        if (g) {
          const u = this._getTotalPages();
          c && t > 0 && this._currentPage === 0 && (h = !0), p && t < 0 && this._currentPage >= u - 1 && (h = !0);
        } else
          c && t > 0 && (h = !0), p && t < 0 && (h = !0);
        if (h) {
          this._isOverscrolling || (this._isOverscrolling = !0, this._elasticAnchorX = t), e.preventDefault();
          const u = 0.3, v = t - this._elasticAnchorX;
          a.style.transition = "none", a.style.transform = `translateX(${v * u}px)`;
          return;
        }
      }
      Math.abs(t) > 30 && (this._isSwiping = !0);
    }
  }
  _handleTouchEnd(e) {
    if (this._isOverscrolling) {
      const o = this.shadowRoot?.querySelector(".carousel, .grid-wrapper");
      o && (o.style.transition = "transform 0.4s cubic-bezier(0.25, 0.8, 0.5, 1)", o.style.transform = ""), this._isOverscrolling = !1, this._elasticAnchorX = 0, this._touchStartX = 0, this._isSwiping = !1;
      return;
    }
    if (!this._isSwiping) {
      this._touchStartX = 0;
      return;
    }
    if (this._config.show_pagination === !1) {
      this._touchStartX = 0, this._isSwiping = !1;
      return;
    }
    const t = e.changedTouches[0].clientX - this._touchStartX, i = 50, a = this.shadowRoot?.querySelector(".carousel, .grid-wrapper");
    if (t < -i)
      if (a) {
        const { scrollLeft: o, scrollWidth: s, clientWidth: n } = a;
        o + n >= s - 10 && this._nextPage();
      } else
        this._nextPage();
    else t > i && (a ? a.scrollLeft <= 10 && this._prevPage() : this._prevPage());
    this._touchStartX = 0, this._isSwiping = !1;
  }
  // Pointer events for Android Companion App (uses same logic as touch)
  // Pointer events for Android Companion App (uses same logic as touch)
  _handlePointerDown(e) {
    e.pointerType !== "mouse" && (this._touchStartX = e.clientX, this._touchStartY = e.clientY, this._isSwiping = !1, this._isOverscrolling = !1, this._elasticAnchorX = 0, e.target.setPointerCapture?.(e.pointerId));
  }
  _handlePointerMove(e) {
    if (e.pointerType === "mouse" || !this._touchStartX) return;
    const t = e.clientX - this._touchStartX, i = e.clientY - this._touchStartY;
    if (Math.abs(t) > Math.abs(i)) {
      const a = this.shadowRoot?.querySelector(".carousel, .grid-wrapper");
      if (a && Math.abs(t) > 0) {
        const { scrollLeft: o, scrollWidth: s, clientWidth: n } = a, d = s - n, c = o <= 5, p = o >= d - 5, g = this._config.show_pagination !== !1;
        let h = !1;
        if (g) {
          const u = this._getTotalPages();
          c && t > 0 && this._currentPage === 0 && (h = !0), p && t < 0 && this._currentPage >= u - 1 && (h = !0);
        } else
          c && t > 0 && (h = !0), p && t < 0 && (h = !0);
        if (h) {
          this._isOverscrolling || (this._isOverscrolling = !0, this._elasticAnchorX = t), e.preventDefault();
          const u = 0.3, v = t - this._elasticAnchorX;
          a.style.transition = "none", a.style.transform = `translateX(${v * u}px)`;
          return;
        }
      }
      Math.abs(t) > 30 && (this._isSwiping = !0);
    }
  }
  _handlePointerUp(e) {
    if (e.target.releasePointerCapture?.(e.pointerId), this._isOverscrolling) {
      const o = this.shadowRoot?.querySelector(".carousel, .grid-wrapper");
      o && (o.style.transition = "transform 0.4s cubic-bezier(0.25, 0.8, 0.5, 1)", o.style.transform = ""), this._isOverscrolling = !1, this._elasticAnchorX = 0, this._touchStartX = 0, this._isSwiping = !1;
      return;
    }
    if (e.pointerType === "mouse" || !this._isSwiping) {
      this._touchStartX = 0;
      return;
    }
    if (this._config.show_pagination === !1) {
      this._touchStartX = 0, this._isSwiping = !1;
      return;
    }
    const t = e.clientX - this._touchStartX, i = 50, a = this.shadowRoot?.querySelector(".carousel, .grid-wrapper");
    if (t < -i)
      if (a) {
        const { scrollLeft: o, scrollWidth: s, clientWidth: n } = a;
        o + n >= s - 10 && this._nextPage();
      } else
        this._nextPage();
    else t > i && (a ? a.scrollLeft <= 10 && this._prevPage() : this._prevPage());
    this._touchStartX = 0, this._isSwiping = !1;
  }
  // Scroll handler for elastic dot indicator
  _handleScroll(e) {
    const t = e.target, i = t.scrollWidth, a = t.clientWidth, o = t.scrollLeft, s = i > a + 10;
    if (s !== this._hasScrollableContent && (this._hasScrollableContent = s), s) {
      const n = i - a;
      let d = o / n;
      (n - o < 10 || d > 0.98) && (d = 1), (o < 10 || d < 0.02) && (d = 0), d = Math.min(1, Math.max(0, d)), this._scrollProgress = d;
    }
  }
  // Render scroll indicator for non-paginated scrollable content
  _renderScrollIndicator() {
    if (!this._hasScrollableContent) return r``;
    const e = this.SCROLL_INDICATOR_DOTS, t = this._scrollProgress, i = Math.round(t * (e - 1));
    return r`
      <div class="scroll-indicator">
        ${Array.from({ length: e }, (a, o) => {
      const s = o === i, n = o === 0 && t < 0.1 || o === e - 1 && t > 0.9;
      return r`
        <span 
          class="scroll-dot ${s ? "active" : ""} ${n ? "pill" : ""}"
        ></span>
      `;
    })}
      </div>
    `;
  }
  _setupResizeHandler() {
    this._resizeHandler = () => {
      const t = this.getBoundingClientRect().width;
      if (t === 0) return;
      const i = Math.max(0, t - 32);
      if (i !== this._containerWidth) {
        this._containerWidth = i;
        const o = Math.max(2, Math.floor(i / 160));
        if (o !== this._itemsPerPage && (this._itemsPerPage = o, this.requestUpdate()), this._config) {
          const s = this._config.columns || 1, n = 300;
          if (s > 1) {
            const d = Math.max(1, Math.floor(i / n)), c = Math.min(s, d);
            c !== this._effectiveListColumns && (this._effectiveListColumns = c, this.requestUpdate());
          } else this._effectiveListColumns !== 1 && (this._effectiveListColumns = 1, this.requestUpdate());
        }
      }
    };
    try {
      this._resizeObserver = new ResizeObserver(() => {
        this._resizeHandler && window.requestAnimationFrame(() => this._resizeHandler());
      }), this._resizeObserver.observe(this);
    } catch (e) {
      console.warn("ResizeObserver not supported, falling back to window resize", e), window.addEventListener("resize", this._resizeHandler);
    }
    this._resizeHandler();
  }
  _handleDotClick(e) {
    e !== this._currentPage && (this._currentPage = e, this.requestUpdate());
  }
  _onDotClick(e) {
    e.stopPropagation(), e.preventDefault();
    const t = e.currentTarget, i = parseInt(t.dataset.page || "0", 10);
    this._handleDotClick(i);
  }
  /**
   * Set card configuration
   */
  setConfig(e) {
    if (!e.entity)
      throw new Error("Please define an entity");
    this._config = { ...mt, ...e }, this._effectiveListColumns = this._config.columns || 1;
  }
  /**
   * Return the card editor element
   */
  static getConfigElement() {
    return document.createElement("jellyha-library-editor");
  }
  /**
   * Return default stub config for card picker
   */
  static getStubConfig() {
    return {
      entity: "sensor.jellyha_library",
      ...mt
    };
  }
  /**
   * Get card size for layout
   */
  getCardSize() {
    return this._config?.layout === "list" ? 5 : 3;
  }
  /**
   * Determine if component should update
   */
  shouldUpdate(e) {
    if (!this._config)
      return !1;
    if (e.has("_currentPage") || e.has("_itemsPerPage") || e.has("_items") || e.has("_error") || e.has("_scrollProgress") || e.has("_hasScrollableContent"))
      return !0;
    if (e.has("hass")) {
      const t = e.get("hass");
      if (t) {
        const i = t.states[this._config.entity], a = this.hass.states[this._config.entity], o = this._config.default_cast_device;
        if (o) {
          const s = t.states[o], n = this.hass.states[o];
          if (s !== n) return !0;
        }
        return i !== a;
      }
    }
    return e.has("_config");
  }
  /**
   * Fetch items from WebSocket
   */
  async _fetchItems() {
    if (!(!this._config || !this.hass || !this.hass.states[this._config.entity])) {
      this._error = void 0;
      try {
        const t = await this.hass.callWS({
          type: "jellyha/get_items",
          entity_id: this._config.entity
        });
        t && t.items && (this._items = t.items);
      } catch (t) {
        console.error("Error fetching JellyHA items:", t), this._error = `Error fetching items: ${t}`;
      }
    }
  }
  /**
   * Called after update - check for scrollable content and fetch data
   */
  updated(e) {
    if (super.updated(e), e.has("hass") || e.has("_config")) {
      const t = this.hass?.states[this._config?.entity];
      if (t) {
        const i = t.attributes.entry_id, a = t.attributes.last_updated;
        (a !== this._lastUpdate || this._items.length === 0 && i) && (this._lastUpdate = a, this._fetchItems());
      }
    }
    this._config.show_pagination || requestAnimationFrame(() => {
      const t = this.shadowRoot?.querySelector(".carousel.scrollable, .grid-wrapper, .list-wrapper");
      if (t) {
        const i = t.scrollWidth > t.clientWidth + 10;
        i !== this._hasScrollableContent && (this._hasScrollableContent = i);
      }
    });
  }
  /**
   * Render the card
   */
  render() {
    if (!this._config || !this.hass)
      return r``;
    if (!this.hass.states[this._config.entity])
      return this._renderError(`Entity not found: ${this._config.entity}`);
    if (this._error)
      return this._renderError(this._error);
    const t = this._filterItems(this._items || []);
    return r`
      <ha-card>
        <div class="card-inner">
            ${this._config.title ? r`
                  <div class="card-header">
                    <h2>${this._config.title}</h2>
                  </div>
                ` : l}
            <div class="card-content">
              ${t.length === 0 ? this._renderEmpty() : this._renderLayout(t)}
            </div>
        </div>
        <jellyha-item-details-modal .hass=${this.hass}></jellyha-item-details-modal>
      </ha-card>
    `;
  }
  /**
   * Filter items based on config
   */
  _filterItems(e) {
    let t = e;
    this._config.media_type === "movies" ? t = t.filter((s) => s.type === "Movie") : this._config.media_type === "series" && (t = t.filter((s) => s.type === "Series")), this._config.filter_favorites && (t = t.filter((s) => s.is_favorite === !0));
    const i = this._config.status_filter || "all";
    i === "unwatched" ? t = t.filter((s) => !s.is_played) : i === "watched" && (t = t.filter((s) => s.is_played === !0)), this._config.filter_newly_added && (t = t.filter((s) => this._isNewItem(s)));
    const a = this._config.sort_option || "date_added_desc";
    t.sort((s, n) => {
      switch (a) {
        case "date_added_asc":
          return (s.date_added || "").localeCompare(n.date_added || "");
        case "date_added_desc":
          return (n.date_added || "").localeCompare(s.date_added || "");
        case "title_asc":
          return (s.name || "").localeCompare(n.name || "");
        case "title_desc":
          return (n.name || "").localeCompare(s.name || "");
        case "year_asc":
          return (s.year || 0) - (n.year || 0);
        case "year_desc":
          return (n.year || 0) - (s.year || 0);
        case "last_played_asc":
          return (s.last_played_date || "").localeCompare(n.last_played_date || "");
        case "last_played_desc":
          return (n.last_played_date || "").localeCompare(s.last_played_date || "");
        default:
          return 0;
      }
    });
    const o = this._config.max_pages;
    if (o != null && o > 0) {
      const s = (this._config.items_per_page || 5) * o;
      t = t.slice(0, s);
    }
    return t;
  }
  /**
   * Render layout based on config
   */
  _renderLayout(e) {
    const t = this._config.layout || "carousel", i = this._config.show_pagination !== !1;
    return t === "carousel" ? this._renderCarousel(e, i) : t === "list" ? this._renderList(e, i) : t === "grid" ? this._renderGrid(e, i) : r`
      <div class="${t}">
        ${e.map((a) => this._renderMediaItem(a))}
      </div>
    `;
  }
  /**
   * Render carousel with optional pagination
   */
  _renderCarousel(e, t) {
    const i = this._config.items_per_page || this._itemsPerPage, a = this._config.max_pages, o = a ? Number(a) : 0, s = o > 0 ? o : 1 / 0, n = Math.min(Math.ceil(e.length / i), s), d = this._currentPage * i, c = t ? e.slice(d, d + i) : e;
    return r`
      <div 
        class="carousel-wrapper ${this._config.horizontal_alignment !== "left" ? "align-center" : ""}"
        @touchstart="${this._handleTouchStart}"
        @touchmove="${this._handleTouchMove}"
        @touchend="${this._handleTouchEnd}"
        @pointerdown="${this._handlePointerDown}"
        @pointermove="${this._handlePointerMove}"
        @pointerup="${this._handlePointerUp}"
      >
        <div 
          class="carousel ${t ? "paginated" : "scrollable"}"
          @scroll="${t ? l : this._handleScroll}"
        >
          ${c.map((p) => this._renderMediaItem(p))}
        </div>
        ${t && n > 1 ? this._renderPagination(n) : l}
        ${t ? l : this._renderScrollIndicator()}
      </div>
    `;
  }
  /**
   * Render list with optional pagination
   */
  _renderList(e, t) {
    const i = this._config.items_per_page || this._itemsPerPage, a = this._config.max_pages, o = a ? Number(a) : 0, s = o > 0 ? o : 1 / 0, n = Math.min(Math.ceil(e.length / i), s), d = this._currentPage * i, c = t ? e.slice(d, d + i) : e, p = this._effectiveListColumns, g = p === 1;
    return r`
      <div 
        class="list-wrapper"
        @touchstart="${this._handleTouchStart}"
        @touchmove="${this._handleTouchMove}"
        @touchend="${this._handleTouchEnd}"
        @pointerdown="${this._handlePointerDown}"
        @pointermove="${this._handlePointerMove}"
        @pointerup="${this._handlePointerUp}"
      >
        <div 
          class="list ${t ? "paginated" : ""} ${g ? "single-column" : ""}"
          style="--jf-list-columns: ${p}"
        >
          ${c.map((h) => this._renderListItem(h))}
        </div>
        ${t && n > 1 ? this._renderPagination(n) : l}
      </div>
    `;
  }
  /**
   * Render grid with optional pagination
   */
  _renderGrid(e, t) {
    const i = this._config.items_per_page || this._itemsPerPage, a = this._config.max_pages, o = a ? Number(a) : 0, s = o > 0 ? o : 1 / 0, n = Math.min(Math.ceil(e.length / i), s), d = this._currentPage * i, c = t ? e.slice(d, d + i) : e, p = this._config.columns || 1, g = p === 1;
    return r`
      <div class="grid-outer">
        <div 
          class="grid-wrapper"
          @touchstart="${this._handleTouchStart}"
          @touchmove="${this._handleTouchMove}"
          @touchend="${this._handleTouchEnd}"
          @pointerdown="${this._handlePointerDown}"
          @pointermove="${this._handlePointerMove}"
          @pointerup="${this._handlePointerUp}"
          @scroll="${t ? l : this._handleScroll}"
        >
          <div
            class="grid ${t ? "paginated" : ""} ${g ? "auto-columns" : ""}"
            style="--jf-columns: ${p}"
          >
            ${c.map((h) => this._renderMediaItem(h))}
          </div>
        </div>
        ${t && n > 1 ? this._renderPagination(n) : l}
        ${t ? l : this._renderScrollIndicator()}
      </div>
    `;
  }
  /**
   * Main Pagination Render Dispatcher
   * Decides between standard and smart pagination based on page count
   */
  _renderPagination(e) {
    return e <= 5 ? this._renderStandardPagination(e) : this._renderSmartPagination(e);
  }
  /**
   * Render Standard Pagination (Existing Logic preserved)
   */
  _renderStandardPagination(e) {
    return r`
      <div class="pagination-dots">
        ${Array.from({ length: e }, (t, i) => r`
          <button
            type="button"
            class="pagination-dot ${i === this._currentPage ? "active" : ""}"
            data-page="${i}"
            @click="${this._onDotClick}"
            aria-label="${i === this._currentPage ? `Page ${i + 1}, current page` : `Go to page ${i + 1}`}"
            aria-current="${i === this._currentPage ? "true" : "false"}"
          ></button>
        `)}
      </div>
    `;
  }
  /**
   * Render Smart Sliding Pagination (iOS Style)
   */
  _renderSmartPagination(e) {
    const d = -(this._currentPage * 16) + 32;
    return r`
      <div class="pagination-container smart" style="width: ${72}px">
        <div 
          class="pagination-track" 
          style="transform: translateX(${d}px); width: ${e * 16}px"
        >
          ${Array.from({ length: e }, (c, p) => {
      const g = Math.abs(p - this._currentPage);
      let h = "smart-dot";
      return p === this._currentPage ? h += " active" : g > 2 ? h += " hidden" : g === 2 && (h += " small"), r`
              <button
                type="button"
                class="${h}"
                data-page="${p}"
                @click="${this._onDotClick}"
                aria-label="${p === this._currentPage ? `Page ${p + 1} of ${e}, current page` : `Go to page ${p + 1} of ${e}`}"
                aria-current="${p === this._currentPage ? "true" : "false"}"
              ></button>
            `;
    })}
        </div>
      </div>
    `;
  }
  /**
   * Render individual list item (horizontal layout with metadata outside poster)
   */
  _renderListItem(e) {
    const t = this._isNewItem(e), i = this._getRating(e), a = this._config.show_media_type_badge !== !1, o = this._isItemPlaying(e);
    return r`
      <div
        class="media-item list-item ${o ? "playing" : ""} ${this._config.show_title ? "" : "no-title"} ${this._config.metadata_position === "above" ? "metadata-above" : ""}"
        tabindex="0"
        role="button"
        aria-label="${e.name}"
        @mousedown="${(s) => this._handleMouseDown(s, e)}"
        @mouseup="${(s) => this._handleMouseUp(s, e)}"
        @touchstart="${(s) => this._handleTouchStartItem(s, e)}"
        @touchmove="${(s) => this._handleTouchMoveItem(s, e)}"
        @touchend="${(s) => this._handleTouchEndItem(s, e)}"
        @touchcancel="${(s) => this._handleTouchEndItem(s, e)}"
        @keydown="${(s) => this._handleKeydown(s, e)}"
      >
        <div class="list-poster-wrapper">
          ${this._config.metadata_position === "above" && this._config.show_date_added && e.date_added ? r`<p class="list-date-added">${this._formatDate(e.date_added)}</p>` : l}
          <div class="poster-container" id="poster-${e.id}">
            <div class="poster-inner">
              <img
                class="poster"
                src="${e.poster_url}"
                alt="${e.name}"
                width="140"
                height="210"
                loading="lazy"
                @load="${this._handleImageLoad}"
                @error="${this._handleImageError}"
              />
              <div class="poster-skeleton"></div>
              
              ${a && !o ? r`<span class="list-type-badge ${e.type === "Movie" ? "movie" : "series"}">
                  ${e.type === "Movie" ? "Movie" : "Series"}
                </span>` : l}
              
              ${o ? l : this._renderStatusBadge(e, t)}
              ${this._renderNowPlayingOverlay(e)}
            </div>
          </div>
          ${this._config.metadata_position !== "above" && this._config.show_date_added && e.date_added ? r`<p class="list-date-added">${this._formatDate(e.date_added)}</p>` : l}
        </div>
        
        <div class="list-info">
          ${this._config.show_title ? r`<h3 class="list-title">${e.name}</h3>` : l}
          
          <div class="list-metadata">
            ${a && !o ? r`<span class="list-type-badge ${e.type === "Movie" ? "movie" : "series"}">
                  ${e.type === "Movie" ? "Movie" : "Series"}
                </span>` : l}
            ${this._config.show_year && e.year ? r`<span class="list-year">${e.year}</span>` : l}
            ${this._config.show_ratings && i ? r`<span class="list-rating">
                  <ha-icon icon="mdi:star"></ha-icon>
                  ${i.toFixed(1)}
                </span>` : l}
            ${this._config.show_runtime && e.runtime_minutes ? r`<span class="list-runtime">
                  <ha-icon icon="mdi:clock-outline"></ha-icon>
                  ${this._formatRuntime(e.runtime_minutes)}
                </span>` : l}
          </div>
          
          ${this._config.show_genres && e.genres && e.genres.length > 0 ? r`<p class="list-genres">${e.genres.slice(0, 3).join(", ")}</p>` : l}
          
          ${this._config.show_description_on_hover !== !1 && e.description ? r`<p class="list-description">${e.description}</p>` : l}
        </div>
      </div>
    `;
  }
  /**
   * Render status badge (watched checkmark, unplayed count, or new badge)
   */
  _renderStatusBadge(e, t) {
    const i = this._config.show_watched_status !== !1;
    return i && e.is_played ? r`
        <div class="status-badge watched">
          <ha-icon icon="mdi:check-bold"></ha-icon>
        </div>
      ` : i && e.type === "Series" && (e.unplayed_count || 0) > 0 ? r`
        <div class="status-badge unplayed">
          ${e.unplayed_count}
        </div>
      ` : t ? r`<span class="new-badge">${V(this.hass.language, "new")}</span>` : r``;
  }
  /**
   * Render individual media item
   */
  _renderMediaItem(e) {
    const t = this._isNewItem(e), i = this._getRating(e), a = this._config.show_media_type_badge !== !1, o = this._isItemPlaying(e);
    return r`
      <div
        class="media-item ${o ? "playing" : ""}"
        tabindex="0"
        role="button"
        aria-label="${e.name}"
        @mousedown="${(s) => this._handleMouseDown(s, e)}"
        @mouseup="${(s) => this._handleMouseUp(s, e)}"
        @touchstart="${(s) => this._handleTouchStartItem(s, e)}"
        @touchmove="${(s) => this._handleTouchMoveItem(s, e)}"
        @touchend="${(s) => this._handleTouchEndItem(s, e)}"
        @touchcancel="${(s) => this._handleTouchEndItem(s, e)}"
        @keydown="${(s) => this._handleKeydown(s, e)}"
      >
        ${this._config.metadata_position === "above" ? r`
              <div class="media-info-above">
                ${this._config.show_title ? r`<p class="media-title">${e.name}</p>` : l}
                ${this._config.show_year && e.year ? r`<p class="media-year">${e.year}</p>` : l}
                ${this._config.show_date_added && e.date_added ? r`<p class="media-date-added">${this._formatDate(e.date_added)}</p>` : l}
              </div>
            ` : l}
        <div class="poster-container" id="poster-${e.id}">
          <div class="poster-inner">
            <img
              class="poster"
              src="${e.poster_url}"
              alt="${e.name}"
              width="140"
              height="210"
              loading="lazy"
              @load="${this._handleImageLoad}"
              @error="${this._handleImageError}"
            />
            <div class="poster-skeleton"></div>
            
            ${a && !o ? r`<span class="media-type-badge ${e.type === "Movie" ? "movie" : "series"}">
                  ${e.type === "Movie" ? "Movie" : "Series"}
                </span>` : l}
            
            ${o ? l : this._renderStatusBadge(e, t)}
            
            ${this._config.show_ratings && i && !o ? r`
                  <span class="rating">
                    <ha-icon icon="mdi:star"></ha-icon>
                    ${i.toFixed(1)}
                  </span>
                ` : l}
            
            ${this._config.show_runtime && e.runtime_minutes && !o ? r`
                  <span class="runtime">
                    <ha-icon icon="mdi:clock-outline"></ha-icon>
                    ${this._formatRuntime(e.runtime_minutes)}
                  </span>
                ` : l}
            
            ${o ? l : r`
            <div class="hover-overlay">
                    ${e.year ? r`<span class="overlay-year">${e.year}</span>` : l}
                    <h3 class="overlay-title">${e.name}</h3>
                    ${this._config.show_genres && e.genres && e.genres.length > 0 ? r`<span class="overlay-genres">${e.genres.slice(0, 3).join(", ")}</span>` : l}
                    ${this._config.show_description_on_hover !== !1 && e.description ? r`<p class="overlay-description">${e.description}</p>` : l}
            </div>`}

            ${this._renderNowPlayingOverlay(e)}
          </div>
        </div>
        
        ${this._config.metadata_position === "below" ? r`
              <div class="media-info-below">
                ${this._config.show_title ? r`<p class="media-title">${e.name}</p>` : l}
                ${this._config.show_year && e.year ? r`<p class="media-year">${e.year}</p>` : l}
                ${this._config.show_date_added && e.date_added ? r`<p class="media-date-added">${this._formatDate(e.date_added)}</p>` : l}
              </div>
            ` : l}
      </div>
    `;
  }
  /**
   * Get rating based on config (IMDB for movies, TMDB for TV)
   */
  _getRating(e) {
    return this._config.rating_source === "auto", e.rating || null;
  }
  /**
   * Format date using Home Assistant's locale
   */
  _formatDate(e) {
    try {
      const t = new Date(e), i = this.hass?.language || "en";
      return new Intl.DateTimeFormat(i, {
        year: "numeric",
        month: "short",
        day: "numeric"
      }).format(t);
    } catch {
      return e;
    }
  }
  /**
   * Format runtime in hours and minutes
   */
  _formatRuntime(e) {
    if (e < 60)
      return `${e}m`;
    const t = Math.floor(e / 60), i = e % 60;
    return i > 0 ? `${t}h ${i}m` : `${t}h`;
  }
  /**
   * Check if item was added within new_badge_days
   */
  _isNewItem(e) {
    if (!this._config.new_badge_days || !e.date_added)
      return !1;
    const t = new Date(e.date_added);
    return ((/* @__PURE__ */ new Date()).getTime() - t.getTime()) / (1e3 * 60 * 60 * 24) <= this._config.new_badge_days;
  }
  /**
   * Start hold timer
   */
  _startHoldTimer(e) {
    this._pressStartTime = Date.now(), this._isHoldActive = !1, this._holdTimer = window.setTimeout(() => {
      this._isHoldActive = !0, this._performAction(e, "hold");
    }, 500);
  }
  /**
   * Clear hold timer
   */
  _clearHoldTimer() {
    this._holdTimer && (clearTimeout(this._holdTimer), this._holdTimer = void 0);
  }
  /**
   * Handle mouse down on media item
   */
  _handleMouseDown(e, t) {
    e.button === 0 && this._startHoldTimer(t);
  }
  /**
   * Handle mouse up on media item
   */
  _handleMouseUp(e, t) {
    this._isHoldActive ? (e.preventDefault(), e.stopPropagation()) : Date.now() - this._pressStartTime < 500 && this._performAction(t, "click"), this._clearHoldTimer();
  }
  /**
   * Handle touch start on media item
   */
  _handleTouchStartItem(e, t) {
    e.touches.length > 0 && (this._itemTouchStartX = e.touches[0].clientX, this._itemTouchStartY = e.touches[0].clientY, e.currentTarget.classList.add("active-press")), this._startHoldTimer(t);
  }
  _handleTouchMoveItem(e, t) {
    if (e.touches.length > 0) {
      const i = Math.abs(e.touches[0].clientX - this._itemTouchStartX), a = Math.abs(e.touches[0].clientY - this._itemTouchStartY);
      (i > 10 || a > 10) && (this._clearHoldTimer(), e.currentTarget.classList.remove("active-press"));
    }
  }
  _handleTouchEndItem(e, t) {
    e.currentTarget.classList.remove("active-press"), this._holdTimer && (clearTimeout(this._holdTimer), this._holdTimer = void 0);
    let a = 0;
    if (e.changedTouches.length > 0) {
      const o = e.changedTouches[0].clientX - this._itemTouchStartX, s = e.changedTouches[0].clientY - this._itemTouchStartY;
      a = Math.sqrt(o * o + s * s);
    }
    if (e.preventDefault(), this._isHoldActive) {
      this._isHoldActive = !1;
      return;
    }
    a > 10 || this._performAction(t, "click");
  }
  /**
   * Check if item is currently playing
   */
  _isItemPlaying(e) {
    if (!this._config.default_cast_device || !this.hass) return !1;
    const t = this.hass.states[this._config.default_cast_device];
    if (!t || t.state !== "playing" && t.state !== "paused" && t.state !== "buffering")
      return !1;
    const i = t.attributes.media_title, a = t.attributes.media_series_title;
    return e.name && (i === e.name || a === e.name) || e.type === "Series" && a === e.name;
  }
  /**
   * Perform configured action
   */
  _performAction(e, t) {
    const i = new CustomEvent("haptic", {
      detail: "selection",
      bubbles: !0,
      composed: !0
    });
    this.dispatchEvent(i);
    const a = t === "click" ? this._config.click_action : this._config.hold_action;
    switch (console.log("JellyHA: performAction", { type: t, action: a, config: this._config, item: e }), a) {
      case "jellyfin":
        window.open(e.jellyfin_url, "_blank");
        break;
      case "cast":
        this._castMedia(e);
        break;
      case "more-info":
        this._showItemDetails(e);
        break;
    }
  }
  /**
   * Cast media to default device
   */
  async _castMedia(e) {
    const t = this._config.default_cast_device;
    if (!t) {
      console.warn("JellyHA: No default cast device configured");
      return;
    }
    try {
      await this.hass.callService("jellyha", "play_on_chromecast", {
        entity_id: t,
        item_id: e.id
      });
    } catch (i) {
      console.error("JellyHA: Failed to cast media", i);
    }
  }
  /**
   * Handle click on media item (for accessibility)
   */
  _handleClick(e) {
    this._performAction(e, "click");
  }
  /**
   * Handle keyboard navigation
   */
  _handleKeydown(e, t) {
    (e.key === "Enter" || e.key === " ") && (e.preventDefault(), this._performAction(t, "click"));
  }
  /**
   * Handle image load - add loaded class for transition
   */
  _handleImageLoad(e) {
    e.target.classList.add("loaded");
  }
  /**
   * Handle image error - could show placeholder
   */
  _handleImageError(e) {
    const t = e.target;
    t.style.display = "none";
  }
  /**
   * Render Now Playing overlay if item matches currently playing media
   */
  _renderNowPlayingOverlay(e) {
    if (!this._config.show_now_playing || !this._isItemPlaying(e))
      return l;
    const t = this.hass.states[this._config.default_cast_device];
    return r`
      <div 
        class="now-playing-overlay" 
        @click="${() => this._handleRewind(this._config.default_cast_device)}"
        @mousedown="${this._stopPropagation}"
        @mouseup="${this._stopPropagation}"
        @touchstart="${this._stopPropagation}"
        @touchend="${this._stopPropagation}"
        @touchcancel="${this._stopPropagation}"
      >
        <span class="now-playing-status">
          ${this._rewindActive ? "REWINDING" : t.state}
        </span>
        <div class="now-playing-controls">
          <ha-icon-button
            class="${this._rewindActive ? "spinning" : ""}"
            .label=${"Play/Pause"}
            @click="${(i) => {
      i.stopPropagation(), this._handlePlayPause(this._config.default_cast_device);
    }}"
          >
            <ha-icon icon="${this._rewindActive ? "mdi:loading" : t.state === "playing" ? "mdi:pause" : "mdi:play"}"></ha-icon>
          </ha-icon-button>
          <ha-icon-button
            class="stop"
            .label=${"Stop"}
            @click="${(i) => {
      i.stopPropagation(), this._handleStop(this._config.default_cast_device);
    }}"
          >
            <ha-icon icon="mdi:stop"></ha-icon>
          </ha-icon-button>
        </div>
      </div>
    `;
  }
  _stopPropagation(e) {
    e.stopPropagation();
  }
  /**
   * Toggle play/pause on player
   */
  _handlePlayPause(e) {
    const t = new CustomEvent("haptic", {
      detail: "selection",
      bubbles: !0,
      composed: !0
    });
    this.dispatchEvent(t), this.hass.callService("media_player", "media_play_pause", { entity_id: e });
  }
  /**
   * Stop playback on player
   */
  _handleStop(e) {
    const t = new CustomEvent("haptic", {
      detail: "selection",
      bubbles: !0,
      composed: !0
    });
    this.dispatchEvent(t), this.hass.callService("media_player", "turn_off", { entity_id: e });
  }
  /**
   * Handle rewind on overlay click
   */
  _handleRewind(e) {
    this._rewindActive = !0, setTimeout(() => {
      this._rewindActive = !1;
    }, 2e3);
    const t = new CustomEvent("haptic", {
      detail: "selection",
      bubbles: !0,
      composed: !0
    });
    this.dispatchEvent(t);
    const i = this.hass.states[e];
    if (i && i.attributes.media_position) {
      const a = i.attributes.media_position, o = i.attributes.media_position_updated_at;
      let s = a;
      if (o) {
        const d = (/* @__PURE__ */ new Date()).getTime(), c = new Date(o).getTime(), p = (d - c) / 1e3;
        i.state === "playing" && (s += p);
      }
      const n = Math.max(0, s - 20);
      this.hass.callService("media_player", "media_seek", {
        entity_id: e,
        seek_position: n
      });
    }
  }
  /**
   * Render empty state
   */
  _renderEmpty() {
    return r`
      <div class="empty">
        <ha-icon icon="mdi:movie-open-outline"></ha-icon>
        <p>${V(this.hass.language, "no_media")}</p>
      </div>
    `;
  }
  /**
   * Render error state
   */
  _renderError(e) {
    return r`
      <ha-card>
        <div class="error">
          <ha-icon icon="mdi:alert-circle"></ha-icon>
          <p>${e}</p>
        </div>
      </ha-card>
    `;
  }
  _showItemDetails(e) {
    this._modal && this._modal.showDialog({
      item: e,
      hass: this.hass,
      defaultCastDevice: this._config.default_cast_device
    });
  }
};
m.styles = Jt;
_([
  E({ attribute: !1 })
], m.prototype, "hass", 2);
_([
  f()
], m.prototype, "_config", 2);
_([
  f()
], m.prototype, "_currentPage", 2);
_([
  f()
], m.prototype, "_itemsPerPage", 2);
_([
  f()
], m.prototype, "_pressStartTime", 2);
_([
  f()
], m.prototype, "_holdTimer", 2);
_([
  f()
], m.prototype, "_isHoldActive", 2);
_([
  f()
], m.prototype, "_rewindActive", 2);
_([
  f()
], m.prototype, "_items", 2);
_([
  f()
], m.prototype, "_error", 2);
_([
  f()
], m.prototype, "_lastUpdate", 2);
_([
  qt("jellyha-item-details-modal")
], m.prototype, "_modal", 2);
_([
  f()
], m.prototype, "_scrollProgress", 2);
_([
  f()
], m.prototype, "_hasScrollableContent", 2);
m = _([
  U("jellyha-library-card")
], m);
var ae = Object.defineProperty, oe = Object.getOwnPropertyDescriptor, ot = (e, t, i, a) => {
  for (var o = a > 1 ? void 0 : a ? oe(t, i) : t, s = e.length - 1, n; s >= 0; s--)
    (n = e[s]) && (o = (a ? n(t, i, o) : n(o)) || o);
  return a && o && ae(t, i, o), o;
};
function se(e, t, i) {
  const a = new CustomEvent(t, {
    bubbles: !0,
    composed: !0,
    detail: i
  });
  e.dispatchEvent(a);
}
let R = class extends w {
  setConfig(e) {
    this._config = e;
  }
  render() {
    if (!this.hass || !this._config)
      return r``;
    const e = Object.keys(this.hass.states).filter(
      (t) => t.startsWith("sensor.jellyha_now_playing_")
    );
    return r`
      <div class="card-config">
        <div class="form-row">
          <ha-select
            label="Now Playing Sensor"
            .value=${this._config.entity || ""}
            @selected=${this._entityChanged}
            @closed=${(t) => t.stopPropagation()}
          >
            ${e.map(
      (t) => r`
                <mwc-list-item .value=${t}>
                  ${this.hass.states[t].attributes.friendly_name || t}
                </mwc-list-item>
              `
    )}
          </ha-select>
        </div>

        <div class="form-row">
          <ha-textfield
            label="Title (Optional)"
            .value=${this._config.title || ""}
            @input=${this._titleChanged}
          ></ha-textfield>
        </div>

        <div class="checkbox-row">
          <ha-switch
            .checked=${this._config.show_title !== !1}
            @change=${this._showTitleChanged}
          ></ha-switch>
          <span>Show Title</span>
        </div>

        <div class="checkbox-row">
          <ha-switch
            .checked=${this._config.show_media_type_badge !== !1}
            @change=${this._showMediaTypeBadgeChanged}
          ></ha-switch>
          <span>Show Media Type Badge</span>
        </div>

        <div class="checkbox-row">
          <ha-switch
            .checked=${this._config.show_year !== !1}
            @change=${this._showYearChanged}
          ></ha-switch>
          <span>Show Year</span>
        </div>

        <div class="checkbox-row">
          <ha-switch
            .checked=${this._config.show_runtime === !0}
            @change=${this._showRuntimeChanged}
          ></ha-switch>
          <span>Show Runtime</span>
        </div>

        <div class="checkbox-row">
          <ha-switch
            .checked=${this._config.show_ratings === !0}
            @change=${this._showRatingsChanged}
          ></ha-switch>
          <span>Show Rating</span>
        </div>

        <div class="checkbox-row">
          <ha-switch
            .checked=${this._config.show_genres === !0}
            @change=${this._showGenresChanged}
          ></ha-switch>
          <span>Show Genre</span>
        </div>

        <div class="checkbox-row">
          <ha-switch
            .checked=${this._config.show_client !== !1}
            @change=${this._showClientChanged}
          ></ha-switch>
          <span>Show Jellyfin Client</span>
        </div>

        <div class="checkbox-row">
          <ha-switch
            .checked=${this._config.show_background === !0}
            @change=${this._showBackgroundChanged}
          ></ha-switch>
          <span>Show Background</span>
        </div>
      </div>
    `;
  }
  _entityChanged(e) {
    const t = e.target;
    this._updateConfig("entity", t.value);
  }
  _titleChanged(e) {
    const t = e.target;
    this._updateConfig("title", t.value);
  }
  _showTitleChanged(e) {
    const t = e.target;
    this._updateConfig("show_title", t.checked);
  }
  _showMediaTypeBadgeChanged(e) {
    const t = e.target;
    this._updateConfig("show_media_type_badge", t.checked);
  }
  _showRatingsChanged(e) {
    const t = e.target;
    this._updateConfig("show_ratings", t.checked);
  }
  _showRuntimeChanged(e) {
    const t = e.target;
    this._updateConfig("show_runtime", t.checked);
  }
  _showGenresChanged(e) {
    const t = e.target;
    this._updateConfig("show_genres", t.checked);
  }
  _showYearChanged(e) {
    const t = e.target;
    this._updateConfig("show_year", t.checked);
  }
  _showClientChanged(e) {
    const t = e.target;
    this._updateConfig("show_client", t.checked);
  }
  _showBackgroundChanged(e) {
    const t = e.target;
    this._updateConfig("show_background", t.checked);
  }
  _updateConfig(e, t) {
    if (!this._config)
      return;
    const i = { ...this._config, [e]: t };
    this._config = i, se(this, "config-changed", { config: i });
  }
};
R.styles = N`
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
ot([
  E({ attribute: !1 })
], R.prototype, "hass", 2);
ot([
  f()
], R.prototype, "_config", 2);
R = ot([
  U("jellyha-now-playing-editor")
], R);
var ne = Object.defineProperty, re = Object.getOwnPropertyDescriptor, L = (e, t, i, a) => {
  for (var o = a > 1 ? void 0 : a ? re(t, i) : t, s = e.length - 1, n; s >= 0; s--)
    (n = e[s]) && (o = (a ? n(t, i, o) : n(o)) || o);
  return a && o && ne(t, i, o), o;
};
window.customCards = window.customCards || [];
window.customCards.push({
  type: "jellyha-now-playing-card",
  name: "JellyHA Now Playing",
  description: "Display currently playing media from Jellyfin",
  preview: !0
});
let k = class extends w {
  constructor() {
    super(...arguments), this._rewindActive = !1, this._overflowState = 0, this._phrases = [];
  }
  setConfig(e) {
    this._config = {
      show_title: !0,
      show_media_type_badge: !0,
      show_year: !0,
      show_client: !0,
      show_background: !0,
      show_genres: !0,
      show_ratings: !0,
      show_runtime: !0,
      ...e
    };
  }
  static getConfigElement() {
    return document.createElement("jellyha-now-playing-editor");
  }
  static getStubConfig(e) {
    return {
      entity: Object.keys(e.states).find((a) => a.startsWith("sensor.jellyha_now_playing_")) || "",
      show_title: !0,
      show_media_type_badge: !0,
      show_year: !0,
      show_client: !0,
      show_background: !0,
      show_genres: !0,
      show_ratings: !0,
      show_runtime: !0
    };
  }
  getCardSize() {
    return 3;
  }
  getLayoutOptions() {
    return {
      grid_rows: 3,
      grid_columns: 12
    };
  }
  getGridOptions() {
    return {
      columns: 12,
      rows: 3,
      min_columns: 6,
      min_rows: 3,
      max_rows: 5
    };
  }
  render() {
    if (!this.hass || !this._config)
      return r``;
    const e = this._config.entity;
    if (!e)
      return this._renderError("Please configure a JellyHA Now Playing sensor entity");
    const t = this.hass.states[e];
    if (!t)
      return this._renderError(V(this.hass.language, "entity_not_found") || "Entity not found");
    const i = t.attributes;
    if (!!!i.item_id)
      return this._renderEmpty();
    const o = i.progress_percent || 0, s = i.image_url, n = i.backdrop_url, d = this._config.show_background && n, c = i.is_paused;
    return r`
            <ha-card class="jellyha-now-playing ${d ? "has-background" : ""} ${this._config.title ? "has-title" : ""}">
                ${d ? r`
                    <div class="card-background" style="background-image: url('${n}')"></div>
                    <div class="card-overlay"></div>
                ` : l}
                
                <div class="card-content">
                    ${this._config.title ? r`
                        <div class="card-header">${this._config.title}</div>
                    ` : l}
                    
                    <div class="main-container">
                        ${s ? r`
                            <div class="poster-container" @click=${this._handlePosterRewind}>
                                <img src="${s}" alt="${i.title}" />
                                ${this._rewindActive ? r`
                                    <div class="rewind-overlay">
                                        <span>REWINDING</span>
                                    </div>
                                ` : l}
                            </div>
                        ` : l}
                        
                        <div class="info-container">
                            <div class="info-top">
                                <div class="header">
                                    ${this._config.show_title !== !1 ? r`<div class="title">${i.title}</div>` : l}
                                    ${i.series_title ? r`<div class="series">${i.series_title}</div>` : l}
                                    ${this._config.show_client !== !1 ? r`
                                        <div class="device-info">
                                            <span>${i.device_name} (${i.client})</span>
                                        </div>
                                    ` : l}
                                </div>

                                ${this._overflowState < 2 ? r`
                                    <div class="meta-container">
                                        ${this._config.show_media_type_badge !== !1 ? r`
                                            <span class="badge meta-priority-4 ${i.media_type?.toLowerCase()}">${i.media_type}</span>
                                        ` : l}
                                        ${this._config.show_year !== !1 && i.year ? r`
                                            <span class="meta-item meta-priority-3">${i.year}</span>
                                        ` : l}
                                        ${this._config.show_runtime && i.runtime_minutes ? r`
                                            <span class="meta-item meta-priority-2">${i.runtime_minutes} min</span>
                                        ` : l}
                                        ${this._config.show_ratings && i.community_rating ? r`
                                            <span class="meta-item external-rating meta-priority-1">
                                                <ha-icon icon="mdi:star"></ha-icon>
                                                <span>${i.community_rating.toFixed(1)}</span>
                                            </span>
                                        ` : l}
                                    </div>
                                ` : l}

                                ${this._overflowState < 1 && this._config.show_genres && i.genres?.length ? r`
                                    <div class="genres-container meta-priority-0">
                                        <div class="genres">${i.genres.join(", ")}</div>
                                    </div>
                                ` : l}
                            </div>

                            <div class="info-bottom">
                                <div class="controls-container">
                                    ${this._config.show_client !== !1 ? r`
                                        <div class="device-info bottom-device-info">
                                            <span>${i.device_name} (${i.client})</span>
                                        </div>
                                    ` : l}

                                    <div class="playback-controls">
                                        ${this._rewindActive ? r`
                                            <ha-icon-button class="spinning" .label=${"Loading"}>
                                                <ha-icon icon="mdi:loading"></ha-icon>
                                            </ha-icon-button>
                                        ` : c ? r`
                                            <ha-icon-button .label=${"Play"} @click=${() => this._handleControl("Unpause")}>
                                                <ha-icon icon="mdi:play"></ha-icon>
                                            </ha-icon-button>
                                        ` : r`
                                            <ha-icon-button .label=${"Pause"} @click=${() => this._handleControl("Pause")}>
                                                <ha-icon icon="mdi:pause"></ha-icon>
                                            </ha-icon-button>
                                        `}
                                        <ha-icon-button .label=${"Stop"} @click=${() => this._handleControl("Stop")}>
                                            <ha-icon icon="mdi:stop"></ha-icon>
                                        </ha-icon-button>
                                    </div>
                                </div>

                                <div class="progress-container" @click=${this._handleSeek}>
                                    <div class="progress-bar">
                                        <div class="progress-fill" style="width: ${o}%"></div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </ha-card>
        `;
  }
  async _fetchPhrases() {
    if (!(this._phrases.length > 0))
      try {
        const e = await fetch("/jellyha_static/now_playing_phrases.json");
        e.ok && (this._phrases = await e.json());
      } catch (e) {
        console.warn("JellyHA: Could not fetch phrases.json", e);
      }
  }
  _renderEmpty() {
    this._fetchPhrases();
    const t = this.hass.themes?.darkMode ? "https://raw.githubusercontent.com/home-assistant/brands/master/custom_integrations/jellyha/dark_logo.png" : "https://raw.githubusercontent.com/home-assistant/brands/master/custom_integrations/jellyha/logo.png", i = "https://raw.githubusercontent.com/home-assistant/brands/master/custom_integrations/jellyha/icon.png";
    let a = "Nothing is currently playing";
    if (this._phrases.length > 0) {
      const s = Math.floor(Date.now() / 864e5) % this._phrases.length;
      a = this._phrases[s];
      const n = Object.keys(this.hass.states).find((c) => c.startsWith("sensor.") && c.endsWith("_unwatched")), d = n ? this.hass.states[n].state : "0";
      a = a.replace(/\[number\]/g, d);
    }
    return r`
            <ha-card class="jellyha-now-playing empty-state">
                <div class="card-content">
                    <div class="logo-container full-logo">
                        <img src="${t}" alt="JellyHA Logo" />
                    </div>
                    <div class="logo-container mini-icon">
                        <img src="${i}" alt="JellyHA Icon" />
                    </div>
                    <p>${a}</p>
                </div>
            </ha-card>
        `;
  }
  _renderError(e) {
    return r`
            <ha-card class="error-state">
                <div class="card-content">
                    <p>${e}</p>
                </div>
            </ha-card>
        `;
  }
  async _handleControl(e) {
    const i = this.hass.states[this._config.entity]?.attributes.session_id;
    i && await this.hass.callService("jellyha", "session_control", {
      session_id: i,
      command: e
    });
  }
  async _handleSeek(e) {
    const t = e.currentTarget.getBoundingClientRect(), i = (e.clientX - t.left) / t.width, a = this.hass.states[this._config.entity];
    if (!a) return;
    const o = a.attributes, s = o.session_id, n = o.position_ticks || 0, d = o.progress_percent || 1, c = n / d * 100;
    if (!s || !c) return;
    const p = Math.round(c * i);
    await this.hass.callService("jellyha", "session_seek", {
      session_id: s,
      position_ticks: p
    });
  }
  async _handlePosterRewind() {
    const e = this.hass.states[this._config.entity];
    if (!e) return;
    const t = e.attributes, i = t.session_id, a = t.position_ticks || 0;
    if (!i) return;
    this._rewindActive = !0, setTimeout(() => {
      this._rewindActive = !1;
    }, 1e3);
    const o = new CustomEvent("haptic", {
      detail: "selection",
      bubbles: !0,
      composed: !0
    });
    this.dispatchEvent(o);
    const s = 20 * 1e7, n = Math.max(0, a - s);
    await this.hass.callService("jellyha", "session_seek", {
      session_id: i,
      position_ticks: n
    });
  }
  connectedCallback() {
    super.connectedCallback(), this._resizeObserver = new ResizeObserver(() => {
      this._checkLayout();
    }), this._resizeObserver.observe(this);
  }
  disconnectedCallback() {
    super.disconnectedCallback(), this._resizeObserver && this._resizeObserver.disconnect();
  }
  updated(e) {
    super.updated(e), e.has("hass") && this._checkLayout();
  }
  _checkLayout() {
    requestAnimationFrame(() => {
      this._doLayoutCheck();
    });
  }
  _doLayoutCheck() {
    const e = this.shadowRoot?.querySelector(".title"), t = this.shadowRoot?.querySelector(".info-bottom");
    if (!e || !t) return;
    const i = this.getBoundingClientRect(), a = e.getBoundingClientRect(), n = t.getBoundingClientRect().top - i.top - 8, d = 28, c = 22, g = a.bottom - i.top + d, h = g + c;
    let u = 0;
    h > n && (u = 1), g > n && (u = 2), this._overflowState !== u && (this._overflowState = u);
  }
};
k.styles = N`
        :host {
            display: block;
            height: 100%;
            overflow: hidden;
        }
        ha-card {
            height: 100%;
            overflow: hidden;
        }
        .jellyha-now-playing {
            overflow: hidden;
            position: relative;
            background: var(--ha-card-background, var(--card-background-color, #fff));
            border-radius: var(--ha-card-border-radius, 12px);
            transition: all 0.3s ease-out;
            container-type: size;
            container-name: now-playing;
            height: 100%;
            display: flex;
            flex-direction: column;
            box-sizing: border-box;
            min-height: 0;
            padding: 0;
        }
        .jellyha-now-playing.has-background {
            background: transparent;
            color: white;
        }
        .jellyha-now-playing.has-background .title,
        .jellyha-now-playing.has-background .series,
        .jellyha-now-playing.has-background .device-info,
        .jellyha-now-playing.has-background .meta-item,
        .jellyha-now-playing.has-background .genres,
        .jellyha-now-playing.has-background .card-header,
        .jellyha-now-playing.has-background ha-icon-button {
            color: #fff !important;
            text-shadow: 0 1px 4px rgba(0,0,0,0.5);
        }
        .jellyha-now-playing.has-background .badge {
            box-shadow: 0 2px 4px rgba(0,0,0,0.3);
        }
        .jellyha-now-playing.has-background .playback-controls ha-icon-button {
            background: rgba(255, 255, 255, 0.15);
        }
        .jellyha-now-playing.has-background .playback-controls ha-icon-button:hover {
            background: rgba(255, 255, 255, 0.25);
        }
        /* Further increase padding when background is on for better balance */
        .jellyha-now-playing.has-background .card-content {
            padding: 24px 20px 12px !important;
        }
        .card-background {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-size: cover;
            background-position: center;
            filter: blur(5px) brightness(0.6);
            transform: scale(1.02);
            z-index: 0;
            transition: background-image 0.5s ease-in-out;
        }
        .card-overlay {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: linear-gradient(to bottom, rgba(0,0,0,0.2) 0%, rgba(0,0,0,0.6) 100%);
            z-index: 1;
        }
        .card-content {
            position: relative;
            z-index: 2;
            padding: 20px !important;
            display: flex;
            flex-direction: column;
            gap: 16px;
            height: 100%;
            box-sizing: border-box;
            overflow: visible; /* Allow poster pop-out */
        }
        .card-header {
            font-size: 1.25rem;
            font-weight: 500;
            color: var(--primary-text-color);
            line-height: 1.2;
            flex: 0 0 auto;
        }
        .main-container {
            display: flex;
            gap: 20px;
            align-items: flex-start;
            flex: 1;
            min-height: 0; /* Crucial for nested flex scrolling/hiding */
            overflow: visible;
        }
        .poster-container {
            flex: 0 0 auto;
            height: 100%;
            aspect-ratio: 2 / 3;
            max-height: 100%;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 8px 16px rgba(0,0,0,0.4);
            transition: transform 0.2s ease-in-out;
            position: relative;
            cursor: pointer;
        }
        .poster-container:hover {
            transform: scale(1.02);
        }
        .poster-container img {
            width: 100%;
            height: 100%;
            object-fit: cover;
        }
        .rewind-overlay {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.4);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 10;
            animation: fadeIn 0.2s ease-out;
        }
        .rewind-overlay span {
            color: white;
            font-weight: 700;
            font-size: 0.8rem; /* Small fixed size */
            letter-spacing: 0.5px;
            background: var(--primary-color);
            padding: 2px 6px;
            border-radius: 4px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.3);
            transform: translateY(-8px);
            white-space: nowrap; /* Prevent wrapping */
        }
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
        @keyframes spin {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }
        .playback-controls .spinning ha-icon {
            animation: spin 1s linear infinite;
        }
        .info-container {
            flex: 1;
            display: flex;
            flex-direction: column;
            height: 100%;
            min-height: 0; /* Crucial */
            min-width: 0;
            overflow: hidden;
        }
        .info-top {
            flex: 1 1 auto; /* Can shrink and grow */
            min-height: 0; /* Allows shrinking below content size */
            overflow: visible; /* Hide overflow content */
            display: flex;
            flex-direction: column;
            margin-bottom: 0;
            padding-bottom: 4px; /* Prevent text clipping at bottom */
        }
        .header {
            margin-bottom: 0px;
            flex-shrink: 0; /* Don't squash the title too easily if possible */
        }
        .title {
            font-size: 1.4rem;
            font-weight: 700;
            line-height: 1.2;
            color: var(--primary-text-color);
            margin-bottom: 2px;
        }
        .series {
            font-size: 1.1rem;
            color: var(--secondary-text-color);
            font-weight: 500;
        }
        .device-info {
            display: flex;
            align-items: center;
            gap: 6px;
            font-size: 0.95rem;
            color: var(--secondary-text-color);
            margin-top: 8px;
            opacity: 0.8;
        }
        .device-info ha-icon {
            --mdc-icon-size: 18px;
        }
        .meta-container {
            display: flex;
            flex-wrap: nowrap;
            gap: 12px;
            align-items: center;
            white-space: nowrap;
        }

        .bottom-device-info {
            display: flex;
            align-items: center;
            gap: 6px;
            font-size: 0.8rem;
            color: var(--secondary-text-color);
            margin-right: auto; /* Push controls to right */
            opacity: 0.8;
        }

        /* Default: Hide top device info, show bottom device info */
        .info-top .device-info {
            display: none;
        }
        
        /* Ensure controls spread out when bottom info is present */
        .controls-container {
            justify-content: space-between;
            align-items: center;
        }
        
        /* When card is too narrow, HIDE bottom device info to prevent crowding */
        @container now-playing (max-width: 350px) {
            .bottom-device-info {
                display: none !important;
            }
            .controls-container {
                justify-content: flex-end; /* Revert to right align */
            }
        }
        
        /* For 5+ row cards, hide device info sooner to prevent overflow */
        @container now-playing (min-height: 300px) and (max-width: 430px) {
            .bottom-device-info {
                display: none !important;
            }
        }
        
        /* Progressive metadata hiding based on priority */
        /* Hide genres first (priority 0) */
        @container now-playing (max-width: 400px) {
            .meta-priority-0 {
                display: none !important;
            }
        }
        
        /* Hide rating (priority 1) */
        @container now-playing (max-width: 370px) {
            .meta-priority-1 {
                display: none !important;
            }
        }
        
        /* Hide runtime (priority 2) */
        @container now-playing (max-width: 320px) {
            .meta-priority-2 {
                display: none !important;
            }
        }
        
        /* Hide year (priority 3) */
        @container now-playing (max-width: 260px) {
            .meta-priority-3 {
                display: none !important;
            }
        }
        
        /* Hide badge last (priority 4) - only in ultra-compact mode */
        @container now-playing (max-width: 220px) {
            .meta-priority-4 {
                display: none !important;
            }
        }
        
        /* Hide badge when card has title AND is short AND narrow (3 rows × 6 columns) to prevent overlap with controls */
        .has-title .meta-priority-4 {
            /* Default: show the badge */
        }
        @container now-playing (max-height: 180px) and (max-width: 320px) {
            .has-title .meta-priority-4 {
                display: none !important;
            }
        }

        /* When card is tall enough (4+ rows ≈ 240px), enable wrapping instead of hiding */
        @container now-playing (min-height: 240px) {
            .meta-container {
                flex-wrap: wrap;
                white-space: normal;
            }
            .info-top {
                overflow: visible;
            }
        }
        
        /* When tall AND narrow, show items that would normally hide (they'll wrap instead) */
        @container now-playing (min-height: 240px) and (max-width: 400px) {
            .meta-priority-0 {
                display: block !important;
            }
        }
        @container now-playing (min-height: 240px) and (max-width: 370px) {
            .meta-priority-1 {
                display: flex !important;
            }
        }
        @container now-playing (min-height: 240px) and (max-width: 320px) {
            .meta-priority-2 {
                display: flex !important;
            }
        }
        @container now-playing (min-height: 240px) and (max-width: 260px) {
            .meta-priority-3 {
                display: flex !important;
            }
        }
        .badge {
            padding: 2px 8px 1px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 800;
            background: var(--primary-color);
            color: white;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            flex-shrink: 0; /* Prevent badge from shrinking */
            overflow: visible; /* Ensure rounded corners aren't clipped */
        }
        .badge.movie { background-color: #AA5CC3; }
        .badge.series { background-color: #F2A218; }
        .badge.episode { background-color: #F59E0B; }

        .meta-item {
            color: var(--secondary-text-color);
            font-size: 0.9rem;
            font-weight: 500;
        }
        .meta-item.external-rating {
            display: flex;
            align-items: center;
            gap: 4px;
            background: rgba(var(--rgb-primary-text-color), 0.08);
            padding: 2px 0px;
            border-radius: 4px;
            border: 1px solid rgba(var(--rgb-primary-text-color), 0.1);
        }
        .meta-item.external-rating ha-icon {
            --mdc-icon-size: 14px;
            color: #F59E0B;
        }
        .genres-container {
            flex-shrink: 0;
            overflow: visible;
            margin-bottom: -4px;
            position: relative;
            z-index: 4; /* Ensure it stays above other elements if needed */
        }
        .genres {
            font-size: 0.95rem;
            color: var(--secondary-text-color);
            margin: 0;
            font-style: italic;
            opacity: 0.7;
            white-space: nowrap;
            text-overflow: ellipsis;
            overflow: hidden;
        }
        .info-bottom {
            flex: 0 0 auto; /* Never shrink */
            width: 100%;
            margin-top: auto;
            z-index: 5;
        }
        .controls-container {
            display: flex;
            justify-content: flex-end;
            margin-bottom: 6px;
        }
        .playback-controls {
            display: flex;
            gap: 12px;
            align-items: center;
        }
        .playback-controls ha-icon-button {
            --mdc-icon-button-size: 40px;
            --mdc-icon-size: 28px;
            color: var(--primary-text-color);
            background: rgba(var(--rgb-primary-text-color), 0.05);
            border-radius: 50%;
            transition: background 0.2s;
        }
        .playback-controls ha-icon-button:hover {
            background: rgba(var(--rgb-primary-text-color), 0.1);
        }
        .playback-controls ha-icon-button ha-icon {
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .progress-container {
            height: 6px;
            background: rgba(var(--rgb-primary-text-color), 0.15); /* Slightly darker for visibility */
            cursor: pointer;
            position: relative;
            border-radius: 3px;
            overflow: hidden;
            width: 100%;
        }
        .has-background .progress-container {
            background: rgba(255, 255, 255, 0.2); /* Much clearer on backdrop */
        }
        .progress-bar {
            height: 100%;
            width: 100%;
        }
        .progress-fill {
            height: 100%;
            background: var(--primary-color);
            transition: width 1s linear;
        }
        .empty-state, .error-state {
            text-align: center;
            padding: 20px;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            height: 100%;
            box-sizing: border-box;
        }
        .empty-state .card-content {
            padding: 0 !important;
            gap: 8px;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            overflow: visible;
            height: auto;
        }
        .empty-state .logo-container.mini-icon {
            display: none;
        }
        .empty-state .logo-container.full-logo {
            display: flex;
            justify-content: center;
            opacity: 0.9;
            margin-bottom: 4px;
        }
        .empty-state img {
            max-width: 200px;
            height: auto;
        }
        .empty-state p {
            margin: 0;
            color: var(--secondary-text-color);
            font-size: 0.9rem;
            opacity: 0.7;
        }

        /* Container Queries for Responsive Information Throttling */
        @container now-playing (max-width: 250px) {
            .empty-state .logo-container.full-logo {
                display: none;
            }
            .empty-state .logo-container.mini-icon {
                display: flex;
                opacity: 0.9;
                margin-bottom: 12px;
            }
            .empty-state img {
                max-width: 80px;
            }
            .empty-state p {
                font-size: 0.9rem;
            }
        }

        /* Standard Tier Hiding (Width based) */
        @container now-playing (max-width: 320px) {
            .genres, .device-info {
                display: none !important;
            }
            .title {
                font-size: 1.25rem;
                margin-bottom: 2px;
            }
        }

        /* Vertical Tier Hiding (Height based - for very short cards) */
        @container now-playing (max-height: 160px) {
            .genres, .device-info {
                display: none !important;
            }
            .meta-container, .card-header {
                display: none !important;
            }
            .meta-container {
                margin-top: 4px;
            }
            .title {
                font-size: 1.2rem;
                line-height: 1.1;
                margin-bottom: 2px;
            }
            .main-container {
                gap: 12px;
            }
            .card-content {
                gap: 8px;
            }
            .info-top {
                justify-content: center;
            }
        }

        @container now-playing (max-width: 280px) {
           .main-container {
                gap: 12px;
            }
            .poster-container {
                flex: 0 0 80px;
                height: 120px;
            }
            .title {
                font-size: 1.1rem;
                display: -webkit-box;
                -webkit-line-clamp: 2;
                -webkit-box-orient: vertical;
                overflow: hidden;
            }
        }

        /* Ultra-Compact Micro Mode (Overlay controls on poster) */
        @container now-playing (max-width: 220px) {
            .card-header, .info-top {
                display: none !important;
            }
            .card-content {
                padding: 10px !important;
                justify-content: center;
                gap: 0;
            }
            .main-container {
                justify-content: center;
                gap: 0;
                position: relative;
                width: 100%;
            }
            .poster-container {
                flex: 0 0 auto !important;
                height: 100% !important;
                aspect-ratio: 2 / 3;
                box-shadow: 0 4px 12px rgba(0,0,0,0.5);
            }
            .info-container {
                position: absolute;
                top: 0;
                left: 50%;
                transform: translateX(-50%);
                width: auto;
                height: 100%;
                aspect-ratio: 2 / 3;
                background: linear-gradient(to bottom, transparent 30%, rgba(0,0,0,0.6) 80%, rgba(0,0,0,0.85) 100%);
                display: flex;
                flex-direction: column;
                justify-content: flex-end;
                border-radius: 8px;
                padding: 10px;
                box-sizing: border-box;
                pointer-events: none;
                z-index: 5;
                overflow: visible;
            }
            .info-bottom {
                pointer-events: auto;
                flex: 0 0 auto;
            }
            .controls-container {
                justify-content: center;
                margin-bottom: 8px;
            }
            .playback-controls ha-icon-button {
                --mdc-icon-button-size: 40px;
                --mdc-icon-size: 28px;
                background: rgba(255, 255, 255, 0.2);
                color: white !important;
            }
            .progress-container {
                height: 4px;
                background: rgba(255, 255, 255, 0.3);
            }
            .progress-fill {
                background: #18BCF2;
            }
            .rewind-overlay span {
                font-size: 0.75rem !important;
                padding: 2px 5px !important;
                white-space: nowrap;
            }
        }

        /* Height-Based Compact Mode (Overlay controls when vertically constrained) */
        @container now-playing (max-height: 180px) {
            .card-header, .info-top {
                display: none !important;
            }
            .card-content {
                padding: 10px !important;
                justify-content: center;
                gap: 0;
            }
            .main-container {
                justify-content: center;
                gap: 0;
                position: relative;
                width: 100%;
            }
            .poster-container {
                flex: 0 0 auto !important;
                height: 100% !important;
                aspect-ratio: 2 / 3;
                box-shadow: 0 4px 12px rgba(0,0,0,0.5);
            }
            .info-container {
                position: absolute;
                top: 0;
                left: 50%;
                transform: translateX(-50%);
                width: auto;
                height: 100%;
                aspect-ratio: 2 / 3;
                background: linear-gradient(to bottom, transparent 30%, rgba(0,0,0,0.6) 80%, rgba(0,0,0,0.85) 100%);
                display: flex;
                flex-direction: column;
                justify-content: flex-end;
                border-radius: 8px;
                padding: 10px;
                box-sizing: border-box;
                pointer-events: none;
                z-index: 5;
                overflow: visible;
            }
            .info-bottom {
                pointer-events: auto;
                flex: 0 0 auto;
            }
            .controls-container {
                justify-content: center;
                margin-bottom: 8px;
            }
            .playback-controls ha-icon-button {
                --mdc-icon-button-size: 40px;
                --mdc-icon-size: 28px;
                background: rgba(255, 255, 255, 0.2);
                color: white !important;
            }
            .progress-container {
                height: 4px;
                background: rgba(255, 255, 255, 0.3);
            }
            .progress-fill {
                background: #18BCF2;
            }
            .rewind-overlay span {
                font-size: 0.75rem !important;
                padding: 2px 5px !important;
                white-space: nowrap;
            }
        }

        /* Tall but Narrow Mode - When card is 4+ rows but too narrow for side layout */
        @container now-playing (min-height: 240px) and (max-width: 300px) {
            .card-header, .info-top {
                display: none !important;
            }
            .card-content {
                padding: 10px !important;
                justify-content: center;
                gap: 0;
            }
            .main-container {
                justify-content: center;
                gap: 0;
                position: relative;
                width: 100%;
            }
            .poster-container {
                flex: 0 0 auto !important;
                height: 100% !important;
                aspect-ratio: 2 / 3;
                box-shadow: 0 4px 12px rgba(0,0,0,0.5);
            }
            .info-container {
                position: absolute;
                top: 0;
                left: 50%;
                transform: translateX(-50%);
                width: auto;
                height: 100%;
                aspect-ratio: 2 / 3;
                background: linear-gradient(to bottom, transparent 30%, rgba(0,0,0,0.6) 80%, rgba(0,0,0,0.85) 100%);
                display: flex;
                flex-direction: column;
                justify-content: flex-end;
                border-radius: 8px;
                padding: 10px;
                box-sizing: border-box;
                pointer-events: none;
                z-index: 5;
                overflow: visible;
            }
            .info-bottom {
                pointer-events: auto;
                flex: 0 0 auto;
            }
            .controls-container {
                justify-content: center;
                margin-bottom: 8px;
            }
            .playback-controls ha-icon-button {
                --mdc-icon-button-size: 40px;
                --mdc-icon-size: 28px;
                background: rgba(255, 255, 255, 0.2);
                color: white !important;
            }
            .progress-container {
                height: 4px;
                background: rgba(255, 255, 255, 0.3);
            }
            .progress-fill {
                background: #18BCF2;
            }
            .rewind-overlay span {
                font-size: 0.75rem !important;
                padding: 2px 5px !important;
                white-space: nowrap;
            }
        }

        /* Very Tall but Narrow Mode - When card is 5+ rows and < 9 columns */
        @container now-playing (min-height: 300px) and (max-width: 350px) {
            .card-header, .info-top {
                display: none !important;
            }
            .card-content {
                padding: 10px !important;
                justify-content: center;
                gap: 0;
            }
            .main-container {
                justify-content: center;
                gap: 0;
                position: relative;
                width: 100%;
            }
            .poster-container {
                flex: 0 0 auto !important;
                height: 100% !important;
                aspect-ratio: 2 / 3;
                box-shadow: 0 4px 12px rgba(0,0,0,0.5);
            }
            .info-container {
                position: absolute;
                top: 0;
                left: 50%;
                transform: translateX(-50%);
                width: auto;
                height: 100%;
                aspect-ratio: 2 / 3;
                background: linear-gradient(to bottom, transparent 30%, rgba(0,0,0,0.6) 80%, rgba(0,0,0,0.85) 100%);
                display: flex;
                flex-direction: column;
                justify-content: flex-end;
                border-radius: 8px;
                padding: 10px;
                box-sizing: border-box;
                pointer-events: none;
                z-index: 5;
                overflow: visible;
            }
            .info-bottom {
                pointer-events: auto;
                flex: 0 0 auto;
            }
            .controls-container {
                justify-content: center;
                margin-bottom: 8px;
            }
            .playback-controls ha-icon-button {
                --mdc-icon-button-size: 40px;
                --mdc-icon-size: 28px;
                background: rgba(255, 255, 255, 0.2);
                color: white !important;
            }
            .progress-container {
                height: 4px;
                background: rgba(255, 255, 255, 0.3);
            }
            .progress-fill {
                background: #18BCF2;
            }
            /* Scale down rewind overlay for compact mode */
            .rewind-overlay span {
                font-size: 0.75rem !important;
                padding: 2px 5px !important;
                white-space: nowrap;
            }
        }
    `;
L([
  E({ attribute: !1 })
], k.prototype, "hass", 2);
L([
  f()
], k.prototype, "_config", 2);
L([
  f()
], k.prototype, "_rewindActive", 2);
L([
  f()
], k.prototype, "_overflowState", 2);
k = L([
  U("jellyha-now-playing-card")
], k);
//# sourceMappingURL=jellyha-cards.js.map
