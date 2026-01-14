/**
 * @license
 * Copyright 2019 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const O = globalThis, B = O.ShadowRoot && (O.ShadyCSS === void 0 || O.ShadyCSS.nativeShadow) && "adoptedStyleSheets" in Document.prototype && "replace" in CSSStyleSheet.prototype, W = Symbol(), J = /* @__PURE__ */ new WeakMap();
let de = class {
  constructor(e, i, s) {
    if (this._$cssResult$ = !0, s !== W) throw Error("CSSResult is not constructable. Use `unsafeCSS` or `css` instead.");
    this.cssText = e, this.t = i;
  }
  get styleSheet() {
    let e = this.o;
    const i = this.t;
    if (B && e === void 0) {
      const s = i !== void 0 && i.length === 1;
      s && (e = J.get(i)), e === void 0 && ((this.o = e = new CSSStyleSheet()).replaceSync(this.cssText), s && J.set(i, e));
    }
    return e;
  }
  toString() {
    return this.cssText;
  }
};
const _e = (t) => new de(typeof t == "string" ? t : t + "", void 0, W), he = (t, ...e) => {
  const i = t.length === 1 ? t[0] : e.reduce((s, a, o) => s + ((n) => {
    if (n._$cssResult$ === !0) return n.cssText;
    if (typeof n == "number") return n;
    throw Error("Value passed to 'css' function must be a 'css' function result: " + n + ". Use 'unsafeCSS' to pass non-literal values, but take care to ensure page security.");
  })(a) + t[o + 1], t[0]);
  return new de(i, t, W);
}, me = (t, e) => {
  if (B) t.adoptedStyleSheets = e.map((i) => i instanceof CSSStyleSheet ? i : i.styleSheet);
  else for (const i of e) {
    const s = document.createElement("style"), a = O.litNonce;
    a !== void 0 && s.setAttribute("nonce", a), s.textContent = i.cssText, t.appendChild(s);
  }
}, K = B ? (t) => t : (t) => t instanceof CSSStyleSheet ? ((e) => {
  let i = "";
  for (const s of e.cssRules) i += s.cssText;
  return _e(i);
})(t) : t;
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const { is: ve, defineProperty: we, getOwnPropertyDescriptor: ye, getOwnPropertyNames: be, getOwnPropertySymbols: $e, getPrototypeOf: xe } = Object, N = globalThis, Z = N.trustedTypes, Ce = Z ? Z.emptyScript : "", Se = N.reactiveElementPolyfillSupport, E = (t, e) => t, L = { toAttribute(t, e) {
  switch (e) {
    case Boolean:
      t = t ? Ce : null;
      break;
    case Object:
    case Array:
      t = t == null ? t : JSON.stringify(t);
  }
  return t;
}, fromAttribute(t, e) {
  let i = t;
  switch (e) {
    case Boolean:
      i = t !== null;
      break;
    case Number:
      i = t === null ? null : Number(t);
      break;
    case Object:
    case Array:
      try {
        i = JSON.parse(t);
      } catch {
        i = null;
      }
  }
  return i;
} }, X = (t, e) => !ve(t, e), Q = { attribute: !0, type: String, converter: L, reflect: !1, useDefault: !1, hasChanged: X };
Symbol.metadata ??= Symbol("metadata"), N.litPropertyMetadata ??= /* @__PURE__ */ new WeakMap();
let $ = class extends HTMLElement {
  static addInitializer(e) {
    this._$Ei(), (this.l ??= []).push(e);
  }
  static get observedAttributes() {
    return this.finalize(), this._$Eh && [...this._$Eh.keys()];
  }
  static createProperty(e, i = Q) {
    if (i.state && (i.attribute = !1), this._$Ei(), this.prototype.hasOwnProperty(e) && ((i = Object.create(i)).wrapped = !0), this.elementProperties.set(e, i), !i.noAccessor) {
      const s = Symbol(), a = this.getPropertyDescriptor(e, s, i);
      a !== void 0 && we(this.prototype, e, a);
    }
  }
  static getPropertyDescriptor(e, i, s) {
    const { get: a, set: o } = ye(this.prototype, e) ?? { get() {
      return this[i];
    }, set(n) {
      this[i] = n;
    } };
    return { get: a, set(n) {
      const d = a?.call(this);
      o?.call(this, n), this.requestUpdate(e, d, s);
    }, configurable: !0, enumerable: !0 };
  }
  static getPropertyOptions(e) {
    return this.elementProperties.get(e) ?? Q;
  }
  static _$Ei() {
    if (this.hasOwnProperty(E("elementProperties"))) return;
    const e = xe(this);
    e.finalize(), e.l !== void 0 && (this.l = [...e.l]), this.elementProperties = new Map(e.elementProperties);
  }
  static finalize() {
    if (this.hasOwnProperty(E("finalized"))) return;
    if (this.finalized = !0, this._$Ei(), this.hasOwnProperty(E("properties"))) {
      const i = this.properties, s = [...be(i), ...$e(i)];
      for (const a of s) this.createProperty(a, i[a]);
    }
    const e = this[Symbol.metadata];
    if (e !== null) {
      const i = litPropertyMetadata.get(e);
      if (i !== void 0) for (const [s, a] of i) this.elementProperties.set(s, a);
    }
    this._$Eh = /* @__PURE__ */ new Map();
    for (const [i, s] of this.elementProperties) {
      const a = this._$Eu(i, s);
      a !== void 0 && this._$Eh.set(a, i);
    }
    this.elementStyles = this.finalizeStyles(this.styles);
  }
  static finalizeStyles(e) {
    const i = [];
    if (Array.isArray(e)) {
      const s = new Set(e.flat(1 / 0).reverse());
      for (const a of s) i.unshift(K(a));
    } else e !== void 0 && i.push(K(e));
    return i;
  }
  static _$Eu(e, i) {
    const s = i.attribute;
    return s === !1 ? void 0 : typeof s == "string" ? s : typeof e == "string" ? e.toLowerCase() : void 0;
  }
  constructor() {
    super(), this._$Ep = void 0, this.isUpdatePending = !1, this.hasUpdated = !1, this._$Em = null, this._$Ev();
  }
  _$Ev() {
    this._$ES = new Promise((e) => this.enableUpdating = e), this._$AL = /* @__PURE__ */ new Map(), this._$E_(), this.requestUpdate(), this.constructor.l?.forEach((e) => e(this));
  }
  addController(e) {
    (this._$EO ??= /* @__PURE__ */ new Set()).add(e), this.renderRoot !== void 0 && this.isConnected && e.hostConnected?.();
  }
  removeController(e) {
    this._$EO?.delete(e);
  }
  _$E_() {
    const e = /* @__PURE__ */ new Map(), i = this.constructor.elementProperties;
    for (const s of i.keys()) this.hasOwnProperty(s) && (e.set(s, this[s]), delete this[s]);
    e.size > 0 && (this._$Ep = e);
  }
  createRenderRoot() {
    const e = this.shadowRoot ?? this.attachShadow(this.constructor.shadowRootOptions);
    return me(e, this.constructor.elementStyles), e;
  }
  connectedCallback() {
    this.renderRoot ??= this.createRenderRoot(), this.enableUpdating(!0), this._$EO?.forEach((e) => e.hostConnected?.());
  }
  enableUpdating(e) {
  }
  disconnectedCallback() {
    this._$EO?.forEach((e) => e.hostDisconnected?.());
  }
  attributeChangedCallback(e, i, s) {
    this._$AK(e, s);
  }
  _$ET(e, i) {
    const s = this.constructor.elementProperties.get(e), a = this.constructor._$Eu(e, s);
    if (a !== void 0 && s.reflect === !0) {
      const o = (s.converter?.toAttribute !== void 0 ? s.converter : L).toAttribute(i, s.type);
      this._$Em = e, o == null ? this.removeAttribute(a) : this.setAttribute(a, o), this._$Em = null;
    }
  }
  _$AK(e, i) {
    const s = this.constructor, a = s._$Eh.get(e);
    if (a !== void 0 && this._$Em !== a) {
      const o = s.getPropertyOptions(a), n = typeof o.converter == "function" ? { fromAttribute: o.converter } : o.converter?.fromAttribute !== void 0 ? o.converter : L;
      this._$Em = a;
      const d = n.fromAttribute(i, o.type);
      this[a] = d ?? this._$Ej?.get(a) ?? d, this._$Em = null;
    }
  }
  requestUpdate(e, i, s, a = !1, o) {
    if (e !== void 0) {
      const n = this.constructor;
      if (a === !1 && (o = this[e]), s ??= n.getPropertyOptions(e), !((s.hasChanged ?? X)(o, i) || s.useDefault && s.reflect && o === this._$Ej?.get(e) && !this.hasAttribute(n._$Eu(e, s)))) return;
      this.C(e, i, s);
    }
    this.isUpdatePending === !1 && (this._$ES = this._$EP());
  }
  C(e, i, { useDefault: s, reflect: a, wrapped: o }, n) {
    s && !(this._$Ej ??= /* @__PURE__ */ new Map()).has(e) && (this._$Ej.set(e, n ?? i ?? this[e]), o !== !0 || n !== void 0) || (this._$AL.has(e) || (this.hasUpdated || s || (i = void 0), this._$AL.set(e, i)), a === !0 && this._$Em !== e && (this._$Eq ??= /* @__PURE__ */ new Set()).add(e));
  }
  async _$EP() {
    this.isUpdatePending = !0;
    try {
      await this._$ES;
    } catch (i) {
      Promise.reject(i);
    }
    const e = this.scheduleUpdate();
    return e != null && await e, !this.isUpdatePending;
  }
  scheduleUpdate() {
    return this.performUpdate();
  }
  performUpdate() {
    if (!this.isUpdatePending) return;
    if (!this.hasUpdated) {
      if (this.renderRoot ??= this.createRenderRoot(), this._$Ep) {
        for (const [a, o] of this._$Ep) this[a] = o;
        this._$Ep = void 0;
      }
      const s = this.constructor.elementProperties;
      if (s.size > 0) for (const [a, o] of s) {
        const { wrapped: n } = o, d = this[a];
        n !== !0 || this._$AL.has(a) || d === void 0 || this.C(a, void 0, o, d);
      }
    }
    let e = !1;
    const i = this._$AL;
    try {
      e = this.shouldUpdate(i), e ? (this.willUpdate(i), this._$EO?.forEach((s) => s.hostUpdate?.()), this.update(i)) : this._$EM();
    } catch (s) {
      throw e = !1, this._$EM(), s;
    }
    e && this._$AE(i);
  }
  willUpdate(e) {
  }
  _$AE(e) {
    this._$EO?.forEach((i) => i.hostUpdated?.()), this.hasUpdated || (this.hasUpdated = !0, this.firstUpdated(e)), this.updated(e);
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
  shouldUpdate(e) {
    return !0;
  }
  update(e) {
    this._$Eq &&= this._$Eq.forEach((i) => this._$ET(i, this[i])), this._$EM();
  }
  updated(e) {
  }
  firstUpdated(e) {
  }
};
$.elementStyles = [], $.shadowRootOptions = { mode: "open" }, $[E("elementProperties")] = /* @__PURE__ */ new Map(), $[E("finalized")] = /* @__PURE__ */ new Map(), Se?.({ ReactiveElement: $ }), (N.reactiveElementVersions ??= []).push("2.1.2");
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const Y = globalThis, ee = (t) => t, R = Y.trustedTypes, te = R ? R.createPolicy("lit-html", { createHTML: (t) => t }) : void 0, ce = "$lit$", m = `lit$${Math.random().toFixed(9).slice(2)}$`, pe = "?" + m, Ae = `<${pe}>`, y = document, k = () => y.createComment(""), j = (t) => t === null || typeof t != "object" && typeof t != "function", q = Array.isArray, Pe = (t) => q(t) || typeof t?.[Symbol.iterator] == "function", H = `[ 	
\f\r]`, P = /<(?:(!--|\/[^a-zA-Z])|(\/?[a-zA-Z][^>\s]*)|(\/?$))/g, ie = /-->/g, se = />/g, v = RegExp(`>|${H}(?:([^\\s"'>=/]+)(${H}*=${H}*(?:[^ 	
\f\r"'\`<>=]|("|')|))|$)`, "g"), ae = /'/g, oe = /"/g, ge = /^(?:script|style|textarea|title)$/i, Ee = (t) => (e, ...i) => ({ _$litType$: t, strings: e, values: i }), r = Ee(1), C = Symbol.for("lit-noChange"), l = Symbol.for("lit-nothing"), ne = /* @__PURE__ */ new WeakMap(), w = y.createTreeWalker(y, 129);
function ue(t, e) {
  if (!q(t) || !t.hasOwnProperty("raw")) throw Error("invalid template strings array");
  return te !== void 0 ? te.createHTML(e) : e;
}
const ke = (t, e) => {
  const i = t.length - 1, s = [];
  let a, o = e === 2 ? "<svg>" : e === 3 ? "<math>" : "", n = P;
  for (let d = 0; d < i; d++) {
    const h = t[d];
    let c, p, g = -1, u = 0;
    for (; u < h.length && (n.lastIndex = u, p = n.exec(h), p !== null); ) u = n.lastIndex, n === P ? p[1] === "!--" ? n = ie : p[1] !== void 0 ? n = se : p[2] !== void 0 ? (ge.test(p[2]) && (a = RegExp("</" + p[2], "g")), n = v) : p[3] !== void 0 && (n = v) : n === v ? p[0] === ">" ? (n = a ?? P, g = -1) : p[1] === void 0 ? g = -2 : (g = n.lastIndex - p[2].length, c = p[1], n = p[3] === void 0 ? v : p[3] === '"' ? oe : ae) : n === oe || n === ae ? n = v : n === ie || n === se ? n = P : (n = v, a = void 0);
    const _ = n === v && t[d + 1].startsWith("/>") ? " " : "";
    o += n === P ? h + Ae : g >= 0 ? (s.push(c), h.slice(0, g) + ce + h.slice(g) + m + _) : h + m + (g === -2 ? d : _);
  }
  return [ue(t, o + (t[i] || "<?>") + (e === 2 ? "</svg>" : e === 3 ? "</math>" : "")), s];
};
class M {
  constructor({ strings: e, _$litType$: i }, s) {
    let a;
    this.parts = [];
    let o = 0, n = 0;
    const d = e.length - 1, h = this.parts, [c, p] = ke(e, i);
    if (this.el = M.createElement(c, s), w.currentNode = this.el.content, i === 2 || i === 3) {
      const g = this.el.content.firstChild;
      g.replaceWith(...g.childNodes);
    }
    for (; (a = w.nextNode()) !== null && h.length < d; ) {
      if (a.nodeType === 1) {
        if (a.hasAttributes()) for (const g of a.getAttributeNames()) if (g.endsWith(ce)) {
          const u = p[n++], _ = a.getAttribute(g).split(m), I = /([.?@])?(.*)/.exec(u);
          h.push({ type: 1, index: o, name: I[2], strings: _, ctor: I[1] === "." ? Me : I[1] === "?" ? Te : I[1] === "@" ? ze : U }), a.removeAttribute(g);
        } else g.startsWith(m) && (h.push({ type: 6, index: o }), a.removeAttribute(g));
        if (ge.test(a.tagName)) {
          const g = a.textContent.split(m), u = g.length - 1;
          if (u > 0) {
            a.textContent = R ? R.emptyScript : "";
            for (let _ = 0; _ < u; _++) a.append(g[_], k()), w.nextNode(), h.push({ type: 2, index: ++o });
            a.append(g[u], k());
          }
        }
      } else if (a.nodeType === 8) if (a.data === pe) h.push({ type: 2, index: o });
      else {
        let g = -1;
        for (; (g = a.data.indexOf(m, g + 1)) !== -1; ) h.push({ type: 7, index: o }), g += m.length - 1;
      }
      o++;
    }
  }
  static createElement(e, i) {
    const s = y.createElement("template");
    return s.innerHTML = e, s;
  }
}
function S(t, e, i = t, s) {
  if (e === C) return e;
  let a = s !== void 0 ? i._$Co?.[s] : i._$Cl;
  const o = j(e) ? void 0 : e._$litDirective$;
  return a?.constructor !== o && (a?._$AO?.(!1), o === void 0 ? a = void 0 : (a = new o(t), a._$AT(t, i, s)), s !== void 0 ? (i._$Co ??= [])[s] = a : i._$Cl = a), a !== void 0 && (e = S(t, a._$AS(t, e.values), a, s)), e;
}
class je {
  constructor(e, i) {
    this._$AV = [], this._$AN = void 0, this._$AD = e, this._$AM = i;
  }
  get parentNode() {
    return this._$AM.parentNode;
  }
  get _$AU() {
    return this._$AM._$AU;
  }
  u(e) {
    const { el: { content: i }, parts: s } = this._$AD, a = (e?.creationScope ?? y).importNode(i, !0);
    w.currentNode = a;
    let o = w.nextNode(), n = 0, d = 0, h = s[0];
    for (; h !== void 0; ) {
      if (n === h.index) {
        let c;
        h.type === 2 ? c = new z(o, o.nextSibling, this, e) : h.type === 1 ? c = new h.ctor(o, h.name, h.strings, this, e) : h.type === 6 && (c = new Ie(o, this, e)), this._$AV.push(c), h = s[++d];
      }
      n !== h?.index && (o = w.nextNode(), n++);
    }
    return w.currentNode = y, a;
  }
  p(e) {
    let i = 0;
    for (const s of this._$AV) s !== void 0 && (s.strings !== void 0 ? (s._$AI(e, s, i), i += s.strings.length - 2) : s._$AI(e[i])), i++;
  }
}
class z {
  get _$AU() {
    return this._$AM?._$AU ?? this._$Cv;
  }
  constructor(e, i, s, a) {
    this.type = 2, this._$AH = l, this._$AN = void 0, this._$AA = e, this._$AB = i, this._$AM = s, this.options = a, this._$Cv = a?.isConnected ?? !0;
  }
  get parentNode() {
    let e = this._$AA.parentNode;
    const i = this._$AM;
    return i !== void 0 && e?.nodeType === 11 && (e = i.parentNode), e;
  }
  get startNode() {
    return this._$AA;
  }
  get endNode() {
    return this._$AB;
  }
  _$AI(e, i = this) {
    e = S(this, e, i), j(e) ? e === l || e == null || e === "" ? (this._$AH !== l && this._$AR(), this._$AH = l) : e !== this._$AH && e !== C && this._(e) : e._$litType$ !== void 0 ? this.$(e) : e.nodeType !== void 0 ? this.T(e) : Pe(e) ? this.k(e) : this._(e);
  }
  O(e) {
    return this._$AA.parentNode.insertBefore(e, this._$AB);
  }
  T(e) {
    this._$AH !== e && (this._$AR(), this._$AH = this.O(e));
  }
  _(e) {
    this._$AH !== l && j(this._$AH) ? this._$AA.nextSibling.data = e : this.T(y.createTextNode(e)), this._$AH = e;
  }
  $(e) {
    const { values: i, _$litType$: s } = e, a = typeof s == "number" ? this._$AC(e) : (s.el === void 0 && (s.el = M.createElement(ue(s.h, s.h[0]), this.options)), s);
    if (this._$AH?._$AD === a) this._$AH.p(i);
    else {
      const o = new je(a, this), n = o.u(this.options);
      o.p(i), this.T(n), this._$AH = o;
    }
  }
  _$AC(e) {
    let i = ne.get(e.strings);
    return i === void 0 && ne.set(e.strings, i = new M(e)), i;
  }
  k(e) {
    q(this._$AH) || (this._$AH = [], this._$AR());
    const i = this._$AH;
    let s, a = 0;
    for (const o of e) a === i.length ? i.push(s = new z(this.O(k()), this.O(k()), this, this.options)) : s = i[a], s._$AI(o), a++;
    a < i.length && (this._$AR(s && s._$AB.nextSibling, a), i.length = a);
  }
  _$AR(e = this._$AA.nextSibling, i) {
    for (this._$AP?.(!1, !0, i); e !== this._$AB; ) {
      const s = ee(e).nextSibling;
      ee(e).remove(), e = s;
    }
  }
  setConnected(e) {
    this._$AM === void 0 && (this._$Cv = e, this._$AP?.(e));
  }
}
class U {
  get tagName() {
    return this.element.tagName;
  }
  get _$AU() {
    return this._$AM._$AU;
  }
  constructor(e, i, s, a, o) {
    this.type = 1, this._$AH = l, this._$AN = void 0, this.element = e, this.name = i, this._$AM = a, this.options = o, s.length > 2 || s[0] !== "" || s[1] !== "" ? (this._$AH = Array(s.length - 1).fill(new String()), this.strings = s) : this._$AH = l;
  }
  _$AI(e, i = this, s, a) {
    const o = this.strings;
    let n = !1;
    if (o === void 0) e = S(this, e, i, 0), n = !j(e) || e !== this._$AH && e !== C, n && (this._$AH = e);
    else {
      const d = e;
      let h, c;
      for (e = o[0], h = 0; h < o.length - 1; h++) c = S(this, d[s + h], i, h), c === C && (c = this._$AH[h]), n ||= !j(c) || c !== this._$AH[h], c === l ? e = l : e !== l && (e += (c ?? "") + o[h + 1]), this._$AH[h] = c;
    }
    n && !a && this.j(e);
  }
  j(e) {
    e === l ? this.element.removeAttribute(this.name) : this.element.setAttribute(this.name, e ?? "");
  }
}
class Me extends U {
  constructor() {
    super(...arguments), this.type = 3;
  }
  j(e) {
    this.element[this.name] = e === l ? void 0 : e;
  }
}
class Te extends U {
  constructor() {
    super(...arguments), this.type = 4;
  }
  j(e) {
    this.element.toggleAttribute(this.name, !!e && e !== l);
  }
}
class ze extends U {
  constructor(e, i, s, a, o) {
    super(e, i, s, a, o), this.type = 5;
  }
  _$AI(e, i = this) {
    if ((e = S(this, e, i, 0) ?? l) === C) return;
    const s = this._$AH, a = e === l && s !== l || e.capture !== s.capture || e.once !== s.once || e.passive !== s.passive, o = e !== l && (s === l || a);
    a && this.element.removeEventListener(this.name, this, s), o && this.element.addEventListener(this.name, this, e), this._$AH = e;
  }
  handleEvent(e) {
    typeof this._$AH == "function" ? this._$AH.call(this.options?.host ?? this.element, e) : this._$AH.handleEvent(e);
  }
}
class Ie {
  constructor(e, i, s) {
    this.element = e, this.type = 6, this._$AN = void 0, this._$AM = i, this.options = s;
  }
  get _$AU() {
    return this._$AM._$AU;
  }
  _$AI(e) {
    S(this, e);
  }
}
const De = Y.litHtmlPolyfillSupport;
De?.(M, z), (Y.litHtmlVersions ??= []).push("3.3.2");
const Oe = (t, e, i) => {
  const s = i?.renderBefore ?? e;
  let a = s._$litPart$;
  if (a === void 0) {
    const o = i?.renderBefore ?? null;
    s._$litPart$ = a = new z(e.insertBefore(k(), o), o, void 0, i ?? {});
  }
  return a._$AI(t), a;
};
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const V = globalThis;
class x extends $ {
  constructor() {
    super(...arguments), this.renderOptions = { host: this }, this._$Do = void 0;
  }
  createRenderRoot() {
    const e = super.createRenderRoot();
    return this.renderOptions.renderBefore ??= e.firstChild, e;
  }
  update(e) {
    const i = this.render();
    this.hasUpdated || (this.renderOptions.isConnected = this.isConnected), super.update(e), this._$Do = Oe(i, this.renderRoot, this.renderOptions);
  }
  connectedCallback() {
    super.connectedCallback(), this._$Do?.setConnected(!0);
  }
  disconnectedCallback() {
    super.disconnectedCallback(), this._$Do?.setConnected(!1);
  }
  render() {
    return C;
  }
}
x._$litElement$ = !0, x.finalized = !0, V.litElementHydrateSupport?.({ LitElement: x });
const Le = V.litElementPolyfillSupport;
Le?.({ LitElement: x });
(V.litElementVersions ??= []).push("4.2.2");
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const fe = (t) => (e, i) => {
  i !== void 0 ? i.addInitializer(() => {
    customElements.define(t, e);
  }) : customElements.define(t, e);
};
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const Re = { attribute: !0, type: String, converter: L, reflect: !1, hasChanged: X }, Ne = (t = Re, e, i) => {
  const { kind: s, metadata: a } = i;
  let o = globalThis.litPropertyMetadata.get(a);
  if (o === void 0 && globalThis.litPropertyMetadata.set(a, o = /* @__PURE__ */ new Map()), s === "setter" && ((t = Object.create(t)).wrapped = !0), o.set(i.name, t), s === "accessor") {
    const { name: n } = i;
    return { set(d) {
      const h = e.get.call(this);
      e.set.call(this, d), this.requestUpdate(n, h, t, !0, d);
    }, init(d) {
      return d !== void 0 && this.C(n, void 0, t, d), d;
    } };
  }
  if (s === "setter") {
    const { name: n } = i;
    return function(d) {
      const h = this[n];
      e.call(this, d), this.requestUpdate(n, h, t, !0, d);
    };
  }
  throw Error("Unsupported decorator location: " + s);
};
function G(t) {
  return (e, i) => typeof i == "object" ? Ne(t, e, i) : ((s, a, o) => {
    const n = a.hasOwnProperty(o);
    return a.constructor.createProperty(o, s), n ? Object.getOwnPropertyDescriptor(a, o) : void 0;
  })(t, e, i);
}
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
function A(t) {
  return G({ ...t, state: !0, attribute: !1 });
}
const Ue = he`
  :host {
    --jf-card-bg: var(--card-background-color, #1c1c1c);
    --jf-primary: var(--primary-color, #03a9f4);
    --jf-text: var(--primary-text-color, #fff);
    --jf-text-secondary: var(--secondary-text-color, rgba(255, 255, 255, 0.7));
    --jf-divider: var(--divider-color, rgba(255, 255, 255, 0.12));
    --jf-poster-radius: 10px;
    --jf-transition: 0s;
    --jf-movie-badge: rgb(99, 102, 241);
    --jf-series-badge: rgb(245, 158, 11);
    --jf-border-color: var(--divider-color, rgba(255, 255, 255, 0.15));
  }

  ha-card {
    background: var(--jf-card-bg);
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
    padding: 2px 8px;
    border-radius: 6px;
    font-size: 0.7rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.3px;
    color: #fff;
    z-index: 5;
    box-shadow: 0 2px 4px rgba(0,0,0,0.3);
    opacity: 0.90;
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
    padding: 2px 8px;
    border-radius: 6px;
    font-size: 0.7rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.3px;
    z-index: 5;
    box-shadow: 0 2px 4px rgba(0,0,0,0.3);
    opacity: 0.90;
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
    padding: 2px 8px;
    border-radius: 6px;
    background: #4CAF50; /* Material Green 500 */
    color: #fff;
    font-size: 0.7rem;
    opacity: 0.90;
  }

  .status-badge.watched ha-icon {
    --mdc-icon-size: 14px;
    margin-top: -1px;
  }

  /* Unplayed Count - Theme Colored Badge */
  .status-badge.unplayed {
    padding: 2px 8px;
    border-radius: 6px;
    background: var(--jf-primary);
    color: #fff;
    font-size: 0.7rem;
    font-weight: 700;
    opacity: 0.90;
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
    color: #ffc107;
    padding: 3px 6px;
    border-radius: 6px;
    font-weight: 600;
    font-size: 0.8rem;
    z-index: 5;
    transition: opacity var(--jf-transition);
  }

  .rating ha-icon {
    --mdc-icon-size: 13px;
    color: #ffc107;
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
    border-radius: 6px;
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
    color: var(--error-color, #f44336);
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
`, D = {
  en: {
    loading: "Loading...",
    no_media: "No recent media found",
    error: "Error loading media",
    new: "New",
    minutes: "min"
  },
  de: {
    loading: "Laden...",
    no_media: "Keine neuen Medien gefunden",
    error: "Fehler beim Laden der Medien",
    new: "Neu",
    minutes: "Min"
  },
  fr: {
    loading: "Chargement...",
    no_media: "Aucun média récent trouvé",
    error: "Erreur lors du chargement des médias",
    new: "Nouveau",
    minutes: "min"
  },
  es: {
    loading: "Cargando...",
    no_media: "No se encontraron medios recientes",
    error: "Error al cargar medios",
    new: "Nuevo",
    minutes: "min"
  },
  it: {
    loading: "Caricamento...",
    no_media: "Nessun media recente trovato",
    error: "Errore durante il caricamento dei media",
    new: "Nuovo",
    minutes: "min"
  },
  nl: {
    loading: "Laden...",
    no_media: "Geen recente media gevonden",
    error: "Fout bij het laden van media",
    new: "Nieuw",
    minutes: "min"
  }
};
function re(t, e) {
  const i = t.split("-")[0].toLowerCase();
  return D[i]?.[e] ? D[i][e] : D.en?.[e] ? D.en[e] : e;
}
var He = Object.defineProperty, Be = Object.getOwnPropertyDescriptor, F = (t, e, i, s) => {
  for (var a = s > 1 ? void 0 : s ? Be(e, i) : e, o = t.length - 1, n; o >= 0; o--)
    (n = t[o]) && (a = (s ? n(e, i, a) : n(a)) || a);
  return s && a && He(e, i, a), a;
};
function We(t, e, i) {
  const s = new CustomEvent(e, {
    bubbles: !0,
    composed: !0,
    detail: i
  });
  t.dispatchEvent(s);
}
let T = class extends x {
  setConfig(t) {
    this._config = t;
  }
  render() {
    return !this.hass || !this._config ? r`` : r`
      <div class="card-config">
        <div class="form-row">
          <ha-entity-picker
            .hass=${this.hass}
            .value=${this._config.entity}
            .label=${"Entity (required)"}
            .includeDomains=${["sensor"]}
            @value-changed=${this._entityChanged}
            allow-custom-entity
          ></ha-entity-picker>
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
            @closed=${(t) => t.stopPropagation()}
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
            @closed=${(t) => t.stopPropagation()}
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
            .value=${this._config.items_per_page !== void 0 ? String(this._config.items_per_page) : ""}
            @input=${this._itemsPerPageChanged}
          ></ha-textfield>
        </div>

        <div class="form-row">
          <ha-textfield
            label="Max Pages"
            type="number"
            min="1"
            max="20"
            .value=${String(this._config.max_pages || 5)}
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
            label="New Badge Days"
            type="number"
            min="0"
            max="30"
            .value=${String(this._config.new_badge_days || 7)}
            @input=${this._newBadgeDaysChanged}
          ></ha-textfield>
        </div>

        <div class="form-row">
          <ha-select
            label="Click Action"
            .value=${this._config.click_action || "jellyfin"}
            @selected=${this._clickActionChanged}
            @closed=${(t) => t.stopPropagation()}
          >
            <mwc-list-item value="jellyfin">Open in Jellyfin</mwc-list-item>
            <mwc-list-item value="more-info">Show More Info</mwc-list-item>
            <mwc-list-item value="none">No Action</mwc-list-item>
          </ha-select>
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
        </div>

        <div class="form-row">
          <ha-select
            label="Metadata Position"
            .value=${this._config.metadata_position || "below"}
            @selected=${this._metadataPositionChanged}
            @closed=${(t) => t.stopPropagation()}
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
      </div>
    `;
  }
  _entityChanged(t) {
    this._updateConfig("entity", t.detail.value);
  }
  _titleChanged(t) {
    const e = t.target;
    this._updateConfig("title", e.value);
  }
  _layoutChanged(t) {
    const e = t.target;
    this._updateConfig("layout", e.value);
  }
  _columnsChanged(t) {
    const e = t.target;
    this._updateConfig("columns", Number(e.value));
  }
  _mediaTypeChanged(t) {
    const e = t.target;
    this._updateConfig("media_type", e.value);
  }
  _itemsPerPageChanged(t) {
    const i = t.target.value.trim();
    i !== "" && this._updateConfig("items_per_page", Number(i));
  }
  _maxPagesChanged(t) {
    const e = t.target;
    this._updateConfig("max_pages", Number(e.value));
  }
  _autoSwipeIntervalChanged(t) {
    const e = t.target;
    this._updateConfig("auto_swipe_interval", Number(e.value));
  }
  _newBadgeDaysChanged(t) {
    const e = t.target;
    this._updateConfig("new_badge_days", Number(e.value));
  }
  _clickActionChanged(t) {
    const e = t.target;
    this._updateConfig("click_action", e.value);
  }
  _showTitleChanged(t) {
    const e = t.target;
    this._updateConfig("show_title", e.checked);
  }
  _showYearChanged(t) {
    const e = t.target;
    this._updateConfig("show_year", e.checked);
  }
  _showRatingsChanged(t) {
    const e = t.target;
    this._updateConfig("show_ratings", e.checked);
  }
  _showRuntimeChanged(t) {
    const e = t.target;
    this._updateConfig("show_runtime", e.checked);
  }
  _showMediaTypeBadgeChanged(t) {
    const e = t.target;
    this._updateConfig("show_media_type_badge", e.checked);
  }
  _showWatchedStatusChanged(t) {
    const e = t.target;
    this._updateConfig("show_watched_status", e.checked);
  }
  _showGenresChanged(t) {
    const e = t.target;
    this._updateConfig("show_genres", e.checked);
  }
  _showDateAddedChanged(t) {
    const e = t.target;
    this._updateConfig("show_date_added", e.checked);
  }
  _showDescriptionOnHoverChanged(t) {
    const e = t.target;
    this._updateConfig("show_description_on_hover", e.checked);
  }
  _metadataPositionChanged(t) {
    const e = t.target;
    this._updateConfig("metadata_position", e.value);
  }
  _horizontalAlignmentChanged(t) {
    const e = t.target;
    this._updateConfig("horizontal_alignment", e.value);
  }
  _showPaginationChanged(t) {
    const e = t.target;
    this._updateConfig("show_pagination", e.checked);
  }
  _updateConfig(t, e) {
    if (!this._config)
      return;
    const i = { ...this._config, [t]: e };
    this._config = i, We(this, "config-changed", { config: i });
  }
};
T.styles = he`
    .form-row {
      margin-bottom: 16px;
    }
    .form-row ha-textfield,
    .form-row ha-select {
      width: 100%;
    }
    .checkbox-row {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 8px;
    }
  `;
F([
  G({ attribute: !1 })
], T.prototype, "hass", 2);
F([
  A()
], T.prototype, "_config", 2);
T = F([
  fe("jellyha-library-editor")
], T);
var Xe = Object.defineProperty, Ye = Object.getOwnPropertyDescriptor, b = (t, e, i, s) => {
  for (var a = s > 1 ? void 0 : s ? Ye(e, i) : e, o = t.length - 1, n; o >= 0; o--)
    (n = t[o]) && (a = (s ? n(e, i, a) : n(a)) || a);
  return s && a && Xe(e, i, a), a;
};
const qe = "1.0.0";
console.info(
  `%c JELLYHA-LIBRARY-CARD %c v${qe} `,
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
const le = {
  title: "Jellyfin Library",
  layout: "carousel",
  media_type: "both",
  items_per_page: 3,
  max_pages: 5,
  auto_swipe_interval: 0,
  // 0 = disabled, otherwise seconds
  columns: 4,
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
  click_action: "jellyfin",
  image_quality: 90,
  image_height: 300,
  theme: "auto",
  show_watched_status: !0
};
function Ve(t, e, i) {
  const s = new CustomEvent(e, {
    bubbles: !0,
    composed: !0,
    detail: i
  });
  t.dispatchEvent(s);
}
let f = class extends x {
  constructor() {
    super(), this._currentPage = 0, this._itemsPerPage = 5, this._containerWidth = 0, this.ITEM_WIDTH = 148, this.LIST_ITEM_MIN_WIDTH = 380, this._effectiveListColumns = 1, this._touchStartX = 0, this._touchStartY = 0, this._isSwiping = !1, this._scrollProgress = 0, this._hasScrollableContent = !1, this.SCROLL_INDICATOR_DOTS = 5, this._onDotClick = this._onDotClick.bind(this), this._handleTouchStart = this._handleTouchStart.bind(this), this._handleTouchMove = this._handleTouchMove.bind(this), this._handleTouchEnd = this._handleTouchEnd.bind(this), this._handlePointerDown = this._handlePointerDown.bind(this), this._handlePointerMove = this._handlePointerMove.bind(this), this._handlePointerUp = this._handlePointerUp.bind(this), this._handleScroll = this._handleScroll.bind(this);
  }
  connectedCallback() {
    super.connectedCallback(), this._setupResizeHandler(), this._setupAutoSwipe();
  }
  disconnectedCallback() {
    super.disconnectedCallback(), this._resizeObserver?.disconnect(), this._resizeHandler && window.removeEventListener("resize", this._resizeHandler), this._clearAutoSwipe();
  }
  _setupAutoSwipe() {
    this._clearAutoSwipe();
    const t = this._config?.auto_swipe_interval;
    t && t > 0 && (this._autoSwipeTimer = window.setInterval(() => {
      this._nextPage();
    }, t * 1e3));
  }
  _clearAutoSwipe() {
    this._autoSwipeTimer && (clearInterval(this._autoSwipeTimer), this._autoSwipeTimer = void 0);
  }
  _nextPage() {
    if (!this._config || !this.hass) return;
    const t = this.hass.states[this._config.entity];
    if (!t) return;
    const e = t.attributes, i = this._filterItems(e.items || []), s = this._config?.items_per_page || this._itemsPerPage, a = this._config?.max_pages || 10, o = Math.min(Math.ceil(i.length / s), a);
    o > 1 && (this._currentPage = (this._currentPage + 1) % o, this.requestUpdate());
  }
  _prevPage() {
    if (!this._config || !this.hass) return;
    const t = this.hass.states[this._config.entity];
    if (!t) return;
    const e = t.attributes, i = this._filterItems(e.items || []), s = this._config?.items_per_page || this._itemsPerPage, a = this._config?.max_pages || 10, o = Math.min(Math.ceil(i.length / s), a);
    o > 1 && (this._currentPage = (this._currentPage - 1 + o) % o, this.requestUpdate());
  }
  // Touch/Swipe handlers
  _handleTouchStart(t) {
    this._touchStartX = t.touches[0].clientX, this._touchStartY = t.touches[0].clientY, this._isSwiping = !1;
  }
  _handleTouchMove(t) {
    if (!this._touchStartX) return;
    const e = t.touches[0].clientX - this._touchStartX, i = t.touches[0].clientY - this._touchStartY;
    Math.abs(e) > Math.abs(i) && Math.abs(e) > 30 && (this._isSwiping = !0, t.preventDefault());
  }
  _handleTouchEnd(t) {
    if (!this._isSwiping) {
      this._touchStartX = 0;
      return;
    }
    const e = t.changedTouches[0].clientX - this._touchStartX, i = 50;
    e < -i ? this._nextPage() : e > i && this._prevPage(), this._touchStartX = 0, this._isSwiping = !1;
  }
  // Pointer events for Android Companion App (uses same logic as touch)
  _handlePointerDown(t) {
    t.pointerType !== "mouse" && (this._touchStartX = t.clientX, this._touchStartY = t.clientY, this._isSwiping = !1, t.target.setPointerCapture?.(t.pointerId));
  }
  _handlePointerMove(t) {
    if (t.pointerType === "mouse" || !this._touchStartX) return;
    const e = t.clientX - this._touchStartX, i = t.clientY - this._touchStartY;
    Math.abs(e) > Math.abs(i) && Math.abs(e) > 30 && (this._isSwiping = !0, t.preventDefault());
  }
  _handlePointerUp(t) {
    if (t.target.releasePointerCapture?.(t.pointerId), t.pointerType === "mouse" || !this._isSwiping) {
      this._touchStartX = 0;
      return;
    }
    const e = t.clientX - this._touchStartX, i = 50;
    e < -i ? this._nextPage() : e > i && this._prevPage(), this._touchStartX = 0, this._isSwiping = !1;
  }
  // Scroll handler for elastic dot indicator
  _handleScroll(t) {
    const e = t.target, i = e.scrollWidth, s = e.clientWidth, a = e.scrollLeft, o = i > s + 10;
    if (o !== this._hasScrollableContent && (this._hasScrollableContent = o), o) {
      const n = i - s;
      let d = a / n;
      (n - a < 10 || d > 0.98) && (d = 1), (a < 10 || d < 0.02) && (d = 0), d = Math.min(1, Math.max(0, d)), this._scrollProgress = d;
    }
  }
  // Render scroll indicator for non-paginated scrollable content
  _renderScrollIndicator() {
    if (!this._hasScrollableContent) return r``;
    const t = this.SCROLL_INDICATOR_DOTS, e = this._scrollProgress, i = Math.round(e * (t - 1));
    return r`
      <div class="scroll-indicator">
        ${Array.from({ length: t }, (s, a) => {
      const o = a === i, n = a === 0 && e < 0.1 || a === t - 1 && e > 0.9;
      return r`
        <span 
          class="scroll-dot ${o ? "active" : ""} ${n ? "pill" : ""}"
        ></span>
      `;
    })}
      </div>
    `;
  }
  _setupResizeHandler() {
    this._resizeHandler = () => {
      const e = this.getBoundingClientRect().width - 32;
      if (!(e < 100) && e !== this._containerWidth) {
        this._containerWidth = e;
        const i = Math.max(2, Math.floor(e / this.ITEM_WIDTH));
        if (i !== this._itemsPerPage && (this._itemsPerPage = i, this._currentPage = 0, this.requestUpdate()), this._config) {
          const s = this._config.columns || 1;
          if (s > 1) {
            const a = Math.max(1, Math.floor(e / this.LIST_ITEM_MIN_WIDTH)), o = Math.min(s, a);
            o !== this._effectiveListColumns && (this._effectiveListColumns = o, this.requestUpdate());
          } else this._effectiveListColumns !== 1 && (this._effectiveListColumns = 1, this.requestUpdate());
        }
      }
    }, setTimeout(() => this._resizeHandler?.(), 100), window.addEventListener("resize", this._resizeHandler);
  }
  _handleDotClick(t) {
    t !== this._currentPage && (this._currentPage = t, this.requestUpdate());
  }
  _onDotClick(t) {
    t.stopPropagation(), t.preventDefault();
    const e = t.currentTarget, i = parseInt(e.dataset.page || "0", 10);
    this._handleDotClick(i);
  }
  /**
   * Set card configuration
   */
  setConfig(t) {
    if (!t.entity)
      throw new Error("Please define an entity");
    this._config = { ...le, ...t }, this._effectiveListColumns = this._config.columns || 1;
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
      ...le
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
  shouldUpdate(t) {
    if (!this._config)
      return !1;
    if (t.has("_currentPage") || t.has("_itemsPerPage") || t.has("_scrollProgress") || t.has("_hasScrollableContent"))
      return !0;
    if (t.has("hass")) {
      const e = t.get("hass");
      if (e) {
        const i = e.states[this._config.entity], s = this.hass.states[this._config.entity];
        return i !== s;
      }
    }
    return t.has("_config");
  }
  /**
   * Called after update - check for scrollable content
   */
  updated(t) {
    super.updated(t), this._config.show_pagination || requestAnimationFrame(() => {
      const e = this.shadowRoot?.querySelector(".carousel.scrollable, .grid-wrapper, .list-wrapper");
      if (e) {
        const i = e.scrollWidth > e.clientWidth + 10;
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
    const t = this.hass.states[this._config.entity];
    if (!t)
      return this._renderError(`Entity not found: ${this._config.entity}`);
    const e = t.attributes, i = this._filterItems(e.items || []);
    return r`
      <ha-card>
        ${this._config.title ? r`
              <div class="card-header">
                <h2>${this._config.title}</h2>
              </div>
            ` : l}
        <div class="card-content">
          ${i.length === 0 ? this._renderEmpty() : this._renderLayout(i)}
        </div>
      </ha-card>
    `;
  }
  /**
   * Filter items based on config
   */
  _filterItems(t) {
    let e = t;
    this._config.media_type === "movies" ? e = e.filter((s) => s.type === "Movie") : this._config.media_type === "series" && (e = e.filter((s) => s.type === "Series"));
    const i = (this._config.items_per_page || 5) * (this._config.max_pages || 5);
    return e = e.slice(0, i), e;
  }
  /**
   * Render layout based on config
   */
  _renderLayout(t) {
    const e = this._config.layout || "carousel", i = this._config.show_pagination !== !1;
    return e === "carousel" ? this._renderCarousel(t, i) : e === "list" ? this._renderList(t, i) : e === "grid" ? this._renderGrid(t, i) : r`
      <div class="${e}">
        ${t.map((s) => this._renderMediaItem(s))}
      </div>
    `;
  }
  /**
   * Render carousel with optional pagination
   */
  _renderCarousel(t, e) {
    const i = this._config.items_per_page || this._itemsPerPage, s = this._config.max_pages || 10, a = Math.min(Math.ceil(t.length / i), s), o = this._currentPage * i, n = e ? t.slice(o, o + i) : t;
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
          class="carousel ${e ? "paginated" : "scrollable"}"
          @scroll="${e ? l : this._handleScroll}"
        >
          ${n.map((d) => this._renderMediaItem(d))}
        </div>
        ${e && a > 1 ? r`
              <div class="pagination-dots">
                ${Array.from({ length: a }, (d, h) => r`
                  <button
                    type="button"
                    class="pagination-dot ${h === this._currentPage ? "active" : ""}"
                    data-page="${h}"
                    @click="${this._onDotClick}"
                    aria-label="Go to page ${h + 1}"
                  ></button>
                `)}
              </div>
            ` : l}
        ${e ? l : this._renderScrollIndicator()}
      </div>
    `;
  }
  /**
   * Render list with optional pagination
   */
  _renderList(t, e) {
    const i = this._config.items_per_page || this._itemsPerPage, s = this._config.max_pages || 10, a = Math.min(Math.ceil(t.length / i), s), o = this._currentPage * i, n = e ? t.slice(o, o + i) : t, d = this._effectiveListColumns, h = d === 1;
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
          class="list ${e ? "paginated" : ""} ${h ? "single-column" : ""}"
          style="--jf-list-columns: ${d}"
        >
          ${n.map((c) => this._renderListItem(c))}
        </div>
        ${e && a > 1 ? r`
              <div class="pagination-dots">
                ${Array.from({ length: a }, (c, p) => r`
                  <button
                    type="button"
                    class="pagination-dot ${p === this._currentPage ? "active" : ""}"
                    data-page="${p}"
                    @click="${this._onDotClick}"
                    aria-label="Go to page ${p + 1}"
                  ></button>
                `)}
              </div>
            ` : l}
      </div>
    `;
  }
  /**
   * Render grid with optional pagination
   */
  _renderGrid(t, e) {
    const i = this._config.items_per_page || this._itemsPerPage, s = this._config.max_pages || 10, a = Math.min(Math.ceil(t.length / i), s), o = this._currentPage * i, n = e ? t.slice(o, o + i) : t, d = this._config.columns || 1, h = d === 1;
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
          @scroll="${e ? l : this._handleScroll}"
        >
          <div
            class="grid ${e ? "paginated" : ""} ${h ? "auto-columns" : ""}"
            style="--jf-columns: ${d}"
          >
            ${n.map((c) => this._renderMediaItem(c))}
          </div>
        </div>
        ${e && a > 1 ? r`
              <div class="pagination-dots">
                ${Array.from({ length: a }, (c, p) => r`
                  <button
                    type="button"
                    class="pagination-dot ${p === this._currentPage ? "active" : ""}"
                    data-page="${p}"
                    @click="${this._onDotClick}"
                    aria-label="Go to page ${p + 1}"
                  ></button>
                `)}
              </div>
            ` : l}
        ${e ? l : this._renderScrollIndicator()}
      </div>
    `;
  }
  /**
   * Render individual list item (horizontal layout with metadata outside poster)
   */
  _renderListItem(t) {
    const e = this._isNewItem(t), i = this._getRating(t), s = this._config.show_media_type_badge !== !1;
    return r`
      <div
        class="media-item list-item ${this._config.show_title ? "" : "no-title"} ${this._config.metadata_position === "above" ? "metadata-above" : ""}"
        tabindex="0"
        role="button"
        aria-label="${t.name}"
        @click="${() => this._handleClick(t)}"
        @keydown="${(a) => this._handleKeydown(a, t)}"
      >
        <div class="list-poster-wrapper">
          ${this._config.metadata_position === "above" && this._config.show_date_added && t.date_added ? r`<p class="list-date-added">${this._formatDate(t.date_added)}</p>` : l}
          <div class="poster-container">
            <div class="poster-inner">
              <img
                class="poster"
                src="${t.poster_url}"
                alt="${t.name}"
                loading="lazy"
                @load="${this._handleImageLoad}"
                @error="${this._handleImageError}"
              />
              <div class="poster-skeleton"></div>
              
              ${this._renderStatusBadge(t, e)}
            </div>
          </div>
          ${this._config.metadata_position !== "above" && this._config.show_date_added && t.date_added ? r`<p class="list-date-added">${this._formatDate(t.date_added)}</p>` : l}
        </div>
        
        <div class="list-info">
          ${this._config.show_title ? r`<h3 class="list-title">${t.name}</h3>` : l}
          
          <div class="list-metadata">
            ${s ? r`<span class="list-type-badge ${t.type === "Movie" ? "movie" : "series"}">
                  ${t.type === "Movie" ? "Movie" : "Series"}
                </span>` : l}
            ${this._config.show_year && t.year ? r`<span class="list-year">${t.year}</span>` : l}
            ${this._config.show_ratings && i ? r`<span class="list-rating">
                  <ha-icon icon="mdi:star"></ha-icon>
                  ${i.toFixed(1)}
                </span>` : l}
            ${this._config.show_runtime && t.runtime_minutes ? r`<span class="list-runtime">
                  <ha-icon icon="mdi:clock-outline"></ha-icon>
                  ${this._formatRuntime(t.runtime_minutes)}
                </span>` : l}
          </div>
          
          ${this._config.show_genres && t.genres && t.genres.length > 0 ? r`<p class="list-genres">${t.genres.slice(0, 3).join(", ")}</p>` : l}
          
          ${this._config.show_description_on_hover !== !1 && t.description ? r`<p class="list-description">${t.description}</p>` : l}
        </div>
      </div>
    `;
  }
  /**
   * Render status badge (watched checkmark, unplayed count, or new badge)
   */
  _renderStatusBadge(t, e) {
    const i = this._config.show_watched_status !== !1;
    return i && t.is_played ? r`
        <div class="status-badge watched">
          <ha-icon icon="mdi:check-bold"></ha-icon>
        </div>
      ` : i && t.type === "Series" && (t.unplayed_count || 0) > 0 ? r`
        <div class="status-badge unplayed">
          ${t.unplayed_count}
        </div>
      ` : e ? r`<span class="new-badge">${re(this.hass.language, "new")}</span>` : r``;
  }
  /**
   * Render individual media item
   */
  _renderMediaItem(t) {
    const e = this._isNewItem(t), i = this._getRating(t), s = this._config.show_media_type_badge !== !1;
    return this._config.show_description_on_hover, r`
      <div
        class="media-item"
        tabindex="0"
        role="button"
        aria-label="${t.name}"
        @click="${() => this._handleClick(t)}"
        @keydown="${(a) => this._handleKeydown(a, t)}"
      >
        ${this._config.metadata_position === "above" ? r`
              <div class="media-info-above">
                ${this._config.show_title ? r`<p class="media-title">${t.name}</p>` : l}
                ${this._config.show_year && t.year ? r`<p class="media-year">${t.year}</p>` : l}
                ${this._config.show_date_added && t.date_added ? r`<p class="media-date-added">${this._formatDate(t.date_added)}</p>` : l}
              </div>
            ` : l}
        <div class="poster-container">
          <div class="poster-inner">
            <img
              class="poster"
              src="${t.poster_url}"
              alt="${t.name}"
              loading="lazy"
              @load="${this._handleImageLoad}"
              @error="${this._handleImageError}"
            />
            <div class="poster-skeleton"></div>
            
            ${s ? r`<span class="media-type-badge ${t.type === "Movie" ? "movie" : "series"}">
                  ${t.type === "Movie" ? "Movie" : "Series"}
                </span>` : l}
            
            ${this._renderStatusBadge(t, e)}
            
            ${this._config.show_ratings && i ? r`
                  <span class="rating">
                    <ha-icon icon="mdi:star"></ha-icon>
                    ${i.toFixed(1)}
                  </span>
                ` : l}
            
            ${this._config.show_runtime && t.runtime_minutes ? r`
                  <span class="runtime">
                    <ha-icon icon="mdi:clock-outline"></ha-icon>
                    ${this._formatRuntime(t.runtime_minutes)}
                  </span>
                ` : l}
            
            <div class="hover-overlay">
                    ${t.year ? r`<span class="overlay-year">${t.year}</span>` : l}
                    <h3 class="overlay-title">${t.name}</h3>
                    ${this._config.show_genres && t.genres && t.genres.length > 0 ? r`<span class="overlay-genres">${t.genres.slice(0, 3).join(", ")}</span>` : l}
                    ${this._config.show_description_on_hover !== !1 && t.description ? r`<p class="overlay-description">${t.description}</p>` : l}
                  </div>
          </div>
        </div>
        
        ${this._config.metadata_position === "below" ? r`
              <div class="media-info-below">
                ${this._config.show_title ? r`<p class="media-title">${t.name}</p>` : l}
                ${this._config.show_year && t.year ? r`<p class="media-year">${t.year}</p>` : l}
                ${this._config.show_date_added && t.date_added ? r`<p class="media-date-added">${this._formatDate(t.date_added)}</p>` : l}
              </div>
            ` : l}
      </div>
    `;
  }
  /**
   * Get rating based on config (IMDB for movies, TMDB for TV)
   */
  _getRating(t) {
    return this._config.rating_source === "auto", t.rating || null;
  }
  /**
   * Format date using Home Assistant's locale
   */
  _formatDate(t) {
    try {
      const e = new Date(t), i = this.hass?.language || "en";
      return e.toLocaleDateString(i, {
        year: "numeric",
        month: "short",
        day: "numeric"
      });
    } catch {
      return t;
    }
  }
  /**
   * Format runtime in hours and minutes
   */
  _formatRuntime(t) {
    if (t < 60)
      return `${t}m`;
    const e = Math.floor(t / 60), i = t % 60;
    return i > 0 ? `${e}h ${i}m` : `${e}h`;
  }
  /**
   * Check if item was added within new_badge_days
   */
  _isNewItem(t) {
    if (!this._config.new_badge_days || !t.date_added)
      return !1;
    const e = new Date(t.date_added);
    return ((/* @__PURE__ */ new Date()).getTime() - e.getTime()) / (1e3 * 60 * 60 * 24) <= this._config.new_badge_days;
  }
  /**
   * Handle click on media item
   */
  _handleClick(t) {
    switch (this._config.click_action) {
      case "jellyfin":
        window.open(t.jellyfin_url, "_blank");
        break;
      case "more-info":
        Ve(this, "hass-more-info", {
          entityId: this._config.entity
        });
        break;
    }
  }
  /**
   * Handle keyboard navigation
   */
  _handleKeydown(t, e) {
    (t.key === "Enter" || t.key === " ") && (t.preventDefault(), this._handleClick(e));
  }
  /**
   * Handle image load - add loaded class for transition
   */
  _handleImageLoad(t) {
    t.target.classList.add("loaded");
  }
  /**
   * Handle image error - could show placeholder
   */
  _handleImageError(t) {
    const e = t.target;
    e.style.display = "none";
  }
  /**
   * Render empty state
   */
  _renderEmpty() {
    return r`
      <div class="empty">
        <ha-icon icon="mdi:movie-open-outline"></ha-icon>
        <p>${re(this.hass.language, "no_media")}</p>
      </div>
    `;
  }
  /**
   * Render error state
   */
  _renderError(t) {
    return r`
      <ha-card>
        <div class="error">
          <ha-icon icon="mdi:alert-circle"></ha-icon>
          <p>${t}</p>
        </div>
      </ha-card>
    `;
  }
};
f.styles = Ue;
b([
  G({ attribute: !1 })
], f.prototype, "hass", 2);
b([
  A()
], f.prototype, "_config", 2);
b([
  A()
], f.prototype, "_currentPage", 2);
b([
  A()
], f.prototype, "_itemsPerPage", 2);
b([
  A()
], f.prototype, "_scrollProgress", 2);
b([
  A()
], f.prototype, "_hasScrollableContent", 2);
f = b([
  fe("jellyha-library-card")
], f);
//# sourceMappingURL=jellyha-cards.js.map
