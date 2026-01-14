/**
 * @license
 * Copyright 2019 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const O = globalThis, W = O.ShadowRoot && (O.ShadyCSS === void 0 || O.ShadyCSS.nativeShadow) && "adoptedStyleSheets" in Document.prototype && "replace" in CSSStyleSheet.prototype, X = Symbol(), K = /* @__PURE__ */ new WeakMap();
let he = class {
  constructor(e, i, s) {
    if (this._$cssResult$ = !0, s !== X) throw Error("CSSResult is not constructable. Use `unsafeCSS` or `css` instead.");
    this.cssText = e, this.t = i;
  }
  get styleSheet() {
    let e = this.o;
    const i = this.t;
    if (W && e === void 0) {
      const s = i !== void 0 && i.length === 1;
      s && (e = K.get(i)), e === void 0 && ((this.o = e = new CSSStyleSheet()).replaceSync(this.cssText), s && K.set(i, e));
    }
    return e;
  }
  toString() {
    return this.cssText;
  }
};
const me = (t) => new he(typeof t == "string" ? t : t + "", void 0, X), de = (t, ...e) => {
  const i = t.length === 1 ? t[0] : e.reduce((s, o, a) => s + ((n) => {
    if (n._$cssResult$ === !0) return n.cssText;
    if (typeof n == "number") return n;
    throw Error("Value passed to 'css' function must be a 'css' function result: " + n + ". Use 'unsafeCSS' to pass non-literal values, but take care to ensure page security.");
  })(o) + t[a + 1], t[0]);
  return new he(i, t, X);
}, _e = (t, e) => {
  if (W) t.adoptedStyleSheets = e.map((i) => i instanceof CSSStyleSheet ? i : i.styleSheet);
  else for (const i of e) {
    const s = document.createElement("style"), o = O.litNonce;
    o !== void 0 && s.setAttribute("nonce", o), s.textContent = i.cssText, t.appendChild(s);
  }
}, Z = W ? (t) => t : (t) => t instanceof CSSStyleSheet ? ((e) => {
  let i = "";
  for (const s of e.cssRules) i += s.cssText;
  return me(i);
})(t) : t;
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const { is: ve, defineProperty: we, getOwnPropertyDescriptor: ye, getOwnPropertyNames: $e, getOwnPropertySymbols: be, getPrototypeOf: xe } = Object, N = globalThis, Q = N.trustedTypes, Ce = Q ? Q.emptyScript : "", Se = N.reactiveElementPolyfillSupport, E = (t, e) => t, L = { toAttribute(t, e) {
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
} }, Y = (t, e) => !ve(t, e), ee = { attribute: !0, type: String, converter: L, reflect: !1, useDefault: !1, hasChanged: Y };
Symbol.metadata ??= Symbol("metadata"), N.litPropertyMetadata ??= /* @__PURE__ */ new WeakMap();
let b = class extends HTMLElement {
  static addInitializer(e) {
    this._$Ei(), (this.l ??= []).push(e);
  }
  static get observedAttributes() {
    return this.finalize(), this._$Eh && [...this._$Eh.keys()];
  }
  static createProperty(e, i = ee) {
    if (i.state && (i.attribute = !1), this._$Ei(), this.prototype.hasOwnProperty(e) && ((i = Object.create(i)).wrapped = !0), this.elementProperties.set(e, i), !i.noAccessor) {
      const s = Symbol(), o = this.getPropertyDescriptor(e, s, i);
      o !== void 0 && we(this.prototype, e, o);
    }
  }
  static getPropertyDescriptor(e, i, s) {
    const { get: o, set: a } = ye(this.prototype, e) ?? { get() {
      return this[i];
    }, set(n) {
      this[i] = n;
    } };
    return { get: o, set(n) {
      const h = o?.call(this);
      a?.call(this, n), this.requestUpdate(e, h, s);
    }, configurable: !0, enumerable: !0 };
  }
  static getPropertyOptions(e) {
    return this.elementProperties.get(e) ?? ee;
  }
  static _$Ei() {
    if (this.hasOwnProperty(E("elementProperties"))) return;
    const e = xe(this);
    e.finalize(), e.l !== void 0 && (this.l = [...e.l]), this.elementProperties = new Map(e.elementProperties);
  }
  static finalize() {
    if (this.hasOwnProperty(E("finalized"))) return;
    if (this.finalized = !0, this._$Ei(), this.hasOwnProperty(E("properties"))) {
      const i = this.properties, s = [...$e(i), ...be(i)];
      for (const o of s) this.createProperty(o, i[o]);
    }
    const e = this[Symbol.metadata];
    if (e !== null) {
      const i = litPropertyMetadata.get(e);
      if (i !== void 0) for (const [s, o] of i) this.elementProperties.set(s, o);
    }
    this._$Eh = /* @__PURE__ */ new Map();
    for (const [i, s] of this.elementProperties) {
      const o = this._$Eu(i, s);
      o !== void 0 && this._$Eh.set(o, i);
    }
    this.elementStyles = this.finalizeStyles(this.styles);
  }
  static finalizeStyles(e) {
    const i = [];
    if (Array.isArray(e)) {
      const s = new Set(e.flat(1 / 0).reverse());
      for (const o of s) i.unshift(Z(o));
    } else e !== void 0 && i.push(Z(e));
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
    return _e(e, this.constructor.elementStyles), e;
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
    const s = this.constructor.elementProperties.get(e), o = this.constructor._$Eu(e, s);
    if (o !== void 0 && s.reflect === !0) {
      const a = (s.converter?.toAttribute !== void 0 ? s.converter : L).toAttribute(i, s.type);
      this._$Em = e, a == null ? this.removeAttribute(o) : this.setAttribute(o, a), this._$Em = null;
    }
  }
  _$AK(e, i) {
    const s = this.constructor, o = s._$Eh.get(e);
    if (o !== void 0 && this._$Em !== o) {
      const a = s.getPropertyOptions(o), n = typeof a.converter == "function" ? { fromAttribute: a.converter } : a.converter?.fromAttribute !== void 0 ? a.converter : L;
      this._$Em = o;
      const h = n.fromAttribute(i, a.type);
      this[o] = h ?? this._$Ej?.get(o) ?? h, this._$Em = null;
    }
  }
  requestUpdate(e, i, s, o = !1, a) {
    if (e !== void 0) {
      const n = this.constructor;
      if (o === !1 && (a = this[e]), s ??= n.getPropertyOptions(e), !((s.hasChanged ?? Y)(a, i) || s.useDefault && s.reflect && a === this._$Ej?.get(e) && !this.hasAttribute(n._$Eu(e, s)))) return;
      this.C(e, i, s);
    }
    this.isUpdatePending === !1 && (this._$ES = this._$EP());
  }
  C(e, i, { useDefault: s, reflect: o, wrapped: a }, n) {
    s && !(this._$Ej ??= /* @__PURE__ */ new Map()).has(e) && (this._$Ej.set(e, n ?? i ?? this[e]), a !== !0 || n !== void 0) || (this._$AL.has(e) || (this.hasUpdated || s || (i = void 0), this._$AL.set(e, i)), o === !0 && this._$Em !== e && (this._$Eq ??= /* @__PURE__ */ new Set()).add(e));
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
        for (const [o, a] of this._$Ep) this[o] = a;
        this._$Ep = void 0;
      }
      const s = this.constructor.elementProperties;
      if (s.size > 0) for (const [o, a] of s) {
        const { wrapped: n } = a, h = this[o];
        n !== !0 || this._$AL.has(o) || h === void 0 || this.C(o, void 0, a, h);
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
b.elementStyles = [], b.shadowRootOptions = { mode: "open" }, b[E("elementProperties")] = /* @__PURE__ */ new Map(), b[E("finalized")] = /* @__PURE__ */ new Map(), Se?.({ ReactiveElement: b }), (N.reactiveElementVersions ??= []).push("2.1.2");
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const q = globalThis, te = (t) => t, R = q.trustedTypes, ie = R ? R.createPolicy("lit-html", { createHTML: (t) => t }) : void 0, ce = "$lit$", _ = `lit$${Math.random().toFixed(9).slice(2)}$`, pe = "?" + _, Ae = `<${pe}>`, y = document, k = () => y.createComment(""), j = (t) => t === null || typeof t != "object" && typeof t != "function", V = Array.isArray, Pe = (t) => V(t) || typeof t?.[Symbol.iterator] == "function", H = `[ 	
\f\r]`, P = /<(?:(!--|\/[^a-zA-Z])|(\/?[a-zA-Z][^>\s]*)|(\/?$))/g, se = /-->/g, oe = />/g, v = RegExp(`>|${H}(?:([^\\s"'>=/]+)(${H}*=${H}*(?:[^ 	
\f\r"'\`<>=]|("|')|))|$)`, "g"), ae = /'/g, ne = /"/g, ge = /^(?:script|style|textarea|title)$/i, Ee = (t) => (e, ...i) => ({ _$litType$: t, strings: e, values: i }), l = Ee(1), C = Symbol.for("lit-noChange"), r = Symbol.for("lit-nothing"), re = /* @__PURE__ */ new WeakMap(), w = y.createTreeWalker(y, 129);
function ue(t, e) {
  if (!V(t) || !t.hasOwnProperty("raw")) throw Error("invalid template strings array");
  return ie !== void 0 ? ie.createHTML(e) : e;
}
const ke = (t, e) => {
  const i = t.length - 1, s = [];
  let o, a = e === 2 ? "<svg>" : e === 3 ? "<math>" : "", n = P;
  for (let h = 0; h < i; h++) {
    const d = t[h];
    let c, p, g = -1, u = 0;
    for (; u < d.length && (n.lastIndex = u, p = n.exec(d), p !== null); ) u = n.lastIndex, n === P ? p[1] === "!--" ? n = se : p[1] !== void 0 ? n = oe : p[2] !== void 0 ? (ge.test(p[2]) && (o = RegExp("</" + p[2], "g")), n = v) : p[3] !== void 0 && (n = v) : n === v ? p[0] === ">" ? (n = o ?? P, g = -1) : p[1] === void 0 ? g = -2 : (g = n.lastIndex - p[2].length, c = p[1], n = p[3] === void 0 ? v : p[3] === '"' ? ne : ae) : n === ne || n === ae ? n = v : n === se || n === oe ? n = P : (n = v, o = void 0);
    const m = n === v && t[h + 1].startsWith("/>") ? " " : "";
    a += n === P ? d + Ae : g >= 0 ? (s.push(c), d.slice(0, g) + ce + d.slice(g) + _ + m) : d + _ + (g === -2 ? h : m);
  }
  return [ue(t, a + (t[i] || "<?>") + (e === 2 ? "</svg>" : e === 3 ? "</math>" : "")), s];
};
class M {
  constructor({ strings: e, _$litType$: i }, s) {
    let o;
    this.parts = [];
    let a = 0, n = 0;
    const h = e.length - 1, d = this.parts, [c, p] = ke(e, i);
    if (this.el = M.createElement(c, s), w.currentNode = this.el.content, i === 2 || i === 3) {
      const g = this.el.content.firstChild;
      g.replaceWith(...g.childNodes);
    }
    for (; (o = w.nextNode()) !== null && d.length < h; ) {
      if (o.nodeType === 1) {
        if (o.hasAttributes()) for (const g of o.getAttributeNames()) if (g.endsWith(ce)) {
          const u = p[n++], m = o.getAttribute(g).split(_), I = /([.?@])?(.*)/.exec(u);
          d.push({ type: 1, index: a, name: I[2], strings: m, ctor: I[1] === "." ? Me : I[1] === "?" ? Te : I[1] === "@" ? ze : U }), o.removeAttribute(g);
        } else g.startsWith(_) && (d.push({ type: 6, index: a }), o.removeAttribute(g));
        if (ge.test(o.tagName)) {
          const g = o.textContent.split(_), u = g.length - 1;
          if (u > 0) {
            o.textContent = R ? R.emptyScript : "";
            for (let m = 0; m < u; m++) o.append(g[m], k()), w.nextNode(), d.push({ type: 2, index: ++a });
            o.append(g[u], k());
          }
        }
      } else if (o.nodeType === 8) if (o.data === pe) d.push({ type: 2, index: a });
      else {
        let g = -1;
        for (; (g = o.data.indexOf(_, g + 1)) !== -1; ) d.push({ type: 7, index: a }), g += _.length - 1;
      }
      a++;
    }
  }
  static createElement(e, i) {
    const s = y.createElement("template");
    return s.innerHTML = e, s;
  }
}
function S(t, e, i = t, s) {
  if (e === C) return e;
  let o = s !== void 0 ? i._$Co?.[s] : i._$Cl;
  const a = j(e) ? void 0 : e._$litDirective$;
  return o?.constructor !== a && (o?._$AO?.(!1), a === void 0 ? o = void 0 : (o = new a(t), o._$AT(t, i, s)), s !== void 0 ? (i._$Co ??= [])[s] = o : i._$Cl = o), o !== void 0 && (e = S(t, o._$AS(t, e.values), o, s)), e;
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
    const { el: { content: i }, parts: s } = this._$AD, o = (e?.creationScope ?? y).importNode(i, !0);
    w.currentNode = o;
    let a = w.nextNode(), n = 0, h = 0, d = s[0];
    for (; d !== void 0; ) {
      if (n === d.index) {
        let c;
        d.type === 2 ? c = new z(a, a.nextSibling, this, e) : d.type === 1 ? c = new d.ctor(a, d.name, d.strings, this, e) : d.type === 6 && (c = new Ie(a, this, e)), this._$AV.push(c), d = s[++h];
      }
      n !== d?.index && (a = w.nextNode(), n++);
    }
    return w.currentNode = y, o;
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
  constructor(e, i, s, o) {
    this.type = 2, this._$AH = r, this._$AN = void 0, this._$AA = e, this._$AB = i, this._$AM = s, this.options = o, this._$Cv = o?.isConnected ?? !0;
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
    e = S(this, e, i), j(e) ? e === r || e == null || e === "" ? (this._$AH !== r && this._$AR(), this._$AH = r) : e !== this._$AH && e !== C && this._(e) : e._$litType$ !== void 0 ? this.$(e) : e.nodeType !== void 0 ? this.T(e) : Pe(e) ? this.k(e) : this._(e);
  }
  O(e) {
    return this._$AA.parentNode.insertBefore(e, this._$AB);
  }
  T(e) {
    this._$AH !== e && (this._$AR(), this._$AH = this.O(e));
  }
  _(e) {
    this._$AH !== r && j(this._$AH) ? this._$AA.nextSibling.data = e : this.T(y.createTextNode(e)), this._$AH = e;
  }
  $(e) {
    const { values: i, _$litType$: s } = e, o = typeof s == "number" ? this._$AC(e) : (s.el === void 0 && (s.el = M.createElement(ue(s.h, s.h[0]), this.options)), s);
    if (this._$AH?._$AD === o) this._$AH.p(i);
    else {
      const a = new je(o, this), n = a.u(this.options);
      a.p(i), this.T(n), this._$AH = a;
    }
  }
  _$AC(e) {
    let i = re.get(e.strings);
    return i === void 0 && re.set(e.strings, i = new M(e)), i;
  }
  k(e) {
    V(this._$AH) || (this._$AH = [], this._$AR());
    const i = this._$AH;
    let s, o = 0;
    for (const a of e) o === i.length ? i.push(s = new z(this.O(k()), this.O(k()), this, this.options)) : s = i[o], s._$AI(a), o++;
    o < i.length && (this._$AR(s && s._$AB.nextSibling, o), i.length = o);
  }
  _$AR(e = this._$AA.nextSibling, i) {
    for (this._$AP?.(!1, !0, i); e !== this._$AB; ) {
      const s = te(e).nextSibling;
      te(e).remove(), e = s;
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
  constructor(e, i, s, o, a) {
    this.type = 1, this._$AH = r, this._$AN = void 0, this.element = e, this.name = i, this._$AM = o, this.options = a, s.length > 2 || s[0] !== "" || s[1] !== "" ? (this._$AH = Array(s.length - 1).fill(new String()), this.strings = s) : this._$AH = r;
  }
  _$AI(e, i = this, s, o) {
    const a = this.strings;
    let n = !1;
    if (a === void 0) e = S(this, e, i, 0), n = !j(e) || e !== this._$AH && e !== C, n && (this._$AH = e);
    else {
      const h = e;
      let d, c;
      for (e = a[0], d = 0; d < a.length - 1; d++) c = S(this, h[s + d], i, d), c === C && (c = this._$AH[d]), n ||= !j(c) || c !== this._$AH[d], c === r ? e = r : e !== r && (e += (c ?? "") + a[d + 1]), this._$AH[d] = c;
    }
    n && !o && this.j(e);
  }
  j(e) {
    e === r ? this.element.removeAttribute(this.name) : this.element.setAttribute(this.name, e ?? "");
  }
}
class Me extends U {
  constructor() {
    super(...arguments), this.type = 3;
  }
  j(e) {
    this.element[this.name] = e === r ? void 0 : e;
  }
}
class Te extends U {
  constructor() {
    super(...arguments), this.type = 4;
  }
  j(e) {
    this.element.toggleAttribute(this.name, !!e && e !== r);
  }
}
class ze extends U {
  constructor(e, i, s, o, a) {
    super(e, i, s, o, a), this.type = 5;
  }
  _$AI(e, i = this) {
    if ((e = S(this, e, i, 0) ?? r) === C) return;
    const s = this._$AH, o = e === r && s !== r || e.capture !== s.capture || e.once !== s.once || e.passive !== s.passive, a = e !== r && (s === r || o);
    o && this.element.removeEventListener(this.name, this, s), a && this.element.addEventListener(this.name, this, e), this._$AH = e;
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
const De = q.litHtmlPolyfillSupport;
De?.(M, z), (q.litHtmlVersions ??= []).push("3.3.2");
const Oe = (t, e, i) => {
  const s = i?.renderBefore ?? e;
  let o = s._$litPart$;
  if (o === void 0) {
    const a = i?.renderBefore ?? null;
    s._$litPart$ = o = new z(e.insertBefore(k(), a), a, void 0, i ?? {});
  }
  return o._$AI(t), o;
};
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const G = globalThis;
class x extends b {
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
x._$litElement$ = !0, x.finalized = !0, G.litElementHydrateSupport?.({ LitElement: x });
const Le = G.litElementPolyfillSupport;
Le?.({ LitElement: x });
(G.litElementVersions ??= []).push("4.2.2");
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
const Re = { attribute: !0, type: String, converter: L, reflect: !1, hasChanged: Y }, Ne = (t = Re, e, i) => {
  const { kind: s, metadata: o } = i;
  let a = globalThis.litPropertyMetadata.get(o);
  if (a === void 0 && globalThis.litPropertyMetadata.set(o, a = /* @__PURE__ */ new Map()), s === "setter" && ((t = Object.create(t)).wrapped = !0), a.set(i.name, t), s === "accessor") {
    const { name: n } = i;
    return { set(h) {
      const d = e.get.call(this);
      e.set.call(this, h), this.requestUpdate(n, d, t, !0, h);
    }, init(h) {
      return h !== void 0 && this.C(n, void 0, t, h), h;
    } };
  }
  if (s === "setter") {
    const { name: n } = i;
    return function(h) {
      const d = this[n];
      e.call(this, h), this.requestUpdate(n, d, t, !0, h);
    };
  }
  throw Error("Unsupported decorator location: " + s);
};
function F(t) {
  return (e, i) => typeof i == "object" ? Ne(t, e, i) : ((s, o, a) => {
    const n = o.hasOwnProperty(a);
    return o.constructor.createProperty(a, s), n ? Object.getOwnPropertyDescriptor(o, a) : void 0;
  })(t, e, i);
}
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
function A(t) {
  return F({ ...t, state: !0, attribute: !1 });
}
const Ue = de`
  :host {
    --jf-card-bg: var(--card-background-color, #1c1c1c);
    --jf-primary: var(--primary-color, #03a9f4);
    --jf-text: var(--primary-text-color, #fff);
    --jf-text-secondary: var(--secondary-text-color, rgba(255, 255, 255, 0.7));
    --jf-divider: var(--divider-color, rgba(255, 255, 255, 0.12));
    --jf-poster-radius: 10px;
    --jf-transition: 0s;
    --jf-movie-badge: rgba(99, 102, 241, 0.85);
    --jf-series-badge: rgba(245, 158, 11, 0.85);
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
function B(t, e) {
  const i = t.split("-")[0].toLowerCase();
  return D[i]?.[e] ? D[i][e] : D.en?.[e] ? D.en[e] : e;
}
var He = Object.defineProperty, Be = Object.getOwnPropertyDescriptor, J = (t, e, i, s) => {
  for (var o = s > 1 ? void 0 : s ? Be(e, i) : e, a = t.length - 1, n; a >= 0; a--)
    (n = t[a]) && (o = (s ? n(e, i, o) : n(o)) || o);
  return s && o && He(e, i, o), o;
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
    return !this.hass || !this._config ? l`` : l`
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

        ${this._config.layout === "grid" || this._config.layout === "list" ? l`
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
T.styles = de`
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
J([
  F({ attribute: !1 })
], T.prototype, "hass", 2);
J([
  A()
], T.prototype, "_config", 2);
T = J([
  fe("jellyha-library-editor")
], T);
var Xe = Object.defineProperty, Ye = Object.getOwnPropertyDescriptor, $ = (t, e, i, s) => {
  for (var o = s > 1 ? void 0 : s ? Ye(e, i) : e, a = t.length - 1, n; a >= 0; a--)
    (n = t[a]) && (o = (s ? n(e, i, o) : n(o)) || o);
  return s && o && Xe(e, i, o), o;
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
  theme: "auto"
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
    const e = t.attributes, i = this._filterItems(e.items || []), s = this._config?.items_per_page || this._itemsPerPage, o = this._config?.max_pages || 10, a = Math.min(Math.ceil(i.length / s), o);
    a > 1 && (this._currentPage = (this._currentPage + 1) % a, this.requestUpdate());
  }
  _prevPage() {
    if (!this._config || !this.hass) return;
    const t = this.hass.states[this._config.entity];
    if (!t) return;
    const e = t.attributes, i = this._filterItems(e.items || []), s = this._config?.items_per_page || this._itemsPerPage, o = this._config?.max_pages || 10, a = Math.min(Math.ceil(i.length / s), o);
    a > 1 && (this._currentPage = (this._currentPage - 1 + a) % a, this.requestUpdate());
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
    const e = t.target, i = e.scrollWidth, s = e.clientWidth, o = e.scrollLeft, a = i > s + 10;
    if (a !== this._hasScrollableContent && (this._hasScrollableContent = a), a) {
      const n = i - s;
      let h = o / n;
      (n - o < 10 || h > 0.98) && (h = 1), (o < 10 || h < 0.02) && (h = 0), h = Math.min(1, Math.max(0, h)), this._scrollProgress = h;
    }
  }
  // Render scroll indicator for non-paginated scrollable content
  _renderScrollIndicator() {
    if (!this._hasScrollableContent) return l``;
    const t = this.SCROLL_INDICATOR_DOTS, e = this._scrollProgress, i = Math.round(e * (t - 1));
    return l`
      <div class="scroll-indicator">
        ${Array.from({ length: t }, (s, o) => {
      const a = o === i, n = o === 0 && e < 0.1 || o === t - 1 && e > 0.9;
      return l`
        <span 
          class="scroll-dot ${a ? "active" : ""} ${n ? "pill" : ""}"
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
            const o = Math.max(1, Math.floor(e / this.LIST_ITEM_MIN_WIDTH)), a = Math.min(s, o);
            a !== this._effectiveListColumns && (this._effectiveListColumns = a, this.requestUpdate());
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
      entity: "",
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
      return l``;
    const t = this.hass.states[this._config.entity];
    if (!t)
      return this._renderError(`Entity not found: ${this._config.entity}`);
    const e = t.attributes, i = this._filterItems(e.items || []);
    return l`
      <ha-card>
        ${this._config.title ? l`
              <div class="card-header">
                <h2>${this._config.title}</h2>
              </div>
            ` : r}
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
    return e === "carousel" ? this._renderCarousel(t, i) : e === "list" ? this._renderList(t, i) : e === "grid" ? this._renderGrid(t, i) : l`
      <div class="${e}">
        ${t.map((s) => this._renderMediaItem(s))}
      </div>
    `;
  }
  /**
   * Render carousel with optional pagination
   */
  _renderCarousel(t, e) {
    const i = this._config.items_per_page || this._itemsPerPage, s = this._config.max_pages || 10, o = Math.min(Math.ceil(t.length / i), s), a = this._currentPage * i, n = e ? t.slice(a, a + i) : t;
    return l`
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
          @scroll="${e ? r : this._handleScroll}"
        >
          ${n.map((h) => this._renderMediaItem(h))}
        </div>
        ${e && o > 1 ? l`
              <div class="pagination-dots">
                ${Array.from({ length: o }, (h, d) => l`
                  <button
                    type="button"
                    class="pagination-dot ${d === this._currentPage ? "active" : ""}"
                    data-page="${d}"
                    @click="${this._onDotClick}"
                    aria-label="Go to page ${d + 1}"
                  ></button>
                `)}
              </div>
            ` : r}
        ${e ? r : this._renderScrollIndicator()}
      </div>
    `;
  }
  /**
   * Render list with optional pagination
   */
  _renderList(t, e) {
    const i = this._config.items_per_page || this._itemsPerPage, s = this._config.max_pages || 10, o = Math.min(Math.ceil(t.length / i), s), a = this._currentPage * i, n = e ? t.slice(a, a + i) : t, h = this._effectiveListColumns, d = h === 1;
    return l`
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
          class="list ${e ? "paginated" : ""} ${d ? "single-column" : ""}"
          style="--jf-list-columns: ${h}"
        >
          ${n.map((c) => this._renderListItem(c))}
        </div>
        ${e && o > 1 ? l`
              <div class="pagination-dots">
                ${Array.from({ length: o }, (c, p) => l`
                  <button
                    type="button"
                    class="pagination-dot ${p === this._currentPage ? "active" : ""}"
                    data-page="${p}"
                    @click="${this._onDotClick}"
                    aria-label="Go to page ${p + 1}"
                  ></button>
                `)}
              </div>
            ` : r}
      </div>
    `;
  }
  /**
   * Render grid with optional pagination
   */
  _renderGrid(t, e) {
    const i = this._config.items_per_page || this._itemsPerPage, s = this._config.max_pages || 10, o = Math.min(Math.ceil(t.length / i), s), a = this._currentPage * i, n = e ? t.slice(a, a + i) : t, h = this._config.columns || 1, d = h === 1;
    return l`
      <div class="grid-outer">
        <div 
          class="grid-wrapper"
          @touchstart="${this._handleTouchStart}"
          @touchmove="${this._handleTouchMove}"
          @touchend="${this._handleTouchEnd}"
          @pointerdown="${this._handlePointerDown}"
          @pointermove="${this._handlePointerMove}"
          @pointerup="${this._handlePointerUp}"
          @scroll="${e ? r : this._handleScroll}"
        >
          <div
            class="grid ${e ? "paginated" : ""} ${d ? "auto-columns" : ""}"
            style="--jf-columns: ${h}"
          >
            ${n.map((c) => this._renderMediaItem(c))}
          </div>
        </div>
        ${e && o > 1 ? l`
              <div class="pagination-dots">
                ${Array.from({ length: o }, (c, p) => l`
                  <button
                    type="button"
                    class="pagination-dot ${p === this._currentPage ? "active" : ""}"
                    data-page="${p}"
                    @click="${this._onDotClick}"
                    aria-label="Go to page ${p + 1}"
                  ></button>
                `)}
              </div>
            ` : r}
        ${e ? r : this._renderScrollIndicator()}
      </div>
    `;
  }
  /**
   * Render individual list item (horizontal layout with metadata outside poster)
   */
  _renderListItem(t) {
    const e = this._isNewItem(t), i = this._getRating(t), s = this._config.show_media_type_badge !== !1;
    return l`
      <div
        class="media-item list-item ${this._config.show_title ? "" : "no-title"} ${this._config.metadata_position === "above" ? "metadata-above" : ""}"
        tabindex="0"
        role="button"
        aria-label="${t.name}"
        @click="${() => this._handleClick(t)}"
        @keydown="${(o) => this._handleKeydown(o, t)}"
      >
        <div class="list-poster-wrapper">
          ${this._config.metadata_position === "above" && this._config.show_date_added && t.date_added ? l`<p class="list-date-added">${this._formatDate(t.date_added)}</p>` : r}
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
              
              ${e ? l`<span class="new-badge">${B(this.hass.language, "new")}</span>` : r}
            </div>
          </div>
          ${this._config.metadata_position !== "above" && this._config.show_date_added && t.date_added ? l`<p class="list-date-added">${this._formatDate(t.date_added)}</p>` : r}
        </div>
        
        <div class="list-info">
          ${this._config.show_title ? l`<h3 class="list-title">${t.name}</h3>` : r}
          
          <div class="list-metadata">
            ${s ? l`<span class="list-type-badge ${t.type === "Movie" ? "movie" : "series"}">
                  ${t.type === "Movie" ? "Movie" : "Series"}
                </span>` : r}
            ${this._config.show_year && t.year ? l`<span class="list-year">${t.year}</span>` : r}
            ${this._config.show_ratings && i ? l`<span class="list-rating">
                  <ha-icon icon="mdi:star"></ha-icon>
                  ${i.toFixed(1)}
                </span>` : r}
            ${this._config.show_runtime && t.runtime_minutes ? l`<span class="list-runtime">
                  <ha-icon icon="mdi:clock-outline"></ha-icon>
                  ${this._formatRuntime(t.runtime_minutes)}
                </span>` : r}
          </div>
          
          ${this._config.show_genres && t.genres && t.genres.length > 0 ? l`<p class="list-genres">${t.genres.slice(0, 3).join(", ")}</p>` : r}
          
          ${this._config.show_description_on_hover !== !1 && t.description ? l`<p class="list-description">${t.description}</p>` : r}
        </div>
      </div>
    `;
  }
  /**
   * Render individual media item
   */
  _renderMediaItem(t) {
    const e = this._isNewItem(t), i = this._getRating(t), s = this._config.show_media_type_badge !== !1;
    return this._config.show_description_on_hover, l`
      <div
        class="media-item"
        tabindex="0"
        role="button"
        aria-label="${t.name}"
        @click="${() => this._handleClick(t)}"
        @keydown="${(o) => this._handleKeydown(o, t)}"
      >
        ${this._config.metadata_position === "above" ? l`
              <div class="media-info-above">
                ${this._config.show_title ? l`<p class="media-title">${t.name}</p>` : r}
                ${this._config.show_year && t.year ? l`<p class="media-year">${t.year}</p>` : r}
                ${this._config.show_date_added && t.date_added ? l`<p class="media-date-added">${this._formatDate(t.date_added)}</p>` : r}
              </div>
            ` : r}
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
            
            ${s ? l`<span class="media-type-badge ${t.type === "Movie" ? "movie" : "series"}">
                  ${t.type === "Movie" ? "Movie" : "Series"}
                </span>` : r}
            
            ${e ? l`<span class="new-badge">${B(this.hass.language, "new")}</span>` : r}
            
            ${this._config.show_ratings && i ? l`
                  <span class="rating">
                    <ha-icon icon="mdi:star"></ha-icon>
                    ${i.toFixed(1)}
                  </span>
                ` : r}
            
            ${this._config.show_runtime && t.runtime_minutes ? l`
                  <span class="runtime">
                    <ha-icon icon="mdi:clock-outline"></ha-icon>
                    ${this._formatRuntime(t.runtime_minutes)}
                  </span>
                ` : r}
            
            <div class="hover-overlay">
                    ${t.year ? l`<span class="overlay-year">${t.year}</span>` : r}
                    <h3 class="overlay-title">${t.name}</h3>
                    ${this._config.show_genres && t.genres && t.genres.length > 0 ? l`<span class="overlay-genres">${t.genres.slice(0, 3).join(", ")}</span>` : r}
                    ${this._config.show_description_on_hover !== !1 && t.description ? l`<p class="overlay-description">${t.description}</p>` : r}
                  </div>
          </div>
        </div>
        
        ${this._config.metadata_position === "below" ? l`
              <div class="media-info-below">
                ${this._config.show_title ? l`<p class="media-title">${t.name}</p>` : r}
                ${this._config.show_year && t.year ? l`<p class="media-year">${t.year}</p>` : r}
                ${this._config.show_date_added && t.date_added ? l`<p class="media-date-added">${this._formatDate(t.date_added)}</p>` : r}
              </div>
            ` : r}
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
    return l`
      <div class="empty">
        <ha-icon icon="mdi:movie-open-outline"></ha-icon>
        <p>${B(this.hass.language, "no_media")}</p>
      </div>
    `;
  }
  /**
   * Render error state
   */
  _renderError(t) {
    return l`
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
$([
  F({ attribute: !1 })
], f.prototype, "hass", 2);
$([
  A()
], f.prototype, "_config", 2);
$([
  A()
], f.prototype, "_currentPage", 2);
$([
  A()
], f.prototype, "_itemsPerPage", 2);
$([
  A()
], f.prototype, "_scrollProgress", 2);
$([
  A()
], f.prototype, "_hasScrollableContent", 2);
f = $([
  fe("jellyha-library-card")
], f);
//# sourceMappingURL=jellyha-cards.js.map
