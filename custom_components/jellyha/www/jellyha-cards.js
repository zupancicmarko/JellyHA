/**
 * @license
 * Copyright 2019 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const te = globalThis, ce = te.ShadowRoot && (te.ShadyCSS === void 0 || te.ShadyCSS.nativeShadow) && "adoptedStyleSheets" in Document.prototype && "replace" in CSSStyleSheet.prototype, he = Symbol(), be = /* @__PURE__ */ new WeakMap();
let Ee = class {
  constructor(e, i, o) {
    if (this._$cssResult$ = !0, o !== he) throw Error("CSSResult is not constructable. Use `unsafeCSS` or `css` instead.");
    this.cssText = e, this.t = i;
  }
  get styleSheet() {
    let e = this.o;
    const i = this.t;
    if (ce && e === void 0) {
      const o = i !== void 0 && i.length === 1;
      o && (e = be.get(i)), e === void 0 && ((this.o = e = new CSSStyleSheet()).replaceSync(this.cssText), o && be.set(i, e));
    }
    return e;
  }
  toString() {
    return this.cssText;
  }
};
const Re = (t) => new Ee(typeof t == "string" ? t : t + "", void 0, he), q = (t, ...e) => {
  const i = t.length === 1 ? t[0] : e.reduce((o, a, s) => o + ((r) => {
    if (r._$cssResult$ === !0) return r.cssText;
    if (typeof r == "number") return r;
    throw Error("Value passed to 'css' function must be a 'css' function result: " + r + ". Use 'unsafeCSS' to pass non-literal values, but take care to ensure page security.");
  })(a) + t[s + 1], t[0]);
  return new Ee(i, t, he);
}, Le = (t, e) => {
  if (ce) t.adoptedStyleSheets = e.map((i) => i instanceof CSSStyleSheet ? i : i.styleSheet);
  else for (const i of e) {
    const o = document.createElement("style"), a = te.litNonce;
    a !== void 0 && o.setAttribute("nonce", a), o.textContent = i.cssText, t.appendChild(o);
  }
}, ye = ce ? (t) => t : (t) => t instanceof CSSStyleSheet ? ((e) => {
  let i = "";
  for (const o of e.cssRules) i += o.cssText;
  return Re(i);
})(t) : t;
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const { is: He, defineProperty: Fe, getOwnPropertyDescriptor: Be, getOwnPropertyNames: We, getOwnPropertySymbols: Ge, getPrototypeOf: Ye } = Object, ae = globalThis, ve = ae.trustedTypes, Xe = ve ? ve.emptyScript : "", Je = ae.reactiveElementPolyfillSupport, F = (t, e) => t, ie = { toAttribute(t, e) {
  switch (e) {
    case Boolean:
      t = t ? Xe : null;
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
} }, pe = (t, e) => !He(t, e), xe = { attribute: !0, type: String, converter: ie, reflect: !1, useDefault: !1, hasChanged: pe };
Symbol.metadata ??= Symbol("metadata"), ae.litPropertyMetadata ??= /* @__PURE__ */ new WeakMap();
let O = class extends HTMLElement {
  static addInitializer(e) {
    this._$Ei(), (this.l ??= []).push(e);
  }
  static get observedAttributes() {
    return this.finalize(), this._$Eh && [...this._$Eh.keys()];
  }
  static createProperty(e, i = xe) {
    if (i.state && (i.attribute = !1), this._$Ei(), this.prototype.hasOwnProperty(e) && ((i = Object.create(i)).wrapped = !0), this.elementProperties.set(e, i), !i.noAccessor) {
      const o = Symbol(), a = this.getPropertyDescriptor(e, o, i);
      a !== void 0 && Fe(this.prototype, e, a);
    }
  }
  static getPropertyDescriptor(e, i, o) {
    const { get: a, set: s } = Be(this.prototype, e) ?? { get() {
      return this[i];
    }, set(r) {
      this[i] = r;
    } };
    return { get: a, set(r) {
      const h = a?.call(this);
      s?.call(this, r), this.requestUpdate(e, h, o);
    }, configurable: !0, enumerable: !0 };
  }
  static getPropertyOptions(e) {
    return this.elementProperties.get(e) ?? xe;
  }
  static _$Ei() {
    if (this.hasOwnProperty(F("elementProperties"))) return;
    const e = Ye(this);
    e.finalize(), e.l !== void 0 && (this.l = [...e.l]), this.elementProperties = new Map(e.elementProperties);
  }
  static finalize() {
    if (this.hasOwnProperty(F("finalized"))) return;
    if (this.finalized = !0, this._$Ei(), this.hasOwnProperty(F("properties"))) {
      const i = this.properties, o = [...We(i), ...Ge(i)];
      for (const a of o) this.createProperty(a, i[a]);
    }
    const e = this[Symbol.metadata];
    if (e !== null) {
      const i = litPropertyMetadata.get(e);
      if (i !== void 0) for (const [o, a] of i) this.elementProperties.set(o, a);
    }
    this._$Eh = /* @__PURE__ */ new Map();
    for (const [i, o] of this.elementProperties) {
      const a = this._$Eu(i, o);
      a !== void 0 && this._$Eh.set(a, i);
    }
    this.elementStyles = this.finalizeStyles(this.styles);
  }
  static finalizeStyles(e) {
    const i = [];
    if (Array.isArray(e)) {
      const o = new Set(e.flat(1 / 0).reverse());
      for (const a of o) i.unshift(ye(a));
    } else e !== void 0 && i.push(ye(e));
    return i;
  }
  static _$Eu(e, i) {
    const o = i.attribute;
    return o === !1 ? void 0 : typeof o == "string" ? o : typeof e == "string" ? e.toLowerCase() : void 0;
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
    for (const o of i.keys()) this.hasOwnProperty(o) && (e.set(o, this[o]), delete this[o]);
    e.size > 0 && (this._$Ep = e);
  }
  createRenderRoot() {
    const e = this.shadowRoot ?? this.attachShadow(this.constructor.shadowRootOptions);
    return Le(e, this.constructor.elementStyles), e;
  }
  connectedCallback() {
    this.renderRoot ??= this.createRenderRoot(), this.enableUpdating(!0), this._$EO?.forEach((e) => e.hostConnected?.());
  }
  enableUpdating(e) {
  }
  disconnectedCallback() {
    this._$EO?.forEach((e) => e.hostDisconnected?.());
  }
  attributeChangedCallback(e, i, o) {
    this._$AK(e, o);
  }
  _$ET(e, i) {
    const o = this.constructor.elementProperties.get(e), a = this.constructor._$Eu(e, o);
    if (a !== void 0 && o.reflect === !0) {
      const s = (o.converter?.toAttribute !== void 0 ? o.converter : ie).toAttribute(i, o.type);
      this._$Em = e, s == null ? this.removeAttribute(a) : this.setAttribute(a, s), this._$Em = null;
    }
  }
  _$AK(e, i) {
    const o = this.constructor, a = o._$Eh.get(e);
    if (a !== void 0 && this._$Em !== a) {
      const s = o.getPropertyOptions(a), r = typeof s.converter == "function" ? { fromAttribute: s.converter } : s.converter?.fromAttribute !== void 0 ? s.converter : ie;
      this._$Em = a;
      const h = r.fromAttribute(i, s.type);
      this[a] = h ?? this._$Ej?.get(a) ?? h, this._$Em = null;
    }
  }
  requestUpdate(e, i, o, a = !1, s) {
    if (e !== void 0) {
      const r = this.constructor;
      if (a === !1 && (s = this[e]), o ??= r.getPropertyOptions(e), !((o.hasChanged ?? pe)(s, i) || o.useDefault && o.reflect && s === this._$Ej?.get(e) && !this.hasAttribute(r._$Eu(e, o)))) return;
      this.C(e, i, o);
    }
    this.isUpdatePending === !1 && (this._$ES = this._$EP());
  }
  C(e, i, { useDefault: o, reflect: a, wrapped: s }, r) {
    o && !(this._$Ej ??= /* @__PURE__ */ new Map()).has(e) && (this._$Ej.set(e, r ?? i ?? this[e]), s !== !0 || r !== void 0) || (this._$AL.has(e) || (this.hasUpdated || o || (i = void 0), this._$AL.set(e, i)), a === !0 && this._$Em !== e && (this._$Eq ??= /* @__PURE__ */ new Set()).add(e));
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
        for (const [a, s] of this._$Ep) this[a] = s;
        this._$Ep = void 0;
      }
      const o = this.constructor.elementProperties;
      if (o.size > 0) for (const [a, s] of o) {
        const { wrapped: r } = s, h = this[a];
        r !== !0 || this._$AL.has(a) || h === void 0 || this.C(a, void 0, s, h);
      }
    }
    let e = !1;
    const i = this._$AL;
    try {
      e = this.shouldUpdate(i), e ? (this.willUpdate(i), this._$EO?.forEach((o) => o.hostUpdate?.()), this.update(i)) : this._$EM();
    } catch (o) {
      throw e = !1, this._$EM(), o;
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
O.elementStyles = [], O.shadowRootOptions = { mode: "open" }, O[F("elementProperties")] = /* @__PURE__ */ new Map(), O[F("finalized")] = /* @__PURE__ */ new Map(), Je?.({ ReactiveElement: O }), (ae.reactiveElementVersions ??= []).push("2.1.2");
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const _e = globalThis, $e = (t) => t, oe = _e.trustedTypes, ke = oe ? oe.createPolicy("lit-html", { createHTML: (t) => t }) : void 0, Me = "$lit$", T = `lit$${Math.random().toFixed(9).slice(2)}$`, ze = "?" + T, qe = `<${ze}>`, D = document, W = () => D.createComment(""), G = (t) => t === null || typeof t != "object" && typeof t != "function", ge = Array.isArray, Ve = (t) => ge(t) || typeof t?.[Symbol.iterator] == "function", ne = `[ 	
\f\r]`, H = /<(?:(!--|\/[^a-zA-Z])|(\/?[a-zA-Z][^>\s]*)|(\/?$))/g, Se = /-->/g, Ce = />/g, M = RegExp(`>|${ne}(?:([^\\s"'>=/]+)(${ne}*=${ne}*(?:[^ 	
\f\r"'\`<>=]|("|')|))|$)`, "g"), Pe = /'/g, Ae = /"/g, De = /^(?:script|style|textarea|title)$/i, Ze = (t) => (e, ...i) => ({ _$litType$: t, strings: e, values: i }), n = Ze(1), N = Symbol.for("lit-noChange"), d = Symbol.for("lit-nothing"), je = /* @__PURE__ */ new WeakMap(), z = D.createTreeWalker(D, 129);
function Ie(t, e) {
  if (!ge(t) || !t.hasOwnProperty("raw")) throw Error("invalid template strings array");
  return ke !== void 0 ? ke.createHTML(e) : e;
}
const Ke = (t, e) => {
  const i = t.length - 1, o = [];
  let a, s = e === 2 ? "<svg>" : e === 3 ? "<math>" : "", r = H;
  for (let h = 0; h < i; h++) {
    const c = t[h];
    let _, g, p = -1, m = 0;
    for (; m < c.length && (r.lastIndex = m, g = r.exec(c), g !== null); ) m = r.lastIndex, r === H ? g[1] === "!--" ? r = Se : g[1] !== void 0 ? r = Ce : g[2] !== void 0 ? (De.test(g[2]) && (a = RegExp("</" + g[2], "g")), r = M) : g[3] !== void 0 && (r = M) : r === M ? g[0] === ">" ? (r = a ?? H, p = -1) : g[1] === void 0 ? p = -2 : (p = r.lastIndex - g[2].length, _ = g[1], r = g[3] === void 0 ? M : g[3] === '"' ? Ae : Pe) : r === Ae || r === Pe ? r = M : r === Se || r === Ce ? r = H : (r = M, a = void 0);
    const f = r === M && t[h + 1].startsWith("/>") ? " " : "";
    s += r === H ? c + qe : p >= 0 ? (o.push(_), c.slice(0, p) + Me + c.slice(p) + T + f) : c + T + (p === -2 ? h : f);
  }
  return [Ie(t, s + (t[i] || "<?>") + (e === 2 ? "</svg>" : e === 3 ? "</math>" : "")), o];
};
class Y {
  constructor({ strings: e, _$litType$: i }, o) {
    let a;
    this.parts = [];
    let s = 0, r = 0;
    const h = e.length - 1, c = this.parts, [_, g] = Ke(e, i);
    if (this.el = Y.createElement(_, o), z.currentNode = this.el.content, i === 2 || i === 3) {
      const p = this.el.content.firstChild;
      p.replaceWith(...p.childNodes);
    }
    for (; (a = z.nextNode()) !== null && c.length < h; ) {
      if (a.nodeType === 1) {
        if (a.hasAttributes()) for (const p of a.getAttributeNames()) if (p.endsWith(Me)) {
          const m = g[r++], f = a.getAttribute(p).split(T), x = /([.?@])?(.*)/.exec(m);
          c.push({ type: 1, index: s, name: x[2], strings: f, ctor: x[1] === "." ? et : x[1] === "?" ? tt : x[1] === "@" ? it : se }), a.removeAttribute(p);
        } else p.startsWith(T) && (c.push({ type: 6, index: s }), a.removeAttribute(p));
        if (De.test(a.tagName)) {
          const p = a.textContent.split(T), m = p.length - 1;
          if (m > 0) {
            a.textContent = oe ? oe.emptyScript : "";
            for (let f = 0; f < m; f++) a.append(p[f], W()), z.nextNode(), c.push({ type: 2, index: ++s });
            a.append(p[m], W());
          }
        }
      } else if (a.nodeType === 8) if (a.data === ze) c.push({ type: 2, index: s });
      else {
        let p = -1;
        for (; (p = a.data.indexOf(T, p + 1)) !== -1; ) c.push({ type: 7, index: s }), p += T.length - 1;
      }
      s++;
    }
  }
  static createElement(e, i) {
    const o = D.createElement("template");
    return o.innerHTML = e, o;
  }
}
function U(t, e, i = t, o) {
  if (e === N) return e;
  let a = o !== void 0 ? i._$Co?.[o] : i._$Cl;
  const s = G(e) ? void 0 : e._$litDirective$;
  return a?.constructor !== s && (a?._$AO?.(!1), s === void 0 ? a = void 0 : (a = new s(t), a._$AT(t, i, o)), o !== void 0 ? (i._$Co ??= [])[o] = a : i._$Cl = a), a !== void 0 && (e = U(t, a._$AS(t, e.values), a, o)), e;
}
class Qe {
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
    const { el: { content: i }, parts: o } = this._$AD, a = (e?.creationScope ?? D).importNode(i, !0);
    z.currentNode = a;
    let s = z.nextNode(), r = 0, h = 0, c = o[0];
    for (; c !== void 0; ) {
      if (r === c.index) {
        let _;
        c.type === 2 ? _ = new V(s, s.nextSibling, this, e) : c.type === 1 ? _ = new c.ctor(s, c.name, c.strings, this, e) : c.type === 6 && (_ = new ot(s, this, e)), this._$AV.push(_), c = o[++h];
      }
      r !== c?.index && (s = z.nextNode(), r++);
    }
    return z.currentNode = D, a;
  }
  p(e) {
    let i = 0;
    for (const o of this._$AV) o !== void 0 && (o.strings !== void 0 ? (o._$AI(e, o, i), i += o.strings.length - 2) : o._$AI(e[i])), i++;
  }
}
class V {
  get _$AU() {
    return this._$AM?._$AU ?? this._$Cv;
  }
  constructor(e, i, o, a) {
    this.type = 2, this._$AH = d, this._$AN = void 0, this._$AA = e, this._$AB = i, this._$AM = o, this.options = a, this._$Cv = a?.isConnected ?? !0;
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
    e = U(this, e, i), G(e) ? e === d || e == null || e === "" ? (this._$AH !== d && this._$AR(), this._$AH = d) : e !== this._$AH && e !== N && this._(e) : e._$litType$ !== void 0 ? this.$(e) : e.nodeType !== void 0 ? this.T(e) : Ve(e) ? this.k(e) : this._(e);
  }
  O(e) {
    return this._$AA.parentNode.insertBefore(e, this._$AB);
  }
  T(e) {
    this._$AH !== e && (this._$AR(), this._$AH = this.O(e));
  }
  _(e) {
    this._$AH !== d && G(this._$AH) ? this._$AA.nextSibling.data = e : this.T(D.createTextNode(e)), this._$AH = e;
  }
  $(e) {
    const { values: i, _$litType$: o } = e, a = typeof o == "number" ? this._$AC(e) : (o.el === void 0 && (o.el = Y.createElement(Ie(o.h, o.h[0]), this.options)), o);
    if (this._$AH?._$AD === a) this._$AH.p(i);
    else {
      const s = new Qe(a, this), r = s.u(this.options);
      s.p(i), this.T(r), this._$AH = s;
    }
  }
  _$AC(e) {
    let i = je.get(e.strings);
    return i === void 0 && je.set(e.strings, i = new Y(e)), i;
  }
  k(e) {
    ge(this._$AH) || (this._$AH = [], this._$AR());
    const i = this._$AH;
    let o, a = 0;
    for (const s of e) a === i.length ? i.push(o = new V(this.O(W()), this.O(W()), this, this.options)) : o = i[a], o._$AI(s), a++;
    a < i.length && (this._$AR(o && o._$AB.nextSibling, a), i.length = a);
  }
  _$AR(e = this._$AA.nextSibling, i) {
    for (this._$AP?.(!1, !0, i); e !== this._$AB; ) {
      const o = $e(e).nextSibling;
      $e(e).remove(), e = o;
    }
  }
  setConnected(e) {
    this._$AM === void 0 && (this._$Cv = e, this._$AP?.(e));
  }
}
class se {
  get tagName() {
    return this.element.tagName;
  }
  get _$AU() {
    return this._$AM._$AU;
  }
  constructor(e, i, o, a, s) {
    this.type = 1, this._$AH = d, this._$AN = void 0, this.element = e, this.name = i, this._$AM = a, this.options = s, o.length > 2 || o[0] !== "" || o[1] !== "" ? (this._$AH = Array(o.length - 1).fill(new String()), this.strings = o) : this._$AH = d;
  }
  _$AI(e, i = this, o, a) {
    const s = this.strings;
    let r = !1;
    if (s === void 0) e = U(this, e, i, 0), r = !G(e) || e !== this._$AH && e !== N, r && (this._$AH = e);
    else {
      const h = e;
      let c, _;
      for (e = s[0], c = 0; c < s.length - 1; c++) _ = U(this, h[o + c], i, c), _ === N && (_ = this._$AH[c]), r ||= !G(_) || _ !== this._$AH[c], _ === d ? e = d : e !== d && (e += (_ ?? "") + s[c + 1]), this._$AH[c] = _;
    }
    r && !a && this.j(e);
  }
  j(e) {
    e === d ? this.element.removeAttribute(this.name) : this.element.setAttribute(this.name, e ?? "");
  }
}
class et extends se {
  constructor() {
    super(...arguments), this.type = 3;
  }
  j(e) {
    this.element[this.name] = e === d ? void 0 : e;
  }
}
class tt extends se {
  constructor() {
    super(...arguments), this.type = 4;
  }
  j(e) {
    this.element.toggleAttribute(this.name, !!e && e !== d);
  }
}
class it extends se {
  constructor(e, i, o, a, s) {
    super(e, i, o, a, s), this.type = 5;
  }
  _$AI(e, i = this) {
    if ((e = U(this, e, i, 0) ?? d) === N) return;
    const o = this._$AH, a = e === d && o !== d || e.capture !== o.capture || e.once !== o.once || e.passive !== o.passive, s = e !== d && (o === d || a);
    a && this.element.removeEventListener(this.name, this, o), s && this.element.addEventListener(this.name, this, e), this._$AH = e;
  }
  handleEvent(e) {
    typeof this._$AH == "function" ? this._$AH.call(this.options?.host ?? this.element, e) : this._$AH.handleEvent(e);
  }
}
class ot {
  constructor(e, i, o) {
    this.element = e, this.type = 6, this._$AN = void 0, this._$AM = i, this.options = o;
  }
  get _$AU() {
    return this._$AM._$AU;
  }
  _$AI(e) {
    U(this, e);
  }
}
const at = _e.litHtmlPolyfillSupport;
at?.(Y, V), (_e.litHtmlVersions ??= []).push("3.3.2");
const Oe = (t, e, i) => {
  const o = i?.renderBefore ?? e;
  let a = o._$litPart$;
  if (a === void 0) {
    const s = i?.renderBefore ?? null;
    o._$litPart$ = a = new V(e.insertBefore(W(), s), s, void 0, i ?? {});
  }
  return a._$AI(t), a;
};
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const ue = globalThis;
class j extends O {
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
    return N;
  }
}
j._$litElement$ = !0, j.finalized = !0, ue.litElementHydrateSupport?.({ LitElement: j });
const st = ue.litElementPolyfillSupport;
st?.({ LitElement: j });
(ue.litElementVersions ??= []).push("4.2.2");
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const R = (t) => (e, i) => {
  i !== void 0 ? i.addInitializer(() => {
    customElements.define(t, e);
  }) : customElements.define(t, e);
};
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const rt = { attribute: !0, type: String, converter: ie, reflect: !1, hasChanged: pe }, nt = (t = rt, e, i) => {
  const { kind: o, metadata: a } = i;
  let s = globalThis.litPropertyMetadata.get(a);
  if (s === void 0 && globalThis.litPropertyMetadata.set(a, s = /* @__PURE__ */ new Map()), o === "setter" && ((t = Object.create(t)).wrapped = !0), s.set(i.name, t), o === "accessor") {
    const { name: r } = i;
    return { set(h) {
      const c = e.get.call(this);
      e.set.call(this, h), this.requestUpdate(r, c, t, !0, h);
    }, init(h) {
      return h !== void 0 && this.C(r, void 0, t, h), h;
    } };
  }
  if (o === "setter") {
    const { name: r } = i;
    return function(h) {
      const c = this[r];
      e.call(this, h), this.requestUpdate(r, c, t, !0, h);
    };
  }
  throw Error("Unsupported decorator location: " + o);
};
function P(t) {
  return (e, i) => typeof i == "object" ? nt(t, e, i) : ((o, a, s) => {
    const r = a.hasOwnProperty(s);
    return a.constructor.createProperty(s, o), r ? Object.getOwnPropertyDescriptor(a, s) : void 0;
  })(t, e, i);
}
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
function u(t) {
  return P({ ...t, state: !0, attribute: !1 });
}
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const lt = (t, e, i) => (i.configurable = !0, i.enumerable = !0, Reflect.decorate && typeof e != "object" && Object.defineProperty(t, e, i), i);
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
function dt(t, e) {
  return (i, o, a) => {
    const s = (r) => r.renderRoot?.querySelector(t) ?? null;
    return lt(i, o, { get() {
      return s(this);
    } });
  };
}
function le(t, e) {
  if (!e || !t.date_added)
    return !1;
  const i = new Date(t.date_added);
  return ((/* @__PURE__ */ new Date()).getTime() - i.getTime()) / (1e3 * 60 * 60 * 24) <= e;
}
function Q(t, e = "en") {
  try {
    const i = new Date(t);
    return new Intl.DateTimeFormat(e, {
      year: "numeric",
      month: "short",
      day: "numeric"
    }).format(i);
  } catch {
    return t;
  }
}
function de(t) {
  if (t < 60)
    return `${t}m`;
  const e = Math.floor(t / 60), i = t % 60;
  return i > 0 ? `${e}h ${i}m` : `${e}h`;
}
function B(t, e) {
  return t && `${t}&width=${e}`;
}
const Ne = q`
  :host {
    display: block;
    height: 100%;
    width: 100%;
    background: none !important;
    position: relative;
    z-index: 1;
    --jf-card-bg: var(--ha-card-background, var(--card-background-color, #1c1c1c));
    --jf-primary: var(--primary-color, #18BCF2);
    --jf-text: var(--primary-text-color, #fff);
    --jf-text-secondary: var(--secondary-text-color, rgba(255, 255, 255, 0.7));
    --jf-divider: var(--divider-color, rgba(255, 255, 255, 0.12));
    --jf-poster-radius: var(--ha-card-border-radius, 12px);
    --jf-transition: 0.2s ease-out;
    --jf-movie-badge: #AA5CC3;
    --jf-series-badge: #F2A218;
    --jf-series-badge: #F2A218;
    --jf-border-color: var(--divider-color, rgba(255, 255, 255, 0.15));
    --jf-highlight: var(--primary-color, #18BCF2);
  }

  ha-card {
    background: var(--jf-card-bg);
    border-radius: var(--ha-card-border-radius, 12px);
    position: relative;
    z-index: 1; /* Lift slightly to ensure shadow is consistent */
    box-shadow: var(--ha-card-box-shadow, none);
    border: var(--ha-card-border, 1px solid var(--ha-card-border-color, var(--divider-color, #e0e0e0)));
    overflow: hidden;
    display: flex;
    flex-direction: column;
    height: 100%;
    width: 100%;
    margin: 0;
    box-sizing: border-box;
  }

  .card-inner {
    border-radius: inherit; /* Inherit from ha-card to match theme */
    overflow: hidden;
    position: relative;
    z-index: 1;
    display: flex;
    flex-direction: column;
    height: 100%;
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

  /* Search Bar Styles */
  .search-container {
    padding: 16px 16px 8px 16px; /* Increased top padding */
    display: flex;
    gap: 12px;
    align-items: center;
  }

  .search-input-wrapper,
  .search-select-wrapper {
    position: relative;
    display: flex;
    align-items: center;
  }

  .search-input-wrapper {
    flex: 1; /* Title search takes remaining space */
  }

  .search-select-wrapper {
    flex: 0 0 160px; /* Wider genre picker */
  }

  .search-input,
  .search-select {
    width: 100%;
    /* Use theme-aware transparent background */
    background: color-mix(in srgb, var(--jf-text), transparent 93%);
    border: 1px solid color-mix(in srgb, var(--jf-text), transparent 85%);
    border-radius: 20px; /* More round edges */
    padding: 8px 32px 8px 36px;
    color: var(--primary-text-color);
    font-size: 1rem;
    font-family: var(--mdc-typography-body1-font-family, var(--mdc-typography-font-family, Roboto, sans-serif)); /* Match HA font */
    outline: none;
    transition: background 0.2s, border-color 0.2s, box-shadow 0.2s;
    height: 42px; /* Ensure same height */
    appearance: none;
    -webkit-appearance: none;
    box-sizing: border-box; /* Ensure padding doesn't affect height width calculation */
  }

  .search-select {
    padding-right: 32px;
    padding-left: 16px;
    cursor: pointer;
  }

  .search-select option {
    /* Use solid background from theme to avoid transparency issues in darker themes */
    background: var(--paper-listbox-background-color, var(--primary-background-color, #1c1c1c));
    color: var(--primary-text-color);
  }

  .search-input:focus,
  .search-select:focus {
    background: color-mix(in srgb, var(--jf-text), transparent 90%);
    border-color: var(--primary-color);
    box-shadow: 0 0 0 1px var(--primary-color); /* Highlight focus */
  }

  .search-icon {
    position: absolute;
    left: 12px; /* Adjusted for rounded corners */
    color: var(--secondary-text-color);
    pointer-events: none;
    --mdc-icon-size: 20px;
  }

  .select-icon {
    position: absolute;
    right: 12px;
    color: var(--secondary-text-color);
    pointer-events: none;
    --mdc-icon-size: 20px;
  }

  .clear-search {
    position: absolute;
    right: 8px;
    background: none;
    border: none;
    color: var(--secondary-text-color);
    cursor: pointer;
    padding: 4px;
    display: flex;
    align-items: center;
    border-radius: 50%;
    transition: color 0.2s;
  }

  .clear-search:hover {
    color: var(--primary-text-color);
    background: rgba(var(--rgb-primary-text-color), 0.1);
  }

  .clear-search ha-icon {
    --mdc-icon-size: 18px;
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
    flex: 1; /* Allow content to fill remaining space */
    display: flex; /* Ensure children can fill height */
    flex-direction: column;
    min-height: 0; /* Critical for scrolling inside flex items */
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
    padding: 8px 16px 16px 16px;
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
    background: var(--jf-text);
    opacity: 0.25;
    border: none;
    cursor: pointer;
    padding: 0;
    transition: background var(--jf-transition), transform var(--jf-transition), opacity var(--jf-transition);
    pointer-events: auto;
    z-index: 100;
  }

  .pagination-dot:hover {
    opacity: 0.5;
  }

  .pagination-dot.active {
    background: var(--jf-primary);
    opacity: 1;
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
    background: var(--jf-text);
    opacity: 0.25;
    transition: width 0.15s ease-out, background 0.15s ease-out, border-radius 0.15s ease-out, opacity 0.15s ease-out;
  }

  /* Active dot */
  .scroll-dot.active {
    background: var(--jf-primary);
    opacity: 1;
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
    padding: 8px 16px 16px 16px;
    min-width: fit-content;
  }

  /* Auto-fill responsive grid when columns = 1 (Auto) */
  .grid.auto-columns {
    grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
    justify-items: center;
    justify-content: center;
  }

  /* Horizontal Grid Mode (Infinite Scroll) */
  .grid.horizontal {
    display: grid;
    grid-auto-flow: column;
    grid-template-columns: auto; /* Let columns grow as needed */
    grid-template-rows: repeat(var(--jf-grid-rows, 2), auto);
    min-width: max-content; /* Force container to grow horizontally */
    gap: 16px;
    padding: 8px 16px 16px 16px;
  }

  /* List Wrapper for pagination */
  .list-wrapper {
    position: relative;
    overflow-y: auto; /* Enable vertical scrolling */
    height: 100%; /* Fill available space */
    touch-action: pan-y;
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

  .media-item.list-item {
    flex-direction: row;
    align-items: flex-start;
    gap: 16px;
  }

  /* Specific override for List view */
  .media-item.list-item .poster-container {
    width: 100px !important;
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
    font-size: 0.8rem;
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
  .media-item.list-item .hover-overlay {
    display: none;
  }

  /* Keep badges visible in list layout */
  .media-item.list-item:hover .rating,
  .media-item.list-item:hover .runtime {
    opacity: 1;
  }

  /* Emphasize metadata on hover */
  .media-item.list-item:hover .list-title {
    color: var(--jf-primary);
  }

  .media-item.list-item:hover .list-info {
    transform: translateX(2px);
    transition: transform 0.2s ease;
  }

  .media-item.list-item:hover .list-date-added {
    font-weight: 600;
  }

  /* Move date up when it's above poster */
  .media-item.list-item:hover .list-poster-wrapper .list-date-added:first-child {
    transform: translateY(-2px);
  }

  /* Move date down when it's below poster */
  .media-item.list-item:hover .list-poster-wrapper .list-date-added:last-child {
    transform: translateY(2px);
  }

  .media-item.list-item:hover .list-year,
  .media-item.list-item:hover .list-runtime,
  .media-item.list-item:hover .list-rating {
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
    user-select: none;
    -webkit-user-select: none;
    -webkit-touch-callout: none;
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
  /* Pulse animation for confirming hold action */
  @keyframes holdPulse {
    0% { transform: scale(0.96); }
    50% { transform: scale(0.92); }
    100% { transform: scale(0.96); }
  }

  .poster-container.hold-pulse {
    animation: holdPulse 0.3s ease-in-out;
  }
  .media-item.active-press .poster-container,
  .media-item:active .poster-container {
    transform: scale(0.96);
    transition: transform 0.1s ease-out;
  }

  /* Vignette overlay for list items on hover */
  .media-item.list-item .poster-inner::after {
    content: '';
    position: absolute;
    inset: 0;
    border-radius: var(--jf-poster-radius);
    background: radial-gradient(
      ellipse at center,
      transparent 50%,
      rgba(0, 0, 0, 0.15) 100%
    );
    opacity: 0;
    transition: opacity var(--jf-transition);
    pointer-events: none;
  }

  .media-item.list-item:hover .poster-inner::after {
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

  /* Error fallback - stop animation and show placeholder icon */
  .poster-skeleton.error {
    animation: none;
    background: var(--jf-divider);
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .poster-skeleton.error::after {
    content: '🎬';
    font-size: 2rem;
    opacity: 0.4;
  }

  /* Media Type Badge (MOVIE/SERIES) - Top Left - matches new-badge style */
  .media-type-badge {
    position: absolute;
    top: 6px;
    left: 6px;
    padding: 2px 8px 1px 8px;
    border-radius: 4px;
    font-size: 0.8rem;
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
    background: #009ac7;
    color: #fff;
    padding: 2px 8px 1px 8px;
    border-radius: 4px;
    font-size: 0.8rem;
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
    font-size: 0.8rem;
  }

  .status-badge.watched ha-icon {
    --mdc-icon-size: 14px;
    margin-top: -1px;
  }

  /* Unplayed Count - Theme Colored Badge */
  .status-badge.unplayed {
    padding: 2px 8px 1px 8px;
    border-radius: 4px;
    background: #009ac7;
    color: #fff;
    font-size: 0.8rem;
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
    z-index: 7;
  }

  .media-item:hover .hover-overlay {
    opacity: 1;
  }

  .hover-overlay .overlay-year {
    font-size: 0.85rem;
    font-weight: 600;
    color: #fff !important;
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

  /* Censor Bar Overlay - Aggressive Style */
  .censor-bar {
    position: absolute;
    top: 50%;
    left: -4%;
    right: -2%;
    transform: translateY(calc(-50%)) rotate(-5deg);
    background: #000;
    color: #fff;
    padding: 4px 4px;
    text-align: center;
    z-index: 6;
    box-shadow: 0 4px 10px rgba(0,0,0,0.5);
    border-top: 2px solid white;
    border-bottom: 2px solid white;
    width: 105%;
    display: flex;
    justify-content: center;
    align-items: center;
  }

  .censor-bar span {
    font-family: 'Impact', 'Arial Black', sans-serif;
    font-size: 1.4rem;
    font-weight: 900;
    text-transform: uppercase;
    line-height: 1.1;
    letter-spacing: 0.8px; /* Slightly increased for better readability */
    text-shadow: 2px 2px 0px #000;
    display: -webkit-box;
    -webkit-line-clamp: 2;
    -webkit-box-orient: vertical;
    overflow: hidden;
    max-width: 85%; /* Ensure text stays within visible poster area since bar is wider */
  }

  /* Highlight Style for Next Up */
  .censor-bar.highlight {
    background: var(--jf-series-badge);
    border-color: rgba(255, 255, 255, 0.95);
    box-shadow: 0 4px 12px rgba(0,0,0,0.6);
    z-index: 7;
    transform: translateY(calc(-50%)) rotate(-6deg) scale(1.05);
  }
  
  /* List specific adjustments for Censor Bar */
  .censor-bar.list-bar {
    padding: 2px 2px;
    /* Adjust position for smaller poster */
    transform: translateY(calc(-50%)) rotate(-3deg);
  }

  .censor-bar.list-bar span {
    font-size: 0.9rem; /* Smaller text for list view */
    letter-spacing: 0.3px;
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
    background: rgba(0, 0, 0, 0.4);
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
    color: rgba(255, 255, 255, 0.95);
    font-weight: 700;
    font-size: 0.8rem;
    line-height: 1;
    letter-spacing: 0.5px;
    background: rgba(255, 255, 255, 0.15);
    backdrop-filter: blur(4px);
    -webkit-backdrop-filter: blur(4px);
    padding: 7px 10px 5px;
    border-radius: 20px;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.2);
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
    background: var(--jf-text);
    opacity: 0.25;
    border: none;
    cursor: pointer;
    padding: 0;
    transition: background var(--jf-transition), transform 0.3s ease, opacity 0.3s ease;
    pointer-events: auto;
    flex-shrink: 0;
  }

  .smart-dot:hover {
    opacity: 0.5;
  }

  .smart-dot.active {
    background: var(--jf-primary);
    opacity: 1;
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
`, ee = {
  en: {
    loading: "Loading…",
    no_media: "No recent media found",
    error: "Error loading media",
    new: "New",
    minutes: "min",
    play: "Play",
    pause: "Pause",
    stop: "Stop",
    nothing_playing: "Nothing is currently playing",
    entity_not_found: "Entity not found",
    rewinding: "REWINDING",
    no_trailer: "No trailer available",
    // Editor
    "editor.entity": "Entity",
    "editor.title": "Title",
    "editor.show_title": "Show Title",
    "editor.show_subtitle": "Show Artist / Series",
    "editor.show_year": "Show Year",
    "editor.show_runtime": "Show Runtime",
    "editor.show_rating": "Show Rating",
    "editor.show_genres": "Show Genre",
    "editor.show_client": "Show Jellyfin Client",
    "editor.show_user": "Show User",
    "editor.show_time": "Show Elapsed / Remaining Time",
    "editor.show_background": "Show Background",
    "editor.use_series_image": "Use Series Cover Image",
    "editor.show_media_type_badge": "Show Media Type Badge",
    "editor.show_watched_status": "Show Watched Status",
    "editor.show_date_added": "Show Date Added",
    "editor.show_description": "Show Description",
    "editor.layout": "Layout",
    "editor.layout_carousel": "Carousel",
    "editor.layout_grid": "Grid",
    "editor.layout_list": "List",
    "editor.media_type": "Media Type",
    "editor.media_type_both": "Movies & TV Shows",
    "editor.media_type_movies": "Movies Only",
    "editor.media_type_series": "TV Shows Only",
    "editor.media_type_next_up": "Next Up",
    "editor.items_per_page": "Items Per Page",
    "editor.max_pages": "Max Pages (0 = no limit)",
    "editor.auto_swipe": "Auto Swipe (sec, 0 = off)",
    "editor.new_badge_days": "New Badge Days (0 = off)",
    "editor.click_action": "Single Tap (Click)",
    "editor.hold_action": "Long Press (Hold)",
    "editor.double_tap_action": "Double Tap",
    "editor.action_jellyfin": "Open in Jellyfin",
    "editor.action_cast": "Cast to Chromecast",
    "editor.action_more_info": "More Information",
    "editor.action_trailer": "Watch Trailer",
    "editor.action_none": "No Action",
    "editor.default_cast_device": "Default Cast Device",
    "editor.show_now_playing_overlay": 'Show "Now Playing" Overlay on Posters',
    "editor.metadata_position": "Metadata Position",
    "editor.metadata_below": "Below",
    "editor.metadata_above": "Above",
    "editor.sort_order": "Sort Order",
    "editor.sort_date_added_desc": "Date Added (Newest First)",
    "editor.sort_date_added_asc": "Date Added (Oldest First)",
    "editor.sort_title_asc": "Title (A-Z)",
    "editor.sort_title_desc": "Title (Z-A)",
    "editor.sort_year_desc": "Year (Newest First)",
    "editor.sort_year_asc": "Year (Oldest First)",
    "editor.sort_last_played_desc": "Last Played (Newest First)",
    "editor.sort_last_played_asc": "Last Played (Oldest First)",
    "editor.enable_pagination": "Enable Pagination",
    "editor.show_pagination_dots": "Show Pagination Dots",
    "editor.filter_watch_status": "Filter Watch Status",
    "editor.filter_all": "All",
    "editor.filter_unwatched": "Unwatched",
    "editor.filter_watched": "Watched",
    "editor.filter_favorites": "Filter Favorites",
    "editor.filter_new_items": "Filter New Items",
    "editor.columns": "Columns",
    "editor.rows": "Rows",
    "editor.now_playing_sensor": "Now Playing Sensor",
    "editor.auto": "Auto",
    "editor.show_search": "Show Search Bar",
    "search.placeholder_title": "Search Title",
    "search.placeholder_genre": "Genre",
    "search.all_genres": "All Genres"
  },
  de: {
    loading: "Laden…",
    no_media: "Keine Medien gefunden",
    error: "Fehler beim Laden",
    new: "Neu",
    minutes: "Min",
    play: "Abspielen",
    pause: "Pause",
    stop: "Stopp",
    nothing_playing: "Nichts wird abgespielt",
    entity_not_found: "Entität nicht gefunden",
    rewinding: "SPULEN",
    no_trailer: "Kein Trailer verfügbar",
    // Editor
    "editor.entity": "Entität",
    "editor.title": "Titel",
    "editor.show_title": "Titel anzeigen",
    "editor.show_subtitle": "Interpret / Serie anzeigen",
    "editor.show_year": "Jahr anzeigen",
    "editor.show_runtime": "Laufzeit anzeigen",
    "editor.show_rating": "Bewertung anzeigen",
    "editor.show_genres": "Genre anzeigen",
    "editor.show_client": "Jellyfin-Client anzeigen",
    "editor.show_user": "Benutzer anzeigen",
    "editor.show_time": "Verstrichene / Restzeit anzeigen",
    "editor.show_background": "Hintergrund anzeigen",
    "editor.use_series_image": "Serien-Cover verwenden",
    "editor.show_media_type_badge": "Medientyp-Abzeichen anzeigen",
    "editor.show_watched_status": "Gesehen-Status anzeigen",
    "editor.show_date_added": "Hinzugefügt am anzeigen",
    "editor.show_description": "Beschreibung anzeigen",
    "editor.layout": "Layout",
    "editor.layout_carousel": "Karussell",
    "editor.layout_grid": "Raster",
    "editor.layout_list": "Liste",
    "editor.media_type": "Medientyp",
    "editor.media_type_both": "Filme & Serien",
    "editor.media_type_movies": "Nur Filme",
    "editor.media_type_series": "Nur Serien",
    "editor.media_type_next_up": "Als Nächstes",
    "editor.items_per_page": "Elemente pro Seite",
    "editor.max_pages": "Max. Seiten (0 = kein Limit)",
    "editor.auto_swipe": "Auto-Swipe (Sek., 0 = aus)",
    "editor.new_badge_days": 'Badge "Neu" Tage (0 = aus)',
    "editor.click_action": "Kurz drücken (Klick)",
    "editor.hold_action": "Lang drücken (Halten)",
    "editor.double_tap_action": "Doppeltippen",
    "editor.action_jellyfin": "In Jellyfin öffnen",
    "editor.action_cast": "An Chromecast senden",
    "editor.action_more_info": "Mehr Informationen",
    "editor.action_trailer": "Trailer ansehen",
    "editor.action_none": "Keine Aktion",
    "editor.default_cast_device": "Standard-Chromecast-Gerät",
    "editor.show_now_playing_overlay": '"Jetzt läuft"-Overlay anzeigen',
    "editor.metadata_position": "Metadaten-Position",
    "editor.metadata_below": "Darunter",
    "editor.metadata_above": "Darüber",
    "editor.sort_order": "Sortierung",
    "editor.sort_date_added_desc": "Hinzugefügt (Neueste zuerst)",
    "editor.sort_date_added_asc": "Hinzugefügt (Älteste zuerst)",
    "editor.sort_title_asc": "Titel (A-Z)",
    "editor.sort_title_desc": "Titel (Z-A)",
    "editor.sort_year_desc": "Jahr (Neueste zuerst)",
    "editor.sort_year_asc": "Jahr (Älteste zuerst)",
    "editor.sort_last_played_desc": "Zuletzt gespielt (Neueste zuerst)",
    "editor.sort_last_played_asc": "Zuletzt gespielt (Älteste zuerst)",
    "editor.enable_pagination": "Seitennummerierung aktivieren",
    "editor.show_pagination_dots": "Paginierungspunkte anzeigen",
    "editor.filter_watch_status": "Gesehen-Status filtern",
    "editor.filter_all": "Alle",
    "editor.filter_unwatched": "Ungesehen",
    "editor.filter_watched": "Gesehen",
    "editor.filter_favorites": "Favoriten filtern",
    "editor.filter_new_items": "Neue Elemente filtern",
    "editor.columns": "Spalten",
    "editor.rows": "Zeilen",
    "editor.now_playing_sensor": "Sensor für aktuelle Wiedergabe",
    "editor.auto": "Automatisch",
    "editor.show_search": "Suchleiste anzeigen",
    "search.placeholder_title": "Titel suchen",
    "search.placeholder_genre": "Genre",
    "search.all_genres": "Alle Genres"
  },
  fr: {
    loading: "Chargement…",
    no_media: "Aucun média récent trouvé",
    error: "Erreur de chargement des médias",
    new: "Nouveau",
    minutes: "min",
    play: "Lire",
    pause: "Pause",
    stop: "Arrêt",
    nothing_playing: "Rien en lecture",
    entity_not_found: "Entité non trouvée",
    rewinding: "BOBINAGE",
    no_trailer: "Aucune bande-annonce disponible",
    // Editor
    "editor.entity": "Entité",
    "editor.title": "Titre",
    "editor.show_title": "Afficher le titre",
    "editor.show_subtitle": "Afficher l'artiste / la série",
    "editor.show_year": "Afficher l'année",
    "editor.show_runtime": "Afficher la durée",
    "editor.show_rating": "Afficher la note",
    "editor.show_genres": "Afficher le genre",
    "editor.show_client": "Afficher le client Jellyfin",
    "editor.show_user": "Afficher l'utilisateur",
    "editor.show_time": "Afficher le temps écoulé / restant",
    "editor.show_background": "Afficher l'arrière-plan",
    "editor.use_series_image": "Utiliser l'image de couverture de la série",
    "editor.show_media_type_badge": "Afficher le badge de type de média",
    "editor.show_watched_status": "Afficher le statut de visionnage",
    "editor.show_date_added": "Afficher la date d'ajout",
    "editor.show_description": "Afficher la description",
    "editor.layout": "Mise en page",
    "editor.layout_carousel": "Carrousel",
    "editor.layout_grid": "Grille",
    "editor.layout_list": "Liste",
    "editor.media_type": "Type de média",
    "editor.media_type_both": "Films et séries",
    "editor.media_type_movies": "Films seulement",
    "editor.media_type_series": "Séries seulement",
    "editor.media_type_next_up": "À suivre",
    "editor.items_per_page": "Éléments par page",
    "editor.max_pages": "Pages max (0 = illimité)",
    "editor.auto_swipe": "Défilement auto (sec, 0 = désactivé)",
    "editor.new_badge_days": "Jours badge nouveau (0 = désactivé)",
    "editor.click_action": "Appui court (Clic)",
    "editor.hold_action": "Appui long (Maintenir)",
    "editor.double_tap_action": "Double appui",
    "editor.action_jellyfin": "Ouvrir dans Jellyfin",
    "editor.action_cast": "Caster sur Chromecast",
    "editor.action_more_info": "Plus d'informations",
    "editor.action_trailer": "Voir la bande-annonce",
    "editor.action_none": "Aucune action",
    "editor.default_cast_device": "Appareil Cast par défaut",
    "editor.show_now_playing_overlay": 'Superposition "En lecture"',
    "editor.metadata_position": "Position des métadonnées",
    "editor.metadata_below": "Dessous",
    "editor.metadata_above": "Dessus",
    "editor.sort_order": "Ordre de tri",
    "editor.sort_date_added_desc": "Date d'ajout (Plus récent)",
    "editor.sort_date_added_asc": "Date d'ajout (Plus ancien)",
    "editor.sort_title_asc": "Titre (A-Z)",
    "editor.sort_title_desc": "Titre (Z-A)",
    "editor.sort_year_desc": "Année (Plus récent)",
    "editor.sort_year_asc": "Année (Plus ancien)",
    "editor.sort_last_played_desc": "Dernière lecture (Plus récent)",
    "editor.sort_last_played_asc": "Dernière lecture (Plus ancien)",
    "editor.enable_pagination": "Activer la pagination",
    "editor.show_pagination_dots": "Afficher les points de pagination",
    "editor.filter_watch_status": "Filtrer le statut de visionnage",
    "editor.filter_all": "Tous",
    "editor.filter_unwatched": "Non vus",
    "editor.filter_watched": "Vus",
    "editor.filter_favorites": "Filtrer les favoris",
    "editor.filter_new_items": "Filtrer les nouveaux éléments",
    "editor.columns": "Colonnes",
    "editor.rows": "Lignes",
    "editor.now_playing_sensor": "Capteur de lecture en cours",
    "editor.auto": "Auto",
    "editor.show_search": "Afficher la barre de recherche",
    "search.placeholder_title": "Rechercher un titre",
    "search.placeholder_genre": "Genre",
    "search.all_genres": "Tous les genres"
  },
  es: {
    loading: "Cargando…",
    no_media: "No se encontraron medios recientes",
    error: "Error al cargar medios",
    new: "Nuevo",
    minutes: "min",
    play: "Reproducir",
    pause: "Pausa",
    stop: "Detener",
    nothing_playing: "Nada sonando",
    entity_not_found: "Entidad no encontrada",
    rewinding: "REBOBINANDO",
    no_trailer: "No hay tráiler disponible",
    // Editor
    "editor.entity": "Entidad",
    "editor.title": "Título",
    "editor.show_title": "Mostrar título",
    "editor.show_subtitle": "Mostrar artista / serie",
    "editor.show_year": "Mostrar año",
    "editor.show_runtime": "Mostrar duración",
    "editor.show_rating": "Mostrar clasificación",
    "editor.show_genres": "Mostrar género",
    "editor.show_client": "Mostrar cliente Jellyfin",
    "editor.show_user": "Mostrar usuario",
    "editor.show_time": "Mostrar tiempo transcurrido / restante",
    "editor.show_background": "Mostrar fondo",
    "editor.use_series_image": "Usar imagen de portada de serie",
    "editor.show_media_type_badge": "Mostrar insignia de tipo de medio",
    "editor.show_watched_status": "Mostrar estado de visualización",
    "editor.show_date_added": "Mostrar fecha de adición",
    "editor.show_description": "Mostrar descripción",
    "editor.layout": "Diseño",
    "editor.layout_carousel": "Carrusel",
    "editor.layout_grid": "Cuadrícula",
    "editor.layout_list": "Lista",
    "editor.media_type": "Tipo de medio",
    "editor.media_type_both": "Películas y Series",
    "editor.media_type_movies": "Solo películas",
    "editor.media_type_series": "Solo series",
    "editor.media_type_next_up": "A continuación",
    "editor.items_per_page": "Elementos por página",
    "editor.max_pages": "Máx. páginas (0 = sin límite)",
    "editor.auto_swipe": "Deslizamiento automático (seg, 0 = apagado)",
    "editor.new_badge_days": "Días de insignia nueva (0 = apagado)",
    "editor.click_action": "Pulsación corta (Clic)",
    "editor.hold_action": "Pulsación larga (Mantener)",
    "editor.double_tap_action": "Doble toque",
    "editor.action_jellyfin": "Abrir en Jellyfin",
    "editor.action_cast": "Cast a Chromecast",
    "editor.action_more_info": "Más información",
    "editor.action_trailer": "Ver tráiler",
    "editor.action_none": "Ninguna acción",
    "editor.default_cast_device": "Dispositivo Cast predeterminado",
    "editor.show_now_playing_overlay": 'Superposición "Reproduciendo"',
    "editor.metadata_position": "Posición de metadatos",
    "editor.metadata_below": "Debajo",
    "editor.metadata_above": "Arriba",
    "editor.sort_order": "Orden de clasificación",
    "editor.sort_date_added_desc": "Fecha de adición (Más reciente)",
    "editor.sort_date_added_asc": "Fecha de adición (Más antiguo)",
    "editor.sort_title_asc": "Título (A-Z)",
    "editor.sort_title_desc": "Título (Z-A)",
    "editor.sort_year_desc": "Año (Más reciente)",
    "editor.sort_year_asc": "Año (Más antiguo)",
    "editor.sort_last_played_desc": "Última reproducción (Más reciente)",
    "editor.sort_last_played_asc": "Última reproducción (Más antiguo)",
    "editor.enable_pagination": "Habilitar paginación",
    "editor.show_pagination_dots": "Mostrar puntos de paginación",
    "editor.filter_watch_status": "Filtrar estado de visualización",
    "editor.filter_all": "Todos",
    "editor.filter_unwatched": "No vistos",
    "editor.filter_watched": "Vistos",
    "editor.filter_favorites": "Filtrar favoritos",
    "editor.filter_new_items": "Filtrar elementos nuevos",
    "editor.columns": "Columnas",
    "editor.rows": "Filas",
    "editor.now_playing_sensor": "Sensor de reproducción actual",
    "editor.auto": "Auto",
    "editor.show_search": "Mostrar barra de búsqueda",
    "search.placeholder_title": "Buscar título",
    "search.placeholder_genre": "Género",
    "search.all_genres": "Todos los géneros"
  },
  it: {
    loading: "Caricamento…",
    no_media: "Nessun media recente trovato",
    error: "Errore nel caricamento dei media",
    new: "Nuovo",
    minutes: "min",
    play: "Riproduci",
    pause: "Pausa",
    stop: "Stop",
    nothing_playing: "Niente in riproduzione",
    entity_not_found: "Entità non trovata",
    rewinding: "RIAVVOLGIMENTO",
    no_trailer: "Nessun trailer disponibile",
    // Editor
    "editor.entity": "Entità",
    "editor.title": "Titolo",
    "editor.show_title": "Mostra titolo",
    "editor.show_subtitle": "Mostra artista / serie",
    "editor.show_year": "Mostra anno",
    "editor.show_runtime": "Mostra durata",
    "editor.show_rating": "Mostra valutazione",
    "editor.show_genres": "Mostra genere",
    "editor.show_client": "Mostra client Jellyfin",
    "editor.show_user": "Mostra utente",
    "editor.show_time": "Mostra tempo trascorso / rimanente",
    "editor.show_background": "Mostra sfondo",
    "editor.use_series_image": "Usa immagine copertina serie",
    "editor.show_media_type_badge": "Mostra badge tipo media",
    "editor.show_watched_status": "Mostra stato guardato",
    "editor.show_date_added": "Mostra data aggiunta",
    "editor.show_description": "Mostra descrizione",
    "editor.layout": "Layout",
    "editor.layout_carousel": "Carosello",
    "editor.layout_grid": "Griglia",
    "editor.layout_list": "Elenco",
    "editor.media_type": "Tipo di media",
    "editor.media_type_both": "Film e Serie TV",
    "editor.media_type_movies": "Solo Film",
    "editor.media_type_series": "Solo Serie TV",
    "editor.media_type_next_up": "In coda",
    "editor.items_per_page": "Elementi per pagina",
    "editor.max_pages": "Max pagine (0 = nessun limite)",
    "editor.auto_swipe": "Scorrimento automatico (sec, 0 = spento)",
    "editor.new_badge_days": "Giorni badge nuovo (0 = spento)",
    "editor.click_action": "Pressione breve (Click)",
    "editor.hold_action": "Pressione lunga (Tieni premuto)",
    "editor.double_tap_action": "Doppio tocco",
    "editor.action_jellyfin": "Apri in Jellyfin",
    "editor.action_cast": "Cast su Chromecast",
    "editor.action_more_info": "Più informazioni",
    "editor.action_trailer": "Guarda il trailer",
    "editor.action_none": "Nessuna azione",
    "editor.default_cast_device": "Dispositivo Cast predefinito",
    "editor.show_now_playing_overlay": 'Overlay "In riproduzione"',
    "editor.metadata_position": "Posizione metadati",
    "editor.metadata_below": "Sotto",
    "editor.metadata_above": "Sopra",
    "editor.sort_order": "Ordinamento",
    "editor.sort_date_added_desc": "Data aggiunta (Più recente)",
    "editor.sort_date_added_asc": "Data aggiunta (Meno recente)",
    "editor.sort_title_asc": "Titolo (A-Z)",
    "editor.sort_title_desc": "Titolo (Z-A)",
    "editor.sort_year_desc": "Anno (Più recente)",
    "editor.sort_year_asc": "Anno (Meno recente)",
    "editor.sort_last_played_desc": "Ultima riproduzione (Più recente)",
    "editor.sort_last_played_asc": "Ultima riproduzione (Meno recente)",
    "editor.enable_pagination": "Abilita impaginazione",
    "editor.show_pagination_dots": "Mostra punti impaginazione",
    "editor.filter_watch_status": "Filtra stato guardato",
    "editor.filter_all": "Tutti",
    "editor.filter_unwatched": "Non guardati",
    "editor.filter_watched": "Guardati",
    "editor.filter_favorites": "Filtra preferiti",
    "editor.filter_new_items": "Filtra nuovi elementi",
    "editor.columns": "Colonne",
    "editor.rows": "Righe",
    "editor.now_playing_sensor": "Sensore in riproduzione",
    "editor.auto": "Auto",
    "editor.show_search": "Mostra barra di ricerca",
    "search.placeholder_title": "Cerca titolo",
    "search.placeholder_genre": "Genere",
    "search.all_genres": "Tutti i generi"
  },
  nl: {
    loading: "Laden…",
    no_media: "Geen recente media gevonden",
    error: "Fout bij laden media",
    new: "Nieuw",
    minutes: "min",
    play: "Afspelen",
    pause: "Pauze",
    stop: "Stop",
    nothing_playing: "Niets aan het spelen",
    entity_not_found: "Entiteit niet gevonden",
    rewinding: "TERUGSPOELEN",
    no_trailer: "Geen trailer beschikbaar",
    // Editor
    "editor.entity": "Entiteit",
    "editor.title": "Titel",
    "editor.show_title": "Titel tonen",
    "editor.show_subtitle": "Artiest / serie tonen",
    "editor.show_year": "Jaar tonen",
    "editor.show_runtime": "Duur tonen",
    "editor.show_rating": "Beoordeling tonen",
    "editor.show_genres": "Genre tonen",
    "editor.show_client": "Jellyfin-client tonen",
    "editor.show_user": "Gebruiker tonen",
    "editor.show_time": "Verstreken / resterende tijd tonen",
    "editor.show_background": "Achtergrond tonen",
    "editor.use_series_image": "Gebruik serie-omslagafbeelding",
    "editor.show_media_type_badge": "Mediatype-badge tonen",
    "editor.show_watched_status": "Bekeken-status tonen",
    "editor.show_date_added": "Datum toegevoegd tonen",
    "editor.show_description": "Beschrijving tonen",
    "editor.layout": "Indeling",
    "editor.layout_carousel": "Carrousel",
    "editor.layout_grid": "Raster",
    "editor.layout_list": "Lijst",
    "editor.media_type": "Mediatype",
    "editor.media_type_both": "Films & Series",
    "editor.media_type_movies": "Alleen films",
    "editor.media_type_series": "Alleen series",
    "editor.media_type_next_up": "Volgende",
    "editor.items_per_page": "Items per pagina",
    "editor.max_pages": "Max. pagina's (0 = geen limiet)",
    "editor.auto_swipe": "Auto-swipe (sec, 0 = uit)",
    "editor.new_badge_days": "Dagen badge nieuw (0 = uit)",
    "editor.click_action": "Kort indrukken (Klik)",
    "editor.hold_action": "Lang indrukken (Vasthouden)",
    "editor.double_tap_action": "Dubbel tikken",
    "editor.action_jellyfin": "Open in Jellyfin",
    "editor.action_cast": "Casten naar Chromecast",
    "editor.action_more_info": "Meer informatie",
    "editor.action_trailer": "Bekijk trailer",
    "editor.action_none": "Geen actie",
    "editor.default_cast_device": "Standaard Cast-apparaat",
    "editor.show_now_playing_overlay": '"Nu aan het spelen"-overlay',
    "editor.metadata_position": "Positie metadata",
    "editor.metadata_below": "Onder",
    "editor.metadata_above": "Boven",
    "editor.sort_order": "Sorteervolgorde",
    "editor.sort_date_added_desc": "Datum toegevoegd (Nieuwste)",
    "editor.sort_date_added_asc": "Datum toegevoegd (Oudste)",
    "editor.sort_title_asc": "Titel (A-Z)",
    "editor.sort_title_desc": "Titel (Z-A)",
    "editor.sort_year_desc": "Jaar (Nieuwste)",
    "editor.sort_year_asc": "Jaar (Oudste)",
    "editor.sort_last_played_desc": "Laatst gespeeld (Nieuwste)",
    "editor.sort_last_played_asc": "Laatst gespeeld (Oudste)",
    "editor.enable_pagination": "Paginering inschakelen",
    "editor.show_pagination_dots": "Paginering-stippen tonen",
    "editor.filter_watch_status": "Kijkstatus filteren",
    "editor.filter_all": "Alles",
    "editor.filter_unwatched": "Onbekeken",
    "editor.filter_watched": "Bekeken",
    "editor.filter_favorites": "Favorieten filteren",
    "editor.filter_new_items": "Nieuwe items filteren",
    "editor.columns": "Kolommen",
    "editor.rows": "Rijen",
    "editor.now_playing_sensor": 'Sensor "Nu aan het spelen"',
    "editor.auto": "Auto",
    "editor.show_search": "Zoekbalk tonen",
    "search.placeholder_title": "Zoek titel",
    "search.placeholder_genre": "Genre",
    "search.all_genres": "Alle genres"
  },
  sl: {
    loading: "Nalaganje…",
    no_media: "Ni nedavnih medijev",
    error: "Napaka pri nalaganju medijev",
    new: "Novo",
    minutes: "min",
    play: "Predvajaj",
    pause: "Premor",
    stop: "Stop",
    nothing_playing: "Nič se ne predvaja",
    entity_not_found: "Entiteta ni najdena",
    rewinding: "PREVIJANJE",
    no_trailer: "Napovednik ni na voljo",
    // Editor
    "editor.entity": "Entiteta",
    "editor.title": "Naslov",
    "editor.show_title": "Prikaži naslov",
    "editor.show_subtitle": "Prikaži izvajalca / serijo",
    "editor.show_year": "Prikaži leto",
    "editor.show_runtime": "Prikaži trajanje",
    "editor.show_rating": "Prikaži oceno",
    "editor.show_genres": "Prikaži žanr",
    "editor.show_client": "Prikaži Jellyfin odjemalec",
    "editor.show_user": "Prikaži uporabnika",
    "editor.show_time": "Prikaži pretečen / preostali čas",
    "editor.show_background": "Prikaži ozadje",
    "editor.use_series_image": "Uporabi sliko naslovnice serije",
    "editor.show_media_type_badge": "Prikaži značko tipa medija",
    "editor.show_watched_status": "Prikaži status ogleda",
    "editor.show_date_added": "Prikaži datum dodajanja",
    "editor.show_description": "Prikaži opis",
    "editor.layout": "Postavitev",
    "editor.layout_carousel": "Vrtiljak",
    "editor.layout_grid": "Mreža",
    "editor.layout_list": "Seznam",
    "editor.media_type": "Tip medija",
    "editor.media_type_both": "Filmi in serije",
    "editor.media_type_movies": "Samo filmi",
    "editor.media_type_series": "Samo serije",
    "editor.media_type_next_up": "Naslednje",
    "editor.items_per_page": "Elementov na stran",
    "editor.max_pages": "Max strani (0 = brez omejitve)",
    "editor.auto_swipe": "Samodejno drsenje (sek, 0 = izklopljeno)",
    "editor.new_badge_days": "Dnevi za značko Novo (0 = izklopljeno)",
    "editor.click_action": "Kratek pritisk (Klik)",
    "editor.hold_action": "Dolg pritisk (Drži)",
    "editor.double_tap_action": "Dvojni dotik",
    "editor.action_jellyfin": "Odpri v Jellyfin",
    "editor.action_cast": "Predvajaj na Chromecast",
    "editor.action_more_info": "Več informacij",
    "editor.action_trailer": "Poglej napovednik",
    "editor.action_none": "Brez akcije",
    "editor.default_cast_device": "Privzeta Chromecast naprava",
    "editor.show_now_playing_overlay": 'Prikaži "Zdaj se predvaja" prekrivanje',
    "editor.metadata_position": "Pozicija metapodatkov",
    "editor.metadata_below": "Spodaj",
    "editor.metadata_above": "Zgoraj",
    "editor.sort_order": "Vrstni red",
    "editor.sort_date_added_desc": "Datum dodajanja (Novejši naprej)",
    "editor.sort_date_added_asc": "Datum dodajanja (Starejši naprej)",
    "editor.sort_title_asc": "Naslov (A-Z)",
    "editor.sort_title_desc": "Naslov (Z-A)",
    "editor.sort_year_desc": "Leto (Novejši naprej)",
    "editor.sort_year_asc": "Leto (Starejši naprej)",
    "editor.sort_last_played_desc": "Zadnje predvajano (Novejši naprej)",
    "editor.sort_last_played_asc": "Zadnje predvajano (Starejši naprej)",
    "editor.enable_pagination": "Omogoči oštevilčevanje",
    "editor.show_pagination_dots": "Prikaži pike oštevilčevanja",
    "editor.filter_watch_status": "Filtriraj status ogleda",
    "editor.filter_all": "Vse",
    "editor.filter_unwatched": "Neogledano",
    "editor.filter_watched": "Ogledano",
    "editor.filter_favorites": "Filtriraj priljubljene",
    "editor.filter_new_items": "Filtriraj nove elemente",
    "editor.columns": "Stolpci",
    "editor.rows": "Vrstice",
    "editor.now_playing_sensor": "Senzor predvajanja",
    "editor.auto": "Avtomatsko",
    "editor.show_search": "Prikaži iskalno vrstico",
    "search.placeholder_title": "Išči naslov",
    "search.placeholder_genre": "Žanr",
    "search.all_genres": "Vsi žanri"
  },
  ru: {
    loading: "Загрузка…",
    no_media: "Недавние медиа не найдены",
    error: "Ошибка загрузки медиа",
    new: "Новое",
    minutes: "мин",
    play: "Воспроизвести",
    pause: "Пауза",
    stop: "Остановить",
    nothing_playing: "Ничего не воспроизводится",
    entity_not_found: "Объект не найден",
    rewinding: "ПЕРЕМОТКА",
    no_trailer: "Трейлер недоступен",
    // Editor
    "editor.entity": "Объект",
    "editor.title": "Название",
    "editor.show_title": "Показывать название",
    "editor.show_subtitle": "Показывать исполнителя / сериал",
    "editor.show_year": "Показывать год",
    "editor.show_runtime": "Показывать продолжительность",
    "editor.show_rating": "Показывать рейтинг",
    "editor.show_genres": "Показывать жанр",
    "editor.show_client": "Показывать клиент Jellyfin",
    "editor.show_user": "Показывать пользователя",
    "editor.show_time": "Показывать прошедшее / оставшееся время",
    "editor.show_background": "Показывать фон",
    "editor.use_series_image": "Использовать обложку сериала",
    "editor.show_media_type_badge": "Показывать значок типа медиа",
    "editor.show_watched_status": "Показывать статус просмотра",
    "editor.show_date_added": "Показывать дату добавления",
    "editor.show_description": "Показывать описание",
    "editor.layout": "Макет",
    "editor.layout_carousel": "Карусель",
    "editor.layout_grid": "Сетка",
    "editor.layout_list": "Список",
    "editor.media_type": "Тип медиа",
    "editor.media_type_both": "Фильмы и Сериалы",
    "editor.media_type_movies": "Только фильмы",
    "editor.media_type_series": "Только сериалы",
    "editor.media_type_next_up": "Далее",
    "editor.items_per_page": "Элементов на странице",
    "editor.max_pages": "Макс. страниц (0 = без ограничений)",
    "editor.auto_swipe": "Автопрокрутка (сек, 0 = выкл)",
    "editor.new_badge_days": 'Дней для значка "Новое" (0 = выкл)',
    "editor.click_action": "Короткое нажатие (Клик)",
    "editor.hold_action": "Долгое нажатие (Удержание)",
    "editor.double_tap_action": "Двойное нажатие",
    "editor.action_jellyfin": "Открыть в Jellyfin",
    "editor.action_cast": "Трансляция на Chromecast",
    "editor.action_more_info": "Больше информации",
    "editor.action_trailer": "Посмотреть трейлер",
    "editor.action_none": "Нет действия",
    "editor.default_cast_device": "Устройство Cast по умолчанию",
    "editor.show_now_playing_overlay": 'Оверлей "Сейчас играет"',
    "editor.metadata_position": "Расположение метаданных",
    "editor.metadata_below": "Снизу",
    "editor.metadata_above": "Сверху",
    "editor.sort_order": "Порядок сортировки",
    "editor.sort_date_added_desc": "Дата добавления (Сначала новые)",
    "editor.sort_date_added_asc": "Дата добавления (Сначала старые)",
    "editor.sort_title_asc": "Название (А-Я)",
    "editor.sort_title_desc": "Название (Я-А)",
    "editor.sort_year_desc": "Год (Сначала новые)",
    "editor.sort_year_asc": "Год (Сначала старые)",
    "editor.sort_last_played_desc": "Последний просмотр (Сначала новые)",
    "editor.sort_last_played_asc": "Последний просмотр (Сначала старые)",
    "editor.enable_pagination": "Включить пагинацию",
    "editor.show_pagination_dots": "Показывать точки пагинации",
    "editor.filter_watch_status": "Фильтр просмотра",
    "editor.filter_all": "Все",
    "editor.filter_unwatched": "Непросмотренное",
    "editor.filter_watched": "Просмотренное",
    "editor.filter_favorites": "Фильтр избранного",
    "editor.filter_new_items": "Фильтр новых элементов",
    "editor.columns": "Столбцы",
    "editor.rows": "Строки",
    "editor.now_playing_sensor": "Сенсор текущего воспроизведения",
    "editor.auto": "Авто",
    "editor.show_search": "Показывать панель поиска",
    "search.placeholder_title": "Поиск по названию",
    "search.placeholder_genre": "Жанр",
    "search.all_genres": "Все жанры"
  }
};
function l(t, e) {
  const i = t.split("-")[0].toLowerCase();
  return ee[i]?.[e] ? ee[i][e] : ee.en?.[e] ? ee.en[e] : e;
}
var ct = Object.defineProperty, ht = Object.getOwnPropertyDescriptor, k = (t, e, i, o) => {
  for (var a = o > 1 ? void 0 : o ? ht(e, i) : e, s = t.length - 1, r; s >= 0; s--)
    (r = t[s]) && (a = (o ? r(e, i, a) : r(a)) || a);
  return o && a && ct(e, i, a), a;
};
let y = class extends j {
  constructor() {
    super(...arguments), this._open = !1, this._confirmDelete = !1, this._viewMode = "default", this._episodes = [], this._touchStartY = 0, this._currentTranslateY = 0, this._isDragging = !1, this._swipeClosingThreshold = 100, this._portalContainer = null, this.closeDialog = () => {
      this._open = !1, this._confirmDelete = !1, this.dispatchEvent(new CustomEvent("closed", { bubbles: !0, composed: !0 })), this.requestUpdate();
    }, this._toggleEpisodesView = (t) => {
      t && (t.stopPropagation(), t.preventDefault()), this._viewMode === "default" ? this._fetchEpisodes() : this._viewMode = "default";
    }, this._handlePlayEpisode = async (t) => {
      if (this._haptic(), !this._defaultCastDevice) {
        this.dispatchEvent(new CustomEvent("hass-notification", {
          detail: { message: "No Chromecast device selected. Please configure a cast device in the card editor." },
          bubbles: !0,
          composed: !0
        }));
        return;
      }
      try {
        await this.hass.callService("jellyha", "play_on_chromecast", {
          entity_id: this._defaultCastDevice,
          item_id: t.id,
          server_entity_id: this._serverEntityId
        }), this.closeDialog();
      } catch (e) {
        console.error("Failed to cast episode", e), this.dispatchEvent(new CustomEvent("hass-notification", {
          detail: { message: "Failed to cast episode. Check logs." },
          bubbles: !0,
          composed: !0
        }));
      }
    }, this._handlePlay = async () => {
      if (this._haptic(), !this._item || !this._defaultCastDevice) {
        this._defaultCastDevice || this.dispatchEvent(new CustomEvent("hass-notification", {
          detail: { message: "No Chromecast device selected. Please configure a cast device in the card editor." },
          bubbles: !0,
          composed: !0
        }));
        return;
      }
      try {
        await this.hass.callService("jellyha", "play_on_chromecast", {
          entity_id: this._defaultCastDevice,
          item_id: this._item.id,
          server_entity_id: this._serverEntityId
        }), this.closeDialog();
      } catch (t) {
        console.error("Failed to cast", t);
      }
    }, this._playNextUp = async () => {
      if (this._haptic(), !this._nextUpItem || !this._defaultCastDevice) {
        this._defaultCastDevice || this.dispatchEvent(new CustomEvent("hass-notification", {
          detail: { message: "No Chromecast device selected. Please configure a cast device in the card editor." },
          bubbles: !0,
          composed: !0
        }));
        return;
      }
      try {
        await this.hass.callService("jellyha", "play_on_chromecast", {
          entity_id: this._defaultCastDevice,
          item_id: this._nextUpItem.id,
          server_entity_id: this._serverEntityId
        }), this.closeDialog();
      } catch (t) {
        console.error("Failed to cast next up", t);
      }
    }, this._handleFavorite = async () => {
      if (!this._item) return;
      this._haptic();
      const t = !this._item.is_favorite;
      this._item = { ...this._item, is_favorite: t }, await this.hass.callService("jellyha", "update_favorite", {
        item_id: this._item.id,
        is_favorite: t,
        server_entity_id: this._serverEntityId
      }), this.requestUpdate();
    }, this._handleWatched = async () => {
      if (!this._item) return;
      this._haptic();
      const t = !this._item.is_played;
      this._item = { ...this._item, is_played: t }, await this.hass.callService("jellyha", "mark_watched", {
        item_id: this._item.id,
        is_played: t,
        server_entity_id: this._serverEntityId
      }), this.requestUpdate();
    }, this._handleDeleteConfirm = async () => {
      if (!this._item) return;
      this._haptic();
      const t = this._item.id;
      this.closeDialog(), await this.hass.callService("jellyha", "delete_item", {
        item_id: t,
        server_entity_id: this._serverEntityId
      });
    }, this._handleWatchTrailer = () => {
      this._haptic();
      const t = this._item;
      if (!t?.trailer_url) return;
      const e = t.trailer_url;
      let i = "";
      try {
        const o = new URL(e);
        o.hostname.includes("youtube.com") ? i = o.searchParams.get("v") || "" : o.hostname.includes("youtu.be") && (i = o.pathname.slice(1));
      } catch {
      }
      if (i) {
        const o = navigator.userAgent || navigator.vendor || window.opera;
        if (/android/i.test(o)) {
          window.open(`vnd.youtube:${i}`, "_blank");
          return;
        }
      }
      this._openExternalUrl(e);
    }, this._handleMarkEpisodeWatched = async (t) => {
      this._haptic();
      const e = !t.is_played;
      if (this._episodes = this._episodes.map(
        (i) => i.id === t.id ? { ...i, is_played: e, unplayed_count: e ? 0 : 1 } : i
      ), e && this._nextUpItem && t.id === this._nextUpItem.id) {
        const i = this._episodes.findIndex((o) => o.id === t.id);
        i !== -1 && i < this._episodes.length - 1 && (this._nextUpItem = this._episodes[i + 1]);
      } else if (!e && this._nextUpItem && t.id !== this._nextUpItem.id) {
        const i = this._episodes.findIndex((a) => a.id === t.id), o = this._episodes.findIndex((a) => a.id === this._nextUpItem.id);
        i !== -1 && o !== -1 && i < o && (this._nextUpItem = this._episodes[i]);
      }
      this.requestUpdate(), await this.hass.callService("jellyha", "mark_watched", {
        item_id: t.id,
        is_played: e,
        server_entity_id: this._serverEntityId
      });
    }, this._handleModalTouchStart = (t) => {
      const e = t.target, i = this._getScrollParent(e);
      i && i.scrollTop > 0 || (this._touchStartY = t.touches[0].clientY, this._isDragging = !0);
    }, this._handleModalTouchMove = (t) => {
      if (!this._isDragging) return;
      const e = t.touches[0].clientY - this._touchStartY;
      e > 0 ? (t.cancelable && t.preventDefault(), this._currentTranslateY = e) : this._isDragging = !1;
    }, this._handleModalTouchEnd = (t) => {
      this._isDragging && (this._isDragging = !1, this._currentTranslateY > this._swipeClosingThreshold ? (this.closeDialog(), setTimeout(() => {
        this._currentTranslateY = 0;
      }, 300)) : this._currentTranslateY = 0);
    };
  }
  connectedCallback() {
    super.connectedCallback(), this._portalContainer = document.createElement("div"), this._portalContainer.id = "jellyha-modal-portal", document.body.appendChild(this._portalContainer);
  }
  disconnectedCallback() {
    super.disconnectedCallback(), this._portalContainer && (this._portalContainer.remove(), this._portalContainer = null);
  }
  async showDialog(t) {
    this._item = t.item, this.hass = t.hass, this._defaultCastDevice = t.defaultCastDevice, this._serverEntityId = t.serverEntityId, this._open = !0, this._open = !0, this._nextUpItem = void 0, this._viewMode = "default", this._episodes = [], this._item.type === "Series" && this._fetchNextUp(this._item), this._fetchFullDetails(this._item.id), await this.updateComplete;
  }
  async _fetchFullDetails(t) {
    try {
      const e = await this.hass.callWS({
        type: "call_service",
        domain: "jellyha",
        service: "get_item",
        service_data: {
          item_id: t,
          entity_id: this._serverEntityId,
          config_entry_id: this._item?.config_entry_id
        },
        return_response: !0
      }), i = e?.response || e;
      i && i.item && (this._item = { ...this._item, ...i.item }, this.requestUpdate());
    } catch (e) {
      console.warn("Failed to fetch full item details:", JSON.stringify(e, null, 2));
    }
  }
  async _fetchNextUp(t) {
    const e = Object.keys(this.hass.states).filter(
      (o) => this.hass.states[o].attributes.integration === "jellyha" || o.startsWith("sensor.jellyha_")
      // Fallback convention
    ), i = this._serverEntityId || (e.length > 0 ? e[0] : "sensor.jellyha_library");
    try {
      const o = await this.hass.callWS({
        type: "jellyha/get_next_up",
        entity_id: i,
        series_id: t.id
      });
      o && o.item && (this._nextUpItem = o.item);
    } catch (o) {
      console.warn("Failed to fetch Next Up:", o);
    }
  }
  async _fetchEpisodes() {
    if (!this._item || this._item.type !== "Series") return;
    const t = this._nextUpItem?.season || 1, e = Object.keys(this.hass.states).filter(
      (o) => this.hass.states[o].attributes.integration === "jellyha" || o.startsWith("sensor.jellyha_")
    ), i = this._serverEntityId || (e.length > 0 ? e[0] : "sensor.jellyha_library");
    try {
      this._viewMode = "episodes", this.requestUpdate();
      const o = await this.hass.callWS({
        type: "jellyha/get_episodes",
        entity_id: i,
        series_id: this._item.id,
        season: t
      });
      o && o.items ? this._episodes = o.items : this._episodes = [], this.requestUpdate();
    } catch (o) {
      console.warn("Failed to fetch episodes:", o), this._episodes = [], this.requestUpdate();
    }
  }
  updated() {
    if (this._portalContainer) {
      Oe(this._renderDialogContent(), this._portalContainer);
      const t = this._portalContainer.querySelector(".content");
      t && (t.removeEventListener("touchstart", this._handleModalTouchStart), t.removeEventListener("touchmove", this._handleModalTouchMove), t.removeEventListener("touchend", this._handleModalTouchEnd), t.addEventListener("touchstart", this._handleModalTouchStart, { passive: !0 }), t.addEventListener("touchmove", this._handleModalTouchMove, { passive: !1 }), t.addEventListener("touchend", this._handleModalTouchEnd, { passive: !0 }));
    }
  }
  render() {
    return n``;
  }
  _getPortalStyles() {
    return n`
        <style>
             ha-dialog {
                --mdc-dialog-z-index: 9999;
                --mdc-dialog-min-width: 400px;
                --mdc-dialog-max-width: 90vw;
                --mdc-theme-surface: transparent; 
                --ha-dialog-background: transparent;
                --mdc-dialog-box-shadow: none;
                --dialog-content-padding: 0;
                --mdc-dialog-content-padding: 0;
                --dialog-surface-margin: 0;
             }

            .content {
                display: flex; /* Flex container for children scrollers */
                flex-direction: column;
                
                transform-origin: top center;
                will-change: transform;
                background: var(--ha-card-background, var(--card-background-color, #1c1c1c));
                border-radius: 20px;
                box-shadow: 0 10px 40px rgba(0,0,0,0.5); /* Card shadow */
                padding: 24px;
                max-height: 80vh;
                overscroll-behavior-y: contain; /* Prevent browser overscroll/refresh */
                
                /* Hide scrollbar on the container itself */
                scrollbar-width: none; 
                -ms-overflow-style: none; 
                overflow: hidden; /* Clip content to rounded corners */
            }
            
            /* Episodes View specific */
            .content.episodes {
                overflow: hidden !important; 
                padding-right: 24px; 
            }

            .content::-webkit-scrollbar {
                display: none; 
                width: 0px !important;
                height: 0px !important;
                background: transparent;
            }

            /* Inner Layouts (Default View) */
            .default-layout {
                display: block; /* Mobile default */
                overflow-y: auto;
                height: 100%;
                width: 100%;
                padding-right: 4px; /* Space for scrollbar */
                
                /* Inset Scrollbar */
                scrollbar-width: thin; 
                scrollbar-color: rgba(255, 255, 255, 0.2) transparent;
            }
            .default-layout::-webkit-scrollbar {
                display: block;
                width: 6px !important;
                height: 6px !important;
            }
            .default-layout::-webkit-scrollbar-thumb {
                background: rgba(255, 255, 255, 0.2);
                border-radius: 3px;
            }
            .default-layout::-webkit-scrollbar-track {
                background: transparent;
            }

            /* Desktop Grid */
            @media (min-width: 601px) {
                .default-layout {
                    display: grid;
                    grid-template-columns: 300px 1fr;
                    gap: 24px;
                    overflow-y: auto; 
                }
                .content.episodes {
                    max-height: 80vh;
                }
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
                gap: 8px; /* Tighter gap for chips */
                padding: 4px 0; /* Minimal vertical padding */
                /* Remove container background for native look */
                background: transparent;
                border-radius: 0;
            }

            .stat-item {
                display: flex;
                gap: 6px;
                align-items: center;
                /* Native Chip Styling */
                border: 1px solid var(--divider-color);
                border-radius: 18px;
                padding: 6px 12px;
                font-size: 0.9rem;
                font-weight: 500;
                color: var(--primary-text-color);
                background: transparent; 
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
                background: var(--secondary-background-color, rgba(0, 0, 0, 0.1));
                border-radius: 12px;
                padding: 12px;
                display: flex;
                gap: 16px;
                align-items: center;
                margin-top: 16px;
                border: 1px solid var(--divider-color);
                cursor: pointer;
                transition: background 0.2s, transform 0.1s;
                position: relative;
                overflow: hidden;
            }
            .next-up-card:hover {
                background: rgba(var(--rgb-primary-text-color), 0.05);
            }
            .next-up-card:active {
                background: rgba(var(--rgb-primary-text-color), 0.1);
                transform: scale(0.98); /* Button press effect */
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
                .poster-col { max-width: 350px; margin: 0 auto; width: 100%; margin-bottom: 24px; }
            }

            /* Episode List Styles */
            .episodes-header {
                 display: flex;
                 align-items: center;
                 gap: 12px;
                 margin-bottom: 16px;
            }
            .back-btn {
                background: none;
                border: none;
                color: var(--primary-text-color);
                cursor: pointer;
                padding: 8px;
                border-radius: 50%;
                display: flex; /* Fix icon alignment */
            }
            .back-btn:hover {
                background: rgba(255,255,255,0.1);
            }
            .episodes-title {
                margin: 0;
                font-size: 1.5rem;
                font-weight: 600;
            }
            .episodes-list {
                display: flex;
                flex-direction: column;
                gap: 12px;
                overflow-y: auto;
                flex: 1; /* Take remaining height */
                min-height: 0; /* Flexbox scroll fix */
                padding-right: 4px; /* Space for scrollbar */
                
                /* Re-enable scrollbars for this list */
                scrollbar-width: thin; 
                scrollbar-color: rgba(255, 255, 255, 0.2) transparent;
            }
            .episodes-list::-webkit-scrollbar {
                display: block;
                width: 6px !important;
                height: 6px !important;
            }
            .episodes-list::-webkit-scrollbar-thumb {
                background: rgba(255, 255, 255, 0.2);
                border-radius: 3px;
            }
            .episodes-list::-webkit-scrollbar-track {
                background: transparent;
            }
            .episode-row {
                display: flex;
                gap: 16px;
                padding: 12px;
                background: rgba(255,255,255,0.03);
                border-radius: 12px;
                align-items: center;
                transition: background 0.2s;
            }
            .episode-row:hover {
                background: rgba(255,255,255,0.08); /* Slightly lighter on hover */
            }
            .episode-row.next-up-highlight {
                background: rgba(var(--rgb-primary-color), 0.1);
                border-left: 3px solid var(--primary-color);
            }
            .episode-content {
                flex: 1;
                min-width: 0;
                display: flex;
                flex-direction: column;
                justify-content: center;
                gap: 4px;
            }
            .episode-footer {
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            .episode-actions {
                display: flex;
                gap: 12px;
            }
            .episode-thumb {
                width: 100px;
                aspect-ratio: 16/9;
                object-fit: cover;
                border-radius: 8px;
                flex-shrink: 0; 
                background: var(--secondary-background-color); /* Skeleton placeholder */
                border: 1px solid rgba(255, 255, 255, 0.5);
            }
            .episode-info {
                flex: 1;
                min-width: 0; /* truncate text */
            }
            .episode-title {
                margin: 0;
                font-size: 1rem;
                font-weight: 500;
                line-height: 1.2;
                color: var(--primary-text-color);
            }
            .episode-meta {
                font-size: 0.85rem;
                color: var(--secondary-text-color);
                display: flex;
                align-items: center;
            }
            .play-episode-btn {
                background: transparent;
                border: none;
                color: var(--primary-color);
                border-radius: 50%; /* Keep radius for hover effect */
                width: 36px;
                height: 36px;
                display: flex;
                align-items: center;
                justify-content: center;
                cursor: pointer;
                transition: all 0.2s;
            }
            .play-episode-btn:hover {
                background: rgba(255, 255, 255, 0.15);
                color: var(--primary-color);
            }
            /* Specific override for the checkmark button */
            .watched-btn {
                color: var(--secondary-text-color);
                opacity: 0.6;
            }
            .watched-btn:hover {
                opacity: 1;
            }
            .watched-btn.active {
                color: var(--primary-color);
                opacity: 1;
            }
        </style>
        `;
  }
  _renderDialogContent() {
    return !this._open || !this._item ? n`` : n`
            ${this._getPortalStyles()}
            <ha-dialog
                open
                .escapeKeyAction=${"close"}
                .scrimClickAction=${"close"}
                @closed=${this.closeDialog}
                hideActions
                .heading=${""} 
            >
                <ha-card 
                    class="content ${this._viewMode}"
                    style="${this._isDragging || this._currentTranslateY > 0 ? `transform: translateY(${this._currentTranslateY}px); transition: ${this._isDragging ? "none" : "transform 0.3s ease-out"}` : ""}"
                >
                    ${this._viewMode === "episodes" ? this._renderEpisodesContent() : this._renderDefaultContent()}
                </ha-card>
            </ha-dialog>
        `;
  }
  _renderDefaultContent() {
    if (!this._item) return n``;
    const t = this._item, e = t.type === "Series", i = t.year || (t.date_added ? new Date(t.date_added).getFullYear() : "");
    return n`
        <div class="default-layout">
            <div class="poster-col">
                <img class="poster-img" src="${t.poster_url}" alt="${t.name}" />

                <div class="actions-col">
                    ${this._confirmDelete ? n`
                        <div class="confirmation-box">
                            <span>Delete?</span>
                            <button class="confirm-btn confirm-yes" @click=${this._handleDeleteConfirm}>Yes</button>
                            <button class="confirm-btn" @click=${() => this._confirmDelete = !1}>No</button>
                        </div>
                        ` : n`
                        <button class="action-btn" @click=${this._handlePlay} title="Play on Chromecast">
                            <ha-icon icon="mdi:cast"></ha-icon>
                        </button>
                        
                        ${e ? n`
                                <button class="action-btn" @click=${(o) => {
      this._haptic(), this._toggleEpisodesView(o);
    }} title="View All Episodes" type="button">
                                <ha-icon icon="mdi:format-list-bulleted"></ha-icon>
                                </button>
                        ` : d}

                        ${t.trailer_url ? n`
                            <button class="action-btn" @click=${this._handleWatchTrailer} title="Watch Trailer">
                                <ha-icon icon="mdi:filmstrip"></ha-icon>
                        ` : d}

                        <button class="action-btn ${t.is_played ? "active" : ""}" @click=${this._handleWatched} title="${t.is_played ? "Mark Unwatched" : "Mark Watched"}">
                            <ha-icon icon="mdi:check"></ha-icon>
                        </button>

                        <button class="action-btn favorite-btn ${t.is_favorite ? "active" : ""}" @click=${this._handleFavorite} title="${t.is_favorite ? "Remove Favorite" : "Add to Favorites"}">
                                <ha-icon icon="${t.is_favorite ? "mdi:heart" : "mdi:heart-outline"}"></ha-icon>
                        </button>

                        <a href="javascript:void(0)" class="action-btn" title="Open in Jellyfin" @click=${(o) => {
      o.preventDefault(), this._haptic(), this._openExternalUrl(t.jellyfin_url);
    }}>
                            <ha-icon icon="mdi:popcorn"></ha-icon>
                        </a>

                        <button class="action-btn" @click=${() => {
      this._haptic(), this._confirmDelete = !0;
    }} title="Delete Item">
                            <ha-icon icon="mdi:trash-can-outline"></ha-icon>
                        </button>
                        
                    `}
                </div>
            </div>

            <div class="details-col">
                <div class="header-group">
                    <h1>${t.name}</h1>
                    <div class="header-sub">
                        ${i ? n`<span>${i}</span>` : d}
                        <span class="badge">${t.type}</span>
                        ${t.official_rating ? n`<span class="badge">${t.official_rating}</span>` : d}
                    </div>
                </div>
                
                ${this._nextUpItem ? n`
                    <div class="next-up-card" @click=${this._playNextUp}>
                        <img class="next-up-thumb" src="${this._nextUpItem.backdrop_url || this._nextUpItem.poster_url}" />
                        <div class="next-up-info">
                            <span class="next-up-label">Next Up</span>
                            <h3 class="next-up-title">${this._nextUpItem.name}</h3>
                            <span class="next-up-meta">S${this._nextUpItem.season} : E${this._nextUpItem.episode} • ${this._formatRuntime(this._nextUpItem.runtime_minutes)}</span>
                        </div>
                        <ha-icon icon="mdi:cast" style="font-size: 36px; color: var(--primary-color); opacity: 1;"></ha-icon>
                    </div>
                ` : d}

                <div class="stats-row">
                    <div class="stat-item">
                        <ha-icon icon="mdi:star" style="color: #FBC02D;"></ha-icon>
                        <span>${t.rating ? t.rating.toFixed(1) : "N/A"}</span>
                    </div>
                    ${e ? n`
                        <div class="stat-item">
                            <ha-icon icon="mdi:television-classic"></ha-icon>
                            <span>${t.unplayed_count !== void 0 ? t.unplayed_count + " Unplayed" : ""}</span>
                        </div>
                        ` : n`
                        <div class="stat-item">
                            <ha-icon icon="mdi:clock-outline"></ha-icon>
                            <span>${this._formatRuntime(t.runtime_minutes)}</span>
                        </div>
                        `}
                </div>

                    ${t.description ? n`<div class="description">${t.description}</div>` : d}

                    ${t.genres && t.genres.length > 0 ? n`
                    <div class="genres-list">
                        ${t.genres.map((o) => n`<span class="genre-tag">${o}</span>`)}
                    </div>
                    ` : d}
                
                    <div class="divider"></div>

                    <div class="media-info-grid">
                    ${this._renderMediaDetails(e && this._nextUpItem ? this._nextUpItem : t)}
                    </div>
            </div>
        </div>
        `;
  }
  _renderEpisodesContent() {
    if (!this._item) return n``;
    const t = this._item.name;
    return n`
            <div style="display: flex; flex-direction: column; height: 100%; overflow: hidden;">
                <div class="episodes-header">
                    <button class="back-btn" @click=${(e) => this._toggleEpisodesView(e)} type="button">
                        <ha-icon icon="mdi:arrow-left"></ha-icon>
                    </button>
                    <h2 class="episodes-title">${t}</h2>
                </div>
                
                <div class="episodes-list">
                    ${this._episodes.map((e) => n`
                        <div class="episode-row ${this._nextUpItem && e.id === this._nextUpItem.id ? "next-up-highlight" : ""}" @click=${(i) => {
      i.stopPropagation(), this._handlePlayEpisode(e);
    }}>
                            <img class="episode-thumb" src="${e.backdrop_url || e.poster_url || this._item.backdrop_url}" />
                            
                            <div class="episode-content">
                                <h4 class="episode-title">
                                    ${e.episode || e.index_number}. ${e.name}
                                    ${this._nextUpItem && e.id === this._nextUpItem.id ? n`<span style="font-size: 0.7em; background: var(--primary-color); color: white; padding: 2px 6px; border-radius: 4px; margin-left: 8px; vertical-align: middle; white-space: nowrap;">NEXT UP</span>` : d}
                                </h4>
                                
                                <div class="episode-footer">
                                    <div class="episode-meta">
                                        <span>${this._formatRuntime(e.runtime_minutes)}</span>
                                        ${e.rating !== void 0 ? n` <ha-icon icon="mdi:star" style="--mdc-icon-size: 14px; color: #FBC02D; margin-left: 6px; transform: translateY(-1px);"></ha-icon> ${e.rating.toFixed(1)}` : d}
                                    </div>

                                    <div class="episode-actions">
                                        <button class="play-episode-btn watched-btn ${e.is_played ? "active" : ""}" @click=${(i) => {
      i.stopPropagation(), this._handleMarkEpisodeWatched(e);
    }} type="button" title="${e.is_played ? "Mark Unwatched" : "Mark Watched"}">
                                            <ha-icon icon="mdi:check"></ha-icon>
                                        </button>

                                        <button class="play-episode-btn" @click=${(i) => {
      i.stopPropagation(), this._handlePlayEpisode(e);
    }} type="button">
                                            <ha-icon icon="mdi:cast"></ha-icon>
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    `)}
                </div>
            </div>
        `;
  }
  _formatRuntime(t) {
    if (!t) return "";
    const e = Math.floor(t / 60), i = t % 60;
    return e > 0 ? `${e}h ${i}m` : `${i} min`;
  }
  _renderMediaDetails(t) {
    const e = [], i = t.media_streams || [], o = i.find((s) => s.Type?.toLowerCase() === "video");
    o && (o.Codec && e.push(n`<div class="info-pair"><b>Video</b><span>${o.Codec.toUpperCase()}</span></div>`), o.Width && o.Height && e.push(n`<div class="info-pair"><b>Resolution</b><span>${o.Width}x${o.Height}</span></div>`));
    const a = i.find((s) => s.Type?.toLowerCase() === "audio" && !!s.IsDefault) || i.find((s) => s.Type?.toLowerCase() === "audio");
    return a && (a.Codec && e.push(n`<div class="info-pair"><b>Audio</b><span>${a.Codec.toUpperCase()}</span></div>`), a.Channels && e.push(n`<div class="info-pair"><b>Channels</b><span>${a.Channels} ch</span></div>`)), e;
  }
  _haptic(t = "selection") {
    const e = new CustomEvent("haptic", {
      detail: t,
      bubbles: !0,
      composed: !0
    });
    this.dispatchEvent(e);
  }
  _openExternalUrl(t) {
    if (!t) return;
    let e;
    if (this.hass && this.hass.states) {
      for (const i in this.hass.states)
        if (i.startsWith("sensor.") && this.hass.states[i].attributes?.config_external_url) {
          e = this.hass.states[i].attributes.config_external_url;
          break;
        }
    }
    if (e && e.trim() !== "")
      try {
        const i = new URL(t), o = new URL(e);
        i.protocol = o.protocol, i.host = o.host, i.port = o.port || "";
        const a = o.pathname === "/" ? "" : o.pathname;
        a && !i.pathname.startsWith(a) && (i.pathname = a + i.pathname), window.open(i.toString(), "_blank");
        return;
      } catch (i) {
        console.warn("JellyHA: Failed to parse URLs to inject external URL override", i);
      }
    window.open(t, "_blank");
  }
  /* Swipe to Close Logic */
  _getScrollParent(t) {
    if (!t) return null;
    let e = t;
    for (; e && e !== this._portalContainer && e !== document.body; ) {
      if (e.classList?.contains("content"))
        return e.scrollHeight > e.clientHeight ? e : null;
      const { overflowY: i } = window.getComputedStyle(e);
      if ((i === "auto" || i === "scroll") && e.scrollHeight > e.clientHeight)
        return e;
      e = e.parentElement;
    }
    return null;
  }
};
y.styles = q`
        /* Styles handled in _getPortalStyles */
    `;
k([
  P({ attribute: !1 })
], y.prototype, "hass", 2);
k([
  u()
], y.prototype, "_item", 2);
k([
  u()
], y.prototype, "_nextUpItem", 2);
k([
  u()
], y.prototype, "_defaultCastDevice", 2);
k([
  u()
], y.prototype, "_serverEntityId", 2);
k([
  u()
], y.prototype, "_open", 2);
k([
  u()
], y.prototype, "_confirmDelete", 2);
k([
  u()
], y.prototype, "_viewMode", 2);
k([
  u()
], y.prototype, "_episodes", 2);
k([
  u()
], y.prototype, "_touchStartY", 2);
k([
  u()
], y.prototype, "_currentTranslateY", 2);
k([
  u()
], y.prototype, "_isDragging", 2);
y = k([
  R("jellyha-item-details-modal")
], y);
var pt = Object.defineProperty, _t = Object.getOwnPropertyDescriptor, me = (t, e, i, o) => {
  for (var a = o > 1 ? void 0 : o ? _t(e, i) : e, s = t.length - 1, r; s >= 0; s--)
    (r = t[s]) && (a = (o ? r(e, i, a) : r(a)) || a);
  return o && a && pt(e, i, a), a;
};
function gt(t, e, i) {
  const o = new CustomEvent(e, {
    bubbles: !0,
    composed: !0,
    detail: i
  });
  t.dispatchEvent(o);
}
let X = class extends j {
  setConfig(t) {
    this._config = t;
  }
  render() {
    if (!this.hass || !this._config)
      return n``;
    const t = this._config.click_action || "more-info", e = this._config.hold_action || "jellyfin", i = this._config.double_tap_action || "none", o = this.hass.locale?.language || this.hass.language, s = this._config.layout === "grid" && this._config.enable_pagination === !1 && (this._config.auto_swipe_interval || 0) > 0 ? l(o, "editor.rows") : l(o, "editor.columns");
    return n`
      <div class="card-config">
        <div class="form-row">
          <ha-selector
            .hass=${this.hass}
            .selector=${{ entity: { domain: "sensor" } }}
            .value=${this._config.entity}
            label="${l(o, "editor.entity")}"
            @value-changed=${this._entityChanged}
          ></ha-selector>
        </div>

        <div class="form-row">
          <ha-textfield
            label="${l(o, "editor.title")}"
            .value=${this._config.title || ""}
            @input=${this._titleChanged}
          ></ha-textfield>
        </div>

        <div class="side-by-side">
          <div class="form-row">
            <ha-select
              label="${l(o, "editor.layout")}"
              .value=${this._config.layout || "carousel"}
              @selected=${this._layoutChanged}
              @closed=${(r) => r.stopPropagation()}
            >
              <mwc-list-item value="carousel">${l(o, "editor.layout_carousel")}</mwc-list-item>
              <mwc-list-item value="grid">${l(o, "editor.layout_grid")}</mwc-list-item>
              <mwc-list-item value="list">${l(o, "editor.layout_list")}</mwc-list-item>
            </ha-select>
          </div>

          <div class="form-row">
            <ha-select
              label="${l(o, "editor.media_type")}"
              .value=${this._config.media_type || "both"}
              @selected=${this._mediaTypeChanged}
              @closed=${(r) => r.stopPropagation()}
            >
              <mwc-list-item value="both">${l(o, "editor.media_type_both")}</mwc-list-item>
              <mwc-list-item value="movies">${l(o, "editor.media_type_movies")}</mwc-list-item>
              <mwc-list-item value="series">${l(o, "editor.media_type_series")}</mwc-list-item>
              <mwc-list-item value="next_up">${l(o, "editor.media_type_next_up")}</mwc-list-item>
            </ha-select>
          </div>
        </div>

        ${this._config.layout === "grid" || this._config.layout === "list" ? n`
              <div class="form-row">
                <ha-slider
                  labeled
                  min="1"
                  max="${this._config.layout === "list" ? 8 : 12}"
                  .value=${this._config.columns || 1}
                  @change=${this._columnsChanged}
                ></ha-slider>
                <span>${s}: ${(this._config.columns || 1) === 1 ? l(o, "editor.auto") : this._config.columns}</span>
              </div>
            ` : ""}

        <div class="side-by-side">
          <div class="form-row">
            <ha-textfield
              label="${l(o, "editor.items_per_page")}"
              type="number"
              min="1"
              required
              .value=${this._config.items_per_page !== void 0 && this._config.items_per_page !== null ? String(this._config.items_per_page) : ""}
              @input=${this._itemsPerPageChanged}
            ></ha-textfield>
          </div>

          <div class="form-row">
            <ha-textfield
              label="${l(o, "editor.max_pages")}"
              type="number"
              min="0"
              max="20"
              .value=${this._config.max_pages !== void 0 && this._config.max_pages !== null ? String(this._config.max_pages) : ""}
              @input=${this._maxPagesChanged}
            ></ha-textfield>
          </div>
        </div>

        <div class="side-by-side">
          <div class="form-row">
            <ha-textfield
              label="${l(o, "editor.auto_swipe")}"
              type="number"
              min="0"
              max="60"
              .value=${String(this._config.auto_swipe_interval || 0)}
              @input=${this._autoSwipeIntervalChanged}
            ></ha-textfield>
          </div>

          <div class="form-row">
            <ha-textfield
              label="${l(o, "editor.new_badge_days")}"
              type="number"
              min="0"
              max="30"
              .value=${this._config.new_badge_days !== void 0 && this._config.new_badge_days !== null ? String(this._config.new_badge_days) : ""}
              @input=${this._newBadgeDaysChanged}
            ></ha-textfield>
          </div>
        </div>

        <div class="side-by-side">
          <div class="form-row">
            <ha-select
              label="${l(o, "editor.click_action")}"
              .value=${t}
              @selected=${this._clickActionChanged}
              @closed=${(r) => r.stopPropagation()}
            >
              <mwc-list-item value="jellyfin">${l(o, "editor.action_jellyfin")}</mwc-list-item>
              <mwc-list-item value="cast">${l(o, "editor.action_cast")}</mwc-list-item>
              <mwc-list-item value="more-info">${l(o, "editor.action_more_info")}</mwc-list-item>
              <mwc-list-item value="trailer">${l(o, "editor.action_trailer")}</mwc-list-item>
              <mwc-list-item value="none">${l(o, "editor.action_none")}</mwc-list-item>
            </ha-select>
          </div>

          <div class="form-row">
            <ha-select
              label="${l(o, "editor.hold_action")}"
              .value=${e}
              @selected=${this._holdActionChanged}
              @closed=${(r) => r.stopPropagation()}
            >
              <mwc-list-item value="jellyfin">${l(o, "editor.action_jellyfin")}</mwc-list-item>
              <mwc-list-item value="cast">${l(o, "editor.action_cast")}</mwc-list-item>
              <mwc-list-item value="more-info">${l(o, "editor.action_more_info")}</mwc-list-item>
              <mwc-list-item value="trailer">${l(o, "editor.action_trailer")}</mwc-list-item>
              <mwc-list-item value="none">${l(o, "editor.action_none")}</mwc-list-item>
            </ha-select>
          </div>
        </div>

        <div class="side-by-side">
          <div class="form-row">
            <ha-select
              label="${l(o, "editor.double_tap_action")}"
              .value=${i}
              @selected=${this._doubleTapActionChanged}
              @closed=${(r) => r.stopPropagation()}
            >
              <mwc-list-item value="jellyfin">${l(o, "editor.action_jellyfin")}</mwc-list-item>
              <mwc-list-item value="cast">${l(o, "editor.action_cast")}</mwc-list-item>
              <mwc-list-item value="more-info">${l(o, "editor.action_more_info")}</mwc-list-item>
              <mwc-list-item value="trailer">${l(o, "editor.action_trailer")}</mwc-list-item>
              <mwc-list-item value="none">${l(o, "editor.action_none")}</mwc-list-item>
            </ha-select>
          </div>

          ${t === "cast" || e === "cast" || i === "cast" ? n`
                <div class="form-row">
                  <ha-entity-picker
                    .hass=${this.hass}
                    .value=${this._config.default_cast_device}
                    .includeDomains=${["media_player"]}
                    @value-changed=${this._defaultCastDeviceChanged}
                  ></ha-entity-picker>
                </div>
              ` : n`<div></div>`}
        </div>

        ${t === "cast" || e === "cast" || i === "cast" ? n`
              <div class="checkbox-row">
                <ha-switch
                  .checked=${this._config.show_now_playing !== !1}
                  @change=${this._showNowPlayingChanged}
                ></ha-switch>
                <span>${l(o, "editor.show_now_playing_overlay")}</span>
              </div>
            ` : ""}

    <div class="checkbox-row">
      <ha-switch
        .checked=${this._config.show_title !== !1}
        @change=${this._showTitleChanged}
      ></ha-switch>
      <span>${l(o, "editor.show_title")}</span>
    </div>

    <div class="checkbox-row">
      <ha-switch
        .checked=${this._config.show_year !== !1}
        @change=${this._showYearChanged}
      ></ha-switch>
      <span>${l(o, "editor.show_year")}</span>
    </div>

    <div class="checkbox-row">
      <ha-switch
        .checked=${this._config.show_ratings !== !1}
        @change=${this._showRatingsChanged}
      ></ha-switch>
      <span>${l(o, "editor.show_rating")}</span>
    </div>

    <div class="checkbox-row">
      <ha-switch
        .checked=${this._config.show_runtime === !0}
        @change=${this._showRuntimeChanged}
      ></ha-switch>
      <span>${l(o, "editor.show_runtime")}</span>
    </div>

    <div class="checkbox-row">
      <ha-switch
        .checked=${this._config.show_date_added === !0}
        @change=${this._showDateAddedChanged}
      ></ha-switch>
      <span>${l(o, "editor.show_date_added")}</span>
    </div>

    <div class="checkbox-row">
      <ha-switch
        .checked=${this._config.show_genres === !0}
        @change=${this._showGenresChanged}
      ></ha-switch>
      <span>${l(o, "editor.show_genres")}</span>
    </div>

    <div class="checkbox-row">
      <ha-switch
        .checked=${this._config.show_description_on_hover !== !1}
        @change=${this._showDescriptionOnHoverChanged}
      ></ha-switch>
      <span>${l(o, "editor.show_description")}</span>
    </div>

    <div class="checkbox-row">
      <ha-switch
        .checked=${this._config.show_media_type_badge !== !1}
        @change=${this._showMediaTypeBadgeChanged}
      ></ha-switch>
      <span>${l(o, "editor.show_media_type_badge")}</span>
    </div>

    <div class="checkbox-row">
      <ha-switch
        .checked=${this._config.show_watched_status !== !1}
        @change=${this._showWatchedStatusChanged}
      ></ha-switch>
      <span>${l(o, "editor.show_watched_status")}</span>
    </div>

    <div class="checkbox-row">
      <ha-switch
        .checked=${this._config.show_search === !0}
        @change=${this._showSearchChanged}
      ></ha-switch>
      <span>${l(o, "editor.show_search")}</span>
    </div>

    <div class="side-by-side">
      <div class="form-row">
        <ha-select
          label="${l(o, "editor.metadata_position")}"
          .value=${this._config.metadata_position || "below"}
          @selected=${this._metadataPositionChanged}
          @closed=${(r) => r.stopPropagation()}
        >
          <mwc-list-item value="below">${l(o, "editor.metadata_below")}</mwc-list-item>
          <mwc-list-item value="above">${l(o, "editor.metadata_above")}</mwc-list-item>
        </ha-select>
      </div>

      <div class="form-row">
        ${this._config.media_type !== "next_up" ? n`
            <ha-select
            label="${l(o, "editor.sort_order")}"
            .value=${this._config.sort_option || "date_added_desc"}
            @selected=${this._sortOptionChanged}
            @closed=${(r) => r.stopPropagation()}
            >
            <mwc-list-item value="date_added_desc">${l(o, "editor.sort_date_added_desc")}</mwc-list-item>
            <mwc-list-item value="date_added_asc">${l(o, "editor.sort_date_added_asc")}</mwc-list-item>
            <mwc-list-item value="title_asc">${l(o, "editor.sort_title_asc")}</mwc-list-item>
            <mwc-list-item value="title_desc">${l(o, "editor.sort_title_desc")}</mwc-list-item>
            <mwc-list-item value="year_desc">${l(o, "editor.sort_year_desc")}</mwc-list-item>
            <mwc-list-item value="year_asc">${l(o, "editor.sort_year_asc")}</mwc-list-item>
            <mwc-list-item value="last_played_desc">${l(o, "editor.sort_last_played_desc")}</mwc-list-item>
            <mwc-list-item value="last_played_asc">${l(o, "editor.sort_last_played_asc")}</mwc-list-item>
            </ha-select>
        ` : n`<div></div>`}
      </div>
    </div>

    <div class="side-by-side">
      <div class="checkbox-row">
        <ha-switch
          .checked=${this._config.enable_pagination !== !1}
          @change=${this._enablePaginationChanged}
        ></ha-switch>
        <span>${l(o, "editor.enable_pagination")}</span>
      </div>

      <div class="checkbox-row">
        <ha-switch
          .checked=${this._config.show_pagination_dots !== !1}
          @change=${this._showPaginationDotsChanged}
        ></ha-switch>
        <span>${l(o, "editor.show_pagination_dots")}</span>
      </div>
    </div>

    <div class="form-row">
      <ha-select
        label="${l(o, "editor.filter_watch_status")}"
        .value=${this._config.status_filter || "all"}
        @selected=${this._statusFilterChanged}
        @closed=${(r) => r.stopPropagation()}
      >
        <mwc-list-item value="all">${l(o, "editor.filter_all")}</mwc-list-item>
        <mwc-list-item value="unwatched">${l(o, "editor.filter_unwatched")}</mwc-list-item>
        <mwc-list-item value="watched">${l(o, "editor.filter_watched")}</mwc-list-item>
      </ha-select>
    </div>

    <div class="side-by-side">
      <div class="checkbox-row">
        <ha-switch
          .checked=${this._config.filter_favorites === !0}
          @change=${this._filterFavoritesChanged}
        ></ha-switch>
        <span>${l(o, "editor.filter_favorites")}</span>
      </div>

      <div class="checkbox-row">
        <ha-switch
          .checked=${this._config.filter_newly_added === !0}
          @change=${this._filterNewlyAddedChanged}
        ></ha-switch>
        <span>${l(o, "editor.filter_new_items")}</span>
      </div>
    </div>

    ${this._config.media_type === "next_up" ? n`
          <div class=\"checkbox-row\">
            <ha-switch
              .checked=${this._config.use_series_image === !0}
              @change=${this._useSeriesImageChanged}
            ></ha-switch>
            <span>${l(o, "editor.use_series_image")}</span>
          </div>
        ` : ""}


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
    i !== "" ? this._updateConfig("items_per_page", Number(i)) : this._updateConfig("items_per_page", null);
  }
  _maxPagesChanged(t) {
    const i = t.target.value;
    i === "" || i === null ? this._updateConfig("max_pages", null) : this._updateConfig("max_pages", Number(i));
  }
  _autoSwipeIntervalChanged(t) {
    const e = t.target;
    this._updateConfig("auto_swipe_interval", Number(e.value));
  }
  _newBadgeDaysChanged(t) {
    const i = t.target.value;
    i === "" || i === null ? this._updateConfig("new_badge_days", null) : this._updateConfig("new_badge_days", Number(i));
  }
  _clickActionChanged(t) {
    const e = t.target;
    this._updateConfig("click_action", e.value);
  }
  _holdActionChanged(t) {
    const e = t.target;
    this._updateConfig("hold_action", e.value);
  }
  _doubleTapActionChanged(t) {
    const e = t.target;
    this._updateConfig("double_tap_action", e.value);
  }
  _defaultCastDeviceChanged(t) {
    this._updateConfig("default_cast_device", t.detail.value);
  }
  _showNowPlayingChanged(t) {
    const e = t.target;
    this._updateConfig("show_now_playing", e.checked);
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
  _enablePaginationChanged(t) {
    const e = t.target;
    this._updateConfig("enable_pagination", e.checked);
  }
  _showPaginationDotsChanged(t) {
    const e = t.target;
    this._updateConfig("show_pagination_dots", e.checked);
  }
  _filterFavoritesChanged(t) {
    const e = t.target;
    this._updateConfig("filter_favorites", e.checked);
  }
  _statusFilterChanged(t) {
    const e = t.target;
    this._updateConfig("status_filter", e.value);
  }
  _filterNewlyAddedChanged(t) {
    const e = t.target;
    this._updateConfig("filter_newly_added", e.checked);
  }
  _showSearchChanged(t) {
    const e = t.target;
    this._updateConfig("show_search", e.checked);
  }
  _sortOptionChanged(t) {
    const e = t.target;
    this._updateConfig("sort_option", e.value);
  }
  _useSeriesImageChanged(t) {
    const e = t.target;
    this._updateConfig("use_series_image", e.checked);
  }
  _updateConfig(t, e) {
    if (!this._config)
      return;
    const i = { ...this._config, [t]: e };
    this._config = i, gt(this, "config-changed", { config: i });
  }
};
X.styles = q`
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
me([
  P({ attribute: !1 })
], X.prototype, "hass", 2);
me([
  u()
], X.prototype, "_config", 2);
X = me([
  R("jellyha-library-editor")
], X);
var ut = Object.defineProperty, mt = Object.getOwnPropertyDescriptor, S = (t, e, i, o) => {
  for (var a = o > 1 ? void 0 : o ? mt(e, i) : e, s = t.length - 1, r; s >= 0; s--)
    (r = t[s]) && (a = (o ? r(e, i, a) : r(a)) || a);
  return o && a && ut(e, i, a), a;
};
let v = class extends j {
  constructor() {
    super(...arguments), this.layout = "grid", this.isNextUpHighlight = !1, this._pressStartTime = 0, this._isHoldActive = !1, this._itemTouchStartX = 0, this._itemTouchStartY = 0, this._rewindActive = !1;
  }
  render() {
    return !this.item || !this.config || !this.hass ? n`` : this.layout === "list" ? this._renderListItem() : this._renderMediaItem();
  }
  _renderListItem() {
    const t = this.item, e = le(t, this.config.new_badge_days || 0), i = this._getRating(t), o = this.config.show_media_type_badge !== !1, a = this._isItemPlaying(t);
    return n`
      <div
        class="media-item list-item ${a ? "playing" : ""} ${this.config.show_title ? "" : "no-title"} ${this.config.metadata_position === "above" ? "metadata-above" : ""}"
        tabindex="0"
        role="button"
        aria-label="${t.name}"
        @mousedown="${this._handleMouseDown}"
        @mouseup="${this._handleMouseUp}"
        @touchstart="${this._handleTouchStart}"
        @touchmove="${this._handleTouchMove}"
        @touchend="${this._handleTouchEnd}"
        @touchcancel="${this._handleTouchEnd}"
        @keydown="${this._handleKeydown}"
        @contextmenu="${this._handleContextMenu}"
      >
        <div class="list-poster-wrapper">
          ${this.config.metadata_position === "above" && this.config.show_date_added && t.date_added ? n`<p class="list-date-added">${Q(t.date_added, this.hass?.locale?.language || this.hass?.language)}</p>` : d}
          <div class="poster-container" id="poster-${t.id}">
            <div class="poster-inner">
              <img
                class="poster"
                src="${B(
      this.config.use_series_image && t.series_poster_url ? t.series_poster_url : t.poster_url,
      160
    )}"
                alt="${t.name}"
                width="80"
                height="120"
                loading="lazy"
                decoding="async"
                @load="${this._handleImageLoad}"
                @error="${this._handleImageError}"
              />
              <div class="poster-skeleton"></div>
              
              ${o && !a && !t.series_name ? n`<span class="list-type-badge ${t.series_name ? "series" : t.type === "Movie" ? "movie" : "series"}">
                    ${t.series_name && t.season !== void 0 && t.episode !== void 0 ? `S${String(t.season).padStart(2, "0")}E${String(t.episode).padStart(2, "0")}` : t.type === "Movie" ? "Movie" : "Series"}
                  </span>` : d}

              ${t.series_name && !a ? n`
            <div class="censor-bar list-bar ${this.isNextUpHighlight ? "highlight" : ""}">
              <span>${t.series_name}</span>
            </div>
              ` : d}
              
              ${a ? d : this._renderStatusBadge(t, e)}
              ${this._renderNowPlayingOverlay(t)}
            </div>
          </div>
          ${this.config.metadata_position !== "above" && this.config.show_date_added && t.date_added ? n`<p class="list-date-added">${Q(t.date_added, this.hass?.locale?.language || this.hass?.language)}</p>` : d}
        </div>
        
        <div class="list-info">
          ${this.config.show_title ? n`<h3 class="list-title">${t.name}</h3>` : d}
          
          <div class="list-metadata">
            ${o && !a ? n`<span class="list-type-badge ${t.series_name ? "series" : t.type === "Movie" ? "movie" : "series"}">
                  ${t.series_name && t.season !== void 0 && t.episode !== void 0 ? `S${String(t.season).padStart(2, "0")}E${String(t.episode).padStart(2, "0")}` : t.type === "Movie" ? "Movie" : "Series"}
                </span>` : d}
            ${this.config.show_year && t.year ? n`<span class="list-year">${t.year}</span>` : d}
            ${this.config.show_ratings && i ? n`<span class="list-rating">
                  <ha-icon icon="mdi:star"></ha-icon>
                  ${i.toFixed(1)}
                </span>` : d}
            ${this.config.show_runtime && t.runtime_minutes ? n`<span class="list-runtime">
                  <ha-icon icon="mdi:clock-outline"></ha-icon>
                  ${de(t.runtime_minutes)}
                </span>` : d}
          </div>
          
          ${this.config.show_genres && t.genres && t.genres.length > 0 ? n`<p class="list-genres">${t.genres.slice(0, 3).join(", ")}</p>` : d}
          
          ${this.config.show_description_on_hover !== !1 && t.description ? n`<p class="list-description">${t.description}</p>` : d}
        </div>
      </div>
    `;
  }
  _renderMediaItem() {
    const t = this.item, e = le(t, this.config.new_badge_days || 0), i = this._getRating(t), o = this.config.show_media_type_badge !== !1, a = this._isItemPlaying(t);
    return n`
      <div
        class="media-item ${a ? "playing" : ""}"
        tabindex="0"
        role="button"
        aria-label="${t.name}"
        @mousedown="${this._handleMouseDown}"
        @mouseup="${this._handleMouseUp}"
        @touchstart="${this._handleTouchStart}"
        @touchmove="${this._handleTouchMove}"
        @touchend="${this._handleTouchEnd}"
        @touchcancel="${this._handleTouchEnd}"
        @keydown="${this._handleKeydown}"
        @contextmenu="${this._handleContextMenu}"
      >
        ${this.config.metadata_position === "above" ? n`
              <div class="media-info-above">
                ${this.config.show_title ? n`<p class="media-title">${t.name}</p>` : d}
                ${this.config.show_year && t.year ? n`<p class="media-year">${t.year}</p>` : d}
                ${this.config.show_date_added && t.date_added ? n`<p class="media-date-added">${Q(t.date_added, this.hass?.locale?.language || this.hass?.language)}</p>` : d}
              </div>
            ` : d}
        <div class="poster-container" id="poster-${t.id}">
          <div class="poster-inner">
            <img
              class="poster"
              src="${B(
      this.config.use_series_image && t.series_poster_url ? t.series_poster_url : t.poster_url,
      300
    )}"
              alt="${t.name}"
              width="140"
              height="210"
              loading="auto"
              decoding="async"
              @load="${this._handleImageLoad}"
              @error="${this._handleImageError}"
            />
            <div class="poster-skeleton"></div>
            
            ${o && !a ? n`
            <span class="media-type-badge ${t.series_name ? "series" : t.type === "Movie" ? "movie" : "series"}">
              ${t.series_name && t.season !== void 0 && t.episode !== void 0 ? `S${String(t.season).padStart(2, "0")}E${String(t.episode).padStart(2, "0")}` : t.type === "Movie" ? "Movie" : "Series"}
            </span>
          ` : d}

            ${t.series_name && !a ? n`
            <div class="censor-bar ${this.isNextUpHighlight ? "highlight" : ""}">
              <span>${t.series_name}</span>
            </div>
              ` : d}
            
            ${a ? d : this._renderStatusBadge(t, e)}
            
            ${this.config.show_ratings && i && !a ? n`
                  <span class="rating">
                    <ha-icon icon="mdi:star"></ha-icon>
                    ${i.toFixed(1)}
                  </span>
                ` : d}
            
            ${this.config.show_runtime && t.runtime_minutes && !a ? n`
                  <span class="runtime">
                    <ha-icon icon="mdi:clock-outline"></ha-icon>
                    ${de(t.runtime_minutes)}
                  </span>
                ` : d}
            
            ${a ? d : n`
            <div class="hover-overlay">
              ${t.year ? n`<span class="overlay-year">${t.year}</span>` : d}
              <h3 class="overlay-title">${t.name}</h3>
              ${this.config.show_genres && t.genres && t.genres.length > 0 ? n`<span class="overlay-genres">${t.genres.slice(0, 3).join(", ")}</span>` : d}
              ${this.config.show_description_on_hover !== !1 && t.description ? n`<p class="overlay-description">${t.description}</p>` : d}
            </div>`}

            ${this._renderNowPlayingOverlay(t)}
          </div>
        </div>
        
        ${this.config.metadata_position === "below" ? n`
              <div class="media-info-below">
                ${this.config.show_title ? n`<p class="media-title">${t.name}</p>` : d}
                ${this.config.show_year && t.year ? n`<p class="media-year">${t.year}</p>` : d}
                ${this.config.show_date_added && t.date_added ? n`<p class="media-date-added">${Q(t.date_added, this.hass?.locale?.language || this.hass?.language)}</p>` : d}
              </div>
            ` : d}
      </div>
    `;
  }
  _renderStatusBadge(t, e) {
    const i = this.config.show_watched_status !== !1;
    return i && t.is_played ? n`
        <div class="status-badge watched">
          <ha-icon icon="mdi:check-bold"></ha-icon>
        </div>
      ` : i && t.type === "Series" && (t.unplayed_count || 0) > 0 ? n`
        <div class="status-badge unplayed">
          ${t.unplayed_count}
        </div>
      ` : e ? n`<span class="new-badge">${l(this.hass.locale?.language || this.hass.language, "new")}</span>` : n``;
  }
  _renderNowPlayingOverlay(t) {
    if (!this.config.show_now_playing || !this._isItemPlaying(t))
      return d;
    const e = this.hass.states[this.config.default_cast_device];
    return n`
      <div 
        class="now-playing-overlay" 
        @click="${() => this._handleRewind(this.config.default_cast_device)}"
        @mousedown="${this._stopPropagation}"
        @mouseup="${this._stopPropagation}"
        @touchstart="${this._stopPropagation}"
        @touchend="${this._stopPropagation}"
        @touchcancel="${this._stopPropagation}"
        role="button"
        tabindex="0"
      >
        <span class="now-playing-status">
          ${this._rewindActive ? "REWINDING" : e.state}
        </span>
        <div class="now-playing-controls">
          <ha-icon-button
            class="${this._rewindActive ? "spinning" : ""}"
            .label=${"Play/Pause"}
            @click="${(i) => {
      i.stopPropagation(), this._handlePlayPause(this.config.default_cast_device);
    }}"
          >
            <ha-icon icon="${this._rewindActive ? "mdi:loading" : e.state === "playing" ? "mdi:pause" : "mdi:play"}"></ha-icon>
          </ha-icon-button>
          <ha-icon-button
            class="stop"
            .label=${"Stop"}
            @click="${(i) => {
      i.stopPropagation(), this._handleStop(this.config.default_cast_device);
    }}"
          >
            <ha-icon icon="mdi:stop"></ha-icon>
          </ha-icon-button>
        </div>
      </div>
    `;
  }
  /* --- Helpers --- */
  _isItemPlaying(t) {
    if (!this.config.default_cast_device || !this.hass) return !1;
    const e = this.hass.states[this.config.default_cast_device];
    if (!e || e.state !== "playing" && e.state !== "paused" && e.state !== "buffering")
      return !1;
    const i = e.attributes.media_title, o = e.attributes.media_series_title;
    return t.name && (i === t.name || o === t.name) || t.type === "Series" && o === t.name;
  }
  _getRating(t) {
    return this.config.rating_source === "auto", t.rating || null;
  }
  /* --- Event Handlers --- */
  _fireAction(t) {
    const e = new CustomEvent("jellyha-action", {
      detail: { type: t, item: this.item },
      bubbles: !0,
      composed: !0
    });
    this.dispatchEvent(e);
  }
  _startHoldTimer() {
    this._pressStartTime = Date.now(), this._isHoldActive = !1, this._holdTimer = window.setTimeout(() => {
      this._isHoldActive = !0;
      const t = this.shadowRoot?.querySelector(`#poster-${this.item.id}`);
      t && (t.classList.add("hold-pulse"), setTimeout(() => {
        t.classList.remove("hold-pulse");
      }, 300)), this._dispatchHaptic("medium"), this._fireAction("hold");
    }, 500);
  }
  _clearHoldTimer() {
    this._holdTimer && (clearTimeout(this._holdTimer), this._holdTimer = void 0);
  }
  _handleMouseDown(t) {
    t.button === 0 && this._startHoldTimer();
  }
  _handleMouseUp(t) {
    this._isHoldActive ? (t.preventDefault(), t.stopPropagation()) : Date.now() - this._pressStartTime < 500 && this._handleTap(), this._clearHoldTimer();
  }
  _handleTap() {
    if ((this.config.double_tap_action || "none") === "none") {
      this._dispatchHaptic("light"), this._fireAction("click");
      return;
    }
    this._clickTimer ? (clearTimeout(this._clickTimer), this._clickTimer = void 0, this._dispatchHaptic("medium"), this._fireAction("double_tap")) : this._clickTimer = window.setTimeout(() => {
      this._clickTimer = void 0, this._dispatchHaptic("light"), this._fireAction("click");
    }, 250);
  }
  _handleContextMenu(t) {
    t.preventDefault(), t.stopPropagation();
  }
  _handleTouchStart(t) {
    t.touches.length > 0 && (this._itemTouchStartX = t.touches[0].clientX, this._itemTouchStartY = t.touches[0].clientY, t.currentTarget.classList.add("active-press")), this._startHoldTimer();
  }
  _handleTouchMove(t) {
    if (t.touches.length > 0) {
      const e = Math.abs(t.touches[0].clientX - this._itemTouchStartX), i = Math.abs(t.touches[0].clientY - this._itemTouchStartY);
      (e > 10 || i > 10) && (this._clearHoldTimer(), t.currentTarget.classList.remove("active-press"));
    }
  }
  _handleTouchEnd(t) {
    t.currentTarget.classList.remove("active-press"), this._clearHoldTimer();
    let i = 0;
    if (t.changedTouches.length > 0) {
      const o = t.changedTouches[0].clientX - this._itemTouchStartX, a = t.changedTouches[0].clientY - this._itemTouchStartY;
      i = Math.sqrt(o * o + a * a);
    }
    if (t.cancelable && t.preventDefault(), this._isHoldActive) {
      this._isHoldActive = !1;
      return;
    }
    i > 10 || this._handleTap();
  }
  _handleKeydown(t) {
    (t.key === "Enter" || t.key === " ") && (t.preventDefault(), this._fireAction("click"));
  }
  _handleImageLoad(t) {
    t.target.classList.add("loaded");
  }
  _handleImageError(t) {
    const e = t.target;
    e.style.opacity = "0", e.style.position = "absolute";
    const i = e.nextElementSibling;
    i && i.classList.contains("poster-skeleton") && i.classList.add("error");
  }
  /* --- Playback Control Handlers --- */
  _stopPropagation(t) {
    t.stopPropagation();
  }
  _handlePlayPause(t) {
    this._dispatchHaptic(), this.hass.callService("media_player", "media_play_pause", { entity_id: t });
  }
  _handleStop(t) {
    this._dispatchHaptic(), this.hass.callService("media_player", "turn_off", { entity_id: t });
  }
  _handleRewind(t) {
    this._rewindActive = !0, setTimeout(() => {
      this._rewindActive = !1;
    }, 2e3), this._dispatchHaptic();
    const e = this.hass.states[t];
    if (e && e.attributes.media_position) {
      const i = e.attributes.media_position, o = e.attributes.media_position_updated_at;
      let a = i;
      if (o) {
        const r = (/* @__PURE__ */ new Date()).getTime(), h = new Date(o).getTime(), c = (r - h) / 1e3;
        e.state === "playing" && (a += c);
      }
      const s = Math.max(0, a - 20);
      this.hass.callService("media_player", "media_seek", {
        entity_id: t,
        seek_position: s
      });
    }
  }
  _dispatchHaptic(t = "selection") {
    const e = new CustomEvent("haptic", {
      detail: t,
      bubbles: !0,
      composed: !0
    });
    this.dispatchEvent(e);
  }
};
v.styles = Ne;
S([
  P({ attribute: !1 })
], v.prototype, "hass", 2);
S([
  P({ attribute: !1 })
], v.prototype, "config", 2);
S([
  P({ attribute: !1 })
], v.prototype, "item", 2);
S([
  P({ type: String })
], v.prototype, "layout", 2);
S([
  P({ type: Boolean })
], v.prototype, "isNextUpHighlight", 2);
S([
  u()
], v.prototype, "_pressStartTime", 2);
S([
  u()
], v.prototype, "_holdTimer", 2);
S([
  u()
], v.prototype, "_isHoldActive", 2);
S([
  u()
], v.prototype, "_itemTouchStartX", 2);
S([
  u()
], v.prototype, "_itemTouchStartY", 2);
S([
  u()
], v.prototype, "_clickTimer", 2);
S([
  u()
], v.prototype, "_rewindActive", 2);
v = S([
  R("jellyha-media-item")
], v);
var ft = Object.defineProperty, wt = Object.getOwnPropertyDescriptor, b = (t, e, i, o) => {
  for (var a = o > 1 ? void 0 : o ? wt(e, i) : e, s = t.length - 1, r; s >= 0; s--)
    (r = t[s]) && (a = (o ? r(e, i, a) : r(a)) || a);
  return o && a && ft(e, i, a), a;
};
const bt = "1.0.0";
console.info(
  `%c JELLYHA-LIBRARY-CARD %c v${bt} `,
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
const Te = {
  title: "",
  layout: "carousel",
  media_type: "both",
  items_per_page: 3,
  max_pages: 5,
  auto_swipe_interval: 0,
  // 0 = disabled, otherwise seconds
  columns: 2,
  show_title: !0,
  show_year: !0,
  show_runtime: !0,
  show_ratings: !0,
  show_media_type_badge: !0,
  show_genres: !0,
  show_description_on_hover: !0,
  enable_pagination: !0,
  metadata_position: "below",
  show_date_added: !1,
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
function yt(t, e, i) {
  const o = new CustomEvent(e, {
    bubbles: !0,
    composed: !0,
    detail: i
  });
  t.dispatchEvent(o);
}
let w = class extends j {
  constructor() {
    super(), this._currentPage = 0, this._itemsPerPage = 5, this._pressStartTime = 0, this._isHoldActive = !1, this._rewindActive = !1, this._items = [], this._lastUpdate = "", this._searchQuery = "", this._searchGenre = "", this._touchStartX = 0, this._touchStartY = 0, this._isOverscrolling = !1, this._elasticAnchorX = 0, this._itemTouchStartX = 0, this._itemTouchStartY = 0, this._containerWidth = 0, this.ITEM_WIDTH = 148, this.LIST_ITEM_MIN_WIDTH = 380, this._effectiveListColumns = 1, this._isSwiping = !1, this._autoSwipePaused = !1, this._lastFrameTime = 0, this._scrollAccumulator = 0, this._scrollProgress = 0, this._hasScrollableContent = !1, this.SCROLL_INDICATOR_DOTS = 5, this._handleMouseEnter = () => {
      this._autoSwipePaused = !0;
    }, this._handleMouseLeave = () => {
      this._autoSwipePaused = !1;
    }, this._handleTouchStartInteraction = () => {
      this._autoSwipePaused = !0;
    }, this._handleTouchEndInteraction = () => {
      setTimeout(() => {
        this._autoSwipePaused = !1;
      }, 2e3);
    }, this._onDotClick = this._onDotClick.bind(this), this._handleTouchStart = this._handleTouchStart.bind(this), this._handleTouchMove = this._handleTouchMove.bind(this), this._handleTouchEnd = this._handleTouchEnd.bind(this), this._handlePointerDown = this._handlePointerDown.bind(this), this._handlePointerMove = this._handlePointerMove.bind(this), this._handlePointerUp = this._handlePointerUp.bind(this), this._handleScroll = this._handleScroll.bind(this);
  }
  connectedCallback() {
    super.connectedCallback(), this._setupResizeHandler(), this.addEventListener("mouseenter", this._handleMouseEnter), this.addEventListener("mouseleave", this._handleMouseLeave), this.addEventListener("touchstart", this._handleTouchStartInteraction, { passive: !0 }), this.addEventListener("touchend", this._handleTouchEndInteraction), this._setupAutoSwipe();
  }
  disconnectedCallback() {
    super.disconnectedCallback(), this._resizeObserver?.disconnect(), this._resizeHandler && window.removeEventListener("resize", this._resizeHandler), this.removeEventListener("mouseenter", this._handleMouseEnter), this.removeEventListener("mouseleave", this._handleMouseLeave), this.removeEventListener("touchstart", this._handleTouchStartInteraction), this.removeEventListener("touchend", this._handleTouchEndInteraction), this._clearAutoSwipe();
  }
  _setupAutoSwipe() {
    this._clearAutoSwipe();
    const t = this._config?.auto_swipe_interval;
    !t || t <= 0 || (this._config.enable_pagination !== !1 ? this._autoSwipeTimer = window.setInterval(() => {
      this._autoSwipePaused || this._handleAutoSwipePage();
    }, t * 1e3) : this._startContinuousScroll());
  }
  _clearAutoSwipe() {
    this._autoSwipeTimer && (clearInterval(this._autoSwipeTimer), this._autoSwipeTimer = void 0), this._animationFrameId && (cancelAnimationFrame(this._animationFrameId), this._animationFrameId = void 0);
  }
  /* Continuous Scroll Logic */
  _startContinuousScroll() {
    const t = (e) => {
      this._lastFrameTime || (this._lastFrameTime = e);
      const i = e - this._lastFrameTime;
      if (this._lastFrameTime = e, !this._autoSwipePaused && this._config.auto_swipe_interval) {
        const o = this.shadowRoot?.querySelector(".carousel, .grid-wrapper, .list-wrapper");
        if (o) {
          const { scrollLeft: a, scrollWidth: s, clientWidth: r } = o;
          Math.abs(this._scrollAccumulator - a) > 10 && (this._scrollAccumulator = a);
          const c = r / (this._config.auto_swipe_interval * 1e3) * i, _ = s / 2;
          this._scrollAccumulator += c, this._scrollAccumulator >= _ ? (this._scrollAccumulator = this._scrollAccumulator - _, o.scrollLeft = this._scrollAccumulator) : o.scrollLeft = this._scrollAccumulator;
        }
      }
      this._animationFrameId = requestAnimationFrame(t);
    };
    this._animationFrameId = requestAnimationFrame(t);
  }
  /* Pagination Auto Swipe Logic */
  async _handleAutoSwipePage() {
    const t = this._items || [], e = this._config.items_per_page || this._itemsPerPage, i = this._config.max_pages || 10, o = Math.min(Math.ceil(t.length / e), i);
    this._currentPage >= o - 1 ? await this._animatePageChange("next", () => {
      this._currentPage = 0;
    }) : this._nextPage();
  }
  /* Pagination Handlers */
  async _nextPage() {
    if (!this._config?.entity || !this.hass || !this.hass.states[this._config.entity]) return;
    const e = this._filterItems(this._items || []), i = this._config.items_per_page || this._itemsPerPage, o = this._config.max_pages || 10, a = Math.min(Math.ceil(e.length / i), o);
    this._currentPage < a - 1 && await this._animatePageChange("next", () => {
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
  _setScrollPosition(t) {
    const e = this.shadowRoot?.querySelector(".carousel, .grid-wrapper, .list-wrapper");
    e && (t === "start" ? e.scrollLeft = 0 : e.scrollLeft = e.scrollWidth);
  }
  /**
   * Helper to animate page changes (Slide & Fade)
   **/
  async _animatePageChange(t, e) {
    const i = this.shadowRoot?.querySelector(".carousel, .grid-wrapper, .list-wrapper");
    if (!i) {
      e();
      return;
    }
    const o = t === "next" ? "-30px" : "30px";
    i.style.transition = "transform 0.2s ease-out, opacity 0.2s ease-out", i.style.transform = `translateX(${o})`, i.style.opacity = "0", await new Promise((s) => setTimeout(s, 200)), e(), await this.updateComplete, this._setScrollPosition(t === "next" ? "start" : "end");
    const a = t === "next" ? "30px" : "-30px";
    i.style.transition = "none", i.style.opacity = "0", i.style.transform = `translateX(${a})`, i.offsetHeight, i.style.transition = "transform 0.25s ease-out, opacity 0.25s ease-out", i.style.transform = "translateX(0)", i.style.opacity = "1", await new Promise((s) => setTimeout(s, 250)), i.style.transition = "", i.style.transform = "", i.style.opacity = "";
  }
  /**
   * Helper to get total pages (used for elastic check)
   */
  _getTotalPages() {
    if (!this._config?.entity || !this.hass || !this.hass.states[this._config.entity]) return 1;
    const e = this._filterItems(this._items || []), i = this._config.items_per_page || this._itemsPerPage, o = this._config.max_pages || 10;
    return Math.min(Math.ceil(e.length / i), o);
  }
  // Touch/Swipe handlers
  _handleTouchStart(t) {
    this._touchStartX = t.touches[0].clientX, this._touchStartY = t.touches[0].clientY, this._isSwiping = !1, this._isOverscrolling = !1, this._elasticAnchorX = 0;
  }
  _handleTouchMove(t) {
    if (!this._touchStartX) return;
    const e = t.touches[0].clientX - this._touchStartX, i = t.touches[0].clientY - this._touchStartY;
    if (Math.abs(e) > Math.abs(i)) {
      const o = this.shadowRoot?.querySelector(".carousel, .grid-wrapper, .list-wrapper");
      if (o && Math.abs(e) > 0) {
        const { scrollLeft: a, scrollWidth: s, clientWidth: r } = o, h = s - r, c = a <= 5, _ = a >= h - 5, g = this._config.show_pagination !== !1;
        let p = !1;
        if (g) {
          const m = this._getTotalPages();
          c && e > 0 && this._currentPage === 0 && (p = !0), _ && e < 0 && this._currentPage >= m - 1 && (p = !0);
        } else
          c && e > 0 && (p = !0), _ && e < 0 && (p = !0);
        if (p) {
          this._isOverscrolling || (this._isOverscrolling = !0, this._elasticAnchorX = e), t.cancelable && t.preventDefault();
          const m = 0.3, f = e - this._elasticAnchorX;
          o.style.transition = "none", o.style.transform = `translateX(${f * m}px)`;
          return;
        }
      }
      Math.abs(e) > 30 && (this._isSwiping = !0);
    }
  }
  _handleTouchEnd(t) {
    if (this._isOverscrolling) {
      const a = this.shadowRoot?.querySelector(".carousel, .grid-wrapper, .list-wrapper");
      a && (a.style.transition = "transform 0.4s cubic-bezier(0.25, 0.8, 0.5, 1)", a.style.transform = ""), this._isOverscrolling = !1, this._elasticAnchorX = 0, this._touchStartX = 0, this._isSwiping = !1;
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
    const e = t.changedTouches[0].clientX - this._touchStartX, i = 50, o = this.shadowRoot?.querySelector(".carousel, .grid-wrapper, .list-wrapper");
    if (e < -i)
      if (o) {
        const { scrollLeft: a, scrollWidth: s, clientWidth: r } = o;
        a + r >= s - 10 && this._nextPage();
      } else
        this._nextPage();
    else e > i && (o ? o.scrollLeft <= 10 && this._prevPage() : this._prevPage());
    this._touchStartX = 0, this._isSwiping = !1;
  }
  // Pointer events for Android Companion App (uses same logic as touch)
  // Pointer events for Android Companion App (uses same logic as touch)
  _handlePointerDown(t) {
    t.pointerType !== "mouse" && (this._touchStartX = t.clientX, this._touchStartY = t.clientY, this._isSwiping = !1, this._isOverscrolling = !1, this._elasticAnchorX = 0, t.target.setPointerCapture?.(t.pointerId));
  }
  _handlePointerMove(t) {
    if (t.pointerType === "mouse" || !this._touchStartX) return;
    const e = t.clientX - this._touchStartX, i = t.clientY - this._touchStartY;
    if (Math.abs(e) > Math.abs(i)) {
      const o = this.shadowRoot?.querySelector(".carousel, .grid-wrapper, .list-wrapper");
      if (o && Math.abs(e) > 0) {
        const { scrollLeft: a, scrollWidth: s, clientWidth: r } = o, h = s - r, c = a <= 5, _ = a >= h - 5, g = this._config.show_pagination !== !1;
        let p = !1;
        if (g) {
          const m = this._getTotalPages();
          c && e > 0 && this._currentPage === 0 && (p = !0), _ && e < 0 && this._currentPage >= m - 1 && (p = !0);
        } else
          c && e > 0 && (p = !0), _ && e < 0 && (p = !0);
        if (p) {
          this._isOverscrolling || (this._isOverscrolling = !0, this._elasticAnchorX = e), t.cancelable && t.preventDefault();
          const m = 0.3, f = e - this._elasticAnchorX;
          o.style.transition = "none", o.style.transform = `translateX(${f * m}px)`;
          return;
        }
      }
      Math.abs(e) > 30 && (this._isSwiping = !0);
    }
  }
  _handlePointerUp(t) {
    if (t.target.releasePointerCapture?.(t.pointerId), this._isOverscrolling) {
      const a = this.shadowRoot?.querySelector(".carousel, .grid-wrapper, .list-wrapper");
      a && (a.style.transition = "transform 0.4s cubic-bezier(0.25, 0.8, 0.5, 1)", a.style.transform = ""), this._isOverscrolling = !1, this._elasticAnchorX = 0, this._touchStartX = 0, this._isSwiping = !1;
      return;
    }
    if (t.pointerType === "mouse" || !this._isSwiping) {
      this._touchStartX = 0;
      return;
    }
    if (this._config.show_pagination === !1) {
      this._touchStartX = 0, this._isSwiping = !1;
      return;
    }
    const e = t.clientX - this._touchStartX, i = 50, o = this.shadowRoot?.querySelector(".carousel, .grid-wrapper, .list-wrapper");
    if (e < -i)
      if (o) {
        const { scrollLeft: a, scrollWidth: s, clientWidth: r } = o;
        a + r >= s - 10 && this._nextPage();
      } else
        this._nextPage();
    else e > i && (o ? o.scrollLeft <= 10 && this._prevPage() : this._prevPage());
    this._touchStartX = 0, this._isSwiping = !1;
  }
  // Scroll handler for elastic dot indicator
  _handleScroll(t) {
    const e = t.target, i = e.scrollWidth, o = e.clientWidth, a = e.scrollLeft, s = i > o + 10;
    if (s !== this._hasScrollableContent && (this._hasScrollableContent = s), s) {
      let r = 0;
      const h = this._config.enable_pagination === !1 && (this._config.auto_swipe_interval || 0) > 0;
      if (h) {
        const c = i / 2;
        r = a / c;
      } else {
        const c = i - o;
        r = a / c;
      }
      !h && (i - o - a < 10 || r > 0.98) && (r = 1), (a < 10 || r < 0.02) && (r = 0), r = Math.min(1, Math.max(0, r)), this._scrollProgress = r;
    }
  }
  // Render scroll indicator for non-paginated scrollable content
  _renderScrollIndicator() {
    if (!this._hasScrollableContent || this._config.show_pagination_dots === !1) return n``;
    const t = this.SCROLL_INDICATOR_DOTS, e = this._scrollProgress, i = Math.round(e * (t - 1));
    return n`
      <div class="scroll-indicator">
        ${Array.from({ length: t }, (o, a) => {
      const s = a === i, r = a === 0 && e < 0.1 || a === t - 1 && e > 0.9;
      return n`
        <span 
          class="scroll-dot ${s ? "active" : ""} ${r ? "pill" : ""}"
        ></span>
      `;
    })}
      </div>
    `;
  }
  _setupResizeHandler() {
    this._resizeHandler = () => {
      const e = this.getBoundingClientRect().width;
      if (e === 0) return;
      const i = Math.max(0, e - 32);
      if (i !== this._containerWidth) {
        this._containerWidth = i;
        const a = Math.max(2, Math.floor(i / 160));
        if (a !== this._itemsPerPage && (this._itemsPerPage = a, this.requestUpdate()), this._config) {
          const s = this._config.columns || 1, r = 300;
          if (s > 1) {
            const h = Math.max(1, Math.floor(i / r)), c = Math.min(s, h);
            c !== this._effectiveListColumns && (this._effectiveListColumns = c, this.requestUpdate());
          } else this._effectiveListColumns !== 1 && (this._effectiveListColumns = 1, this.requestUpdate());
        }
      }
    };
    try {
      this._resizeObserver = new ResizeObserver(() => {
        this._resizeHandler && window.requestAnimationFrame(() => this._resizeHandler());
      }), this._resizeObserver.observe(this);
    } catch (t) {
      console.warn("ResizeObserver not supported, falling back to window resize", t), window.addEventListener("resize", this._resizeHandler);
    }
    this._resizeHandler();
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
    this._config = { ...Te, ...t }, this._effectiveListColumns = this._config.columns || 1;
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
      ...Te
    };
  }
  /**
   * Get card size for layout
   */
  getCardSize() {
    return this._config?.layout === "list" ? 5 : 3;
  }
  getLayoutOptions() {
    return {
      grid_rows: 6,
      grid_columns: 12
    };
  }
  getGridOptions() {
    return {
      columns: 12,
      rows: 6,
      min_columns: 12,
      min_rows: 4
    };
  }
  /**
   * Determine if component should update
   */
  shouldUpdate(t) {
    if (!this._config)
      return !1;
    if (t.has("_currentPage") || t.has("_itemsPerPage") || t.has("_items") || t.has("_error") || t.has("_searchQuery") || t.has("_searchGenre") || t.has("_scrollProgress") || t.has("_hasScrollableContent"))
      return !0;
    if (t.has("hass")) {
      const e = t.get("hass");
      if (e) {
        const i = e.states[this._config.entity], o = this.hass.states[this._config.entity], a = this._config.default_cast_device;
        if (a) {
          const s = e.states[a], r = this.hass.states[a];
          if (s !== r) return !0;
        }
        return i !== o;
      }
    }
    return t.has("_config");
  }
  /**
   * Fetch items from WebSocket
   */
  async _fetchItems() {
    if (!(!this._config || !this.hass || !this.hass.states[this._config.entity])) {
      this._error = void 0;
      try {
        let e;
        this._config.media_type === "next_up" ? e = await this.hass.callWS({
          type: "jellyha/get_user_next_up",
          entity_id: this._config.entity
        }) : e = await this.hass.callWS({
          type: "jellyha/get_items",
          entity_id: this._config.entity
        }), e && e.items ? (this._items = e.items, this._config.media_type === "next_up" && this._items.length > 0 ? this._mostRecentNextUpItemId = this._items[0].id : this._mostRecentNextUpItemId = void 0) : (this._items = [], this._mostRecentNextUpItemId = void 0);
      } catch (e) {
        console.error("Error fetching JellyHA items:", e), this._error = `Error fetching items: ${e}`;
      }
    }
  }
  /**
   * Called after update - check for scrollable content and fetch data
   */
  updated(t) {
    if (super.updated(t), t.has("hass") || t.has("_config")) {
      const e = this.hass?.states[this._config?.entity];
      if (e) {
        const i = e.attributes.entry_id, o = e.attributes.last_updated;
        (o !== this._lastUpdate || this._items.length === 0 && i) && (this._lastUpdate = o, this._fetchItems());
      }
    }
    this._config.enable_pagination || requestAnimationFrame(() => {
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
      return n``;
    if (!this.hass.states[this._config.entity])
      return this._renderError(`Entity not found: ${this._config.entity}`);
    if (this._error)
      return this._renderError(this._error);
    const e = this._filterItems(this._items || []);
    return n`
      <ha-card>
        <div class="card-inner">
            ${this._config.title ? n`
                  <div class="card-header">
                    <h2>${this._config.title}</h2>
                  </div>
                ` : d}
            ${this._config.show_search ? this._renderSearchBar(e) : d}
            <div class="card-content">
              ${e.length === 0 ? this._renderEmpty() : this._renderLayout(e)}
            </div>
        </div>
        <jellyha-item-details-modal .hass=${this.hass}></jellyha-item-details-modal>
      </ha-card>
    `;
  }
  /**
   * Filter items based on config
   */
  _filterItems(t) {
    let e = t;
    if (this._searchQuery) {
      const s = this._searchQuery.toLowerCase();
      e = e.filter((r) => r.name.toLowerCase().includes(s));
    }
    if (this._searchGenre && (e = e.filter((s) => s.genres && s.genres.includes(this._searchGenre))), this._config.media_type === "movies")
      e = e.filter((s) => s.type === "Movie");
    else if (this._config.media_type === "series")
      e = e.filter((s) => s.type === "Series");
    else if (this._config.media_type === "next_up") {
      const s = this._config.max_pages;
      if (s != null && s > 0) {
        const r = (this._config.items_per_page || 5) * s;
        e = e.slice(0, r);
      }
      return e;
    }
    this._config.filter_favorites && (e = e.filter((s) => s.is_favorite === !0));
    const i = this._config.status_filter || "all";
    i === "unwatched" ? e = e.filter((s) => !s.is_played) : i === "watched" && (e = e.filter((s) => s.is_played === !0)), this._config.filter_newly_added && (e = e.filter((s) => le(s, this._config.new_badge_days || 0)));
    const o = this._config.sort_option || "date_added_desc";
    e.sort((s, r) => {
      switch (o) {
        case "date_added_asc":
          return (s.date_added || "").localeCompare(r.date_added || "");
        case "date_added_desc":
          return (r.date_added || "").localeCompare(s.date_added || "");
        case "title_asc":
          return (s.name || "").localeCompare(r.name || "");
        case "title_desc":
          return (r.name || "").localeCompare(s.name || "");
        case "year_asc":
          return (s.year || 0) - (r.year || 0);
        case "year_desc":
          return (r.year || 0) - (s.year || 0);
        case "last_played_asc":
          return (s.last_played_date || "").localeCompare(r.last_played_date || "");
        case "last_played_desc":
          return (r.last_played_date || "").localeCompare(s.last_played_date || "");
        default:
          return 0;
      }
    });
    const a = this._config.max_pages;
    if (a != null && a > 0) {
      const s = (this._config.items_per_page || 5) * a;
      e = e.slice(0, s);
    }
    return e;
  }
  /**
   * Render media item action handler
   */
  _handleItemAction(t) {
    const { type: e, item: i } = t.detail;
    this._performAction(i, e);
  }
  /**
   * Render layout based on config
   */
  _renderLayout(t) {
    const e = this._config.layout || "carousel", i = this._config.enable_pagination !== !1;
    return e === "carousel" ? this._renderCarousel(t, i) : e === "list" ? this._renderList(t, i) : e === "grid" ? this._renderGrid(t, i) : n`
      <div class="${e}">
        ${t.map((o) => n`
            <jellyha-media-item
                .hass=${this.hass}
                .config=${this._config}
                .item=${o}
                .layout=${"grid"}
                @jellyha-action=${this._handleItemAction}
            ></jellyha-media-item>
        `)}
      </div>
    `;
  }
  /**
   * Render carousel with optional pagination
   */
  _renderCarousel(t, e) {
    const i = this._config.items_per_page || this._itemsPerPage, o = this._config.max_pages, a = o ? Number(o) : 0, s = a > 0 ? a : 1 / 0, r = Math.min(Math.ceil(t.length / i), s), h = this._currentPage * i, c = !e && (this._config.auto_swipe_interval || 0) > 0, _ = e ? t.slice(h, h + i) : c ? [...t, ...t] : t;
    return n`
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
          @scroll="${e ? d : this._handleScroll}"
        >
          ${_.map((g) => n`
            <jellyha-media-item
                .hass=${this.hass}
                .config=${this._config}
                .item=${g}
                .layout=${"grid"}
                .isNextUpHighlight=${this._config.media_type === "next_up" && g.id === this._mostRecentNextUpItemId}
                @jellyha-action=${this._handleItemAction}
            ></jellyha-media-item>
          `)}
        </div>
        ${e && r > 1 ? this._renderPagination(r) : d}
        ${e ? d : this._renderScrollIndicator()}
      </div>
    `;
  }
  /**
   * Render list with optional pagination
   */
  _renderList(t, e) {
    const i = this._config.items_per_page || this._itemsPerPage, o = this._config.max_pages, a = o ? Number(o) : 0, s = a > 0 ? a : 1 / 0, r = Math.min(Math.ceil(t.length / i), s), h = this._currentPage * i, c = !e && (this._config.auto_swipe_interval || 0) > 0, _ = e ? t.slice(h, h + i) : c ? [...t, ...t] : t, g = this._effectiveListColumns, p = g === 1;
    return n`
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
          class="list ${e ? "paginated" : ""} ${p ? "single-column" : ""}"
          style="--jf-list-columns: ${g}"
        >
          ${_.map((m) => n`
            <jellyha-media-item
                .hass=${this.hass}
                .config=${this._config}
                .item=${m}
                .layout=${"list"}
                .isNextUpHighlight=${this._config.media_type === "next_up" && m.id === this._mostRecentNextUpItemId}
                @jellyha-action=${this._handleItemAction}
            ></jellyha-media-item>
          `)}
        </div>
        ${e && r > 1 ? this._renderPagination(r) : d}
      </div>
    `;
  }
  /**
   * Render grid with optional pagination
   */
  _renderGrid(t, e) {
    const i = this._config.items_per_page || this._itemsPerPage, o = this._config.max_pages, a = o ? Number(o) : 0, s = a > 0 ? a : 1 / 0, r = Math.min(Math.ceil(t.length / i), s), h = this._currentPage * i, c = !e && (this._config.auto_swipe_interval || 0) > 0, _ = e ? t.slice(h, h + i) : c ? [...t, ...t] : t, g = this._config.columns || 1, p = g === 1, m = !e && (this._config.auto_swipe_interval || 0) > 0;
    return n`
      <div class="grid-outer">
        <div 
          class="grid-wrapper"
          @touchstart="${this._handleTouchStart}"
          @touchmove="${this._handleTouchMove}"
          @touchend="${this._handleTouchEnd}"
          @pointerdown="${this._handlePointerDown}"
          @pointermove="${this._handlePointerMove}"
          @pointerup="${this._handlePointerUp}"
          @scroll="${e ? d : this._handleScroll}"
        >
          <div
            class="grid ${e ? "paginated" : ""} ${p ? "auto-columns" : ""} ${m ? "horizontal" : ""}"
            style="--jf-columns: ${g}; --jf-grid-rows: ${g}"
          >
            ${_.map((f) => n`
                <jellyha-media-item
                    .hass=${this.hass}
                    .config=${this._config}
                    .item=${f}
                    .layout=${"grid"}
                    .isNextUpHighlight=${this._config.media_type === "next_up" && f.id === this._mostRecentNextUpItemId}
                    @jellyha-action=${this._handleItemAction}
                ></jellyha-media-item>
            `)}
          </div>
        </div>
        ${e && r > 1 ? this._renderPagination(r) : d}
        ${e ? d : this._renderScrollIndicator()}
      </div>
    `;
  }
  /**
   * Main Pagination Render Dispatcher
   * Decides between standard and smart pagination based on page count
   */
  _renderPagination(t) {
    return this._config.show_pagination_dots === !1 ? n`` : t <= 5 ? this._renderStandardPagination(t) : this._renderSmartPagination(t);
  }
  /**
   * Render Standard Pagination (Existing Logic preserved)
   */
  _renderStandardPagination(t) {
    return n`
      <div class="pagination-dots">
        ${Array.from({ length: t }, (e, i) => n`
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
  _renderSmartPagination(t) {
    const h = -(this._currentPage * 16) + 32;
    return n`
      <div class="pagination-container smart" style="width: ${72}px">
        <div 
          class="pagination-track" 
          style="transform: translateX(${h}px); width: ${t * 16}px"
        >
          ${Array.from({ length: t }, (c, _) => {
      const g = Math.abs(_ - this._currentPage);
      let p = "smart-dot";
      return _ === this._currentPage ? p += " active" : g > 2 ? p += " hidden" : g === 2 && (p += " small"), n`
              <button
                type="button"
                class="${p}"
                data-page="${_}"
                @click="${this._onDotClick}"
                aria-label="${_ === this._currentPage ? `Page ${_ + 1} of ${t}, current page` : `Go to page ${_ + 1} of ${t}`}"
                aria-current="${_ === this._currentPage ? "true" : "false"}"
              ></button>
            `;
    })}
        </div>
      </div>
    `;
  }
  /**
   * Perform configured action
   */
  _performAction(t, e) {
    let i = "none";
    switch (e === "click" ? i = this._config.click_action || "more-info" : e === "hold" ? i = this._config.hold_action || "jellyfin" : e === "double_tap" && (i = this._config.double_tap_action || "none"), i) {
      case "jellyfin":
        this._openExternalUrl(t.jellyfin_url);
        break;
      case "cast":
        this._castMedia(t);
        break;
      case "more-info":
        this._showItemDetails(t);
        break;
      case "trailer":
        t.trailer_url ? this._openExternalUrl(t.trailer_url) : yt(this, "hass-notification", {
          message: l(this.hass.locale?.language || this.hass.language, "no_trailer")
        });
        break;
    }
  }
  async _castMedia(t) {
    const e = this._config.default_cast_device;
    if (!e) {
      console.warn("JellyHA: No default cast device configured");
      return;
    }
    try {
      await this.hass.callService("jellyha", "play_on_chromecast", {
        entity_id: e,
        item_id: t.id,
        server_entity_id: this._config.entity
      });
    } catch (i) {
      console.error("JellyHA: Failed to cast media", i);
    }
  }
  _openExternalUrl(t) {
    if (!t) return;
    const i = this.hass?.states[this._config?.entity]?.attributes?.config_external_url;
    if (i && i.trim() !== "")
      try {
        const o = new URL(t), a = new URL(i);
        o.protocol = a.protocol, o.host = a.host, o.port = a.port || "";
        const s = a.pathname === "/" ? "" : a.pathname;
        s && !o.pathname.startsWith(s) && (o.pathname = s + o.pathname), window.open(o.toString(), "_blank");
        return;
      } catch (o) {
        console.warn("JellyHA: Failed to parse URLs to inject external URL override, falling back to original", o);
      }
    window.open(t, "_blank");
  }
  /**
   * Render empty state
   */
  _renderEmpty() {
    return n`
      <div class="empty">
        <ha-icon icon="mdi:movie-open-outline"></ha-icon>
        <p>${l(this.hass.locale?.language || this.hass.language, "no_media")}</p>
      </div>
    `;
  }
  /**
   * Render error state
   */
  _renderError(t) {
    return n`
      <ha-card>
        <div class="error">
          <ha-icon icon="mdi:alert-circle"></ha-icon>
          <p>${t}</p>
        </div>
      </ha-card>
    `;
  }
  _showItemDetails(t) {
    this._modal && this._modal.showDialog({
      item: t,
      hass: this.hass,
      defaultCastDevice: this._config.default_cast_device,
      serverEntityId: this._config.entity
    });
  }
  _handleSearchInput(t) {
    const e = t.target;
    this._searchQuery = e.value, this._currentPage = 0;
  }
  _handleGenreChange(t) {
    const e = t.target;
    this._searchGenre = e.value, this._currentPage = 0;
  }
  _renderSearchBar(t) {
    const e = /* @__PURE__ */ new Set();
    (this._items || []).forEach((a) => {
      a.genres && a.genres.forEach((s) => e.add(s));
    });
    const i = Array.from(e).sort(), o = this.hass.locale?.language || this.hass.language;
    return n`
      <div class="search-container">
        <div class="search-input-wrapper">
          <ha-icon icon="mdi:magnify" class="search-icon"></ha-icon>
          <input 
            type="text" 
            class="search-input" 
            placeholder="${l(o, "search.placeholder_title")}"
            .value="${this._searchQuery}"
            @input="${this._handleSearchInput}"
          />
          ${this._searchQuery ? n`
            <button class="clear-search" @click="${() => {
      this._searchQuery = "", this._currentPage = 0;
    }}">
              <ha-icon icon="mdi:close"></ha-icon>
            </button>
          ` : d}
        </div>
        
        <div class="search-select-wrapper">
          <select class="search-select" @change="${this._handleGenreChange}" .value="${this._searchGenre}">
             <option value="">${l(o, "search.all_genres")}</option>
             ${i.map((a) => n`
               <option value="${a}">${a}</option>
             `)}
          </select>
          <ha-icon icon="mdi:chevron-down" class="select-icon"></ha-icon>
        </div>
      </div>
    `;
  }
};
w.styles = Ne;
b([
  P({ attribute: !1 })
], w.prototype, "hass", 2);
b([
  u()
], w.prototype, "_config", 2);
b([
  u()
], w.prototype, "_currentPage", 2);
b([
  u()
], w.prototype, "_itemsPerPage", 2);
b([
  u()
], w.prototype, "_pressStartTime", 2);
b([
  u()
], w.prototype, "_holdTimer", 2);
b([
  u()
], w.prototype, "_isHoldActive", 2);
b([
  u()
], w.prototype, "_rewindActive", 2);
b([
  u()
], w.prototype, "_items", 2);
b([
  u()
], w.prototype, "_error", 2);
b([
  u()
], w.prototype, "_lastUpdate", 2);
b([
  u()
], w.prototype, "_mostRecentNextUpItemId", 2);
b([
  u()
], w.prototype, "_searchQuery", 2);
b([
  u()
], w.prototype, "_searchGenre", 2);
b([
  dt("jellyha-item-details-modal")
], w.prototype, "_modal", 2);
b([
  u()
], w.prototype, "_scrollProgress", 2);
b([
  u()
], w.prototype, "_hasScrollableContent", 2);
w = b([
  R("jellyha-library-card")
], w);
var vt = Object.defineProperty, xt = Object.getOwnPropertyDescriptor, fe = (t, e, i, o) => {
  for (var a = o > 1 ? void 0 : o ? xt(e, i) : e, s = t.length - 1, r; s >= 0; s--)
    (r = t[s]) && (a = (o ? r(e, i, a) : r(a)) || a);
  return o && a && vt(e, i, a), a;
};
function $t(t, e, i) {
  const o = new CustomEvent(e, {
    bubbles: !0,
    composed: !0,
    detail: i
  });
  t.dispatchEvent(o);
}
let J = class extends j {
  setConfig(t) {
    this._config = t;
  }
  render() {
    if (!this.hass || !this._config)
      return n``;
    const t = Object.keys(this.hass.states).filter(
      (i) => i.startsWith("sensor.jellyha_now_playing_")
    ), e = this.hass.locale?.language || this.hass.language;
    return n`
      <div class="card-config">
        <div class="form-row">
          <ha-select
            label="${l(e, "editor.now_playing_sensor")}"
            .value=${this._config.entity || ""}
            @selected=${this._entityChanged}
            @closed=${(i) => i.stopPropagation()}
          >
            ${t.map(
      (i) => n`
                <mwc-list-item .value=${i}>
                  ${this.hass.states[i].attributes.friendly_name || i}
                </mwc-list-item>
              `
    )}
          </ha-select>
        </div>

        <div class="form-row">
          <ha-textfield
            label="${l(e, "editor.title")} (Optional)"
            .value=${this._config.title || ""}
            @input=${this._titleChanged}
          ></ha-textfield>
        </div>

        <div class="checkbox-pair">
          <div class="checkbox-row">
            <ha-switch
              .checked=${this._config.show_title !== !1}
              @change=${this._showTitleChanged}
            ></ha-switch>
            <span>${l(e, "editor.show_title")}</span>
          </div>
          <div class="checkbox-row">
            <ha-switch
              .checked=${this._config.show_subtitle !== !1}
              @change=${this._showSubtitleChanged}
            ></ha-switch>
            <span>${l(e, "editor.show_subtitle")}</span>
          </div>
        </div>

        <div class="checkbox-row">
          <ha-switch
            .checked=${this._config.show_media_type_badge !== !1}
            @change=${this._showMediaTypeBadgeChanged}
          ></ha-switch>
          <span>${l(e, "editor.show_media_type_badge")}</span>
        </div>

        <div class="checkbox-pair">
          <div class="checkbox-row">
            <ha-switch
              .checked=${this._config.show_year !== !1}
              @change=${this._showYearChanged}
            ></ha-switch>
            <span>${l(e, "editor.show_year")}</span>
          </div>
          <div class="checkbox-row">
            <ha-switch
              .checked=${this._config.show_genres === !0}
              @change=${this._showGenresChanged}
            ></ha-switch>
            <span>${l(e, "editor.show_genres")}</span>
          </div>
        </div>

        <div class="checkbox-row">
          <ha-switch
            .checked=${this._config.show_runtime === !0}
            @change=${this._showRuntimeChanged}
          ></ha-switch>
          <span>${l(e, "editor.show_runtime")}</span>
        </div>

        <div class="checkbox-row">
          <ha-switch
            .checked=${this._config.show_ratings === !0}
            @change=${this._showRatingsChanged}
          ></ha-switch>
          <span>${l(e, "editor.show_rating")}</span>
        </div>

        <div class="checkbox-pair">
          <div class="checkbox-row">
            <ha-switch
              .checked=${this._config.show_user !== !1}
              @change=${this._showUserChanged}
            ></ha-switch>
            <span>${l(e, "editor.show_user")}</span>
          </div>
          <div class="checkbox-row">
            <ha-switch
              .checked=${this._config.show_client !== !1}
              @change=${this._showClientChanged}
            ></ha-switch>
            <span>${l(e, "editor.show_client")}</span>
          </div>
        </div>

        <div class="checkbox-row">
          <ha-switch
            .checked=${this._config.show_time === !0}
            @change=${this._showTimeChanged}
          ></ha-switch>
          <span>${l(e, "editor.show_time")}</span>
        </div>

        <div class="checkbox-row">
          <ha-switch
            .checked=${this._config.show_background === !0}
            @change=${this._showBackgroundChanged}
          ></ha-switch>
          <span>${l(e, "editor.show_background")}</span>
        </div>

        <div class="checkbox-row">
          <ha-switch
            .checked=${this._config.use_series_image === !0}
            @change=${this._useSeriesImageChanged}
          ></ha-switch>
          <span>${l(e, "editor.use_series_image")}</span>
        </div>
      </div>
    `;
  }
  _entityChanged(t) {
    const e = t.target;
    this._updateConfig("entity", e.value);
  }
  _titleChanged(t) {
    const e = t.target;
    this._updateConfig("title", e.value);
  }
  _showTitleChanged(t) {
    const e = t.target;
    this._updateConfig("show_title", e.checked);
  }
  _showSubtitleChanged(t) {
    const e = t.target;
    this._updateConfig("show_subtitle", e.checked);
  }
  _showMediaTypeBadgeChanged(t) {
    const e = t.target;
    this._updateConfig("show_media_type_badge", e.checked);
  }
  _showYearChanged(t) {
    const e = t.target;
    this._updateConfig("show_year", e.checked);
  }
  _showGenresChanged(t) {
    const e = t.target;
    this._updateConfig("show_genres", e.checked);
  }
  _showRatingsChanged(t) {
    const e = t.target;
    this._updateConfig("show_ratings", e.checked);
  }
  _showRuntimeChanged(t) {
    const e = t.target;
    this._updateConfig("show_runtime", e.checked);
  }
  _showUserChanged(t) {
    const e = t.target;
    this._updateConfig("show_user", e.checked);
  }
  _showClientChanged(t) {
    const e = t.target;
    this._updateConfig("show_client", e.checked);
  }
  _showTimeChanged(t) {
    const e = t.target;
    this._updateConfig("show_time", e.checked);
  }
  _showBackgroundChanged(t) {
    const e = t.target;
    this._updateConfig("show_background", e.checked);
  }
  _useSeriesImageChanged(t) {
    const e = t.target;
    this._updateConfig("use_series_image", e.checked);
  }
  _updateConfig(t, e) {
    if (!this._config)
      return;
    const i = { ...this._config, [t]: e };
    this._config = i, $t(this, "config-changed", { config: i });
  }
};
J.styles = q`
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
fe([
  P({ attribute: !1 })
], J.prototype, "hass", 2);
fe([
  u()
], J.prototype, "_config", 2);
J = fe([
  R("jellyha-now-playing-editor")
], J);
var kt = Object.defineProperty, St = Object.getOwnPropertyDescriptor, A = (t, e, i, o) => {
  for (var a = o > 1 ? void 0 : o ? St(e, i) : e, s = t.length - 1, r; s >= 0; s--)
    (r = t[s]) && (a = (o ? r(e, i, a) : r(a)) || a);
  return o && a && kt(e, i, a), a;
};
window.customCards = window.customCards || [];
window.customCards.push({
  type: "jellyha-now-playing-card",
  name: "JellyHA Now Playing",
  description: "Display currently playing media from Jellyfin",
  preview: !0
});
let $ = class extends j {
  constructor() {
    super(...arguments), this._rewindActive = !1, this._overflowState = 0, this._dominantColor = "var(--primary-color)", this._longPressProgress = 0, this._stopPulse = !1, this._isDragging = !1, this._dragPercentage = 0, this._optimisticSeekPercent = null, this._longPressRaf = null, this._longPressConsumed = !1, this._optimisticFavorites = {}, this._phrases = [];
  }
  setConfig(t) {
    this._config = {
      show_title: !0,
      show_media_type_badge: !0,
      show_year: !0,
      show_client: !0,
      show_user: !0,
      show_time: !1,
      show_background: !0,
      show_genres: !0,
      show_ratings: !0,
      show_runtime: !0,
      use_series_image: !1,
      ...t
    };
  }
  static getConfigElement() {
    return document.createElement("jellyha-now-playing-editor");
  }
  static getStubConfig(t) {
    return {
      entity: Object.keys(t.states).find((o) => o.startsWith("sensor.jellyha_now_playing_")) || "",
      show_title: !0,
      show_media_type_badge: !0,
      show_year: !0,
      show_client: !0,
      show_user: !0,
      show_time: !1,
      show_background: !0,
      show_genres: !0,
      show_ratings: !0,
      show_runtime: !0,
      use_series_image: !1
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
      return n``;
    const t = this._config.entity;
    if (!t)
      return this._renderError("Please configure a JellyHA Now Playing sensor entity");
    const e = this.hass.states[t];
    if (!e)
      return this._renderError(l(this.hass.locale?.language || this.hass.language, "entity_not_found") || "Entity not found");
    const i = e.attributes;
    if (!!!i.item_id)
      return this._renderEmpty();
    const a = this._optimisticSeekPercent !== null ? this._optimisticSeekPercent : i.progress_percent || 0, s = this._config.use_series_image && i.series_image_url ? i.series_image_url : i.image_url, r = i.item_id;
    if (r !== this._cachedItemId) {
      this._cachedItemId = r;
      const K = i.backdrop_url || i.image_url;
      this._cachedBackdropUrl = K ? B(K, 640) : void 0;
    }
    r !== this._cachedColorItemId && s && (this._cachedColorItemId = r, this._extractDominantColor(B(s, 80)));
    const h = this._cachedBackdropUrl, c = this._config.show_background && h, _ = i.is_paused, g = i.media_type?.toLowerCase() === "audio", p = i.media_type?.toLowerCase() || "", f = this._config.show_subtitle !== !1 && (i.artist_name || i.series_title) || "", x = this._config.show_year !== !1 && i.year ? String(i.year) : "", E = this._config.show_genres && i.genres?.length ? i.genres.slice(0, 2).join(", ") : "", C = [x, E].filter(Boolean).join(" • "), I = this._config.show_user !== !1 && i.user_name || "", L = this._config.show_client !== !1 && i.client || "", Z = p === "episode" && i.season !== void 0 && i.episode !== void 0 ? `S${String(i.season).padStart(2, "0")}E${String(i.episode).padStart(2, "0")}` : i.media_type || "", re = i.item_id && this._optimisticFavorites[i.item_id] !== void 0 ? this._optimisticFavorites[i.item_id] : i.is_favorite || !1, we = 125.66, Ue = we * (1 - this._longPressProgress);
    return n`
            <ha-card class="jellyha-now-playing ${c ? "has-background" : ""} ${this._config.title ? "has-title" : ""}" style="--card-dominant-color: ${this._dominantColor};">
                ${c ? n`
                    <div class="card-background" style="background-image: url('${h}')"></div>
                    <div class="card-overlay"></div>
                ` : d}
                
                <div class="card-content">
                    ${this._config.title ? n`
                        <div class="card-header">${this._config.title}</div>
                    ` : d}
                    
                    <div class="main-container">
                        ${s ? n`
                            <div class="poster-container" @click=${this._handlePosterRewind}>
                                <img src="${B(s, 160)}" alt="${i.title}" loading="eager" fetchpriority="high" />
                                
                                ${this._config.show_media_type_badge !== !1 && Z ? n`
                                    <span class="poster-badge media-type-badge ${p}">${Z}</span>
                                ` : d}
                                ${this._config.show_ratings && i.community_rating ? n`
                                    <span class="poster-badge rating-badge">
                                        <ha-icon icon="mdi:star"></ha-icon>
                                        ${i.community_rating.toFixed(1)}
                                    </span>
                                ` : d}
                                ${this._config.show_runtime && i.runtime_minutes ? n`
                                    <span class="poster-badge runtime-badge">
                                        <ha-icon icon="mdi:clock-outline"></ha-icon>
                                        ${p === "audio" && i.duration_ticks ? `${Math.floor(i.duration_ticks / 1e7 / 60)}m ${Math.floor(i.duration_ticks / 1e7 % 60)}s` : de(i.runtime_minutes)}
                                    </span>
                                ` : d}

                                ${this._rewindActive ? n`
                                    <div class="rewind-overlay">
                                        <span>${l(this.hass.locale?.language || this.hass.language, "rewinding")}</span>
                                    </div>
                                ` : d}
                            </div>
                        ` : d}
                        
                        <div class="info-container">
                            <div class="info-top">
                                <div class="header">
                                    ${this._config.show_title !== !1 ? n`<div class="title">${i.title}</div>` : d}
                                    ${f ? n`<div class="subtitle">${f}</div>` : d}
                                    ${this._overflowState < 1 && C ? n`<div class="meta-line">${C}</div>` : d}
                                    ${this._overflowState < 1 && (I || L) ? n`<div class="client-line">${I ? n`<strong>${I}</strong>` : d}${I && L ? " " : ""}${L || d}</div>` : d}
                                </div>
                            </div>

                            <div class="info-bottom">
                                <div class="playback-controls">
                                    ${g ? n`
                                        <ha-icon-button class="music-subtle-btn ${re ? "active" : ""}" .label=${"Favorite"} @click=${() => this._handleFavoriteToggle(i.item_id, re)}>
                                            <ha-icon icon="${re ? "mdi:heart" : "mdi:heart-outline"}"></ha-icon>
                                        </ha-icon-button>
                                        <ha-icon-button .label=${l(this.hass.locale?.language || this.hass.language, "previous") || "Previous"} @click=${() => this._handleControl("PreviousTrack")}>
                                            <ha-icon icon="mdi:skip-previous"></ha-icon>
                                        </ha-icon-button>
                                    ` : n`
                                        <ha-icon-button class="seek-btn" .label=${"Rewind 10s"} @click=${() => this._handleSeekRelative(-10)}>
                                            <ha-icon icon="mdi:rewind-10"></ha-icon>
                                        </ha-icon-button>
                                    `}

                                    <div class="play-pause-wrapper ${this._stopPulse ? "stop-pulse" : ""}"
                                        @pointerdown=${this._startLongPress}
                                        @pointerup=${this._endLongPress}
                                        @pointerleave=${this._endLongPress}
                                        @contextmenu=${(K) => K.preventDefault()}
                                    >
                                        ${this._rewindActive ? n`
                                            <ha-icon-button class="play-pause-btn spinning" .label=${l(this.hass.locale?.language || this.hass.language, "loading")}>
                                                <ha-icon icon="mdi:loading"></ha-icon>
                                            </ha-icon-button>
                                        ` : _ ? n`
                                            <ha-icon-button class="play-pause-btn" .label=${l(this.hass.locale?.language || this.hass.language, "play")} @click=${() => {
      if (this._longPressConsumed) {
        this._longPressConsumed = !1;
        return;
      }
      this._handleControl(g ? "PlayPause" : "Unpause");
    }}>
                                                <ha-icon icon="mdi:play"></ha-icon>
                                            </ha-icon-button>
                                        ` : n`
                                            <ha-icon-button class="play-pause-btn" .label=${l(this.hass.locale?.language || this.hass.language, "pause")} @click=${() => {
      if (this._longPressConsumed) {
        this._longPressConsumed = !1;
        return;
      }
      this._handleControl("Pause");
    }}>
                                                <ha-icon icon="mdi:pause"></ha-icon>
                                            </ha-icon-button>
                                        `}
                                        ${this._longPressProgress > 0 ? n`
                                            <svg class="stop-ring" viewBox="0 0 44 44">
                                                <circle cx="22" cy="22" r="20"
                                                    stroke="#ef4444" stroke-width="3" fill="none"
                                                    stroke-dasharray="${we}"
                                                    stroke-dashoffset="${Ue}"
                                                    stroke-linecap="round"
                                                    transform="rotate(-90 22 22)" />
                                            </svg>
                                        ` : d}
                                    </div>

                                    ${g ? n`
                                        <ha-icon-button .label=${l(this.hass.locale?.language || this.hass.language, "next") || "Next"} @click=${() => this._handleControl("NextTrack")}>
                                            <ha-icon icon="mdi:skip-next"></ha-icon>
                                        </ha-icon-button>
                                        <ha-icon-button class="music-subtle-btn ${i.repeat_mode && i.repeat_mode !== "RepeatNone" ? "active" : ""}" .label=${"Repeat"} @click=${() => this._handleRepeatMode(i.session_id, i.repeat_mode || "RepeatNone")}>
                                            <ha-icon icon="${i.repeat_mode === "RepeatOne" ? "mdi:repeat-once" : "mdi:repeat"}"></ha-icon>
                                        </ha-icon-button>
                                    ` : n`
                                        <ha-icon-button class="seek-btn" .label=${"Forward 30s"} @click=${() => this._handleSeekRelative(30)}>
                                            <ha-icon icon="mdi:fast-forward-30"></ha-icon>
                                        </ha-icon-button>
                                    `}
                                </div>

                                <div class="progress-container"
                                    @pointerdown=${this._startDrag}
                                    @pointermove=${this._handleDrag}
                                    @pointerup=${this._endDrag}
                                    @pointercancel=${this._cancelDrag}
                                >
                                    <div class="progress-bar">
                                        <div class="progress-fill" style="width: ${this._isDragging ? this._dragPercentage : a}%; transition: ${this._isDragging ? "none" : "width 1s linear"}; background: ${this._dominantColor}"></div>
                                        <div class="seek-handle" style="left: ${this._isDragging ? this._dragPercentage : a}%; transition: ${this._isDragging ? "none" : "left 1s linear"}; transform: translate(-50%, -50%) ${this._isDragging ? "scale(1.3)" : "scale(1)"}; background: ${this._dominantColor}"></div>
                                    </div>
                                </div>

                                ${this._config.show_time && i.duration_ticks ? n`
                                    <div class="timestamps">
                                        <span class="time-elapsed">${this._formatTicks(i.position_ticks || 0)}</span>
                                        <span class="time-remaining">${this._formatTicks(-((i.duration_ticks || 0) - (i.position_ticks || 0)))}</span>
                                    </div>
                                ` : d}
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
        const t = await fetch("/jellyha_static/phrases.json");
        t.ok && (this._phrases = await t.json());
      } catch (t) {
        console.warn("JellyHA: Could not fetch phrases.json", t);
      }
  }
  _renderEmpty() {
    this._fetchPhrases();
    const e = this.hass.themes?.darkMode ? "https://raw.githubusercontent.com/home-assistant/brands/master/custom_integrations/jellyha/dark_logo.png" : "https://raw.githubusercontent.com/home-assistant/brands/master/custom_integrations/jellyha/logo.png", i = "https://raw.githubusercontent.com/home-assistant/brands/master/custom_integrations/jellyha/icon.png";
    let o = l(this.hass.locale?.language || this.hass.language, "nothing_playing");
    if (this._phrases.length > 0) {
      const s = Math.floor(Date.now() / 864e5) % this._phrases.length;
      o = this._phrases[s];
      const r = Object.keys(this.hass.states).find((c) => c.startsWith("sensor.") && c.endsWith("_unwatched")), h = r ? this.hass.states[r].state : "0";
      o = o.replace(/\[number\]/g, h);
    }
    return n`
            <ha-card class="jellyha-now-playing empty-state">
                <div class="card-content">
                    <div class="logo-container full-logo">
                        <img src="${e}" alt="JellyHA Logo" />
                    </div>
                    <div class="logo-container mini-icon">
                        <img src="${i}" alt="JellyHA Icon" />
                    </div>
                    <p>${o}</p>
                </div>
            </ha-card>
        `;
  }
  _renderError(t) {
    return n`
            <ha-card class="error-state">
                <div class="card-content">
                    <p>${t}</p>
                </div>
            </ha-card>
        `;
  }
  async _handleControl(t) {
    this._haptic("light");
    const i = this.hass.states[this._config.entity]?.attributes.session_id;
    i && await this.hass.callService("jellyha", "session_control", {
      entity_id: this._config.entity,
      session_id: i,
      command: t
    });
  }
  async _handleRepeatMode(t, e) {
    let i = "RepeatAll";
    e === "RepeatAll" ? i = "RepeatOne" : e === "RepeatOne" && (i = "RepeatNone"), await this.hass.callService("jellyha", "session_general_command", {
      entity_id: this._config.entity,
      session_id: t,
      command: "SetRepeatMode",
      arguments: { RepeatMode: i }
    });
  }
  _haptic(t = "selection") {
    const e = new CustomEvent("haptic", {
      detail: t,
      bubbles: !0,
      composed: !0
    });
    this.dispatchEvent(e);
  }
  async _handleFavoriteToggle(t, e) {
    this._haptic();
    const i = !e;
    this._optimisticFavorites[t] = i, this.requestUpdate(), await this.hass.callService("jellyha", "update_favorite", {
      entity_id: this._config.entity,
      item_id: t,
      is_favorite: i
    });
  }
  _getDragPercent(t) {
    const i = t.currentTarget.getBoundingClientRect();
    let o = t.clientX - i.left;
    return o < 10 && (o = 0), o > i.width - 10 && (o = i.width), Math.max(0, Math.min(100, o / i.width * 100));
  }
  _startDrag(t) {
    t.currentTarget.setPointerCapture(t.pointerId), this._isDragging = !0, this._dragPercentage = this._getDragPercent(t), this._haptic("light");
  }
  _handleDrag(t) {
    this._isDragging && (this._dragPercentage = this._getDragPercent(t));
  }
  _cancelDrag(t) {
    if (!this._isDragging) return;
    t.currentTarget.releasePointerCapture(t.pointerId), this._isDragging = !1;
  }
  async _endDrag(t) {
    if (!this._isDragging) return;
    t.currentTarget.releasePointerCapture(t.pointerId), this._isDragging = !1;
    const i = this._getDragPercent(t);
    this._setOptimisticSeek(i);
    const o = this.hass.states[this._config.entity];
    if (!o) return;
    const a = o.attributes, s = a.session_id, r = a.duration_ticks;
    if (!s || !r) return;
    const h = Math.round(r * (i / 100));
    await this.hass.callService("jellyha", "session_seek", {
      entity_id: this._config.entity,
      session_id: s,
      position_ticks: h
    });
  }
  _setOptimisticSeek(t) {
    this._optimisticSeekTimer && clearTimeout(this._optimisticSeekTimer), this._optimisticSeekPercent = t, this._optimisticSeekTimer = window.setTimeout(() => {
      this._optimisticSeekPercent = null;
    }, 3e3);
  }
  async _handleSeekRelative(t) {
    this._haptic("light");
    const e = this.hass.states[this._config.entity];
    if (!e) return;
    const i = e.attributes, o = i.session_id, a = i.position_ticks || 0;
    if (!o) return;
    const s = t * 1e7, r = Math.max(0, a + s), h = i.duration_ticks;
    h && this._setOptimisticSeek(r / h * 100), await this.hass.callService("jellyha", "session_seek", {
      entity_id: this._config.entity,
      session_id: o,
      position_ticks: r
    });
  }
  async _handlePosterRewind() {
    const t = this.hass.states[this._config.entity];
    if (!t) return;
    const e = t.attributes, i = e.session_id, o = e.position_ticks || 0;
    if (!i) return;
    this._rewindActive = !0, setTimeout(() => {
      this._rewindActive = !1;
    }, 1e3), this._haptic("selection");
    const a = 20 * 1e7, s = Math.max(0, o - a), r = e.duration_ticks;
    r && this._setOptimisticSeek(s / r * 100), await this.hass.callService("jellyha", "session_seek", {
      entity_id: this._config.entity,
      session_id: i,
      position_ticks: s
    });
  }
  _startLongPress() {
    const t = Date.now(), e = 800;
    this._haptic("selection");
    const i = () => {
      const o = Date.now() - t;
      if (this._longPressProgress = Math.min(o / e, 1), this._longPressProgress >= 1) {
        this._longPressConsumed = !0, this._handleControl("Stop"), this._haptic("success"), navigator.vibrate && navigator.vibrate(50), this._stopPulse = !0, setTimeout(() => {
          this._stopPulse = !1;
        }, 600), this._endLongPress();
        return;
      }
      this._longPressRaf = requestAnimationFrame(i);
    };
    this._longPressRaf = requestAnimationFrame(i);
  }
  _endLongPress() {
    this._longPressRaf && (cancelAnimationFrame(this._longPressRaf), this._longPressRaf = null), this._longPressProgress = 0;
  }
  _extractDominantColor(t) {
    const e = new Image();
    e.crossOrigin = "anonymous", e.onload = () => {
      try {
        const i = document.createElement("canvas");
        i.width = 50, i.height = 50;
        const o = i.getContext("2d");
        if (!o) return;
        o.drawImage(e, 0, 0, 50, 50);
        const a = o.getImageData(0, 0, 50, 50).data;
        let s = 0, r = 0, h = 0, c = 0;
        for (let _ = 0; _ < a.length; _ += 16) {
          const g = a[_], p = a[_ + 1], m = a[_ + 2], f = Math.max(g, p, m), x = Math.min(g, p, m), E = f === 0 ? 0 : (f - x) / f, C = f / 255;
          E > c && C > 0.15 && C < 0.95 && (c = E, s = g, r = p, h = m);
        }
        if (c > 0.1) {
          const _ = s / 255, g = r / 255, p = h / 255, m = Math.max(_, g, p), f = Math.min(_, g, p);
          let x = 0;
          const E = (m + f) / 2, C = m - f, I = C === 0 ? 0 : C / (1 - Math.abs(2 * E - 1));
          C !== 0 && (m === _ ? x = ((g - p) / C + (g < p ? 6 : 0)) * 60 : m === g ? x = ((p - _) / C + 2) * 60 : x = ((_ - g) / C + 4) * 60);
          const L = Math.max(E * 100, 70), Z = Math.max(I * 100, 60);
          this._dominantColor = `hsl(${Math.round(x)}, ${Math.round(Z)}%, ${Math.round(L)}%)`;
        } else
          this._dominantColor = "var(--primary-color)";
      } catch {
        this._dominantColor = "var(--primary-color)";
      }
    }, e.onerror = () => {
      this._dominantColor = "var(--primary-color)";
    }, e.src = t;
  }
  connectedCallback() {
    super.connectedCallback(), this._resizeObserver = new ResizeObserver(() => {
      this._checkLayout();
    }), this._resizeObserver.observe(this);
  }
  disconnectedCallback() {
    super.disconnectedCallback(), this._resizeObserver && this._resizeObserver.disconnect(), this._endLongPress();
  }
  updated(t) {
    super.updated(t), t.has("hass") && this._checkLayout();
  }
  _checkLayout() {
    requestAnimationFrame(() => {
      this._doLayoutCheck();
    });
  }
  _doLayoutCheck() {
    const t = this.shadowRoot?.querySelector(".title"), e = this.shadowRoot?.querySelector(".info-bottom");
    if (!t || !e) return;
    const i = this.getBoundingClientRect(), o = t.getBoundingClientRect(), r = e.getBoundingClientRect().top - i.top - 8, h = 20, c = 18, g = o.bottom - i.top + 22, m = g + h + c;
    let f = 0;
    m > r && (f = 1), g > r && (f = 2), this._overflowState !== f && (this._overflowState = f);
  }
  _formatTicks(t) {
    const e = t < 0, i = Math.floor(Math.abs(t) / 1e7), o = Math.floor(i / 3600), a = Math.floor(i % 3600 / 60), s = i % 60, r = e ? "-" : "";
    return o > 0 ? `${r}${o}:${String(a).padStart(2, "0")}:${String(s).padStart(2, "0")}` : `${r}${a}:${String(s).padStart(2, "0")}`;
  }
};
$.styles = q`
        :host {
            display: block;
            height: 100%;
            width: 100%;
            background: none !important;
            position: relative;
            z-index: 2;
        }
        ha-card {
            height: 100%;
            overflow: hidden;
            position: relative;
            background: var(--ha-card-background, var(--card-background-color, #fff));
            border-radius: var(--ha-card-border-radius, 12px);
            box-shadow: var(--ha-card-box-shadow, none);
            border: var(--ha-card-border, 1px solid var(--ha-card-border-color, var(--divider-color, #e0e0e0)));
            transition: all 0.3s ease-out;
            container-type: size;
            container-name: now-playing;
            display: flex;
            flex-direction: column;
            box-sizing: border-box;
            min-height: 0;
            padding: 0;
            width: 100%;
            margin: 0;
        }

        .jellyha-now-playing.has-background {
            background: transparent;
            color: white;
        }
        .jellyha-now-playing.has-background .meta-line,
        .jellyha-now-playing.has-background .client-line,
        .jellyha-now-playing.has-background .time-elapsed,
        .jellyha-now-playing.has-background .time-remaining,
        .jellyha-now-playing.has-background .card-header,
        .jellyha-now-playing.has-background ha-icon-button:not(.music-subtle-btn) {
            color: #fff !important;
            text-shadow: 0 1px 4px rgba(0,0,0,0.5);
        }
        .jellyha-now-playing.has-background .poster-badge {
            box-shadow: 0 2px 4px rgba(0,0,0,0.3);
        }
        .jellyha-now-playing.has-background .playback-controls ha-icon-button {
            background: rgba(255, 255, 255, 0.15);
        }
        .jellyha-now-playing.has-background .playback-controls ha-icon-button:hover {
            background: rgba(255, 255, 255, 0.25);
        }
        .jellyha-now-playing.has-background .card-content {
            padding: 18px 20px 14px !important;
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
            overflow: visible;
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
            min-height: 0;
            overflow: visible;
        }

        /* --- Poster with overlay badges --- */
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

        /* Poster overlay badges — matches Library Card style */
        .poster-badge {
            position: absolute;
            border-radius: 4px;
            color: #fff;
            z-index: 5;
            pointer-events: none;
            white-space: nowrap;
        }
        .media-type-badge {
            top: 6px;
            left: 6px;
            padding: 2px 8px 1px 8px;
            font-size: 0.8rem;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.3px;
            background: var(--primary-color);
            box-shadow: 0 2px 4px rgba(0,0,0,0.3);
        }
        .media-type-badge.movie { background-color: #AA5CC3; }
        .media-type-badge.series { background-color: #F2A218; }
        .media-type-badge.episode { background-color: #F59E0B; }
        .media-type-badge.audio { background-color: #10B981; }

        .rating-badge {
            bottom: 6px;
            right: 6px;
            display: inline-flex;
            align-items: center;
            gap: 2px;
            background: rgba(0, 0, 0, 0.6);
            color: #F59E0B;
            padding: var(--short-badge-padding, 3px 6px);
            font-weight: 600;
            font-size: 0.8rem;
        }
        .rating-badge ha-icon {
            --mdc-icon-size: 13px;
            color: #F59E0B;
            margin-top: -1px;
        }
        .runtime-badge {
            bottom: 6px;
            left: 6px;
            display: inline-flex;
            align-items: center;
            gap: 2px;
            background: rgba(0, 0, 0, 0.6);
            color: rgba(255, 255, 255, 0.85);
            padding: var(--short-badge-padding, 3px 6px);
            font-weight: 600;
            font-size: 0.8rem;
        }
        .runtime-badge ha-icon {
            --mdc-icon-size: 12px;
            color: rgba(255, 255, 255, 0.85);
            margin-top: -1px;
        }

        /* Rewind overlay */
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
            color: rgba(255, 255, 255, 0.95);
            font-weight: 700;
            font-size: 0.8rem;
            line-height: 1;
            letter-spacing: 0.5px;
            background: rgba(255, 255, 255, 0.15);
            backdrop-filter: blur(4px);
            -webkit-backdrop-filter: blur(4px);
            padding: 7px 10px 5px;
            border-radius: 20px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.2);
            white-space: nowrap;
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

        /* --- Info container --- */
        .info-container {
            flex: 1;
            display: flex;
            flex-direction: column;
            height: 100%;
            min-height: 0;
            min-width: 0;
            overflow: visible;
        }
        .info-top {
            flex: 1 1 auto;
            min-height: 0;
            overflow: visible;
            display: flex;
            flex-direction: column;
            margin-bottom: 0;
            padding-bottom: 4px;
        }
        .header {
            margin-bottom: 0px;
            flex-shrink: 0;
        }

        /* 4-line text structure */
        .title {
            font-size: 1.3rem;
            font-weight: 700;
            line-height: 1.2;
            color: var(--card-dominant-color, var(--primary-text-color));
            margin-top: 6px;
            margin-bottom: 2px;
            overflow: hidden;
        }
        .subtitle {
            font-size: 1.05rem;
            color: var(--card-dominant-color, var(--secondary-text-color));
            font-weight: 400;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            margin-bottom: 6px;
        }
        .meta-line {
            font-size: 0.85rem;
            color: var(--secondary-text-color);
            opacity: 0.8;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            margin-bottom: 1px;
            margin-top: 5px;
        }
        .client-line {
            font-size: 0.75rem;
            color: var(--secondary-text-color);
            opacity: 0.4;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        /* --- Info Bottom: Controls + Progress --- */
        .info-bottom {
            flex: 0 0 auto;
            width: 100%;
            margin-top: auto;
            z-index: 5;
        }

        /* Playback controls (centered) */
        .playback-controls {
            display: flex;
            gap: 8px;
            align-items: center;
            justify-content: center;
            margin-bottom: 6px;
        }
        .playback-controls ha-icon-button:not(.music-subtle-btn) {
            --mdc-icon-button-size: 36px;
            --mdc-icon-size: 22px;
            color: var(--primary-text-color);
            background: rgba(var(--rgb-primary-text-color), 0.05);
            border-radius: 50%;
            transition: background 0.2s;
        }
        .playback-controls ha-icon-button:not(.music-subtle-btn):hover {
            background: rgba(var(--rgb-primary-text-color), 0.1);
        }
        .playback-controls ha-icon-button ha-icon {
            display: flex;
            align-items: center;
            justify-content: center;
        }

        /* Play/Pause button slightly larger */
        .play-pause-wrapper {
            position: relative;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .play-pause-btn {
            --mdc-icon-button-size: 44px !important;
            --mdc-icon-size: 30px !important;
        }

        /* Stop ring SVG */
        .stop-ring {
            position: absolute;
            top: 50%;
            left: 50%;
            width: 44px;
            height: 44px;
            transform: translate(-50%, -50%);
            pointer-events: none;
            z-index: 10;
        }

        /* Subtle music controls (shuffle/repeat) */
        .music-subtle-btn {
            --mdc-icon-button-size: 36px !important;
            --mdc-icon-size: 20px !important;
            opacity: 0.35;
            background: transparent !important;
            border-radius: 50%;
            transition: opacity 0.2s, color 0.2s;
        }
        .music-subtle-btn:hover {
            opacity: 0.7;
        }
        .music-subtle-btn.active {
            color: var(--card-dominant-color, var(--primary-color)) !important;
            opacity: 1 !important;
            background: transparent !important;
        }

        /* Stop confirmed pulse animation */
        .play-pause-wrapper.stop-pulse {
            animation: stopPulse 0.5s ease-out;
            border-radius: 50%;
        }
        @keyframes stopPulse {
            0% { transform: scale(1); box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.5); }
            50% { transform: scale(1.15); box-shadow: 0 0 0 12px rgba(239, 68, 68, 0); }
            100% { transform: scale(1); box-shadow: 0 0 0 0 rgba(239, 68, 68, 0); }
        }

        /* --- Progress bar with seek handle --- */
        .progress-container {
            cursor: pointer;
            position: relative;
            width: 100%;
            padding: 4px 0;
            box-sizing: border-box;
            touch-action: none;
        }
        .progress-bar {
            height: 6px;
            background: rgba(var(--rgb-primary-text-color), 0.12);
            border-radius: 0;
            overflow: visible;
            position: relative;
            backdrop-filter: blur(8px);
            -webkit-backdrop-filter: blur(8px);
        }
        .has-background .progress-bar {
            background: rgba(255, 255, 255, 0.15);
        }
        .progress-fill {
            height: 100%;
            border-radius: 0;
            transition: background-color 0.5s ease;
            background: var(--card-dominant-color, var(--primary-color));
            opacity: 0.65;
        }
        .seek-handle {
            position: absolute;
            top: 50%;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            transform: translate(-50%, -50%);
            background: var(--card-dominant-color, var(--primary-color));
            box-shadow: 0 0 4px rgba(0,0,0,0.3);
            pointer-events: none;
            transition: background-color 0.5s ease, transform 0.2s ease;
        }

        /* --- Timestamps below progress bar --- */
        .timestamps {
            display: flex;
            justify-content: space-between;
            margin-top: 2px;
            padding: 0;
        }
        .time-elapsed,
        .time-remaining {
            font-size: 0.75rem;
            color: var(--secondary-text-color);
            opacity: 0.85;
            font-variant-numeric: tabular-nums;
            white-space: nowrap;
        }

        /* --- Empty & Error states --- */
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


        /* Compact empty state */
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

        /* Hide meta/client lines when narrow */
        @container now-playing (max-width: 320px) {
            .meta-line, .client-line {
                display: none !important;
            }
            .title {
                font-size: 1.25rem;
                margin-bottom: 2px;
            }
        }

        /* Adjust layout when very narrow */
        @container now-playing (max-width: 280px) {
            .main-container {
                gap: 12px;
            }
            .title {
                font-size: 1.1rem;
                display: -webkit-box;
                -webkit-line-clamp: 2;
                -webkit-box-orient: vertical;
                overflow: hidden;
                white-space: normal;
            }
        }

        /* Very short cards: hide extra text */
        @container now-playing (max-height: 195px) {
            .meta-line, .client-line {
                display: none !important;
            }
            .card-header {
                display: none !important;
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
            .poster-container {
                --short-badge-padding: 1px !important;
            }
        }

        /* Ultra-Compact Micro Mode (Overlay controls on poster) */
        @container now-playing (max-width: 350px) {
            .card-header {
                display: none !important;
            }
            .poster-badge {
                display: none !important;
            }
            .info-top {
                display: flex !important;
                padding: 0 !important;
                margin: 0 !important;
            }
            .info-top .meta-line, .info-top .client-line {
                display: none !important;
            }
            .info-top .title {
                font-size: 1.10rem !important;
                line-height: 1.1;
                margin-bottom: 2px !important;
                color: var(--card-dominant-color, white) !important;
                text-shadow: 0 1px 3px rgba(0,0,0,0.8) !important;
                overflow: hidden;
                display: -webkit-box;
                -webkit-line-clamp: 2;
                -webkit-box-orient: vertical;
                white-space: normal !important;
            }
            .info-top .subtitle {
                font-size: 0.95rem !important;
                color: var(--card-dominant-color, rgba(255, 255, 255, 0.8)) !important;
                text-shadow: 0 1px 3px rgba(0,0,0,0.8) !important;
                margin-bottom: 0 !important;
                overflow: hidden;
                white-space: nowrap !important;
                text-overflow: ellipsis !important;
                opacity: 0.9;
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
                width: max-content;
                margin: 0 auto;
                border-radius: 8px;
                transition: transform 0.2s ease-in-out;
            }
            .main-container:hover {
                transform: scale(1.02);
            }
            .poster-container {
                flex: 0 0 auto !important;
                height: 100% !important;
                aspect-ratio: 2 / 3;
                box-shadow: 0 4px 12px rgba(0,0,0,0.5);
            }
            .poster-container:hover {
                transform: none;
            }
            .info-container {
                position: absolute;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                transform: none;
                background: linear-gradient(to bottom, rgba(0,0,0,0.7) 0%, rgba(0,0,0,0.2) 20%, transparent 50%, rgba(0,0,0,0.2) 80%, rgba(0,0,0,0.7) 100%);
                display: flex;
                flex-direction: column;
                justify-content: space-between;
                border-radius: 8px;
                padding: 12px 10px 4px 10px;
                box-sizing: border-box;
                pointer-events: none;
                z-index: 5;
                overflow: visible;
            }
            .info-bottom {
                pointer-events: auto;
                flex: 0 0 auto;
            }
            .playback-controls {
                margin-bottom: 4px;
            }
            .playback-controls ha-icon-button:not(.music-subtle-btn) {
                --mdc-icon-button-size: 36px;
                --mdc-icon-size: 24px;
                background: rgba(255, 255, 255, 0.25) !important;
                color: white !important;
            }
            .playback-controls ha-icon-button:not(.music-subtle-btn):hover {
                background: rgba(255, 255, 255, 0.4) !important;
            }
            .playback-controls .play-pause-btn {
                background: rgba(255, 255, 255, 0.25) !important;
            }
            .playback-controls .play-pause-btn:hover {
                background: rgba(255, 255, 255, 0.4) !important;
            }
            .progress-container {
                padding: 0;
            }
            .progress-bar {
                height: 5px; /* Thicker bar */
                border-radius: 2.5px;
            }
            .seek-handle {
                width: 10px;
                height: 10px;
            }
            .timestamps {
                margin-top: 2px;
                padding: 0;
                justify-content: space-between !important;
            }
            .time-elapsed,
            .time-remaining {
                color: rgba(255, 255, 255, 0.8);
                text-shadow: 0 1px 3px rgba(0,0,0,0.5);
                font-size: 0.7rem;
            }
            .rewind-overlay span {
                font-size: 0.75rem !important;
                line-height: 1 !important;
                padding: 5px 8px 4px !important;
                white-space: nowrap;
            }
        }

        /* Height-Based Compact Mode */
        @container now-playing (max-height: 180px) {
            .card-header {
                display: none !important;
            }
            .poster-badge {
                display: none !important;
            }
            .info-top {
                display: flex !important;
                padding: 0 !important;
                margin: 0 !important;
            }
            .info-top .meta-line, .info-top .client-line {
                display: none !important;
            }
            .info-top .title {
                font-size: 1.25rem !important;
                line-height: 1.1;
                margin-bottom: 2px !important;
                color: var(--card-dominant-color, white) !important;
                text-shadow: 0 1px 3px rgba(0,0,0,0.8) !important;
                overflow: hidden;
                display: -webkit-box;
                -webkit-line-clamp: 2;
                -webkit-box-orient: vertical;
                white-space: normal !important;
            }
            .info-top .subtitle {
                font-size: 0.95rem !important;
                color: var(--card-dominant-color, rgba(255, 255, 255, 0.8)) !important;
                text-shadow: 0 1px 3px rgba(0,0,0,0.8) !important;
                margin-bottom: 0 !important;
                overflow: hidden;
                white-space: nowrap !important;
                text-overflow: ellipsis !important;
                opacity: 0.9;
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
                width: max-content;
                margin: 0 auto;
                border-radius: 8px;
                transition: transform 0.2s ease-in-out;
            }
            .main-container:hover {
                transform: scale(1.02);
            }
            .poster-container {
                flex: 0 0 auto !important;
                height: 100% !important;
                aspect-ratio: 2 / 3;
                box-shadow: 0 4px 12px rgba(0,0,0,0.5);
            }
            .poster-container:hover {
                transform: none;
            }
            .info-container {
                position: absolute;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                transform: none;
                background: linear-gradient(to bottom, rgba(0,0,0,0.7) 0%, rgba(0,0,0,0.2) 20%, transparent 50%, rgba(0,0,0,0.2) 80%, rgba(0,0,0,0.7) 100%);
                display: flex;
                flex-direction: column;
                justify-content: space-between;
                border-radius: 8px;
                padding: 12px 10px 4px 10px;
                box-sizing: border-box;
                pointer-events: none;
                z-index: 5;
                overflow: visible;
            }
            .info-bottom {
                pointer-events: auto;
                flex: 0 0 auto;
            }
            .playback-controls {
                margin-bottom: 4px;
            }
            .playback-controls ha-icon-button:not(.music-subtle-btn) {
                --mdc-icon-button-size: 36px;
                --mdc-icon-size: 24px;
                background: rgba(255, 255, 255, 0.25) !important;
                color: white !important;
            }
            .playback-controls ha-icon-button:not(.music-subtle-btn):hover {
                background: rgba(255, 255, 255, 0.4) !important;
            }
            .playback-controls .play-pause-btn {
                background: rgba(255, 255, 255, 0.25) !important;
            }
            .playback-controls .play-pause-btn:hover {
                background: rgba(255, 255, 255, 0.4) !important;
            }
            .progress-container {
                padding: 0 4px;
            }
            .progress-bar {
                height: 5px;
                border-radius: 2.5px;
            }
            .seek-handle {
                width: 10px;
                height: 10px;
            }
            .timestamps {
                margin-top: 2px;
                padding: 0 4px;
                justify-content: space-between !important;
            }
            .time-elapsed,
            .time-remaining {
                color: rgba(255, 255, 255, 0.8);
                text-shadow: 0 1px 3px rgba(0,0,0,0.5);
                font-size: 0.7rem;
            }
            .rewind-overlay span {
                font-size: 0.75rem !important;
                line-height: 1 !important;
                padding: 5px 8px 4px !important;
                white-space: nowrap;
            }
        }

        /* Tall but Narrow Mode */
        @container now-playing (min-height: 240px) and (max-width: 400px) {
            .card-header {
                display: none !important;
            }
            .poster-badge {
                display: none !important;
            }
            .info-top {
                display: flex !important;
                padding: 0 !important;
                margin: 0 !important;
            }
            .info-top .meta-line, .info-top .client-line {
                display: none !important;
            }
            .info-top .title {
                font-size: 1.25rem !important;
                line-height: 1.1;
                margin-bottom: 2px !important;
                color: var(--card-dominant-color, white) !important;
                text-shadow: 0 1px 3px rgba(0,0,0,0.8) !important;
                overflow: hidden;
                display: -webkit-box;
                -webkit-line-clamp: 2;
                -webkit-box-orient: vertical;
                white-space: normal !important;
            }
            .info-top .subtitle {
                font-size: 0.95rem !important;
                color: var(--card-dominant-color, rgba(255, 255, 255, 0.8)) !important;
                text-shadow: 0 1px 3px rgba(0,0,0,0.8) !important;
                margin-bottom: 0 !important;
                overflow: hidden;
                white-space: nowrap !important;
                text-overflow: ellipsis !important;
                opacity: 0.9;
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
                width: max-content;
                margin: 0 auto;
                border-radius: 8px;
                transition: transform 0.2s ease-in-out;
            }
            .main-container:hover {
                transform: scale(1.02);
            }
            .poster-container {
                flex: 0 0 auto !important;
                height: 100% !important;
                aspect-ratio: 2 / 3;
                box-shadow: 0 4px 12px rgba(0,0,0,0.5);
            }
            .poster-container:hover {
                transform: none;
            }
            .info-container {
                position: absolute;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                transform: none;
                background: linear-gradient(to bottom, rgba(0,0,0,0.7) 0%, rgba(0,0,0,0.2) 20%, transparent 50%, rgba(0,0,0,0.2) 80%, rgba(0,0,0,0.7) 100%);
                display: flex;
                flex-direction: column;
                justify-content: space-between;
                border-radius: 8px;
                padding: 12px 10px 4px 10px;
                box-sizing: border-box;
                pointer-events: none;
                z-index: 5;
                overflow: visible;
            }
            .info-bottom {
                pointer-events: auto;
                flex: 0 0 auto;
            }
            .playback-controls {
                margin-bottom: 4px;
            }
            .playback-controls ha-icon-button:not(.music-subtle-btn) {
                --mdc-icon-button-size: 36px;
                --mdc-icon-size: 24px;
                background: rgba(255, 255, 255, 0.25) !important;
                color: white !important;
            }
            .playback-controls ha-icon-button:not(.music-subtle-btn):hover {
                background: rgba(255, 255, 255, 0.4) !important;
            }
            .playback-controls .play-pause-btn {
                background: rgba(255, 255, 255, 0.25) !important;
            }
            .playback-controls .play-pause-btn:hover {
                background: rgba(255, 255, 255, 0.4) !important;
            }
            .progress-container {
                padding: 0 4px;
            }
            .progress-bar {
                height: 5px;
                border-radius: 2.5px;
            }
            .seek-handle {
                width: 10px;
                height: 10px;
            }
            .timestamps {
                margin-top: 2px;
                padding: 0 4px;
                justify-content: space-between !important;
            }
            .time-elapsed,
            .time-remaining {
                color: rgba(255, 255, 255, 0.8);
                text-shadow: 0 1px 3px rgba(0,0,0,0.5);
                font-size: 0.7rem;
            }
            .rewind-overlay span {
                font-size: 0.75rem !important;
                line-height: 1 !important;
                padding: 5px 8px 4px !important;
                white-space: nowrap;
            }
        }

        /* Very Tall but Narrow Mode */
        @container now-playing (min-height: 300px) and (max-width: 450px) {
            .card-header {
                display: none !important;
            }
            .poster-badge {
                display: none !important;
            }
            .info-top {
                display: flex !important;
                padding: 0 !important;
                margin: 0 !important;
            }
            .info-top .meta-line, .info-top .client-line {
                display: none !important;
            }
            .info-top .title {
                font-size: 1.25rem !important;
                line-height: 1.1;
                margin-bottom: 2px !important;
                color: var(--card-dominant-color, white) !important;
                text-shadow: 0 1px 3px rgba(0,0,0,0.8) !important;
                overflow: hidden;
                display: -webkit-box;
                -webkit-line-clamp: 2;
                -webkit-box-orient: vertical;
                white-space: normal !important;
            }
            .info-top .subtitle {
                font-size: 0.95rem !important;
                color: var(--card-dominant-color, rgba(255, 255, 255, 0.8)) !important;
                text-shadow: 0 1px 3px rgba(0,0,0,0.8) !important;
                margin-bottom: 0 !important;
                overflow: hidden;
                white-space: nowrap !important;
                text-overflow: ellipsis !important;
                opacity: 0.9;
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
                width: max-content;
                margin: 0 auto;
                border-radius: 8px;
                transition: transform 0.2s ease-in-out;
            }
            .main-container:hover {
                transform: scale(1.02);
            }
            .poster-container {
                flex: 0 0 auto !important;
                height: 100% !important;
                aspect-ratio: 2 / 3;
                box-shadow: 0 4px 12px rgba(0,0,0,0.5);
            }
            .poster-container:hover {
                transform: none;
            }
            .info-container {
                position: absolute;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                transform: none;
                background: linear-gradient(to bottom, rgba(0,0,0,0.85) 0%, rgba(0,0,0,0.3) 25%, transparent 45%, transparent 55%, rgba(0,0,0,0.4) 75%, rgba(0,0,0,0.7) 100%);
                display: flex;
                flex-direction: column;
                justify-content: space-between;
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
            .playback-controls {
                margin-bottom: 8px;
            }
            .playback-controls ha-icon-button:not(.music-subtle-btn) {
                --mdc-icon-button-size: 36px;
                --mdc-icon-size: 24px;
                background: rgba(255, 255, 255, 0.25) !important;
                color: white !important;
            }
            .playback-controls ha-icon-button:not(.music-subtle-btn):hover {
                background: rgba(255, 255, 255, 0.4) !important;
            }
            .playback-controls .play-pause-btn {
                background: rgba(255, 255, 255, 0.25) !important;
            }
            .playback-controls .play-pause-btn:hover {
                background: rgba(255, 255, 255, 0.4) !important;
            }
            .progress-container {
                padding: 0 4px;
            }
            .progress-bar {
                height: 5px;
                border-radius: 2.5px;
            }
            .seek-handle {
                width: 10px;
                height: 10px;
            }
            .timestamps {
                margin-top: 5px;
                padding: 0 4px;
                justify-content: space-between !important;
            }
            .time-elapsed,
            .time-remaining {
                color: rgba(255, 255, 255, 0.8);
                text-shadow: 0 1px 3px rgba(0,0,0,0.5);
                font-size: 0.7rem;
            }
            .rewind-overlay span {
                font-size: 0.75rem !important;
                line-height: 1 !important;
                padding: 5px 8px 4px !important;
                white-space: nowrap;
            }
        }

    `;
A([
  P({ attribute: !1 })
], $.prototype, "hass", 2);
A([
  u()
], $.prototype, "_config", 2);
A([
  u()
], $.prototype, "_rewindActive", 2);
A([
  u()
], $.prototype, "_overflowState", 2);
A([
  u()
], $.prototype, "_dominantColor", 2);
A([
  u()
], $.prototype, "_longPressProgress", 2);
A([
  u()
], $.prototype, "_stopPulse", 2);
A([
  u()
], $.prototype, "_isDragging", 2);
A([
  u()
], $.prototype, "_dragPercentage", 2);
A([
  u()
], $.prototype, "_optimisticSeekPercent", 2);
$ = A([
  R("jellyha-now-playing-card")
], $);
//# sourceMappingURL=jellyha-cards.js.map
