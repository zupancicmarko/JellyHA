if (typeof window < "u") {
  const e = window;
  e.__jellyha_element_cache = e.__jellyha_element_cache || /* @__PURE__ */ new Map();
  const t = e.__jellyha_element_cache, i = (a) => {
    if (!(!a || typeof a.define != "function" || typeof a.get != "function")) {
      for (const [r, n] of t.entries())
        if (!a.get(r))
          try {
            a.define(r, n.constructor, n.options);
          } catch {
          }
    }
  }, o = (a) => {
    if (!a || a.__jellyha_wrapped)
      return;
    a.__jellyha_wrapped = !0;
    const r = a.define.bind(a), n = a.get.bind(a);
    a.define = function(c, p, u) {
      if (!(typeof c == "string" && c.startsWith("jellyha-") && (t.set(c.toLowerCase(), { constructor: p, options: u }), n(c))))
        return r(c, p, u);
    }, a.get = function(c) {
      const p = n(c);
      if (p)
        return p;
      if (typeof c == "string" && c.startsWith("jellyha-")) {
        const u = t.get(c.toLowerCase());
        if (u) {
          try {
            r(c, u.constructor, u.options);
          } catch {
          }
          return n(c) || u.constructor;
        }
      }
    };
  };
  if (typeof window.customElements < "u" && o(window.customElements), !e.__jellyha_def_hooked) {
    e.__jellyha_def_hooked = !0;
    const a = Object.defineProperty;
    Object.defineProperty = function(r, n, c) {
      const p = a.call(Object, r, n, c);
      return r === window && n === "customElements" && c && c.value && (o(c.value), i(c.value)), p;
    };
  }
  ["home-assistant", "hc-main"].forEach((a) => {
    typeof window.customElements < "u" && typeof window.customElements.whenDefined == "function" && window.customElements.whenDefined(a).then(() => {
      typeof window.customElements < "u" && (o(window.customElements), i(window.customElements));
    }).catch(() => {
    });
  }), [100, 500, 1500, 3e3].forEach((a) => {
    setTimeout(() => {
      typeof window.customElements < "u" && (o(window.customElements), i(window.customElements));
    }, a);
  });
}
/**
 * @license
 * Copyright 2019 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const Xe = globalThis, ht = Xe.ShadowRoot && (Xe.ShadyCSS === void 0 || Xe.ShadyCSS.nativeShadow) && "adoptedStyleSheets" in Document.prototype && "replace" in CSSStyleSheet.prototype, ut = Symbol(), wt = /* @__PURE__ */ new WeakMap();
let Rt = class {
  constructor(t, i, o) {
    if (this._$cssResult$ = !0, o !== ut) throw Error("CSSResult is not constructable. Use `unsafeCSS` or `css` instead.");
    this.cssText = t, this.t = i;
  }
  get styleSheet() {
    let t = this.o;
    const i = this.t;
    if (ht && t === void 0) {
      const o = i !== void 0 && i.length === 1;
      o && (t = wt.get(i)), t === void 0 && ((this.o = t = new CSSStyleSheet()).replaceSync(this.cssText), o && wt.set(i, t));
    }
    return t;
  }
  toString() {
    return this.cssText;
  }
};
const Kt = (e) => new Rt(typeof e == "string" ? e : e + "", void 0, ut), Pe = (e, ...t) => {
  const i = e.length === 1 ? e[0] : t.reduce((o, s, a) => o + ((r) => {
    if (r._$cssResult$ === !0) return r.cssText;
    if (typeof r == "number") return r;
    throw Error("Value passed to 'css' function must be a 'css' function result: " + r + ". Use 'unsafeCSS' to pass non-literal values, but take care to ensure page security.");
  })(s) + e[a + 1], e[0]);
  return new Rt(i, e, ut);
}, Zt = (e, t) => {
  if (ht) e.adoptedStyleSheets = t.map((i) => i instanceof CSSStyleSheet ? i : i.styleSheet);
  else for (const i of t) {
    const o = document.createElement("style"), s = Xe.litNonce;
    s !== void 0 && o.setAttribute("nonce", s), o.textContent = i.cssText, e.appendChild(o);
  }
}, xt = ht ? (e) => e : (e) => e instanceof CSSStyleSheet ? ((t) => {
  let i = "";
  for (const o of t.cssRules) i += o.cssText;
  return Kt(i);
})(e) : e;
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const { is: Qt, defineProperty: ei, getOwnPropertyDescriptor: ti, getOwnPropertyNames: ii, getOwnPropertySymbols: ai, getPrototypeOf: oi } = Object, tt = globalThis, kt = tt.trustedTypes, si = kt ? kt.emptyScript : "", ri = tt.reactiveElementPolyfillSupport, Me = (e, t) => e, Ze = { toAttribute(e, t) {
  switch (t) {
    case Boolean:
      e = e ? si : null;
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
} }, _t = (e, t) => !Qt(e, t), $t = { attribute: !0, type: String, converter: Ze, reflect: !1, useDefault: !1, hasChanged: _t };
Symbol.metadata ??= Symbol("metadata"), tt.litPropertyMetadata ??= /* @__PURE__ */ new WeakMap();
let xe = class extends HTMLElement {
  static addInitializer(t) {
    this._$Ei(), (this.l ??= []).push(t);
  }
  static get observedAttributes() {
    return this.finalize(), this._$Eh && [...this._$Eh.keys()];
  }
  static createProperty(t, i = $t) {
    if (i.state && (i.attribute = !1), this._$Ei(), this.prototype.hasOwnProperty(t) && ((i = Object.create(i)).wrapped = !0), this.elementProperties.set(t, i), !i.noAccessor) {
      const o = Symbol(), s = this.getPropertyDescriptor(t, o, i);
      s !== void 0 && ei(this.prototype, t, s);
    }
  }
  static getPropertyDescriptor(t, i, o) {
    const { get: s, set: a } = ti(this.prototype, t) ?? { get() {
      return this[i];
    }, set(r) {
      this[i] = r;
    } };
    return { get: s, set(r) {
      const n = s?.call(this);
      a?.call(this, r), this.requestUpdate(t, n, o);
    }, configurable: !0, enumerable: !0 };
  }
  static getPropertyOptions(t) {
    return this.elementProperties.get(t) ?? $t;
  }
  static _$Ei() {
    if (this.hasOwnProperty(Me("elementProperties"))) return;
    const t = oi(this);
    t.finalize(), t.l !== void 0 && (this.l = [...t.l]), this.elementProperties = new Map(t.elementProperties);
  }
  static finalize() {
    if (this.hasOwnProperty(Me("finalized"))) return;
    if (this.finalized = !0, this._$Ei(), this.hasOwnProperty(Me("properties"))) {
      const i = this.properties, o = [...ii(i), ...ai(i)];
      for (const s of o) this.createProperty(s, i[s]);
    }
    const t = this[Symbol.metadata];
    if (t !== null) {
      const i = litPropertyMetadata.get(t);
      if (i !== void 0) for (const [o, s] of i) this.elementProperties.set(o, s);
    }
    this._$Eh = /* @__PURE__ */ new Map();
    for (const [i, o] of this.elementProperties) {
      const s = this._$Eu(i, o);
      s !== void 0 && this._$Eh.set(s, i);
    }
    this.elementStyles = this.finalizeStyles(this.styles);
  }
  static finalizeStyles(t) {
    const i = [];
    if (Array.isArray(t)) {
      const o = new Set(t.flat(1 / 0).reverse());
      for (const s of o) i.unshift(xt(s));
    } else t !== void 0 && i.push(xt(t));
    return i;
  }
  static _$Eu(t, i) {
    const o = i.attribute;
    return o === !1 ? void 0 : typeof o == "string" ? o : typeof t == "string" ? t.toLowerCase() : void 0;
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
    for (const o of i.keys()) this.hasOwnProperty(o) && (t.set(o, this[o]), delete this[o]);
    t.size > 0 && (this._$Ep = t);
  }
  createRenderRoot() {
    const t = this.shadowRoot ?? this.attachShadow(this.constructor.shadowRootOptions);
    return Zt(t, this.constructor.elementStyles), t;
  }
  connectedCallback() {
    this.renderRoot ??= this.createRenderRoot(), this.enableUpdating(!0), this._$EO?.forEach((t) => t.hostConnected?.());
  }
  enableUpdating(t) {
  }
  disconnectedCallback() {
    this._$EO?.forEach((t) => t.hostDisconnected?.());
  }
  attributeChangedCallback(t, i, o) {
    this._$AK(t, o);
  }
  _$ET(t, i) {
    const o = this.constructor.elementProperties.get(t), s = this.constructor._$Eu(t, o);
    if (s !== void 0 && o.reflect === !0) {
      const a = (o.converter?.toAttribute !== void 0 ? o.converter : Ze).toAttribute(i, o.type);
      this._$Em = t, a == null ? this.removeAttribute(s) : this.setAttribute(s, a), this._$Em = null;
    }
  }
  _$AK(t, i) {
    const o = this.constructor, s = o._$Eh.get(t);
    if (s !== void 0 && this._$Em !== s) {
      const a = o.getPropertyOptions(s), r = typeof a.converter == "function" ? { fromAttribute: a.converter } : a.converter?.fromAttribute !== void 0 ? a.converter : Ze;
      this._$Em = s;
      const n = r.fromAttribute(i, a.type);
      this[s] = n ?? this._$Ej?.get(s) ?? n, this._$Em = null;
    }
  }
  requestUpdate(t, i, o, s = !1, a) {
    if (t !== void 0) {
      const r = this.constructor;
      if (s === !1 && (a = this[t]), o ??= r.getPropertyOptions(t), !((o.hasChanged ?? _t)(a, i) || o.useDefault && o.reflect && a === this._$Ej?.get(t) && !this.hasAttribute(r._$Eu(t, o)))) return;
      this.C(t, i, o);
    }
    this.isUpdatePending === !1 && (this._$ES = this._$EP());
  }
  C(t, i, { useDefault: o, reflect: s, wrapped: a }, r) {
    o && !(this._$Ej ??= /* @__PURE__ */ new Map()).has(t) && (this._$Ej.set(t, r ?? i ?? this[t]), a !== !0 || r !== void 0) || (this._$AL.has(t) || (this.hasUpdated || o || (i = void 0), this._$AL.set(t, i)), s === !0 && this._$Em !== t && (this._$Eq ??= /* @__PURE__ */ new Set()).add(t));
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
        for (const [s, a] of this._$Ep) this[s] = a;
        this._$Ep = void 0;
      }
      const o = this.constructor.elementProperties;
      if (o.size > 0) for (const [s, a] of o) {
        const { wrapped: r } = a, n = this[s];
        r !== !0 || this._$AL.has(s) || n === void 0 || this.C(s, void 0, a, n);
      }
    }
    let t = !1;
    const i = this._$AL;
    try {
      t = this.shouldUpdate(i), t ? (this.willUpdate(i), this._$EO?.forEach((o) => o.hostUpdate?.()), this.update(i)) : this._$EM();
    } catch (o) {
      throw t = !1, this._$EM(), o;
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
xe.elementStyles = [], xe.shadowRootOptions = { mode: "open" }, xe[Me("elementProperties")] = /* @__PURE__ */ new Map(), xe[Me("finalized")] = /* @__PURE__ */ new Map(), ri?.({ ReactiveElement: xe }), (tt.reactiveElementVersions ??= []).push("2.1.2");
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const gt = globalThis, St = (e) => e, Qe = gt.trustedTypes, Ct = Qe ? Qe.createPolicy("lit-html", { createHTML: (e) => e }) : void 0, Ot = "$lit$", le = `lit$${Math.random().toFixed(9).slice(2)}$`, Ut = "?" + le, ni = `<${Ut}>`, _e = document, De = () => _e.createComment(""), Le = (e) => e === null || typeof e != "object" && typeof e != "function", mt = Array.isArray, li = (e) => mt(e) || typeof e?.[Symbol.iterator] == "function", rt = `[ 	
\f\r]`, Ae = /<(?:(!--|\/[^a-zA-Z])|(\/?[a-zA-Z][^>\s]*)|(\/?$))/g, Pt = /-->/g, jt = />/g, pe = RegExp(`>|${rt}(?:([^\\s"'>=/]+)(${rt}*=${rt}*(?:[^ 	
\f\r"'\`<>=]|("|')|))|$)`, "g"), It = /'/g, Et = /"/g, Ft = /^(?:script|style|textarea|title)$/i, di = (e) => (t, ...i) => ({ _$litType$: e, strings: t, values: i }), l = di(1), Se = Symbol.for("lit-noChange"), h = Symbol.for("lit-nothing"), Tt = /* @__PURE__ */ new WeakMap(), he = _e.createTreeWalker(_e, 129);
function Bt(e, t) {
  if (!mt(e) || !e.hasOwnProperty("raw")) throw Error("invalid template strings array");
  return Ct !== void 0 ? Ct.createHTML(t) : t;
}
const ci = (e, t) => {
  const i = e.length - 1, o = [];
  let s, a = t === 2 ? "<svg>" : t === 3 ? "<math>" : "", r = Ae;
  for (let n = 0; n < i; n++) {
    const c = e[n];
    let p, u, _ = -1, g = 0;
    for (; g < c.length && (r.lastIndex = g, u = r.exec(c), u !== null); ) g = r.lastIndex, r === Ae ? u[1] === "!--" ? r = Pt : u[1] !== void 0 ? r = jt : u[2] !== void 0 ? (Ft.test(u[2]) && (s = RegExp("</" + u[2], "g")), r = pe) : u[3] !== void 0 && (r = pe) : r === pe ? u[0] === ">" ? (r = s ?? Ae, _ = -1) : u[1] === void 0 ? _ = -2 : (_ = r.lastIndex - u[2].length, p = u[1], r = u[3] === void 0 ? pe : u[3] === '"' ? Et : It) : r === Et || r === It ? r = pe : r === Pt || r === jt ? r = Ae : (r = pe, s = void 0);
    const m = r === pe && e[n + 1].startsWith("/>") ? " " : "";
    a += r === Ae ? c + ni : _ >= 0 ? (o.push(p), c.slice(0, _) + Ot + c.slice(_) + le + m) : c + le + (_ === -2 ? n : m);
  }
  return [Bt(e, a + (e[i] || "<?>") + (t === 2 ? "</svg>" : t === 3 ? "</math>" : "")), o];
};
class Ne {
  constructor({ strings: t, _$litType$: i }, o) {
    let s;
    this.parts = [];
    let a = 0, r = 0;
    const n = t.length - 1, c = this.parts, [p, u] = ci(t, i);
    if (this.el = Ne.createElement(p, o), he.currentNode = this.el.content, i === 2 || i === 3) {
      const _ = this.el.content.firstChild;
      _.replaceWith(..._.childNodes);
    }
    for (; (s = he.nextNode()) !== null && c.length < n; ) {
      if (s.nodeType === 1) {
        if (s.hasAttributes()) for (const _ of s.getAttributeNames()) if (_.endsWith(Ot)) {
          const g = u[r++], m = s.getAttribute(_).split(le), b = /([.?@])?(.*)/.exec(g);
          c.push({ type: 1, index: a, name: b[2], strings: m, ctor: b[1] === "." ? hi : b[1] === "?" ? ui : b[1] === "@" ? _i : it }), s.removeAttribute(_);
        } else _.startsWith(le) && (c.push({ type: 6, index: a }), s.removeAttribute(_));
        if (Ft.test(s.tagName)) {
          const _ = s.textContent.split(le), g = _.length - 1;
          if (g > 0) {
            s.textContent = Qe ? Qe.emptyScript : "";
            for (let m = 0; m < g; m++) s.append(_[m], De()), he.nextNode(), c.push({ type: 2, index: ++a });
            s.append(_[g], De());
          }
        }
      } else if (s.nodeType === 8) if (s.data === Ut) c.push({ type: 2, index: a });
      else {
        let _ = -1;
        for (; (_ = s.data.indexOf(le, _ + 1)) !== -1; ) c.push({ type: 7, index: a }), _ += le.length - 1;
      }
      a++;
    }
  }
  static createElement(t, i) {
    const o = _e.createElement("template");
    return o.innerHTML = t, o;
  }
}
function Ce(e, t, i = e, o) {
  if (t === Se) return t;
  let s = o !== void 0 ? i._$Co?.[o] : i._$Cl;
  const a = Le(t) ? void 0 : t._$litDirective$;
  return s?.constructor !== a && (s?._$AO?.(!1), a === void 0 ? s = void 0 : (s = new a(e), s._$AT(e, i, o)), o !== void 0 ? (i._$Co ??= [])[o] = s : i._$Cl = s), s !== void 0 && (t = Ce(e, s._$AS(e, t.values), s, o)), t;
}
class pi {
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
    const { el: { content: i }, parts: o } = this._$AD, s = (t?.creationScope ?? _e).importNode(i, !0);
    he.currentNode = s;
    let a = he.nextNode(), r = 0, n = 0, c = o[0];
    for (; c !== void 0; ) {
      if (r === c.index) {
        let p;
        c.type === 2 ? p = new Ue(a, a.nextSibling, this, t) : c.type === 1 ? p = new c.ctor(a, c.name, c.strings, this, t) : c.type === 6 && (p = new gi(a, this, t)), this._$AV.push(p), c = o[++n];
      }
      r !== c?.index && (a = he.nextNode(), r++);
    }
    return he.currentNode = _e, s;
  }
  p(t) {
    let i = 0;
    for (const o of this._$AV) o !== void 0 && (o.strings !== void 0 ? (o._$AI(t, o, i), i += o.strings.length - 2) : o._$AI(t[i])), i++;
  }
}
class Ue {
  get _$AU() {
    return this._$AM?._$AU ?? this._$Cv;
  }
  constructor(t, i, o, s) {
    this.type = 2, this._$AH = h, this._$AN = void 0, this._$AA = t, this._$AB = i, this._$AM = o, this.options = s, this._$Cv = s?.isConnected ?? !0;
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
    t = Ce(this, t, i), Le(t) ? t === h || t == null || t === "" ? (this._$AH !== h && this._$AR(), this._$AH = h) : t !== this._$AH && t !== Se && this._(t) : t._$litType$ !== void 0 ? this.$(t) : t.nodeType !== void 0 ? this.T(t) : li(t) ? this.k(t) : this._(t);
  }
  O(t) {
    return this._$AA.parentNode.insertBefore(t, this._$AB);
  }
  T(t) {
    this._$AH !== t && (this._$AR(), this._$AH = this.O(t));
  }
  _(t) {
    this._$AH !== h && Le(this._$AH) ? this._$AA.nextSibling.data = t : this.T(_e.createTextNode(t)), this._$AH = t;
  }
  $(t) {
    const { values: i, _$litType$: o } = t, s = typeof o == "number" ? this._$AC(t) : (o.el === void 0 && (o.el = Ne.createElement(Bt(o.h, o.h[0]), this.options)), o);
    if (this._$AH?._$AD === s) this._$AH.p(i);
    else {
      const a = new pi(s, this), r = a.u(this.options);
      a.p(i), this.T(r), this._$AH = a;
    }
  }
  _$AC(t) {
    let i = Tt.get(t.strings);
    return i === void 0 && Tt.set(t.strings, i = new Ne(t)), i;
  }
  k(t) {
    mt(this._$AH) || (this._$AH = [], this._$AR());
    const i = this._$AH;
    let o, s = 0;
    for (const a of t) s === i.length ? i.push(o = new Ue(this.O(De()), this.O(De()), this, this.options)) : o = i[s], o._$AI(a), s++;
    s < i.length && (this._$AR(o && o._$AB.nextSibling, s), i.length = s);
  }
  _$AR(t = this._$AA.nextSibling, i) {
    for (this._$AP?.(!1, !0, i); t !== this._$AB; ) {
      const o = St(t).nextSibling;
      St(t).remove(), t = o;
    }
  }
  setConnected(t) {
    this._$AM === void 0 && (this._$Cv = t, this._$AP?.(t));
  }
}
class it {
  get tagName() {
    return this.element.tagName;
  }
  get _$AU() {
    return this._$AM._$AU;
  }
  constructor(t, i, o, s, a) {
    this.type = 1, this._$AH = h, this._$AN = void 0, this.element = t, this.name = i, this._$AM = s, this.options = a, o.length > 2 || o[0] !== "" || o[1] !== "" ? (this._$AH = Array(o.length - 1).fill(new String()), this.strings = o) : this._$AH = h;
  }
  _$AI(t, i = this, o, s) {
    const a = this.strings;
    let r = !1;
    if (a === void 0) t = Ce(this, t, i, 0), r = !Le(t) || t !== this._$AH && t !== Se, r && (this._$AH = t);
    else {
      const n = t;
      let c, p;
      for (t = a[0], c = 0; c < a.length - 1; c++) p = Ce(this, n[o + c], i, c), p === Se && (p = this._$AH[c]), r ||= !Le(p) || p !== this._$AH[c], p === h ? t = h : t !== h && (t += (p ?? "") + a[c + 1]), this._$AH[c] = p;
    }
    r && !s && this.j(t);
  }
  j(t) {
    t === h ? this.element.removeAttribute(this.name) : this.element.setAttribute(this.name, t ?? "");
  }
}
class hi extends it {
  constructor() {
    super(...arguments), this.type = 3;
  }
  j(t) {
    this.element[this.name] = t === h ? void 0 : t;
  }
}
class ui extends it {
  constructor() {
    super(...arguments), this.type = 4;
  }
  j(t) {
    this.element.toggleAttribute(this.name, !!t && t !== h);
  }
}
class _i extends it {
  constructor(t, i, o, s, a) {
    super(t, i, o, s, a), this.type = 5;
  }
  _$AI(t, i = this) {
    if ((t = Ce(this, t, i, 0) ?? h) === Se) return;
    const o = this._$AH, s = t === h && o !== h || t.capture !== o.capture || t.once !== o.once || t.passive !== o.passive, a = t !== h && (o === h || s);
    s && this.element.removeEventListener(this.name, this, o), a && this.element.addEventListener(this.name, this, t), this._$AH = t;
  }
  handleEvent(t) {
    typeof this._$AH == "function" ? this._$AH.call(this.options?.host ?? this.element, t) : this._$AH.handleEvent(t);
  }
}
class gi {
  constructor(t, i, o) {
    this.element = t, this.type = 6, this._$AN = void 0, this._$AM = i, this.options = o;
  }
  get _$AU() {
    return this._$AM._$AU;
  }
  _$AI(t) {
    Ce(this, t);
  }
}
const mi = gt.litHtmlPolyfillSupport;
mi?.(Ne, Ue), (gt.litHtmlVersions ??= []).push("3.3.2");
const et = (e, t, i) => {
  const o = i?.renderBefore ?? t;
  let s = o._$litPart$;
  if (s === void 0) {
    const a = i?.renderBefore ?? null;
    o._$litPart$ = s = new Ue(t.insertBefore(De(), a), a, void 0, i ?? {});
  }
  return s._$AI(e), s;
};
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const ft = globalThis;
class X extends xe {
  constructor() {
    super(...arguments), this.renderOptions = { host: this }, this._$Do = void 0;
  }
  createRenderRoot() {
    const t = super.createRenderRoot();
    return this.renderOptions.renderBefore ??= t.firstChild, t;
  }
  update(t) {
    const i = this.render();
    this.hasUpdated || (this.renderOptions.isConnected = this.isConnected), super.update(t), this._$Do = et(i, this.renderRoot, this.renderOptions);
  }
  connectedCallback() {
    super.connectedCallback(), this._$Do?.setConnected(!0);
  }
  disconnectedCallback() {
    super.disconnectedCallback(), this._$Do?.setConnected(!1);
  }
  render() {
    return Se;
  }
}
X._$litElement$ = !0, X.finalized = !0, ft.litElementHydrateSupport?.({ LitElement: X });
const fi = ft.litElementPolyfillSupport;
fi?.({ LitElement: X });
(ft.litElementVersions ??= []).push("4.2.2");
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const ge = (e) => (t, i) => {
  i !== void 0 ? i.addInitializer(() => {
    customElements.define(e, t);
  }) : customElements.define(e, t);
};
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const bi = { attribute: !0, type: String, converter: Ze, reflect: !1, hasChanged: _t }, yi = (e = bi, t, i) => {
  const { kind: o, metadata: s } = i;
  let a = globalThis.litPropertyMetadata.get(s);
  if (a === void 0 && globalThis.litPropertyMetadata.set(s, a = /* @__PURE__ */ new Map()), o === "setter" && ((e = Object.create(e)).wrapped = !0), a.set(i.name, e), o === "accessor") {
    const { name: r } = i;
    return { set(n) {
      const c = t.get.call(this);
      t.set.call(this, n), this.requestUpdate(r, c, e, !0, n);
    }, init(n) {
      return n !== void 0 && this.C(r, void 0, e, n), n;
    } };
  }
  if (o === "setter") {
    const { name: r } = i;
    return function(n) {
      const c = this[r];
      t.call(this, n), this.requestUpdate(r, c, e, !0, n);
    };
  }
  throw Error("Unsupported decorator location: " + o);
};
function V(e) {
  return (t, i) => typeof i == "object" ? yi(e, t, i) : ((o, s, a) => {
    const r = s.hasOwnProperty(a);
    return s.constructor.createProperty(a, o), r ? Object.getOwnPropertyDescriptor(s, a) : void 0;
  })(e, t, i);
}
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
function f(e) {
  return V({ ...e, state: !0, attribute: !1 });
}
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const vi = (e, t, i) => (i.configurable = !0, i.enumerable = !0, Reflect.decorate && typeof t != "object" && Object.defineProperty(e, t, i), i);
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
function wi(e, t) {
  return (i, o, s) => {
    const a = (r) => r.renderRoot?.querySelector(e) ?? null;
    return vi(i, o, { get() {
      return a(this);
    } });
  };
}
function Ke(e, t) {
  if (!t || !e.date_added)
    return !1;
  const i = new Date(e.date_added);
  return ((/* @__PURE__ */ new Date()).getTime() - i.getTime()) / (1e3 * 60 * 60 * 24) <= t;
}
function nt(e, t = "en") {
  try {
    const i = new Date(e);
    return new Intl.DateTimeFormat(t, {
      year: "numeric",
      month: "short",
      day: "numeric"
    }).format(i);
  } catch {
    return e;
  }
}
function ue(e) {
  if (e < 60)
    return `${e}m`;
  const t = Math.floor(e / 60), i = e % 60;
  return i > 0 ? `${t}h ${i}m` : `${t}h`;
}
function R(e, t) {
  if (!e || e.includes("width=")) return e;
  const i = e.includes("?") ? "&" : "?";
  return `${e}${i}width=${t}`;
}
function $e(e, t) {
  if (!t) return "Run Script";
  const i = t.includes(".") ? t : `script.${t}`, o = e?.states?.[i]?.attributes?.friendly_name;
  if (typeof o == "string" && o.trim())
    return o;
  if (t.includes(".")) {
    const a = e?.states?.[t]?.attributes?.friendly_name;
    if (typeof a == "string" && a.trim())
      return a;
  }
  return (t.includes(".") ? t.split(".").slice(1).join(".") : t).split("_").map((a) => ["on", "in", "at", "to", "for", "a", "an", "the", "and", "or", "of"].includes(a.toLowerCase()) ? a.toLowerCase() : a.toLowerCase() === "tv" ? "TV" : a.charAt(0).toUpperCase() + a.slice(1)).join(" ").replace(/^\w/, (a) => a.toUpperCase());
}
var xi = Object.defineProperty, ki = Object.getOwnPropertyDescriptor, Y = (e, t, i, o) => {
  for (var s = o > 1 ? void 0 : o ? ki(t, i) : t, a = e.length - 1, r; a >= 0; a--)
    (r = e[a]) && (s = (o ? r(t, i, s) : r(s)) || s);
  return o && s && xi(t, i, s), s;
};
const $i = /* @__PURE__ */ new Set([
  "subrip",
  "srt",
  "vtt",
  "webvtt",
  "mov_text",
  "ass",
  "ssa",
  "text",
  "ttml"
]), Si = {
  slv: "sl",
  eng: "en",
  deu: "de",
  ger: "de",
  fre: "fr",
  fra: "fr",
  spa: "es",
  ita: "it",
  dut: "nl",
  nld: "nl",
  hrv: "hr",
  srp: "sr",
  bos: "bs",
  rus: "ru",
  pol: "pl",
  ces: "cs",
  cze: "cs",
  hun: "hu",
  jpn: "ja",
  zho: "zh",
  chi: "zh"
};
function Ci(e, t, i) {
  if (!i) return !1;
  const o = i.trim().toLowerCase();
  if (!o) return !1;
  const s = [
    /* @__PURE__ */ new Set(["sl", "slv", "slovenian", "slovenski"]),
    /* @__PURE__ */ new Set(["en", "eng", "english"]),
    /* @__PURE__ */ new Set(["de", "ger", "deu", "german", "deutsch"]),
    /* @__PURE__ */ new Set(["fr", "fre", "fra", "french", "francais", "français"]),
    /* @__PURE__ */ new Set(["es", "spa", "spanish", "espanol", "español"]),
    /* @__PURE__ */ new Set(["it", "ita", "italian", "italiano"]),
    /* @__PURE__ */ new Set(["nl", "dut", "nld", "dutch", "nederlands"]),
    /* @__PURE__ */ new Set(["hr", "hrv", "croatian", "hrvatski"]),
    /* @__PURE__ */ new Set(["sr", "srp", "serbian", "srpski"]),
    /* @__PURE__ */ new Set(["bs", "bos", "bosnian", "bosanski"]),
    /* @__PURE__ */ new Set(["ru", "rus", "russian"]),
    /* @__PURE__ */ new Set(["pl", "pol", "polish", "polski"]),
    /* @__PURE__ */ new Set(["cs", "cze", "ces", "czech"]),
    /* @__PURE__ */ new Set(["hu", "hun", "hungarian", "magyar"]),
    /* @__PURE__ */ new Set(["ja", "jpn", "japanese"]),
    /* @__PURE__ */ new Set(["zh", "zho", "chi", "chinese", "zhs", "zht"])
  ], a = (e || "").trim().toLowerCase(), r = (t || "").trim().toLowerCase();
  let n;
  for (const c of s)
    if (c.has(o)) {
      n = c;
      break;
    }
  if (n) {
    if (n.has(a) || r && Array.from(n).some((c) => r.includes(c))) return !0;
  } else if (a === o || a.startsWith(o) || r.includes(o)) return !0;
  return !1;
}
let q = class extends X {
  constructor() {
    super(...arguments), this._open = !1, this._loading = !1, this._mimeType = "video/mp4", this._playMethod = "DirectPlay", this._subtitleTracks = [], this._portalContainer = null, this._handleKeyDown = (e) => {
      e.key === "Escape" && this._open && (this.close(), e.stopPropagation());
    }, this.close = () => {
      this._open = !1, this._loading = !1, this._error = void 0, this._teardownActiveSession(), this._streamUrl = void 0, this._subtitleTracks = [], this._item = void 0, this._renderPortal();
    };
  }
  connectedCallback() {
    super.connectedCallback(), window.addEventListener("keydown", this._handleKeyDown);
  }
  disconnectedCallback() {
    super.disconnectedCallback(), window.removeEventListener("keydown", this._handleKeyDown), this.close(), this._destroyPortal();
  }
  async play(e) {
    this._teardownActiveSession(), this.hass = e.hass, this._item = e.item, this._open = !0, this._loading = !0, this._error = void 0, this._streamUrl = void 0, this._subtitleTracks = [], this._mimeType = e.item.type === "Audio" ? "audio/mp4" : "video/mp4", this._ensurePortal(), this._renderPortal();
    try {
      let t = e.item, i = e.configEntryId || t.config_entry_id || t.entry_id;
      if (!i && e.serverEntityId && e.hass.states[e.serverEntityId] && (i = e.hass.states[e.serverEntityId]?.attributes?.config_entry_id), !i) {
        const s = Object.values(e.hass.states).find(
          (a) => a?.entity_id?.startsWith("sensor.jellyha") && a?.attributes?.config_entry_id
        );
        s && (i = s.attributes?.config_entry_id);
      }
      if (t.type === "Series" || t.type === "Season")
        try {
          const s = await e.hass.callWS({
            type: "jellyha/get_next_up",
            series_id: t.id,
            ...i ? { config_entry_id: i } : {},
            ...e.serverEntityId ? { server_entity_id: e.serverEntityId } : {}
          });
          s?.item && (t = s.item, this._item = t);
        } catch (s) {
          console.debug("JellyHA: Could not resolve next up episode for series", s);
        }
      if (t.type !== "Audio" && (!t.media_streams || t.media_streams.length === 0))
        try {
          const s = await e.hass.callWS({
            type: "jellyha/get_item",
            item_id: t.id,
            ...i ? { config_entry_id: i } : {},
            ...e.serverEntityId ? { server_entity_id: e.serverEntityId } : {}
          });
          s?.item?.media_streams && (t = { ...t, media_streams: s.item.media_streams }, this._item = t);
        } catch (s) {
          console.debug("JellyHA: Could not fetch detailed media_streams for item", s);
        }
      const o = await this._resolveStream({ ...e, item: t });
      if (!this._open) {
        this._teardownActiveSession();
        return;
      }
      if (this._streamUrl = o.url, this._mimeType = o.mimeType, i) {
        const s = this._resolveSubtitles(t, i, e);
        this._subtitleTracks = await Promise.all(
          s.map(async (a) => {
            try {
              const r = await e.hass.callWS({
                type: "auth/sign_path",
                path: a.url,
                expires: 86400
              });
              if (r?.path)
                return { ...a, url: r.path };
            } catch (r) {
              console.warn("JellyHA: Failed to sign subtitle path", a.url, r);
            }
            return a;
          })
        );
      } else
        this._subtitleTracks = [];
      this._loading = !1, this._renderPortal(), this._attachVideoMedia(), this._activateDefaultSubtitle();
    } catch (t) {
      if (console.error("JellyHA: Failed to resolve media stream for browser playback", t), !this._open) return;
      this._loading = !1, this._error = t?.message || "Failed to resolve media stream", this._renderPortal();
    }
  }
  _resolveSubtitles(e, t, i) {
    if (e.type === "Audio") return [];
    const o = (e.media_streams || []).filter(
      (p) => p.Type === "Subtitle" && (p.IsExternal || !p.Codec || $i.has(p.Codec.toLowerCase()))
    );
    if (!o || o.length === 0) return [];
    const s = (i.subtitleMode || "auto").toLowerCase(), a = (i.subtitleLanguage || "").split(",").map((p) => p.trim().toLowerCase()).filter(Boolean);
    let r = -1;
    const n = (p, u = !1) => {
      const _ = o.filter((m) => u && !m.IsForced ? !1 : Ci(m.Language, m.DisplayTitle || m.Title, p));
      return _.length === 0 ? void 0 : _.find((m) => {
        const b = (m.DisplayTitle || m.Title || "").toLowerCase();
        return !m.IsHearingImpaired && !b.includes("sdh") && !b.includes("hearing impaired");
      }) || _[0];
    };
    if (s === "none")
      r = -1;
    else if (s === "forced_only") {
      for (const p of a) {
        const u = n(p, !0);
        if (u) {
          r = u.Index;
          break;
        }
      }
      if (r === -1) {
        const p = o.find((u) => u.IsForced);
        p && (r = p.Index);
      }
    } else {
      for (const p of a) {
        const u = n(p);
        if (u) {
          r = u.Index;
          break;
        }
      }
      if (r === -1 && s === "auto") {
        const p = (i.hass?.language || "").split("-")[0].toLowerCase();
        if (p) {
          const u = n(p);
          u && (r = u.Index);
        }
      }
      if (r === -1 && s === "auto") {
        const p = o.find((u) => u.IsDefault);
        p && (r = p.Index);
      }
    }
    const c = e.media_source_id || e.MediaSources?.[0]?.Id || e.id;
    return o.map((p) => {
      const u = (p.Language || "en").trim().toLowerCase(), _ = u.length === 3 && Si[u] || u, g = p.DisplayTitle || p.Title || (_ ? _.toUpperCase() : `Subtitle ${p.Index}`), m = `/api/jellyha/subtitles/${t}/${e.id}/${p.Index}/stream.vtt?media_source_id=${encodeURIComponent(c)}`;
      return {
        index: p.Index,
        label: g,
        lang: _,
        url: m,
        isDefault: p.Index === r
      };
    });
  }
  _setupTextTrackListener(e) {
    if (e._hasJellyHaTrackListener || !e.textTracks) return;
    e._hasJellyHaTrackListener = !0;
    let t = !1;
    e.textTracks.addEventListener("change", () => {
      if (!t) {
        t = !0;
        try {
          let i = 0;
          for (let o = 0; o < e.textTracks.length; o++) {
            const s = e.textTracks[o];
            s.mode === "showing" && (i++, i > 1 && (s.mode = "disabled"));
          }
        } finally {
          t = !1;
        }
      }
    });
  }
  _activateDefaultSubtitle() {
    if (!this._portalContainer || !this._subtitleTracks || this._subtitleTracks.length === 0) return;
    const e = this._subtitleTracks.find((t) => t.isDefault);
    requestAnimationFrame(() => {
      const t = this._portalContainer?.querySelector("video");
      if (!t || !t.textTracks) return;
      this._setupTextTrackListener(t);
      const i = e ? `jellyha-track-${e.index}` : null;
      let o = !1;
      for (let s = 0; s < t.textTracks.length; s++) {
        const a = t.textTracks[s];
        !!(i && (a.id ? a.id === i : a.label === e?.label)) && !o ? (a.mode = "showing", o = !0) : a.mode = "disabled";
      }
    });
  }
  _teardownActiveSession() {
    if (this._hlsInstance) {
      try {
        this._hlsInstance.destroy();
      } catch (e) {
        console.debug("JellyHA: Error destroying HLS instance", e);
      }
      this._hlsInstance = void 0;
    }
    if (this._hlsToken || this._playSessionId) {
      const e = this._hlsToken, t = this._playSessionId;
      try {
        const i = this.hass?.callWS({
          type: "jellyha/stop_playback",
          ...e ? { token: e } : {},
          ...t ? { play_session_id: t } : {}
        });
        i && typeof i.catch == "function" && i.catch((o) => console.debug("JellyHA: Error terminating playback session", o));
      } catch (i) {
        console.debug("JellyHA: Error terminating playback session", i);
      }
      this._hlsToken = void 0, this._playSessionId = void 0;
    }
    if (this._playMethod = "DirectPlay", this._portalContainer) {
      const e = this._portalContainer.querySelector("video");
      e && (e.pause(), e.src = "", e.load());
      const t = this._portalContainer.querySelector("audio");
      t && (t.pause(), t.src = "", t.load());
    }
  }
  async _attachVideoMedia() {
    if (!this._portalContainer || !this._streamUrl || this._item?.type === "Audio") return;
    const e = this._portalContainer.querySelector("video");
    if (!e) return;
    if (this._streamUrl.includes(".m3u8") || this._mimeType === "application/x-mpegURL" || this._mimeType === "application/vnd.apple.mpegurl") {
      if (typeof e.canPlayType == "function" && e.canPlayType("application/vnd.apple.mpegurl")) {
        e.src = this._streamUrl;
        return;
      }
      try {
        const i = await import("./hls-qy80PMYy.js"), o = i.default || i;
        if (o.isSupported()) {
          this._hlsInstance && this._hlsInstance.destroy();
          const s = new o({
            enableWorker: !0,
            lowLatencyMode: !0
          });
          this._hlsInstance = s, s.loadSource(this._streamUrl), s.attachMedia(e), s.on(o.Events.MANIFEST_PARSED, () => {
            e.play().catch(() => {
            }), this._activateDefaultSubtitle();
          }), s.on(o.Events.ERROR, (a, r) => {
            if (r.fatal)
              switch (console.error("JellyHA: Hls fatal error", r), r.type) {
                case o.ErrorTypes.NETWORK_ERROR:
                  s.startLoad();
                  break;
                case o.ErrorTypes.MEDIA_ERROR:
                  s.recoverMediaError();
                  break;
                default:
                  s.destroy(), this._error = "Playback failed", this._renderPortal();
                  break;
              }
          });
        } else
          e.src = this._streamUrl;
      } catch (i) {
        console.error("JellyHA: Error loading hls.js", i), e.src = this._streamUrl;
      }
    }
  }
  async _resolveStream(e) {
    const t = e.item, i = e.hass;
    let o = e.configEntryId || t.config_entry_id || t.entry_id;
    if (!o && e.serverEntityId && i.states[e.serverEntityId] && (o = i.states[e.serverEntityId]?.attributes?.config_entry_id), !o) {
      const r = Object.values(i.states).find(
        (n) => n?.entity_id?.startsWith("sensor.jellyha") && n?.attributes?.config_entry_id
      );
      r && (o = r.attributes?.config_entry_id);
    }
    let s, a = t.type === "Audio" ? "audio/mp4" : "video/mp4";
    try {
      const r = await i.callWS({
        type: "jellyha/resolve_playback",
        item_id: t.id,
        ...o ? { config_entry_id: o } : {},
        ...e.serverEntityId ? { server_entity_id: e.serverEntityId } : {}
      });
      if (r?.url)
        return this._playMethod = r.play_method || "DirectPlay", this._playSessionId = r.play_session_id, this._hlsToken = r.token, { url: r.url, mimeType: r.mime_type || a };
    } catch (r) {
      console.warn("JellyHA: WebSocket jellyha/resolve_playback failed, falling back", r);
    }
    if (o) {
      let r = "video";
      t.type === "Movie" ? r = "movie" : t.type === "Episode" ? r = "episode" : t.type === "Series" ? r = "series" : t.type === "Season" ? r = "season" : t.type === "Audio" && (r = "track");
      const n = `media-source://jellyha/${o}/${r}/${t.id}`;
      try {
        const c = await i.callWS({
          type: "media_source/resolve_media",
          media_content_id: n
        });
        c?.url && (s = c.url, c.mime_type && (a = c.mime_type), this._playMethod = "DirectPlay");
      } catch (c) {
        console.warn("JellyHA: WebSocket media_source/resolve_media failed, trying direct proxy route", c);
      }
    }
    if (!s && o) {
      const r = t.type === "Audio" ? "Audio" : "Videos";
      s = `/api/jellyha/stream/${o}/${t.id}?media_type=${r}`, this._playMethod = "DirectPlay";
    }
    if (!s)
      throw new Error("Unable to determine Jellyfin media stream endpoint.");
    return { url: s, mimeType: a };
  }
  _ensurePortal() {
    this._portalContainer || (this._portalContainer = document.createElement("div"), this._portalContainer.id = "jellyha-browser-player-portal", document.body.appendChild(this._portalContainer));
  }
  _destroyPortal() {
    this._portalContainer && (this._portalContainer.remove(), this._portalContainer = null);
  }
  _getPortalStyles() {
    return l`
        <style>
            .jellyha-player-scrim {
                position: fixed;
                inset: 0;
                z-index: 100000;
                background: rgba(0, 0, 0, 0.45);
                backdrop-filter: blur(3px);
                -webkit-backdrop-filter: blur(3px);
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 16px;
                box-sizing: border-box;
                animation: jellyhaFadeIn 0.2s ease-out;
            }

            @keyframes jellyhaFadeIn {
                from { opacity: 0; }
                to { opacity: 1; }
            }

            @keyframes jellyhaScaleIn {
                from { transform: scale(0.96); opacity: 0; }
                to { transform: scale(1); opacity: 1; }
            }

            .jellyha-player-surface {
                position: relative;
                display: flex;
                flex-direction: column;
                background: #14161f;
                color: #ffffff;
                box-sizing: border-box;
                border-radius: 20px;
                border: var(--ha-card-border, var(--ha-card-border-width, 1px) solid var(--ha-card-border-color, var(--divider-color, rgba(255, 255, 255, 0.14))));
                box-shadow: 0 24px 72px rgba(0, 0, 0, 0.85);
                width: min(960px, 95vw);
                max-height: min(92vh, 880px);
                overflow: hidden;
                animation: jellyhaScaleIn 0.22s cubic-bezier(0.16, 1, 0.3, 1);
            }

            .jellyha-player-header {
                display: flex;
                align-items: center;
                justify-content: space-between;
                padding: 14px 20px;
                background: rgba(255, 255, 255, 0.03);
                border-bottom: 1px solid rgba(255, 255, 255, 0.08);
                gap: 12px;
            }

            .jellyha-player-title-wrap {
                display: flex;
                flex-direction: column;
                min-width: 0;
            }

            .jellyha-player-subtitle {
                font-size: 0.78rem;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 0.04em;
                color: #03a9f4;
                white-space: nowrap;
                overflow: hidden;
                text-overflow: ellipsis;
            }

            .jellyha-player-title {
                font-size: 1.05rem;
                font-weight: 700;
                color: #ffffff;
                white-space: nowrap;
                overflow: hidden;
                text-overflow: ellipsis;
            }

            .jellyha-player-close-btn {
                background: rgba(255, 255, 255, 0.1);
                backdrop-filter: blur(8px);
                -webkit-backdrop-filter: blur(8px);
                border: 1px solid rgba(255, 255, 255, 0.2);
                border-radius: 50%;
                width: 34px;
                height: 34px;
                display: flex;
                align-items: center;
                justify-content: center;
                cursor: pointer;
                color: #ffffff;
                transition: all 0.2s ease;
                padding: 0;
                flex-shrink: 0;
            }

            .jellyha-player-close-btn:hover {
                background: rgba(255, 255, 255, 0.2);
                transform: scale(1.06);
            }

            .jellyha-player-content {
                display: flex;
                flex-direction: column;
                align-items: center;
                justify-content: center;
                padding: 0;
                background: #000000;
                min-height: 240px;
            }

            .jellyha-player-video {
                width: 100%;
                max-height: min(78vh, 640px);
                aspect-ratio: 16/9;
                background: #000000;
                outline: none;
                display: block;
            }

            .jellyha-player-audio-wrap {
                display: flex;
                flex-direction: column;
                align-items: center;
                justify-content: center;
                padding: 32px 24px;
                width: 100%;
                box-sizing: border-box;
                gap: 20px;
                background: linear-gradient(180deg, #181b28 0%, #10121a 100%);
            }

            .jellyha-player-audio-poster {
                width: 140px;
                height: 140px;
                border-radius: 16px;
                object-fit: cover;
                box-shadow: 0 12px 32px rgba(0, 0, 0, 0.6);
            }

            .jellyha-player-audio {
                width: min(500px, 90%);
                outline: none;
            }

            .jellyha-player-loading,
            .jellyha-player-error {
                display: flex;
                flex-direction: column;
                align-items: center;
                justify-content: center;
                padding: 48px 24px;
                gap: 16px;
                color: rgba(255, 255, 255, 0.85);
                text-align: center;
            }

            .jellyha-spinner {
                width: 36px;
                height: 36px;
                border: 3px solid rgba(255, 255, 255, 0.15);
                border-top-color: #03a9f4;
                border-radius: 50%;
                animation: jellyhaSpin 0.8s linear infinite;
            }

            @keyframes jellyhaSpin {
                to { transform: rotate(360deg); }
            }
        </style>
        `;
  }
  _renderPortal() {
    if (!this._portalContainer) return;
    if (!this._open) {
      et(l``, this._portalContainer);
      return;
    }
    const e = this._item, t = e?.type === "Audio";
    let i = "", o = e?.name || "Playing Media";
    e?.type === "Episode" ? (i = e.series_name || "", o = `${e.season != null && e.episode != null ? `S${e.season}:E${e.episode} • ` : ""}${e.name || "Episode"}`) : e?.type === "Movie" && e?.year ? i = `${e.year}` : t && e?.artist_name && (i = e.artist_name);
    const s = l`
            ${this._getPortalStyles()}
            <div class="jellyha-player-scrim" @click=${this.close}>
                <div class="jellyha-player-surface" @click=${(a) => a.stopPropagation()}>
                    <div class="jellyha-player-header">
                        <div class="jellyha-player-title-wrap">
                            ${i ? l`<span class="jellyha-player-subtitle">${i}</span>` : h}
                            <span class="jellyha-player-title" title="${o}">${o}</span>
                        </div>
                        <button class="jellyha-player-close-btn" @click=${this.close} aria-label="Close" title="Close">
                            <ha-icon icon="mdi:close"></ha-icon>
                        </button>
                    </div>

                    <div class="jellyha-player-content">
                        ${this._loading ? l`
                            <div class="jellyha-player-loading">
                                <div class="jellyha-spinner"></div>
                                <span>Loading stream...</span>
                            </div>
                        ` : this._error ? l`
                            <div class="jellyha-player-error">
                                <ha-icon icon="mdi:alert-circle-outline" style="--mdc-icon-size: 40px; color: #ff5252;"></ha-icon>
                                <span>${this._error}</span>
                            </div>
                        ` : t ? l`
                            <div class="jellyha-player-audio-wrap">
                                ${e?.poster_url ? l`
                                    <img class="jellyha-player-audio-poster" src="${e.poster_url}" alt="" />
                                ` : h}
                                <audio class="jellyha-player-audio" controls autoplay>
                                    <source src="${this._streamUrl}" type="${this._mimeType}">
                                    Audio format not supported.
                                </audio>
                            </div>
                        ` : l`
                            <video class="jellyha-player-video" controls autoplay playsinline crossorigin="anonymous" @loadedmetadata=${() => this._activateDefaultSubtitle()}>
                                ${!this._streamUrl?.includes(".m3u8") && this._mimeType !== "application/x-mpegURL" && this._mimeType !== "application/vnd.apple.mpegurl" ? l`
                                    <source src="${this._streamUrl}" type="${this._mimeType}">
                                ` : h}
                                ${this._subtitleTracks.map((a) => l`
                                    <track
                                        id="jellyha-track-${a.index}"
                                        kind="subtitles"
                                        label="${a.label}"
                                        srclang="${a.lang}"
                                        src="${a.url}"
                                    >
                                `)}
                                Video format not supported.
                            </video>
                        `}
                    </div>
                </div>
            </div>
        `;
    et(s, this._portalContainer);
  }
  render() {
    return h;
  }
};
Y([
  V({ attribute: !1 })
], q.prototype, "hass", 2);
Y([
  f()
], q.prototype, "_open", 2);
Y([
  f()
], q.prototype, "_loading", 2);
Y([
  f()
], q.prototype, "_error", 2);
Y([
  f()
], q.prototype, "_streamUrl", 2);
Y([
  f()
], q.prototype, "_mimeType", 2);
Y([
  f()
], q.prototype, "_playMethod", 2);
Y([
  f()
], q.prototype, "_playSessionId", 2);
Y([
  f()
], q.prototype, "_hlsToken", 2);
Y([
  f()
], q.prototype, "_item", 2);
Y([
  f()
], q.prototype, "_subtitleTracks", 2);
q = Y([
  ge("jellyha-browser-player")
], q);
let ze = null;
async function Ht(e) {
  (!ze || !document.body.contains(ze)) && (ze = document.createElement("jellyha-browser-player"), document.body.appendChild(ze)), await ze.play(e);
}
const qt = Pe`
  .list-metadata {
    display: flex !important;
    flex-direction: column !important;
    align-items: flex-start !important;
    gap: 3px;
    margin: 1px 0 2px 0 !important;
  }

  .idle-meta-row,
  .meta-line.idle-meta-row,
  .list-meta-row,
  .list-meta-pills {
    display: flex !important;
    flex-direction: row !important;
    align-items: center !important;
    flex-wrap: wrap !important;
    gap: 6px 8px;
    font-size: 12px;
    color: #ffffff;
    text-shadow: 0 1px 3px rgba(0, 0, 0, 0.65);
    margin: 0 !important;
    line-height: 1;
  }

  .list-meta-row {
    gap: 2px 6px !important;
  }

  .meta-line.idle-meta-row .media-type-badge.inline-badge,
  .idle-meta-row .media-type-badge.inline-badge,
  .list-metadata .media-type-badge.inline-badge,
  .media-type-badge.inline-badge {
    position: static !important;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    height: 22px;
    box-sizing: border-box;
    border-radius: 4px;
    font-size: 0.78rem;
    font-weight: 800;
    letter-spacing: 0.3px;
    text-transform: uppercase;
    padding: 1.5px 8px 0.5px 8px;
    line-height: 1;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.4);
    text-shadow: 0 1px 4px rgba(0, 0, 0, 0.5) !important;
    pointer-events: none;
    flex-shrink: 0;
  }

  .new-badge.inline-badge {
    position: static !important;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    height: 22px;
    box-sizing: border-box;
    border-radius: 4px;
    font-size: 0.78rem;
    font-weight: 800;
    letter-spacing: 0.3px;
    text-transform: uppercase;
    padding: 1.5px 8px 0.5px 8px;
    line-height: 1;
    background: #009ac7;
    color: #fff;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.4);
    text-shadow: 0 1px 4px rgba(0, 0, 0, 0.5) !important;
    pointer-events: none;
    flex-shrink: 0;
  }

  .status-badge.inline-badge {
    position: static !important;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    height: 22px;
    box-sizing: border-box;
    border-radius: 4px;
    font-size: 0.78rem;
    font-weight: 800;
    line-height: 1;
    padding: 0 6px;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.4);
    text-shadow: 0 1px 4px rgba(0, 0, 0, 0.5) !important;
    pointer-events: none;
    flex-shrink: 0;
  }

  .status-badge.inline-badge ha-icon {
    --mdc-icon-size: 14px;
    margin: 0;
  }

  .idle-meta-text,
  .meta-text {
    display: inline-flex;
    align-items: center;
    height: 22px;
    line-height: 1;
    font-size: 12px;
    font-weight: 500;
    color: #ffffff;
    white-space: nowrap;
    text-shadow: 0 1px 3px rgba(0, 0, 0, 0.65);
    transform: translateY(1px);
  }

  .list-metadata .meta-text,
  .list-year,
  .list-runtime,
  .list-date-added {
    display: inline-flex;
    align-items: center;
    height: 16px;
    line-height: 1;
    font-size: 11px !important;
    font-weight: 500;
    color: #ffffff;
    white-space: nowrap;
    text-shadow: 0 1px 3px rgba(0, 0, 0, 0.65);
    transform: translateY(0.5px);
  }

  .idle-dot,
  .meta-dot {
    opacity: 0.6;
    font-size: 12px;
    color: #ffffff;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    height: 22px;
    line-height: 1;
    transform: translateY(0.5px);
  }

  .list-metadata .meta-dot {
    opacity: 0.6;
    font-size: 11px !important;
    color: #ffffff;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    height: 16px;
    line-height: 1;
    transform: translateY(0.5px);
  }

  .idle-rating-pill,
  .rating-pill,
  .poster-badge.rating-pill,
  .rating.rating-pill,
  .list-metadata .rating-pill {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 3px;
    background: rgba(245, 158, 11, 0.25);
    border: 1px solid rgba(245, 158, 11, 0.45);
    backdrop-filter: blur(4px);
    -webkit-backdrop-filter: blur(4px);
    color: #fbbf24;
    height: 22px;
    padding: 1px 6px 0 6px;
    border-radius: 4px;
    font-size: 12px;
    font-weight: 700;
    line-height: 1;
    box-sizing: border-box;
    flex-shrink: 0;
    text-shadow: 0 1px 2px rgba(0, 0, 0, 0.8);
  }

  .featured-hero-scrim .rating-pill,
  .featured-hero-scrim .genre-pill,
  .featured-side .rating-pill,
  .featured-side .genre-pill,
  .list-metadata .rating-pill,
  .list-metadata .genre-pill,
  .media-item.list-item .rating-pill,
  .media-item.list-item .genre-pill {
    font-size: 11px !important;
  }

  .idle-rating-pill ha-icon,
  .rating-pill ha-icon,
  .poster-badge.rating-pill ha-icon,
  .rating.rating-pill ha-icon,
  .list-metadata .rating-pill ha-icon {
    --mdc-icon-size: 12px;
    width: 12px;
    height: 12px;
    display: flex;
    align-items: center;
    justify-content: center;
    transform: translateY(-1px);
    margin: 0;
    padding: 0;
    flex-shrink: 0;
    color: #fbbf24;
  }

  .idle-rating-pill span,
  .rating-pill span,
  .poster-badge.rating-pill span,
  .rating.rating-pill span,
  .list-metadata .rating-pill span {
    display: inline-flex;
    align-items: center;
    line-height: 1;
    transform: translateY(-0.5px);
  }

  .idle-genre-pill,
  .genre-pill.idle-genre-pill,
  .genre-pill,
  .poster-badge.genre-pill,
  .runtime.genre-pill,
  .list-metadata .genre-pill {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    background: rgba(255, 255, 255, 0.14);
    border: 1px solid rgba(255, 255, 255, 0.24);
    backdrop-filter: blur(4px);
    -webkit-backdrop-filter: blur(4px);
    height: 22px;
    padding: 0 7px !important;
    border-radius: 4px;
    font-size: 12px;
    color: #ffffff;
    font-weight: 500;
    line-height: 1 !important;
    box-sizing: border-box;
    flex-shrink: 0;
    text-shadow: 0 1px 2px rgba(0, 0, 0, 0.8);
  }

  .idle-genre-pill span,
  .genre-pill span,
  .poster-badge.genre-pill span,
  .runtime.genre-pill span,
  .list-metadata .genre-pill span {
    display: inline-flex;
    align-items: center;
    line-height: 1;
  }
`, Vt = Pe`
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
    --jf-poster-radius: var(--jellyha-poster-border-radius, 12px);
    --jf-transition: 0.2s ease-out;
    --jf-movie-badge: #AA5CC3;
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

  .carousel jellyha-media-item,
  .carousel .media-item {
    flex: 0 0 auto;
    width: auto;
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

  .grid jellyha-media-item {
    width: auto;
    justify-self: center;
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

  .grid.horizontal jellyha-media-item,
  .grid.horizontal .media-item {
    min-width: 140px;
    width: auto;
    flex: 0 0 auto;
  }

  /* List Wrapper for pagination */
  .list-wrapper {
    position: relative;
    overflow-y: auto; /* Enable vertical scrolling */
    overflow-x: hidden; /* Prevent horizontal scrolling */
    width: 100%;
    box-sizing: border-box;
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
    /* Uses exact column count with minmax(0, 1fr) so columns can shrink fluidly */
    grid-template-columns: repeat(var(--jf-list-columns, 1), minmax(0, 1fr));
    gap: 10px 14px;
    padding: 8px 14px 12px 14px;
    width: 100%;
    box-sizing: border-box;
  }

  .list jellyha-media-item {
    min-width: 0;
    width: 100%;
    display: block;
    box-sizing: border-box;
  }

  /* List item min-width handled via JavaScript ResizeObserver */

  /* Single column uses flex for better layout */
  .list.single-column {
    display: flex;
    flex-direction: column;
  }
  
  .list.single-column jellyha-media-item,
  .list.single-column .media-item {
    min-width: 0;
    width: 100%;
  }

  /* Extra bottom padding when pagination is enabled */
  .list.paginated {
    padding-bottom: 8px;
  }

  /* =========================================================================
     Featured Layout (Concept 1: Spotlight Hero)
     ========================================================================= */
  .featured-wrapper {
    position: relative;
    width: 100%;
    touch-action: pan-y;
    container-type: inline-size;
  }

  .featured {
    display: flex;
    align-items: stretch;
    gap: 10px;
    padding: 8px 14px 14px 14px;
    box-sizing: border-box;
    width: 100%;
    max-height: 460px;
  }

  .featured.single {
    justify-content: center;
  }

  .featured.single .featured-hero-container {
    flex: 0 0 auto;
    max-width: 290px;
    width: 100%;
    max-height: 435px;
    margin: 0 auto;
  }

  .featured-hero-container {
    flex: 0 0 42%;
    max-width: 290px;
    min-width: 180px;
    max-height: 435px;
    display: flex;
    flex-direction: column;
  }

  .featured.multi-column .featured-hero-container {
    flex: 0 0 auto;
    width: clamp(200px, 30%, 290px);
    max-width: 290px;
    max-height: 435px;
  }

  .featured.rows-2 .featured-hero-container {
    max-height: 250px;
    max-width: 175px;
    width: clamp(140px, 25%, 175px);
  }

  .featured.rows-2 .poster-container.featured-hero-poster {
    max-height: 250px;
  }

  .featured-hero-container .featured-main {
    width: 100%;
    height: 100%;
    display: flex;
    flex-direction: column;
  }

  .media-item.featured-hero {
    width: 100%;
    height: 100%;
    display: flex;
    flex-direction: column;
    cursor: pointer;
    position: relative;
    z-index: 1;
    user-select: none;
    -webkit-user-select: none;
  }

  .media-item.featured-hero:hover {
    z-index: 10;
  }

  .poster-container.featured-hero-poster {
    width: 100% !important;
    height: 100% !important;
    max-height: 435px;
    flex: 1;
    aspect-ratio: 2/3;
    border-radius: var(--jf-poster-radius, 12px);
    overflow: visible;
    position: relative;
    border: none;
    box-shadow: none;
    background: transparent;
  }

  .poster-container.featured-hero-poster .poster-inner {
    position: absolute;
    inset: 0;
    width: 100%;
    height: 100%;
    border-radius: var(--jf-poster-radius, 12px);
    overflow: hidden;
    border: 1px solid var(--ha-card-border-color, var(--jf-border-color));
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.4);
    transition: transform var(--jf-transition), box-shadow var(--jf-transition), border-color var(--jf-transition);
    transform-origin: center center;
    transform: translate3d(0, 0, 0);
    will-change: transform;
    z-index: 1;
    box-sizing: border-box;
  }

  .media-item.featured-hero:hover .poster-inner {
    transform: scale(1.02);
    border-color: rgba(255, 255, 255, 0.45);
    box-shadow: 
      0 0 6px rgba(255, 255, 255, 0.08),
      0 8px 22px rgba(0, 0, 0, 0.5);
    z-index: 10;
  }

  .media-item.featured-hero.playing .poster-inner {
    border-color: var(--jf-primary);
    box-shadow: 
      0 0 16px rgba(24, 188, 242, 0.3),
      0 4px 16px rgba(0, 0, 0, 0.4);
    box-shadow: 
      0 0 16px color-mix(in srgb, var(--jf-primary), transparent 65%),
      0 4px 16px rgba(0, 0, 0, 0.4);
  }

  .media-item.featured-hero.playing:hover .poster-inner {
    transform: scale(1.02);
    border-color: var(--jf-primary);
    box-shadow: 
      0 0 20px rgba(24, 188, 242, 0.45),
      0 8px 22px rgba(0, 0, 0, 0.5);
    box-shadow: 
      0 0 20px color-mix(in srgb, var(--jf-primary), transparent 50%),
      0 8px 22px rgba(0, 0, 0, 0.5);
    z-index: 10;
  }

  .poster-container.featured-hero-poster .poster {
    width: 100%;
    height: 100%;
    object-fit: cover;
    border-radius: inherit;
  }


  .featured-hero-scrim {
    position: absolute;
    inset: auto 0 0 0;
    padding: 40px 14px 14px 14px;
    background: linear-gradient(
      to top,
      rgba(0, 0, 0, 0.95) 0%,
      rgba(0, 0, 0, 0.75) 50%,
      rgba(0, 0, 0, 0.3) 80%,
      transparent 100%
    );
    display: flex;
    flex-direction: column;
    gap: 3px;
    z-index: 5;
    pointer-events: none;
  }

  .featured-hero-title {
    margin: 0;
    font-size: 1.15rem;
    font-weight: 700;
    color: #fff;
    line-height: 1.25;
    display: -webkit-box;
    -webkit-line-clamp: 2;
    -webkit-box-orient: vertical;
    overflow: hidden;
    text-overflow: ellipsis;
    text-shadow: 0 2px 6px rgba(0, 0, 0, 0.9);
  }

  .featured-hero-subtitle {
    margin: -1px 0 0 0;
    font-size: 0.85rem;
    font-weight: 500;
    color: rgba(255, 255, 255, 0.9);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    line-height: 1.15;
    text-shadow: 0 1px 4px rgba(0, 0, 0, 0.9);
  }

  /* Metadata Line & Now Playing Style Pills */
  .meta-line {
    display: flex;
    flex-direction: column;
    gap: 3px;
    font-size: 0.8rem;
    line-height: 1;
    margin-top: 2px;
  }

  .meta-text-row {
    display: flex;
    align-items: center;
    gap: 2px 6px;
    row-gap: 2px;
    flex-wrap: wrap;
    line-height: 1;
  }

  .meta-pills-row {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 4px 6px;
    line-height: 1;
  }

  .meta-text {
    display: inline-flex;
    align-items: center;
    height: 16px;
    line-height: 1;
    font-size: 11px;
    font-weight: 500;
    color: var(--jf-text-secondary);
    white-space: nowrap;
    transform: translateY(0.5px);
  }

  .meta-dot {
    opacity: 0.6;
    font-size: 11px;
    color: var(--jf-text-secondary);
    display: inline-flex;
    align-items: center;
    justify-content: center;
    height: 16px;
    line-height: 1;
    transform: translateY(0.5px);
  }

  /* Scrim overrides for hero poster metadata */
  .featured-hero-scrim .meta-text {
    font-size: 11px !important;
    color: rgba(255, 255, 255, 0.9);
    text-shadow: 0 1px 3px rgba(0, 0, 0, 0.85);
  }

  .featured-hero-scrim .meta-dot {
    font-size: 11px !important;
    color: rgba(255, 255, 255, 0.6);
  }

  /* Featured Queue (Side items) */
  .featured-side {
    flex: 1;
    min-width: 0;
    display: grid;
    grid-template-columns: repeat(var(--jf-featured-columns, 1), minmax(0, 1fr));
    grid-template-rows: repeat(var(--jf-featured-rows, 3), 1fr);
    grid-auto-flow: column;
    gap: 10px;
  }

  .featured-side jellyha-media-item {
    display: flex;
    min-height: 0;
    min-width: 0;
    width: 100%;
    height: 100%;
  }

  .featured-side .media-item.list-item,
  .featured-side .media-item.featured-queue-item {
    height: 100%;
    min-height: 120px;
    width: 100%;
  }

  .media-item.featured-queue-item {
    flex: 1;
    width: 100%;
    height: 100%;
    min-height: 123px;
    display: flex;
    flex-direction: row;
    align-items: center;
    gap: 12px;
    padding: 8px 12px;
    background: color-mix(in srgb, var(--jf-text), transparent 96%);
    border: 1px solid var(--ha-card-border-color, rgba(255, 255, 255, 0.16));
    border-radius: var(--jf-poster-radius, 12px) !important;
    overflow: hidden;
    position: relative;
    box-sizing: border-box;
    box-shadow: 0 3px 10px rgba(0, 0, 0, 0.3);
    transition: transform 0.24s cubic-bezier(0.2, 0.8, 0.2, 1), border-color 0.24s ease, box-shadow 0.24s ease, background 0.24s ease;
    cursor: pointer;
  }

  .media-item.featured-queue-item:hover,
  .media-item.featured-queue-item:focus-visible {
    background: color-mix(in srgb, var(--jf-text), transparent 90%);
    border-color: rgba(255, 255, 255, 0.35);
    transform: translateX(4px);
    box-shadow: 
      0 0 4px rgba(255, 255, 255, 0.04),
      0 4px 14px rgba(0, 0, 0, 0.3);
  }

  .media-item.featured-queue-item:hover .poster-container.featured-queue-poster .poster-inner {
    transform: none !important;
    box-shadow: none !important;
    border: none !important;
  }

  .media-item.featured-queue-item.playing {
    border-color: var(--jf-primary);
    background: color-mix(in srgb, var(--jf-primary), transparent 90%);
    box-shadow: 0 0 16px rgba(24, 188, 242, 0.3);
    box-shadow: 0 0 16px color-mix(in srgb, var(--jf-primary), transparent 65%);
  }

  .media-item.featured-queue-item.playing:hover {
    border-color: var(--jf-primary);
    box-shadow: 0 0 20px rgba(24, 188, 242, 0.45);
    box-shadow: 0 0 20px color-mix(in srgb, var(--jf-primary), transparent 50%);
  }

  .featured-queue-poster-wrapper {
    flex-shrink: 0;
  }

  .poster-container.featured-queue-poster {
    width: 68px !important;
    height: 102px !important;
    aspect-ratio: 2/3;
    border-radius: 6px;
    overflow: hidden;
    border: none !important;
    position: relative;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
  }

  .poster-container.featured-queue-poster .poster-inner {
    border-radius: 6px;
    width: 100%;
    height: 100%;
    position: relative;
    overflow: hidden;
  }

  .poster-container.featured-queue-poster .poster {
    width: 100%;
    height: 100%;
    object-fit: cover;
    border-radius: 6px;
  }

  .poster-container.featured-queue-poster .media-type-badge {
    font-size: 0.65rem;
    padding: 1px 5px;
    top: 4px;
    left: 4px;
    border-radius: 3px;
    letter-spacing: 0.2px;
  }

  .poster-container.featured-queue-poster .new-badge {
    font-size: 0.65rem;
    padding: 1px 5px;
    top: 4px;
    right: 4px;
    border-radius: 3px;
    letter-spacing: 0.2px;
  }

  .poster-container.featured-queue-poster .status-badge.watched {
    top: 4px;
    right: 4px;
    padding: 1px 5px;
    border-radius: 3px;
    font-size: 0.65rem;
  }

  .poster-container.featured-queue-poster .status-badge.watched ha-icon {
    --mdc-icon-size: 11px;
    margin: 0;
  }

  .poster-container.featured-queue-poster .status-badge.unplayed {
    top: 4px;
    right: 4px;
    padding: 1px 5px;
    border-radius: 3px;
    font-size: 0.65rem;
  }

  .featured-queue-info {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    justify-content: center;
    gap: 3px;
    overflow: hidden;
    padding-top: 14px;
  }

  .featured-queue-info .meta-text-row {
    flex-wrap: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .featured-queue-info .meta-pills-row {
    flex-wrap: nowrap;
    overflow: hidden;
  }

  .featured-queue-badges {
    position: absolute;
    top: 8px;
    right: 12px;
    z-index: 4;
    display: flex;
    align-items: center;
    gap: 4px;
    pointer-events: none;
  }

  .featured-queue-badges .media-type-badge,
  .featured-queue-badges .new-badge,
  .featured-queue-badges .status-badge {
    height: 22px;
    box-sizing: border-box;
    border-radius: 4px;
    font-size: 0.78rem;
    font-weight: 800;
    line-height: 1;
  }

  .featured-queue-badges .media-type-badge,
  .featured-queue-badges .new-badge {
    padding: 1.5px 8px 0.5px 8px;
  }

  .featured-queue-badges .status-badge {
    padding: 0 6px;
  }

  .featured-queue-badges .status-badge ha-icon {
    --mdc-icon-size: 14px;
    margin: 0;
  }

  .featured-queue-title-container {
    display: flex;
    flex-direction: column;
    gap: 1px;
    min-width: 0;
    width: 100%;
  }

  .featured-queue-subtitle,
  .featured-queue-series {
    margin: 0;
    font-size: 0.78rem;
    font-weight: 500;
    color: var(--jf-text-secondary);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    line-height: 1.15;
    box-sizing: border-box;
  }

  .featured-queue-title {
    margin: 0;
    font-size: 0.95rem;
    font-weight: 600;
    color: var(--jf-text);
    line-height: 1.2;
    max-height: 2.5em;
    overflow: hidden;
    word-break: break-word;
    transition: color 0.2s;
    box-sizing: border-box;
  }

  .media-item.featured-queue-item:hover .featured-queue-title {
    color: var(--jf-primary);
  }

  /* Cramped / Compact queue card layout (for 2+ columns) */
  .media-item.list-item.cramped,
  .media-item.featured-queue-item.cramped {
    flex-direction: column !important;
    justify-content: center !important;
    align-items: center !important;
    padding: 6px 8px !important;
    gap: 0 !important;
    height: 100% !important;
    min-height: 110px !important;
    box-sizing: border-box !important;
  }

  .media-item.list-item.cramped .list-info,
  .media-item.featured-queue-item.cramped .featured-queue-info {
    display: none !important;
  }

  .media-item.list-item.cramped .list-poster-wrapper,
  .media-item.featured-queue-item.cramped .featured-queue-poster-wrapper {
    margin: 0 auto !important;
    display: flex !important;
    justify-content: center !important;
    align-items: center !important;
    height: calc(100% - 10px) !important;
    max-height: 100px !important;
    z-index: 3 !important;
  }

  .media-item.list-item.cramped .poster-container,
  .media-item.featured-queue-item.cramped .poster-container.featured-queue-poster {
    width: auto !important;
    max-width: 72px !important;
    height: 100% !important;
    max-height: 100px !important;
    aspect-ratio: 2/3 !important;
    border-radius: var(--jf-poster-radius, 8px) !important;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.6) !important;
    border: none !important;
    margin: 0 auto !important;
    flex-shrink: 0 !important;
  }

  .media-item.list-item.cramped .poster-container .poster,
  .media-item.featured-queue-item.cramped .poster-container.featured-queue-poster .poster {
    width: 100%;
    height: 100%;
    object-fit: cover;
    border-radius: inherit;
  }

  .media-item.list-item.cramped .list-badges,
  .media-item.featured-queue-item.cramped .featured-queue-badges {
    position: absolute !important;
    top: 6px !important;
    right: 6px !important;
    float: none !important;
    max-width: calc(100% - 12px) !important;
    gap: 3px !important;
    flex-wrap: wrap !important;
    justify-content: flex-end !important;
    z-index: 4 !important;
  }

  .media-item.list-item.cramped .list-action,
  .media-item.featured-queue-item.cramped .featured-queue-action {
    position: absolute !important;
    bottom: 6px !important;
    right: 6px !important;
    z-index: 4 !important;
  }

  .media-item.list-item.cramped .list-card-backdrop-scrim,
  .media-item.featured-queue-item.cramped .featured-queue-backdrop-scrim {
    background: linear-gradient(
      180deg,
      rgba(0, 0, 0, 0.5) 0%,
      rgba(0, 0, 0, 0.25) 50%,
      rgba(0, 0, 0, 0.65) 100%
    ) !important;
  }

  .media-item.list-item.cramped:hover,
  .media-item.list-item.cramped:focus-visible,
  .media-item.featured-queue-item.cramped:hover,
  .media-item.featured-queue-item.cramped:focus-visible {
    transform: translateY(-2px) !important;
    border-color: rgba(255, 255, 255, 0.4) !important;
    box-shadow: 
      0 0 6px rgba(255, 255, 255, 0.08),
      0 6px 18px rgba(0, 0, 0, 0.45) !important;
  }

  /* Backdrop Fanart Background for Grid Cards */
  .media-item:not(.featured-queue-item):not(.list-item).has-backdrop {
    background: #111;
    border: 1px solid var(--ha-card-border-color, rgba(255, 255, 255, 0.18));
    border-radius: var(--jf-poster-radius, 12px);
    padding: 8px;
    position: relative;
    overflow: hidden;
    box-sizing: border-box;
    align-items: center;
    transition: border-color var(--jf-transition), box-shadow var(--jf-transition);
  }

  .media-item:not(.featured-queue-item):not(.list-item).has-backdrop:hover,
  .media-item:not(.featured-queue-item):not(.list-item).has-backdrop:focus-visible {
    border-color: rgba(255, 255, 255, 0.45);
    box-shadow: 0 8px 24px rgba(0, 0, 0, 0.7);
  }

  .media-item:not(.featured-queue-item):not(.list-item).has-backdrop.playing {
    border-color: var(--jf-primary);
    box-shadow: 0 0 16px rgba(24, 188, 242, 0.3);
  }

  .grid-card-backdrop-container {
    position: absolute;
    inset: 0;
    width: 100%;
    height: 100%;
    border-radius: inherit;
    overflow: hidden;
    z-index: 1;
    pointer-events: none;
  }

  .grid-card-backdrop {
    position: absolute;
    inset: 0;
    width: 100%;
    height: 100%;
    object-fit: cover;
    object-position: center;
    filter: brightness(1.05) saturate(1.05);
    transition: transform 0.4s cubic-bezier(0.2, 0.8, 0.2, 1), filter 0.3s ease;
  }

  .media-item.list-item .grid-card-backdrop {
    filter: blur(2px) brightness(0.92);
    -webkit-filter: blur(2px) brightness(0.92);
    transform: scale(1.03);
    transform-origin: center;
  }

  .media-item:not(.featured-queue-item):not(.list-item).has-backdrop:hover .grid-card-backdrop {
    transform: scale(1.05);
    filter: brightness(1.1) saturate(1.1);
  }

  .media-item.list-item.has-backdrop:hover .grid-card-backdrop {
    transform: scale(1.05);
    filter: blur(2px) brightness(0.98);
    -webkit-filter: blur(2px) brightness(0.98);
  }

  .grid-card-backdrop-scrim {
    position: absolute;
    inset: 0;
    background: linear-gradient(
      180deg,
      rgba(0, 0, 0, 0.35) 0%,
      rgba(0, 0, 0, 0.6) 55%,
      rgba(0, 0, 0, 0.94) 100%
    );
    z-index: 2;
    pointer-events: none;
  }

  .media-item:not(.featured-queue-item):not(.list-item).has-backdrop .poster-container {
    position: relative;
    z-index: 3;
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.7);
    border: 1px solid rgba(255, 255, 255, 0.22);
  }

  .media-item:not(.featured-queue-item):not(.list-item).has-backdrop .media-info-below {
    position: relative;
    z-index: 3;
    width: 100%;
    text-shadow: 0 1px 4px rgba(0, 0, 0, 0.9);
  }

  /* Backdrop Fanart Background for Featured Queue Cards */
  .media-item.featured-queue-item.has-backdrop {
    background: #111;
    border: 1px solid var(--ha-card-border-color, rgba(255, 255, 255, 0.18));
  }

  .featured-queue-backdrop-container {
    position: absolute;
    inset: 0;
    width: 100%;
    height: 100%;
    border-radius: inherit;
    overflow: hidden;
    z-index: 1;
    pointer-events: none;
  }

  .featured-queue-backdrop {
    position: absolute;
    inset: 0;
    width: 100%;
    height: 100%;
    object-fit: cover;
    object-position: center 25%;
    filter: blur(2px) brightness(0.92);
    -webkit-filter: blur(2px) brightness(0.92);
    transform: scale(1.03);
    transform-origin: center;
    transition: transform 0.4s cubic-bezier(0.2, 0.8, 0.2, 1), filter 0.3s ease;
  }

  .media-item.featured-queue-item:hover .featured-queue-backdrop {
    transform: scale(1.05);
    filter: blur(2px) brightness(0.98);
    -webkit-filter: blur(2px) brightness(0.98);
  }

  .media-item.featured-queue-item:hover .featured-queue-poster .poster-inner {
    transform: none;
    box-shadow: none;
    border-color: transparent;
  }

  .featured-queue-backdrop-scrim {
    position: absolute;
    inset: 0;
    background: linear-gradient(
      90deg,
      rgba(0, 0, 0, 0.35) 0%,
      rgba(0, 0, 0, 0.42) 35%,
      rgba(0, 0, 0, 0.58) 70%,
      rgba(0, 0, 0, 0.45) 100%
    );
    z-index: 2;
    pointer-events: none;
  }

  .media-item.featured-queue-item.has-backdrop .featured-queue-poster-wrapper {
    position: relative;
    z-index: 3;
  }

  .media-item.featured-queue-item.has-backdrop .poster-container.featured-queue-poster {
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.7);
    border: none !important;
  }

  .media-item.featured-queue-item .featured-queue-info {
    position: relative;
    z-index: 3;
    display: flex;
    flex-direction: column;
    justify-content: center;
    gap: 3px;
    flex: 1;
    min-width: 0;
  }

  .featured-queue-header-row {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
    line-height: 1;
    margin-bottom: 2px;
  }

  .media-type-badge.inline-badge {
    position: static !important;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    height: 22px;
    padding: 1.5px 8px 0.5px 8px;
    border-radius: 4px;
    font-size: 0.78rem;
    font-weight: 800;
    text-transform: uppercase;
    letter-spacing: 0.3px;
    line-height: 1;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.4);
    text-shadow: 0 1px 4px rgba(0, 0, 0, 0.5);
    flex-shrink: 0;
    box-sizing: border-box;
  }

  .new-badge.inline-badge {
    position: static !important;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    height: 22px;
    padding: 1.5px 8px 0.5px 8px;
    border-radius: 4px;
    font-size: 0.78rem;
    font-weight: 800;
    text-transform: uppercase;
    letter-spacing: 0.3px;
    line-height: 1;
    background: #009ac7;
    color: #fff;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.4);
    text-shadow: 0 1px 4px rgba(0, 0, 0, 0.5);
    flex-shrink: 0;
    box-sizing: border-box;
  }

  .status-badge.inline-badge {
    position: static !important;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    height: 22px;
    padding: 0 6px;
    border-radius: 4px;
    font-size: 0.78rem;
    font-weight: 800;
    line-height: 1;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.4);
    flex-shrink: 0;
    box-sizing: border-box;
  }

  .status-badge.inline-badge ha-icon {
    --mdc-icon-size: 14px;
    margin: 0;
  }

  .featured-queue-subtitle,
  .featured-queue-series {
    margin: 0;
    font-size: 0.76rem;
    font-weight: 500;
    color: var(--jf-text-secondary);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .media-item.featured-queue-item.has-backdrop .featured-queue-subtitle,
  .media-item.featured-queue-item.has-backdrop .featured-queue-series {
    color: rgba(255, 255, 255, 0.85);
    text-shadow: 0 1px 3px rgba(0, 0, 0, 0.85);
  }

  .media-item.featured-queue-item.has-backdrop .featured-queue-title {
    color: #ffffff;
    text-shadow: 0 1px 4px rgba(0, 0, 0, 0.9);
  }

  .media-item.featured-queue-item:hover .featured-queue-title,
  .media-item.featured-queue-item.has-backdrop:hover .featured-queue-title,
  .media-item.featured-queue-item:focus-visible .featured-queue-title,
  .media-item.featured-queue-item.has-backdrop:focus-visible .featured-queue-title {
    color: var(--jf-primary) !important;
  }

  .media-item.featured-queue-item.has-backdrop .meta-text {
    color: rgba(255, 255, 255, 0.9);
    text-shadow: 0 1px 3px rgba(0, 0, 0, 0.85);
  }

  .media-item.featured-queue-item.has-backdrop .meta-dot {
    color: rgba(255, 255, 255, 0.6);
  }


  .media-item.featured-queue-item.has-backdrop .featured-queue-action {
    position: relative;
    z-index: 3;
  }

  .media-item.featured-queue-item.has-backdrop:hover,
  .media-item.featured-queue-item.has-backdrop:focus-visible {
    border-color: rgba(255, 255, 255, 0.35);
    box-shadow: 
      0 0 4px rgba(255, 255, 255, 0.04),
      0 4px 14px rgba(0, 0, 0, 0.3);
    transform: translateX(4px);
  }

  .media-item.featured-queue-item.has-backdrop.playing {
    border-color: var(--jf-primary);
    box-shadow: 0 0 14px color-mix(in srgb, var(--jf-primary), transparent 60%);
  }

  .list-action,
  .featured-queue-action {
    flex-shrink: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    padding-right: 4px;
  }

  .list-playing-icon,
  .featured-queue-playing-icon {
    --mdc-icon-size: 20px;
    color: var(--jf-primary);
    animation: pulse 1.5s infinite ease-in-out;
  }

  /* Responsive Stacking: On screens under 640px, stack hero and side cleanly */
  @media (max-width: 640px) {
    .featured {
      flex-direction: column;
      align-items: center;
      gap: 16px;
      padding: 12px 14px 16px 14px;
      max-height: none;
    }

    .featured-hero-container {
      flex: 0 0 auto;
      max-width: 250px;
      width: 100%;
      height: 375px;
      max-height: 380px;
    }

    .featured.multi-column .featured-hero-container {
      width: 100%;
      max-width: 250px;
      height: 375px;
      max-height: 380px;
    }

    .featured-side {
      width: 100%;
      gap: 10px;
      display: grid !important;
      grid-template-columns: repeat(var(--jf-featured-columns, 1), minmax(0, 1fr)) !important;
      grid-template-rows: repeat(3, auto) !important;
      grid-auto-flow: column;
    }

    .featured-side jellyha-media-item {
      flex: 0 0 auto;
      width: 100%;
    }

    .featured-side .media-item.list-item,
    .media-item.featured-queue-item {
      flex: 0 0 auto;
      min-height: 110px;
      padding: 8px 12px;
    }
  }

  .media-item.list-item {
    flex-direction: row;
    align-items: flex-start;
    gap: 10px;
    height: 136px;
    width: 100%;
    min-width: 0;
    box-sizing: border-box;
    overflow: hidden;
    position: relative;
    background: color-mix(in srgb, var(--jf-text), transparent 96%);
    border: 1px solid var(--ha-card-border-color, rgba(255, 255, 255, 0.18));
    border-radius: var(--jf-poster-radius, 12px);
    padding: 10px;
    box-shadow: 0 3px 10px rgba(0, 0, 0, 0.3);
    transition: transform 0.24s cubic-bezier(0.2, 0.8, 0.2, 1), border-color 0.24s ease, box-shadow 0.24s ease, background 0.24s ease;
  }

  .media-item.list-item:hover,
  .media-item.list-item:focus-visible {
    background: color-mix(in srgb, var(--jf-text), transparent 90%);
    border-color: rgba(255, 255, 255, 0.45);
    box-shadow: 
      0 0 4px rgba(255, 255, 255, 0.04),
      0 6px 18px rgba(0, 0, 0, 0.4);
    transform: translateX(4px);
  }

  .media-item.list-item.playing {
    border-color: var(--jf-primary);
    box-shadow: 0 0 16px rgba(24, 188, 242, 0.3);
  }

  /* Specific override for List view */
  .media-item.list-item .poster-container {
    width: 76px !important;
    flex-shrink: 0;
    border: none !important;
  }

  /* Do not enhance poster border, zoom, or box-shadow on hover in list layout */
  .media-item.list-item:hover .poster-container,
  .media-item.list-item.has-backdrop:hover .poster-container {
    border: none !important;
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.7) !important;
    transform: none !important;
  }

  .media-item.list-item:hover .poster-inner,
  .media-item.list-item.has-backdrop:hover .poster-inner {
    transform: none !important;
    box-shadow: none !important;
    border: none !important;
  }

  /* Backdrop Fanart Background for List Cards */
  .media-item.list-item.has-backdrop {
    background: #111;
    border: 1px solid var(--ha-card-border-color, rgba(255, 255, 255, 0.18));
    border-radius: var(--jf-poster-radius, 12px);
    padding: 10px;
    position: relative;
    overflow: hidden;
    box-sizing: border-box;
    height: 136px;
    width: 100%;
    min-width: 0;
    transition: border-color 0.24s ease, box-shadow 0.24s ease, transform 0.24s cubic-bezier(0.2, 0.8, 0.2, 1);
  }

  .media-item.list-item.has-backdrop:hover,
  .media-item.list-item.has-backdrop:focus-visible {
    background: #111;
    border-color: rgba(255, 255, 255, 0.45);
    box-shadow: 
      0 0 4px rgba(255, 255, 255, 0.04),
      0 6px 18px rgba(0, 0, 0, 0.4);
    transform: translateX(4px);
  }

  .media-item.list-item.has-backdrop.playing {
    border-color: var(--jf-primary);
    box-shadow: 0 0 16px rgba(24, 188, 242, 0.3);
  }

  .media-item.list-item .list-poster-wrapper,
  .media-item.list-item.has-backdrop .list-poster-wrapper {
    position: relative;
    z-index: 3;
  }

  .featured-side .poster-container,
  .media-item.list-item .poster-container,
  .media-item.list-item.has-backdrop .poster-container {
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.7);
    border: none !important;
  }

  .media-item.list-item .list-info,
  .media-item.list-item.has-backdrop .list-info {
    position: relative;
    z-index: 3;
  }

  .media-item.list-item.has-backdrop .list-info {
    text-shadow: 0 1px 4px rgba(0, 0, 0, 0.9);
  }

  .media-item.list-item.has-backdrop .list-title {
    color: #fff;
    text-shadow: 0 1px 4px rgba(0, 0, 0, 0.9);
  }

  .media-item.list-item.has-backdrop .list-subtitle {
    color: rgba(255, 255, 255, 0.85);
    text-shadow: 0 1px 3px rgba(0, 0, 0, 0.85);
  }

  .media-item.list-item.has-backdrop .list-description {
    color: rgba(255, 255, 255, 0.8);
    text-shadow: 0 1px 3px rgba(0, 0, 0, 0.85);
  }

  .list-card-backdrop-scrim {
    position: absolute;
    inset: 0;
    background: linear-gradient(
      90deg,
      rgba(0, 0, 0, 0.35) 0%,
      rgba(0, 0, 0, 0.42) 35%,
      rgba(0, 0, 0, 0.58) 70%,
      rgba(0, 0, 0, 0.45) 100%
    );
    z-index: 2;
    pointer-events: none;
  }

  /* List poster wrapper */
  .list-poster-wrapper {
    display: flex;
    flex-direction: column;
    justify-content: flex-start;
    align-self: flex-start;
    flex-shrink: 0;
  }

  /* Vertical alignment when title is hidden - align with poster top */
  .list-item.no-title .list-info {
    padding-top: 4px;
  }

  /* List info container */
  .list-info {
    flex: 1 1 0;
    display: flex;
    flex-direction: column;
    gap: 3px;
    min-width: 0;
    width: 100%;
    height: 100%;
    overflow: hidden;
    justify-content: flex-start;
    padding-top: 5px;
    box-sizing: border-box;
  }

  .list-header {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 6px;
    width: 100%;
    min-width: 0;
  }

  .list-title-container {
    flex: 1 1 0;
    min-width: 0;
    overflow: hidden;
    display: flex;
    flex-direction: column;
  }

  .list-title {
    margin: 3px 0 0 0;
    font-size: 1.0rem;
    font-weight: 600;
    color: var(--jf-text);
    line-height: 1.25;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    min-width: 0;
  }

  .list-subtitle {
    margin: 1px 0 0 0;
    font-size: 0.84rem;
    font-weight: 500;
    color: var(--jf-text-secondary);
    line-height: 1.2;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    min-width: 0;
    transition: color 0.2s ease;
  }

  .media-item.list-item:hover .list-subtitle {
    color: var(--jf-text);
  }

  .list-badges {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    flex-shrink: 0;
    margin-left: auto;
    margin-top: -5px;
  }

  .list-header .media-type-badge.list-type-badge {
    position: static !important;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    height: 22px;
    box-sizing: border-box;
    border-radius: 4px;
    font-size: 0.78rem;
    font-weight: 800;
    letter-spacing: 0.3px;
    text-transform: uppercase;
    padding: 1.5px 8px 0.5px 8px;
    line-height: 1;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.4);
    text-shadow: 0 1px 4px rgba(0, 0, 0, 0.5) !important;
    pointer-events: none;
    flex-shrink: 0;
  }

  .list-badges .new-badge.inline-badge {
    position: static !important;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    height: 22px;
    box-sizing: border-box;
    border-radius: 4px;
    font-size: 0.78rem;
    font-weight: 800;
    letter-spacing: 0.3px;
    text-transform: uppercase;
    padding: 1.5px 8px 0.5px 8px;
    line-height: 1;
    background: #009ac7;
    color: #fff;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.4);
    text-shadow: 0 1px 4px rgba(0, 0, 0, 0.5) !important;
    pointer-events: none;
    flex-shrink: 0;
  }

  .list-badges .status-badge.inline-badge {
    position: static !important;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    height: 22px;
    box-sizing: border-box;
    border-radius: 4px;
    font-size: 0.78rem;
    font-weight: 800;
    line-height: 1;
    padding: 0 6px;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.4);
    text-shadow: 0 1px 4px rgba(0, 0, 0, 0.5) !important;
    pointer-events: none;
    flex-shrink: 0;
  }

  .list-badges .status-badge.inline-badge ha-icon {
    --mdc-icon-size: 14px;
    margin: 0;
  }

  ${qt}

  .media-item.list-item .list-meta-pills {
    display: flex !important;
    flex-direction: row !important;
    align-items: center !important;
    flex-wrap: nowrap !important;
    overflow: hidden !important;
    gap: 5px;
    min-width: 0;
    max-width: 100%;
  }

  .media-item.list-item .list-genre-pill {
    display: inline-flex !important;
    align-items: center;
    justify-content: center;
    max-width: 95px;
    min-width: 0;
    overflow: hidden !important;
    white-space: nowrap !important;
    flex-shrink: 1 !important;
    padding: 0 6px !important;
    box-sizing: border-box;
  }

  .media-item.list-item .list-genre-pill span {
    display: inline-block !important;
    overflow: hidden !important;
    text-overflow: ellipsis !important;
    white-space: nowrap !important;
    max-width: 100%;
    min-width: 0;
  }

  .list-type-badge.movie {
    background: var(--jf-movie-badge);
  }

  .list-type-badge.series,
  .list-type-badge.episode {
    background: var(--jf-series-badge);
  }

  .list-description {
    margin: 0;
    font-size: 11px !important;
    color: var(--jf-text-secondary);
    line-height: 1.3;
    display: -webkit-box;
    -webkit-line-clamp: 2;
    -webkit-box-orient: vertical;
    overflow: hidden;
    text-overflow: ellipsis;
    max-height: calc(1.3em * 2);
    box-sizing: border-box;
  }

  .media-item.list-item.has-subtitle .list-description,
  .media-item.list-item:has(.list-subtitle) .list-description,
  .media-item.list-item.meta-wrapped .list-description {
    -webkit-line-clamp: 1;
    max-height: calc(1.3em * 1);
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
    transform: none;
    transition: none;
  }

  .media-item.list-item:hover .list-year,
  .media-item.list-item:hover .list-runtime,
  .media-item.list-item:hover .list-date-added {
    color: var(--jf-text);
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
    transition: transform 0.15s ease-out;
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
    box-shadow: 0 0 16px rgba(24, 188, 242, 0.3);
    box-shadow: 0 0 16px color-mix(in srgb, var(--jf-primary), transparent 65%);
  }

  .media-item.playing:hover .poster-container {
    border-color: var(--jf-primary);
    box-shadow: 0 0 20px rgba(24, 188, 242, 0.45);
    box-shadow: 0 0 20px color-mix(in srgb, var(--jf-primary), transparent 50%);
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

  /* Card click and press effect on the whole card (not poster) */
  .media-item:active,
  .media-item.active-press {
    transform: scale(0.98);
    transition: transform 0.08s ease-out;
  }

  .media-item.list-item:active,
  .media-item.list-item.active-press,
  .media-item.featured-queue-item:active,
  .media-item.featured-queue-item.active-press {
    transform: translateX(2px) scale(0.98) !important;
    transition: transform 0.08s ease-out !important;
  }

  .media-item:active .poster-container,
  .media-item.active-press .poster-container {
    transform: none !important;
  }

  /* Disable vignette overlay for list items on hover */
  .media-item.list-item .poster-inner::after,
  .media-item.list-item:hover .poster-inner::after {
    display: none !important;
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
    text-shadow: 0 1px 4px rgba(0, 0, 0, 0.5);
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
    text-shadow: 0 1px 4px rgba(0, 0, 0, 0.5);
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
    text-shadow: 0 1px 4px rgba(0, 0, 0, 0.5);
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
    text-shadow: 0 1px 4px rgba(0, 0, 0, 0.5);
  }

  /* Poster Overlay Badges - Bottom corners (aesthetics centralized in sharedMetaRowStyles) */
  .rating {
    position: absolute;
    bottom: 6px;
    right: 6px;
    z-index: 5;
    transition: opacity var(--jf-transition);
  }

  .media-item:hover .rating {
    opacity: 0;
  }

  .runtime {
    position: absolute;
    bottom: 6px;
    left: 6px;
    z-index: 5;
    transition: opacity var(--jf-transition);
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
    justify-content: center;
    align-items: center;
    z-index: 10;
    border-radius: var(--jf-poster-radius);
    animation: fadeIn 0.3s ease-out;
    cursor: pointer;
  }

  .now-playing-controls {
    display: flex;
    justify-content: center;
    align-items: center;
    z-index: 3;
  }

  .now-playing-controls .play-pause-wrapper {
    position: relative;
    display: flex;
    align-items: center;
    justify-content: center;
    touch-action: none;
    border-radius: 50%;
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
    cursor: pointer;
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

  /* Stop ring SVG */
  .now-playing-controls .stop-ring {
    position: absolute;
    top: 50%;
    left: 50%;
    width: 40px;
    height: 40px;
    transform: translate(-50%, -50%);
    pointer-events: none;
    z-index: 10;
  }

  /* Stop confirmed pulse animation */
  .now-playing-controls .play-pause-wrapper.stop-pulse {
    animation: stopPulse 0.5s ease-out;
  }

  @keyframes stopPulse {
    0% { transform: scale(1); box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.5); }
    50% { transform: scale(1.15); box-shadow: 0 0 0 12px rgba(239, 68, 68, 0); }
    100% { transform: scale(1); box-shadow: 0 0 0 0 rgba(239, 68, 68, 0); }
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
`, Ye = {
  en: {
    loading: "Loading…",
    no_media: "No recent media found",
    error: "Error loading media",
    new: "New",
    minutes: "min",
    play: "Play",
    pause: "Pause",
    stop: "Stop",
    previous: "Previous",
    next: "Next",
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
    "editor.show_device_name": "Show Device Name",
    "editor.show_user": "Show User",
    "editor.show_time": "Show Elapsed / Remaining Time",
    "editor.show_background": "Show Background",
    "editor.use_series_image": "Use Series Cover Image",
    "editor.show_media_type_badge": "Show Media Type Badge",
    "editor.badge_style": "Badge Style",
    "editor.badge_style_poster": "Badge on Poster (Default)",
    "editor.badge_style_header": "Badge in Header",
    "editor.badge_style_inline": "Inline with Metadata",
    "editor.badge_style_none": "Hidden",
    "editor.show_watched_status": "Show Watched Status",
    "editor.show_date_added": "Show Date Added",
    "editor.show_description": "Show Description",
    "editor.layout": "Layout",
    "editor.layout_carousel": "Carousel",
    "editor.layout_grid": "Grid",
    "editor.layout_list": "List",
    "editor.layout_featured": "Featured",
    "editor.featured_columns_helper": "Number of side card columns beside the hero poster (1 to 4)",
    "editor.featured_rows": "Rows",
    "editor.featured_rows_helper": "Number of side card rows beside the hero poster (2 or 3)",
    "editor.featured_queue_backdrop": "Show Card Backdrop",
    "editor.featured_queue_backdrop_helper": "Show backdrop fanart in the background of cards",
    "editor.show_card_backdrop": "Show Card Backdrop",
    "editor.show_card_backdrop_helper": "Show backdrop fanart in the background of cards",
    "editor.media_type": "Media Type",
    "editor.media_type_both": "Movies & TV Shows",
    "editor.media_type_movies_episodes": "Movies & Episodes",
    "editor.media_type_movies": "Movies Only",
    "editor.media_type_series": "TV Shows Only",
    "editor.media_type_episodes": "Episodes Only",
    "editor.media_type_next_up": "Next Up",
    "editor.tv_content": "TV Content",
    "editor.tv_content_series": "Shows / Series",
    "editor.tv_content_episodes": "Episodes",
    "editor.items_per_page": "Items Per Page",
    "editor.max_pages": "Max Pages (0 = no limit)",
    "editor.auto_swipe": "Auto Swipe (sec, 0 = off)",
    "editor.new_badge_days": "New Badge Days (0 = off)",
    "editor.click_action": "Single Tap (Click)",
    "editor.hold_action": "Long Press (Hold)",
    "editor.double_tap_action": "Double Tap",
    "editor.action_jellyfin": "Open in Jellyfin",
    "editor.action_play_browser": "Play in Browser",
    "editor.action_play_client": "Play on Jellyfin Client",
    "editor.action_cast": "Cast to Chromecast",
    "editor.action_more_info": "More Information",
    "editor.action_trailer": "Watch Trailer",
    "editor.action_none": "No Action",
    "editor.action_call_service": "Run Script",
    "editor.service_to_call": "Script",
    "editor.service_data": 'Service Data (Optional JSON, e.g. {"player":"tv"})',
    "editor.default_cast_device": "Default Cast Device",
    "editor.default_client_device": "Default Jellyfin Client",
    "editor.no_client_devices_warning": "No Jellyfin client devices configured in the JellyHA integration. Please configure devices in Settings → Devices & services → JellyHA → Configure.",
    "editor.enable_browser_player": 'Enable "Play in Browser"',
    "editor.show_now_playing_overlay": 'Show "Now Playing" Overlay on Posters',
    "editor.enable_custom_play_actions": "Custom Play Actions",
    "editor.custom_play_actions_helper": "When enabled, play targets in the More Info dialog are controlled by modal_play_actions in YAML. You can configure browser playback (type: browser), Cast devices (type: cast), multiple scripts (type: script), or custom labels. When disabled, standard card settings are used.",
    "editor.custom_play_actions_none_configured": "None of the actions have been selected yet. Configure a Cast device, enable browser playback, or configure a Script above, or define custom play targets in YAML under modal_play_actions.",
    "modal.play_on": "Play On",
    "modal.play_on_client": "Play on Client",
    "modal.play_in_browser": "Play in Browser",
    "modal.cancel": "Cancel",
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
    "editor.media_player": "Media Player",
    "editor.now_playing_sensor": "Media Player",
    "editor.auto": "Auto",
    "editor.show_search": "Show Search Bar",
    "editor.show_controls": "Show Playback Controls",
    "editor.horizontal_alignment": "Carousel Alignment",
    "editor.alignment_center": "Center",
    "editor.alignment_left": "Left",
    "editor.subtitles": "Cast Subtitles",
    "editor.subtitles_auto": "Auto (Jellyfin User Profile)",
    "editor.subtitles_none": "None (Disabled)",
    "editor.subtitles_forced_only": "Forced Only",
    "editor.subtitles_custom": "Custom Language List",
    "editor.subtitle_languages": "Cast Subtitle Priority (e.g. sl, en)",
    "editor.idle_section_title": "Ambient Showcase (When Idle)",
    "editor.idle_backdrop_cycle": "Cycle Library Media when Idle",
    "editor.idle_cycle_interval": "Cycle Interval (seconds)",
    "editor.idle_display_mode": "Display Style",
    "editor.idle_display_mode_backdrop": "Full Fanart Backdrop (Screensaver)",
    "editor.idle_display_mode_card": "Card Layout (Poster + Backdrop)",
    "editor.playing_display_mode": "Playback Display Style",
    "editor.playing_display_mode_card": "Card Layout (Poster + Details)",
    "editor.playing_display_mode_full_art": "Full Artwork (Cinematic Hero)",
    "editor.playing_artwork_source": "Playback Artwork Image",
    "editor.playing_artwork_source_backdrop": "Fanart Backdrop",
    "editor.playing_artwork_source_poster": "Poster",
    "editor.idle_media_type": "Media Types to Showcase",
    "editor.idle_content_source": "Content to Showcase",
    "editor.idle_source_random": "Random Library Media",
    "editor.idle_source_recent": "Recently Added",
    "editor.idle_source_latest_movie": "Latest Movie Added",
    "editor.idle_source_latest_episode": "Latest Episode Added",
    "editor.idle_source_latest_both": "Alternating Latest Movie & Episode",
    "editor.idle_recent_limit": "Number of Recent Items",
    "editor.power_section_title": "TV / Display Power",
    "editor.power_entity": "Power Entity (TV, Switch, Script, etc.)",
    "editor.power_entity_helper": "Optional. If not set, the default selected Media Player will be used.",
    "editor.power_state_entity": "Power State Entity (Optional state sensor)",
    "editor.show_power_button": "Show Power Button",
    "editor.stop_on_power_off": "Stop Media on Power Off",
    "editor.volume_section_title": "Volume Controls",
    "editor.show_volume": "Show Volume Controls",
    "editor.volume_entity": "Volume Entity (External AVR/Soundbar, Optional)",
    "editor.volume_entity_helper": "Optional. If not set, the default selected Media Player will be used.",
    "editor.show_volume_step_buttons": "Show Step Buttons (− / +)",
    "editor.volume_step": "Volume Step %",
    "card.latest_movie_badge": "LATEST MOVIE",
    "card.latest_episode_badge": "LATEST EPISODE",
    "card.latest_series_badge": "LATEST SERIES",
    "idle.spotlight": "LIBRARY SPOTLIGHT",
    "idle.discover": "DISCOVER",
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
    previous: "Zurück",
    next: "Weiter",
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
    "editor.show_device_name": "Gerätename anzeigen",
    "editor.show_user": "Benutzer anzeigen",
    "editor.show_time": "Verstrichene / Restzeit anzeigen",
    "editor.show_background": "Hintergrund anzeigen",
    "editor.use_series_image": "Serien-Cover verwenden",
    "editor.show_media_type_badge": "Medientyp-Abzeichen anzeigen",
    "editor.badge_style": "Abzeichen-Stil",
    "editor.badge_style_poster": "Abzeichen auf Poster (Standard)",
    "editor.badge_style_header": "Abzeichen in Kopfzeile",
    "editor.badge_style_inline": "In Metadaten eingebettet",
    "editor.badge_style_none": "Ausgeblendet",
    "editor.show_watched_status": "Gesehen-Status anzeigen",
    "editor.show_date_added": "Hinzugefügt am anzeigen",
    "editor.show_description": "Beschreibung anzeigen",
    "editor.layout": "Layout",
    "editor.layout_carousel": "Karussell",
    "editor.layout_grid": "Raster",
    "editor.layout_list": "Liste",
    "editor.layout_featured": "Hervorgehoben",
    "editor.featured_columns_helper": "Anzahl der Spalten für Seitenkarten neben dem Hauptposter (1 bis 4)",
    "editor.featured_rows": "Zeilen",
    "editor.featured_rows_helper": "Anzahl der Zeilen für Seitenkarten neben dem Hauptposter (2 oder 3)",
    "editor.featured_queue_backdrop": "Karten-Hintergrundbild anzeigen",
    "editor.featured_queue_backdrop_helper": "Fanart-Hintergrundbild in den Karten anzeigen",
    "editor.show_card_backdrop": "Karten-Hintergrundbild anzeigen",
    "editor.show_card_backdrop_helper": "Fanart-Hintergrundbild in den Karten anzeigen",
    "editor.media_type": "Medientyp",
    "editor.media_type_both": "Filme & Serien",
    "editor.media_type_movies_episodes": "Filme & Episoden",
    "editor.media_type_movies": "Nur Filme",
    "editor.media_type_series": "Nur Serien",
    "editor.media_type_episodes": "Nur Episoden",
    "editor.media_type_next_up": "Als Nächstes",
    "editor.tv_content": "TV-Inhalt",
    "editor.tv_content_series": "Shows / Serien",
    "editor.tv_content_episodes": "Episoden",
    "editor.items_per_page": "Elemente pro Seite",
    "editor.max_pages": "Max. Seiten (0 = kein Limit)",
    "editor.auto_swipe": "Auto-Swipe (Sek., 0 = aus)",
    "editor.new_badge_days": 'Badge "Neu" Tage (0 = aus)',
    "editor.click_action": "Kurz drücken (Klick)",
    "editor.hold_action": "Lang drücken (Halten)",
    "editor.double_tap_action": "Doppeltippen",
    "editor.action_jellyfin": "In Jellyfin öffnen",
    "editor.action_play_browser": "Im Browser abspielen",
    "editor.action_play_client": "Auf Jellyfin-Client abspielen",
    "editor.action_cast": "An Chromecast senden",
    "editor.action_more_info": "Mehr Informationen",
    "editor.action_trailer": "Trailer ansehen",
    "editor.action_none": "Keine Aktion",
    "editor.action_call_service": "Skript ausführen",
    "editor.service_to_call": "Skript",
    "editor.service_data": 'Servicedaten (Optional JSON, z.B. {"player":"tv"})',
    "editor.default_cast_device": "Standard-Chromecast-Gerät",
    "editor.default_client_device": "Standard-Jellyfin-Client",
    "editor.no_client_devices_warning": "Keine Jellyfin-Client-Geräte in der JellyHA-Integration konfiguriert. Bitte konfigurieren Sie Geräte unter Einstellungen → Geräte & Dienste → JellyHA → Konfigurieren.",
    "editor.enable_browser_player": '"Im Browser abspielen" aktivieren',
    "editor.show_now_playing_overlay": '"Jetzt läuft"-Overlay anzeigen',
    "editor.enable_custom_play_actions": "Benutzerdefinierte Wiedergabeaktionen",
    "editor.custom_play_actions_helper": "Wenn aktiviert, werden Wiedergabeziele im Dialogfeld durch modal_play_actions in YAML gesteuert. Sie können Browser-Wiedergabe (type: browser), Cast-Geräte (type: cast), mehrere Skripte (type: script) oder Beschriftungen hinzufügen. Wenn deaktiviert, gelten die Standardeinstellungen.",
    "editor.custom_play_actions_none_configured": "Es wurden noch keine Aktionen ausgewählt. Aktivieren Sie Browser-Wiedergabe, konfigurieren Sie oben ein Cast-Gerät oder Skript oder definieren Sie Ziele in YAML unter modal_play_actions.",
    "modal.play_on": "Abspielen auf",
    "modal.play_on_client": "Auf Client abspielen",
    "modal.play_in_browser": "Im Browser abspielen",
    "modal.cancel": "Abbrechen",
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
    "editor.media_player": "Medienplayer",
    "editor.now_playing_sensor": "Medienplayer",
    "editor.auto": "Automatisch",
    "editor.show_search": "Suchleiste anzeigen",
    "editor.show_controls": "Wiedergabesteuerung anzeigen",
    "editor.horizontal_alignment": "Karussell-Ausrichtung",
    "editor.alignment_center": "Zentriert",
    "editor.alignment_left": "Links",
    "editor.subtitles": "Cast-Untertitel",
    "editor.subtitles_auto": "Automatisch (Jellyfin-Benutzerprofil)",
    "editor.subtitles_none": "Keine (Deaktiviert)",
    "editor.subtitles_forced_only": "Nur erzwungene",
    "editor.subtitles_custom": "Benutzerdefinierte Sprachliste",
    "editor.subtitle_languages": "Cast-Untertitelpriorität (z. B. sl, en)",
    "editor.idle_section_title": "Ambient-Anzeige (im Ruhezustand)",
    "editor.idle_backdrop_cycle": "Mediathek im Ruhezustand durchwechseln",
    "editor.idle_cycle_interval": "Wechselintervall (Sekunden)",
    "editor.idle_display_mode": "Anzeigestil",
    "editor.idle_display_mode_backdrop": "Vollbild-Fanart (Bildschirmschoner)",
    "editor.idle_display_mode_card": "Karten-Layout (Poster + Hintergrund)",
    "editor.playing_display_mode": "Wiedergabe-Anzeigestil",
    "editor.playing_display_mode_card": "Karten-Layout (Poster + Details)",
    "editor.playing_display_mode_full_art": "Vollbild-Grafik (Kino-Held)",
    "editor.playing_artwork_source": "Wiedergabe-Grafikbild",
    "editor.playing_artwork_source_backdrop": "Fanart-Hintergrund",
    "editor.playing_artwork_source_poster": "Poster",
    "editor.idle_media_type": "Medientypen für Anzeige",
    "editor.idle_content_source": "Präsentierte Inhalte",
    "editor.idle_source_random": "Zufällige Mediathek-Titel",
    "editor.idle_source_recent": "Kürzlich hinzugefügt",
    "editor.idle_source_latest_movie": "Neuester Film",
    "editor.idle_source_latest_episode": "Neueste Serienfolge",
    "editor.idle_source_latest_both": "Neuester Film & Folge abwechselnd",
    "editor.idle_recent_limit": "Anzahl der kürzlich hinzugefügten Titel",
    "card.latest_movie_badge": "NEUER FILM",
    "card.latest_episode_badge": "NEUE FOLGE",
    "card.latest_series_badge": "NEUE SERIE",
    "idle.spotlight": "HIGHLIGHT",
    "idle.discover": "ENTDECKEN",
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
    previous: "Précédent",
    next: "Suivant",
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
    "editor.show_device_name": "Afficher le nom de l'appareil",
    "editor.show_user": "Afficher l'utilisateur",
    "editor.show_time": "Afficher le temps écoulé / restant",
    "editor.show_background": "Afficher l'arrière-plan",
    "editor.use_series_image": "Utiliser l'image de couverture de la série",
    "editor.show_media_type_badge": "Afficher le badge de type de média",
    "editor.badge_style": "Style de badge",
    "editor.badge_style_poster": "Badge sur l’affiche (Par défaut)",
    "editor.badge_style_header": "Badge dans l’en-tête",
    "editor.badge_style_inline": "Intégré aux métadonnées",
    "editor.badge_style_none": "Masqué",
    "editor.show_watched_status": "Afficher le statut de visionnage",
    "editor.show_date_added": "Afficher la date d'ajout",
    "editor.show_description": "Afficher la description",
    "editor.layout": "Mise en page",
    "editor.layout_carousel": "Carrousel",
    "editor.layout_grid": "Grille",
    "editor.layout_list": "Liste",
    "editor.layout_featured": "En vedette",
    "editor.featured_columns_helper": "Nombre de colonnes de cartes latérales à côté de l'affiche principale (1 à 4)",
    "editor.featured_rows": "Lignes",
    "editor.featured_rows_helper": "Nombre de lignes de cartes latérales à côté de l'affiche principale (2 ou 3)",
    "editor.featured_queue_backdrop": "Afficher l'arrière-plan des cartes",
    "editor.featured_queue_backdrop_helper": "Afficher l'arrière-plan fanart dans les cartes",
    "editor.show_card_backdrop": "Afficher l'arrière-plan des cartes",
    "editor.show_card_backdrop_helper": "Afficher l'arrière-plan fanart dans les cartes",
    "editor.media_type": "Type de média",
    "editor.media_type_both": "Films et séries",
    "editor.media_type_movies_episodes": "Films et épisodes",
    "editor.media_type_movies": "Films seulement",
    "editor.media_type_series": "Séries seulement",
    "editor.media_type_episodes": "Épisodes uniquement",
    "editor.media_type_next_up": "À suivre",
    "editor.tv_content": "Contenu TV",
    "editor.tv_content_series": "Émissions / Séries",
    "editor.tv_content_episodes": "Épisodes",
    "editor.items_per_page": "Éléments par page",
    "editor.max_pages": "Pages max (0 = illimité)",
    "editor.auto_swipe": "Défilement auto (sec, 0 = désactivé)",
    "editor.new_badge_days": "Jours badge nouveau (0 = désactivé)",
    "editor.click_action": "Appui court (Clic)",
    "editor.hold_action": "Appui long (Maintenir)",
    "editor.double_tap_action": "Double appui",
    "editor.action_jellyfin": "Ouvrir dans Jellyfin",
    "editor.action_play_browser": "Lire dans le navigateur",
    "editor.action_play_client": "Lire sur le client Jellyfin",
    "editor.action_cast": "Caster sur Chromecast",
    "editor.action_more_info": "Plus d'informations",
    "editor.action_trailer": "Voir la bande-annonce",
    "editor.action_none": "Aucune action",
    "editor.action_call_service": "Exécuter un script",
    "editor.service_to_call": "Script",
    "editor.service_data": 'Données du service (JSON optionnel, ex: {"player":"tv"})',
    "editor.default_cast_device": "Appareil Cast par défaut",
    "editor.default_client_device": "Client Jellyfin par défaut",
    "editor.no_client_devices_warning": "Aucun appareil client Jellyfin configuré dans l'intégration JellyHA. Veuillez configurer les appareils dans Paramètres → Appareils et services → JellyHA → Configurer.",
    "editor.enable_browser_player": 'Activer "Lire dans le navigateur"',
    "editor.show_now_playing_overlay": 'Superposition "En lecture"',
    "editor.enable_custom_play_actions": "Actions de lecture personnalisées",
    "editor.custom_play_actions_helper": "Lorsque cette option est activée, les cibles de lecture sont contrôlées par modal_play_actions en YAML. Vous pouvez configurer la lecture dans le navigateur (type: browser), des appareils Cast (type: cast), plusieurs scripts (type: script) ou des libellés personnalisés. Lorsque désactivée, les paramètres par défaut de la carte sont utilisés.",
    "editor.custom_play_actions_none_configured": "Aucune action n'a encore été sélectionnée. Activez la lecture dans le navigateur, configurez un appareil Cast ou un script ci-dessus, ou définissez des cibles en YAML sous modal_play_actions.",
    "modal.play_on": "Lire sur",
    "modal.play_on_client": "Lire sur le client",
    "modal.play_in_browser": "Lire dans le navigateur",
    "modal.cancel": "Annuler",
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
    "editor.media_player": "Lecteur multimédia",
    "editor.now_playing_sensor": "Lecteur multimédia",
    "editor.auto": "Auto",
    "editor.show_search": "Afficher la barre de recherche",
    "editor.show_controls": "Afficher les commandes de lecture",
    "editor.horizontal_alignment": "Alignement du carrousel",
    "editor.alignment_center": "Centré",
    "editor.alignment_left": "Gauche",
    "editor.subtitles": "Sous-titres Cast",
    "editor.subtitles_auto": "Auto (Profil utilisateur Jellyfin)",
    "editor.subtitles_none": "Aucun (Désactivé)",
    "editor.subtitles_forced_only": "Forcés uniquement",
    "editor.subtitles_custom": "Liste de langues personnalisée",
    "editor.subtitle_languages": "Priorité des sous-titres Cast (ex. sl, en)",
    "editor.idle_section_title": "Vitrine d’ambiance (en veille)",
    "editor.idle_backdrop_cycle": "Faire défiler les médias en veille",
    "editor.idle_cycle_interval": "Intervalle de défilement (secondes)",
    "editor.idle_display_mode": "Style d’affichage",
    "editor.idle_display_mode_backdrop": "Arrière-plan complet (Économiseur)",
    "editor.idle_display_mode_card": "Disposition carte (Affiche + Fond)",
    "editor.playing_display_mode": "Style d’affichage en lecture",
    "editor.playing_display_mode_card": "Disposition carte (Affiche + Détails)",
    "editor.playing_display_mode_full_art": "Plein écran artistique (Héros cinématographique)",
    "editor.playing_artwork_source": "Image artistique de lecture",
    "editor.playing_artwork_source_backdrop": "Arrière-plan Fanart",
    "editor.playing_artwork_source_poster": "Affiche",
    "editor.idle_media_type": "Types de médias à afficher",
    "editor.idle_content_source": "Contenu à afficher",
    "editor.idle_source_random": "Médias aléatoires",
    "editor.idle_source_recent": "Récemment ajoutés",
    "editor.idle_source_latest_movie": "Dernier film ajouté",
    "editor.idle_source_latest_episode": "Dernier épisode ajouté",
    "editor.idle_source_latest_both": "Alterner dernier film et épisode",
    "editor.idle_recent_limit": "Nombre d'éléments récents",
    "card.latest_movie_badge": "DERNIER FILM",
    "card.latest_episode_badge": "DERNIER ÉPISODE",
    "card.latest_series_badge": "DERNIÈRE SÉRIE",
    "idle.spotlight": "EN VEDETTE",
    "idle.discover": "DÉCOUVRIR",
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
    previous: "Anterior",
    next: "Siguiente",
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
    "editor.show_device_name": "Mostrar nombre del dispositivo",
    "editor.show_user": "Mostrar usuario",
    "editor.show_time": "Mostrar tiempo transcurrido / restante",
    "editor.show_background": "Mostrar fondo",
    "editor.use_series_image": "Usar imagen de portada de serie",
    "editor.show_media_type_badge": "Mostrar insignia de tipo de medio",
    "editor.badge_style": "Estilo de insignia",
    "editor.badge_style_poster": "Insignia en póster (Por defecto)",
    "editor.badge_style_header": "Insignia en encabezado",
    "editor.badge_style_inline": "En los metadatos",
    "editor.badge_style_none": "Oculto",
    "editor.show_watched_status": "Mostrar estado de visualización",
    "editor.show_date_added": "Mostrar fecha de adición",
    "editor.show_description": "Mostrar descripción",
    "editor.layout": "Diseño",
    "editor.layout_carousel": "Carrusel",
    "editor.layout_grid": "Cuadrícula",
    "editor.layout_list": "Lista",
    "editor.layout_featured": "Destacado",
    "editor.featured_columns_helper": "Número de columnas de tarjetas laterales junto al póster principal (1 a 4)",
    "editor.featured_rows": "Filas",
    "editor.featured_rows_helper": "Número de filas de tarjetas laterales junto al póster principal (2 o 3)",
    "editor.featured_queue_backdrop": "Mostrar fondo de tarjetas",
    "editor.featured_queue_backdrop_helper": "Mostrar imagen de fondo fanart en las tarjetas",
    "editor.show_card_backdrop": "Mostrar fondo de tarjetas",
    "editor.show_card_backdrop_helper": "Mostrar imagen de fondo fanart en las tarjetas",
    "editor.media_type": "Tipo de medio",
    "editor.media_type_both": "Películas y Series",
    "editor.media_type_movies_episodes": "Películas y episodios",
    "editor.media_type_movies": "Solo películas",
    "editor.media_type_series": "Solo series",
    "editor.media_type_episodes": "Solo episodios",
    "editor.media_type_next_up": "A continuación",
    "editor.tv_content": "Contenido de TV",
    "editor.tv_content_series": "Programas / Series",
    "editor.tv_content_episodes": "Episodios",
    "editor.items_per_page": "Elementos por página",
    "editor.max_pages": "Máx. páginas (0 = sin límite)",
    "editor.auto_swipe": "Deslizamiento automático (seg, 0 = apagado)",
    "editor.new_badge_days": "Días de insignia nueva (0 = apagado)",
    "editor.click_action": "Pulsación corta (Clic)",
    "editor.hold_action": "Pulsación larga (Mantener)",
    "editor.double_tap_action": "Doble toque",
    "editor.action_jellyfin": "Abrir en Jellyfin",
    "editor.action_play_browser": "Reproducir en el navegador",
    "editor.action_play_client": "Reproducir en cliente Jellyfin",
    "editor.action_cast": "Cast a Chromecast",
    "editor.action_more_info": "Más información",
    "editor.action_trailer": "Ver tráiler",
    "editor.action_none": "Ninguna acción",
    "editor.action_call_service": "Ejecutar script",
    "editor.service_to_call": "Script",
    "editor.service_data": 'Datos del servicio (JSON opcional, ej. {"player":"tv"})',
    "editor.default_cast_device": "Dispositivo Cast predeterminado",
    "editor.default_client_device": "Cliente Jellyfin predeterminado",
    "editor.no_client_devices_warning": "No hay dispositivos cliente Jellyfin configurados en la integración de JellyHA. Configure dispositivos en Configuración → Dispositivos y servicios → JellyHA → Configurar.",
    "editor.enable_browser_player": 'Habilitar "Reproducir en el navegador"',
    "editor.show_now_playing_overlay": 'Superposición "Reproduciendo"',
    "editor.enable_custom_play_actions": "Acciones de reproducción personalizadas",
    "editor.custom_play_actions_helper": "Cuando está habilitado, los destinos de reproducción se controlan mediante modal_play_actions en YAML. Puede configurar reproducción en navegador (type: browser), dispositivos Cast (type: cast), múltiples scripts (type: script) o etiquetas personalizadas. Cuando está deshabilitado, se utiliza la configuración estándar.",
    "editor.custom_play_actions_none_configured": "Aún no se ha seleccionado ninguna acción. Habilite la reproducción en navegador, configure un dispositivo Cast o un script arriba, o defina destinos en YAML bajo modal_play_actions.",
    "modal.play_on": "Reproducir en",
    "modal.play_on_client": "Reproducir en cliente",
    "modal.play_in_browser": "Reproducir en el navegador",
    "modal.cancel": "Cancelar",
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
    "editor.media_player": "Reproductor multimedia",
    "editor.now_playing_sensor": "Reproductor multimedia",
    "editor.auto": "Auto",
    "editor.show_search": "Mostrar barra de búsqueda",
    "editor.show_controls": "Mostrar controles de reproducción",
    "editor.horizontal_alignment": "Alineación del carrusel",
    "editor.alignment_center": "Centrado",
    "editor.alignment_left": "Izquierda",
    "editor.subtitles": "Subtítulos Cast",
    "editor.subtitles_auto": "Automático (Perfil de usuario de Jellyfin)",
    "editor.subtitles_none": "Ninguno (Desactivado)",
    "editor.subtitles_forced_only": "Solo forzados",
    "editor.subtitles_custom": "Lista de idiomas personalizada",
    "editor.subtitle_languages": "Prioridad de subtítulos Cast (p. ej. sl, en)",
    "editor.idle_section_title": "Muestra ambiental (en reposo)",
    "editor.idle_backdrop_cycle": "Rotar medios de biblioteca en reposo",
    "editor.idle_cycle_interval": "Intervalo de rotación (segundos)",
    "editor.idle_display_mode": "Estilo de visualización",
    "editor.idle_display_mode_backdrop": "Fondo completo (Salvapantallas)",
    "editor.idle_display_mode_card": "Diseño tarjeta (Póster + Fondo)",
    "editor.playing_display_mode": "Estilo de visualización de reproducción",
    "editor.playing_display_mode_card": "Diseño tarjeta (Póster + Detalles)",
    "editor.playing_display_mode_full_art": "Ilustración completa (Héroe cinematográfico)",
    "editor.playing_artwork_source": "Imagen de la ilustración",
    "editor.playing_artwork_source_backdrop": "Fondo Fanart",
    "editor.playing_artwork_source_poster": "Póster",
    "editor.idle_media_type": "Tipos de medios a mostrar",
    "editor.idle_content_source": "Contenido a mostrar",
    "editor.idle_source_random": "Medios aleatorios",
    "editor.idle_source_recent": "Añadidos recientemente",
    "editor.idle_source_latest_movie": "Última película añadida",
    "editor.idle_source_latest_episode": "Último episodio añadido",
    "editor.idle_source_latest_both": "Alternar última película y episodio",
    "editor.idle_recent_limit": "Número de elementos recientes",
    "card.latest_movie_badge": "ÚLTIMA PELÍCULA",
    "card.latest_episode_badge": "ÚLTIMO EPISODIO",
    "card.latest_series_badge": "ÚLTIMA SERIE",
    "idle.spotlight": "DESTACADO",
    "idle.discover": "DESCUBRIR",
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
    previous: "Precedente",
    next: "Successivo",
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
    "editor.show_device_name": "Mostra nome del dispositivo",
    "editor.show_user": "Mostra utente",
    "editor.show_time": "Mostra tempo trascorso / rimanente",
    "editor.show_background": "Mostra sfondo",
    "editor.use_series_image": "Usa immagine copertina serie",
    "editor.show_media_type_badge": "Mostra badge tipo media",
    "editor.badge_style": "Stile badge",
    "editor.badge_style_poster": "Badge sulla locandina (Predefinito)",
    "editor.badge_style_header": "Badge nell’intestazione",
    "editor.badge_style_inline": "Nei metadati",
    "editor.badge_style_none": "Nascosto",
    "editor.show_watched_status": "Mostra stato guardato",
    "editor.show_date_added": "Mostra data aggiunta",
    "editor.show_description": "Mostra descrizione",
    "editor.layout": "Layout",
    "editor.layout_carousel": "Carosello",
    "editor.layout_grid": "Griglia",
    "editor.layout_list": "Elenco",
    "editor.layout_featured": "In evidenza",
    "editor.featured_columns_helper": "Numero di colonne di schede laterali accanto al poster principale (da 1 a 4)",
    "editor.featured_rows": "Righe",
    "editor.featured_rows_helper": "Numero di righe di schede laterali accanto al poster principale (2 o 3)",
    "editor.featured_queue_backdrop": "Mostra sfondo schede",
    "editor.featured_queue_backdrop_helper": "Mostra lo sfondo fanart nelle schede",
    "editor.show_card_backdrop": "Mostra sfondo schede",
    "editor.show_card_backdrop_helper": "Mostra lo sfondo fanart nelle schede",
    "editor.media_type": "Tipo di media",
    "editor.media_type_both": "Film e Serie TV",
    "editor.media_type_movies_episodes": "Film ed episodi",
    "editor.media_type_movies": "Solo Film",
    "editor.media_type_series": "Solo Serie TV",
    "editor.media_type_episodes": "Solo episodi",
    "editor.media_type_next_up": "In coda",
    "editor.tv_content": "Contenuto TV",
    "editor.tv_content_series": "Programmi / Serie TV",
    "editor.tv_content_episodes": "Episodi",
    "editor.items_per_page": "Elementi per pagina",
    "editor.max_pages": "Max pagine (0 = nessun limite)",
    "editor.auto_swipe": "Scorrimento automatico (sec, 0 = spento)",
    "editor.new_badge_days": "Giorni badge nuovo (0 = spento)",
    "editor.click_action": "Pressione breve (Click)",
    "editor.hold_action": "Pressione lunga (Tieni premuto)",
    "editor.double_tap_action": "Doppio tocco",
    "editor.action_jellyfin": "Apri in Jellyfin",
    "editor.action_play_browser": "Riproduci nel browser",
    "editor.action_play_client": "Riproduci su client Jellyfin",
    "editor.action_cast": "Cast su Chromecast",
    "editor.action_more_info": "Più informazioni",
    "editor.action_trailer": "Guarda il trailer",
    "editor.action_none": "Nessuna azione",
    "editor.action_call_service": "Esegui script",
    "editor.service_to_call": "Script",
    "editor.service_data": 'Dati del servizio (JSON opzionale, es. {"player":"tv"})',
    "editor.default_cast_device": "Dispositivo Cast predefinito",
    "editor.default_client_device": "Client Jellyfin predefinito",
    "editor.no_client_devices_warning": "Nessun dispositivo client Jellyfin configurato nell'integrazione JellyHA. Configurare i dispositivi in Impostazioni → Dispositivi e servizi → JellyHA → Configura.",
    "editor.enable_browser_player": 'Abilita "Riproduci nel browser"',
    "editor.show_now_playing_overlay": 'Overlay "In riproduzione"',
    "editor.enable_custom_play_actions": "Azioni di riproduzione personalizzate",
    "editor.custom_play_actions_helper": "Se abilitato, le destinazioni di riproduzione sono controllate da modal_play_actions in YAML. È possibile configurare riproduzione nel browser (type: browser), dispositivi Cast (type: cast), più script (type: script) o etichette personalizzate. Quando disabilitato, vengono usate le impostazioni standard.",
    "editor.custom_play_actions_none_configured": "Nessuna azione è stata ancora selezionata. Abilita la riproduzione nel browser, configura un dispositivo Cast o uno script sopra, o definisci destinazioni in YAML sotto modal_play_actions.",
    "modal.play_on": "Riproduci su",
    "modal.play_on_client": "Riproduci su client",
    "modal.play_in_browser": "Riproduci nel browser",
    "modal.cancel": "Annulla",
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
    "editor.media_player": "Lettore multimediale",
    "editor.now_playing_sensor": "Lettore multimediale",
    "editor.auto": "Auto",
    "editor.show_search": "Mostra barra di ricerca",
    "editor.show_controls": "Mostra controlli di riproduzione",
    "editor.horizontal_alignment": "Allineamento carosello",
    "editor.alignment_center": "Centro",
    "editor.alignment_left": "Sinistra",
    "editor.subtitles": "Sottotitoli Cast",
    "editor.subtitles_auto": "Automatico (Profilo utente Jellyfin)",
    "editor.subtitles_none": "Nessuno (Disabilitato)",
    "editor.subtitles_forced_only": "Solo forzati",
    "editor.subtitles_custom": "Elenco lingue personalizzato",
    "editor.subtitle_languages": "Priorità sottotitoli Cast (es. sl, en)",
    "editor.idle_section_title": "Vetrina ambientale (inattivo)",
    "editor.idle_backdrop_cycle": "Scorri elementi libreria in inattività",
    "editor.idle_cycle_interval": "Intervallo di rotazione (secondi)",
    "editor.idle_display_mode": "Stile visualizzazione",
    "editor.idle_display_mode_backdrop": "Sfondo completo (Salvaschermo)",
    "editor.idle_display_mode_card": "Layout scheda (Locandina + Sfondo)",
    "editor.playing_display_mode": "Stile visualizzazione riproduzione",
    "editor.playing_display_mode_card": "Layout scheda (Locandina + Dettagli)",
    "editor.playing_display_mode_full_art": "Opera d’arte completa (Eroe cinematografico)",
    "editor.playing_artwork_source": "Immagine opera d’arte",
    "editor.playing_artwork_source_backdrop": "Sfondo Fanart",
    "editor.playing_artwork_source_poster": "Locandina",
    "editor.idle_media_type": "Tipi di media da mostrare",
    "editor.idle_content_source": "Contenuto da mostrare",
    "editor.idle_source_random": "Elementi casuali",
    "editor.idle_source_recent": "Aggiunti di recente",
    "editor.idle_source_latest_movie": "Ultimo film aggiunto",
    "editor.idle_source_latest_episode": "Ultimo episodio aggiunto",
    "editor.idle_source_latest_both": "Alterna ultimo film ed episodio",
    "editor.idle_recent_limit": "Numero di elementi recenti",
    "card.latest_movie_badge": "ULTIMO FILM",
    "card.latest_episode_badge": "ULTIMO EPISODIO",
    "card.latest_series_badge": "ULTIMA SERIE",
    "idle.spotlight": "IN EVIDENZA",
    "idle.discover": "SCOPRI",
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
    previous: "Vorige",
    next: "Volgende",
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
    "editor.show_device_name": "Apparaatnaam tonen",
    "editor.show_user": "Gebruiker tonen",
    "editor.show_time": "Verstreken / resterende tijd tonen",
    "editor.show_background": "Achtergrond tonen",
    "editor.use_series_image": "Gebruik serie-omslagafbeelding",
    "editor.show_media_type_badge": "Mediatype-badge tonen",
    "editor.badge_style": "Badgestijl",
    "editor.badge_style_poster": "Badge op poster (Standaard)",
    "editor.badge_style_header": "Badge in koptekst",
    "editor.badge_style_inline": "In metadata opgenomen",
    "editor.badge_style_none": "Verborgen",
    "editor.show_watched_status": "Bekeken-status tonen",
    "editor.show_date_added": "Datum toegevoegd tonen",
    "editor.show_description": "Beschrijving tonen",
    "editor.layout": "Indeling",
    "editor.layout_carousel": "Carrousel",
    "editor.layout_grid": "Raster",
    "editor.layout_list": "Lijst",
    "editor.layout_featured": "Uitgelicht",
    "editor.featured_columns_helper": "Aantal kolommen voor zijkaarten naast de hoofdposter (1 tot 4)",
    "editor.featured_rows": "Rijen",
    "editor.featured_rows_helper": "Aantal rijen zijkarten naast de hoofdposter (2 of 3)",
    "editor.featured_queue_backdrop": "Kaartachtergrond tonen",
    "editor.featured_queue_backdrop_helper": "Toon fanart-achtergrond in de kaarten",
    "editor.show_card_backdrop": "Kaartachtergrond tonen",
    "editor.show_card_backdrop_helper": "Toon fanart-achtergrond in de kaarten",
    "editor.media_type": "Mediatype",
    "editor.media_type_both": "Films & Series",
    "editor.media_type_movies_episodes": "Films en afleveringen",
    "editor.media_type_movies": "Alleen films",
    "editor.media_type_series": "Alleen series",
    "editor.media_type_episodes": "Alleen afleveringen",
    "editor.media_type_next_up": "Volgende",
    "editor.tv_content": "TV-inhoud",
    "editor.tv_content_series": "Shows / Series",
    "editor.tv_content_episodes": "Afleveringen",
    "editor.items_per_page": "Items per pagina",
    "editor.max_pages": "Max. pagina's (0 = geen limiet)",
    "editor.auto_swipe": "Auto-swipe (sec, 0 = uit)",
    "editor.new_badge_days": "Dagen badge nieuw (0 = uit)",
    "editor.click_action": "Kort indrukken (Klik)",
    "editor.hold_action": "Lang indrukken (Vasthouden)",
    "editor.double_tap_action": "Dubbel tikken",
    "editor.action_jellyfin": "Open in Jellyfin",
    "editor.action_play_browser": "Afspelen in browser",
    "editor.action_play_client": "Afspelen op Jellyfin-client",
    "editor.action_cast": "Casten naar Chromecast",
    "editor.action_more_info": "Meer informatie",
    "editor.action_trailer": "Bekijk trailer",
    "editor.action_none": "Geen actie",
    "editor.action_call_service": "Script uitvoeren",
    "editor.service_to_call": "Script",
    "editor.service_data": 'Servicegegevens (Optioneel JSON, bijv. {"player":"tv"})',
    "editor.default_cast_device": "Standaard Cast-apparaat",
    "editor.default_client_device": "Standaard Jellyfin-client",
    "editor.no_client_devices_warning": "Geen Jellyfin-clientapparaten geconfigureerd in de JellyHA-integratie. Configureer apparaten via Instellingen → Apparaten & diensten → JellyHA → Configureren.",
    "editor.enable_browser_player": '"Afspelen in browser" inschakelen',
    "editor.show_now_playing_overlay": '"Nu aan het spelen"-overlay',
    "editor.enable_custom_play_actions": "Aangepaste afspeelacties",
    "editor.custom_play_actions_helper": "Indien ingeschakeld, worden afspeeldoelen beheerd via modal_play_actions in YAML. U kunt afspelen in de browser (type: browser), Cast-apparaten (type: cast), meerdere scripts (type: script) of aangepaste labels configureren. Indien uitgeschakeld, worden de standaardinstellingen gebruikt.",
    "editor.custom_play_actions_none_configured": "Er zijn nog geen acties geselecteerd. Schakel afspelen in browser in, configureer hierboven een Cast-apparaat of script, of definieer doelen in YAML onder modal_play_actions.",
    "modal.play_on": "Afspelen op",
    "modal.play_on_client": "Afspelen op client",
    "modal.play_in_browser": "Afspelen in browser",
    "modal.cancel": "Annuleren",
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
    "editor.media_player": "Mediaspeler",
    "editor.now_playing_sensor": "Mediaspeler",
    "editor.auto": "Auto",
    "editor.show_search": "Zoekbalk tonen",
    "editor.show_controls": "Afspeelknoppen tonen",
    "editor.horizontal_alignment": "Carrousel uitlijning",
    "editor.alignment_center": "Midden",
    "editor.alignment_left": "Links",
    "editor.subtitles": "Cast-ondertitels",
    "editor.subtitles_auto": "Automatisch (Jellyfin-gebruikersprofiel)",
    "editor.subtitles_none": "Geen (Uitgeschakeld)",
    "editor.subtitles_forced_only": "Alleen geforceerd",
    "editor.subtitles_custom": "Aangepaste talenlijst",
    "editor.subtitle_languages": "Cast-ondertitelprioriteit (bijv. sl, en)",
    "editor.idle_section_title": "Ambient Showcase (bij inactiviteit)",
    "editor.idle_backdrop_cycle": "Bibliotheekmedia roteren bij inactiviteit",
    "editor.idle_cycle_interval": "Wisselinterval (seconden)",
    "editor.idle_display_mode": "Weergavestijl",
    "editor.idle_display_mode_backdrop": "Volledige achtergrond (Screensaver)",
    "editor.idle_display_mode_card": "Kaartindeling (Poster + Achtergrond)",
    "editor.playing_display_mode": "Afspeelweergavestijl",
    "editor.playing_display_mode_card": "Kaartindeling (Poster + Details)",
    "editor.playing_display_mode_full_art": "Volledige illustratie (Cinematische held)",
    "editor.playing_artwork_source": "Afspeelillustratie",
    "editor.playing_artwork_source_backdrop": "Fanart-achtergrond",
    "editor.playing_artwork_source_poster": "Poster",
    "editor.idle_media_type": "Weer te geven mediatypes",
    "editor.idle_content_source": "Te tonen inhoud",
    "editor.idle_source_random": "Willekeurige bibliotheekmedia",
    "editor.idle_source_recent": "Onlangs toegevoegd",
    "editor.idle_source_latest_movie": "Laatst toegevoegde film",
    "editor.idle_source_latest_episode": "Laatst toegevoegde aflevering",
    "editor.idle_source_latest_both": "Laatste film en aflevering afwisselen",
    "editor.idle_recent_limit": "Aantal recente items",
    "card.latest_movie_badge": "LAATSTE FILM",
    "card.latest_episode_badge": "LAATSTE AFLEVERING",
    "card.latest_series_badge": "LAATSTE SERIE",
    "idle.spotlight": "IN DE KIJKER",
    "idle.discover": "ONTDEK",
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
    previous: "Prejšnji",
    next: "Naslednji",
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
    "editor.show_device_name": "Prikaži ime naprave",
    "editor.show_user": "Prikaži uporabnika",
    "editor.show_time": "Prikaži pretečen / preostali čas",
    "editor.show_background": "Prikaži ozadje",
    "editor.use_series_image": "Uporabi sliko naslovnice serije",
    "editor.show_media_type_badge": "Prikaži značko tipa medija",
    "editor.badge_style": "Slog značke",
    "editor.badge_style_poster": "Značka na plakatu (Privzeto)",
    "editor.badge_style_header": "Značka v glavi",
    "editor.badge_style_inline": "V vrstici z metapodatki",
    "editor.badge_style_none": "Skrito",
    "editor.show_watched_status": "Prikaži status ogleda",
    "editor.show_date_added": "Prikaži datum dodajanja",
    "editor.show_description": "Prikaži opis",
    "editor.layout": "Postavitev",
    "editor.layout_carousel": "Vrtiljak",
    "editor.layout_grid": "Mreža",
    "editor.layout_list": "Seznam",
    "editor.layout_featured": "Izpostavljeno",
    "editor.featured_columns_helper": "Število stolpcev stranskih kartic poleg glavnega plakata (1 do 4)",
    "editor.featured_rows": "Vrstice",
    "editor.featured_rows_helper": "Število vrstic stranskih kartic poleg glavnega plakata (2 ali 3)",
    "editor.featured_queue_backdrop": "Prikaži ozadje kartic",
    "editor.featured_queue_backdrop_helper": "Prikaži sliko v ozadju kartic",
    "editor.show_card_backdrop": "Prikaži ozadje kartic",
    "editor.show_card_backdrop_helper": "Prikaži sliko v ozadju kartic",
    "editor.media_type": "Tip medija",
    "editor.media_type_both": "Filmi in serije",
    "editor.media_type_movies_episodes": "Filmi in epizode",
    "editor.media_type_movies": "Samo filmi",
    "editor.media_type_series": "Samo serije",
    "editor.media_type_episodes": "Samo epizode",
    "editor.media_type_next_up": "Naslednje",
    "editor.tv_content": "TV vsebina",
    "editor.tv_content_series": "Oddaje / Serije",
    "editor.tv_content_episodes": "Epizode",
    "editor.items_per_page": "Elementov na stran",
    "editor.max_pages": "Max strani (0 = brez omejitve)",
    "editor.auto_swipe": "Samodejno drsenje (sek, 0 = izklopljeno)",
    "editor.new_badge_days": "Dnevi za značko Novo (0 = izklopljeno)",
    "editor.click_action": "Kratek pritisk (Klik)",
    "editor.hold_action": "Dolg pritisk (Drži)",
    "editor.double_tap_action": "Dvojni dotik",
    "editor.action_jellyfin": "Odpri v Jellyfin",
    "editor.action_play_browser": "Predvajaj v brskalniku",
    "editor.action_play_client": "Predvajaj na Jellyfin odjemalcu",
    "editor.action_cast": "Predvajaj na Chromecast",
    "editor.action_more_info": "Več informacij",
    "editor.action_trailer": "Poglej napovednik",
    "editor.action_none": "Brez akcije",
    "editor.action_call_service": "Zaženi skript",
    "editor.service_to_call": "Skript",
    "editor.service_data": 'Podatki servisa (Opcijski JSON, npr. {"player":"tv"})',
    "editor.default_cast_device": "Privzeta Chromecast naprava",
    "editor.default_client_device": "Privzeti Jellyfin odjemalec",
    "editor.no_client_devices_warning": "V integraciji JellyHA ni konfiguriranih Jellyfin odjemalskih naprav. Naprave konfigurirajte v Nastavitve → Naprave in storitve → JellyHA → Konfiguriraj.",
    "editor.enable_browser_player": 'Omogoči "Predvajaj v brskalniku"',
    "editor.show_now_playing_overlay": 'Prikaži "Zdaj se predvaja" prekrivanje',
    "editor.enable_custom_play_actions": "Predvajanje po meri",
    "editor.custom_play_actions_helper": "Ko je omogočeno, se cilji predvajanja v oknu z več informacijami upravljajo prek modal_play_actions v YAML. Dodate lahko predvajanje v brskalniku (type: browser), naprave Cast (type: cast), več skriptov (type: script) ali oznake po meri.",
    "editor.custom_play_actions_none_configured": "Nobeno dejanje še ni izbrano. Zgoraj omogočite predvajanje v brskalniku, izberite napravo Cast ali skript, ali pa določite cilje v YAML pod modal_play_actions.",
    "modal.play_on": "Predvajaj na",
    "modal.play_on_client": "Predvajaj na odjemalcu",
    "modal.play_in_browser": "Predvajaj v brskalniku",
    "modal.cancel": "Prekliči",
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
    "editor.media_player": "Predvajalnik medijev",
    "editor.now_playing_sensor": "Predvajalnik medijev",
    "editor.auto": "Avtomatsko",
    "editor.show_search": "Prikaži iskalno vrstico",
    "editor.show_controls": "Prikaži kontrolnike za predvajanje",
    "editor.horizontal_alignment": "Poravnava vrtiljaka",
    "editor.alignment_center": "Na sredino",
    "editor.alignment_left": "Levo",
    "editor.subtitles": "Chromecast podnapisi",
    "editor.subtitles_auto": "Samodejno (Uporabniški profil Jellyfin)",
    "editor.subtitles_none": "Brez (Onemogočeno)",
    "editor.subtitles_forced_only": "Samo vsiljeni",
    "editor.subtitles_custom": "Prilagojen seznam jezikov",
    "editor.subtitle_languages": "Prioriteta podnapisov (npr. sl, en)",
    "editor.idle_section_title": "Ambientni prikaz (ko ni predvajanja)",
    "editor.idle_backdrop_cycle": "Kroženje knjižnice v mirovanju",
    "editor.idle_cycle_interval": "Interval kroženja (sekunde)",
    "editor.idle_display_mode": "Slog prikaza",
    "editor.idle_display_mode_backdrop": "Celotno ozadje (Ohranjevalnik)",
    "editor.idle_display_mode_card": "Kartica (Plakat + Ozadje)",
    "editor.playing_display_mode": "Slog prikaza predvajanja",
    "editor.playing_display_mode_card": "Postavitev kartice (Plakat + Podrobnosti)",
    "editor.playing_display_mode_full_art": "Celotna umetnost (Kinematografski junak)",
    "editor.playing_artwork_source": "Slika umetnosti predvajanja",
    "editor.playing_artwork_source_backdrop": "Fanart ozadje",
    "editor.playing_artwork_source_poster": "Plakat",
    "editor.idle_media_type": "Vrste medijev za prikaz",
    "editor.idle_content_source": "Vsebina za prikaz v mirovanju",
    "editor.idle_source_random": "Naključna knjižnica",
    "editor.idle_source_recent": "Zadnje dodano",
    "editor.idle_source_latest_movie": "Zadnji dodani film",
    "editor.idle_source_latest_episode": "Zadnja dodana epizoda",
    "editor.idle_source_latest_both": "Izmenično zadnji film in epizoda",
    "editor.idle_recent_limit": "Število zadnjih elementov",
    "card.latest_movie_badge": "ZADNJI FILM",
    "card.latest_episode_badge": "ZADNJA EPIZODA",
    "card.latest_series_badge": "ZADNJA SERIJA",
    "idle.spotlight": "V ŽARIŠČU",
    "idle.discover": "ODKRIJTE",
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
    previous: "Предыдущий",
    next: "Следующий",
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
    "editor.show_device_name": "Показывать имя устройства",
    "editor.show_user": "Показывать пользователя",
    "editor.show_time": "Показывать прошедшее / оставшееся время",
    "editor.show_background": "Показывать фон",
    "editor.use_series_image": "Использовать обложку сериала",
    "editor.show_media_type_badge": "Показывать значок типа медиа",
    "editor.badge_style": "Стиль значка",
    "editor.badge_style_poster": "Значок на постере (По умолчанию)",
    "editor.badge_style_header": "Значок в заголовке",
    "editor.badge_style_inline": "В метаданных",
    "editor.badge_style_none": "Скрыто",
    "editor.show_watched_status": "Показывать статус просмотра",
    "editor.show_date_added": "Показывать дату добавления",
    "editor.show_description": "Показывать описание",
    "editor.layout": "Макет",
    "editor.layout_carousel": "Карусель",
    "editor.layout_grid": "Сетка",
    "editor.layout_list": "Список",
    "editor.layout_featured": "Витрина",
    "editor.featured_columns_helper": "Количество столбцов боковых карточек рядом с главным постером (от 1 до 4)",
    "editor.featured_rows": "Строки",
    "editor.featured_rows_helper": "Количество строк боковых карточек рядом с главным постером (2 или 3)",
    "editor.featured_queue_backdrop": "Показывать фон карточек",
    "editor.featured_queue_backdrop_helper": "Показывать арт-фон позади карточек",
    "editor.show_card_backdrop": "Показывать фон карточек",
    "editor.show_card_backdrop_helper": "Показывать арт-фон позади карточек",
    "editor.media_type": "Тип медиа",
    "editor.media_type_both": "Фильмы и Сериалы",
    "editor.media_type_movies_episodes": "Фильмы и серии",
    "editor.media_type_movies": "Только фильмы",
    "editor.media_type_series": "Только сериалы",
    "editor.media_type_episodes": "Только серии",
    "editor.media_type_next_up": "Далее",
    "editor.tv_content": "ТВ-контент",
    "editor.tv_content_series": "Шоу / Сериалы",
    "editor.tv_content_episodes": "Эпизоды",
    "editor.items_per_page": "Элементов на странице",
    "editor.max_pages": "Макс. страниц (0 = без ограничений)",
    "editor.auto_swipe": "Автопрокрутка (сек, 0 = выкл)",
    "editor.new_badge_days": 'Дней для значка "Новое" (0 = выкл)',
    "editor.click_action": "Короткое нажатие (Клик)",
    "editor.hold_action": "Долгое нажатие (Удержание)",
    "editor.double_tap_action": "Двойное нажатие",
    "editor.action_jellyfin": "Открыть в Jellyfin",
    "editor.action_play_browser": "Воспроизвести в браузере",
    "editor.action_play_client": "Воспроизвести на клиенте Jellyfin",
    "editor.action_cast": "Трансляция на Chromecast",
    "editor.action_more_info": "Больше информации",
    "editor.action_trailer": "Посмотреть трейлер",
    "editor.action_none": "Нет действия",
    "editor.action_call_service": "Запустить скрипт",
    "editor.service_to_call": "Скрипт",
    "editor.service_data": 'Данные сервиса (Опциональный JSON, напр. {"player":"tv"})',
    "editor.default_cast_device": "Устройство Cast по умолчанию",
    "editor.default_client_device": "Клиент Jellyfin по умолчанию",
    "editor.no_client_devices_warning": "В интеграции JellyHA не настроены клиентские устройства Jellyfin. Настройте устройства в Настройки → Устройства и службы → JellyHA → Настроить.",
    "editor.enable_browser_player": 'Включить "Воспроизвести в браузере"',
    "editor.show_now_playing_overlay": 'Оверлей "Сейчас играет"',
    "editor.enable_custom_play_actions": "Пользовательские действия воспроизведения",
    "editor.custom_play_actions_helper": "Если включено, цели воспроизведения настраиваются через modal_play_actions в YAML. Можно настроить воспроизведение в браузере (type: browser), устройства Cast (type: cast), несколько скриптов (type: script) или пользовательские названия. Если выключено, используются стандартные настройки.",
    "editor.custom_play_actions_none_configured": "Действия еще не выбраны. Включите воспроизведение в браузере, настройте устройство Cast или скрипт выше, либо укажите цели в YAML под modal_play_actions.",
    "modal.play_on": "Воспроизвести на",
    "modal.play_on_client": "Воспроизвести на клиенте",
    "modal.play_in_browser": "Воспроизвести в браузере",
    "modal.cancel": "Отмена",
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
    "editor.media_player": "Медиаплеер",
    "editor.now_playing_sensor": "Медиаплеер",
    "editor.auto": "Авто",
    "editor.show_search": "Показывать панель поиска",
    "editor.show_controls": "Показывать управление воспроизведением",
    "editor.horizontal_alignment": "Выравнивание карусели",
    "editor.alignment_center": "По центру",
    "editor.alignment_left": "Слева",
    "editor.subtitles": "Субтитры Cast",
    "editor.subtitles_auto": "Авто (Профиль пользователя Jellyfin)",
    "editor.subtitles_none": "Нет (Отключено)",
    "editor.subtitles_forced_only": "Только принудительные",
    "editor.subtitles_custom": "Пользовательский список языков",
    "editor.subtitle_languages": "Приоритет субтитров Cast (напр. sl, en)",
    "editor.idle_section_title": "Заставка библиотеки (при простое)",
    "editor.idle_backdrop_cycle": "Показывать библиотеку при простое",
    "editor.idle_cycle_interval": "Интервал смены (секунды)",
    "editor.idle_display_mode": "Стиль отображения",
    "editor.idle_display_mode_backdrop": "Полноэкранный фон (Заставка)",
    "editor.idle_display_mode_card": "Вид карточки (Постер + Фон)",
    "editor.playing_display_mode": "Стиль отображения воспроизведения",
    "editor.playing_display_mode_card": "Вид карточки (Постер + Детали)",
    "editor.playing_display_mode_full_art": "Полноэкранный арт (Кинематографичный герой)",
    "editor.playing_artwork_source": "Изображение арта воспроизведения",
    "editor.playing_artwork_source_backdrop": "Фон фанарта",
    "editor.playing_artwork_source_poster": "Постер",
    "editor.idle_media_type": "Типы медиа для показа",
    "editor.idle_content_source": "Контент в режиме ожидания",
    "editor.idle_source_random": "Случайные медиа",
    "editor.idle_source_recent": "Недавно добавленные",
    "editor.idle_source_latest_movie": "Последний добавленный фильм",
    "editor.idle_source_latest_episode": "Последняя добавленная серия",
    "editor.idle_source_latest_both": "Чередовать фильм и серию",
    "editor.idle_recent_limit": "Количество недавних элементов",
    "card.latest_movie_badge": "ПОСЛЕДНИЙ ФИЛЬМ",
    "card.latest_episode_badge": "ПОСЛЕДНЯЯ СЕРИЯ",
    "card.latest_series_badge": "ПОСЛЕДНИЙ СЕРИАЛ",
    "idle.spotlight": "В ЦЕНТРЕ ВНИМАНИЯ",
    "idle.discover": "ОБЗОР",
    "search.placeholder_title": "Поиск по названию",
    "search.placeholder_genre": "Жанр",
    "search.all_genres": "Все жанры"
  }
};
function d(e, t, i) {
  if (!t) return i || "";
  const o = (e || "en").split("-")[0].toLowerCase();
  return Ye[o]?.[t] ? Ye[o][t] : Ye.en?.[t] ? Ye.en[t] : i !== void 0 ? i : "";
}
function Pi(e) {
  if (e?.power_entity)
    return e.power_entity;
  const t = e?.entity;
  if (t && !t.startsWith("sensor.") && !t.startsWith("binary_sensor."))
    return t;
}
function ct(e, t, i) {
  if (!t || !e || !e.states)
    return { isAvailable: !1, isStateless: !1, isOn: !1 };
  const o = e.states[t];
  if (!o)
    return { isAvailable: !1, isStateless: !1, isOn: !1 };
  if (i && e.states[i]) {
    const p = e.states[i], u = p.state.toLowerCase();
    return {
      isAvailable: u !== "unavailable" && u !== "unknown",
      isStateless: !1,
      isOn: u === "on" || u === "playing" || u === "paused" || u === "idle" || u === "home" || u === "active",
      state: p.state,
      entityId: i
    };
  }
  const s = t.split(".")[0], a = s === "script" || s === "button" || s === "scene", r = o.state.toLowerCase(), n = r !== "unavailable" && r !== "unknown";
  let c = !1;
  return a ? c = r === "on" : s === "media_player" ? c = r === "on" || r === "playing" || r === "paused" || r === "idle" || r === "buffering" : c = r === "on" || r === "playing" || r === "home" || r === "active", {
    isAvailable: n,
    isStateless: a,
    isOn: c,
    state: o.state,
    entityId: t
  };
}
async function ji(e, t, i) {
  if (!e || !t) return;
  const o = t.split(".")[0], s = ct(e, t, i);
  try {
    if (o === "script")
      await e.callService("script", "turn_on", { entity_id: t });
    else if (o === "button")
      await e.callService("button", "press", { entity_id: t });
    else if (o === "scene")
      await e.callService("scene", "turn_on", { entity_id: t });
    else if (o === "media_player")
      if (s.isOn)
        try {
          await e.callService("media_player", "turn_off", { entity_id: t });
        } catch {
          await e.callService("homeassistant", "toggle", { entity_id: t });
        }
      else
        try {
          await e.callService("media_player", "turn_on", { entity_id: t });
        } catch {
          await e.callService("homeassistant", "toggle", { entity_id: t });
        }
    else o === "switch" || o === "light" || o === "input_boolean" ? await e.callService("homeassistant", "toggle", { entity_id: t }) : await e.callService("homeassistant", "toggle", { entity_id: t });
  } catch (a) {
    console.error(`[JellyHA] Failed to call power action for ${t}:`, a);
  }
}
function Ii(e) {
  try {
    if (typeof localStorage < "u") {
      const t = localStorage.getItem(`jellyha_volume_${e}`);
      if (t !== null) {
        const i = Number(t);
        if (!isNaN(i) && i >= 0 && i <= 1)
          return i;
      }
    }
  } catch {
  }
}
function Wt(e, t) {
  try {
    typeof localStorage < "u" && localStorage.setItem(`jellyha_volume_${e}`, String(t));
  } catch {
  }
}
function pt(e, t, i, o) {
  const s = t || i;
  if (!s || !e || !e.states || !e.states[s])
    return {
      canControl: !1,
      volumeLevel: 0,
      volumePercent: 0,
      isMuted: !1
    };
  const a = e.states[s], r = a.attributes;
  let n;
  if (r.volume_level !== void 0 && r.volume_level !== null) {
    const _ = Number(r.volume_level);
    isNaN(_) || (n = _ > 1 ? _ / 100 : _);
  }
  if (n === void 0) {
    const _ = s.endsWith("_2") ? s.slice(0, -2) : `${s}_2`, g = e.states[_];
    if (g?.attributes?.volume_level !== void 0 && g.attributes.volume_level !== null) {
      const m = Number(g.attributes.volume_level);
      isNaN(m) || (n = m > 1 ? m / 100 : m);
    }
  }
  n === void 0 && typeof o == "number" && (n = o / 100), n === void 0 && (n = Ii(s));
  const c = typeof n == "number" ? Math.max(0, Math.min(1, n)) : 0, p = Math.round(c * 100);
  n !== void 0 && Wt(s, c);
  const u = !!r.is_volume_muted;
  return {
    canControl: a.state !== "unavailable" && a.state !== "unknown",
    volumeLevel: c,
    volumePercent: p,
    isMuted: u,
    entityId: s
  };
}
async function Jt(e, t, i) {
  if (!e || !t) return;
  const o = Math.max(0, Math.min(1, i));
  Wt(t, o);
  const s = t.split(".")[0];
  try {
    s === "media_player" && await e.callService("media_player", "volume_set", {
      entity_id: t,
      volume_level: o
    });
  } catch (a) {
    console.error(`[JellyHA] Failed to set volume level for ${t}:`, a);
  }
}
async function Ei(e, t, i, o) {
  if (!e || !t || !e.states[t]) return 0;
  e.states[t];
  let s;
  typeof o == "number" ? s = o : s = pt(e, t).volumeLevel;
  const a = Math.max(0, Math.min(1, s + i));
  return await Jt(e, t, a), a;
}
async function Ti(e, t) {
  if (!e || !t || !e.states[t]) return;
  const o = !!e.states[t].attributes.is_volume_muted, s = t.split(".")[0];
  try {
    s === "media_player" && await e.callService("media_player", "volume_mute", {
      entity_id: t,
      is_volume_muted: !o
    });
  } catch (a) {
    console.error(`[JellyHA] Failed to toggle mute for ${t}:`, a);
  }
}
function Ai(e) {
  if (!e || typeof e != "string") return "";
  if (e.startsWith("sensor."))
    return e.replace(/_now_playing.*$/, "");
  if (e.startsWith("media_player.")) {
    const t = e.replace(/^media_player\./, "");
    let i = t;
    return t.includes("_user_") ? i = t.substring(0, t.indexOf("_user_")) : t.includes("_device_") ? i = t.substring(0, t.indexOf("_device_")) : t.includes("_") && (i = t.substring(0, t.lastIndexOf("_"))), `sensor.${i}`;
  }
  return "";
}
function lt(e) {
  return e ? String(e).replace(/-/g, "").toLowerCase() : "";
}
function ne(e, t) {
  return !e || !t ? !1 : e.trim().toLowerCase() === t.trim().toLowerCase();
}
function At(e, t) {
  if (!e || !t) return !1;
  const i = e.trim().toLowerCase(), o = t.trim().toLowerCase();
  return i === o || i.endsWith(` - ${o}`) || i.endsWith(`: ${o}`) || i.includes(` - ${o}`);
}
function zt(e, t, i) {
  if (!e || !t?.states) return null;
  const o = [];
  i?.default_cast_device && !o.includes(i.default_cast_device) && o.push(i.default_cast_device), i?.default_client_device && !o.includes(i.default_client_device) && o.push(i.default_client_device);
  for (const u of Object.keys(t.states))
    u.startsWith("media_player.jellyha_") && !u.includes("_library_browser") && !u.endsWith("_browser") && !o.includes(u) && o.push(u);
  let s = null;
  const a = lt(e.id), r = (e.type || "").toLowerCase(), n = r === "episode" || !!(e.series_name && e.name && e.series_name !== e.name && r !== "series"), c = r === "series", p = r === "season";
  for (const u of o) {
    const _ = t.states[u];
    if (!_) continue;
    const g = _.state;
    if (g !== "playing" && g !== "paused" && g !== "buffering")
      continue;
    const m = _.attributes?.media_title || _.attributes?.title, b = _.attributes?.media_series_title || _.attributes?.series_title, x = _.attributes?.item_id || _.attributes?.media_content_id, v = _.attributes?.series_id || _.attributes?.media_series_id, w = _.attributes?.media_season ?? _.attributes?.season, k = _.attributes?.media_episode ?? _.attributes?.episode, y = lt(x), S = lt(v);
    let $ = !1;
    if (y && a && y === a)
      $ = !0;
    else if (n)
      if (y && a && y !== a)
        $ = !1;
      else {
        const C = !e.series_name || !b || ne(e.series_name, b), T = !!(e.name && (ne(m, e.name) || At(m, e.name))), N = e.season != null && e.episode != null && w != null && k != null && Number(e.season) === Number(w) && Number(e.episode) === Number(k);
        !(e.season != null && w != null && Number(e.season) !== Number(w) || e.episode != null && k != null && Number(e.episode) !== Number(k)) && C && (T || N) && ($ = !0);
      }
    else if (c) {
      const C = !!(S && a && S === a || y && a && y === a), T = !!(e.name && (ne(b, e.name) || ne(m, e.name)));
      (C || T) && ($ = !0);
    } else if (p) {
      const C = !e.series_name || !b || ne(e.series_name, b), T = e.season != null && w != null && Number(e.season) === Number(w), N = !!(e.name && ne(m, e.name));
      C && (T || N) && ($ = !0);
    } else
      e.name && (m || b) && ($ = !!(m && (ne(m, e.name) || At(m, e.name)) || b && ne(b, e.name)));
    if ($) {
      const C = {
        entityId: u,
        state: g,
        friendlyName: _.attributes?.friendly_name || u
      };
      if (g === "playing")
        return C;
      s || (s = C);
    }
  }
  return s;
}
function Mt(e, t) {
  const i = [];
  if (t?.default_cast_device && i.push(t.default_cast_device), t?.default_client_device && !i.includes(t.default_client_device) && i.push(t.default_client_device), e?.states) {
    for (const o of Object.keys(e.states))
      if (o.startsWith("media_player.jellyha_") && !o.includes("_library_browser") && !o.endsWith("_browser") && !i.includes(o)) {
        const s = e.states[o]?.state;
        (s === "playing" || s === "paused" || s === "buffering") && i.push(o);
      }
  }
  return i;
}
async function zi(e, t, i) {
  if (!e || !t) return;
  const a = !!((e.states?.[t]?.attributes?.supported_features || 0) & 256);
  t.startsWith("media_player.jellyha_") || !!(i?.default_client_device && t === i.default_client_device) || !a ? await e.callService("media_player", "media_stop", { entity_id: t }) : await e.callService("media_player", "turn_off", { entity_id: t });
}
function Mi(e) {
  if (!e || typeof e != "string") return !1;
  const t = e.trim();
  if (/^vnd\.youtube:[a-zA-Z0-9_-]{5,20}$/i.test(t))
    return !0;
  try {
    const i = new URL(t);
    return i.protocol === "https:" || i.protocol === "http:";
  } catch {
    return !1;
  }
}
function ae(e, t = "_blank") {
  return Mi(e) ? typeof window > "u" || typeof window.open != "function" ? null : window.open(e.trim(), t, "noopener,noreferrer") : (console.warn("Blocked opening unsafe URL:", e), null);
}
var Di = Object.defineProperty, Li = Object.getOwnPropertyDescriptor, A = (e, t, i, o) => {
  for (var s = o > 1 ? void 0 : o ? Li(t, i) : t, a = e.length - 1, r; a >= 0; a--)
    (r = e[a]) && (s = (o ? r(t, i, s) : r(s)) || s);
  return o && s && Di(t, i, s), s;
};
let j = class extends X {
  constructor() {
    super(...arguments), this._playTargets = [], this._showTargetPicker = !1, this._open = !1, this._confirmDelete = !1, this._viewMode = "default", this._episodes = [], this._selectedSeason = "all", this._touchStartY = 0, this._currentTranslateY = 0, this._isDragging = !1, this._swipeClosingThreshold = 100, this._rowTouchStartX = 0, this._rowTouchStartY = 0, this._portalContainer = null, this._handleKeyDown = (e) => {
      if (e.key === "Escape") {
        if (this._showTargetPicker) {
          this._closeTargetPicker(), e.stopPropagation();
          return;
        }
        this._open && this.closeDialog();
      }
    }, this.closeDialog = () => {
      this._open = !1, this._confirmDelete = !1, this._showTargetPicker = !1, this._pendingPlayItem = void 0, document.body.style.overflow = "", this.dispatchEvent(new CustomEvent("closed", { bubbles: !0, composed: !0 })), this.requestUpdate();
    }, this._toggleEpisodesView = (e) => {
      e && (e.stopPropagation(), e.preventDefault()), this._viewMode === "default" ? this._fetchEpisodes() : this._viewMode = "default";
    }, this._openTargetPicker = (e) => {
      this._haptic(), typeof document < "u" && document.activeElement instanceof HTMLElement && document.activeElement.blur(), this._pendingPlayItem = e, this._showTargetPicker = !0, this.requestUpdate();
    }, this._closeTargetPicker = () => {
      this._showTargetPicker = !1, this._pendingPlayItem = void 0, typeof document < "u" && document.activeElement instanceof HTMLElement && document.activeElement.blur(), this.requestUpdate();
    }, this._initiatePlay = (e) => {
      if (this._playTargets.length !== 0) {
        if (this._playTargets.length === 1) {
          this._executePlayTarget(this._playTargets[0], e);
          return;
        }
        this._openTargetPicker(e);
      }
    }, this._executePlayTarget = async (e, t) => {
      if (this._haptic("medium"), this._closeTargetPicker(), e.type === "cast") {
        const i = e.device || this._defaultCastDevice;
        if (!i) {
          this.dispatchEvent(new CustomEvent("hass-notification", {
            detail: { message: "No Chromecast device selected. Please configure a cast device in the card editor." },
            bubbles: !0,
            composed: !0
          }));
          return;
        }
        try {
          const o = {
            entity_id: i,
            item_id: t.id,
            subtitle_mode: this._subtitleMode || "auto",
            ...this._subtitleLanguage ? { subtitle_language: this._subtitleLanguage } : {}
          };
          (t.config_entry_id || this._item?.config_entry_id) && (o.config_entry_id = t.config_entry_id || this._item?.config_entry_id), this._serverEntityId && (o.server_entity_id = this._serverEntityId), await this.hass.callService("jellyha", "play_on_chromecast", o), this.closeDialog();
        } catch (o) {
          console.error("Failed to cast", o), this.dispatchEvent(new CustomEvent("hass-notification", {
            detail: { message: "Failed to cast item. Check logs." },
            bubbles: !0,
            composed: !0
          }));
        }
      } else if (e.type === "client") {
        const i = e.device || this._defaultClientDevice;
        if (!i) {
          this.dispatchEvent(new CustomEvent("hass-notification", {
            detail: { message: "No Jellyfin client selected. Please configure a client device in the card editor." },
            bubbles: !0,
            composed: !0
          }));
          return;
        }
        try {
          const o = {
            entity_id: i,
            item_id: t.id,
            ...this._serverEntityId ? { server_entity_id: this._serverEntityId } : {}
          };
          (t.config_entry_id || this._item?.config_entry_id) && (o.config_entry_id = t.config_entry_id || this._item?.config_entry_id), await this.hass.callService("jellyha", "session_play", o), this.closeDialog();
        } catch (o) {
          console.error("Failed to play on Jellyfin client", o);
        }
      } else if (e.type === "script") {
        if (!e.service) {
          console.error("No service specified for script play target", e);
          return;
        }
        try {
          const [i, o] = e.service.includes(".") ? e.service.split(".", 2) : ["script", e.service], s = {
            item_id: t.id,
            name: t.name,
            title: t.name,
            type: t.type,
            series_name: t.series_name,
            series_id: t.series_id,
            season: t.season,
            episode: t.episode,
            year: t.year,
            genres: t.genres,
            rating: t.rating,
            poster_url: t.poster_url,
            backdrop_url: t.backdrop_url,
            path: t.path,
            filepath: t.filepath,
            jellyfin_url: this._getJellyfinUrl(t),
            action_type: "modal",
            ...e.service_data || {}
          };
          this.dispatchEvent(new CustomEvent("jellyha_item_clicked", {
            detail: {
              item: t,
              action: "call-service",
              service: e.service,
              service_data: s
            },
            bubbles: !0,
            composed: !0
          })), await this.hass.callService(i, o, s), this.closeDialog();
        } catch (i) {
          console.error("Failed to execute script", i), this.dispatchEvent(new CustomEvent("hass-notification", {
            detail: { message: `Failed to execute script ${e.service}. Check logs.` },
            bubbles: !0,
            composed: !0
          }));
        }
      } else (e.type === "browser" || e.type === "play-browser") && (this.closeDialog(), await Ht({
        hass: this.hass,
        item: t,
        configEntryId: t.config_entry_id || this._item?.config_entry_id,
        serverEntityId: this._serverEntityId,
        subtitleMode: this._subtitleMode,
        subtitleLanguage: this._subtitleLanguage
      }));
    }, this._handlePlayEpisode = async (e) => {
      this._haptic(), this._initiatePlay(e);
    }, this._handlePlay = async () => {
      this._haptic();
      const e = this._item?.type === "Series" && this._nextUpItem ? this._nextUpItem : this._item;
      e && this._initiatePlay(e);
    }, this._playNextUp = async () => {
      this._haptic(), this._nextUpItem && this._initiatePlay(this._nextUpItem);
    }, this._handleFavorite = async () => {
      if (!this._item) return;
      this._haptic();
      const e = !this._item.is_favorite;
      this._item = { ...this._item, is_favorite: e };
      const t = {
        item_id: this._item.id,
        is_favorite: e
      };
      this._item.config_entry_id && (t.config_entry_id = this._item.config_entry_id), this._serverEntityId && (t.entity_id = this._serverEntityId, t.server_entity_id = this._serverEntityId), await this.hass.callService("jellyha", "update_favorite", t), this.requestUpdate();
    }, this._handleWatched = async () => {
      if (!this._item) return;
      this._haptic();
      const e = !this._item.is_played;
      this._item = { ...this._item, is_played: e };
      const t = {
        item_id: this._item.id,
        is_played: e
      };
      this._item.config_entry_id && (t.config_entry_id = this._item.config_entry_id), this._serverEntityId && (t.entity_id = this._serverEntityId, t.server_entity_id = this._serverEntityId), await this.hass.callService("jellyha", "mark_watched", t), this.requestUpdate();
    }, this._handleDeleteConfirm = async () => {
      if (!this._item) return;
      this._haptic();
      const e = this._item.id, t = {
        item_id: e
      };
      this._item.config_entry_id && (t.config_entry_id = this._item.config_entry_id), this._serverEntityId && (t.entity_id = this._serverEntityId, t.server_entity_id = this._serverEntityId), this.closeDialog();
      try {
        await this.hass.callService("jellyha", "delete_item", t);
      } catch (i) {
        console.error("Failed to delete item", i);
        const o = i instanceof Error ? i.message : i?.message;
        this.dispatchEvent(new CustomEvent("hass-notification", {
          detail: { message: o ? `Failed to delete item: ${o}` : "Failed to delete item. Check logs." },
          bubbles: !0,
          composed: !0
        }));
        return;
      }
      typeof window < "u" && window.dispatchEvent(new CustomEvent("jellyha-item-deleted", {
        detail: { itemId: e }
      }));
    }, this._handleWatchTrailer = () => {
      this._haptic();
      const e = this._item;
      if (!e?.trailer_url) return;
      let t = e.trailer_url.trim();
      !t.startsWith("http://") && !t.startsWith("https://") && (t = "https://" + t);
      let i = "";
      try {
        const o = new URL(t);
        o.hostname.includes("youtube.com") ? o.searchParams.has("v") ? i = o.searchParams.get("v") || "" : o.pathname.startsWith("/embed/") ? i = o.pathname.split("/embed/")[1]?.split("/")[0] || "" : o.pathname.startsWith("/shorts/") && (i = o.pathname.split("/shorts/")[1]?.split("/")[0] || "") : o.hostname.includes("youtu.be") && (i = o.pathname.replace(/^\/+/, "").split("/")[0] || "");
      } catch {
      }
      if (i) {
        const o = navigator.userAgent || navigator.vendor || window.opera;
        if (/android/i.test(o)) {
          ae(`vnd.youtube:${i}`, "_blank");
          return;
        }
        ae(`https://www.youtube.com/watch?v=${i}`, "_blank");
        return;
      }
      ae(t, "_blank");
    }, this._handleMarkEpisodeWatched = async (e) => {
      this._haptic();
      const t = !e.is_played;
      if (this._episodes = this._episodes.map(
        (o) => o.id === e.id ? { ...o, is_played: t, unplayed_count: t ? 0 : 1 } : o
      ), t && this._nextUpItem && e.id === this._nextUpItem.id) {
        const o = this._episodes.findIndex((s) => s.id === e.id);
        o !== -1 && o < this._episodes.length - 1 && (this._nextUpItem = this._episodes[o + 1]);
      } else if (!t && this._nextUpItem && e.id !== this._nextUpItem.id) {
        const o = this._episodes.findIndex((a) => a.id === e.id), s = this._episodes.findIndex((a) => a.id === this._nextUpItem.id);
        o !== -1 && s !== -1 && o < s && (this._nextUpItem = this._episodes[o]);
      }
      this.requestUpdate();
      const i = {
        item_id: e.id,
        is_played: t
      };
      (e.config_entry_id || this._item?.config_entry_id) && (i.config_entry_id = e.config_entry_id || this._item?.config_entry_id), this._serverEntityId && (i.entity_id = this._serverEntityId, i.server_entity_id = this._serverEntityId), await this.hass.callService("jellyha", "mark_watched", i);
    }, this._handleModalTouchStart = (e) => {
      const t = e.target, i = this._getScrollParent(t);
      i && i.scrollTop > 0 || (this._touchStartY = e.touches[0].clientY, this._isDragging = !0);
    }, this._handleModalTouchMove = (e) => {
      if (!this._isDragging) return;
      const t = e.touches[0].clientY - this._touchStartY;
      t > 0 ? (e.cancelable && e.preventDefault(), this._currentTranslateY = t) : this._isDragging = !1;
    }, this._handleModalTouchEnd = (e) => {
      this._isDragging && (this._isDragging = !1, this._currentTranslateY > this._swipeClosingThreshold ? (this.closeDialog(), setTimeout(() => {
        this._currentTranslateY = 0;
      }, 300)) : this._currentTranslateY = 0);
    };
  }
  connectedCallback() {
    super.connectedCallback(), this._portalContainer = document.createElement("div"), this._portalContainer.id = "jellyha-modal-portal", document.body.appendChild(this._portalContainer), window.addEventListener("keydown", this._handleKeyDown);
  }
  disconnectedCallback() {
    super.disconnectedCallback(), window.removeEventListener("keydown", this._handleKeyDown), this._portalContainer && (this._portalContainer.remove(), this._portalContainer = null), document.body.style.overflow = "";
  }
  async showDialog(e) {
    this._item = e.item, this.hass = e.hass, this._defaultCastDevice = e.defaultCastDevice, this._defaultClientDevice = e.defaultClientDevice, this._serverEntityId = e.serverEntityId, this._subtitleMode = e.subtitleMode, this._subtitleLanguage = e.subtitleLanguage, this._playTargets = e.playTargets || [], this._showEntityName = e.showEntityName, this._showTargetPicker = !1, this._pendingPlayItem = void 0, this._open = !0, this._nextUpItem = void 0, this._viewMode = "default", this._episodes = [], this._selectedSeason = "all", document.body.style.overflow = "hidden", this._item.type === "Series" && this._fetchNextUp(this._item), this._fetchFullDetails(this._item.id), await this.updateComplete;
  }
  async _fetchFullDetails(e) {
    try {
      const t = await this.hass.callWS({
        type: "call_service",
        domain: "jellyha",
        service: "get_item",
        service_data: {
          item_id: e,
          entity_id: this._serverEntityId,
          server_entity_id: this._serverEntityId,
          config_entry_id: this._item?.config_entry_id
        },
        return_response: !0
      }), i = t?.response || t?.service_response || t;
      i && i.item && (this._item = { ...this._item, ...i.item }, this.requestUpdate());
    } catch (t) {
      console.warn("Failed to fetch full item details:", JSON.stringify(t, null, 2));
    }
  }
  async _fetchNextUp(e) {
    const t = Object.keys(this.hass.states).filter(
      (o) => (this.hass.states[o].attributes.integration === "jellyha" || o.startsWith("sensor.jellyha_")) && this.hass.states[o].attributes.entry_id
    ), i = this._serverEntityId || (t.length > 0 ? t[0] : "sensor.jellyha_library");
    try {
      const o = await this.hass.callWS({
        type: "jellyha/get_next_up",
        entity_id: i,
        server_entity_id: this._serverEntityId,
        ...this._item?.config_entry_id ? { config_entry_id: this._item.config_entry_id } : {},
        series_id: e.id
      });
      o && o.item && (this._nextUpItem = o.item);
    } catch (o) {
      console.warn("Failed to fetch Next Up:", o);
    }
  }
  async _fetchEpisodes() {
    if (!this._item || this._item.type !== "Series") return;
    const e = Object.keys(this.hass.states).filter(
      (i) => (this.hass.states[i].attributes.integration === "jellyha" || i.startsWith("sensor.jellyha_")) && this.hass.states[i].attributes.entry_id
    ), t = this._serverEntityId || (e.length > 0 ? e[0] : "sensor.jellyha_library");
    try {
      this._viewMode = "episodes", this.requestUpdate();
      let i = null;
      try {
        i = await this.hass.callWS({
          type: "jellyha/get_episodes",
          entity_id: t,
          server_entity_id: this._serverEntityId,
          ...this._item?.config_entry_id ? { config_entry_id: this._item.config_entry_id } : {},
          series_id: this._item.id
        });
      } catch {
        const s = this._nextUpItem?.season || 1;
        i = await this.hass.callWS({
          type: "jellyha/get_episodes",
          entity_id: t,
          server_entity_id: this._serverEntityId,
          ...this._item?.config_entry_id ? { config_entry_id: this._item.config_entry_id } : {},
          series_id: this._item.id,
          season: s
        });
      }
      i && i.items ? this._episodes = i.items : this._episodes = [], this.requestUpdate();
    } catch (i) {
      console.warn("Failed to fetch episodes:", i), this._episodes = [], this.requestUpdate();
    }
  }
  updated() {
    if (this._portalContainer) {
      et(this._renderDialogContent(), this._portalContainer);
      const e = this._portalContainer.querySelector(".jellyha-modal-surface");
      e && (e.removeEventListener("touchstart", this._handleModalTouchStart), e.removeEventListener("touchmove", this._handleModalTouchMove), e.removeEventListener("touchend", this._handleModalTouchEnd), e.addEventListener("touchstart", this._handleModalTouchStart, { passive: !0 }), e.addEventListener("touchmove", this._handleModalTouchMove, { passive: !1 }), e.addEventListener("touchend", this._handleModalTouchEnd, { passive: !0 }));
    }
  }
  render() {
    return l``;
  }
  _getPortalStyles() {
    return l`
        <style>
            .jellyha-modal-scrim {
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                z-index: 99999;
                background: rgba(0, 0, 0, 0.45);
                backdrop-filter: blur(3px);
                -webkit-backdrop-filter: blur(3px);
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 16px;
                box-sizing: border-box;
                animation: jellyhaFadeIn 0.2s ease-out;
            }

            @keyframes jellyhaFadeIn {
                from { opacity: 0; }
                to { opacity: 1; }
            }

            @keyframes jellyhaSlideUp {
                from { transform: scale(0.96) translateY(16px); opacity: 0; }
                to { transform: scale(1) translateY(0); opacity: 1; }
            }

            .jellyha-modal-surface {
                position: relative;
                display: flex;
                flex-direction: column;
                transform-origin: center center;
                will-change: transform;
                background: #14161f;
                color: #ffffff;
                box-sizing: border-box;
                border-radius: 24px;
                border: var(--ha-card-border, var(--ha-card-border-width, 1px) solid var(--ha-card-border-color, var(--divider-color, rgba(255, 255, 255, 0.14))));
                box-shadow: 0 24px 72px rgba(0, 0, 0, 0.8);
                width: min(840px, 94vw);
                max-height: min(90vh, 880px);
                overscroll-behavior-y: contain;
                scrollbar-width: none; 
                -ms-overflow-style: none; 
                overflow: hidden;
                animation: jellyhaSlideUp 0.25s cubic-bezier(0.16, 1, 0.3, 1);
            }

            .jellyha-modal-surface::-webkit-scrollbar {
                display: none; 
                width: 0px !important;
                height: 0px !important;
                background: transparent;
            }

            /* Top-Right Circular Close Button */
            .modal-close-btn {
                position: absolute;
                top: 16px;
                right: 16px;
                z-index: 20;
                background: rgba(255, 255, 255, 0.1);
                backdrop-filter: blur(8px);
                -webkit-backdrop-filter: blur(8px);
                border: 1px solid rgba(255, 255, 255, 0.2);
                border-radius: 50%;
                width: 38px;
                height: 38px;
                display: flex;
                align-items: center;
                justify-content: center;
                cursor: pointer;
                color: #ffffff;
                transition: all 0.2s ease;
                padding: 0;
            }
            .modal-close-btn:hover {
                background: rgba(255, 255, 255, 0.25);
                border-color: rgba(255, 255, 255, 0.4);
                transform: scale(1.08);
            }
            .modal-close-btn ha-icon {
                --mdc-icon-size: 20px;
            }

            /* Backdrop Hero Fanart */
            .backdrop-hero {
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                height: 320px;
                pointer-events: none;
                overflow: hidden;
                mask-image: linear-gradient(to bottom, rgba(0,0,0,1) 0%, rgba(0,0,0,0.65) 50%, rgba(0,0,0,0) 100%);
                -webkit-mask-image: linear-gradient(to bottom, rgba(0,0,0,1) 0%, rgba(0,0,0,0.65) 50%, rgba(0,0,0,0) 100%);
                z-index: 0;
            }

            .backdrop-img {
                width: 100%;
                height: 100%;
                object-fit: cover;
                object-position: center 25%;
                opacity: 0.35;
                filter: saturate(1.2) brightness(0.9);
            }

            /* Inner Layouts (Default View) */
            .default-layout {
                position: relative;
                z-index: 1;
                display: block;
                overflow-y: auto;
                height: 100%;
                width: 100%;
                box-sizing: border-box;
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
                    grid-template-columns: 240px 1fr;
                    gap: 28px;
                    padding: 28px;
                    overflow-y: auto; 
                }
                .poster-col {
                    width: 240px;
                }
            }

            @media (max-width: 600px) {
                .default-layout {
                    display: flex;
                    flex-direction: column;
                    gap: 20px;
                    padding: 20px;
                }
                .poster-col {
                    max-width: 240px;
                    margin: 0 auto;
                    width: 100%;
                }
            }

            .poster-col {
                display: flex;
                flex-direction: column;
                gap: 14px;
                position: relative;
                z-index: 1;
            }

            .poster-img {
                width: 100%;
                aspect-ratio: 2/3;
                object-fit: cover;
                border-radius: 14px;
                box-shadow: 0 10px 30px rgba(0, 0, 0, 0.6);
                border: 1px solid rgba(255, 255, 255, 0.12);
            }

            .poster-actions {
                display: flex;
                flex-direction: column;
                gap: 10px;
                width: 100%;
            }

            .primary-play-btn {
                display: flex;
                align-items: center;
                justify-content: center;
                gap: 8px;
                width: 100%;
                padding: 11px 16px;
                box-sizing: border-box;
                background: rgba(3, 169, 244, 0.15);
                color: #ffffff;
                border: 1px solid rgba(3, 169, 244, 0.35);
                border-radius: 24px;
                font-size: 0.95rem;
                font-weight: 600;
                cursor: pointer;
                box-shadow: 0 4px 14px rgba(0, 0, 0, 0.25);
                backdrop-filter: blur(8px);
                -webkit-backdrop-filter: blur(8px);
                transition: all 0.2s ease;
                outline: none;
                -webkit-tap-highlight-color: transparent;
            }
            .primary-play-btn:focus,
            .primary-play-btn:focus-visible,
            button:focus,
            button:focus-visible {
                outline: none;
            }
            .primary-play-btn ha-icon {
                --mdc-icon-size: 20px;
                color: #03a9f4;
                transition: color 0.2s ease;
            }
            .primary-play-btn:hover {
                background: rgba(3, 169, 244, 0.28);
                color: #ffffff;
                border-color: rgba(3, 169, 244, 0.6);
                box-shadow: 0 6px 20px rgba(0, 0, 0, 0.35), 0 0 16px rgba(3, 169, 244, 0.3);
                transform: translateY(-1px);
            }
            .primary-play-btn:hover ha-icon {
                color: #ffffff;
            }
            .primary-play-btn:active {
                transform: scale(0.98);
            }

            .actions-icon-row {
                display: flex;
                flex-wrap: wrap;
                gap: 6px;
                justify-content: center;
                align-items: center;
                width: 100%;
            }

            .action-btn {
                display: flex;
                align-items: center;
                justify-content: center;
                border-radius: 50%;
                border: 1px solid rgba(255, 255, 255, 0.16);
                cursor: pointer;
                background: rgba(255, 255, 255, 0.08);
                color: #d0d4e0;
                width: 34px;
                height: 34px;
                padding: 0;
                box-sizing: border-box;
                text-decoration: none;
                transition: all 0.2s ease;
            }
            .action-btn:hover {
                background: rgba(255, 255, 255, 0.2);
                color: #ffffff;
                border-color: rgba(255, 255, 255, 0.35);
                transform: translateY(-1px);
            }
            .action-btn.active {
                color: #03a9f4;
                border-color: #03a9f4;
                background: rgba(3, 169, 244, 0.2);
            }
            .action-btn.favorite-btn.active {
                color: #ff5252;
                border-color: #ff5252;
                background: rgba(255, 82, 82, 0.2);
            }
            .action-btn ha-icon {
                --mdc-icon-size: 18px;
            }

            .btn-danger {
                color: #ff5252;
                border-color: rgba(255, 82, 82, 0.35);
            }
            .btn-danger:hover {
                background: rgba(255, 82, 82, 0.25);
                border-color: #ff5252;
            }

            .confirmation-box {
                display: flex;
                gap: 8px;
                align-items: center;
                justify-content: center;
                width: 100%;
                background: rgba(255, 82, 82, 0.15);
                border: 1px solid rgba(255, 82, 82, 0.35);
                border-radius: 12px;
                padding: 8px;
                box-sizing: border-box;
                font-size: 0.85rem;
                color: #ffffff;
            }
            .confirm-btn {
                background: rgba(255, 255, 255, 0.12);
                border: none;
                cursor: pointer;
                color: #ffffff;
                font-weight: 600;
                padding: 5px 12px;
                border-radius: 6px;
                transition: background 0.2s;
            }
            .confirm-btn:hover {
                 background: rgba(255, 255, 255, 0.22);
            }
            .confirm-yes {
                background: #e53935;
                color: #ffffff;
            }
            .confirm-yes:hover {
                background: #d32f2f;
            }

            .details-col {
                display: flex;
                flex-direction: column;
                gap: 16px;
                position: relative;
                z-index: 1;
                min-width: 0;
            }

            .header-group {
                padding-right: 52px;
            }

            .header-group h1 {
                margin: 0;
                font-size: 2.1rem;
                font-weight: 700;
                line-height: 1.2;
                color: #ffffff;
                letter-spacing: -0.5px;
            }

            .header-sub {
                display: flex;
                flex-wrap: wrap;
                gap: 10px;
                align-items: center;
                margin-top: 8px;
                color: #9ea4b5;
                font-size: 0.95rem;
            }

            .badge {
                padding: 3px 8px;
                border-radius: 6px;
                background: rgba(255, 255, 255, 0.1);
                color: #ffffff;
                font-size: 0.8rem;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 0.4px;
                border: 1px solid rgba(255, 255, 255, 0.15);
            }

            .stats-row {
                display: flex;
                flex-wrap: wrap;
                gap: 10px;
                padding: 2px 0;
            }

            .stat-item {
                display: inline-flex;
                gap: 6px;
                align-items: center;
                border: 1px solid rgba(255, 255, 255, 0.14);
                background: rgba(255, 255, 255, 0.07);
                border-radius: 18px;
                padding: 5px 14px;
                font-size: 0.9rem;
                font-weight: 500;
                color: #e2e4ea;
            }
            .stat-item ha-icon {
                --mdc-icon-size: 16px;
            }

            .description {
                font-size: 0.95rem;
                line-height: 1.65;
                color: #c4c8d4;
                white-space: pre-wrap;
            }

            .genres-list {
                display: flex;
                flex-wrap: wrap;
                gap: 8px;
            }

            .genre-tag {
                background: rgba(3, 169, 244, 0.15);
                color: #4fc3f7;
                padding: 4px 12px;
                border-radius: 14px;
                font-size: 0.8rem;
                font-weight: 500;
                border: 1px solid rgba(3, 169, 244, 0.3);
            }

            .divider {
                height: 1px;
                background: rgba(255, 255, 255, 0.1);
                margin: 4px 0;
            }

            .tech-specs-row {
                display: flex;
                flex-wrap: wrap;
                gap: 8px;
                align-items: center;
                margin-top: 2px;
            }

            .tech-chip {
                display: inline-flex;
                align-items: center;
                gap: 5px;
                background: rgba(255, 255, 255, 0.08);
                border: 1px solid rgba(255, 255, 255, 0.16);
                border-radius: 6px;
                padding: 4px 10px;
                font-size: 0.75rem;
                font-weight: 600;
                letter-spacing: 0.6px;
                color: #c0c5d4;
                text-transform: uppercase;
            }
            .tech-chip ha-icon {
                --mdc-icon-size: 14px;
                color: #9ea4b5;
            }
            .tech-chip-hdr {
                background: rgba(255, 180, 0, 0.12);
                border-color: rgba(255, 195, 0, 0.35);
                color: #ffca28;
            }
            .tech-chip-hdr ha-icon {
                color: #ffca28;
            }

            /* Next Up Modern Card */
            .next-up-card {
                background: rgba(255, 255, 255, 0.06);
                border: 1px solid rgba(255, 255, 255, 0.14);
                border-radius: 16px;
                padding: 12px 16px;
                display: flex;
                gap: 16px;
                align-items: center;
                cursor: pointer;
                transition: all 0.2s ease;
                position: relative;
                overflow: hidden;
                width: 100%;
                box-sizing: border-box;
            }
            .next-up-card:hover {
                background: rgba(255, 255, 255, 0.1);
                border-color: rgba(255, 255, 255, 0.28);
                transform: translateY(-1px);
            }
            .next-up-card:active {
                transform: scale(0.99);
            }
            .next-up-thumb-wrap {
                position: relative;
                width: 140px;
                flex-shrink: 0;
                aspect-ratio: 16/9;
                border-radius: 10px;
                overflow: hidden;
                background: rgba(0, 0, 0, 0.5);
                border: 1px solid rgba(255, 255, 255, 0.12);
            }
            .next-up-thumb {
                width: 100%;
                height: 100%;
                object-fit: cover;
                display: block;
                transition: transform 0.25s ease;
            }
            .next-up-card:hover .next-up-thumb {
                transform: scale(1.015);
            }
            .next-up-play-overlay {
                position: absolute;
                inset: 0;
                background: rgba(0, 0, 0, 0.2);
                display: flex;
                align-items: center;
                justify-content: center;
                opacity: 0;
                transition: opacity 0.2s ease;
                pointer-events: none;
            }
            .next-up-card:hover .next-up-play-overlay {
                opacity: 1;
            }
            .next-up-play-overlay ha-icon {
                --mdc-icon-size: 28px;
                color: #ffffff;
                filter: drop-shadow(0 2px 6px rgba(0, 0, 0, 0.7));
                transition: transform 0.2s ease;
            }
            .next-up-card:hover .next-up-play-overlay ha-icon {
                transform: scale(1.03);
            }
            .next-up-info {
                flex: 1;
                min-width: 0;
                display: flex;
                flex-direction: column;
                gap: 4px;
            }
            .next-up-header-row {
                display: flex;
                align-items: center;
                gap: 8px;
            }
            .next-up-badge {
                font-size: 0.7rem;
                font-weight: 700;
                letter-spacing: 0.5px;
                color: #03a9f4;
                background: rgba(3, 169, 244, 0.16);
                padding: 2px 7px;
                border-radius: 4px;
                border: 1px solid rgba(3, 169, 244, 0.25);
            }
            .next-up-ep-code {
                font-size: 0.92rem;
                font-weight: 600;
                color: rgba(255, 255, 255, 0.65);
                letter-spacing: 0.3px;
                line-height: 1;
            }
            .next-up-title {
                margin: 0;
                font-size: 1.15rem;
                font-weight: 600;
                color: #ffffff;
                white-space: nowrap;
                overflow: hidden;
                text-overflow: ellipsis;
            }
            .next-up-sub {
                display: flex;
                align-items: center;
                gap: 8px;
                font-size: 0.85rem;
                color: #9ea4b5;
            }
            .next-up-rating {
                display: inline-flex;
                align-items: center;
                gap: 3px;
                color: #FBC02D;
            }
            .next-up-rating ha-icon {
                --mdc-icon-size: 14px;
            }
            .next-up-cast-btn {
                background: rgba(3, 169, 244, 0.15);
                color: #03a9f4;
                border: 1px solid rgba(3, 169, 244, 0.3);
                border-radius: 50%;
                width: 42px;
                height: 42px;
                display: flex;
                align-items: center;
                justify-content: center;
                cursor: pointer;
                flex-shrink: 0;
                backdrop-filter: blur(8px);
                -webkit-backdrop-filter: blur(8px);
                transition: all 0.2s ease;
                padding: 0;
            }
            .next-up-cast-btn:hover {
                background: rgba(3, 169, 244, 0.28);
                border-color: rgba(3, 169, 244, 0.6);
                color: #ffffff;
                box-shadow: 0 4px 16px rgba(0, 0, 0, 0.3), 0 0 12px rgba(3, 169, 244, 0.3);
                transform: scale(1.05);
            }
            .next-up-cast-btn:active {
                transform: scale(0.96);
            }
            .next-up-cast-btn ha-icon {
                --mdc-icon-size: 20px;
            }

            /* Episodes View specific */
            .jellyha-modal-surface.episodes {
                overflow: hidden !important; 
                padding: 16px 20px 24px 20px;
                max-height: min(90vh, 880px);
                box-sizing: border-box;
            }
            .jellyha-modal-surface.episodes .modal-close-btn {
                top: 16px;
                right: 20px;
            }

            .episodes-container {
                display: flex;
                flex-direction: column;
                height: 100%;
                min-height: 0;
                overflow: visible;
                position: relative;
                z-index: 1;
            }

            /* Episode List Styles */
            .episodes-header {
                 display: flex;
                 align-items: center;
                 gap: 14px;
                 margin-bottom: 18px;
                 padding-right: 56px;
                 padding-top: 4px;
                 padding-bottom: 4px;
                 margin-top: -4px;
            }
            .back-btn {
                background: rgba(255, 255, 255, 0.1);
                backdrop-filter: blur(8px);
                -webkit-backdrop-filter: blur(8px);
                border: 1px solid rgba(255, 255, 255, 0.2);
                color: #ffffff;
                cursor: pointer;
                width: 38px;
                height: 38px;
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 0;
                transition: all 0.2s ease;
                flex-shrink: 0;
            }
            .back-btn:hover {
                background: rgba(255, 255, 255, 0.25);
                border-color: rgba(255, 255, 255, 0.4);
                transform: scale(1.08);
            }
            .back-btn ha-icon {
                --mdc-icon-size: 20px;
            }
            .episodes-title {
                margin: 0;
                font-size: 1.6rem;
                font-weight: 700;
                color: #ffffff;
            }
            .season-selector {
                display: flex;
                gap: 8px;
                margin-bottom: 16px;
                overflow-x: auto;
                padding-bottom: 4px;
                scrollbar-width: none;
            }
            .season-selector::-webkit-scrollbar {
                display: none;
            }
            .season-tab {
                background: rgba(255, 255, 255, 0.08);
                border: 1px solid rgba(255, 255, 255, 0.15);
                color: rgba(255, 255, 255, 0.8);
                padding: 6px 14px;
                border-radius: 20px;
                cursor: pointer;
                font-size: 0.85rem;
                font-weight: 500;
                transition: all 0.2s ease;
                white-space: nowrap;
            }
            .season-tab:hover {
                background: rgba(255, 255, 255, 0.15);
                color: #ffffff;
            }
            .season-tab.active {
                background: var(--primary-color, #03a9f4);
                border-color: var(--primary-color, #03a9f4);
                color: #ffffff;
                font-weight: 600;
            }
            .season-tab:active {
                transform: scale(0.95);
            }
            .episodes-list {
                display: flex;
                flex-direction: column;
                gap: 12px;
                overflow-y: auto;
                flex: 1;
                min-height: 0;
                padding: 6px 4px 12px 0;
                margin-top: -6px;
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
                padding: 12px 16px;
                background: rgba(255, 255, 255, 0.04);
                border: 1px solid rgba(255, 255, 255, 0.08);
                border-radius: 14px;
                align-items: center;
                transition: all 0.2s ease;
                cursor: pointer;
                user-select: none;
                -webkit-user-select: none;
                -webkit-tap-highlight-color: transparent;
            }
            .episode-row:hover {
                background: rgba(255, 255, 255, 0.09);
                border-color: rgba(255, 255, 255, 0.2);
                transform: translateY(-1px);
            }
            .episode-row:active,
            .episode-row.active-press {
                transform: scale(0.99);
            }
            .episode-row.next-up-highlight {
                background: rgba(3, 169, 244, 0.12);
                border-color: rgba(3, 169, 244, 0.25);
            }
            .episode-row.next-up-highlight:hover {
                background: rgba(3, 169, 244, 0.18);
                border-color: rgba(3, 169, 244, 0.35);
                transform: translateY(-1px);
            }
            .episode-row.next-up-highlight:active,
            .episode-row.next-up-highlight.active-press {
                transform: scale(0.99);
            }
            .episode-thumb-wrap {
                position: relative;
                width: 120px;
                aspect-ratio: 16/9;
                border-radius: 8px;
                overflow: hidden;
                flex-shrink: 0; 
                background: rgba(0, 0, 0, 0.5);
                border: 1px solid rgba(255, 255, 255, 0.12);
            }
            .episode-thumb {
                width: 100%;
                height: 100%;
                object-fit: cover;
                display: block;
                transition: transform 0.25s ease;
            }
            .episode-play-overlay {
                position: absolute;
                inset: 0;
                background: rgba(0, 0, 0, 0.2);
                display: flex;
                align-items: center;
                justify-content: center;
                opacity: 0;
                transition: opacity 0.2s ease;
                pointer-events: none;
            }
            .episode-row:hover .episode-play-overlay {
                opacity: 1;
            }
            .episode-row:hover .episode-thumb {
                transform: scale(1.015);
            }
            .episode-play-overlay ha-icon {
                --mdc-icon-size: 28px;
                color: #ffffff;
                filter: drop-shadow(0 2px 6px rgba(0, 0, 0, 0.6));
                transition: transform 0.2s ease;
            }
            .episode-row:hover .episode-play-overlay ha-icon {
                transform: scale(1.03);
            }
            .episode-content {
                flex: 1;
                min-width: 0;
                display: flex;
                flex-direction: column;
                justify-content: center;
                gap: 4px;
            }
            .episode-header-line {
                display: flex;
                align-items: center;
                gap: 8px;
                line-height: 1;
            }
            .episode-number {
                font-size: 0.82rem;
                font-weight: 600;
                color: rgba(255, 255, 255, 0.65);
                letter-spacing: 0.3px;
                text-transform: uppercase;
            }
            .next-up-badge {
                font-size: 0.65rem;
                font-weight: 700;
                background: var(--primary-color, #03a9f4);
                color: #ffffff;
                padding: 2px 6px;
                border-radius: 4px;
                letter-spacing: 0.5px;
                white-space: nowrap;
                line-height: 1.2;
            }
            .episode-title {
                margin: 0;
                font-size: 1rem;
                font-weight: 600;
                line-height: 1.3;
                color: #ffffff;
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
            }
            .episode-meta {
                font-size: 0.82rem;
                color: #9ea4b5;
                display: flex;
                align-items: center;
                gap: 6px;
                line-height: 1.2;
            }
            .episode-meta .meta-dot {
                color: rgba(255, 255, 255, 0.35);
                font-size: 0.8rem;
            }
            .episode-rating {
                display: inline-flex;
                align-items: center;
                gap: 4px;
            }
            .episode-rating ha-icon {
                --mdc-icon-size: 13px;
                color: #FBC02D;
                transform: translateY(-1px);
            }
            .episode-actions {
                display: flex;
                gap: 8px;
                align-items: center;
                flex-shrink: 0;
                margin-left: auto;
            }
            .play-episode-btn {
                background: rgba(255, 255, 255, 0.08);
                border: 1px solid rgba(255, 255, 255, 0.15);
                color: #03a9f4;
                border-radius: 50%;
                width: 34px;
                height: 34px;
                display: flex;
                align-items: center;
                justify-content: center;
                cursor: pointer;
                transition: all 0.2s;
                padding: 0;
            }
            .play-episode-btn:hover {
                background: rgba(3, 169, 244, 0.25);
                border-color: rgba(3, 169, 244, 0.5);
                color: #ffffff;
                transform: scale(1.08);
            }
            .play-episode-btn:active {
                transform: scale(0.92);
            }
            .play-episode-btn ha-icon {
                --mdc-icon-size: 18px;
            }
            .watched-btn {
                color: #9ea4b5;
            }
            .watched-btn.active {
                color: #03a9f4;
                background: rgba(3, 169, 244, 0.2);
                border-color: #03a9f4;
            }

            /* Target Picker Action Sheet Overlay */
            .target-picker-overlay {
                position: absolute;
                inset: 0;
                background: rgba(0, 0, 0, 0.45);
                backdrop-filter: blur(3px);
                -webkit-backdrop-filter: blur(3px);
                display: flex;
                align-items: center;
                justify-content: center;
                z-index: 60;
                padding: 20px;
                box-sizing: border-box;
                border-radius: 28px;
                animation: targetPickerFadeIn 0.2s ease-out;
            }
            @keyframes targetPickerFadeIn {
                from { opacity: 0; }
                to { opacity: 1; }
            }
            .target-picker-card {
                background: #181b28;
                border: var(--ha-card-border, var(--ha-card-border-width, 1px) solid var(--ha-card-border-color, var(--divider-color, rgba(255, 255, 255, 0.14))));
                border-radius: 20px;
                width: 100%;
                max-width: 360px;
                box-shadow: 0 20px 48px rgba(0, 0, 0, 0.7);
                padding: 20px;
                box-sizing: border-box;
                display: flex;
                flex-direction: column;
                gap: 14px;
                animation: targetPickerScaleUp 0.2s cubic-bezier(0.16, 1, 0.3, 1);
            }
            @keyframes targetPickerScaleUp {
                from { transform: scale(0.92); opacity: 0; }
                to { transform: scale(1); opacity: 1; }
            }
            .target-picker-header {
                display: flex;
                align-items: center;
                justify-content: space-between;
                gap: 12px;
            }
            .target-picker-title-wrap {
                display: flex;
                flex-direction: column;
                gap: 2px;
                overflow: hidden;
            }
            .target-picker-title {
                font-size: 1.05rem;
                font-weight: 700;
                color: #ffffff;
                letter-spacing: 0.3px;
            }
            .target-picker-item-name {
                font-size: 0.8rem;
                color: rgba(255, 255, 255, 0.6);
                white-space: nowrap;
                overflow: hidden;
                text-overflow: ellipsis;
            }
            .target-picker-close-btn {
                background: rgba(255, 255, 255, 0.1);
                backdrop-filter: blur(8px);
                -webkit-backdrop-filter: blur(8px);
                border: 1px solid rgba(255, 255, 255, 0.2);
                border-radius: 50%;
                width: 34px;
                height: 34px;
                display: flex;
                align-items: center;
                justify-content: center;
                cursor: pointer;
                color: #ffffff;
                transition: all 0.2s ease;
                padding: 0;
                flex-shrink: 0;
            }
            .target-picker-close-btn:hover {
                background: rgba(255, 255, 255, 0.25);
                border-color: rgba(255, 255, 255, 0.4);
                transform: scale(1.08);
            }
            .target-picker-close-btn ha-icon {
                --mdc-icon-size: 18px;
            }
            .target-picker-list {
                display: flex;
                flex-direction: column;
                gap: 8px;
                max-height: 280px;
                overflow-y: auto;
                padding: 4px;
                margin: -4px;
                scrollbar-width: thin;
                scrollbar-color: rgba(255, 255, 255, 0.2) transparent;
            }
            .target-option-btn {
                display: flex;
                align-items: center;
                gap: 12px;
                padding: 12px 14px;
                border-radius: 12px;
                background: rgba(255, 255, 255, 0.05);
                border: 1px solid rgba(255, 255, 255, 0.09);
                color: #ffffff;
                cursor: pointer;
                text-align: left;
                transition: all 0.2s ease;
                box-sizing: border-box;
                width: 100%;
            }
            .target-option-btn:hover {
                background: rgba(2, 136, 209, 0.22);
                border-color: rgba(2, 136, 209, 0.55);
                transform: translateY(-1px);
            }
            .target-option-btn:active {
                transform: scale(0.98);
            }
            .target-icon-badge {
                display: flex;
                align-items: center;
                justify-content: center;
                width: 38px;
                height: 38px;
                border-radius: 10px;
                background: rgba(2, 136, 209, 0.25);
                color: #29b6f6;
                flex-shrink: 0;
            }
            .target-icon-badge ha-icon {
                --mdc-icon-size: 22px;
            }
            .target-info {
                display: flex;
                flex-direction: column;
                justify-content: center;
                gap: 2px;
                flex: 1;
                overflow: hidden;
            }
            .target-name {
                font-size: 0.95rem;
                font-weight: 600;
                color: #ffffff;
                white-space: nowrap;
                overflow: hidden;
                text-overflow: ellipsis;
            }
            .target-detail {
                font-size: 0.75rem;
                color: rgba(255, 255, 255, 0.5);
                white-space: nowrap;
                overflow: hidden;
                text-overflow: ellipsis;
            }
            .target-chevron {
                --mdc-icon-size: 18px;
                color: rgba(255, 255, 255, 0.35);
                flex-shrink: 0;
            }
            .target-picker-cancel-btn {
                width: 100%;
                padding: 10px;
                border-radius: 10px;
                background: transparent;
                border: 1px solid rgba(255, 255, 255, 0.15);
                color: rgba(255, 255, 255, 0.8);
                font-size: 0.9rem;
                font-weight: 600;
                cursor: pointer;
                transition: all 0.2s;
                box-sizing: border-box;
            }
            .target-picker-cancel-btn:hover {
                background: rgba(255, 255, 255, 0.08);
                color: #ffffff;
            }
        </style>
        `;
  }
  _renderDialogContent() {
    return !this._open || !this._item ? l`` : l`
            ${this._getPortalStyles()}
            <div class="jellyha-modal-scrim" @click=${this.closeDialog}>
                <div 
                    class="jellyha-modal-surface ${this._viewMode}" 
                    @click=${(e) => e.stopPropagation()}
                    style="${this._isDragging || this._currentTranslateY > 0 ? `transform: translateY(${this._currentTranslateY}px); transition: ${this._isDragging ? "none" : "transform 0.3s ease-out"}` : ""}"
                >
                    <button class="modal-close-btn" @click=${this.closeDialog} aria-label="Close" title="Close">
                        <ha-icon icon="mdi:close"></ha-icon>
                    </button>
                    ${(() => {
      const e = this._item.backdrop_url || (this._item.type === "Episode" ? this._item.series_poster_url || this._item.poster_url : this._item.poster_url);
      return e ? l`
                            <div class="backdrop-hero">
                                <img class="backdrop-img" src="${e}" alt="" />
                            </div>
                        ` : h;
    })()}
                    ${this._viewMode === "episodes" ? this._renderEpisodesContent() : this._renderDefaultContent()}
                    ${this._renderTargetPickerOverlay()}
                </div>
            </div>
        `;
  }
  _renderDefaultContent() {
    if (!this._item) return l``;
    const e = this._item, t = e.type === "Series", i = e.year || (e.date_added ? new Date(e.date_added).getFullYear() : ""), o = t && this._nextUpItem ? this._nextUpItem : e;
    return l`
        <div class="default-layout">
            <div class="poster-col">
                <img class="poster-img" src="${e.poster_url}" alt="${e.name}" />

                <div class="poster-actions">
                    ${this._confirmDelete ? l`
                            <div class="confirmation-box">
                                <span>Delete item?</span>
                                <button class="confirm-btn confirm-yes" @click=${this._handleDeleteConfirm}>Yes</button>
                                <button class="confirm-btn" @click=${() => this._confirmDelete = !1}>No</button>
                            </div>
                        ` : l`
                            <!-- Primary Play Button -->
                            ${this._renderPrimaryPlayButton(o)}

                            <!-- Secondary Action Icons Toolbar -->
                            <div class="actions-icon-row">
                                ${t ? l`
                                    <button class="action-btn" @click=${(s) => {
      this._haptic(), this._toggleEpisodesView(s);
    }} title="View All Episodes" type="button">
                                        <ha-icon icon="mdi:format-list-bulleted"></ha-icon>
                                    </button>
                                ` : h}

                                ${e.trailer_url ? l`
                                    <button class="action-btn" @click=${this._handleWatchTrailer} title="Watch Trailer">
                                        <ha-icon icon="mdi:filmstrip"></ha-icon>
                                    </button>
                                ` : h}

                                <button class="action-btn ${e.is_played ? "active" : ""}" @click=${this._handleWatched} title="${e.is_played ? "Mark Unwatched" : "Mark Watched"}">
                                    <ha-icon icon="mdi:check"></ha-icon>
                                </button>

                                <button class="action-btn favorite-btn ${e.is_favorite ? "active" : ""}" @click=${this._handleFavorite} title="${e.is_favorite ? "Remove Favorite" : "Add to Favorites"}">
                                    <ha-icon icon="${e.is_favorite ? "mdi:heart" : "mdi:heart-outline"}"></ha-icon>
                                </button>

                                <a href="${this._getJellyfinUrl(e) || "javascript:void(0)"}" target="_blank" rel="noopener noreferrer" class="action-btn" title="Open in Jellyfin" @click=${(s) => {
      this._haptic(), this._getJellyfinUrl(e) || (s.preventDefault(), this._openExternalUrl(e.jellyfin_url));
    }}>
                                    <ha-icon icon="mdi:open-in-new"></ha-icon>
                                </a>

                                ${this.hass?.user?.is_admin === !1 ? h : l`
                                <button class="action-btn btn-danger" @click=${() => {
      this._haptic(), this._confirmDelete = !0;
    }} title="Delete Item">
                                    <ha-icon icon="mdi:trash-can-outline"></ha-icon>
                                </button>`}
                            </div>
                        `}
                </div>
            </div>

            <div class="details-col">
                <div class="header-group">
                    <h1>${e.name}</h1>
                    <div class="header-sub">
                        ${e.series_name ? l`<span>${e.series_name}</span>` : h}
                        ${e.type === "Episode" && e.season != null && e.episode != null ? l`<span class="badge">S${String(e.season).padStart(2, "0")}E${String(e.episode).padStart(2, "0")}</span>` : h}
                        ${i ? l`<span>${i}</span>` : h}
                        <span class="badge">${e.type}</span>
                        ${e.official_rating ? l`<span class="badge">${e.official_rating}</span>` : h}
                    </div>
                </div>
                
                ${this._nextUpItem ? l`
                    <div class="next-up-card" @click=${this._playTargets.length > 0 ? this._playNextUp : void 0} style="${this._playTargets.length === 0 ? "cursor: default;" : ""}">
                        <div class="next-up-thumb-wrap">
                            <img class="next-up-thumb" src="${this._nextUpItem.poster_url || this._nextUpItem.backdrop_url || this._item.poster_url}" alt="${this._nextUpItem.name}" />
                            ${this._playTargets.length > 0 ? l`
                                <div class="next-up-play-overlay">
                                    <ha-icon icon="mdi:play"></ha-icon>
                                </div>
                            ` : h}
                        </div>
                        <div class="next-up-info">
                            <div class="next-up-header-row">
                                ${this._nextUpItem.season != null && (this._nextUpItem.episode != null || this._nextUpItem.index_number != null) ? l`
                                    <span class="next-up-ep-code">S${this._nextUpItem.season}:E${this._nextUpItem.episode ?? this._nextUpItem.index_number}</span>
                                ` : this._nextUpItem.episode != null || this._nextUpItem.index_number != null ? l`
                                    <span class="next-up-ep-code">E${this._nextUpItem.episode ?? this._nextUpItem.index_number}</span>
                                ` : h}
                                <span class="next-up-badge">NEXT UP</span>
                            </div>
                            <h3 class="next-up-title">${this._nextUpItem.name}</h3>
                            <div class="next-up-sub">
                                ${this._nextUpItem.runtime_minutes ? l`<span>${this._formatRuntime(this._nextUpItem.runtime_minutes)}</span>` : h}
                                ${this._nextUpItem.rating ? l`
                                    <span>•</span>
                                    <span class="next-up-rating"><ha-icon icon="mdi:star"></ha-icon> ${this._nextUpItem.rating.toFixed(1)}</span>
                                ` : h}
                            </div>
                        </div>
                        ${this._playTargets.length > 0 ? l`
                            <button class="next-up-cast-btn" title="${this._getNextUpPlayTitle()}" @click=${(s) => {
      s.stopPropagation(), this._playNextUp();
    }}>
                                <ha-icon icon="${this._getNextUpPlayIcon()}"></ha-icon>
                            </button>
                        ` : h}
                    </div>
                ` : h}

                <div class="stats-row">
                    ${e.rating ? l`
                        <div class="stat-item">
                            <ha-icon icon="mdi:star" style="color: #FBC02D;"></ha-icon>
                            <span>${e.rating.toFixed(1)}</span>
                        </div>
                    ` : h}
                    ${t ? l`
                        ${e.unplayed_count !== void 0 ? l`
                            <div class="stat-item">
                                <ha-icon icon="mdi:television-classic"></ha-icon>
                                <span>${e.unplayed_count} Unplayed</span>
                            </div>
                        ` : h}
                    ` : l`
                        ${e.runtime_minutes ? l`
                            <div class="stat-item">
                                <ha-icon icon="mdi:clock-outline"></ha-icon>
                                <span>${this._formatRuntime(e.runtime_minutes)}</span>
                            </div>
                        ` : h}
                    `}
                </div>

                ${e.description ? l`<div class="description">${e.description}</div>` : h}

                ${e.genres && e.genres.length > 0 ? l`
                    <div class="genres-list">
                        ${e.genres.map((s) => l`<span class="genre-tag">${s}</span>`)}
                    </div>
                ` : h}

                ${this._renderMediaDetails(t && this._nextUpItem ? this._nextUpItem : e)}
            </div>
        </div>
        `;
  }
  _renderEpisodesContent() {
    if (!this._item) return l``;
    const e = this._item.name, t = Array.from(
      new Set(
        this._episodes.map((o) => o.season).filter((o) => typeof o == "number" && !isNaN(o))
      )
    ).sort((o, s) => o - s), i = this._selectedSeason && this._selectedSeason !== "all" ? this._episodes.filter((o) => o.season === this._selectedSeason) : this._episodes;
    return l`
            <div class="episodes-container">
                <div class="episodes-header">
                    <button class="back-btn" @click=${(o) => this._toggleEpisodesView(o)} type="button" title="Back to Details">
                        <ha-icon icon="mdi:arrow-left"></ha-icon>
                    </button>
                    <h2 class="episodes-title">${e}</h2>
                </div>

                ${t.length > 1 ? l`
                    <div class="season-selector">
                        <button class="season-tab ${this._selectedSeason === "all" || !this._selectedSeason ? "active" : ""}" @click=${() => {
      this._haptic("selection"), this._selectedSeason = "all", this.requestUpdate();
    }}>All</button>
                        ${t.map((o) => l`
                            <button class="season-tab ${this._selectedSeason === o ? "active" : ""}" @click=${() => {
      this._haptic("selection"), this._selectedSeason = o, this.requestUpdate();
    }}>Season ${o}</button>
                        `)}
                    </div>
                ` : h}
                
                <div class="episodes-list">
                    ${i.length === 0 ? l`
                        <div style="text-align: center; color: rgba(255,255,255,0.6); padding: 40px 20px;">
                            No episodes found.
                        </div>
                    ` : i.map((o) => {
      const s = !!(this._nextUpItem && o.id === this._nextUpItem.id), a = o.season ? `S${o.season}:E${o.episode ?? o.index_number ?? ""}` : o.episode ?? o.index_number ? `E${o.episode ?? o.index_number}` : "", r = this._formatRuntime(o.runtime_minutes);
      return l`
                            <div class="episode-row ${s ? "next-up-highlight" : ""}"
                                @click=${(n) => {
        n.stopPropagation(), this._playTargets.length > 0 && this._handlePlayEpisode(o);
      }}
                                @touchstart=${(n) => this._handleRowTouchStart(n)}
                                @touchmove=${(n) => this._handleRowTouchMove(n)}
                                @touchend=${(n) => this._handleRowTouchEnd(n)}
                                @touchcancel=${(n) => this._handleRowTouchEnd(n)}
                                style="${this._playTargets.length === 0 ? "cursor: default;" : ""}">
                                
                                <div class="episode-thumb-wrap">
                                    <img class="episode-thumb" src="${o.poster_url || o.backdrop_url || this._item.poster_url}" alt="${o.name || ""}" />
                                    ${this._playTargets.length > 0 ? l`
                                        <div class="episode-play-overlay">
                                            <ha-icon icon="mdi:play"></ha-icon>
                                        </div>
                                    ` : h}
                                </div>
                                
                                <div class="episode-content">
                                    ${a || s ? l`
                                        <div class="episode-header-line">
                                            ${a ? l`<span class="episode-number">${a}</span>` : h}
                                            ${s ? l`<span class="next-up-badge">NEXT UP</span>` : h}
                                        </div>
                                    ` : h}

                                    <h4 class="episode-title" title="${o.name || "Episode"}">${o.name || "Episode"}</h4>
                                    
                                    ${r || o.rating ? l`
                                        <div class="episode-meta">
                                            ${r ? l`<span>${r}</span>` : h}
                                            ${r && o.rating ? l`<span class="meta-dot">•</span>` : h}
                                            ${o.rating ? l`<span class="episode-rating"><ha-icon icon="mdi:star"></ha-icon>${o.rating.toFixed(1)}</span>` : h}
                                        </div>
                                    ` : h}
                                </div>

                                <div class="episode-actions">
                                    <button class="play-episode-btn watched-btn ${o.is_played ? "active" : ""}"
                                        @click=${(n) => {
        n.stopPropagation(), this._handleMarkEpisodeWatched(o);
      }}
                                        @touchstart=${(n) => n.stopPropagation()}
                                        @touchend=${(n) => n.stopPropagation()}
                                        type="button"
                                        title="${o.is_played ? "Mark Unwatched" : "Mark Watched"}">
                                        <ha-icon icon="mdi:check"></ha-icon>
                                    </button>

                                    ${this._playTargets.length > 0 ? l`
                                        <button class="play-episode-btn"
                                            @click=${(n) => {
        n.stopPropagation(), this._handlePlayEpisode(o);
      }}
                                            @touchstart=${(n) => n.stopPropagation()}
                                            @touchend=${(n) => n.stopPropagation()}
                                            type="button"
                                            title="${this._getEpisodePlayTitle()}">
                                            <ha-icon icon="${this._getEpisodePlayIcon()}"></ha-icon>
                                        </button>
                                    ` : h}
                                </div>
                            </div>
                        `;
    })}
                </div>
            </div>
        `;
  }
  _formatRuntime(e) {
    if (!e) return "";
    const t = Math.floor(e / 60), i = e % 60;
    return t > 0 ? `${t}h ${i}m` : `${i} min`;
  }
  _renderMediaDetails(e) {
    const t = [], i = e.media_streams || [], o = i.find((a) => a.Type?.toLowerCase() === "video");
    if (o) {
      if (o.Width && o.Height) {
        let u = "";
        o.Width >= 3800 || o.Height >= 2e3 ? u = "4K UHD" : o.Height >= 1e3 || o.Width >= 1900 ? u = "1080p" : o.Height >= 700 || o.Width >= 1200 ? u = "720p" : u = `${o.Width}x${o.Height}`, t.push(l`<span class="tech-chip"><ha-icon icon="mdi:video-outline"></ha-icon>${u}</span>`);
      }
      const a = (o.VideoRangeType || "").toUpperCase(), r = (o.VideoRange || "").toUpperCase(), n = (o.ColorTransfer || "").toLowerCase(), c = o.DvProfile;
      let p = e.dynamic_range || "";
      p || (a.startsWith("DOVI") || c != null ? p = "Dolby Vision" : a === "HDR10PLUS" || a === "HDR10+" ? p = "HDR10+" : a === "HDR10" || n === "smpte2084" ? p = "HDR10" : a === "HLG" || n === "arib-std-b67" ? p = "HLG" : r === "HDR" && (p = "HDR")), p && p !== "SDR" && t.push(l`<span class="tech-chip tech-chip-hdr"><ha-icon icon="mdi:hdr"></ha-icon>${p}</span>`), o.Codec && t.push(l`<span class="tech-chip">${o.Codec.toUpperCase()}</span>`);
    }
    const s = i.find((a) => a.Type?.toLowerCase() === "audio" && !!a.IsDefault) || i.find((a) => a.Type?.toLowerCase() === "audio");
    if (s && (s.Codec && t.push(l`<span class="tech-chip"><ha-icon icon="mdi:volume-high"></ha-icon>${s.Codec.toUpperCase()}</span>`), s.Channels)) {
      let a = `${s.Channels} ch`;
      s.Channels === 6 ? a = "5.1" : s.Channels === 8 ? a = "7.1" : s.Channels === 2 && (a = "Stereo"), t.push(l`<span class="tech-chip">${a}</span>`);
    }
    return t.length === 0 ? l`` : l`
            <div class="divider"></div>
            <div class="tech-specs-row">
                ${t}
            </div>
        `;
  }
  _haptic(e = "selection") {
    const t = new CustomEvent("haptic", {
      detail: e,
      bubbles: !0,
      composed: !0
    });
    this.dispatchEvent(t), window.dispatchEvent(new CustomEvent("haptic", {
      detail: e,
      bubbles: !0,
      composed: !0
    }));
    try {
      if (typeof navigator < "u" && typeof navigator.vibrate == "function") {
        const i = e === "medium" || e === "heavy" ? 20 : e === "success" ? [15, 50, 15] : 10;
        navigator.vibrate(i);
      }
    } catch {
    }
  }
  _handleRowTouchStart(e) {
    e.touches.length > 0 && (this._rowTouchStartX = e.touches[0].clientX, this._rowTouchStartY = e.touches[0].clientY, e.currentTarget.classList.add("active-press"));
  }
  _handleRowTouchMove(e) {
    if (e.touches.length > 0) {
      const t = Math.abs(e.touches[0].clientX - this._rowTouchStartX), i = Math.abs(e.touches[0].clientY - this._rowTouchStartY);
      (t > 10 || i > 10) && e.currentTarget.classList.remove("active-press");
    }
  }
  _handleRowTouchEnd(e) {
    e.currentTarget.classList.remove("active-press");
  }
  _getTargetDisplayName(e) {
    if (e.name) return e.name;
    if (e.type === "cast") return "Cast to Chromecast";
    if (e.type === "client") {
      const t = this.hass?.locale?.language || this.hass?.language || "en";
      return d(t, "editor.action_play_client") || "Play on Jellyfin Client";
    }
    if (e.type === "browser" || e.type === "play-browser") {
      const t = this.hass?.locale?.language || this.hass?.language || "en";
      return d(t, "modal.play_in_browser") || "Play in Browser";
    }
    return $e(this.hass, e.service);
  }
  _renderPrimaryPlayButton(e) {
    if (this._playTargets.length === 0) return h;
    if (this._playTargets.length === 1) {
      const t = this._playTargets[0], i = t.type === "browser" || t.type === "play-browser", o = t.type === "client", s = t.icon || (t.type === "cast" ? "mdi:cast" : o ? "mdi:television-play" : i ? "mdi:monitor" : "mdi:play"), a = this._getTargetDisplayName(t);
      return l`
                <button class="primary-play-btn" @click=${this._handlePlay} title="${a}">
                    <ha-icon icon="${s}"></ha-icon>
                    <span>${a}</span>
                </button>
            `;
    }
    return l`
            <button class="primary-play-btn" @click=${this._handlePlay} title="Play">
                <ha-icon icon="mdi:play"></ha-icon>
                <span>Play</span>
            </button>
        `;
  }
  _getNextUpPlayIcon() {
    if (this._playTargets.length === 1) {
      const e = this._playTargets[0].type === "browser" || this._playTargets[0].type === "play-browser", t = this._playTargets[0].type === "client";
      return this._playTargets[0].icon || (this._playTargets[0].type === "cast" ? "mdi:cast" : t ? "mdi:television-play" : e ? "mdi:monitor" : "mdi:play");
    }
    return "mdi:play";
  }
  _getNextUpPlayTitle() {
    return this._playTargets.length === 1 ? this._getTargetDisplayName(this._playTargets[0]) : "Play Next Up";
  }
  _getEpisodePlayIcon() {
    if (this._playTargets.length === 1) {
      const e = this._playTargets[0].type === "browser" || this._playTargets[0].type === "play-browser", t = this._playTargets[0].type === "client";
      return this._playTargets[0].icon || (this._playTargets[0].type === "cast" ? "mdi:cast" : t ? "mdi:television-play" : e ? "mdi:monitor" : "mdi:play");
    }
    return "mdi:play";
  }
  _getEpisodePlayTitle() {
    return this._playTargets.length === 1 ? this._getTargetDisplayName(this._playTargets[0]) : "Play Episode";
  }
  _renderTargetPickerOverlay() {
    if (!this._showTargetPicker || !this._pendingPlayItem) return h;
    const e = this._pendingPlayItem.series_name ? `${this._pendingPlayItem.series_name} - ${this._pendingPlayItem.name}` : this._pendingPlayItem.name, t = this.hass?.locale?.language || this.hass?.language || "en", i = d(t, "modal.play_on") || "Play On", o = d(t, "modal.cancel") || "Cancel";
    return l`
            <div class="target-picker-overlay" @click=${this._closeTargetPicker}>
                <div class="target-picker-card" @click=${(s) => s.stopPropagation()}>
                    <div class="target-picker-header">
                        <div class="target-picker-title-wrap">
                            <span class="target-picker-title">${i}</span>
                            <span class="target-picker-item-name">${e}</span>
                        </div>
                        <button class="target-picker-close-btn" @click=${this._closeTargetPicker} aria-label="Close" title="Close">
                            <ha-icon icon="mdi:close"></ha-icon>
                        </button>
                    </div>

                    <div class="target-picker-list">
                        ${this._playTargets.map((s) => {
      const a = s.type === "browser" || s.type === "play-browser", r = s.type === "client", n = s.icon || (s.type === "cast" ? "mdi:cast" : r ? "mdi:television-play" : a ? "mdi:monitor" : "mdi:play"), c = this._getTargetDisplayName(s), p = s.type === "cast" ? s.device || this._defaultCastDevice || "Chromecast" : r ? s.device || this._defaultClientDevice || "Jellyfin Client" : a ? "Web Browser" : s.service || "Script", u = s.show_entity_name !== !1 && s.show_entity !== !1 && this._showEntityName !== !1;
      return l`
                                <button class="target-option-btn" @click=${() => this._executePlayTarget(s, this._pendingPlayItem)}>
                                    <div class="target-icon-badge">
                                        <ha-icon icon="${n}"></ha-icon>
                                    </div>
                                    <div class="target-info">
                                        <span class="target-name">${c}</span>
                                        ${u && p ? l`<span class="target-detail">${p}</span>` : h}
                                    </div>
                                    <ha-icon icon="mdi:chevron-right" class="target-chevron"></ha-icon>
                                </button>
                            `;
    })}
                    </div>

                    <button class="target-picker-cancel-btn" @click=${this._closeTargetPicker}>
                        ${o}
                    </button>
                </div>
            </div>
        `;
  }
  _getJellyfinUrl(e) {
    const t = e || this._item;
    if (!t) return;
    let i = t.jellyfin_url;
    if (!i && t.id) {
      let s;
      if (this.hass && this.hass.states) {
        if (this._serverEntityId && this.hass.states[this._serverEntityId]) {
          const a = this.hass.states[this._serverEntityId].attributes;
          s = a?.config_external_url || a?.server_url;
        }
        if (!s) {
          for (const a in this.hass.states)
            if (a.startsWith("sensor.") || a.startsWith("media_player.")) {
              const r = this.hass.states[a].attributes;
              if (r?.config_external_url || r?.server_url) {
                s = r.config_external_url || r.server_url;
                break;
              }
            }
        }
      }
      s && s.trim() !== "" && (i = `${s.replace(/\/$/, "")}/web/index.html#!/details?id=${t.id}`);
    }
    if (!i) return;
    let o;
    if (this.hass && this.hass.states && (this._serverEntityId && this.hass.states[this._serverEntityId]?.attributes?.config_external_url && (o = this.hass.states[this._serverEntityId].attributes.config_external_url), !o)) {
      for (const s in this.hass.states)
        if (s.startsWith("sensor.") && this.hass.states[s].attributes?.config_external_url) {
          o = this.hass.states[s].attributes.config_external_url;
          break;
        }
    }
    if (o && o.trim() !== "")
      try {
        const s = new URL(i), a = new URL(o);
        s.protocol = a.protocol, s.host = a.host, s.port = a.port || "";
        const r = a.pathname === "/" ? "" : a.pathname;
        return r && !s.pathname.startsWith(r) && (s.pathname = r + s.pathname), s.toString();
      } catch (s) {
        console.warn("JellyHA: Failed to parse URLs to inject external URL override", s);
      }
    return i;
  }
  _openExternalUrl(e) {
    const t = e || this._getJellyfinUrl();
    if (!t) return;
    try {
      const o = new URL(t);
      if (o.hostname.includes("youtube.com") || o.hostname.includes("youtu.be") || o.hostname.includes("vimeo.com")) {
        ae(t, "_blank");
        return;
      }
    } catch {
    }
    const i = this._getJellyfinUrl({ ...this._item, jellyfin_url: t }) || t;
    ae(i, "_blank");
  }
  /* Swipe to Close Logic */
  _getScrollParent(e) {
    if (!e) return null;
    let t = e;
    for (; t && t !== this._portalContainer && t !== document.body; ) {
      if (t.classList?.contains("jellyha-modal-surface") || t.classList?.contains("default-layout") || t.classList?.contains("episodes-list"))
        return t.scrollHeight > t.clientHeight ? t : null;
      const { overflowY: i } = window.getComputedStyle(t);
      if ((i === "auto" || i === "scroll") && t.scrollHeight > t.clientHeight)
        return t;
      t = t.parentElement;
    }
    return null;
  }
};
j.styles = Pe`
        /* Styles handled in _getPortalStyles */
    `;
A([
  V({ attribute: !1 })
], j.prototype, "hass", 2);
A([
  f()
], j.prototype, "_item", 2);
A([
  f()
], j.prototype, "_nextUpItem", 2);
A([
  f()
], j.prototype, "_defaultCastDevice", 2);
A([
  f()
], j.prototype, "_defaultClientDevice", 2);
A([
  f()
], j.prototype, "_serverEntityId", 2);
A([
  f()
], j.prototype, "_subtitleMode", 2);
A([
  f()
], j.prototype, "_subtitleLanguage", 2);
A([
  f()
], j.prototype, "_playTargets", 2);
A([
  f()
], j.prototype, "_showTargetPicker", 2);
A([
  f()
], j.prototype, "_pendingPlayItem", 2);
A([
  f()
], j.prototype, "_showEntityName", 2);
A([
  f()
], j.prototype, "_open", 2);
A([
  f()
], j.prototype, "_confirmDelete", 2);
A([
  f()
], j.prototype, "_viewMode", 2);
A([
  f()
], j.prototype, "_episodes", 2);
A([
  f()
], j.prototype, "_selectedSeason", 2);
A([
  f()
], j.prototype, "_touchStartY", 2);
A([
  f()
], j.prototype, "_currentTranslateY", 2);
A([
  f()
], j.prototype, "_isDragging", 2);
j = A([
  ge("jellyha-item-details-modal")
], j);
var Ni = Object.defineProperty, Ri = Object.getOwnPropertyDescriptor, bt = (e, t, i, o) => {
  for (var s = o > 1 ? void 0 : o ? Ri(t, i) : t, a = e.length - 1, r; a >= 0; a--)
    (r = e[a]) && (s = (o ? r(t, i, s) : r(s)) || s);
  return o && s && Ni(t, i, s), s;
};
function dt(e, t, i) {
  const o = new CustomEvent(t, {
    bubbles: !0,
    composed: !0,
    detail: i
  });
  e.dispatchEvent(o);
}
let Re = class extends X {
  constructor() {
    super(...arguments), this._filterCastDevices = (e) => {
      const t = e?.entity_id;
      if (!t || !t.startsWith("media_player."))
        return !1;
      if (t === this._config?.default_cast_device)
        return !0;
      const i = this.hass?.entities?.[t]?.platform;
      return i ? i === "cast" : !t.startsWith("media_player.jellyha_");
    }, this._filterClientDevices = (e) => this._isConfiguredClientDevice(e);
  }
  setConfig(e) {
    this._config = e;
  }
  render() {
    if (!this.hass || !this._config)
      return l``;
    const e = this._config.click_action || "more-info", t = this._config.hold_action || "jellyfin", i = this._config.double_tap_action || "none", o = e === "cast" || t === "cast" || i === "cast", s = e === "play-client" || t === "play-client" || i === "play-client", a = this.hass.locale?.language || this.hass.language, r = Object.keys(this.hass.states || {}).filter(
      (p) => p.startsWith("sensor.") && (p.endsWith("_library") || p === "sensor.jellyha_library") && (p.includes("jellyha") || this.hass.states[p]?.attributes?.integration === "jellyha")
    );
    this._config.entity && !r.includes(this._config.entity) && r.unshift(this._config.entity);
    const c = this._config.layout === "grid" && this._config.enable_pagination === !1 && (this._config.auto_swipe_interval || 0) > 0 ? d(a, "editor.rows") : d(a, "editor.columns");
    return l`
      <div class="card-config">
        <div class="form-row">
          <ha-selector
            .hass=${this.hass}
            .selector=${{
      entity: {
        domain: "sensor",
        ...r.length > 0 ? { include_entities: r } : {}
      }
    }}
            .value=${this._config.entity}
            label="${d(a, "editor.entity")}"
            @value-changed=${this._entityChanged}
          ></ha-selector>
        </div>

        <div class="form-row">
          <ha-selector
            .hass=${this.hass}
            .selector=${{ text: {} }}
            .value=${this._config.title || ""}
            .label=${d(a, "editor.title")}
            label="${d(a, "editor.title")}"
            @value-changed=${this._titleChanged}
          ></ha-selector>
        </div>

        <div class="side-by-side">
          <div class="form-row">
            <ha-selector
              .hass=${this.hass}
              .selector=${{
      select: {
        mode: "dropdown",
        options: [
          { value: "carousel", label: d(a, "editor.layout_carousel") },
          { value: "grid", label: d(a, "editor.layout_grid") },
          { value: "list", label: d(a, "editor.layout_list") },
          { value: "featured", label: d(a, "editor.layout_featured") }
        ]
      }
    }}
              .value=${this._config.layout || "carousel"}
              .label=${d(a, "editor.layout")}
              label="${d(a, "editor.layout")}"
              @value-changed=${this._layoutChanged}
            ></ha-selector>
          </div>

          <div class="form-row">
            <ha-selector
              .hass=${this.hass}
              .selector=${{
      select: {
        mode: "dropdown",
        options: [
          { value: "both", label: d(a, "editor.media_type_both") },
          { value: "movies", label: d(a, "editor.media_type_movies") },
          { value: "series", label: d(a, "editor.media_type_series") },
          { value: "next_up", label: d(a, "editor.media_type_next_up") }
        ]
      }
    }}
              .value=${this._config.media_type || "both"}
              .label=${d(a, "editor.media_type")}
              label="${d(a, "editor.media_type")}"
              @value-changed=${this._mediaTypeChanged}
            ></ha-selector>
          </div>
        </div>

        ${!this._config.layout || this._config.layout === "carousel" ? l`
          <div class="form-row">
            <ha-selector
              .hass=${this.hass}
              .selector=${{
      select: {
        mode: "dropdown",
        options: [
          { value: "center", label: d(a, "editor.alignment_center") || "Center" },
          { value: "left", label: d(a, "editor.alignment_left") || "Left" }
        ]
      }
    }}
              .value=${this._config.horizontal_alignment || "center"}
              .label=${d(a, "editor.horizontal_alignment") || "Carousel Alignment"}
              label="${d(a, "editor.horizontal_alignment") || "Carousel Alignment"}"
              @value-changed=${this._horizontalAlignmentChanged}
            ></ha-selector>
          </div>
        ` : ""}

        ${this._config.media_type === "series" || this._config.media_type === "both" || !this._config.media_type ? l`
          <div class="side-by-side">
            <div class="form-row">
              <ha-selector
                .hass=${this.hass}
                .selector=${{
      select: {
        mode: "dropdown",
        options: [
          { value: "series", label: d(a, "editor.tv_content_series") },
          { value: "episodes", label: d(a, "editor.tv_content_episodes") }
        ]
      }
    }}
                .value=${this._config.tv_content || "series"}
                .label=${d(a, "editor.tv_content")}
                label="${d(a, "editor.tv_content")}"
                @value-changed=${this._tvContentChanged}
              ></ha-selector>
            </div>
            ${this._config.tv_content === "episodes" ? l`
              <div class="checkbox-row">
                <ha-switch
                  .checked=${this._config.use_series_image === !0}
                  @change=${this._useSeriesImageChanged}
                ></ha-switch>
                <span>${d(a, "editor.use_series_image")}</span>
              </div>
            ` : h}
          </div>
        ` : ""}

        ${this._config.media_type === "next_up" ? l`
          <div class="checkbox-row" style="margin-bottom: 16px;">
            <ha-switch
              .checked=${this._config.use_series_image === !0}
              @change=${this._useSeriesImageChanged}
            ></ha-switch>
            <span>${d(a, "editor.use_series_image")}</span>
          </div>
        ` : ""}

        ${this._config.layout === "grid" || this._config.layout === "list" || this._config.layout === "featured" ? l`
              <div class="form-row">
                <ha-selector
                  .hass=${this.hass}
                  .selector=${{
      number: {
        min: 1,
        max: this._config.layout === "featured" ? 4 : this._config.layout === "list" ? 8 : 12,
        mode: "slider"
      }
    }}
                  .value=${this._config.columns || 1}
                  .label=${this._config.layout === "featured" ? `${d(a, "editor.columns")}: ${this._config.columns || 1}` : `${c}: ${(this._config.columns || 1) === 1 ? d(a, "editor.auto") : this._config.columns}`}
                  label="${this._config.layout === "featured" ? `${d(a, "editor.columns")}: ${this._config.columns || 1}` : `${c}: ${(this._config.columns || 1) === 1 ? d(a, "editor.auto") : this._config.columns}`}"
                  @value-changed=${this._columnsChanged}
                ></ha-selector>
              </div>
              ${this._config.layout === "featured" ? l`
                <div class="helper-text" style="margin-top: -8px; margin-bottom: 12px;">
                  ${d(a, "editor.featured_columns_helper")}
                </div>
                <div class="form-row">
                  <ha-selector
                    .hass=${this.hass}
                    .selector=${{
      number: {
        min: 2,
        max: 3,
        mode: "slider"
      }
    }}
                    .value=${this._config.rows || 3}
                    .label=${`${d(a, "editor.featured_rows") || "Rows"}: ${this._config.rows || 3}`}
                    label="${`${d(a, "editor.featured_rows") || "Rows"}: ${this._config.rows || 3}`}"
                    @value-changed=${this._rowsChanged}
                  ></ha-selector>
                </div>
                <div class="helper-text" style="margin-top: -8px; margin-bottom: 12px;">
                  ${d(a, "editor.featured_rows_helper")}
                </div>
              ` : ""}
            ` : ""}


        ${this._config.layout === "featured" ? l`
            <div class="form-row">
              <ha-selector
                .hass=${this.hass}
                .selector=${{
      number: {
        min: 0,
        max: 20,
        mode: "box"
      }
    }}
                .value=${this._config.max_pages !== void 0 && this._config.max_pages !== null ? this._config.max_pages : 5}
                .label=${d(a, "editor.max_pages")}
                label="${d(a, "editor.max_pages")}"
                @value-changed=${this._maxPagesChanged}
              ></ha-selector>
            </div>
          ` : l`
            <div class="side-by-side">
              <div class="form-row">
                <ha-selector
                  .hass=${this.hass}
                  .selector=${{
      number: {
        min: 1,
        max: 50,
        mode: "box"
      }
    }}
                  .value=${this._config.items_per_page !== void 0 && this._config.items_per_page !== null ? this._config.items_per_page : 5}
                  .label=${d(a, "editor.items_per_page")}
                  label="${d(a, "editor.items_per_page")}"
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
        mode: "box"
      }
    }}
                  .value=${this._config.max_pages !== void 0 && this._config.max_pages !== null ? this._config.max_pages : 5}
                  .label=${d(a, "editor.max_pages")}
                  label="${d(a, "editor.max_pages")}"
                  @value-changed=${this._maxPagesChanged}
                ></ha-selector>
              </div>
            </div>
          `}

        <div class="side-by-side">
          <div class="form-row">
            <ha-selector
              .hass=${this.hass}
              .selector=${{
      number: {
        min: 0,
        max: 60,
        mode: "box",
        unit_of_measurement: "s"
      }
    }}
              .value=${this._config.auto_swipe_interval !== void 0 && this._config.auto_swipe_interval !== null ? this._config.auto_swipe_interval : 0}
              .label=${d(a, "editor.auto_swipe")}
              label="${d(a, "editor.auto_swipe")}"
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
        mode: "box",
        unit_of_measurement: "days"
      }
    }}
              .value=${this._config.new_badge_days !== void 0 && this._config.new_badge_days !== null ? this._config.new_badge_days : 3}
              .label=${d(a, "editor.new_badge_days")}
              label="${d(a, "editor.new_badge_days")}"
              @value-changed=${this._newBadgeDaysChanged}
            ></ha-selector>
          </div>
        </div>

    <div class="checkbox-row">
      <ha-switch
        .checked=${this._config.show_title !== !1}
        @change=${this._showTitleChanged}
      ></ha-switch>
      <span>${d(a, "editor.show_title")}</span>
    </div>

    <div class="checkbox-row">
      <ha-switch
        .checked=${this._config.show_year !== !1}
        @change=${this._showYearChanged}
      ></ha-switch>
      <span>${d(a, "editor.show_year")}</span>
    </div>

    <div class="checkbox-row">
      <ha-switch
        .checked=${this._config.show_ratings !== !1}
        @change=${this._showRatingsChanged}
      ></ha-switch>
      <span>${d(a, "editor.show_rating")}</span>
    </div>

    ${this._isRuntimeOptionVisible() ? l`
        <div class="checkbox-row">
          <ha-switch
            .checked=${this._config.show_runtime !== !1}
            @change=${this._showRuntimeChanged}
          ></ha-switch>
          <span>${d(a, "editor.show_runtime")}</span>
        </div>
      ` : h}

    <div class="checkbox-row">
      <ha-switch
        .checked=${this._config.show_date_added === !0}
        @change=${this._showDateAddedChanged}
      ></ha-switch>
      <span>${d(a, "editor.show_date_added")}</span>
    </div>

    <div class="checkbox-row">
      <ha-switch
        .checked=${this._config.show_genres !== !1}
        @change=${this._showGenresChanged}
      ></ha-switch>
      <span>${d(a, "editor.show_genres")}</span>
    </div>

    <div class="checkbox-row">
      <ha-switch
        .checked=${this._config.show_description_on_hover !== !1}
        @change=${this._showDescriptionOnHoverChanged}
      ></ha-switch>
      <span>${d(a, "editor.show_description")}</span>
    </div>

    <div class="checkbox-row">
      <ha-switch
        .checked=${this._config.show_media_type_badge !== !1}
        @change=${this._showMediaTypeBadgeChanged}
      ></ha-switch>
      <span>${d(a, "editor.show_media_type_badge")}</span>
    </div>

    <div class="checkbox-row">
      <ha-switch
        .checked=${this._config.show_watched_status !== !1}
        @change=${this._showWatchedStatusChanged}
      ></ha-switch>
      <span>${d(a, "editor.show_watched_status")}</span>
    </div>

    <div class="checkbox-row">
      <ha-switch
        .checked=${this._config.show_search === !0}
        @change=${this._showSearchChanged}
      ></ha-switch>
      <span>${d(a, "editor.show_search")}</span>
    </div>

    ${this._config.layout === "list" || this._config.layout === "featured" ? l`
        <div class="checkbox-row" style="margin-bottom: 4px;">
          <ha-switch
            .checked=${this._config.show_card_backdrop !== void 0 ? this._config.show_card_backdrop !== !1 : this._config.layout === "featured" ? this._config.featured_queue_backdrop !== !1 : !0}
            @change=${this._showCardBackdropChanged}
          ></ha-switch>
          <span>${d(a, "editor.show_card_backdrop")}</span>
        </div>
        <div class="helper-text" style="margin-bottom: 12px;">
          ${d(a, "editor.show_card_backdrop_helper")}
        </div>
      ` : ""}

    ${this._config.media_type !== "next_up" ? l`
        <div class="form-row">
          <ha-selector
            .hass=${this.hass}
            .selector=${{
      select: {
        mode: "dropdown",
        options: [
          { value: "date_added_desc", label: d(a, "editor.sort_date_added_desc") },
          { value: "date_added_asc", label: d(a, "editor.sort_date_added_asc") },
          { value: "title_asc", label: d(a, "editor.sort_title_asc") },
          { value: "title_desc", label: d(a, "editor.sort_title_desc") },
          { value: "year_desc", label: d(a, "editor.sort_year_desc") },
          { value: "year_asc", label: d(a, "editor.sort_year_asc") },
          { value: "last_played_desc", label: d(a, "editor.sort_last_played_desc") },
          { value: "last_played_asc", label: d(a, "editor.sort_last_played_asc") }
        ]
      }
    }}
            .value=${this._config.sort_option || "date_added_desc"}
            .label=${d(a, "editor.sort_order")}
            label="${d(a, "editor.sort_order")}"
            @value-changed=${this._sortOptionChanged}
          ></ha-selector>
        </div>
      ` : ""}

    <div class="side-by-side">
      <div class="checkbox-row">
        <ha-switch
          .checked=${this._config.enable_pagination !== !1}
          @change=${this._enablePaginationChanged}
        ></ha-switch>
        <span>${d(a, "editor.enable_pagination")}</span>
      </div>

      <div class="checkbox-row">
        <ha-switch
          .checked=${this._config.show_pagination_dots !== !1}
          @change=${this._showPaginationDotsChanged}
        ></ha-switch>
        <span>${d(a, "editor.show_pagination_dots")}</span>
      </div>
    </div>

    <div class="form-row">
      <ha-selector
        .hass=${this.hass}
        .selector=${{
      select: {
        mode: "dropdown",
        options: [
          { value: "all", label: d(a, "editor.filter_all") },
          { value: "unwatched", label: d(a, "editor.filter_unwatched") },
          { value: "watched", label: d(a, "editor.filter_watched") }
        ]
      }
    }}
        .value=${this._config.status_filter || "all"}
        .label=${d(a, "editor.filter_watch_status")}
        label="${d(a, "editor.filter_watch_status")}"
        @value-changed=${this._statusFilterChanged}
      ></ha-selector>
    </div>

    <div class="side-by-side">
      <div class="checkbox-row">
        <ha-switch
          .checked=${this._config.filter_favorites === !0}
          @change=${this._filterFavoritesChanged}
        ></ha-switch>
        <span>${d(a, "editor.filter_favorites")}</span>
      </div>

      <div class="checkbox-row">
        <ha-switch
          .checked=${this._config.filter_newly_added === !0}
          @change=${this._filterNewlyAddedChanged}
        ></ha-switch>
        <span>${d(a, "editor.filter_new_items")}</span>
      </div>
    </div>

        <div class="side-by-side">
          <div class="form-row">
            <ha-selector
              .hass=${this.hass}
              .selector=${{
      select: {
        mode: "dropdown",
        options: [
          { value: "jellyfin", label: d(a, "editor.action_jellyfin") },
          { value: "play-browser", label: d(a, "editor.action_play_browser") },
          { value: "play-client", label: d(a, "editor.action_play_client") },
          { value: "cast", label: d(a, "editor.action_cast") },
          { value: "more-info", label: d(a, "editor.action_more_info") },
          { value: "trailer", label: d(a, "editor.action_trailer") },
          { value: "call-service", label: d(a, "editor.action_call_service") },
          { value: "none", label: d(a, "editor.action_none") }
        ]
      }
    }}
              .value=${e}
              .label=${d(a, "editor.click_action")}
              label="${d(a, "editor.click_action")}"
              @value-changed=${this._clickActionChanged}
            ></ha-selector>
          </div>

          <div class="form-row">
            <ha-selector
              .hass=${this.hass}
              .selector=${{
      select: {
        mode: "dropdown",
        options: [
          { value: "jellyfin", label: d(a, "editor.action_jellyfin") },
          { value: "play-browser", label: d(a, "editor.action_play_browser") },
          { value: "play-client", label: d(a, "editor.action_play_client") },
          { value: "cast", label: d(a, "editor.action_cast") },
          { value: "more-info", label: d(a, "editor.action_more_info") },
          { value: "trailer", label: d(a, "editor.action_trailer") },
          { value: "call-service", label: d(a, "editor.action_call_service") },
          { value: "none", label: d(a, "editor.action_none") }
        ]
      }
    }}
              .value=${t}
              .label=${d(a, "editor.hold_action")}
              label="${d(a, "editor.hold_action")}"
              @value-changed=${this._holdActionChanged}
            ></ha-selector>
          </div>
        </div>

        <div class="side-by-side">
          <div class="form-row ${o ? "double-tap-aligned" : ""}">
            <ha-selector
              .hass=${this.hass}
              .selector=${{
      select: {
        mode: "dropdown",
        options: [
          { value: "jellyfin", label: d(a, "editor.action_jellyfin") },
          { value: "play-browser", label: d(a, "editor.action_play_browser") },
          { value: "play-client", label: d(a, "editor.action_play_client") },
          { value: "cast", label: d(a, "editor.action_cast") },
          { value: "more-info", label: d(a, "editor.action_more_info") },
          { value: "trailer", label: d(a, "editor.action_trailer") },
          { value: "call-service", label: d(a, "editor.action_call_service") },
          { value: "none", label: d(a, "editor.action_none") }
        ]
      }
    }}
              .value=${i}
              .label=${d(a, "editor.double_tap_action")}
              label="${d(a, "editor.double_tap_action")}"
              @value-changed=${this._doubleTapActionChanged}
            ></ha-selector>
          </div>

          ${o ? l`
                <div class="form-row">
                  <ha-entity-picker
                    .hass=${this.hass}
                    .value=${this._config.default_cast_device}
                    .includeDomains=${["media_player"]}
                    .entityFilter=${this._filterCastDevices}
                    .label=${d(a, "editor.default_cast_device") || "Default Cast Device"}
                    label="${d(a, "editor.default_cast_device") || "Default Cast Device"}"
                    @value-changed=${this._defaultCastDeviceChanged}
                  ></ha-entity-picker>
                </div>

                <div class="form-row">
                  <ha-selector
                    .hass=${this.hass}
                    .selector=${{
      select: {
        mode: "dropdown",
        options: [
          { value: "auto", label: d(a, "editor.subtitles_auto") || "Auto (Jellyfin User Profile)" },
          { value: "none", label: d(a, "editor.subtitles_none") || "None (Disabled)" },
          { value: "forced_only", label: d(a, "editor.subtitles_forced_only") || "Forced Only" },
          { value: "custom", label: d(a, "editor.subtitles_custom") || "Custom Language List" }
        ]
      }
    }}
                    .value=${this._config.subtitle_mode || "auto"}
                    .label=${d(a, "editor.subtitles") || "Cast Subtitles"}
                    label="${d(a, "editor.subtitles") || "Cast Subtitles"}"
                    @value-changed=${this._subtitleModeChanged}
                  ></ha-selector>
                </div>

                ${this._config.subtitle_mode === "custom" ? l`
                    <div class="form-row">
                      <ha-selector
                        .hass=${this.hass}
                        .selector=${{ text: {} }}
                        .value=${this._config.subtitle_language || ""}
                        .label=${d(a, "editor.subtitle_languages") || "Cast Subtitle Priority (e.g. sl, en)"}
                        label="${d(a, "editor.subtitle_languages") || "Cast Subtitle Priority (e.g. sl, en)"}"
                        @value-changed=${this._subtitleLanguageChanged}
                      ></ha-selector>
                    </div>
                  ` : ""}
              ` : l`<div></div>`}
        </div>

        ${s ? l`
            <div class="form-row">
              <ha-entity-picker
                .hass=${this.hass}
                .value=${this._config.default_client_device}
                .includeDomains=${["media_player"]}
                .entityFilter=${this._filterClientDevices}
                .label=${d(a, "editor.default_client_device") || "Default Jellyfin Client"}
                label="${d(a, "editor.default_client_device") || "Default Jellyfin Client"}"
                @value-changed=${this._defaultClientDeviceChanged}
              ></ha-entity-picker>
              ${this._hasConfiguredClientDevices() ? "" : l`
                    <div class="warning-banner">
                      <ha-icon icon="mdi:alert-circle-outline"></ha-icon>
                      <span>${d(a, "editor.no_client_devices_warning") || "No Jellyfin client devices configured in the JellyHA integration. Please configure devices in Settings → Devices & services → JellyHA → Configure."}</span>
                    </div>
                  `}
            </div>
          ` : ""}

        ${e === "call-service" ? l`
            <div class="form-row">
              <ha-selector
                .hass=${this.hass}
                .selector=${{
      entity: {
        domain: "script"
      }
    }}
                .value=${this._config.click_service || this._config.service || ""}
                .label=${`${d(a, "editor.click_action")}: ${d(a, "editor.service_to_call")}`}
                label="${d(a, "editor.click_action")}: ${d(a, "editor.service_to_call")}"
                @value-changed=${this._clickServiceChanged}
              ></ha-selector>
            </div>
          ` : ""}

        ${t === "call-service" ? l`
            <div class="form-row">
              <ha-selector
                .hass=${this.hass}
                .selector=${{
      entity: {
        domain: "script"
      }
    }}
                .value=${this._config.hold_service || this._config.service || ""}
                .label=${`${d(a, "editor.hold_action")}: ${d(a, "editor.service_to_call")}`}
                label="${d(a, "editor.hold_action")}: ${d(a, "editor.service_to_call")}"
                @value-changed=${this._holdServiceChanged}
              ></ha-selector>
            </div>
          ` : ""}

        ${i === "call-service" ? l`
            <div class="form-row">
              <ha-selector
                .hass=${this.hass}
                .selector=${{
      entity: {
        domain: "script"
      }
    }}
                .value=${this._config.double_tap_service || this._config.service || ""}
                .label=${`${d(a, "editor.double_tap_action")}: ${d(a, "editor.service_to_call")}`}
                label="${d(a, "editor.double_tap_action")}: ${d(a, "editor.service_to_call")}"
                @value-changed=${this._doubleTapServiceChanged}
              ></ha-selector>
            </div>
          ` : ""}

    <div class="checkbox-row" style="margin-top: 16px;">
      <ha-switch
        .checked=${this._config.enable_browser_player !== !1}
        @change=${this._enableBrowserPlayerChanged}
      ></ha-switch>
      <span>${d(a, "editor.enable_browser_player")}</span>
    </div>

    <div class="checkbox-row">
      <ha-switch
        .checked=${this._config.show_now_playing !== !1}
        @change=${this._showNowPlayingChanged}
      ></ha-switch>
      <span>${d(a, "editor.show_now_playing_overlay")}</span>
    </div>

    <div class="checkbox-row" style="margin-top: 16px; margin-bottom: 4px;">
      <ha-switch
        .checked=${this._config.enable_custom_play_actions === !0}
        @change=${this._enableCustomPlayActionsChanged}
      ></ha-switch>
      <span>${d(a, "editor.enable_custom_play_actions") || "Custom Play Actions"}</span>
    </div>
    <div class="helper-text">
      ${d(a, "editor.custom_play_actions_helper") || "When enabled, play targets in the More Info dialog are controlled by modal_play_actions in YAML. You can add multiple scripts, cast devices, or custom labels. When disabled, standard card settings are used."}
    </div>
    ${this._config.enable_custom_play_actions && (!this._config.modal_play_actions || this._config.modal_play_actions.length === 0) ? l`
        <div class="warning-banner">
          <ha-icon icon="mdi:alert-outline"></ha-icon>
          <span>${d(a, "editor.custom_play_actions_none_configured") || "None of the actions have been selected yet. Configure a Cast device or Script above, or define custom play targets in YAML under modal_play_actions."}</span>
        </div>
      ` : ""}


  </div>
`;
  }
  _entityChanged(e) {
    this._updateConfig("entity", e.detail.value);
  }
  _titleChanged(e) {
    const t = e.detail?.value !== void 0 ? e.detail.value : e.target?.value;
    this._updateConfig("title", t);
  }
  _layoutChanged(e) {
    const t = e.detail?.value !== void 0 ? e.detail.value : e.target?.value;
    t !== void 0 && this._updateConfig("layout", t);
  }
  _columnsChanged(e) {
    const t = e.detail?.value !== void 0 ? e.detail.value : e.target?.value;
    this._updateConfig("columns", Number(t));
  }
  _rowsChanged(e) {
    const t = e.detail?.value !== void 0 ? e.detail.value : e.target?.value;
    this._updateConfig("rows", Number(t));
  }
  _mediaTypeChanged(e) {
    const t = e.detail?.value !== void 0 ? e.detail.value : e.target?.value;
    t !== void 0 && this._updateConfig("media_type", t);
  }
  _tvContentChanged(e) {
    const t = e.detail?.value !== void 0 ? e.detail.value : e.target?.value;
    t !== void 0 && this._updateConfig("tv_content", t);
  }
  _itemsPerPageChanged(e) {
    const t = e.detail?.value !== void 0 ? e.detail.value : e.target?.value;
    t !== "" && t !== null && t !== void 0 ? this._updateConfig("items_per_page", Number(t)) : this._updateConfig("items_per_page", null);
  }
  _maxPagesChanged(e) {
    const t = e.detail?.value !== void 0 ? e.detail.value : e.target?.value;
    t === "" || t === null || t === void 0 ? this._updateConfig("max_pages", null) : this._updateConfig("max_pages", Number(t));
  }
  _autoSwipeIntervalChanged(e) {
    const t = e.detail?.value !== void 0 ? e.detail.value : e.target?.value;
    this._updateConfig("auto_swipe_interval", Number(t || 0));
  }
  _newBadgeDaysChanged(e) {
    const t = e.detail?.value !== void 0 ? e.detail.value : e.target?.value;
    t === "" || t === null || t === void 0 ? this._updateConfig("new_badge_days", null) : this._updateConfig("new_badge_days", Number(t));
  }
  _clickActionChanged(e) {
    const t = e.detail?.value !== void 0 ? e.detail.value : e.target?.value;
    t !== void 0 && this._updateConfig("click_action", t);
  }
  _holdActionChanged(e) {
    const t = e.detail?.value !== void 0 ? e.detail.value : e.target?.value;
    t !== void 0 && this._updateConfig("hold_action", t);
  }
  _doubleTapActionChanged(e) {
    const t = e.detail?.value !== void 0 ? e.detail.value : e.target?.value;
    t !== void 0 && this._updateConfig("double_tap_action", t);
  }
  _clickServiceChanged(e) {
    const t = e.detail?.value !== void 0 ? e.detail.value : e.target?.value;
    t !== void 0 && this._updateConfig("click_service", t);
  }
  _holdServiceChanged(e) {
    const t = e.detail?.value !== void 0 ? e.detail.value : e.target?.value;
    t !== void 0 && this._updateConfig("hold_service", t);
  }
  _doubleTapServiceChanged(e) {
    const t = e.detail?.value !== void 0 ? e.detail.value : e.target?.value;
    t !== void 0 && this._updateConfig("double_tap_service", t);
  }
  _isConfiguredClientDevice(e) {
    const t = e?.entity_id;
    if (!t || !t.startsWith("media_player."))
      return !1;
    const i = this.hass?.states?.[t] || e;
    if (!i || i.state === "unavailable" || i.state === "unknown" || this.hass?.states && !this.hass.states[t])
      return !1;
    const o = this.hass?.entities?.[t];
    if (o?.disabled_by)
      return !1;
    const s = String(i?.attributes?.friendly_name || "");
    if (t.includes("library_browser") || t.includes("media_browser") || s.toLowerCase().includes("library browser"))
      return !1;
    const a = o?.unique_id || "";
    return a.includes("_media_browser") || a === "JellyHA_media_browser" || a.includes("_media_player_") && !a.includes("_device_player_") || !(o?.platform === "jellyha" || t.startsWith("media_player.jellyha_") || i?.attributes?.device_id !== void 0) ? !1 : !!(i?.attributes?.device_id || a.includes("_device_player_") || s.startsWith("Device ") || t.includes("_device_"));
  }
  _hasConfiguredClientDevices() {
    return this.hass?.states ? Object.keys(this.hass.states).some(
      (e) => this._isConfiguredClientDevice(this.hass.states[e])
    ) : !1;
  }
  _defaultClientDeviceChanged(e) {
    const t = e.detail?.value !== void 0 ? e.detail.value : e.target?.value;
    this._updateConfig("default_client_device", t);
  }
  _defaultCastDeviceChanged(e) {
    const t = e.detail?.value !== void 0 ? e.detail.value : e.target?.value;
    this._updateConfig("default_cast_device", t);
  }
  _subtitleModeChanged(e) {
    const t = e.detail?.value !== void 0 ? e.detail.value : e.target?.value;
    t !== void 0 && this._updateConfig("subtitle_mode", t);
  }
  _subtitleLanguageChanged(e) {
    const t = e.detail?.value !== void 0 ? e.detail.value : e.target?.value;
    t !== void 0 && this._updateConfig("subtitle_language", t);
  }
  _showNowPlayingChanged(e) {
    const t = e.target;
    this._updateConfig("show_now_playing", t.checked);
  }
  _enableBrowserPlayerChanged(e) {
    const i = e.target.checked, o = { ...this._config, enable_browser_player: i };
    if (o.enable_custom_play_actions && o.modal_play_actions)
      if (i) {
        if (!o.modal_play_actions.some((a) => a.type === "browser" || a.type === "play-browser")) {
          const a = o.modal_play_actions.findIndex((n) => n.type === "cast"), r = a !== -1 ? a + 1 : 0;
          o.modal_play_actions = [
            ...o.modal_play_actions.slice(0, r),
            {
              type: "browser",
              name: "Play in Browser",
              icon: "mdi:monitor"
            },
            ...o.modal_play_actions.slice(r)
          ];
        }
      } else
        o.modal_play_actions = o.modal_play_actions.filter(
          (s) => s.type !== "browser" && s.type !== "play-browser"
        );
    this._config = o, dt(this, "config-changed", { config: o });
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
  _isRuntimeOptionVisible() {
    const e = this._config?.media_type, t = this._config?.tv_content || "series";
    return !(e === "series" && t === "series");
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
  _showCardBackdropChanged(e) {
    const t = e.target;
    this._updateConfig("show_card_backdrop", t.checked), this._updateConfig("featured_queue_backdrop", t.checked);
  }
  _horizontalAlignmentChanged(e) {
    const t = e.detail?.value !== void 0 ? e.detail.value : e.target?.value;
    t !== void 0 && this._updateConfig("horizontal_alignment", t);
  }
  _enablePaginationChanged(e) {
    const t = e.target;
    this._updateConfig("enable_pagination", t.checked);
  }
  _showPaginationDotsChanged(e) {
    const t = e.target;
    this._updateConfig("show_pagination_dots", t.checked);
  }
  _filterFavoritesChanged(e) {
    const t = e.target;
    this._updateConfig("filter_favorites", t.checked);
  }
  _statusFilterChanged(e) {
    const t = e.detail?.value !== void 0 ? e.detail.value : e.target?.value;
    t !== void 0 && this._updateConfig("status_filter", t);
  }
  _filterNewlyAddedChanged(e) {
    const t = e.target;
    this._updateConfig("filter_newly_added", t.checked);
  }
  _showSearchChanged(e) {
    const t = e.target;
    this._updateConfig("show_search", t.checked);
  }
  _sortOptionChanged(e) {
    const t = e.detail?.value !== void 0 ? e.detail.value : e.target?.value;
    t !== void 0 && this._updateConfig("sort_option", t);
  }
  _useSeriesImageChanged(e) {
    const t = e.target;
    this._updateConfig("use_series_image", t.checked);
  }
  _enableCustomPlayActionsChanged(e) {
    const i = e.target.checked;
    if (!this._config) return;
    const o = { ...this._config, enable_custom_play_actions: i };
    if (i) {
      if (!o.modal_play_actions || o.modal_play_actions.length === 0) {
        const s = [];
        this._config.default_cast_device && s.push({
          type: "cast",
          name: "Cast to Chromecast",
          device: this._config.default_cast_device,
          icon: "mdi:cast"
        }), this._config.default_client_device && s.push({
          type: "client",
          name: "Play on Jellyfin Client",
          device: this._config.default_client_device,
          icon: "mdi:television-play"
        }), this._config.enable_browser_player !== !1 && s.push({
          type: "browser",
          name: "Play in Browser",
          icon: "mdi:monitor"
        });
        const a = this._config.modal_service || (this._config.click_action === "call-service" ? this._config.click_service || this._config.service : void 0) || (this._config.hold_action === "call-service" ? this._config.hold_service : void 0) || (this._config.double_tap_action === "call-service" ? this._config.double_tap_service : void 0) || this._config.click_service || this._config.service;
        a && s.push({
          type: "script",
          name: $e(this.hass, a),
          service: a,
          icon: "mdi:play"
        }), s.length > 0 && (o.modal_play_actions = s);
      } else if (this._config.enable_browser_player !== !1 && !o.modal_play_actions.some((a) => a.type === "browser" || a.type === "play-browser")) {
        const a = o.modal_play_actions.findIndex((n) => n.type === "cast"), r = a !== -1 ? a + 1 : 0;
        o.modal_play_actions = [
          ...o.modal_play_actions.slice(0, r),
          {
            type: "browser",
            name: "Play in Browser",
            icon: "mdi:monitor"
          },
          ...o.modal_play_actions.slice(r)
        ];
      }
    }
    this._config = o, dt(this, "config-changed", { config: o });
  }
  _updateConfig(e, t) {
    if (!this._config)
      return;
    const i = { ...this._config, [e]: t };
    this._config = i, dt(this, "config-changed", { config: i });
  }
};
Re.styles = Pe`
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
    .side-by-side > .checkbox-row {
      margin-bottom: 0;
      align-self: center;
    }
    .side-by-side > .form-row.double-tap-aligned {
      margin-top: 24px;
      align-self: end;
    }
    .helper-text {
      font-size: 0.8rem;
      color: var(--secondary-text-color, #888);
      margin-top: 4px;
      margin-left: 32px;
      line-height: 1.3;
    }
    .warning-banner {
      margin-top: 8px;
      padding: 8px 12px;
      background: rgba(255, 152, 0, 0.12);
      border: 1px solid rgba(255, 152, 0, 0.35);
      border-radius: 8px;
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 0.85rem;
      color: var(--primary-text-color, #fff);
    }
    .warning-banner ha-icon {
      --mdc-icon-size: 20px;
      color: #ff9800;
      flex-shrink: 0;
    }
  `;
bt([
  V({ attribute: !1 })
], Re.prototype, "hass", 2);
bt([
  f()
], Re.prototype, "_config", 2);
Re = bt([
  ge("jellyha-library-editor")
], Re);
var Oi = Object.defineProperty, Ui = Object.getOwnPropertyDescriptor, K = (e, t, i, o) => {
  for (var s = o > 1 ? void 0 : o ? Ui(t, i) : t, a = e.length - 1, r; a >= 0; a--)
    (r = e[a]) && (s = (o ? r(t, i, s) : r(s)) || s);
  return o && s && Oi(t, i, s), s;
};
let J = class extends X {
  constructor() {
    super(...arguments), this.layout = "grid", this.isNextUpHighlight = !1, this._pressStartTime = 0, this._isHoldActive = !1, this._itemTouchStartX = 0, this._itemTouchStartY = 0, this._rewindActive = !1, this._longPressProgress = 0, this._stopPulse = !1, this._longPressRaf = null, this._longPressConsumed = !1;
  }
  firstUpdated(e) {
    if (super.firstUpdated(e), typeof ResizeObserver < "u") {
      this._metaResizeObserver = new ResizeObserver(() => {
        this._checkMetaWrap();
      });
      const t = this.shadowRoot?.querySelector(".list-meta-row");
      t && this._metaResizeObserver.observe(t);
    }
  }
  disconnectedCallback() {
    super.disconnectedCallback(), this._metaResizeObserver?.disconnect(), this._longPressRaf && (cancelAnimationFrame(this._longPressRaf), this._longPressRaf = null), this._clearHoldTimer(), this._clickTimer && (clearTimeout(this._clickTimer), this._clickTimer = void 0);
  }
  updated(e) {
    super.updated(e), this._checkMetaWrap();
    const t = this.shadowRoot?.querySelector(".list-meta-row");
    t && this._metaResizeObserver && this._metaResizeObserver.observe(t);
  }
  _checkMetaWrap() {
    const e = this.shadowRoot?.querySelector(".list-meta-row"), t = this.shadowRoot?.querySelector(".media-item.list-item");
    if (e && t) {
      const i = e.offsetHeight > 22;
      t.classList.toggle("meta-wrapped", i);
    }
  }
  render() {
    return !this.item || !this.config || !this.hass ? l`` : this.layout === "list" || this.layout === "featured-queue" ? this._renderListItem() : this.layout === "featured-hero" ? this._renderFeaturedHero() : this._renderMediaItem();
  }
  _renderListItem() {
    const e = this.item, t = Ke(e, this.config.new_badge_days || 0), i = this._getRating(e), o = this.config.show_media_type_badge !== !1, s = this._isItemPlaying(e), r = this.config.show_ratings !== !1 && this.config.show_rating !== !1 && i ? i.toFixed(1) : "", n = e.year ?? (e.date_added ? new Date(e.date_added).getFullYear() : void 0), c = this.config.show_year !== !1 && n ? String(n) : "", p = this._isRuntimeVisible() && e.runtime_minutes ? ue(e.runtime_minutes) : "", _ = this.config.show_date_added === !0 && e.date_added ? nt(e.date_added, this.hass?.locale?.language || this.hass?.language) : "", g = e.series_name && e.season != null && e.episode != null && !isNaN(Number(e.season)) && !isNaN(Number(e.episode)) ? `S${String(Number(e.season)).padStart(2, "0")}E${String(Number(e.episode)).padStart(2, "0")}` : e.type === "Movie" ? "MOVIE" : "SERIES", m = e.series_name ? "series" : e.type === "Movie" ? "movie" : "series", b = this.config.show_subtitle !== !1, x = e.type === "Episode" || !!(e.series_name && e.name !== e.series_name), v = b && x && e.series_name && e.name !== e.series_name ? e.series_name : "", w = this.config.show_genres !== !1 && e.genres && e.genres.length > 0 ? e.genres.slice(0, 3) : [], k = w.length > 0, y = this.config.show_card_backdrop !== void 0 ? !!this.config.show_card_backdrop : this.config.featured_queue_backdrop !== !1, S = y ? R(
      e.backdrop_url || (this.config.use_series_image && e.series_poster_url ? e.series_poster_url : e.poster_url),
      600
    ) : "", $ = this.config.show_watched_status !== !1, C = $ && e.is_played, T = $ && e.type === "Series" && (e.unplayed_count || 0) > 0, G = (o || (t || C || T)) && !s, F = this.layout === "featured-queue" && (this.isCramped !== void 0 ? this.isCramped : !!this.classList?.contains("cramped") || (this.config.columns || 1) >= 3);
    return l`
      <div
        class="media-item list-item ${this.layout === "featured-queue" ? "featured-queue-item" : ""} ${y ? "has-backdrop" : ""} ${s ? "playing" : ""} ${this.config.show_title === !1 ? "no-title" : ""} ${v ? "has-subtitle" : ""} ${F ? "cramped" : ""}"
        tabindex="0"
        role="button"
        aria-label="${e.name}"
        @mousedown="${this._handleMouseDown}"
        @mouseup="${this._handleMouseUp}"
        @mouseleave="${this._handleMouseLeave}"
        @touchstart="${this._handleTouchStart}"
        @touchmove="${this._handleTouchMove}"
        @touchend="${this._handleTouchEnd}"
        @touchcancel="${this._handleTouchEnd}"
        @keydown="${this._handleKeydown}"
        @contextmenu="${this._handleContextMenu}"
      >
        ${y ? l`
          <div class="grid-card-backdrop-container">
            <img
              class="grid-card-backdrop"
              src="${S}"
              alt=""
              loading="lazy"
              decoding="async"
              @load="${this._handleImageLoad}"
              @error="${this._handleImageError}"
            />
            <div class="list-card-backdrop-scrim"></div>
          </div>
        ` : h}
        <div class="list-poster-wrapper">
          <div class="poster-container" id="poster-${e.id}">
            <div class="poster-inner">
              <img
                class="poster"
                src="${R(
      this.config.use_series_image && e.series_poster_url ? e.series_poster_url : e.poster_url,
      240
    )}"
                alt="${e.name}"
                width="76"
                height="114"
                loading="lazy"
                decoding="async"
                @load="${this._handleImageLoad}"
                @error="${this._handleImageError}"
              />
              <div class="poster-skeleton"></div>
              
              ${e.series_name && !s ? l`
            <div class="censor-bar list-bar ${this.isNextUpHighlight ? "highlight" : ""}">
              <span>${e.series_name}</span>
            </div>
              ` : h}
              
              ${this._renderNowPlayingOverlay(e)}
            </div>
          </div>
        </div>
        
        <div class="list-info">
          <div class="list-header">
            <div class="list-title-container">
              ${this.config.show_title !== !1 ? l`<h3 class="list-title" title="${e.name}">${e.name}</h3>` : h}
              ${v ? l`<p class="list-subtitle" title="${v}">${v}</p>` : h}
            </div>
            ${G ? l`
              <div class="list-badges ${F ? "cramped-badges" : ""}">
                ${o ? l`<span class="media-type-badge list-type-badge ${m}">${g}</span>` : h}
                ${t ? l`<span class="new-badge inline-badge">${d(this.hass?.locale?.language || this.hass?.language, "new")}</span>` : h}
                ${$ && e.is_played ? l`<div class="status-badge watched inline-badge"><ha-icon icon="mdi:check-bold"></ha-icon></div>` : h}
                ${$ && e.type === "Series" && (e.unplayed_count || 0) > 0 ? l`<div class="status-badge unplayed inline-badge">${e.unplayed_count}</div>` : h}
              </div>
            ` : h}
          </div>
          
          <div class="list-metadata">
            ${c || p || _ ? l`
              <div class="idle-meta-row list-meta-row">
                ${c ? l`<span class="idle-meta-text meta-text meta-year list-year">${c}</span>` : h}
                ${c && p ? l`<span class="idle-dot meta-dot">•</span>` : h}
                ${p ? l`<span class="idle-meta-text meta-text meta-runtime list-runtime">${p}</span>` : h}
                ${(c || p) && _ ? l`<span class="idle-dot meta-dot">•</span>` : h}
                ${_ ? l`<span class="idle-meta-text meta-text meta-date-added list-date-added">${_}</span>` : h}
              </div>
            ` : h}

            ${r || k ? l`
              <div class="idle-meta-row list-meta-pills">
                ${r ? l`<span class="idle-rating-pill rating-pill list-rating">
                      <ha-icon icon="mdi:star"></ha-icon>
                      <span>${r}</span>
                    </span>` : h}
                ${w.map((P) => l`<span class="genre-pill idle-genre-pill list-genre-pill" title="${P}"><span>${P}</span></span>`)}
              </div>
            ` : h}
          </div>
          
          ${this.config.show_description_on_hover !== !1 && (e.description || e.overview) && !F ? l`<p class="list-description" title="${e.description || e.overview}">${e.description || e.overview}</p>` : h}

        </div>
      </div>
    `;
  }
  _renderMediaItem() {
    const e = this.item, t = Ke(e, this.config.new_badge_days || 0), i = this._getRating(e), o = this.config.show_media_type_badge !== !1, s = this._isItemPlaying(e), a = this.config.show_year !== !1 && !!(e.year ?? (e.date_added ? new Date(e.date_added).getFullYear() : void 0)), r = !!(this.config.show_date_added && e.date_added), n = this.config.show_title !== !1, c = n || a || r;
    return l`
      <div
        class="media-item ${s ? "playing" : ""}"
        tabindex="0"
        role="button"
        aria-label="${e.name}"
        @mousedown="${this._handleMouseDown}"
        @mouseup="${this._handleMouseUp}"
        @mouseleave="${this._handleMouseLeave}"
        @touchstart="${this._handleTouchStart}"
        @touchmove="${this._handleTouchMove}"
        @touchend="${this._handleTouchEnd}"
        @touchcancel="${this._handleTouchEnd}"
        @keydown="${this._handleKeydown}"
        @contextmenu="${this._handleContextMenu}"
      >
        <div class="poster-container" id="poster-${e.id}">
          <div class="poster-inner">
            <img
              class="poster"
              src="${R(
      this.config.use_series_image && e.series_poster_url ? e.series_poster_url : e.poster_url,
      300
    )}"
              alt="${e.name}"
              width="140"
              height="210"
              loading="auto"
              decoding="async"
              @load="${this._handleImageLoad}"
              @error="${this._handleImageError}"
            />
            <div class="poster-skeleton"></div>
            
            ${o && !s ? l`
            <span class="media-type-badge ${e.series_name ? "series" : e.type === "Movie" ? "movie" : "series"}">
              ${e.series_name && e.season !== void 0 && e.episode !== void 0 ? `S${String(e.season).padStart(2, "0")}E${String(e.episode).padStart(2, "0")}` : e.type === "Movie" ? "Movie" : "Series"}
            </span>
          ` : h}

            ${e.series_name && !s ? l`
            <div class="censor-bar ${this.isNextUpHighlight ? "highlight" : ""}">
              <span>${e.series_name}</span>
            </div>
              ` : h}
            
            ${s ? h : this._renderStatusBadge(e, t)}
            
            ${this.config.show_ratings !== !1 && this.config.show_rating !== !1 && i && !s ? l`
                  <span class="rating rating-pill">
                    <ha-icon icon="mdi:star"></ha-icon>
                    <span>${i.toFixed(1)}</span>
                  </span>
                ` : h}
            
            ${this._isRuntimeVisible() && e.runtime_minutes && !s ? l`
                  <span class="runtime genre-pill">
                    <span>${ue(e.runtime_minutes)}</span>
                  </span>
                ` : h}
            
            ${s ? h : l`
            <div class="hover-overlay">
              ${this.config.show_year !== !1 && (e.year ?? (e.date_added ? new Date(e.date_added).getFullYear() : void 0)) ? l`<span class="overlay-year">${e.year ?? new Date(e.date_added).getFullYear()}</span>` : h}
              ${this.config.show_title !== !1 ? l`<h3 class="overlay-title" title="${e.name}">${e.name}</h3>` : h}
              ${this.config.show_genres !== !1 && e.genres && e.genres.length > 0 ? l`<span class="overlay-genres">${e.genres.slice(0, 3).join(", ")}</span>` : h}
              ${this.config.show_description_on_hover !== !1 && e.description ? l`<p class="overlay-description" title="${e.description}">${e.description}</p>` : h}
            </div>`}

            ${this._renderNowPlayingOverlay(e)}
          </div>
        </div>
        
        ${c ? l`
          <div class="media-info-below">
            ${n ? l`<p class="media-title" title="${e.name}">${e.name}</p>` : h}
            ${a ? l`<p class="media-year">${e.year ?? new Date(e.date_added).getFullYear()}</p>` : h}
            ${r ? l`<p class="media-date-added">${nt(e.date_added, this.hass?.locale?.language || this.hass?.language)}</p>` : h}
          </div>
        ` : h}
      </div>
    `;
  }
  _renderStatusBadge(e, t, i = !1) {
    const o = this.config.show_watched_status !== !1, s = i ? "inline-badge" : "";
    return o && e.is_played ? l`
        <div class="status-badge watched ${s}">
          <ha-icon icon="mdi:check-bold"></ha-icon>
        </div>
      ` : o && e.type === "Series" && (e.unplayed_count || 0) > 0 ? l`
        <div class="status-badge unplayed ${s}">
          ${e.unplayed_count}
        </div>
      ` : t ? l`<span class="new-badge ${s}">${d(this.hass?.locale?.language || this.hass?.language, "new")}</span>` : l``;
  }
  _renderNowPlayingOverlay(e) {
    if (!this.config.show_now_playing)
      return h;
    const t = zt(e, this.hass, this.config);
    if (!t)
      return h;
    const i = t.state === "paused", s = 2 * Math.PI * 18, a = s * (1 - this._longPressProgress);
    return l`
      <div 
        class="now-playing-overlay" 
        @click="${(r) => {
      r.stopPropagation(), this._handleRewind(t.entityId);
    }}"
        @mousedown="${this._stopPropagation}"
        @mouseup="${this._stopPropagation}"
        @touchstart="${this._stopPropagation}"
        @touchend="${this._stopPropagation}"
        @touchcancel="${this._stopPropagation}"
        role="button"
        tabindex="0"
      >
        <div class="now-playing-controls">
          <div 
            class="play-pause-wrapper ${this._stopPulse ? "stop-pulse" : ""}"
            @pointerdown="${(r) => {
      r.stopPropagation(), this._startLongPress(t.entityId);
    }}"
            @pointerup="${(r) => {
      r.stopPropagation(), this._endLongPress();
    }}"
            @pointerleave="${() => this._endLongPress()}"
            @pointercancel="${() => this._endLongPress()}"
            @contextmenu="${(r) => {
      r.preventDefault(), r.stopPropagation();
    }}"
          >
            ${this._rewindActive ? l`
              <ha-icon-button
                class="play-pause-btn spinning"
                .label=${d(this.hass?.locale?.language || this.hass?.language, "loading") || "Loading"}
              >
                <ha-icon icon="mdi:loading"></ha-icon>
              </ha-icon-button>
            ` : i ? l`
              <ha-icon-button
                class="play-pause-btn"
                .label=${d(this.hass?.locale?.language || this.hass?.language, "play") || "Play"}
                @click="${(r) => {
      if (r.stopPropagation(), this._longPressConsumed) {
        this._longPressConsumed = !1;
        return;
      }
      this._handlePlayPause(t.entityId);
    }}"
              >
                <ha-icon icon="mdi:play"></ha-icon>
              </ha-icon-button>
            ` : l`
              <ha-icon-button
                class="play-pause-btn"
                .label=${d(this.hass?.locale?.language || this.hass?.language, "pause") || "Pause"}
                @click="${(r) => {
      if (r.stopPropagation(), this._longPressConsumed) {
        this._longPressConsumed = !1;
        return;
      }
      this._handlePlayPause(t.entityId);
    }}"
              >
                <ha-icon icon="mdi:pause"></ha-icon>
              </ha-icon-button>
            `}
            ${this._longPressProgress > 0 ? l`
              <svg class="stop-ring" viewBox="0 0 40 40">
                <circle cx="20" cy="20" r="18"
                  stroke="#ef4444" stroke-width="2.5" fill="none"
                  stroke-dasharray="${s}"
                  stroke-dashoffset="${a}"
                  stroke-linecap="round"
                  transform="rotate(-90 20 20)" />
              </svg>
            ` : h}
          </div>
        </div>
      </div>
    `;
  }
  /* --- Helpers --- */
  _isItemPlaying(e) {
    return !!zt(e, this.hass, this.config);
  }
  _getRating(e) {
    if (this.config.rating_source === "imdb" && e.rating_imdb) {
      const t = parseFloat(e.rating_imdb);
      if (!isNaN(t)) return t;
    }
    if (this.config.rating_source === "tmdb" && e.rating_tmdb) {
      const t = parseFloat(e.rating_tmdb);
      if (!isNaN(t)) return t;
    }
    return e.rating ?? e.community_rating ?? null;
  }
  /* --- Event Handlers --- */
  _fireAction(e) {
    const t = new CustomEvent("jellyha-action", {
      detail: { type: e, item: this.item },
      bubbles: !0,
      composed: !0
    });
    this.dispatchEvent(t);
  }
  _startHoldTimer() {
    this._pressStartTime = Date.now(), this._isHoldActive = !1;
    const e = typeof window < "u" ? window.setTimeout : setTimeout;
    this._holdTimer = e(() => {
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
  _handleMouseDown(e) {
    if (e.button !== 0) return;
    e.currentTarget.classList.add("active-press"), this._startHoldTimer();
  }
  _handleMouseUp(e) {
    e.currentTarget.classList.remove("active-press"), this._isHoldActive ? (e.preventDefault(), e.stopPropagation()) : Date.now() - this._pressStartTime < 500 && this._handleTap(), this._clearHoldTimer();
  }
  _handleMouseLeave(e) {
    e.currentTarget.classList.remove("active-press"), this._clearHoldTimer();
  }
  _handleTap() {
    if ((this.config.double_tap_action || "none") === "none") {
      this._dispatchHaptic("light"), this._fireAction("click");
      return;
    }
    if (this._clickTimer)
      clearTimeout(this._clickTimer), this._clickTimer = void 0, this._dispatchHaptic("medium"), this._fireAction("double_tap");
    else {
      const t = typeof window < "u" ? window.setTimeout : setTimeout;
      this._clickTimer = t(() => {
        this._clickTimer = void 0, this._dispatchHaptic("light"), this._fireAction("click");
      }, 250);
    }
  }
  _handleContextMenu(e) {
    e.preventDefault(), e.stopPropagation();
  }
  _handleTouchStart(e) {
    e.touches.length > 0 && (this._itemTouchStartX = e.touches[0].clientX, this._itemTouchStartY = e.touches[0].clientY, e.currentTarget.classList.add("active-press")), this._startHoldTimer();
  }
  _handleTouchMove(e) {
    if (e.touches.length > 0) {
      const t = Math.abs(e.touches[0].clientX - this._itemTouchStartX), i = Math.abs(e.touches[0].clientY - this._itemTouchStartY);
      (t > 10 || i > 10) && (this._clearHoldTimer(), e.currentTarget.classList.remove("active-press"));
    }
  }
  _handleTouchEnd(e) {
    e.currentTarget.classList.remove("active-press"), this._clearHoldTimer();
    let i = 0;
    if (e.changedTouches.length > 0) {
      const o = e.changedTouches[0].clientX - this._itemTouchStartX, s = e.changedTouches[0].clientY - this._itemTouchStartY;
      i = Math.sqrt(o * o + s * s);
    }
    if (e.cancelable && e.preventDefault(), this._isHoldActive) {
      this._isHoldActive = !1;
      return;
    }
    i > 10 || this._handleTap();
  }
  _handleKeydown(e) {
    (e.key === "Enter" || e.key === " ") && (e.preventDefault(), this._fireAction("click"));
  }
  _handleImageLoad(e) {
    e.target.classList.add("loaded");
  }
  _handleImageError(e) {
    const t = e.target;
    t.style.opacity = "0", t.style.position = "absolute";
    const i = t.nextElementSibling;
    i && i.classList.contains("poster-skeleton") && i.classList.add("error");
  }
  /* --- Playback Control Handlers --- */
  _stopPropagation(e) {
    e.stopPropagation();
  }
  _handlePlayPause(e) {
    this.hass && (this._dispatchHaptic(), this.hass.callService("media_player", "media_play_pause", { entity_id: e }));
  }
  _handleStop(e) {
    this.hass && (this._dispatchHaptic(), zi(this.hass, e, this.config));
  }
  _startLongPress(e) {
    this._longPressRaf && (cancelAnimationFrame(this._longPressRaf), this._longPressRaf = null), this._longPressConsumed = !1;
    const t = Date.now(), i = 800;
    this._dispatchHaptic("selection");
    const o = () => {
      const s = Date.now() - t;
      if (this._longPressProgress = Math.min(s / i, 1), this._longPressProgress >= 1) {
        this._longPressConsumed = !0, this._handleStop(e), this._dispatchHaptic("success"), typeof navigator < "u" && navigator.vibrate && navigator.vibrate(50), this._stopPulse = !0, setTimeout(() => {
          this._stopPulse = !1;
        }, 600), this._endLongPress();
        return;
      }
      this._longPressRaf = requestAnimationFrame(o);
    };
    this._longPressRaf = requestAnimationFrame(o);
  }
  _endLongPress() {
    this._longPressRaf && (cancelAnimationFrame(this._longPressRaf), this._longPressRaf = null), this._longPressProgress = 0;
  }
  _handleRewind(e) {
    this._rewindActive = !0, setTimeout(() => {
      this._rewindActive = !1;
    }, 2e3), this._dispatchHaptic();
    const t = this.hass.states[e];
    if (t && t.attributes.media_position) {
      const i = t.attributes.media_position, o = t.attributes.media_position_updated_at;
      let s = i;
      if (o) {
        const r = (/* @__PURE__ */ new Date()).getTime(), n = new Date(o).getTime(), c = (r - n) / 1e3;
        t.state === "playing" && (s += c);
      }
      const a = Math.max(0, s - 20);
      this.hass.callService("media_player", "media_seek", {
        entity_id: e,
        seek_position: a
      });
    }
  }
  _dispatchHaptic(e = "selection") {
    const t = new CustomEvent("haptic", {
      detail: e,
      bubbles: !0,
      composed: !0
    });
    this.dispatchEvent(t);
  }
  _renderMetaLine(e, t) {
    const i = this.config.show_year !== !1, o = this._isRuntimeVisible(), s = this.config.show_date_added === !0, a = this.config.show_ratings !== !1 && this.config.show_rating !== !1, r = this.config.show_genres !== !1;
    let n = e.year;
    if (!n && e.date_added) {
      const w = new Date(e.date_added);
      isNaN(w.getFullYear()) || (n = w.getFullYear());
    }
    const c = i && n ? String(n) : "", p = o && e.runtime_minutes ? ue(e.runtime_minutes) : "", u = s && e.date_added ? nt(e.date_added, this.hass?.locale?.language || this.hass?.language) : "", _ = a && t && !this._isItemPlaying(e) ? t.toFixed(1) : "", g = r && e.genres && e.genres.length > 0 ? e.genres.slice(0, 2) : [], m = g.length > 0, b = [];
    c && b.push({ text: c, className: "meta-year" }), p && b.push({ text: p, className: "meta-runtime" }), u && b.push({ text: u, className: "meta-date-added" });
    const x = b.length > 0, v = !!_ || m;
    return !x && !v ? h : l`
      <div class="meta-line">
        ${x ? l`
          <div class="meta-text-row">
            ${b.map((w, k) => l`
              ${k > 0 ? l`<span class="idle-dot meta-dot">•</span>` : h}
              <span class="idle-meta-text meta-text ${w.className}">${w.text}</span>
            `)}
          </div>
        ` : h}
        ${v ? l`
          <div class="meta-pills-row">
            ${_ ? l`
              <span class="idle-rating-pill rating-pill">
                <ha-icon icon="mdi:star"></ha-icon>
                <span>${_}</span>
              </span>
            ` : h}
            ${m ? g.map((w) => l`<span class="genre-pill idle-genre-pill">${w}</span>`) : h}
          </div>
        ` : h}
      </div>
    `;
  }
  _isRuntimeVisible() {
    const e = this.config?.media_type, t = this.config?.tv_content || "series";
    return e === "series" && t === "series" ? !1 : this.config?.show_runtime !== !1;
  }
  _renderFeaturedHero() {
    const e = this.item, t = Ke(e, this.config.new_badge_days || 0), i = this._getRating(e), o = this.config.show_media_type_badge !== !1, s = this._isItemPlaying(e), a = this.config.show_title !== !1;
    return l`
      <div
        class="media-item featured-hero ${s ? "playing" : ""}"
        tabindex="0"
        role="button"
        aria-label="${e.name}"
        @mousedown="${this._handleMouseDown}"
        @mouseup="${this._handleMouseUp}"
        @mouseleave="${this._handleMouseLeave}"
        @touchstart="${this._handleTouchStart}"
        @touchmove="${this._handleTouchMove}"
        @touchend="${this._handleTouchEnd}"
        @touchcancel="${this._handleTouchEnd}"
        @keydown="${this._handleKeydown}"
        @contextmenu="${this._handleContextMenu}"
      >
        <div class="poster-container featured-hero-poster" id="poster-${e.id}">
          <div class="poster-inner">
            <img
              class="poster"
              src="${R(
      this.config.use_series_image && e.series_poster_url ? e.series_poster_url : e.poster_url,
      600
    )}"
              alt="${e.name}"
              width="240"
              height="360"
              loading="auto"
              decoding="async"
              @load="${this._handleImageLoad}"
              @error="${this._handleImageError}"
            />
            <div class="poster-skeleton"></div>

            ${o && !s ? l`
                <span class="media-type-badge ${e.series_name ? "series" : e.type === "Movie" ? "movie" : "series"}">
                  ${e.series_name && e.season != null && e.episode != null && !isNaN(Number(e.season)) && !isNaN(Number(e.episode)) ? `S${String(Number(e.season)).padStart(2, "0")}E${String(Number(e.episode)).padStart(2, "0")}` : e.type === "Movie" ? "MOVIE" : "SERIES"}
                </span>
              ` : h}

            ${s ? h : this._renderStatusBadge(e, t)}

            ${e.series_name && !s ? l`
                <div class="censor-bar ${this.isNextUpHighlight ? "highlight" : ""}">
                  <span>${e.series_name}</span>
                </div>
              ` : h}

            ${s ? h : l`
                <div class="featured-hero-scrim">
                  ${a ? l`<h3 class="featured-hero-title" title="${e.name}">${e.name}</h3>` : h}
                  ${a && e.series_name && e.name !== e.series_name ? l`<p class="featured-hero-subtitle" title="${e.series_name}">${e.series_name}</p>` : h}
                  ${this._renderMetaLine(e, i)}
                </div>
              `}

            ${this._renderNowPlayingOverlay(e)}
          </div>
        </div>
      </div>
    `;
  }
  _renderFeaturedQueue() {
    return this._renderListItem();
  }
};
J.styles = Vt;
K([
  V({ attribute: !1 })
], J.prototype, "hass", 2);
K([
  V({ attribute: !1 })
], J.prototype, "config", 2);
K([
  V({ attribute: !1 })
], J.prototype, "item", 2);
K([
  V({ type: String })
], J.prototype, "layout", 2);
K([
  V({ type: Boolean })
], J.prototype, "isNextUpHighlight", 2);
K([
  V({ type: Boolean })
], J.prototype, "isCramped", 2);
K([
  f()
], J.prototype, "_rewindActive", 2);
K([
  f()
], J.prototype, "_longPressProgress", 2);
K([
  f()
], J.prototype, "_stopPulse", 2);
J = K([
  ge("jellyha-media-item")
], J);
var Fi = Object.defineProperty, Bi = Object.getOwnPropertyDescriptor, z = (e, t, i, o) => {
  for (var s = o > 1 ? void 0 : o ? Bi(t, i) : t, a = e.length - 1, r; a >= 0; a--)
    (r = e[a]) && (s = (o ? r(t, i, s) : r(s)) || s);
  return o && s && Fi(t, i, s), s;
};
const Hi = "1.7.0";
console.info(
  `%c JELLYHA-LIBRARY-CARD %c v${Hi} `,
  "color: white; background: #00a4dc; font-weight: bold;",
  "color: #00a4dc; background: white; font-weight: bold;"
);
typeof window < "u" && (window.customCards = window.customCards || [], window.customCards.some((e) => e.type === "jellyha-library-card") || window.customCards.push({
  type: "jellyha-library-card",
  name: "JellyHA Library",
  description: "Display media from Jellyfin",
  preview: !0
}));
const Dt = {
  title: "",
  layout: "carousel",
  media_type: "both",
  tv_content: "series",
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
  show_pagination_dots: !0,
  horizontal_alignment: "center",
  show_date_added: !1,
  rating_source: "auto",
  new_badge_days: 3,
  theme: "auto",
  show_watched_status: !0,
  click_action: "more-info",
  hold_action: "jellyfin",
  double_tap_action: "none",
  default_cast_device: "",
  default_client_device: "",
  show_now_playing: !0,
  use_series_image: !1,
  show_search: !1,
  show_card_backdrop: !0,
  featured_queue_backdrop: !0,
  filter_favorites: !1,
  status_filter: "all",
  filter_newly_added: !1,
  sort_option: "date_added_desc"
};
function we(e, t, i) {
  const o = new CustomEvent(t, {
    bubbles: !0,
    composed: !0,
    detail: i
  });
  e.dispatchEvent(o);
}
let I = class extends X {
  constructor() {
    super(), this._currentPage = 0, this._itemsPerPage = 5, this._pressStartTime = 0, this._isHoldActive = !1, this._rewindActive = !1, this._items = [], this._lastUpdate = "", this._searchQuery = "", this._searchGenre = "", this._touchStartX = 0, this._touchStartY = 0, this._isOverscrolling = !1, this._elasticAnchorX = 0, this._itemTouchStartX = 0, this._itemTouchStartY = 0, this._containerWidth = 0, this.LIST_ITEM_MIN_WIDTH = 300, this.FEATURED_QUEUE_ITEM_MIN_WIDTH = 200, this._effectiveListColumns = 1, this._isFeaturedCramped = !1, this._isSwiping = !1, this._autoSwipePaused = !1, this._lastFrameTime = 0, this._scrollAccumulator = 0, this._scrollProgress = 0, this._hasScrollableContent = !1, this.SCROLL_INDICATOR_DOTS = 5, this._handleMouseEnter = () => {
      this._autoSwipePaused = !0;
    }, this._handleMouseLeave = () => {
      this._autoSwipePaused = !1;
    }, this._handleTouchStartInteraction = () => {
      this._autoSwipePaused = !0;
    }, this._handleTouchEndInteraction = () => {
      setTimeout(() => {
        this._autoSwipePaused = !1;
      }, 2e3);
    }, this._handleItemDeleted = (e) => {
      const i = e.detail?.itemId;
      if (i && this._items && this._items.length > 0) {
        const o = this._items.length;
        if (this._items = this._items.filter((s) => s.id !== i), this._items.length !== o) {
          this._mostRecentNextUpItemId === i && (this._mostRecentNextUpItemId = this._items[0]?.id);
          const s = this._getTotalPages();
          this._currentPage >= s && s > 0 && (this._currentPage = Math.max(0, s - 1)), this.requestUpdate();
        }
      }
    }, this._onDotClick = this._onDotClick.bind(this), this._handleTouchStart = this._handleTouchStart.bind(this), this._handleTouchMove = this._handleTouchMove.bind(this), this._handleTouchEnd = this._handleTouchEnd.bind(this), this._handlePointerDown = this._handlePointerDown.bind(this), this._handlePointerMove = this._handlePointerMove.bind(this), this._handlePointerUp = this._handlePointerUp.bind(this), this._handleScroll = this._handleScroll.bind(this);
  }
  connectedCallback() {
    super.connectedCallback(), this._setupResizeHandler(), this.addEventListener("mouseenter", this._handleMouseEnter), this.addEventListener("mouseleave", this._handleMouseLeave), this.addEventListener("touchstart", this._handleTouchStartInteraction, { passive: !0 }), this.addEventListener("touchend", this._handleTouchEndInteraction), this._setupAutoSwipe(), typeof window < "u" && window.addEventListener("jellyha-item-deleted", this._handleItemDeleted);
  }
  disconnectedCallback() {
    super.disconnectedCallback(), this._resizeObserver?.disconnect(), this._resizeHandler && window.removeEventListener("resize", this._resizeHandler), this.removeEventListener("mouseenter", this._handleMouseEnter), this.removeEventListener("mouseleave", this._handleMouseLeave), this.removeEventListener("touchstart", this._handleTouchStartInteraction), this.removeEventListener("touchend", this._handleTouchEndInteraction), this._clearAutoSwipe(), typeof window < "u" && window.removeEventListener("jellyha-item-deleted", this._handleItemDeleted);
  }
  _setupAutoSwipe() {
    this._clearAutoSwipe();
    const e = this._config?.auto_swipe_interval;
    !e || e <= 0 || (this._config.enable_pagination !== !1 || this._config.layout === "featured" ? this._autoSwipeTimer = window.setInterval(() => {
      this._autoSwipePaused || this._handleAutoSwipePage();
    }, e * 1e3) : this._startContinuousScroll());
  }
  _clearAutoSwipe() {
    this._autoSwipeTimer && (clearInterval(this._autoSwipeTimer), this._autoSwipeTimer = void 0), this._animationFrameId && (cancelAnimationFrame(this._animationFrameId), this._animationFrameId = void 0);
  }
  /* Continuous Scroll Logic */
  _startContinuousScroll() {
    const e = (t) => {
      this._lastFrameTime || (this._lastFrameTime = t);
      const i = t - this._lastFrameTime;
      if (this._lastFrameTime = t, !this._autoSwipePaused && this._config.auto_swipe_interval) {
        const o = this.shadowRoot?.querySelector(".carousel, .grid-wrapper, .list-wrapper, .featured-wrapper");
        if (o) {
          const { scrollLeft: s, scrollWidth: a, clientWidth: r } = o;
          Math.abs(this._scrollAccumulator - s) > 10 && (this._scrollAccumulator = s);
          const c = r / (this._config.auto_swipe_interval * 1e3) * i, p = a / 2;
          this._scrollAccumulator += c, this._scrollAccumulator >= p ? (this._scrollAccumulator = this._scrollAccumulator - p, o.scrollLeft = this._scrollAccumulator) : o.scrollLeft = this._scrollAccumulator;
        }
      }
      this._animationFrameId = requestAnimationFrame(e);
    };
    this._animationFrameId = requestAnimationFrame(e);
  }
  /* Helper to get items per page based on layout */
  _getEffectiveItemsPerPage() {
    if (this._config?.layout === "featured") {
      const e = Math.max(1, this._config.columns || 1), t = Math.max(2, Math.min(3, this._config.rows || 3));
      return 1 + e * t;
    }
    return this._config?.items_per_page || this._itemsPerPage;
  }
  /* Pagination Auto Swipe Logic */
  async _handleAutoSwipePage() {
    const e = this._items || [], t = this._getEffectiveItemsPerPage(), i = this._config.max_pages || 10, o = Math.min(Math.ceil(e.length / t), i);
    this._currentPage >= o - 1 ? await this._animatePageChange("next", () => {
      this._currentPage = 0;
    }) : this._nextPage();
  }
  /* Pagination Handlers */
  async _nextPage() {
    if (!this._config?.entity || !this.hass || !this.hass.states[this._config.entity]) return;
    const t = this._filterItems(this._items || []), i = this._getEffectiveItemsPerPage(), o = this._config.max_pages || 10, s = Math.min(Math.ceil(t.length / i), o);
    this._currentPage < s - 1 && await this._animatePageChange("next", () => {
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
    const t = this.shadowRoot?.querySelector(".carousel, .grid-wrapper, .list-wrapper, .featured-wrapper");
    t && (e === "start" ? t.scrollLeft = 0 : t.scrollLeft = t.scrollWidth);
  }
  /**
   * Helper to animate page changes (Slide & Fade)
   **/
  async _animatePageChange(e, t) {
    const i = this.shadowRoot?.querySelector(".carousel, .grid-wrapper, .list-wrapper, .featured-wrapper");
    if (!i) {
      t();
      return;
    }
    const o = e === "next" ? "-30px" : "30px";
    i.style.transition = "transform 0.2s ease-out, opacity 0.2s ease-out", i.style.transform = `translateX(${o})`, i.style.opacity = "0", await new Promise((a) => setTimeout(a, 200)), t(), await this.updateComplete, this._setScrollPosition(e === "next" ? "start" : "end");
    const s = e === "next" ? "30px" : "-30px";
    i.style.transition = "none", i.style.opacity = "0", i.style.transform = `translateX(${s})`, i.offsetHeight, i.style.transition = "transform 0.25s ease-out, opacity 0.25s ease-out", i.style.transform = "translateX(0)", i.style.opacity = "1", await new Promise((a) => setTimeout(a, 250)), i.style.transition = "", i.style.transform = "", i.style.opacity = "";
  }
  /**
   * Helper to get total pages (used for elastic check)
   */
  _getTotalPages() {
    if (!this._config?.entity || !this.hass || !this.hass.states[this._config.entity]) return 1;
    const t = this._filterItems(this._items || []), i = this._getEffectiveItemsPerPage(), o = this._config.max_pages || 10;
    return Math.min(Math.ceil(t.length / i), o);
  }
  // Touch/Swipe handlers
  _handleTouchStart(e) {
    this._touchStartX = e.touches[0].clientX, this._touchStartY = e.touches[0].clientY, this._isSwiping = !1, this._isOverscrolling = !1, this._elasticAnchorX = 0;
  }
  _handleTouchMove(e) {
    if (!this._touchStartX) return;
    const t = e.touches[0].clientX - this._touchStartX, i = e.touches[0].clientY - this._touchStartY;
    if (Math.abs(t) > Math.abs(i)) {
      const o = this.shadowRoot?.querySelector(".carousel, .grid-wrapper, .list-wrapper, .featured-wrapper");
      if (o && Math.abs(t) > 0) {
        const { scrollLeft: s, scrollWidth: a, clientWidth: r } = o, n = a - r, c = s <= 5, p = s >= n - 5, u = this._config.show_pagination !== !1;
        let _ = !1;
        if (u) {
          const g = this._getTotalPages();
          c && t > 0 && this._currentPage === 0 && (_ = !0), p && t < 0 && this._currentPage >= g - 1 && (_ = !0);
        } else
          c && t > 0 && (_ = !0), p && t < 0 && (_ = !0);
        if (_) {
          this._isOverscrolling || (this._isOverscrolling = !0, this._elasticAnchorX = t), e.cancelable && e.preventDefault();
          const g = 0.3, m = t - this._elasticAnchorX;
          o.style.transition = "none", o.style.transform = `translateX(${m * g}px)`;
          return;
        }
      }
      Math.abs(t) > 30 && (this._isSwiping = !0);
    }
  }
  _handleTouchEnd(e) {
    if (this._isOverscrolling) {
      const s = this.shadowRoot?.querySelector(".carousel, .grid-wrapper, .list-wrapper, .featured-wrapper");
      s && (s.style.transition = "transform 0.4s cubic-bezier(0.25, 0.8, 0.5, 1)", s.style.transform = ""), this._isOverscrolling = !1, this._elasticAnchorX = 0, this._touchStartX = 0, this._isSwiping = !1;
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
    const t = e.changedTouches[0].clientX - this._touchStartX, i = 50, o = this.shadowRoot?.querySelector(".carousel, .grid-wrapper, .list-wrapper, .featured-wrapper");
    if (t < -i)
      if (o) {
        const { scrollLeft: s, scrollWidth: a, clientWidth: r } = o;
        s + r >= a - 10 && this._nextPage();
      } else
        this._nextPage();
    else t > i && (o ? o.scrollLeft <= 10 && this._prevPage() : this._prevPage());
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
      const o = this.shadowRoot?.querySelector(".carousel, .grid-wrapper, .list-wrapper, .featured-wrapper");
      if (o && Math.abs(t) > 0) {
        const { scrollLeft: s, scrollWidth: a, clientWidth: r } = o, n = a - r, c = s <= 5, p = s >= n - 5, u = this._config.show_pagination !== !1;
        let _ = !1;
        if (u) {
          const g = this._getTotalPages();
          c && t > 0 && this._currentPage === 0 && (_ = !0), p && t < 0 && this._currentPage >= g - 1 && (_ = !0);
        } else
          c && t > 0 && (_ = !0), p && t < 0 && (_ = !0);
        if (_) {
          this._isOverscrolling || (this._isOverscrolling = !0, this._elasticAnchorX = t), e.cancelable && e.preventDefault();
          const g = 0.3, m = t - this._elasticAnchorX;
          o.style.transition = "none", o.style.transform = `translateX(${m * g}px)`;
          return;
        }
      }
      Math.abs(t) > 30 && (this._isSwiping = !0);
    }
  }
  _handlePointerUp(e) {
    if (e.target.releasePointerCapture?.(e.pointerId), this._isOverscrolling) {
      const s = this.shadowRoot?.querySelector(".carousel, .grid-wrapper, .list-wrapper, .featured-wrapper");
      s && (s.style.transition = "transform 0.4s cubic-bezier(0.25, 0.8, 0.5, 1)", s.style.transform = ""), this._isOverscrolling = !1, this._elasticAnchorX = 0, this._touchStartX = 0, this._isSwiping = !1;
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
    const t = e.clientX - this._touchStartX, i = 50, o = this.shadowRoot?.querySelector(".carousel, .grid-wrapper, .list-wrapper, .featured-wrapper");
    if (t < -i)
      if (o) {
        const { scrollLeft: s, scrollWidth: a, clientWidth: r } = o;
        s + r >= a - 10 && this._nextPage();
      } else
        this._nextPage();
    else t > i && (o ? o.scrollLeft <= 10 && this._prevPage() : this._prevPage());
    this._touchStartX = 0, this._isSwiping = !1;
  }
  // Scroll handler for elastic dot indicator
  _handleScroll(e) {
    const t = e.target, i = t.scrollWidth, o = t.clientWidth, s = t.scrollLeft, a = i > o + 10;
    if (a !== this._hasScrollableContent && (this._hasScrollableContent = a), a) {
      let r = 0;
      const n = this._config.enable_pagination === !1 && (this._config.auto_swipe_interval || 0) > 0;
      if (n) {
        const c = i / 2;
        r = s / c;
      } else {
        const c = i - o;
        r = s / c;
      }
      !n && (i - o - s < 10 || r > 0.98) && (r = 1), (s < 10 || r < 0.02) && (r = 0), r = Math.min(1, Math.max(0, r)), this._scrollProgress = r;
    }
  }
  // Render scroll indicator for non-paginated scrollable content
  _renderScrollIndicator() {
    if (!this._hasScrollableContent || this._config.show_pagination_dots === !1) return l``;
    const e = this.SCROLL_INDICATOR_DOTS, t = this._scrollProgress, i = Math.round(t * (e - 1));
    return l`
      <div class="scroll-indicator">
        ${Array.from({ length: e }, (o, s) => {
      const a = s === i, r = s === 0 && t < 0.1 || s === e - 1 && t > 0.9;
      return l`
        <span 
          class="scroll-dot ${a ? "active" : ""} ${r ? "pill" : ""}"
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
        const s = Math.max(2, Math.floor(i / 160));
        if (s !== this._itemsPerPage && (this._itemsPerPage = s, this.requestUpdate()), this._updateEffectiveListColumns(i), this._config && this._config.layout === "featured") {
          const a = Math.max(1, this._config.columns || 1);
          let r;
          const n = this.shadowRoot?.querySelector(".featured-side");
          n && n.clientWidth > 0 ? r = (n.clientWidth - (a - 1) * 10) / a : r = ((i < 500 ? i : Math.max(0, i - 266)) - (a - 1) * 10) / a;
          const c = a >= 3 || r < this.FEATURED_QUEUE_ITEM_MIN_WIDTH;
          c !== this._isFeaturedCramped && (this._isFeaturedCramped = c, this.requestUpdate());
        }
      }
    };
    try {
      this._resizeObserver = new ResizeObserver(() => {
        this._resizeHandler && window.requestAnimationFrame(() => this._resizeHandler());
      }), this._resizeObserver.observe(this);
    } catch (e) {
      console.warn("ResizeObserver not supported, falling back to window resize", e);
    }
    window.addEventListener("resize", this._resizeHandler), this._resizeHandler();
  }
  _updateEffectiveListColumns(e) {
    if (!this._config) return;
    const t = this._config.columns || 1;
    if (t > 1) {
      const i = Math.max(1, Math.floor(e / this.LIST_ITEM_MIN_WIDTH)), o = Math.min(t, i);
      o !== this._effectiveListColumns && (this._effectiveListColumns = o, this.requestUpdate());
    } else this._effectiveListColumns !== 1 && (this._effectiveListColumns = 1, this.requestUpdate());
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
    this._config = { ...Dt, ...e }, this._containerWidth > 0 ? this._updateEffectiveListColumns(this._containerWidth) : this._effectiveListColumns = this._config.columns || 1;
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
      ...Dt
    };
  }
  /**
   * Get card size for layout
   */
  getCardSize() {
    return this._config?.layout === "list" || this._config?.layout === "featured" ? 5 : 3;
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
  shouldUpdate(e) {
    if (!this._config)
      return !1;
    if (e.has("_currentPage") || e.has("_itemsPerPage") || e.has("_items") || e.has("_error") || e.has("_searchQuery") || e.has("_searchGenre") || e.has("_isFeaturedCramped") || e.has("_scrollProgress") || e.has("_hasScrollableContent"))
      return !0;
    if (e.has("hass")) {
      const t = e.get("hass");
      if (t) {
        const i = t.states[this._config.entity], o = this.hass.states[this._config.entity], s = /* @__PURE__ */ new Set([
          ...Mt(this.hass, this._config),
          ...Mt(t, this._config)
        ]);
        for (const a of s)
          if (t.states[a] !== this.hass.states[a])
            return !0;
        return i !== o;
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
        let t;
        if (this._config.media_type === "next_up")
          t = await this.hass.callWS({
            type: "jellyha/get_user_next_up",
            entity_id: this._config.entity,
            server_entity_id: this._config.entity
          });
        else if ((this._config.media_type === "series" || this._config.media_type === "both" || !this._config.media_type) && this._config.tv_content === "episodes") {
          const i = this._config.media_type === "series" ? ["Episode"] : ["Movie", "Episode"];
          t = await this.hass.callWS({
            type: "jellyha/get_latest_items",
            entity_id: this._config.entity,
            server_entity_id: this._config.entity,
            item_types: i
          });
        } else
          t = await this.hass.callWS({
            type: "jellyha/get_items",
            entity_id: this._config.entity,
            server_entity_id: this._config.entity
          });
        t && t.items ? (this._items = t.items, this._config.media_type === "next_up" && this._items.length > 0 ? this._mostRecentNextUpItemId = this._items[0].id : this._mostRecentNextUpItemId = void 0) : (this._items = [], this._mostRecentNextUpItemId = void 0);
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
        const i = t.attributes.entry_id, o = t.attributes.last_updated;
        let s = !1;
        if (o !== this._lastUpdate || this._items.length === 0 && i)
          this._lastUpdate = o, s = !0;
        else if (e.has("_config")) {
          const a = e.get("_config");
          a && (a.media_type !== this._config?.media_type || a.tv_content !== this._config?.tv_content || a.entity !== this._config?.entity) && (s = !0);
        }
        s && this._fetchItems();
      }
      if (this._config?.layout === "featured") {
        const i = Math.max(1, this._config.columns || 1), o = this.shadowRoot?.querySelector(".featured-side");
        if (o && o.clientWidth > 0) {
          const s = (o.clientWidth - (i - 1) * 10) / i;
          this._isFeaturedCramped = i >= 3 || s < this.FEATURED_QUEUE_ITEM_MIN_WIDTH;
        } else
          this._isFeaturedCramped = i >= 3;
      }
    }
    this._config.enable_pagination || requestAnimationFrame(() => {
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
      return l``;
    if (!this.hass.states[this._config.entity])
      return this._renderError(`Entity not found: ${this._config.entity}`);
    if (this._error)
      return this._renderError(this._error);
    const t = this._filterItems(this._items || []);
    return l`
      <ha-card>
        <div class="card-inner">
            ${this._config.title ? l`
                  <div class="card-header">
                    <h2>${this._config.title}</h2>
                  </div>
                ` : h}
            ${this._config.show_search ? this._renderSearchBar(t) : h}
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
    if (this._searchQuery) {
      const a = this._searchQuery.toLowerCase();
      t = t.filter((r) => r.name.toLowerCase().includes(a));
    }
    this._searchGenre && (t = t.filter((a) => a.genres && a.genres.includes(this._searchGenre))), this._config.media_type === "movies" ? t = t.filter((a) => a.type === "Movie") : this._config.media_type === "series" ? this._config.tv_content === "episodes" ? t = t.filter((a) => a.type === "Episode") : t = t.filter((a) => a.type === "Series") : this._config.media_type === "both" || !this._config.media_type ? this._config.tv_content === "episodes" ? t = t.filter((a) => a.type === "Movie" || a.type === "Episode") : t = t.filter((a) => a.type !== "Episode") : this._config.media_type, this._config.filter_favorites && (t = t.filter((a) => a.is_favorite === !0));
    const i = this._config.status_filter || "all";
    if (i === "unwatched" ? t = t.filter((a) => !a.is_played) : i === "watched" && (t = t.filter((a) => a.is_played === !0)), this._config.filter_newly_added && (t = t.filter((a) => Ke(a, this._config.new_badge_days || 0))), this._config.media_type === "next_up") {
      const a = this._config.max_pages;
      if (a != null && a > 0) {
        const r = this._getEffectiveItemsPerPage() * a;
        t = t.slice(0, r);
      }
      return t;
    }
    const o = this._config.sort_option || "date_added_desc";
    t.sort((a, r) => {
      switch (o) {
        case "date_added_asc":
          return (a.date_added || "").localeCompare(r.date_added || "");
        case "date_added_desc":
          return (r.date_added || "").localeCompare(a.date_added || "");
        case "title_asc":
          return (a.name || "").localeCompare(r.name || "");
        case "title_desc":
          return (r.name || "").localeCompare(a.name || "");
        case "year_asc":
          return (a.year || 0) - (r.year || 0);
        case "year_desc":
          return (r.year || 0) - (a.year || 0);
        case "last_played_asc":
          return (a.last_played_date || "").localeCompare(r.last_played_date || "");
        case "last_played_desc":
          return (r.last_played_date || "").localeCompare(a.last_played_date || "");
        default:
          return 0;
      }
    });
    const s = this._config.max_pages;
    if (s != null && s > 0) {
      const a = this._getEffectiveItemsPerPage() * s;
      t = t.slice(0, a);
    }
    return t;
  }
  /**
   * Render media item action handler
   */
  _handleItemAction(e) {
    const { type: t, item: i } = e.detail;
    this._performAction(i, t);
  }
  /**
   * Render layout based on config
   */
  _renderLayout(e) {
    const t = this._config.layout || "carousel", i = this._config.enable_pagination !== !1;
    return t === "carousel" ? this._renderCarousel(e, i) : t === "list" ? this._renderList(e, i) : t === "grid" ? this._renderGrid(e, i) : t === "featured" ? this._renderFeatured(e, i) : l`
      <div class="${t}">
        ${e.map((o) => l`
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
  _renderCarousel(e, t) {
    const i = this._config.items_per_page || this._itemsPerPage, o = this._config.max_pages, s = o ? Number(o) : 0, a = s > 0 ? s : 1 / 0, r = Math.min(Math.ceil(e.length / i), a), n = this._currentPage * i, c = !t && (this._config.auto_swipe_interval || 0) > 0, p = t ? e.slice(n, n + i) : c ? [...e, ...e] : e;
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
          class="carousel ${t ? "paginated" : "scrollable"}"
          @scroll="${t ? h : this._handleScroll}"
        >
          ${p.map((u) => l`
            <jellyha-media-item
                .hass=${this.hass}
                .config=${this._config}
                .item=${u}
                .layout=${"grid"}
                .isNextUpHighlight=${this._config.media_type === "next_up" && u.id === this._mostRecentNextUpItemId}
                @jellyha-action=${this._handleItemAction}
            ></jellyha-media-item>
          `)}
        </div>
        ${t && r > 1 ? this._renderPagination(r) : h}
        ${t ? h : this._renderScrollIndicator()}
      </div>
    `;
  }
  /**
   * Render list with optional pagination
   */
  _renderList(e, t) {
    const i = this._config.items_per_page || this._itemsPerPage, o = this._config.max_pages, s = o ? Number(o) : 0, a = s > 0 ? s : 1 / 0, r = Math.min(Math.ceil(e.length / i), a), n = this._currentPage * i, c = !t && (this._config.auto_swipe_interval || 0) > 0, p = t ? e.slice(n, n + i) : c ? [...e, ...e] : e, u = this._effectiveListColumns, _ = u === 1;
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
          class="list ${t ? "paginated" : ""} ${_ ? "single-column" : ""}"
          style="--jf-list-columns: ${u}"
        >
          ${p.map((g) => l`
            <jellyha-media-item
                .hass=${this.hass}
                .config=${this._config}
                .item=${g}
                .layout=${"list"}
                .isNextUpHighlight=${this._config.media_type === "next_up" && g.id === this._mostRecentNextUpItemId}
                @jellyha-action=${this._handleItemAction}
            ></jellyha-media-item>
          `)}
        </div>
        ${t && r > 1 ? this._renderPagination(r) : h}
      </div>
    `;
  }
  /**
   * Render grid with optional pagination
   */
  _renderGrid(e, t) {
    const i = this._config.items_per_page || this._itemsPerPage, o = this._config.max_pages, s = o ? Number(o) : 0, a = s > 0 ? s : 1 / 0, r = Math.min(Math.ceil(e.length / i), a), n = this._currentPage * i, c = !t && (this._config.auto_swipe_interval || 0) > 0, p = t ? e.slice(n, n + i) : c ? [...e, ...e] : e, u = this._config.columns || 1, _ = u === 1, g = !t && (this._config.auto_swipe_interval || 0) > 0;
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
          @scroll="${t ? h : this._handleScroll}"
        >
          <div
            class="grid ${t ? "paginated" : ""} ${_ ? "auto-columns" : ""} ${g ? "horizontal" : ""}"
            style="--jf-columns: ${u}; --jf-grid-rows: ${u}"
          >
            ${p.map((m) => l`
                <jellyha-media-item
                    .hass=${this.hass}
                    .config=${this._config}
                    .item=${m}
                    .layout=${"grid"}
                    .isNextUpHighlight=${this._config.media_type === "next_up" && m.id === this._mostRecentNextUpItemId}
                    @jellyha-action=${this._handleItemAction}
                ></jellyha-media-item>
            `)}
          </div>
        </div>
        ${t && r > 1 ? this._renderPagination(r) : h}
        ${t ? h : this._renderScrollIndicator()}
      </div>
    `;
  }
  /**
   * Render featured layout: first item of each page as a large hero poster,
   * and the remaining items (default 3) as a compact, height-locked queue beside it.
   */
  _renderFeatured(e, t) {
    const i = this._getEffectiveItemsPerPage(), o = this._config.max_pages, s = o ? Number(o) : 0, a = s > 0 ? s : 1 / 0, r = Math.min(Math.ceil(e.length / i), a), n = this._currentPage * i, c = e.slice(n, n + i), [p, ...u] = c;
    if (!p) return l``;
    const _ = Math.max(1, this._config.columns || 1), g = Math.max(2, Math.min(3, this._config.rows || 3)), m = _ >= 3 || this._isFeaturedCramped;
    return l`
      <div 
        class="featured-wrapper"
        @touchstart="${this._handleTouchStart}"
        @touchmove="${this._handleTouchMove}"
        @touchend="${this._handleTouchEnd}"
        @pointerdown="${this._handlePointerDown}"
        @pointermove="${this._handlePointerMove}"
        @pointerup="${this._handlePointerUp}"
      >
        <div class="featured ${u.length === 0 ? "single" : ""} ${_ > 1 ? "multi-column" : ""} rows-${g}">
            <div class="featured-hero-container">
              <jellyha-media-item
                class="featured-main"
                .hass=${this.hass}
                .config=${this._config}
                .item=${p}
                .layout=${"featured-hero"}
                .isNextUpHighlight=${this._config.media_type === "next_up" && p.id === this._mostRecentNextUpItemId}
                @jellyha-action=${this._handleItemAction}
              ></jellyha-media-item>
            </div>
            ${u.length > 0 ? l`
              <div 
                class="featured-side columns-${_} rows-${g} ${m ? "cramped" : ""}"
                style="--jf-featured-columns: ${_}; --jf-featured-rows: ${g};"
              >
                ${u.map((b) => l`
                  <jellyha-media-item
                    class="${m ? "cramped" : ""}"
                    .hass=${this.hass}
                    .config=${this._config}
                    .item=${b}
                    .layout=${"featured-queue"}
                    .isCramped=${m}
                    .isNextUpHighlight=${this._config.media_type === "next_up" && b.id === this._mostRecentNextUpItemId}
                    @jellyha-action=${this._handleItemAction}
                  ></jellyha-media-item>
                `)}
              </div>
            ` : h}
          </div>
        ${t && r > 1 ? this._renderPagination(r) : h}
      </div>
    `;
  }
  /**
   * Main Pagination Render Dispatcher
   * Decides between standard and smart pagination based on page count
   */
  _renderPagination(e) {
    return this._config.show_pagination_dots === !1 ? l`` : e <= 5 ? this._renderStandardPagination(e) : this._renderSmartPagination(e);
  }
  /**
   * Render Standard Pagination (Existing Logic preserved)
   */
  _renderStandardPagination(e) {
    return l`
      <div class="pagination-dots">
        ${Array.from({ length: e }, (t, i) => l`
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
    const n = -(this._currentPage * 16) + 32;
    return l`
      <div class="pagination-container smart" style="width: ${72}px">
        <div 
          class="pagination-track" 
          style="transform: translateX(${n}px); width: ${e * 16}px"
        >
          ${Array.from({ length: e }, (c, p) => {
      const u = Math.abs(p - this._currentPage);
      let _ = "smart-dot";
      return p === this._currentPage ? _ += " active" : u > 2 ? _ += " hidden" : u === 2 && (_ += " small"), l`
              <button
                type="button"
                class="${_}"
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
   * Perform configured action
   */
  _performAction(e, t) {
    let i = "none";
    switch (t === "click" ? i = this._config.click_action || "more-info" : t === "hold" ? i = this._config.hold_action || "jellyfin" : t === "double_tap" && (i = this._config.double_tap_action || "none"), i) {
      case "jellyfin":
        this._openExternalUrl(e.jellyfin_url, e);
        break;
      case "play-client":
        this._playOnClient(e, t);
        break;
      case "cast":
        this._castMedia(e, t);
        break;
      case "more-info":
        this._showItemDetails(e);
        break;
      case "trailer":
        e.trailer_url ? ae(e.trailer_url, "_blank") : we(this, "hass-notification", {
          message: d(this.hass.locale?.language || this.hass.language, "no_trailer")
        });
        break;
      case "call-service":
        this._callCustomService(e, t);
        break;
      case "play-browser":
        this._playInBrowser(e, t);
        break;
    }
  }
  _playInBrowser(e, t = "click") {
    let i = this._config.subtitle_mode, o = this._config.subtitle_language;
    t === "click" ? (this._config.click_subtitle_mode && (i = this._config.click_subtitle_mode), this._config.click_subtitle_language && (o = this._config.click_subtitle_language)) : t === "hold" ? (this._config.hold_subtitle_mode && (i = this._config.hold_subtitle_mode), this._config.hold_subtitle_language && (o = this._config.hold_subtitle_language)) : t === "double_tap" && (this._config.double_tap_subtitle_mode && (i = this._config.double_tap_subtitle_mode), this._config.double_tap_subtitle_language && (o = this._config.double_tap_subtitle_language)), Ht({
      hass: this.hass,
      item: e,
      configEntryId: e.config_entry_id || e.entry_id,
      serverEntityId: this._config.entity,
      subtitleMode: i,
      subtitleLanguage: o
    });
  }
  async _callCustomService(e, t) {
    let i = "", o = {};
    t === "click" ? (i = this._config.click_service || this._config.service || "", o = this._config.click_service_data || this._config.service_data || {}) : t === "hold" ? (i = this._config.hold_service || this._config.service || "", o = this._config.hold_service_data || this._config.service_data || {}) : t === "double_tap" && (i = this._config.double_tap_service || this._config.service || "", o = this._config.double_tap_service_data || this._config.service_data || {});
    const s = {
      ...o,
      item_id: e.id,
      title: e.name,
      name: e.name,
      media_type: e.type,
      series_name: e.series_name || null,
      series_id: e.series_id || null,
      season: e.season != null ? e.season : null,
      episode: e.episode != null ? e.episode : null,
      year: e.year || null,
      genres: e.genres || [],
      rating: e.rating || null,
      poster_url: e.poster_url || null,
      series_poster_url: e.series_poster_url || null,
      backdrop_url: e.backdrop_url || null,
      date_created: e.date_added || null,
      date_added: e.date_added || null,
      description: e.description || null,
      overview: e.description || null,
      official_rating: e.official_rating || null,
      last_played_date: e.last_played_date || null,
      // Music attributes (Audio, MusicAlbum, MusicArtist, etc.)
      artist: e.artist_name || e.album_artist || null,
      artist_name: e.artist_name || null,
      album: e.album || null,
      album_artist: e.album_artist || null,
      jellyfin_url: e.jellyfin_url || null,
      is_played: e.is_played ?? !1,
      is_favorite: e.is_favorite ?? !1,
      runtime_minutes: e.runtime_minutes || null,
      dynamic_range: e.dynamic_range || null,
      video_range: e.video_range || null,
      video_range_type: e.video_range_type || null,
      video_codec: e.video_codec || null,
      dv_profile: e.dv_profile || null,
      path: e.path || null,
      filepath: e.filepath || e.path || null,
      config_entry_id: e.config_entry_id || e.entry_id || null,
      action_type: t
    };
    if (we(this, "jellyha_item_clicked", s), !i) {
      console.warn('JellyHA: "call-service" action selected but no action/service configured.'), we(this, "hass-notification", {
        message: 'No script configured for "Run Script" action. Please select a script in the card editor.'
      });
      return;
    }
    const a = i.trim().split("."), r = a[0], n = a.slice(1).join(".");
    if (!r || !n) {
      console.error(`JellyHA: Invalid service name "${i}". Expected format: domain.service (e.g. script.my_script)`), we(this, "hass-notification", {
        message: `Invalid script/service name: "${i}". Expected format: script.your_script_name`
      });
      return;
    }
    try {
      await this.hass.callService(r, n, s);
    } catch (c) {
      console.error(`JellyHA: Failed to call service ${i}`, c), we(this, "hass-notification", {
        message: `Failed to call ${i}: ${c?.message || c}`
      });
    }
  }
  async _castMedia(e, t) {
    const i = this._config.default_cast_device;
    if (!i) {
      console.warn("JellyHA: No default cast device configured");
      return;
    }
    let o = this._config.subtitle_mode || "auto", s = this._config.subtitle_language;
    t === "click" ? (this._config.click_subtitle_mode && (o = this._config.click_subtitle_mode), this._config.click_subtitle_language && (s = this._config.click_subtitle_language)) : t === "hold" ? (this._config.hold_subtitle_mode && (o = this._config.hold_subtitle_mode), this._config.hold_subtitle_language && (s = this._config.hold_subtitle_language)) : t === "double_tap" && (this._config.double_tap_subtitle_mode && (o = this._config.double_tap_subtitle_mode), this._config.double_tap_subtitle_language && (s = this._config.double_tap_subtitle_language));
    try {
      await this.hass.callService("jellyha", "play_on_chromecast", {
        entity_id: i,
        item_id: e.id,
        server_entity_id: this._config.entity,
        ...e.config_entry_id ? { config_entry_id: e.config_entry_id } : {},
        subtitle_mode: o,
        ...s ? { subtitle_language: s } : {}
      });
    } catch (a) {
      console.error("JellyHA: Failed to cast media", a);
    }
  }
  async _playOnClient(e, t) {
    const i = this._config.default_client_device;
    if (!i) {
      console.warn("JellyHA: No default Jellyfin client device configured"), we(this, "hass-notification", {
        message: "No Jellyfin client device configured. Please select a client in the card editor."
      });
      return;
    }
    try {
      await this.hass.callService("jellyha", "session_play", {
        entity_id: i,
        item_id: e.id,
        server_entity_id: this._config.entity,
        ...e.config_entry_id ? { config_entry_id: e.config_entry_id } : {}
      });
    } catch (o) {
      console.error("JellyHA: Failed to play on Jellyfin client", o);
    }
  }
  _openExternalUrl(e, t) {
    let i = e;
    if (!i && t?.id) {
      const a = this.hass?.states[this._config?.entity], r = a?.attributes?.config_external_url || a?.attributes?.server_url;
      r && r.trim() !== "" && (i = `${r.replace(/\/$/, "")}/web/index.html#!/details?id=${t.id}`);
    }
    if (!i) return;
    try {
      const a = new URL(i);
      if (a.hostname.includes("youtube.com") || a.hostname.includes("youtu.be") || a.hostname.includes("vimeo.com")) {
        ae(i, "_blank");
        return;
      }
    } catch {
    }
    const s = this.hass?.states[this._config?.entity]?.attributes?.config_external_url;
    if (s && s.trim() !== "")
      try {
        const a = new URL(i), r = new URL(s);
        a.protocol = r.protocol, a.host = r.host, a.port = r.port || "";
        const n = r.pathname === "/" ? "" : r.pathname;
        n && !a.pathname.startsWith(n) && (a.pathname = n + a.pathname), ae(a.toString(), "_blank");
        return;
      } catch (a) {
        console.warn("JellyHA: Failed to parse URLs to inject external URL override, falling back to original", a);
      }
    ae(i, "_blank");
  }
  /**
   * Render empty state
   */
  _renderEmpty() {
    return l`
      <div class="empty">
        <ha-icon icon="mdi:movie-open-outline"></ha-icon>
        <p>${d(this.hass.locale?.language || this.hass.language, "no_media")}</p>
      </div>
    `;
  }
  /**
   * Render error state
   */
  _renderError(e) {
    return l`
      <ha-card>
        <div class="error">
          <ha-icon icon="mdi:alert-circle"></ha-icon>
          <p>${e}</p>
        </div>
      </ha-card>
    `;
  }
  _getEffectivePlayTargets() {
    if (this._config.enable_custom_play_actions)
      return this._config.modal_play_actions || [];
    const e = [];
    if (this._config.default_cast_device && e.push({
      type: "cast",
      name: "Cast to Chromecast",
      device: this._config.default_cast_device,
      icon: "mdi:cast"
    }), this._config.default_client_device) {
      const t = this.hass?.locale?.language || this.hass?.language || "en";
      e.push({
        type: "client",
        name: d(t, "editor.action_play_client") || "Play on Jellyfin Client",
        device: this._config.default_client_device,
        icon: "mdi:television-play"
      });
    }
    if (this._config.enable_browser_player !== !1) {
      const t = this.hass?.locale?.language || this.hass?.language || "en";
      e.push({
        type: "browser",
        name: d(t, "modal.play_in_browser") || "Play in Browser",
        icon: "mdi:monitor"
      });
    }
    if (this._config.modal_service)
      e.push({
        type: "script",
        name: $e(this.hass, this._config.modal_service),
        service: this._config.modal_service,
        service_data: this._config.modal_service_data,
        icon: "mdi:play"
      });
    else {
      if (this._config.click_action === "call-service" && (this._config.click_service || this._config.service)) {
        const t = this._config.click_service || this._config.service;
        e.push({
          type: "script",
          name: $e(this.hass, t),
          service: t,
          service_data: this._config.click_service_data || this._config.service_data,
          icon: "mdi:play"
        });
      }
      this._config.hold_action === "call-service" && this._config.hold_service && (e.some((t) => t.type === "script" && t.service === this._config.hold_service) || e.push({
        type: "script",
        name: $e(this.hass, this._config.hold_service),
        service: this._config.hold_service,
        service_data: this._config.hold_service_data,
        icon: "mdi:play"
      })), this._config.double_tap_action === "call-service" && this._config.double_tap_service && (e.some((t) => t.type === "script" && t.service === this._config.double_tap_service) || e.push({
        type: "script",
        name: $e(this.hass, this._config.double_tap_service),
        service: this._config.double_tap_service,
        service_data: this._config.double_tap_service_data,
        icon: "mdi:play"
      }));
    }
    return e;
  }
  _showItemDetails(e) {
    if (this._modal) {
      let t = this._config.subtitle_mode || "auto", i = this._config.subtitle_language;
      this._config.click_subtitle_mode && (t = this._config.click_subtitle_mode), this._config.click_subtitle_language && (i = this._config.click_subtitle_language), this._modal.showDialog({
        item: e,
        hass: this.hass,
        defaultCastDevice: this._config.default_cast_device,
        defaultClientDevice: this._config.default_client_device,
        serverEntityId: this._config.entity,
        subtitleMode: t,
        subtitleLanguage: i,
        playTargets: this._getEffectivePlayTargets(),
        showEntityName: this._config.show_entity_name ?? this._config.show_modal_entity_name
      });
    }
  }
  _handleSearchInput(e) {
    const t = e.target;
    this._searchQuery = t.value, this._currentPage = 0;
  }
  _handleGenreChange(e) {
    const t = e.target;
    this._searchGenre = t.value, this._currentPage = 0;
  }
  _renderSearchBar(e) {
    const t = /* @__PURE__ */ new Set();
    (this._items || []).forEach((s) => {
      s.genres && s.genres.forEach((a) => t.add(a));
    });
    const i = Array.from(t).sort(), o = this.hass.locale?.language || this.hass.language;
    return l`
      <div class="search-container">
        <div class="search-input-wrapper">
          <ha-icon icon="mdi:magnify" class="search-icon"></ha-icon>
          <input 
            type="text" 
            class="search-input" 
            placeholder="${d(o, "search.placeholder_title")}"
            .value="${this._searchQuery}"
            @input="${this._handleSearchInput}"
          />
          ${this._searchQuery ? l`
            <button class="clear-search" @click="${() => {
      this._searchQuery = "", this._currentPage = 0;
    }}">
              <ha-icon icon="mdi:close"></ha-icon>
            </button>
          ` : h}
        </div>
        
        <div class="search-select-wrapper">
          <select class="search-select" @change="${this._handleGenreChange}" .value="${this._searchGenre}">
             <option value="">${d(o, "search.all_genres")}</option>
             ${i.map((s) => l`
               <option value="${s}">${s}</option>
             `)}
          </select>
          <ha-icon icon="mdi:chevron-down" class="select-icon"></ha-icon>
        </div>
      </div>
    `;
  }
};
I.styles = Vt;
z([
  V({ attribute: !1 })
], I.prototype, "hass", 2);
z([
  f()
], I.prototype, "_config", 2);
z([
  f()
], I.prototype, "_currentPage", 2);
z([
  f()
], I.prototype, "_itemsPerPage", 2);
z([
  f()
], I.prototype, "_pressStartTime", 2);
z([
  f()
], I.prototype, "_holdTimer", 2);
z([
  f()
], I.prototype, "_isHoldActive", 2);
z([
  f()
], I.prototype, "_rewindActive", 2);
z([
  f()
], I.prototype, "_items", 2);
z([
  f()
], I.prototype, "_error", 2);
z([
  f()
], I.prototype, "_lastUpdate", 2);
z([
  f()
], I.prototype, "_mostRecentNextUpItemId", 2);
z([
  f()
], I.prototype, "_searchQuery", 2);
z([
  f()
], I.prototype, "_searchGenre", 2);
z([
  wi("jellyha-item-details-modal")
], I.prototype, "_modal", 2);
z([
  f()
], I.prototype, "_effectiveListColumns", 2);
z([
  f()
], I.prototype, "_isFeaturedCramped", 2);
z([
  f()
], I.prototype, "_scrollProgress", 2);
z([
  f()
], I.prototype, "_hasScrollableContent", 2);
I = z([
  ge("jellyha-library-card")
], I);
var qi = Object.defineProperty, Vi = Object.getOwnPropertyDescriptor, yt = (e, t, i, o) => {
  for (var s = o > 1 ? void 0 : o ? Vi(t, i) : t, a = e.length - 1, r; a >= 0; a--)
    (r = e[a]) && (s = (o ? r(t, i, s) : r(s)) || s);
  return o && s && qi(t, i, s), s;
};
function Wi(e, t, i) {
  const o = new CustomEvent(t, {
    bubbles: !0,
    composed: !0,
    detail: i
  });
  e.dispatchEvent(o);
}
let Oe = class extends X {
  setConfig(e) {
    this._config = e;
  }
  render() {
    if (!this.hass || !this._config)
      return l``;
    const e = (n, c) => {
      const p = String(this.hass.states[n]?.attributes?.friendly_name || n), u = String(this.hass.states[c]?.attributes?.friendly_name || c);
      return p.localeCompare(u);
    }, t = Object.keys(this.hass.states).filter(
      (n) => n.startsWith("media_player.jellyha_") && !n.includes("_library_browser") && !n.endsWith("_browser")
    ).sort(e), i = Object.keys(this.hass.states).filter(
      (n) => n.startsWith("media_player.") && !n.startsWith("media_player.jellyha_") && !n.includes("_library_browser") && !n.endsWith("_browser")
    ).sort(e), o = Object.keys(this.hass.states).filter(
      (n) => n.startsWith("sensor.jellyha_") && n.includes("now_playing")
    ).sort(e), s = [
      ...t.map((n) => ({
        entity: n,
        label: `${this.hass.states[n]?.attributes?.friendly_name || n} (JellyHA)`
      })),
      ...i.map((n) => ({
        entity: n,
        label: `${this.hass.states[n]?.attributes?.friendly_name || n} (Media Player)`
      })),
      ...o.map((n) => ({
        entity: n,
        label: `${this.hass.states[n]?.attributes?.friendly_name || n} (Legacy Sensor)`
      }))
    ];
    this._config.entity && !s.some((n) => n.entity === this._config.entity) && s.unshift({
      entity: this._config.entity,
      label: String(this.hass.states[this._config.entity]?.attributes?.friendly_name || this._config.entity)
    });
    const a = this.hass.locale?.language || this.hass.language, r = d(a, "editor.media_player") || "Media Player";
    return l`
      <div class="card-config">
        <div class="form-row">
          <ha-selector
            .hass=${this.hass}
            .selector=${{
      select: {
        mode: "dropdown",
        custom_value: !0,
        options: s.map((n) => ({
          value: n.entity,
          label: n.label
        }))
      }
    }}
            .value=${this._config.entity || ""}
            .label=${r}
            label="${r}"
            @value-changed=${this._entityChanged}
          ></ha-selector>
        </div>

        <div class="form-row">
          <ha-selector
            .hass=${this.hass}
            .selector=${{ text: {} }}
            .value=${this._config.title || ""}
            .label="${d(a, "editor.title")} (Optional)"
            label="${d(a, "editor.title")} (Optional)"
            @value-changed=${this._titleChanged}
          ></ha-selector>
        </div>

        <div class="checkbox-pair">
          <div class="checkbox-row">
            <ha-switch
              .checked=${this._config.show_title !== !1}
              @change=${this._showTitleChanged}
            ></ha-switch>
            <span>${d(a, "editor.show_title")}</span>
          </div>
          <div class="checkbox-row">
            <ha-switch
              .checked=${this._config.show_subtitle !== !1}
              @change=${this._showSubtitleChanged}
            ></ha-switch>
            <span>${d(a, "editor.show_subtitle")}</span>
          </div>
        </div>

        <div class="checkbox-row">
          <ha-switch
            .checked=${this._config.show_media_type_badge !== !1}
            @change=${this._showMediaTypeBadgeChanged}
          ></ha-switch>
          <span>${d(a, "editor.show_media_type_badge")}</span>
        </div>

        ${this._config.show_media_type_badge !== !1 ? l`
          <div class="form-row" style="margin-left: 16px; margin-top: 4px; margin-bottom: 12px;">
            <ha-selector
              .hass=${this.hass}
              .selector=${{
      select: {
        mode: "dropdown",
        options: [
          { value: "poster", label: d(a, "editor.badge_style_poster") },
          { value: "header", label: d(a, "editor.badge_style_header") },
          { value: "inline", label: d(a, "editor.badge_style_inline") },
          { value: "none", label: d(a, "editor.badge_style_none") }
        ]
      }
    }}
              .value=${this._config.badge_style || this._config.media_type_badge_style || "poster"}
              .label="${d(a, "editor.badge_style")}"
              label="${d(a, "editor.badge_style")}"
              @value-changed=${this._badgeStyleChanged}
            ></ha-selector>
          </div>
        ` : ""}

        <div class="checkbox-pair">
          <div class="checkbox-row">
            <ha-switch
              .checked=${this._config.show_year !== !1}
              @change=${this._showYearChanged}
            ></ha-switch>
            <span>${d(a, "editor.show_year")}</span>
          </div>
          <div class="checkbox-row">
            <ha-switch
              .checked=${this._config.show_genres !== !1}
              @change=${this._showGenresChanged}
            ></ha-switch>
            <span>${d(a, "editor.show_genres")}</span>
          </div>
        </div>

        <div class="checkbox-pair">
          <div class="checkbox-row">
            <ha-switch
              .checked=${this._config.show_runtime !== !1}
              @change=${this._showRuntimeChanged}
            ></ha-switch>
            <span>${d(a, "editor.show_runtime")}</span>
          </div>
          <div class="checkbox-row">
            <ha-switch
              .checked=${this._config.show_ratings !== !1}
              @change=${this._showRatingsChanged}
            ></ha-switch>
            <span>${d(a, "editor.show_rating")}</span>
          </div>
        </div>

        <div class="checkbox-row">
          <ha-switch
            .checked=${this._config.show_description !== !1}
            @change=${this._showDescriptionChanged}
          ></ha-switch>
          <span>${d(a, "editor.show_description") || "Show Description"}</span>
        </div>

        <div class="checkbox-pair">
          <div class="checkbox-row">
            <ha-switch
              .checked=${this._config.show_user !== !1}
              @change=${this._showUserChanged}
            ></ha-switch>
            <span>${d(a, "editor.show_user")}</span>
          </div>
          <div class="checkbox-row">
            <ha-switch
              .checked=${this._config.show_client !== !1}
              @change=${this._showClientChanged}
            ></ha-switch>
            <span>${d(a, "editor.show_client")}</span>
          </div>
          <div class="checkbox-row">
            <ha-switch
              .checked=${this._config.show_device_name === !0}
              @change=${this._showDeviceNameChanged}
            ></ha-switch>
            <span>${d(a, "editor.show_device_name")}</span>
          </div>
        </div>

        <div class="checkbox-row">
          <ha-switch
            .checked=${this._config.show_time === !0}
            @change=${this._showTimeChanged}
          ></ha-switch>
          <span>${d(a, "editor.show_time")}</span>
        </div>

        <div class="checkbox-row">
          <ha-switch
            .checked=${this._config.show_background !== !1}
            @change=${this._showBackgroundChanged}
          ></ha-switch>
          <span>${d(a, "editor.show_background")}</span>
        </div>

        <div class="checkbox-row">
          <ha-switch
            .checked=${this._config.use_series_image === !0}
            @change=${this._useSeriesImageChanged}
          ></ha-switch>
          <span>${d(a, "editor.use_series_image")}</span>
        </div>

        <div class="checkbox-row">
          <ha-switch
            .checked=${this._config.show_controls !== !1}
            @change=${this._showControlsChanged}
          ></ha-switch>
          <span>${d(a, "editor.show_controls") || "Show Playback Controls"}</span>
        </div>

        <div class="form-row" style="margin-top: 10px;">
          <ha-selector
            .hass=${this.hass}
            .selector=${{
      select: {
        mode: "dropdown",
        options: [
          { value: "card", label: d(a, "editor.playing_display_mode_card") || "Card Layout (Poster + Details)" },
          { value: "full_art", label: d(a, "editor.playing_display_mode_full_art") || "Full Artwork (Cinematic Hero)" }
        ]
      }
    }}
            .value=${this._config.playing_display_mode || "card"}
            .label="${d(a, "editor.playing_display_mode") || "Playback Display Style"}"
            label="${d(a, "editor.playing_display_mode") || "Playback Display Style"}"
            @value-changed=${this._playingDisplayModeChanged}
          ></ha-selector>
        </div>

        ${this._config.playing_display_mode === "full_art" ? l`
          <div class="form-row" style="margin-left: 16px; margin-top: 10px;">
            <ha-selector
              .hass=${this.hass}
              .selector=${{
      select: {
        mode: "dropdown",
        options: [
          { value: "backdrop", label: d(a, "editor.playing_artwork_source_backdrop") || "Fanart Backdrop" },
          { value: "poster", label: d(a, "editor.playing_artwork_source_poster") || "Poster" }
        ]
      }
    }}
              .value=${this._config.playing_artwork_source || "backdrop"}
              .label="${d(a, "editor.playing_artwork_source") || "Playback Artwork Image"}"
              label="${d(a, "editor.playing_artwork_source") || "Playback Artwork Image"}"
              @value-changed=${this._playingArtworkSourceChanged}
            ></ha-selector>
          </div>
        ` : ""}

        <div style="height: 1px; background: var(--divider-color, rgba(127,127,127,0.2)); margin: 16px 0 12px 0;"></div>
        <div style="font-weight: 500; font-size: 0.95rem; margin-bottom: 12px; color: var(--primary-text-color);">
          ${d(a, "editor.power_section_title") || "TV / Display Power"}
        </div>

        <div class="form-row">
          <ha-selector
            .hass=${this.hass}
            .selector=${{
      entity: {
        domain: ["media_player", "switch", "script", "button", "scene", "input_boolean"]
      }
    }}
            .value=${this._config.power_entity || ""}
            .label="${d(a, "editor.power_entity") || "Power Entity (TV, Switch, Script, etc.)"}"
            label="${d(a, "editor.power_entity") || "Power Entity (TV, Switch, Script, etc.)"}"
            .helper="${d(a, "editor.power_entity_helper") || "Optional. If not set, the default selected Media Player will be used."}"
            helper="${d(a, "editor.power_entity_helper") || "Optional. If not set, the default selected Media Player will be used."}"
            .placeholder=${this._defaultEntityPlaceholder}
            placeholder=${this._defaultEntityPlaceholder}
            .required=${!1}
            @value-changed=${this._powerEntityChanged}
          ></ha-selector>
        </div>

        <div class="form-row">
          <ha-selector
            .hass=${this.hass}
            .selector=${{
      entity: {}
    }}
            .value=${this._config.power_state_entity || ""}
            .label="${d(a, "editor.power_state_entity") || "Power State Entity (Optional state sensor)"}"
            label="${d(a, "editor.power_state_entity") || "Power State Entity (Optional state sensor)"}"
            .required=${!1}
            @value-changed=${this._powerStateEntityChanged}
          ></ha-selector>
        </div>

        <div class="checkbox-pair">
          <div class="checkbox-row">
            <ha-switch
              .checked=${this._config.show_power_button !== !1 && this._config.show_power !== !1}
              @change=${this._showPowerButtonChanged}
            ></ha-switch>
            <span>${d(a, "editor.show_power_button") || "Show Power Button"}</span>
          </div>
          <div class="checkbox-row">
            <ha-switch
              .checked=${this._config.stop_on_power_off !== !1}
              @change=${this._stopOnPowerOffChanged}
            ></ha-switch>
            <span>${d(a, "editor.stop_on_power_off") || "Stop Media on Power Off"}</span>
          </div>
        </div>

        <div style="height: 1px; background: var(--divider-color, rgba(127,127,127,0.2)); margin: 16px 0 12px 0;"></div>
        <div style="font-weight: 500; font-size: 0.95rem; margin-bottom: 12px; color: var(--primary-text-color);">
          ${d(a, "editor.volume_section_title") || "Volume Controls"}
        </div>

        <div class="checkbox-pair">
          <div class="checkbox-row">
            <ha-switch
              .checked=${this._config.show_volume === !0 || this._config.show_volume !== !1 && !!this._config.volume_entity}
              @change=${this._showVolumeChanged}
            ></ha-switch>
            <span>${d(a, "editor.show_volume") || "Show Volume Controls"}</span>
          </div>

          <div class="checkbox-row">
            <ha-switch
              .checked=${this._config.show_volume_step_buttons !== !1}
              @change=${this._showVolumeStepButtonsChanged}
            ></ha-switch>
            <span>${d(a, "editor.show_volume_step_buttons") || "Show Step Buttons (− / +)"}</span>
          </div>
        </div>

        <div class="form-row" style="margin-top: 10px;">
          <ha-selector
            .hass=${this.hass}
            .selector=${{
      entity: {
        domain: "media_player"
      }
    }}
            .value=${this._config.volume_entity || ""}
            .label="${d(a, "editor.volume_entity") || "Volume Entity (External AVR/Soundbar, Optional)"}"
            label="${d(a, "editor.volume_entity") || "Volume Entity (External AVR/Soundbar, Optional)"}"
            .helper="${d(a, "editor.volume_entity_helper") || "Optional. If not set, the default selected Media Player will be used."}"
            helper="${d(a, "editor.volume_entity_helper") || "Optional. If not set, the default selected Media Player will be used."}"
            .placeholder=${this._defaultEntityPlaceholder}
            placeholder=${this._defaultEntityPlaceholder}
            .required=${!1}
            @value-changed=${this._volumeEntityChanged}
          ></ha-selector>
        </div>

        <div class="form-row" style="margin-top: 10px;">
          <ha-selector
            .hass=${this.hass}
            .selector=${{
      number: {
        min: 1,
        max: 20,
        step: 1,
        mode: "box"
      }
    }}
            .value=${this._config.volume_step ?? 5}
            .label="${d(a, "editor.volume_step") || "Volume Step %"}"
            label="${d(a, "editor.volume_step") || "Volume Step %"}"
            @value-changed=${this._volumeStepChanged}
          ></ha-selector>
        </div>

        <div style="height: 1px; background: var(--divider-color, rgba(127,127,127,0.2)); margin: 16px 0 12px 0;"></div>
        <div style="font-weight: 500; font-size: 0.95rem; margin-bottom: 12px; color: var(--primary-text-color);">
          ${d(a, "editor.idle_section_title") || "Ambient Showcase (When Idle)"}
        </div>

        <div class="checkbox-row">
          <ha-switch
            .checked=${this._config.idle_backdrop_cycle === !0}
            @change=${this._idleBackdropCycleChanged}
          ></ha-switch>
          <span>${d(a, "editor.idle_backdrop_cycle") || "Cycle Library Media when Idle"}</span>
        </div>

        ${this._config.idle_backdrop_cycle === !0 ? l`
          <div class="form-row" style="margin-left: 16px; margin-top: 10px;">
            <ha-selector
              .hass=${this.hass}
              .selector=${{
      select: {
        mode: "dropdown",
        options: [
          { value: "random", label: d(a, "editor.idle_source_random") || "Random Library Media" },
          { value: "movies", label: d(a, "editor.media_type_movies") || "Movies Only" },
          { value: "series", label: d(a, "editor.media_type_series") || "TV Shows Only" },
          { value: "recent", label: d(a, "editor.idle_source_recent") || "Recently Added" },
          { value: "latest_movie", label: d(a, "editor.idle_source_latest_movie") || "Latest Movie Added" },
          { value: "latest_episode", label: d(a, "editor.idle_source_latest_episode") || "Latest Episode Added" },
          { value: "latest_both", label: d(a, "editor.idle_source_latest_both") || "Alternating Latest Movie & Episode" }
        ]
      }
    }}
              .value=${this._config.idle_content_source === "movies" || !this._config.idle_content_source && this._config.idle_media_type === "movies" ? "movies" : this._config.idle_content_source === "series" || !this._config.idle_content_source && this._config.idle_media_type === "series" ? "series" : this._config.idle_content_source || "random"}
              .label="${d(a, "editor.idle_content_source") || "Content to Showcase"}"
              label="${d(a, "editor.idle_content_source") || "Content to Showcase"}"
              @value-changed=${this._idleContentSourceChanged}
            ></ha-selector>
          </div>

          ${this._config.idle_content_source === "recent" ? l`
            <div class="form-row" style="margin-left: 16px; margin-top: 10px;">
              <ha-selector
                .hass=${this.hass}
                .selector=${{
      number: {
        min: 1,
        max: 50,
        step: 1,
        mode: "box"
      }
    }}
                .value=${this._config.idle_recent_limit || 15}
                .label="${d(a, "editor.idle_recent_limit") || "Number of Recent Items"}"
                label="${d(a, "editor.idle_recent_limit") || "Number of Recent Items"}"
                @value-changed=${this._idleRecentLimitChanged}
              ></ha-selector>
            </div>
          ` : ""}

          <div class="form-row" style="margin-left: 16px; margin-top: 10px;">
            <ha-selector
              .hass=${this.hass}
              .selector=${{
      select: {
        mode: "dropdown",
        options: [
          { value: "backdrop", label: d(a, "editor.idle_display_mode_backdrop") || "Full Fanart Backdrop (Screensaver)" },
          { value: "card", label: d(a, "editor.idle_display_mode_card") || "Card Layout (Poster + Backdrop)" }
        ]
      }
    }}
              .value=${this._config.idle_display_mode || "backdrop"}
              .label="${d(a, "editor.idle_display_mode") || "Display Style"}"
              label="${d(a, "editor.idle_display_mode") || "Display Style"}"
              @value-changed=${this._idleDisplayModeChanged}
            ></ha-selector>
          </div>

          ${this._config.idle_content_source === "recent" ? l`
            <div class="form-row" style="margin-left: 16px; margin-top: 10px;">
              <ha-selector
                .hass=${this.hass}
                .selector=${{
      select: {
        mode: "dropdown",
        options: [
          { value: "both", label: d(a, "editor.media_type_both") || "Movies & TV Shows" },
          { value: "movies_episodes", label: d(a, "editor.media_type_movies_episodes") || "Movies & Episodes" },
          { value: "movies", label: d(a, "editor.media_type_movies") || "Movies Only" },
          { value: "series", label: d(a, "editor.media_type_series") || "TV Shows Only" },
          { value: "episodes", label: d(a, "editor.media_type_episodes") || "Episodes Only" }
        ]
      }
    }}
                .value=${this._config.idle_media_type || "both"}
                .label="${d(a, "editor.idle_media_type") || "Media Types to Showcase"}"
                label="${d(a, "editor.idle_media_type") || "Media Types to Showcase"}"
                @value-changed=${this._idleMediaTypeChanged}
              ></ha-selector>
            </div>
          ` : ""}

          ${this._config.idle_content_source !== "latest_movie" && this._config.idle_content_source !== "latest_episode" ? l`
            <div class="form-row" style="margin-left: 16px; margin-top: 10px;">
              <ha-selector
                .hass=${this.hass}
                .selector=${{
      number: {
        min: 5,
        max: 120,
        step: 5,
        mode: "box"
      }
    }}
                .value=${this._config.idle_cycle_interval || 20}
                .label="${d(a, "editor.idle_cycle_interval") || "Cycle Interval (seconds)"}"
                label="${d(a, "editor.idle_cycle_interval") || "Cycle Interval (seconds)"}"
                @value-changed=${this._idleCycleIntervalChanged}
              ></ha-selector>
            </div>
          ` : ""}
        ` : ""}
      </div>
    `;
  }
  _idleBackdropCycleChanged(e) {
    const t = e.target;
    this._updateConfig("idle_backdrop_cycle", t.checked);
  }
  _idleContentSourceChanged(e) {
    const t = e.detail && "value" in e.detail ? e.detail.value : e.target?.value;
    t !== void 0 && (t === "movies" ? (this._updateConfig("idle_content_source", "movies"), this._updateConfig("idle_media_type", "movies")) : t === "series" ? (this._updateConfig("idle_content_source", "series"), this._updateConfig("idle_media_type", "series")) : t === "random" ? (this._updateConfig("idle_content_source", "random"), this._updateConfig("idle_media_type", "both")) : this._updateConfig("idle_content_source", t));
  }
  _idleRecentLimitChanged(e) {
    const t = e.detail && "value" in e.detail ? e.detail.value : e.target?.value, i = t !== void 0 ? Number(t) : NaN;
    isNaN(i) || this._updateConfig("idle_recent_limit", i);
  }
  _idleDisplayModeChanged(e) {
    const t = e.detail && "value" in e.detail ? e.detail.value : e.target?.value;
    t !== void 0 && this._updateConfig("idle_display_mode", t);
  }
  _playingDisplayModeChanged(e) {
    const t = e.detail && "value" in e.detail ? e.detail.value : e.target?.value;
    t !== void 0 && this._updateConfig("playing_display_mode", t);
  }
  _playingArtworkSourceChanged(e) {
    const t = e.detail && "value" in e.detail ? e.detail.value : e.target?.value;
    t !== void 0 && this._updateConfig("playing_artwork_source", t);
  }
  _idleMediaTypeChanged(e) {
    const t = e.detail && "value" in e.detail ? e.detail.value : e.target?.value;
    t !== void 0 && this._updateConfig("idle_media_type", t);
  }
  _idleCycleIntervalChanged(e) {
    const t = e.detail && "value" in e.detail ? e.detail.value : e.target?.value, i = t !== void 0 ? Number(t) : NaN;
    isNaN(i) || this._updateConfig("idle_cycle_interval", i);
  }
  _showControlsChanged(e) {
    const t = e.target;
    this._updateConfig("show_controls", t.checked);
  }
  _powerEntityChanged(e) {
    const t = e.detail && "value" in e.detail ? e.detail.value : e.target?.value;
    this._updateConfig("power_entity", t || void 0);
  }
  _powerStateEntityChanged(e) {
    const t = e.detail && "value" in e.detail ? e.detail.value : e.target?.value;
    this._updateConfig("power_state_entity", t || void 0);
  }
  _showPowerButtonChanged(e) {
    const t = e.target;
    this._updateConfig("show_power_button", t.checked);
  }
  _stopOnPowerOffChanged(e) {
    const t = e.target;
    this._updateConfig("stop_on_power_off", t.checked);
  }
  _showVolumeChanged(e) {
    const t = e.target;
    this._updateConfig("show_volume", t.checked);
  }
  _volumeEntityChanged(e) {
    const t = e.detail && "value" in e.detail ? e.detail.value : e.target?.value;
    this._updateConfig("volume_entity", t || void 0);
  }
  _showVolumeStepButtonsChanged(e) {
    const t = e.target;
    this._updateConfig("show_volume_step_buttons", t.checked);
  }
  _volumeStepChanged(e) {
    const t = e.detail && "value" in e.detail ? e.detail.value : e.target?.value, i = t !== void 0 ? Number(t) : NaN;
    isNaN(i) || this._updateConfig("volume_step", i);
  }
  _entityChanged(e) {
    const t = e.detail && "value" in e.detail ? e.detail.value : e.target?.value;
    t !== void 0 && this._updateConfig("entity", t);
  }
  _titleChanged(e) {
    const t = e.detail && "value" in e.detail ? e.detail.value : e.target?.value;
    this._updateConfig("title", t || void 0);
  }
  _showTitleChanged(e) {
    const t = e.target;
    this._updateConfig("show_title", t.checked);
  }
  _showSubtitleChanged(e) {
    const t = e.target;
    this._updateConfig("show_subtitle", t.checked);
  }
  _showMediaTypeBadgeChanged(e) {
    const t = e.target;
    this._updateConfig("show_media_type_badge", t.checked);
  }
  _badgeStyleChanged(e) {
    const t = e.detail && "value" in e.detail ? e.detail.value : e.target?.value;
    t !== void 0 && this._updateConfig("badge_style", t);
  }
  _showYearChanged(e) {
    const t = e.target;
    this._updateConfig("show_year", t.checked);
  }
  _showGenresChanged(e) {
    const t = e.target;
    this._updateConfig("show_genres", t.checked);
  }
  _showRatingsChanged(e) {
    const t = e.target;
    this._updateConfig("show_ratings", t.checked);
  }
  _showRuntimeChanged(e) {
    const t = e.target;
    this._updateConfig("show_runtime", t.checked);
  }
  _showDescriptionChanged(e) {
    const t = e.target;
    this._updateConfig("show_description", t.checked);
  }
  _showUserChanged(e) {
    const t = e.target;
    this._updateConfig("show_user", t.checked);
  }
  _showClientChanged(e) {
    const t = e.target;
    this._updateConfig("show_client", t.checked);
  }
  _showDeviceNameChanged(e) {
    const t = e.target;
    this._updateConfig("show_device_name", t.checked);
  }
  _showTimeChanged(e) {
    const t = e.target;
    this._updateConfig("show_time", t.checked);
  }
  _showBackgroundChanged(e) {
    const t = e.target;
    this._updateConfig("show_background", t.checked);
  }
  _useSeriesImageChanged(e) {
    const t = e.target;
    this._updateConfig("use_series_image", t.checked);
  }
  get _defaultEntityPlaceholder() {
    const e = this._config?.entity;
    return e && !e.startsWith("sensor.") && !e.startsWith("binary_sensor.") ? `Default: ${e}` : "";
  }
  _updateConfig(e, t) {
    if (!this._config)
      return;
    const i = { ...this._config };
    t === void 0 || t === "" ? delete i[e] : i[e] = t, this._config = i, Wi(this, "config-changed", { config: i });
  }
};
Oe.styles = Pe`
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
yt([
  V({ attribute: !1 })
], Oe.prototype, "hass", 2);
yt([
  f()
], Oe.prototype, "_config", 2);
Oe = yt([
  ge("jellyha-now-playing-editor")
], Oe);
var Ji = Object.defineProperty, Yi = Object.getOwnPropertyDescriptor, M = (e, t, i, o) => {
  for (var s = o > 1 ? void 0 : o ? Yi(t, i) : t, a = e.length - 1, r; a >= 0; a--)
    (r = e[a]) && (s = (o ? r(t, i, s) : r(s)) || s);
  return o && s && Ji(t, i, s), s;
};
typeof window < "u" && (window.customCards = window.customCards || [], window.customCards.some((e) => e.type === "jellyha-now-playing-card") || window.customCards.push({
  type: "jellyha-now-playing-card",
  name: "JellyHA Now Playing",
  description: "Display currently playing media from Jellyfin",
  preview: !0
}));
let E = class extends X {
  constructor() {
    super(...arguments), this._rewindActive = !1, this._overflowState = 0, this._dominantColor = "var(--primary-color)", this._longPressProgress = 0, this._stopPulse = !1, this._isDragging = !1, this._dragPercentage = 0, this._optimisticSeekPercent = null, this._isSeeking = !1, this._powerActivating = !1, this._isVolumeDragging = !1, this._dragVolumePercent = null, this._optimisticVolume = {}, this._idleItems = [], this._currentIdleIndex = 0, this._prevIdleIndex = null, this._idleFadeOut = !1, this._lastHapticVolumeTick = 0, this._fetchingIdleItems = !1, this._longPressRaf = null, this._longPressConsumed = !1, this._layoutCheckRaf = null, this._optimisticFavorites = {}, this._resolvedImages = {}, this._fetchingImageKey = null, this._resolvedMetadata = {}, this._fetchingMetadataId = null, this._phrases = [];
  }
  setConfig(e) {
    const t = e.show_power_button ?? e.show_power ?? !0, i = e.show_volume ?? !!e.volume_entity;
    this._config = {
      show_title: !0,
      show_subtitle: !0,
      show_media_type_badge: !0,
      badge_style: "poster",
      show_year: !0,
      show_client: !0,
      show_device_name: !1,
      show_user: !0,
      show_time: !1,
      show_background: !0,
      show_genres: !0,
      show_ratings: !0,
      show_runtime: !0,
      use_series_image: !1,
      show_controls: !0,
      idle_backdrop_cycle: !1,
      idle_cycle_interval: 20,
      idle_display_mode: "backdrop",
      idle_media_type: "both",
      stop_on_power_off: !0,
      show_volume_step_buttons: !0,
      volume_step: 5,
      ...e,
      show_power_button: t,
      show_volume: i
    };
  }
  static getConfigElement() {
    return document.createElement("jellyha-now-playing-editor");
  }
  static getStubConfig(e) {
    const t = Object.keys(e.states);
    return {
      entity: t.find((o) => o.startsWith("media_player.jellyha_") && !o.includes("_library_browser") && !o.endsWith("_browser")) || t.find((o) => o.startsWith("sensor.jellyha_now_playing_")) || "",
      show_title: !0,
      show_subtitle: !0,
      show_media_type_badge: !0,
      badge_style: "poster",
      show_year: !0,
      show_client: !0,
      show_device_name: !1,
      show_user: !0,
      show_time: !1,
      show_background: !0,
      show_genres: !0,
      show_ratings: !0,
      show_runtime: !0,
      use_series_image: !1,
      show_controls: !0,
      idle_backdrop_cycle: !1,
      idle_cycle_interval: 20,
      idle_display_mode: "backdrop",
      idle_media_type: "both"
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
      min_rows: 2
    };
  }
  render() {
    if (!this.hass || !this._config)
      return l``;
    const e = this._config.entity;
    if (!e)
      return this._renderError("Please configure a JellyHA Now Playing entity");
    const t = this.hass.states[e];
    if (!t)
      return this._renderError(d(this.hass.locale?.language || this.hass.language, "entity_not_found") || "Entity not found");
    const i = e.startsWith("media_player."), o = t.attributes, s = i && (t.state === "playing" || t.state === "paused" || t.state === "buffering") || !!o.item_id;
    if (s && (this._lastActiveStateObj = t), !(s || this._isSeeking && !!this._lastActiveStateObj))
      return this._config.idle_backdrop_cycle ? this._renderIdleShowcase() : (this._stopIdleTimer(), this._renderEmpty());
    this._stopIdleTimer();
    const r = !s && this._isSeeking && this._lastActiveStateObj ? this._lastActiveStateObj : t, n = r.attributes, c = this._extractItemId(r);
    c && !this._resolvedMetadata[c] && (!n.community_rating || !n.year || !n.genres || !n.media_type) && this._fetchMissingMetadata(c);
    const p = c ? this._resolvedMetadata[c] : null, u = this._getDurationSeconds(r), _ = this._getCurrentPositionSeconds(r);
    let g = 0;
    this._optimisticSeekPercent !== null ? g = this._optimisticSeekPercent : u > 0 ? g = Math.min(100, Math.max(0, _ / u * 100)) : typeof n.progress_percent == "number" && (g = n.progress_percent);
    const m = this._isDragging && u > 0 ? this._dragPercentage / 100 * u : this._optimisticSeekPercent !== null && u > 0 ? this._optimisticSeekPercent / 100 * u : _, b = this._isDragging ? this._dragPercentage : g, x = this._isDragging ? 8 : 6, v = `calc(${b}% + (50 - ${b}) * ${x * 2 / 100}px)`, { seriesImageUrl: w, episodeImageUrl: k } = this._resolveImages(r, p), y = this._config.use_series_image && w ? w : k || n.image_url || r.attributes.entity_picture || p?.poster_url, S = y, $ = c || n.item_id || r.attributes.media_content_id, C = `${$}_${this._config.use_series_image ? "series" : "item"}`;
    if (C !== this._cachedItemId) {
      this._cachedItemId = C;
      const Je = n.backdrop_url || p?.backdrop_url || y;
      this._cachedBackdropUrl = Je ? R(Je, 640) : void 0;
    }
    C !== this._cachedColorItemId && S && (this._cachedColorItemId = C, this._extractDominantColor(R(S, 80)));
    const T = this._cachedBackdropUrl, N = this._config.show_background !== !1 && T, G = i ? r.state === "paused" : n.is_paused, P = (n.media_type || (p?.type ? p.type : null) || r.attributes.media_content_type || "").toLowerCase(), D = P === "audio" || P === "music";
    let O = n.title || r.attributes.media_title || p?.name || "";
    const Z = this._config.show_subtitle !== !1, L = n.series_title || r.attributes.media_series_title || p?.series_name || "", oe = Z && (n.artist_name || r.attributes.media_artist || L || p?.artist_name) || "", B = n.year ?? p?.year, U = this._config.show_year !== !1 && B ? String(B) : "", Q = n.season !== void 0 && n.season !== null ? n.season : r.attributes.media_season !== void 0 && r.attributes.media_season !== null ? r.attributes.media_season : p?.season, W = n.episode !== void 0 && n.episode !== null ? n.episode : r.attributes.media_episode !== void 0 && r.attributes.media_episode !== null ? r.attributes.media_episode : p?.episode, me = Number(Q), fe = Number(W), at = Q != null && W != null && !isNaN(me) && !isNaN(fe) && me >= 0 && fe >= 0, se = (P === "episode" || P === "tvshow") && at ? `S${String(me).padStart(2, "0")}E${String(fe).padStart(2, "0")}` : P === "movie" ? "MOVIE" : P === "episode" ? "EPISODE" : P === "tvshow" ? "SERIES" : n.media_type || p?.type || "", de = this._config.badge_style || this._config.media_type_badge_style || "poster", ce = this._config.show_media_type_badge !== !1 && !!se, ee = de === "inline", je = ce && ee && !!se;
    let Fe = !1, Ie = !1;
    ce && de !== "none" && (de === "poster" ? Fe = !0 : de === "header" && (Ie = !0));
    const Be = n.runtime_minutes || (u > 0 ? Math.round(u / 60) : p?.runtime_minutes || 0), He = P === "audio" && u > 0 ? `${Math.floor(u / 60)}m ${Math.floor(u % 60)}s` : Be > 0 ? ue(Be) : "", be = this._config.show_runtime !== !1 && He ? He : "", Ee = n.community_rating ?? p?.community_rating ?? p?.rating, ye = Number(Ee), Te = !isNaN(ye) && ye > 0 ? ye.toFixed(1) : Ee ? String(Ee) : "", re = this._config.show_ratings !== !1 && Te ? Te : "", qe = n.genres && n.genres.length > 0 ? n.genres : p?.genres || [], te = this._config.show_genres !== !1 && qe?.length ? qe.slice(0, 3) : [];
    ee ? je || U || be || re || te.length > 0 : U || te.length > 0;
    const ve = n.user_name || this.hass?.user?.name || "", H = this._config.show_user !== !1 ? ve : "", Yt = n.client || r.attributes.app_name || r.attributes.friendly_name || "", Gt = this._config.show_client !== !1 ? Yt : "", Xt = this._config.show_device_name === !0 && n.device_name || "", Ve = [...new Set([Xt, Gt].filter(Boolean))].join(" · "), We = $ && this._optimisticFavorites[$] !== void 0 ? this._optimisticFavorites[$] : n.is_favorite || p?.is_favorite || !1, st = 125.66, vt = st * (1 - this._longPressProgress), ie = this._supportsRemote(r);
    return this._config.playing_display_mode === "full_art" ? this._renderFullArtPlayingMode({
      stateObj: r,
      rawStateObj: t,
      attributes: n,
      cachedItem: p,
      imageUrl: S,
      backdropUrl: T,
      displayTitle: O,
      subtitle: oe,
      mediaType: P,
      badgeText: se,
      showBadge: ce,
      badgeStyle: de,
      showInlineBadge: je,
      showHeaderBadge: Ie,
      yearStr: U,
      runtimeStr: be,
      ratingStr: re,
      genres: te,
      userName: H,
      sourceInfo: Ve,
      isFavorite: We,
      supportsRemote: ie,
      isPaused: G,
      isMusic: D,
      durationSeconds: u,
      displayPositionSeconds: m,
      curProgress: b,
      handleLeft: v,
      ringCircumference: st,
      ringOffset: vt
    }) : l`
            <ha-card class="jellyha-now-playing ${N ? "has-background" : ""} ${this._config.title ? "has-title" : ""}" style="--card-dominant-color: ${this._dominantColor};">
                ${N ? l`
                    <div class="card-background" style="background-image: url('${T}')"></div>
                    <div class="card-overlay"></div>
                ` : h}
                
                <div class="card-content">
                    ${this._config.title ? l`
                        <div class="card-header">${this._config.title}</div>
                    ` : h}
                    
                    <div class="main-container">
                        ${S ? l`
                            <div class="poster-container ${ie ? "" : "no-rewind"}" @click=${ie ? this._handlePosterRewind : void 0}>
                                <img src="${R(S, 160)}" alt="${O}" loading="eager" fetchpriority="high" />
                                
                                ${Fe ? l`
                                    <span class="poster-badge media-type-badge ${P}">${se}</span>
                                ` : h}
                                ${!ee && re ? l`
                                    <span class="poster-badge rating-badge rating-pill">
                                        <ha-icon icon="mdi:star"></ha-icon>
                                        <span>${re}</span>
                                    </span>
                                ` : h}
                                ${!ee && be ? l`
                                    <span class="poster-badge runtime-badge genre-pill">
                                        <span>${be}</span>
                                    </span>
                                ` : h}

                                ${this._rewindActive ? l`
                                    <div class="rewind-overlay">
                                        <span>${d(this.hass.locale?.language || this.hass.language, "rewinding")}</span>
                                    </div>
                                ` : h}
                            </div>
                        ` : h}
                        
                        <div class="info-container">
                            <div class="title-row">
                                ${this._config.show_title !== !1 ? l`<div class="title">${O}</div>` : h}
                                <div class="header-actions">
                                    ${Ie ? l`
                                        <span class="media-type-badge header-badge ${P}">${se}</span>
                                    ` : h}
                                    ${this._renderPowerButton()}
                                </div>
                            </div>

                            <div class="info-top info-middle">
                                ${this._overflowState < 4 && oe ? l`<div class="subtitle">${oe}</div>` : h}
                                ${this._overflowState < 3 ? this._renderMetaRow({
      badge: je ? l`<span class="media-type-badge inline-badge ${P}">${se}</span>` : h,
      year: U,
      runtime: ee ? be : void 0,
      rating: ee ? re : void 0,
      genres: this._overflowState < 2 ? te : [],
      isInline: ee
    }) : h}
                                ${this._overflowState < 1 && (H || Ve) ? l`<div class="client-line">${H ? l`<strong>${H}</strong>` : h}${H && Ve ? " · " : ""}${Ve || h}</div>` : h}
                            </div>

                            <div class="info-bottom">
                                ${ie && this._config.show_controls !== !1 ? l`
                                    <div class="playback-controls">
                                        ${D ? l`
                                            <ha-icon-button class="music-subtle-btn ${We ? "active" : ""}" .label=${"Favorite"} @click=${() => this._handleFavoriteToggle(n.item_id, We)}>
                                                <ha-icon icon="${We ? "mdi:heart" : "mdi:heart-outline"}"></ha-icon>
                                            </ha-icon-button>
                                            <ha-icon-button .label=${d(this.hass.locale?.language || this.hass.language, "previous") || "Previous"} @click=${() => this._handleControl("PreviousTrack")}>
                                                <ha-icon icon="mdi:skip-previous"></ha-icon>
                                            </ha-icon-button>
                                        ` : l`
                                            <ha-icon-button class="seek-btn" .label=${"Rewind 10s"} @click=${() => this._handleSeekRelative(-10)}>
                                                <ha-icon icon="mdi:rewind-10"></ha-icon>
                                            </ha-icon-button>
                                        `}

                                        <div class="play-pause-wrapper ${this._stopPulse ? "stop-pulse" : ""}"
                                            @pointerdown=${this._startLongPress}
                                            @pointerup=${this._endLongPress}
                                            @pointerleave=${this._endLongPress}
                                            @contextmenu=${(Je) => Je.preventDefault()}
                                        >
                                            ${this._rewindActive || this._isSeeking || t.state === "buffering" ? l`
                                                <ha-icon-button class="play-pause-btn spinning" .label=${d(this.hass.locale?.language || this.hass.language, "loading")}>
                                                    <ha-icon icon="mdi:loading"></ha-icon>
                                                </ha-icon-button>
                                            ` : G ? l`
                                                <ha-icon-button class="play-pause-btn" .label=${d(this.hass.locale?.language || this.hass.language, "play")} @click=${() => {
      if (this._longPressConsumed) {
        this._longPressConsumed = !1;
        return;
      }
      this._handleControl(D ? "PlayPause" : "Unpause");
    }}>
                                                    <ha-icon icon="mdi:play"></ha-icon>
                                                </ha-icon-button>
                                            ` : l`
                                                <ha-icon-button class="play-pause-btn" .label=${d(this.hass.locale?.language || this.hass.language, "pause")} @click=${() => {
      if (this._longPressConsumed) {
        this._longPressConsumed = !1;
        return;
      }
      this._handleControl("Pause");
    }}>
                                                    <ha-icon icon="mdi:pause"></ha-icon>
                                                </ha-icon-button>
                                            `}
                                            ${this._longPressProgress > 0 ? l`
                                                <svg class="stop-ring" viewBox="0 0 44 44">
                                                    <circle cx="22" cy="22" r="20"
                                                        stroke="#ef4444" stroke-width="3" fill="none"
                                                        stroke-dasharray="${st}"
                                                        stroke-dashoffset="${vt}"
                                                        stroke-linecap="round"
                                                        transform="rotate(-90 22 22)" />
                                                </svg>
                                            ` : h}
                                        </div>

                                        ${D ? l`
                                            <ha-icon-button .label=${d(this.hass.locale?.language || this.hass.language, "next") || "Next"} @click=${() => this._handleControl("NextTrack")}>
                                                <ha-icon icon="mdi:skip-next"></ha-icon>
                                            </ha-icon-button>
                                            <ha-icon-button class="music-subtle-btn ${n.repeat_mode && n.repeat_mode !== "RepeatNone" ? "active" : ""}" .label=${"Repeat"} @click=${() => this._handleRepeatMode(n.session_id, n.repeat_mode || "RepeatNone")}>
                                                <ha-icon icon="${n.repeat_mode === "RepeatOne" ? "mdi:repeat-once" : "mdi:repeat"}"></ha-icon>
                                            </ha-icon-button>
                                        ` : l`
                                            <ha-icon-button class="seek-btn" .label=${"Forward 30s"} @click=${() => this._handleSeekRelative(30)}>
                                                <ha-icon icon="mdi:fast-forward-30"></ha-icon>
                                            </ha-icon-button>
                                        `}
                                    </div>
                                ` : h}

                                ${this._renderVolumeControls()}

                                <div class="progress-container ${ie ? "" : "readonly"}"
                                    @pointerdown=${ie ? this._startDrag : void 0}
                                    @pointermove=${ie ? this._handleDrag : void 0}
                                    @pointerup=${ie ? this._endDrag : void 0}
                                    @pointercancel=${ie ? this._cancelDrag : void 0}
                                >
                                    <div class="progress-bar">
                                        <div class="progress-fill" style="width: ${b}%; transition: ${this._isDragging ? "none" : "width 1s linear"}; background: ${this._dominantColor}"></div>
                                        <div class="seek-handle" style="left: ${v}; transition: ${this._isDragging ? "none" : "left 1s linear"}; transform: translate(-50%, -50%) ${this._isDragging ? "scale(1.3)" : "scale(1)"}; background: ${this._dominantColor}"></div>
                                    </div>
                                </div>

                                ${this._config.show_time && u > 0 ? l`
                                    <div class="timestamps">
                                        <span class="time-elapsed">${this._formatSeconds(m)}</span>
                                        <span class="time-remaining">${this._formatSeconds(-(u - m))}</span>
                                    </div>
                                ` : h}
                            </div>
                        </div>
                    </div>
                </div>
            </ha-card>
        `;
  }
  _renderFullArtPlayingMode(e) {
    const t = this._config.playing_artwork_source === "poster";
    let i, o = "backdrop-source";
    t ? (i = e.imageUrl || e.backdropUrl, o = "poster-source") : (i = e.backdropUrl || e.imageUrl, o = "backdrop-source");
    const s = i ? R(i, t ? 640 : 960) : "";
    return l`
            <ha-card class="jellyha-now-playing has-background full-art-playing-card ${this._config.title ? "has-title" : ""}" style="--card-dominant-color: ${this._dominantColor};">
                <div class="full-art-backdrop-container">
                    ${s ? l`
                        <img class="full-art-hero-img ${o}" src="${s}" alt="${e.displayTitle}" />
                    ` : h}
                    <div class="full-art-scrim"></div>
                </div>

                <div class="full-art-top-overlay">
                    ${this._config.title ? l`
                        <div class="card-header">${this._config.title}</div>
                    ` : h}

                    <div class="full-art-header-row">
                        <div class="title-row">
                            ${this._config.show_title !== !1 ? l`<div class="title">${e.displayTitle}</div>` : l`<div></div>`}
                            ${e.showBadge && e.badgeStyle === "poster" ? l`
                                <span class="media-type-badge header-badge ${e.mediaType}">${e.badgeText}</span>
                            ` : h}
                        </div>
                        <div class="header-actions">
                            ${e.showHeaderBadge ? l`
                                <span class="media-type-badge header-badge ${e.mediaType}">${e.badgeText}</span>
                            ` : h}
                            ${this._renderPowerButton()}
                        </div>
                    </div>

                    ${e.subtitle ? l`<div class="subtitle">${e.subtitle}</div>` : h}

                    ${this._renderMetaRow({
      badge: e.showInlineBadge ? l`<span class="media-type-badge inline-badge ${e.mediaType}">${e.badgeText}</span>` : h,
      year: e.yearStr,
      runtime: e.runtimeStr,
      rating: e.ratingStr,
      genres: e.genres,
      isInline: !0
    })}

                    ${e.userName || e.sourceInfo ? l`
                        <div class="client-line">${e.userName ? l`<strong>${e.userName}</strong>` : h}${e.userName && e.sourceInfo ? " · " : ""}${e.sourceInfo || h}</div>
                    ` : h}

                    ${this._config.show_description !== !1 && (e.attributes.overview || e.cachedItem?.description) ? l`
                        <div class="full-art-overview">${e.attributes.overview || e.cachedItem?.description}</div>
                    ` : h}
                </div>

                <div class="full-art-bottom-overlay">

                    ${e.supportsRemote && this._config.show_controls !== !1 ? l`
                        <div class="playback-controls">
                            ${e.isMusic ? l`
                                <ha-icon-button class="music-subtle-btn ${e.isFavorite ? "active" : ""}" .label=${"Favorite"} @click=${() => this._handleFavoriteToggle(e.attributes.item_id, e.isFavorite)}>
                                    <ha-icon icon="${e.isFavorite ? "mdi:heart" : "mdi:heart-outline"}"></ha-icon>
                                </ha-icon-button>
                                <ha-icon-button .label=${d(this.hass.locale?.language || this.hass.language, "previous") || "Previous"} @click=${() => this._handleControl("PreviousTrack")}>
                                    <ha-icon icon="mdi:skip-previous"></ha-icon>
                                </ha-icon-button>
                            ` : l`
                                <ha-icon-button class="seek-btn" .label=${"Rewind 10s"} @click=${() => this._handleSeekRelative(-10)}>
                                    <ha-icon icon="mdi:rewind-10"></ha-icon>
                                </ha-icon-button>
                            `}

                            <div class="play-pause-wrapper ${this._stopPulse ? "stop-pulse" : ""}"
                                @pointerdown=${this._startLongPress}
                                @pointerup=${this._endLongPress}
                                @pointerleave=${this._endLongPress}
                                @contextmenu=${(a) => a.preventDefault()}
                            >
                                ${this._rewindActive || this._isSeeking || e.rawStateObj.state === "buffering" ? l`
                                    <ha-icon-button class="play-pause-btn spinning" .label=${d(this.hass.locale?.language || this.hass.language, "loading")}>
                                        <ha-icon icon="mdi:loading"></ha-icon>
                                    </ha-icon-button>
                                ` : e.isPaused ? l`
                                    <ha-icon-button class="play-pause-btn" .label=${d(this.hass.locale?.language || this.hass.language, "play")} @click=${() => {
      if (this._longPressConsumed) {
        this._longPressConsumed = !1;
        return;
      }
      this._handleControl(e.isMusic ? "PlayPause" : "Unpause");
    }}>
                                        <ha-icon icon="mdi:play"></ha-icon>
                                    </ha-icon-button>
                                ` : l`
                                    <ha-icon-button class="play-pause-btn" .label=${d(this.hass.locale?.language || this.hass.language, "pause")} @click=${() => {
      if (this._longPressConsumed) {
        this._longPressConsumed = !1;
        return;
      }
      this._handleControl("Pause");
    }}>
                                        <ha-icon icon="mdi:pause"></ha-icon>
                                    </ha-icon-button>
                                `}
                                ${this._longPressProgress > 0 ? l`
                                    <svg class="stop-ring" viewBox="0 0 44 44">
                                        <circle cx="22" cy="22" r="20"
                                            stroke="#ef4444" stroke-width="3" fill="none"
                                            stroke-dasharray="${e.ringCircumference}"
                                            stroke-dashoffset="${e.ringOffset}"
                                            stroke-linecap="round"
                                            transform="rotate(-90 22 22)" />
                                    </svg>
                                ` : h}
                            </div>

                            ${e.isMusic ? l`
                                <ha-icon-button .label=${d(this.hass.locale?.language || this.hass.language, "next") || "Next"} @click=${() => this._handleControl("NextTrack")}>
                                    <ha-icon icon="mdi:skip-next"></ha-icon>
                                </ha-icon-button>
                                <ha-icon-button class="music-subtle-btn ${e.attributes.repeat_mode && e.attributes.repeat_mode !== "RepeatNone" ? "active" : ""}" .label=${"Repeat"} @click=${() => this._handleRepeatMode(e.attributes.session_id, e.attributes.repeat_mode || "RepeatNone")}>
                                    <ha-icon icon="${e.attributes.repeat_mode === "RepeatOne" ? "mdi:repeat-once" : "mdi:repeat"}"></ha-icon>
                                </ha-icon-button>
                            ` : l`
                                <ha-icon-button class="seek-btn" .label=${"Forward 30s"} @click=${() => this._handleSeekRelative(30)}>
                                    <ha-icon icon="mdi:fast-forward-30"></ha-icon>
                                </ha-icon-button>
                            `}
                        </div>
                    ` : h}

                    ${this._renderVolumeControls()}

                    <div class="progress-container ${e.supportsRemote ? "" : "readonly"}"
                        @pointerdown=${e.supportsRemote ? this._startDrag : void 0}
                        @pointermove=${e.supportsRemote ? this._handleDrag : void 0}
                        @pointerup=${e.supportsRemote ? this._endDrag : void 0}
                        @pointercancel=${e.supportsRemote ? this._cancelDrag : void 0}
                    >
                        <div class="progress-bar">
                            <div class="progress-fill" style="width: ${e.curProgress}%; transition: ${this._isDragging ? "none" : "width 1s linear"}; background: ${this._dominantColor}"></div>
                            <div class="seek-handle" style="left: ${e.handleLeft}; transition: ${this._isDragging ? "none" : "left 1s linear"}; transform: translate(-50%, -50%) ${this._isDragging ? "scale(1.3)" : "scale(1)"}; background: ${this._dominantColor}"></div>
                        </div>
                    </div>

                    ${this._config.show_time && e.durationSeconds > 0 ? l`
                        <div class="timestamps">
                            <span class="time-elapsed">${this._formatSeconds(e.displayPositionSeconds)}</span>
                            <span class="time-remaining">${this._formatSeconds(-(e.durationSeconds - e.displayPositionSeconds))}</span>
                        </div>
                    ` : h}
                </div>
            </ha-card>
        `;
  }
  async _fetchPhrases() {
    if (!(this._phrases.length > 0))
      try {
        const e = await fetch("/jellyha_static/phrases.json");
        e.ok && (this._phrases = await e.json());
      } catch (e) {
        console.warn("JellyHA: Could not fetch phrases.json", e);
      }
  }
  _renderEmpty() {
    this._fetchPhrases();
    const t = this.hass.themes?.darkMode ? "https://raw.githubusercontent.com/home-assistant/brands/master/custom_integrations/jellyha/dark_logo.png" : "https://raw.githubusercontent.com/home-assistant/brands/master/custom_integrations/jellyha/logo.png", i = "https://raw.githubusercontent.com/home-assistant/brands/master/custom_integrations/jellyha/icon.png";
    let o = d(this.hass.locale?.language || this.hass.language, "nothing_playing");
    if (this._phrases.length > 0) {
      const a = Math.floor(Date.now() / 864e5) % this._phrases.length;
      o = this._phrases[a];
      const r = this._config?.entity || "", n = Ai(r), c = n ? `${n}_unwatched` : "";
      let p = c && this.hass.states[c] ? c : "";
      p || (p = Object.keys(this.hass.states).find((_) => _.startsWith("sensor.") && _.endsWith("_unwatched")) || "");
      const u = p ? this.hass.states[p].state : "0";
      o = o.replace(/\[number\]/g, u);
    }
    return l`
            <ha-card class="jellyha-now-playing empty-state">
                <div class="empty-top-actions">
                    ${this._renderPowerButton()}
                </div>
                <div class="card-content">
                    <div class="logo-container full-logo">
                        <img src="${t}" alt="JellyHA Logo" />
                    </div>
                    <div class="logo-container mini-icon">
                        <img src="${i}" alt="JellyHA Icon" />
                    </div>
                    <p>${o}</p>
                </div>
            </ha-card>
        `;
  }
  _renderIdleShowcase() {
    if (this._idleItems.length === 0)
      return this._fetchingIdleItems || this._fetchIdleLibraryItems(), this._renderEmpty();
    const e = this._idleItems[this._currentIdleIndex];
    if (!e)
      return this._renderEmpty();
    this._idleTimer || this._startIdleTimer();
    const t = this._prevIdleIndex !== null ? this._idleItems[this._prevIdleIndex] : null, i = this.hass.locale?.language || this.hass.language;
    return this._config.idle_display_mode === "card" ? this._renderIdleCardMode(e, t, i) : this._renderIdleBackdropMode(e, t, i);
  }
  _getItemFromLatestSensor(e) {
    if (!this.hass?.states) return null;
    const t = this._config?.entity || "";
    let i = "jellyha";
    if (t.startsWith("media_player.")) {
      const r = t.replace(/^media_player\./, "");
      i = r.includes("_") ? r.substring(0, r.lastIndexOf("_")) : r;
    }
    const o = e === "movie" ? `sensor.${i}_latest_movie` : `sensor.${i}_latest_episode`, s = this.hass.states[o] || this.hass.states[`sensor.jellyha_latest_${e}`];
    if (!s || !s.attributes || s.state === "unavailable" || s.state === "unknown")
      return null;
    const a = s.attributes;
    return {
      id: a.item_id || s.state,
      name: a.title || a.name || s.state,
      type: e === "movie" ? "Movie" : "Episode",
      year: a.year,
      description: a.overview || a.description,
      genres: a.genres || [],
      rating: a.rating,
      community_rating: a.community_rating,
      official_rating: a.official_rating,
      critic_rating: a.critic_rating,
      runtime_minutes: a.runtime_minutes,
      poster_url: a.poster_url,
      series_poster_url: a.series_poster_url,
      backdrop_url: a.backdrop_url,
      series_name: a.series_name,
      season: a.season,
      episode: a.episode,
      date_added: a.date_added,
      dynamic_range: a.dynamic_range,
      resolution: a.resolution,
      jellyfin_url: a.jellyfin_url || ""
    };
  }
  _renderIdleBackdropMode(e, t, i) {
    const o = R(e.backdrop_url || e.poster_url, 960), s = t ? R(t.backdrop_url || t.poster_url, 960) : "", a = e.community_rating ?? e.rating, r = typeof a == "number" && !isNaN(a) && a > 0 ? a.toFixed(1) : a ? String(a) : "", n = e.runtime_minutes ? ue(e.runtime_minutes) : "", c = e.genres && e.genres.length > 0 ? e.genres.slice(0, 3) : [], p = this._config.show_genres !== !1 ? c : [], u = this._config.show_media_type_badge !== !1 && this._config.badge_style !== "none", _ = this._config.badge_style || this._config.media_type_badge_style || "poster", g = u && _ === "inline", m = u && !g, b = e.type === "Movie", x = e.type === "Episode";
    e.type;
    const v = e.season, w = e.episode, k = Number(v), y = Number(w), S = v != null && w != null && !isNaN(k) && !isNaN(y) && k >= 0 && y >= 0, C = x && S ? `S${String(k).padStart(2, "0")}E${String(y).padStart(2, "0")}` : "";
    let T = "", N = "";
    x ? (T = e.name || e.series_name || "", N = this._config.show_subtitle !== !1 && (e.series_name || e.tagline) || "") : (T = e.name || "", N = this._config.show_subtitle !== !1 && e.tagline || "");
    const G = this._idleItems.findIndex((L) => b ? L.type === "Movie" : x ? L.type === "Episode" : L.type === "Series" || L.type !== "Movie" && L.type !== "Episode") === this._currentIdleIndex, F = this._config.idle_content_source === "latest_movie" || this._config.idle_content_source === "latest_episode" || this._config.idle_content_source === "latest_both" || this._config.idle_content_source === "recent" && G, P = x && !!C, D = F && P ? C : null, O = b ? "movie" : x ? "episode" : "series", Z = F ? b ? d(i, "card.latest_movie_badge") || "LATEST MOVIE" : x ? d(i, "card.latest_episode_badge") || "LATEST EPISODE" : d(i, "card.latest_series_badge") || "LATEST SERIES" : b ? d(i, "movie") || "Movie" : P ? C : d(i, "episode") || "Episode";
    return l`
            <ha-card class="jellyha-now-playing has-background idle-showcase-card">
                <div class="idle-backdrop-container">
                    <img class="idle-backdrop-img" src="${o}" alt="${e.name}" />
                    ${s ? l`
                        <img class="idle-backdrop-img prev-backdrop ${this._idleFadeOut ? "fade-out" : ""}" src="${s}" alt="" />
                    ` : h}
                    <div class="idle-backdrop-scrim"></div>
                </div>

                <div class="idle-backdrop-top-actions">
                    ${m ? l`
                        <span class="media-type-badge idle-backdrop-top-badge ${F ? "latest-badge" : ""} ${O}">${Z}</span>
                        ${D ? l`
                            <span class="media-type-badge idle-backdrop-top-badge ${O}">${D}</span>
                        ` : h}
                    ` : h}
                    ${this._renderPowerButton()}
                </div>

                <div class="idle-bottom-content">
                    <div class="title-row">
                        ${this._config.show_title !== !1 ? l`
                            <h2 class="idle-title">${T}</h2>
                        ` : h}
                    </div>
                    ${N ? l`
                        <div class="subtitle-row">
                            <span class="subtitle">${N}</span>
                        </div>
                    ` : h}
                    ${this._renderMetaRow({
      badge: g ? l`
                            <span class="media-type-badge inline-badge ${F ? "latest-badge" : ""} ${O}">${Z}</span>
                            ${D ? l`
                                <span class="media-type-badge inline-badge ${O}">${D}</span>
                            ` : h}
                        ` : h,
      year: this._config.show_year !== !1 && e.year ? e.year : void 0,
      runtime: this._config.show_runtime !== !1 && n ? n : void 0,
      rating: this._config.show_ratings !== !1 && r ? r : void 0,
      genres: p,
      isInline: !0
    })}
                    ${this._config.show_description !== !1 && e.description ? l`
                        <p class="idle-overview">${e.description}</p>
                    ` : h}
                </div>
            </ha-card>
        `;
  }
  _renderIdleCardMode(e, t, i) {
    const o = R(e.backdrop_url || e.poster_url, 960), s = t ? R(t.backdrop_url || t.poster_url, 960) : "", a = this._config.use_series_image && e.series_poster_url ? e.series_poster_url : e.poster_url || e.backdrop_url, r = R(a, 320), n = t && this._config.use_series_image && t.series_poster_url ? t.series_poster_url : t?.poster_url || t?.backdrop_url, c = n ? R(n, 320) : "", p = e.community_rating ?? e.rating, u = typeof p == "number" && !isNaN(p) && p > 0 ? p.toFixed(1) : p ? String(p) : "", _ = e.runtime_minutes ? ue(e.runtime_minutes) : "", g = this._config.show_runtime !== !1 && _ ? _ : "", m = this._config.show_ratings !== !1 && u ? u : "", b = e.genres && e.genres.length > 0 ? e.genres.slice(0, 3) : [], x = this._config.show_genres !== !1 ? b : [], v = this._config.badge_style || this._config.media_type_badge_style || "poster", w = this._config.show_media_type_badge !== !1 && v !== "none", k = w && v === "inline", y = e.type === "Movie", S = e.type === "Episode";
    e.type;
    const $ = e.season, C = e.episode, T = Number($), N = Number(C), G = $ != null && C != null && !isNaN(T) && !isNaN(N) && T >= 0 && N >= 0, P = S && G ? `S${String(T).padStart(2, "0")}E${String(N).padStart(2, "0")}` : "";
    let D = "", O = "";
    S ? (D = e.name || e.series_name || "", O = this._config.show_subtitle !== !1 && (e.series_name || e.tagline) || "") : (D = e.name || "", O = this._config.show_subtitle !== !1 && e.tagline || "");
    const Z = this._idleItems.findIndex((W) => y ? W.type === "Movie" : S ? W.type === "Episode" : W.type === "Series" || W.type !== "Movie" && W.type !== "Episode") === this._currentIdleIndex, L = this._config.idle_content_source === "latest_movie" || this._config.idle_content_source === "latest_episode" || this._config.idle_content_source === "latest_both" || this._config.idle_content_source === "recent" && Z, oe = S && !!P, B = L && oe ? P : null, U = y ? "movie" : S ? "episode" : "series", Q = L ? y ? d(i, "card.latest_movie_badge") || "LATEST MOVIE" : S ? d(i, "card.latest_episode_badge") || "LATEST EPISODE" : d(i, "card.latest_series_badge") || "LATEST SERIES" : y ? d(i, "movie") || "Movie" : oe ? P : d(i, "episode") || "Episode";
    return l`
            <ha-card class="jellyha-now-playing has-background idle-card-mode">
                <div class="idle-card-bg-container">
                    ${o ? l`
                        <img class="idle-card-bg-img" src="${o}" alt="" />
                    ` : h}
                    ${s ? l`
                        <img class="idle-card-bg-img prev-bg ${this._idleFadeOut ? "fade-out" : ""}" src="${s}" alt="" />
                    ` : h}
                    <div class="card-overlay"></div>
                </div>

                <div class="card-content">
                    <div class="main-container">
                        <div class="poster-container no-rewind">
                            <img class="idle-poster-img" src="${r}" alt="${e.name}" loading="eager" />
                            ${c ? l`
                                <img class="idle-poster-img prev-poster ${this._idleFadeOut ? "fade-out" : ""}" src="${c}" alt="" />
                            ` : h}
                            ${w && v === "poster" ? l`
                                <div class="poster-badge-group">
                                    <span class="poster-badge media-type-badge ${L ? "latest-badge" : ""} ${U}">${Q}</span>
                                    ${B ? l`
                                        <span class="poster-badge media-type-badge ${U}">${B}</span>
                                    ` : h}
                                </div>
                            ` : h}
                            ${!k && m ? l`
                                <span class="poster-badge rating-badge rating-pill">
                                    <ha-icon icon="mdi:star"></ha-icon>
                                    <span>${m}</span>
                                </span>
                            ` : h}
                            ${!k && g ? l`
                                <span class="poster-badge runtime-badge genre-pill">
                                    <span>${g}</span>
                                </span>
                            ` : h}
                        </div>

                        <div class="info-container">
                            <div class="info-top">
                                <div class="title-row">
                                    ${this._config.show_title !== !1 ? l`
                                        <span class="title" title="${e.series_name ? `${e.series_name} - ${e.name}` : D}">${D}</span>
                                    ` : h}
                                    <div class="header-actions">
                                        ${w && v === "header" ? l`
                                            <span class="media-type-badge header-badge ${L ? "latest-badge" : ""} ${U}">${Q}</span>
                                            ${B ? l`
                                                <span class="media-type-badge header-badge ${U}">${B}</span>
                                            ` : h}
                                        ` : h}
                                        ${this._renderPowerButton()}
                                    </div>
                                </div>
                                ${O ? l`
                                    <div class="subtitle-row">
                                        <span class="subtitle">${O}</span>
                                    </div>
                                ` : h}
                                ${this._renderMetaRow({
      badge: w && k ? l`
                                        <span class="media-type-badge inline-badge ${L ? "latest-badge" : ""} ${U}">${Q}</span>
                                        ${B ? l`
                                            <span class="media-type-badge inline-badge ${U}">${B}</span>
                                        ` : h}
                                    ` : h,
      year: this._config.show_year !== !1 && e.year ? e.year : void 0,
      runtime: k ? g : void 0,
      rating: k ? m : void 0,
      genres: x,
      isInline: k
    })}
                                ${this._config.show_description !== !1 && e.description ? l`
                                    <div class="idle-card-desc">${e.description}</div>
                                ` : h}
                            </div>
                        </div>
                    </div>
                </div>
            </ha-card>
        `;
  }
  _renderMetaRow(e) {
    const { badge: t, year: i, runtime: o, rating: s, genres: a = [], isInline: r = !0 } = e, n = i ? String(i) : "", c = o ? String(o) : "", p = s ? String(s) : "", u = a && a.length > 0, _ = t && t !== h;
    if (!(_ || !!n || !!c || !!p || u))
      return h;
    const m = !!n || !!c || !!p || u, b = !!c || !!p || u, x = !!p || u;
    return l`
            <div class="meta-line ${r ? "idle-meta-row" : ""}">
                ${_ ? l`
                    ${t}
                    ${m ? l`<span class="idle-dot meta-dot">•</span>` : h}
                ` : h}
                ${n ? l`
                    <span class="idle-meta-text meta-text meta-year">${n}</span>
                    ${b ? l`<span class="idle-dot meta-dot">•</span>` : h}
                ` : h}
                ${c ? l`
                    <span class="idle-meta-text meta-text meta-runtime">${c}</span>
                    ${x ? l`<span class="idle-dot meta-dot">•</span>` : h}
                ` : h}
                ${p ? l`
                    <span class="idle-rating-pill rating-pill">
                        <ha-icon icon="mdi:star"></ha-icon>
                        <span>${p}</span>
                    </span>
                ` : h}
                ${u ? a.map((v) => l`<span class="genre-pill idle-genre-pill">${v}</span>`) : h}
            </div>
        `;
  }
  _startIdleTimer() {
    if (this._stopIdleTimer(), !this._config?.idle_backdrop_cycle || this._idleItems.length <= 1) return;
    const e = Number(this._config.idle_cycle_interval), t = Math.max(5, !isNaN(e) && e > 0 ? e : 20);
    this._idleTimer = window.setInterval(() => {
      this._advanceIdleSlide();
    }, t * 1e3);
  }
  _stopIdleTimer() {
    this._idleTimer && (clearInterval(this._idleTimer), this._idleTimer = void 0);
  }
  _advanceIdleSlide() {
    if (!this.isConnected || !this._config?.idle_backdrop_cycle || this._idleItems.length <= 1) return;
    this._prevIdleIndex = this._currentIdleIndex, this._currentIdleIndex = (this._currentIdleIndex + 1) % this._idleItems.length, this._idleFadeOut = !0, this.requestUpdate();
    const e = (this._currentIdleIndex + 1) % this._idleItems.length, t = this._idleItems[e];
    if (t) {
      if (this._config?.idle_display_mode === "card" && t.poster_url) {
        const s = new Image();
        s.src = R(t.poster_url, 320);
      }
      const o = t.backdrop_url || t.poster_url;
      if (o) {
        const s = new Image();
        s.src = R(o, 960);
      }
    }
    setTimeout(() => {
      this._prevIdleIndex = null, this._idleFadeOut = !1, this.requestUpdate();
    }, 850);
  }
  async _fetchIdleLibraryItems() {
    if (!(!this.hass || this._fetchingIdleItems)) {
      this._fetchingIdleItems = !0;
      try {
        const e = this._config?.idle_content_source || "random";
        if (e === "latest_movie" || e === "latest_episode" || e === "latest_both") {
          const n = [];
          if (e === "latest_movie" || e === "latest_both") {
            const c = this._getItemFromLatestSensor("movie");
            c && n.push(c);
          }
          if (e === "latest_episode" || e === "latest_both") {
            const c = this._getItemFromLatestSensor("episode");
            c && n.push(c);
          }
          if (n.length > 0) {
            this._idleItems = n, this._currentIdleIndex = 0, this._prevIdleIndex = null, this._idleFadeOut = !1, this._startIdleTimer(), this.requestUpdate();
            return;
          }
        }
        const t = this._config?.entity || "";
        let i = Object.keys(this.hass?.states || {}).find(
          (n) => n.startsWith("sensor.jellyha") && n.endsWith("_library")
        );
        if (t.startsWith("media_player.")) {
          const n = t.replace(/^media_player\./, ""), p = `sensor.${n.includes("_") ? n.substring(0, n.lastIndexOf("_")) : n}_library`;
          this.hass?.states[p] && (i = p);
        }
        const o = e === "movies" || e === "series" ? e : this._config.idle_media_type || "both", s = this._config.idle_display_mode === "card", a = Math.max(1, this._config.idle_recent_limit || 15);
        let r = null;
        if (e === "recent") {
          let n = ["Movie", "Series"];
          o === "movies" ? n = ["Movie"] : o === "series" ? n = ["Series"] : o === "movies_episodes" ? n = ["Movie", "Episode"] : o === "episodes" && (n = ["Episode"]);
          try {
            const c = {
              type: "jellyha/get_latest_items",
              item_types: n,
              limit: Math.max(a * 3, 100)
            };
            i && (c.server_entity_id = i), t && (c.entity_id = t), r = await this.hass.callWS(c);
          } catch (c) {
            console.warn("[JellyHA] get_latest_items failed, falling back to get_items:", c);
          }
        }
        if (!r || !Array.isArray(r.items) || r.items.length === 0) {
          const n = {
            type: "jellyha/get_items"
          };
          i && (n.server_entity_id = i), t && (n.entity_id = t), r = await this.hass.callWS(n);
        }
        if (r && Array.isArray(r.items) && r.items.length > 0) {
          let n = r.items.filter((c) => s && !!c.poster_url || !!c.backdrop_url);
          if (o === "movies" ? n = n.filter((c) => c.type === "Movie") : o === "series" ? n = n.filter((c) => c.type === "Series" || c.type === "Episode") : o === "movies_episodes" ? n = n.filter((c) => c.type === "Movie" || c.type === "Episode") : o === "episodes" && (n = n.filter((c) => c.type === "Episode")), n.length > 0) {
            if (e === "recent") {
              n.sort((u, _) => {
                const g = u.date_added ? new Date(u.date_added).getTime() : 0;
                return (_.date_added ? new Date(_.date_added).getTime() : 0) - g;
              });
              const c = Math.max(1, this._config.idle_recent_limit || 15);
              let p = n.slice(0, c);
              if (o === "movies_episodes") {
                const u = p.some((g) => g.type === "Movie"), _ = p.some((g) => g.type === "Episode");
                if (!u) {
                  const g = n.find((m) => m.type === "Movie");
                  g && p.push(g);
                }
                if (!_) {
                  const g = n.find((m) => m.type === "Episode");
                  g && p.push(g);
                }
              } else if (o === "both") {
                const u = p.some((g) => g.type === "Movie"), _ = p.some((g) => g.type === "Series");
                if (!u) {
                  const g = n.find((m) => m.type === "Movie");
                  g && p.push(g);
                }
                if (!_) {
                  const g = n.find((m) => m.type === "Series");
                  g && p.push(g);
                }
              }
              this._idleItems = p;
            } else if (e === "latest_movie") {
              const c = n.find((p) => p.type === "Movie");
              this._idleItems = c ? [c] : n.slice(0, 1);
            } else if (e === "latest_episode") {
              const c = n.find((p) => p.type === "Episode" || p.type === "Series");
              this._idleItems = c ? [c] : n.slice(0, 1);
            } else
              this._idleItems = this._shuffleArray(n);
            this._currentIdleIndex = 0, this._prevIdleIndex = null, this._idleFadeOut = !1, this._startIdleTimer(), this.requestUpdate();
          }
        }
      } catch (e) {
        console.warn("[JellyHA] Failed to fetch library items for idle showcase:", e);
      } finally {
        this._fetchingIdleItems = !1;
      }
    }
  }
  _shuffleArray(e) {
    const t = [...e];
    for (let i = t.length - 1; i > 0; i--) {
      const o = Math.floor(Math.random() * (i + 1));
      [t[i], t[o]] = [t[o], t[i]];
    }
    return t;
  }
  _renderError(e) {
    return l`
            <ha-card class="error-state">
                <div class="card-content">
                    <p>${e}</p>
                </div>
            </ha-card>
        `;
  }
  _extractItemId(e) {
    const t = e.attributes;
    if (t.item_id) return String(t.item_id);
    const i = e.attributes.media_content_id || "", o = e.attributes.entity_picture || "", s = i.match(/(?:Videos|Items|Audio|stream\/[a-zA-Z0-9_-]+|hls\/[a-zA-Z0-9_-]+)\/([a-zA-Z0-9_-]+)/i);
    if (s && s[1]) return s[1];
    const a = o.match(/(?:Items|image\/[a-zA-Z0-9_-]+)\/([a-zA-Z0-9_-]+)/i);
    return a && a[1] ? a[1] : null;
  }
  async _fetchMissingMetadata(e) {
    if (!(!e || this._resolvedMetadata[e] || this._fetchingMetadataId === e)) {
      this._fetchingMetadataId = e;
      try {
        const t = Object.keys(this.hass?.states || {}).find(
          (s) => s.startsWith("sensor.jellyha") && s.endsWith("_library")
        ), i = {
          type: "jellyha/get_item",
          item_id: e
        };
        t && (i.server_entity_id = t);
        const o = await this.hass.callWS(i);
        o && o.item ? this._resolvedMetadata[e] = o.item : this._resolvedMetadata[e] = {}, this.requestUpdate(), this._checkLayout();
      } catch {
      } finally {
        this._fetchingMetadataId = null;
      }
    }
  }
  _resolveImages(e, t) {
    const i = e.attributes;
    let o = i.series_image_url || t?.series_poster_url, s = i.image_url || t?.poster_url || t?.image_url;
    const a = (i.media_type || t?.type || e.attributes.media_content_type || "").toLowerCase(), r = i.series_title || e.attributes.media_series_title || t?.series_name, n = i.title || e.attributes.media_title || t?.name, c = a === "episode" || a === "tvshow" || !!r || e.attributes.media_season !== void 0 || t?.season !== void 0, p = e.attributes.media_content_id || "", u = e.attributes.entity_picture || "", _ = i.item_id || t?.id || p || r || e.entity_id;
    if (_ && this._resolvedImages[_] && (o || (o = this._resolvedImages[_].seriesImageUrl), s || (s = this._resolvedImages[_].episodeImageUrl)), !c || o && s)
      return { seriesImageUrl: o, episodeImageUrl: s };
    t && (t.series_poster_url && !o && (o = t.series_poster_url), (t.poster_url || t.image_url) && !s && (s = t.poster_url || t.image_url));
    const g = p.match(/^(https?:\/\/[^\/]+)\/(?:Videos|Items)\/([a-zA-Z0-9_-]+)/i), m = u.match(/^(https?:\/\/[^\/]+)\/Items\/([a-zA-Z0-9_-]+)\/Images\/Primary/i), b = u.match(/(?:Items|image\/[a-zA-Z0-9_-]+)\/([a-zA-Z0-9_-]+)/i), x = g ? g[1] : m ? m[1] : "", v = g ? g[2] : i.item_id || null, w = m ? m[2] : b ? b[1] : null, k = p.match(/[?&](?:api_key|ApiKey)=([a-zA-Z0-9]+)/i) || u.match(/[?&](?:api_key|ApiKey)=([a-zA-Z0-9]+)/i), y = k ? `&api_key=${k[1]}` : "";
    if (x && v) {
      const S = `${x}/Items/${v}/Images/Primary?maxHeight=300&quality=90${y}`;
      s || (w === v ? s = u : s = S), w && w !== v && !o && (o = u);
    } else (m || b) && !s && !o && (s = u);
    return _ && (o || s) && (this._resolvedImages[_] = {
      ...this._resolvedImages[_],
      ...o ? { seriesImageUrl: o } : {},
      ...s ? { episodeImageUrl: s } : {}
    }), c && (!o || !s) && this._fetchingImageKey !== _ && this._fetchMissingImages(r, n, _), { seriesImageUrl: o, episodeImageUrl: s };
  }
  async _fetchMissingImages(e, t, i) {
    if (i) {
      this._fetchingImageKey = i;
      try {
        if (t) {
          const s = (await this.hass.callWS({
            type: "jellyha/search_media",
            query: t,
            media_type: "Episode",
            limit: 1
          }))?.items;
          if (s && s.length > 0) {
            const a = s[0], r = a.poster_url || a.image_url, n = a.series_poster_url;
            if (r || n) {
              this._resolvedImages[i] = {
                ...this._resolvedImages[i],
                ...r ? { episodeImageUrl: r } : {},
                ...n ? { seriesImageUrl: n } : {}
              }, this.requestUpdate();
              return;
            }
          }
        }
        if (e && !this._resolvedImages[i]?.seriesImageUrl) {
          const s = (await this.hass.callWS({
            type: "jellyha/search_media",
            query: e,
            media_type: "Series",
            limit: 1
          }))?.items;
          if (s && s.length > 0) {
            const a = s[0].poster_url || s[0].series_poster_url || s[0].image_url;
            a && (this._resolvedImages[i] = {
              ...this._resolvedImages[i],
              seriesImageUrl: a
            }, this.requestUpdate());
          }
        }
      } catch {
      } finally {
        this._fetchingImageKey = null;
      }
    }
  }
  _supportsRemote(e) {
    if (!e || this._config.show_controls === !1) return !1;
    const t = e.attributes;
    return !(e.entity_id.startsWith("media_player.") && t.supported_features !== void 0 && t.supported_features === 0);
  }
  async _handleControl(e) {
    this._haptic("light");
    const t = this._config.entity, i = this.hass.states[t];
    if (!i || !this._supportsRemote(i)) return;
    if (t.startsWith("media_player.")) {
      let a = "";
      if (e === "Pause" ? a = "media_pause" : e === "Unpause" || e === "Play" ? a = "media_play" : e === "PlayPause" ? a = "media_play_pause" : e === "Stop" ? a = "media_stop" : e === "NextTrack" ? a = "media_next_track" : e === "PreviousTrack" && (a = "media_previous_track"), a) {
        await this.hass.callService("media_player", a, {
          entity_id: t
        });
        return;
      }
    }
    const s = i?.attributes.session_id;
    s && await this.hass.callService("jellyha", "session_control", {
      entity_id: t,
      session_id: s,
      command: e
    });
  }
  async _handleRepeatMode(e, t) {
    let i = "RepeatAll", o = "all";
    t === "RepeatAll" || t === "all" ? (i = "RepeatOne", o = "one") : (t === "RepeatOne" || t === "one") && (i = "RepeatNone", o = "off");
    const s = this._config.entity;
    if (s.startsWith("media_player.")) {
      await this.hass.callService("media_player", "repeat_set", {
        entity_id: s,
        repeat: o
      });
      return;
    }
    await this.hass.callService("jellyha", "session_general_command", {
      entity_id: s,
      session_id: e,
      command: "SetRepeatMode",
      arguments: { RepeatMode: i }
    });
  }
  _haptic(e = "selection") {
    const t = new CustomEvent("haptic", {
      detail: e,
      bubbles: !0,
      composed: !0
    });
    this.dispatchEvent(t);
  }
  async _handleFavoriteToggle(e, t) {
    this._haptic();
    const i = !t;
    this._optimisticFavorites[e] = i, this.requestUpdate(), await this.hass.callService("jellyha", "update_favorite", {
      entity_id: this._config.entity,
      item_id: e,
      is_favorite: i
    });
  }
  get _targetPowerEntity() {
    return Pi(this._config);
  }
  async _handlePowerClick(e) {
    e.stopPropagation(), this._haptic("light");
    const t = this._targetPowerEntity;
    if (!t || !this.hass) return;
    const i = ct(this.hass, t, this._config?.power_state_entity);
    if ((i.isOn || !i.isStateless) && this._config.stop_on_power_off !== !1) {
      const o = this._config.entity, s = this.hass.states[o];
      s && (s.state === "playing" || s.state === "paused") && await this._handleControl("Stop");
    }
    this._powerActivating = !0, this.requestUpdate(), setTimeout(() => {
      this._powerActivating = !1, this.requestUpdate();
    }, 200), await ji(this.hass, t, this._config?.power_state_entity);
  }
  _handlePowerKeydown(e) {
    (e.key === "Enter" || e.key === " ") && (e.preventDefault(), this._handlePowerClick(e));
  }
  _renderPowerButton() {
    const e = this._targetPowerEntity, t = this._config?.show_power_button !== !1 && this._config?.show_power !== !1;
    if (!e || !t || !this.hass) return h;
    const i = ct(this.hass, e, this._config?.power_state_entity), o = i.isStateless ? "stateless-ready" : i.isOn ? "is-on" : "is-off", s = this._powerActivating ? "activating" : "", a = i.isOn ? "Power Off" : "Power On";
    return l`
            <div
                class="power-btn-hit-area"
                role="button"
                tabindex="0"
                aria-label=${a}
                title=${a}
                @click=${this._handlePowerClick}
                @keydown=${this._handlePowerKeydown}
            >
                <ha-icon-button
                    class="power-btn ${o} ${s}"
                    .label=${a}
                    tabindex="-1"
                >
                    <ha-icon icon="mdi:power"></ha-icon>
                </ha-icon-button>
            </div>
        `;
  }
  async _handleToggleMute() {
    this._haptic("light");
    const e = this._config?.volume_entity || this._config?.entity;
    !e || !this.hass || await Ti(this.hass, e);
  }
  async _handleVolumeStep(e) {
    this._haptic("light");
    const t = this._config?.volume_entity || this._config?.entity;
    if (!t || !this.hass) return;
    const i = this._optimisticVolume[t], o = pt(this.hass, this._config?.volume_entity, this._config?.entity, i), s = this._optimisticVolume[t] ?? o.volumePercent, a = Math.max(0, Math.min(100, Math.round(s + e)));
    this._optimisticVolume = { ...this._optimisticVolume, [t]: a }, this.requestUpdate(), await Ei(this.hass, t, e / 100, s / 100);
  }
  _startVolumeDrag(e) {
    e.stopPropagation(), e.preventDefault();
    const t = e.currentTarget.closest(".volume-slider-track") || e.currentTarget;
    if (!t) return;
    t.setPointerCapture(e.pointerId), this._isVolumeDragging = !0, this._haptic("selection");
    const i = t.getBoundingClientRect(), o = Math.min(100, Math.max(0, Math.round((e.clientX - i.left) / i.width * 100)));
    this._dragVolumePercent = o;
    const s = this._config?.volume_entity || this._config?.entity;
    s && (this._optimisticVolume = { ...this._optimisticVolume, [s]: o }), this._lastHapticVolumeTick = Math.floor(o / 5);
  }
  _handleVolumeDrag(e) {
    if (!this._isVolumeDragging) return;
    e.stopPropagation();
    const t = e.currentTarget.closest(".volume-slider-track") || e.currentTarget;
    if (!t) return;
    const i = t.getBoundingClientRect(), o = Math.min(100, Math.max(0, Math.round((e.clientX - i.left) / i.width * 100)));
    this._dragVolumePercent = o;
    const s = this._config?.volume_entity || this._config?.entity;
    s && (this._optimisticVolume = { ...this._optimisticVolume, [s]: o });
    const a = Math.floor(o / 5);
    a !== this._lastHapticVolumeTick && (this._lastHapticVolumeTick = a, this._haptic("selection"));
  }
  async _endVolumeDrag(e) {
    if (!this._isVolumeDragging) return;
    e.stopPropagation();
    const t = e.currentTarget.closest(".volume-slider-track") || e.currentTarget;
    t && t.hasPointerCapture(e.pointerId) && t.releasePointerCapture(e.pointerId);
    const i = this._dragVolumePercent ?? 0;
    this._isVolumeDragging = !1, this._dragVolumePercent = null;
    const o = this._config?.volume_entity || this._config?.entity;
    o && this.hass && (this._optimisticVolume = { ...this._optimisticVolume, [o]: i }, this.requestUpdate(), await Jt(this.hass, o, i / 100));
  }
  _cancelVolumeDrag(e) {
    if (!this._isVolumeDragging) return;
    const t = e.currentTarget.closest(".volume-slider-track") || e.currentTarget;
    t && t.hasPointerCapture(e.pointerId) && t.releasePointerCapture(e.pointerId), this._isVolumeDragging = !1, this._dragVolumePercent = null, this.requestUpdate();
  }
  _renderVolumeControls() {
    if (!(this._config?.show_volume === !0 || this._config?.show_volume !== !1 && !!this._config?.volume_entity) || !this.hass) return h;
    const t = this._config?.volume_entity || this._config?.entity, i = t ? this._optimisticVolume[t] : void 0, o = pt(this.hass, this._config?.volume_entity, this._config?.entity, i), s = o.isMuted;
    let a;
    this._isVolumeDragging && this._dragVolumePercent !== null ? a = this._dragVolumePercent : t && this._optimisticVolume[t] !== void 0 ? a = this._optimisticVolume[t] : a = o.volumePercent;
    const r = this._config?.show_volume_step_buttons !== !1, n = typeof this._config?.volume_step == "number" && this._config.volume_step > 0 ? this._config.volume_step : 5, c = s ? "mdi:volume-mute" : a === 0 ? "mdi:volume-off" : a < 50 ? "mdi:volume-medium" : "mdi:volume-high";
    return l`
            <div class="volume-capsule ${r ? "" : "no-step-buttons"}">
                <ha-icon-button
                    class="volume-btn mute-btn ${s ? "muted" : ""}"
                    .label=${s ? "Unmute" : "Mute"}
                    title=${s ? "Unmute" : "Mute"}
                    @click=${this._handleToggleMute}
                >
                    <ha-icon icon="${c}"></ha-icon>
                </ha-icon-button>

                <div
                    class="volume-slider-track"
                    @pointerdown=${this._startVolumeDrag}
                    @pointermove=${this._handleVolumeDrag}
                    @pointerup=${this._endVolumeDrag}
                    @pointercancel=${this._cancelVolumeDrag}
                >
                    <div
                        class="volume-slider-fill"
                        style="width: ${a}%; background: ${this._dominantColor};"
                    ></div>
                    <div
                        class="volume-slider-thumb"
                        style="left: ${a}%; background: ${this._dominantColor};"
                    ></div>
                </div>

                <span class="volume-pct">${a}%</span>

                ${r ? l`
                    <ha-icon-button
                        class="volume-btn volume-step-btn"
                        .label=${`Decrease volume by ${n}%`}
                        title=${`-${n}%`}
                        @click=${() => this._handleVolumeStep(-n)}
                    >
                        <ha-icon icon="mdi:minus"></ha-icon>
                    </ha-icon-button>
                    <ha-icon-button
                        class="volume-btn volume-step-btn"
                        .label=${`Increase volume by ${n}%`}
                        title=${`+${n}%`}
                        @click=${() => this._handleVolumeStep(n)}
                    >
                        <ha-icon icon="mdi:plus"></ha-icon>
                    </ha-icon-button>
                ` : h}
            </div>
        `;
  }
  _getDragPercent(e) {
    const i = e.currentTarget.getBoundingClientRect();
    let o = e.clientX - i.left;
    return o < 10 && (o = 0), o > i.width - 10 && (o = i.width), Math.max(0, Math.min(100, o / i.width * 100));
  }
  _startDrag(e) {
    const t = this._config.entity, i = this.hass?.states[t];
    if (!i || !this._supportsRemote(i)) return;
    e.currentTarget.setPointerCapture(e.pointerId), this._isDragging = !0, this._dragPercentage = this._getDragPercent(e), this._haptic("light");
  }
  _handleDrag(e) {
    this._isDragging && (this._dragPercentage = this._getDragPercent(e));
  }
  _cancelDrag(e) {
    if (!this._isDragging) return;
    const t = e.currentTarget;
    if (t?.releasePointerCapture)
      try {
        t.releasePointerCapture(e.pointerId);
      } catch {
      }
    this._isDragging = !1, this.requestUpdate();
  }
  _getDurationSeconds(e) {
    const t = e.attributes;
    if (t.duration_ticks && t.duration_ticks > 0)
      return t.duration_ticks / 1e7;
    const i = e.attributes.media_duration;
    return typeof i == "number" && i > 0 ? i : t.runtime_minutes && t.runtime_minutes > 0 ? t.runtime_minutes * 60 : 0;
  }
  _getCurrentPositionSeconds(e) {
    const t = e.attributes, i = this._getDurationSeconds(e);
    let o = 0, s;
    const a = e.attributes.media_position;
    if (typeof a == "number" ? (o = a, s = e.attributes.media_position_updated_at || e.last_updated) : typeof t.position_ticks == "number" ? (o = t.position_ticks / 1e7, s = e.last_updated) : typeof t.progress_percent == "number" && i > 0 && (o = t.progress_percent / 100 * i, s = e.last_updated), (e.entity_id.startsWith("media_player.") ? e.state === "playing" : !t.is_paused && !!t.item_id) && s) {
      const c = new Date(s).getTime();
      if (!isNaN(c)) {
        const p = Math.max(0, (Date.now() - c) / 1e3), u = o + p;
        return i > 0 ? Math.min(i, Math.max(0, u)) : Math.max(0, u);
      }
    }
    return i > 0 ? Math.min(i, Math.max(0, o)) : Math.max(0, o);
  }
  async _endDrag(e) {
    if (!this._isDragging) return;
    const t = e.currentTarget;
    if (t?.releasePointerCapture)
      try {
        t.releasePointerCapture(e.pointerId);
      } catch {
      }
    this._isDragging = !1;
    const i = this._getDragPercent(e);
    this._setOptimisticSeek(i);
    const o = this._config.entity, s = this.hass.states[o];
    if (!s) return;
    const a = this._getDurationSeconds(s);
    if (a <= 0) return;
    const n = s.attributes.session_id;
    if (o.startsWith("media_player.")) {
      const p = Math.round(a * (i / 100));
      await this.hass.callService("media_player", "media_seek", {
        entity_id: o,
        seek_position: p
      });
      return;
    }
    if (!n) return;
    const c = Math.round(a * 1e7 * (i / 100));
    await this.hass.callService("jellyha", "session_seek", {
      entity_id: o,
      session_id: n,
      position_ticks: c
    });
  }
  _setOptimisticSeek(e) {
    this._optimisticSeekTimer && clearTimeout(this._optimisticSeekTimer), this._optimisticSeekPercent = e, this._isSeeking = !0, this._seekingTimer && clearTimeout(this._seekingTimer), this._seekingTimer = setTimeout(() => {
      this._isSeeking = !1, this.requestUpdate();
    }, 3e3), this.requestUpdate(), this._optimisticSeekTimer = setTimeout(() => {
      this._optimisticSeekPercent = null, this.requestUpdate();
    }, 2500);
  }
  async _handleSeekRelative(e) {
    this._haptic("light");
    const t = this._config.entity, i = this.hass.states[t];
    if (!i || !this._supportsRemote(i)) return;
    const o = this._getDurationSeconds(i), s = this._getCurrentPositionSeconds(i), a = Math.max(
      0,
      o > 0 ? Math.min(o, s + e) : s + e
    );
    if (o > 0 && this._setOptimisticSeek(a / o * 100), t.startsWith("media_player.")) {
      await this.hass.callService("media_player", "media_seek", {
        entity_id: t,
        seek_position: Math.round(a)
      });
      return;
    }
    const n = i.attributes.session_id;
    n && await this.hass.callService("jellyha", "session_seek", {
      entity_id: t,
      session_id: n,
      position_ticks: Math.round(a * 1e7)
    });
  }
  async _handlePosterRewind() {
    const e = this._config.entity, t = this.hass.states[e];
    !t || !this._supportsRemote(t) || (this._rewindActive = !0, setTimeout(() => {
      this._rewindActive = !1;
    }, 1e3), this._haptic("selection"), await this._handleSeekRelative(-20));
  }
  _startLongPress() {
    const e = Date.now(), t = 800;
    this._haptic("selection");
    const i = () => {
      const o = Date.now() - e;
      if (this._longPressProgress = Math.min(o / t, 1), this._longPressProgress >= 1) {
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
  _extractDominantColor(e) {
    if (typeof Image > "u") return;
    const t = new Image();
    t.crossOrigin = "anonymous", t.onload = () => {
      try {
        const i = document.createElement("canvas");
        i.width = 50, i.height = 50;
        const o = i.getContext("2d");
        if (!o) return;
        o.drawImage(t, 0, 0, 50, 50);
        const s = o.getImageData(0, 0, 50, 50).data;
        let a = 0, r = 0, n = 0, c = 0;
        for (let p = 0; p < s.length; p += 16) {
          const u = s[p], _ = s[p + 1], g = s[p + 2], m = Math.max(u, _, g), b = Math.min(u, _, g), x = m === 0 ? 0 : (m - b) / m, v = m / 255;
          x > c && v > 0.15 && v < 0.95 && (c = x, a = u, r = _, n = g);
        }
        if (c > 0.1) {
          const p = a / 255, u = r / 255, _ = n / 255, g = Math.max(p, u, _), m = Math.min(p, u, _);
          let b = 0;
          const x = (g + m) / 2, v = g - m, w = v === 0 ? 0 : v / (1 - Math.abs(2 * x - 1));
          v !== 0 && (g === p ? b = ((u - _) / v + (u < _ ? 6 : 0)) * 60 : g === u ? b = ((_ - p) / v + 2) * 60 : b = ((p - u) / v + 4) * 60);
          const k = Math.max(x * 100, 70), y = Math.max(w * 100, 60);
          this._dominantColor = `hsl(${Math.round(b)}, ${Math.round(y)}%, ${Math.round(k)}%)`;
        } else
          this._dominantColor = "var(--primary-color)";
      } catch {
        this._dominantColor = "var(--primary-color)";
      }
    }, t.onerror = () => {
      this._dominantColor = "var(--primary-color)";
    }, t.src = e;
  }
  connectedCallback() {
    super.connectedCallback(), this._resizeObserver = new ResizeObserver(() => {
      this._checkLayout();
    }), this._resizeObserver.observe(this), this._startProgressTimer(), this._visibilityHandler = () => {
      document.hidden ? this._stopIdleTimer() : this._config?.idle_backdrop_cycle && this._idleItems.length > 1 && this._startIdleTimer();
    }, document.addEventListener("visibilitychange", this._visibilityHandler), this._config?.idle_backdrop_cycle && (this._idleItems.length > 1 && !this._idleTimer ? this._startIdleTimer() : this._idleItems.length === 0 && !this._fetchingIdleItems && this.hass && this._fetchIdleLibraryItems());
  }
  disconnectedCallback() {
    super.disconnectedCallback(), this._resizeObserver && this._resizeObserver.disconnect(), this._layoutCheckRaf && (cancelAnimationFrame(this._layoutCheckRaf), this._layoutCheckRaf = null), this._stopProgressTimer(), this._endLongPress(), this._stopIdleTimer(), this._seekingTimer && (clearTimeout(this._seekingTimer), this._seekingTimer = void 0), this._optimisticSeekTimer && (clearTimeout(this._optimisticSeekTimer), this._optimisticSeekTimer = void 0), this._visibilityHandler && (document.removeEventListener("visibilitychange", this._visibilityHandler), this._visibilityHandler = void 0);
  }
  _startProgressTimer() {
    this._stopProgressTimer(), this._progressTimer = window.setInterval(() => {
      if (!this.isConnected || !this.hass || !this._config?.entity) return;
      const e = this.hass.states[this._config.entity];
      if (!e) return;
      (this._config.entity.startsWith("media_player.") ? e.state === "playing" : !e.attributes?.is_paused && !!e.attributes?.item_id) && !this._isDragging && this.requestUpdate();
    }, 1e3);
  }
  _stopProgressTimer() {
    this._progressTimer && (clearInterval(this._progressTimer), this._progressTimer = void 0);
  }
  updated(e) {
    if (super.updated(e), this._checkLayout(), e.has("hass") && this._config?.idle_backdrop_cycle) {
      if (this._idleItems.length === 0 && !this._fetchingIdleItems)
        this._fetchIdleLibraryItems();
      else if (this._config.idle_content_source === "latest_movie" || this._config.idle_content_source === "latest_episode" || this._config.idle_content_source === "latest_both") {
        const t = this._config.idle_content_source === "latest_movie" || this._config.idle_content_source === "latest_both" ? this._getItemFromLatestSensor("movie") : null, i = this._config.idle_content_source === "latest_episode" || this._config.idle_content_source === "latest_both" ? this._getItemFromLatestSensor("episode") : null, o = this._idleItems.map((a) => a.id).join(","), s = [t?.id, i?.id].filter(Boolean).join(",");
        s && s !== o && !this._fetchingIdleItems && this._fetchIdleLibraryItems();
      }
    }
    if (e.has("_config")) {
      this._checkLayout();
      const t = e.get("_config");
      if (!this._config?.idle_backdrop_cycle)
        this._stopIdleTimer();
      else {
        const i = !t || t.idle_display_mode !== this._config.idle_display_mode, o = !t || t.idle_media_type !== this._config.idle_media_type, s = !t || t.idle_content_source !== this._config.idle_content_source, a = !t || t.idle_recent_limit !== this._config.idle_recent_limit;
        i || o || s || a || this._idleItems.length === 0 ? (this._idleItems = [], this._stopIdleTimer(), this._fetchIdleLibraryItems()) : (t?.idle_cycle_interval !== this._config.idle_cycle_interval || !this._idleTimer) && this._startIdleTimer();
      }
    }
  }
  _checkLayout() {
    this._layoutCheckRaf && cancelAnimationFrame(this._layoutCheckRaf), this._layoutCheckRaf = requestAnimationFrame(() => {
      this._layoutCheckRaf = null, this._doLayoutCheck();
    });
  }
  _doLayoutCheck() {
    const e = this.getBoundingClientRect(), t = this.shadowRoot?.querySelector("ha-card");
    if (!t || e.height === 0) return;
    if (t.classList.contains("empty-state") || t.classList.contains("error-state")) {
      t.classList.remove("compact-height", "micro-height", "tall-narrow", "very-tall-narrow", "compact-width");
      return;
    }
    const i = e.height, o = e.width, s = t.classList.contains("compact-height") ? i <= 215 : i <= 205;
    t.classList.toggle("compact-height", s);
    const a = t.classList.contains("micro-height") ? i <= 135 : i <= 125;
    t.classList.toggle("micro-height", a);
    const r = t.classList.contains("tall-narrow") ? i >= 235 && o <= 405 : i >= 245 && o <= 395;
    t.classList.toggle("tall-narrow", r);
    const n = t.classList.contains("very-tall-narrow") ? i >= 295 && o <= 455 : i >= 305 && o <= 445;
    t.classList.toggle("very-tall-narrow", n);
    const c = t.classList.contains("compact-width") ? o <= 310 : o <= 300;
    t.classList.toggle("compact-width", c);
    const p = this.shadowRoot?.querySelector(".title-row") || this.shadowRoot?.querySelector(".title"), u = this.shadowRoot?.querySelector(".info-bottom"), _ = this.shadowRoot?.querySelector(".info-container");
    if (!u) return;
    const g = u.getBoundingClientRect(), m = p ? p.getBoundingClientRect() : null, b = m ? m.bottom : _ ? _.getBoundingClientRect().top + 32 : e.top + 32, x = g.top - b, v = g.bottom - (e.bottom - 6), w = v > 0 ? Math.min(x - v, 0) : x, k = this._config?.entity ? this.hass?.states[this._config.entity] : null, y = k?.attributes, S = k ? this._extractItemId(k) : null, $ = S ? this._resolvedMetadata[S] : null, C = this._config?.show_subtitle !== !1, T = y?.series_title || y?.media_series_title || $?.series_name || "", G = !!(C && (y?.artist_name || y?.media_artist || T || $?.artist_name) || ""), F = this._config?.badge_style || this._config?.media_type_badge_style || "poster", D = this._config?.show_media_type_badge !== !1 && F !== "none" && F === "inline", O = this._config?.show_year !== !1 ? y?.release_year || y?.year || $?.year : "", Z = y?.runtime_minutes || $?.runtime_minutes || 0, L = Z > 0 ? ue(Z) : "", oe = this._config?.show_runtime !== !1 && D && L ? L : "", B = y?.community_rating ?? $?.community_rating ?? $?.rating, U = Number(B), Q = !isNaN(U) && U > 0 ? U.toFixed(1) : B ? String(B) : "", W = this._config?.show_ratings !== !1 && D && Q ? Q : "", me = y?.genres && y.genres.length > 0 ? y.genres : $?.genres || [], fe = this._config?.show_genres !== !1 && me?.length ? me.slice(0, 3) : [], at = fe.length > 0, ot = D || !!O || !!oe || !!W, se = G ? 22 : 0, de = ot ? 29 : 0;
    let ce = 0;
    at && (ot ? ce = 27 : ce = fe.length > 2 ? 56 : 29);
    const ee = y?.user_name || this.hass?.user?.name || "", je = this._config?.show_user !== !1 ? ee : "", Fe = y?.client || k?.attributes?.app_name || k?.attributes?.friendly_name || "", Ie = this._config?.show_client !== !1 ? Fe : "", Be = this._config?.show_device_name === !0 && y?.device_name || "", He = [...new Set([Be, Ie].filter(Boolean))].join(" · "), Ee = !!(je || He) ? 22 : 0, ye = se, Te = ye + de, re = Te + ce, qe = re + Ee, te = w - 4, ve = this._overflowState;
    let H = 4;
    qe + (ve > 0 ? 4 : 0) <= te ? H = 0 : re + (ve > 1 ? 4 : 0) <= te ? H = 1 : Te + (ve > 2 ? 4 : 0) <= te ? H = 2 : ye + (ve > 3 ? 4 : 0) <= te ? H = 3 : H = 4, this._overflowState !== H && (this._overflowState = H);
  }
  _formatSeconds(e) {
    const t = e < 0, i = Math.floor(Math.abs(e)), o = Math.floor(i / 3600), s = Math.floor(i % 3600 / 60), a = i % 60, r = t ? "-" : "";
    return o > 0 ? `${r}${o}:${String(s).padStart(2, "0")}:${String(a).padStart(2, "0")}` : `${r}${s}:${String(a).padStart(2, "0")}`;
  }
  _formatTicks(e) {
    return this._formatSeconds(e / 1e7);
  }
};
E.styles = Pe`
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
            min-height: 0;
            overflow: hidden;
            position: relative;
            background: var(--ha-card-background, var(--card-background-color, #fff));
            border-radius: var(--ha-card-border-radius, 12px);
            box-shadow: var(--ha-card-box-shadow, none);
            border: var(--ha-card-border, 1px solid var(--ha-card-border-color, var(--divider-color, #e0e0e0)));
            transition: background 0.3s ease-out, border-color 0.3s ease-out, box-shadow 0.3s ease-out;
            container-type: inline-size;
            container-name: now-playing;
            display: flex;
            flex-direction: column;
            box-sizing: border-box;
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
        .jellyha-now-playing.has-background .title,
        .jellyha-now-playing.has-background .subtitle {
            text-shadow: 0 1px 3px rgba(0, 0, 0, 0.75);
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
            filter: blur(5px) brightness(0.72);
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
            background: linear-gradient(to bottom, rgba(0, 0, 0, 0.22) 0%, rgba(0, 0, 0, 0.52) 100%);
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
            align-items: stretch;
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
        .poster-container.no-rewind {
            cursor: default;
        }
        .poster-container.no-rewind:hover {
            transform: none;
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
            text-shadow: 0 1px 4px rgba(0, 0, 0, 0.5);
        }
        .poster-badge-group {
            position: absolute;
            top: 6px;
            left: 6px;
            display: inline-flex;
            flex-wrap: wrap;
            gap: 4px;
            z-index: 5;
            pointer-events: none;
            max-width: calc(100% - 12px);
        }
        .poster-badge-group .poster-badge {
            position: static !important;
        }
        .media-type-badge {
            top: 6px;
            left: 6px;
            padding: 2px 8px 1px 8px;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.3px;
            background: var(--primary-color);
            box-shadow: 0 2px 4px rgba(0,0,0,0.3);
            text-shadow: 0 1px 4px rgba(0, 0, 0, 0.5);
        }
        .media-type-badge.movie,
        .media-type-badge.latest-badge.movie {
            background-color: #AA5CC3;
            color: #ffffff;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);
        }
        .media-type-badge.series,
        .media-type-badge.episode,
        .media-type-badge.tvshow,
        .media-type-badge.latest-badge.series,
        .media-type-badge.latest-badge.episode,
        .media-type-badge.latest-badge.tvshow {
            background-color: #F2A218;
            color: #ffffff;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);
        }
        .media-type-badge.audio,
        .media-type-badge.latest-badge.audio {
            background-color: #10B981;
            color: #ffffff;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);
        }
        .media-type-badge.idle-backdrop-top-badge {
            position: absolute !important;
            top: 14px;
            right: 16px;
            left: auto !important;
            bottom: auto !important;
            z-index: 5;
            margin: 0 !important;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: 800;
            letter-spacing: 0.3px;
            text-transform: uppercase;
            padding: 2px 8px 1px 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);
            text-shadow: 0 1px 4px rgba(0, 0, 0, 0.5) !important;
            pointer-events: none;
        }
        .media-type-badge.inline-badge {
            position: static !important;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            height: 22px;
            box-sizing: border-box;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: 800;
            letter-spacing: 0.3px;
            text-transform: uppercase;
            padding: 1.5px 8px 0.5px 8px;
            line-height: 1;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.4);
            text-shadow: 0 1px 4px rgba(0, 0, 0, 0.5) !important;
            pointer-events: none;
            flex-shrink: 0;
        }

        .rating-badge {
            bottom: 6px;
            right: 6px;
            position: absolute;
            z-index: 5;
        }
        .runtime-badge {
            bottom: 6px;
            left: 6px;
            position: absolute;
            z-index: 5;
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
            justify-content: space-between;
            align-self: stretch;
            min-height: 0;
            min-width: 0;
            overflow: hidden;
            position: relative;
        }
        .title-row {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 8px;
            width: 100%;
            flex: 0 0 auto;
            position: relative;
            z-index: 10;
        }

        .title-row .title {
            flex: 1 1 auto;
            min-width: 0;
            margin: 0;
        }

        .header-actions {
            height: 26px;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            flex-shrink: 0;
            margin: 0;
            position: relative;
            z-index: 10;
        }

        .title-row .header-actions {
            margin-left: auto;
        }

        .info-top,
        .info-middle {
            flex: 1 1 auto;
            min-height: 0;
            overflow: hidden;
            display: flex;
            flex-direction: column;
            margin-bottom: 0;
            padding-bottom: 2px;
        }
        .header {
            margin-bottom: 0px;
            flex-shrink: 0;
            min-height: 0;
        }

        .media-type-badge.header-badge {
            position: static !important;
            flex-shrink: 0;
            margin-top: 6px;
            border-radius: 4px;
            font-size: 0.8rem;
            letter-spacing: 0.3px;
            padding: 2px 8px 1px 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.3);
            text-shadow: 0 1px 4px rgba(0, 0, 0, 0.5) !important;
            pointer-events: none;
            align-self: flex-start;
        }

        /* 4-line text structure */
        .title {
            font-size: 1.3rem;
            font-weight: 700;
            line-height: 1.2;
            color: var(--card-dominant-color, var(--primary-text-color));
            margin-top: 2px;
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
            display: flex;
            align-items: center;
            flex-wrap: wrap;
            gap: 5px 8px;
            font-size: 0.85rem;
            color: var(--secondary-text-color);
            opacity: 0.85;
            margin-top: 4px;
            margin-bottom: 3px;
            line-height: 1.2;
        }
        .meta-year,
        .meta-runtime {
            font-size: 0.85rem;
            font-weight: 500;
        }
        .meta-dot {
            opacity: 0.45;
            font-size: 0.72rem;
            line-height: 1;
        }
        ha-card:not(.has-background) .idle-meta-row,
        ha-card:not(.has-background) .meta-line {
            color: var(--secondary-text-color);
            text-shadow: none;
        }
        ha-card:not(.has-background) .idle-meta-text,
        ha-card:not(.has-background) .meta-text {
            color: var(--secondary-text-color);
        }
        ha-card:not(.has-background) .idle-dot,
        ha-card:not(.has-background) .meta-dot {
            color: var(--secondary-text-color);
        }
        ha-card:not(.has-background) .idle-genre-pill,
        ha-card:not(.has-background) .genre-pill {
            background: rgba(var(--rgb-primary-text-color, 255, 255, 255), 0.08);
            border: 1px solid rgba(var(--rgb-primary-text-color, 255, 255, 255), 0.14);
            color: var(--secondary-text-color);
            text-shadow: none;
        }
        .genre-pill {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            height: 22px;
            box-sizing: border-box;
            background: rgba(var(--rgb-primary-text-color, 255, 255, 255), 0.08);
            border: 1px solid rgba(var(--rgb-primary-text-color, 255, 255, 255), 0.14);
            padding: 0 7px;
            border-radius: 4px;
            font-size: 0.80rem;
            color: var(--secondary-text-color);
            line-height: 1;
            font-weight: 500;
            white-space: nowrap;
        }
        .has-background .genre-pill {
            background: rgba(255, 255, 255, 0.12);
            border: 1px solid rgba(255, 255, 255, 0.18);
            color: rgba(255, 255, 255, 0.92);
            text-shadow: 0 1px 2px rgba(0, 0, 0, 0.6);
        }
        .client-line {
            font-size: 0.80rem;
            color: var(--secondary-text-color);
            opacity: 0.70;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            margin-top: 7px;
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
            margin-bottom: 4px;
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

        /* --- Header Actions & Uniform Power Button --- */
        .header-actions {
            height: 26px;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            flex-shrink: 0;
            margin: 0;
        }
        .header-actions .media-type-badge.header-badge {
            margin-top: 0 !important;
            align-self: center !important;
        }
        .idle-backdrop-top-actions {
            position: absolute;
            top: 14px;
            right: 16px;
            z-index: 5;
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }
        .idle-backdrop-top-actions .media-type-badge.idle-backdrop-top-badge {
            position: static !important;
            margin: 0 !important;
        }
        .empty-top-actions {
            position: absolute;
            top: 14px;
            right: 16px;
            z-index: 5;
        }

        .power-btn-hit-area {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            position: relative;
            width: 26px;
            height: 26px;
            flex-shrink: 0;
            cursor: pointer;
            outline: none;
            -webkit-tap-highlight-color: transparent;
            z-index: 10;
        }
        .power-btn-hit-area::before {
            content: '';
            position: absolute;
            top: -11px;
            right: -11px;
            bottom: -11px;
            left: -11px;
            border-radius: 14px;
            cursor: pointer;
            z-index: 1;
        }
        .power-btn-hit-area:hover .power-btn {
            background: rgba(255, 255, 255, 0.2) !important;
            border-color: rgba(255, 255, 255, 0.28) !important;
            box-shadow: 0 1px 4px rgba(0, 0, 0, 0.25) !important;
        }
        .power-btn-hit-area:active .power-btn {
            transform: scale(0.94) !important;
            transition: transform 0.08s ease;
        }
        .power-btn-hit-area:focus-visible .power-btn {
            outline: 2px solid var(--primary-color, #03a9f4) !important;
            outline-offset: 2px;
        }

        .power-btn {
            --mdc-icon-button-size: 26px !important;
            --mdc-icon-size: 16px !important;
            --mdc-ripple-color: transparent !important;
            --ha-ripple-color: transparent !important;
            --md-ripple-hover-color: transparent !important;
            --md-ripple-pressed-color: transparent !important;
            --md-ripple-focus-color: transparent !important;
            width: 26px !important;
            height: 26px !important;
            border-radius: 50% !important;
            overflow: hidden !important;
            background: rgba(255, 255, 255, 0.12) !important;
            border: 1px solid rgba(255, 255, 255, 0.16) !important;
            backdrop-filter: blur(8px);
            -webkit-backdrop-filter: blur(8px);
            box-shadow: 0 1px 4px rgba(0, 0, 0, 0.25);
            padding: 0 !important;
            margin: 0 !important;
            display: inline-flex !important;
            align-items: center !important;
            justify-content: center !important;
            cursor: pointer;
            outline: none !important;
            transition: background 0.15s ease, transform 0.08s ease, border-color 0.15s ease, box-shadow 0.15s ease;
            box-sizing: border-box !important;
            flex-shrink: 0;
            pointer-events: none;
            transform-origin: center center;
        }
        .power-btn ha-icon {
            --mdc-icon-size: 16px !important;
            width: 16px !important;
            height: 16px !important;
            display: flex !important;
            align-items: center !important;
            justify-content: center !important;
            margin: 0 !important;
            padding: 0 !important;
            line-height: 1 !important;
            transform-origin: center center;
        }
        .power-btn:hover {
            background: rgba(255, 255, 255, 0.2) !important;
            border-color: rgba(255, 255, 255, 0.28) !important;
            box-shadow: 0 1px 4px rgba(0, 0, 0, 0.25) !important;
            outline: none !important;
        }
        .power-btn:focus,
        .power-btn:focus-visible {
            outline: none !important;
            box-shadow: 0 1px 4px rgba(0, 0, 0, 0.25) !important;
        }
        ha-icon-button.power-btn::part(ripple) {
            display: none !important;
        }
        ha-icon-button.power-btn mwc-ripple,
        ha-icon-button.power-btn md-ripple {
            display: none !important;
        }
        ha-icon-button.power-btn::part(button) {
            padding: 0 !important;
            display: flex !important;
            align-items: center !important;
            justify-content: center !important;
            width: 100% !important;
            height: 100% !important;
        }
        .power-btn:active {
            transform: scale(0.94) !important;
            transition: transform 0.08s ease;
        }
        .power-btn.is-on,
        .jellyha-now-playing.has-background .power-btn.is-on {
            background: rgba(255, 255, 255, 0.75) !important;
            border: 1px solid rgba(255, 255, 255, 0.75) !important;
            color: #111111 !important;
            box-shadow: 0 1px 4px rgba(0, 0, 0, 0.25) !important;
        }
        .power-btn.is-on ha-icon {
            color: #111111 !important;
        }
        .power-btn-hit-area:hover .power-btn.is-on,
        .power-btn.is-on:hover {
            background: rgba(255, 255, 255, 0.88) !important;
            border-color: rgba(255, 255, 255, 0.88) !important;
            box-shadow: 0 1px 6px rgba(0, 0, 0, 0.35) !important;
            color: #000000 !important;
        }
        .power-btn-hit-area:hover .power-btn.is-on ha-icon,
        .power-btn.is-on:hover ha-icon {
            color: #000000 !important;
        }

        .power-btn.stateless-ready,
        .jellyha-now-playing.has-background .power-btn.stateless-ready {
            color: #ffffff !important;
        }
        .power-btn.stateless-ready ha-icon {
            color: #ffffff !important;
        }
        .power-btn.is-off,
        .jellyha-now-playing.has-background .power-btn.is-off {
            color: rgba(255, 255, 255, 0.45) !important;
        }
        .power-btn.is-off ha-icon {
            color: rgba(255, 255, 255, 0.45) !important;
        }
        .power-btn.activating {
            animation: powerTap 0.2s ease-out;
        }
        @keyframes powerTap {
            0% { transform: scale(0.94); }
            100% { transform: scale(1); }
        }

        /* --- Option 1 Capsule Volume Slider --- */
        .volume-capsule {
            height: 38px;
            box-sizing: border-box;
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 0 8px;
            background: rgba(255, 255, 255, 0.15);
            border-radius: 9999px;
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            border: none;
            box-shadow: 0 4px 16px rgba(0, 0, 0, 0.28);
            margin-top: 4px;
            margin-bottom: 4px;
            width: 100%;
        }
        .volume-capsule.no-step-buttons {
            padding-right: 14px;
        }
        .volume-capsule.no-step-buttons .volume-pct {
            margin-right: 0;
        }
        .volume-btn {
            --mdc-icon-button-size: 28px !important;
            --mdc-icon-size: 18px !important;
            --mdc-ripple-color: transparent !important;
            --ha-icon-button-inactive-color: rgba(255, 255, 255, 0.85) !important;
            width: 28px !important;
            height: 28px !important;
            padding: 0 !important;
            margin: 0 !important;
            display: inline-flex !important;
            align-items: center;
            justify-content: center;
            border-radius: 50% !important;
            overflow: hidden !important;
            background: transparent !important;
            border: none !important;
            box-shadow: none !important;
            filter: none !important;
            text-shadow: none !important;
            cursor: pointer;
            transition: background 0.15s ease, color 0.15s ease, transform 0.1s ease;
            flex-shrink: 0;
            box-sizing: border-box;
        }
        .volume-btn:hover {
            background: rgba(255, 255, 255, 0.18) !important;
            color: #ffffff !important;
            box-shadow: none !important;
            filter: none !important;
            text-shadow: none !important;
        }
        .volume-btn:active {
            background: rgba(255, 255, 255, 0.28) !important;
            transform: scale(0.92) !important;
            box-shadow: none !important;
            filter: none !important;
        }
        ha-icon-button.volume-btn::part(ripple) {
            display: none !important;
        }
        ha-icon-button.volume-btn ha-icon {
            box-shadow: none !important;
            filter: none !important;
            text-shadow: none !important;
            background: transparent !important;
        }
        .mute-btn {
            color: #ffffff !important;
            --mdc-icon-size: 18px !important;
        }
        .mute-btn.muted,
        .mute-btn.muted ha-icon {
            color: #ef4444 !important;
        }
        .volume-step-btn,
        .jellyha-now-playing.has-background .volume-step-btn {
            --mdc-icon-button-size: 28px !important;
            --mdc-icon-size: 16px !important;
            width: 28px !important;
            height: 28px !important;
            color: rgba(255, 255, 255, 0.75) !important;
            border-radius: 50% !important;
            overflow: hidden !important;
        }
        .volume-step-btn ha-icon {
            color: rgba(255, 255, 255, 0.75) !important;
            background: transparent !important;
        }
        .volume-step-btn:hover,
        .volume-step-btn:hover ha-icon {
            color: #ffffff !important;
        }
        .volume-slider-track {
            flex: 1;
            height: 12px;
            background: rgba(255, 255, 255, 0.20);
            border-radius: 9999px;
            position: relative;
            cursor: pointer;
            touch-action: none;
            display: flex;
            align-items: center;
        }
        .volume-slider-fill {
            position: absolute;
            left: 0;
            top: 0;
            height: 100%;
            border-radius: 9999px;
            pointer-events: none;
            overflow: hidden;
        }
        .volume-slider-fill::after {
            content: '';
            position: absolute;
            right: 0;
            top: 0;
            bottom: 0;
            width: 28px;
            max-width: 100%;
            background: linear-gradient(to right, transparent 0%, rgba(0, 0, 0, 0.28) 100%);
            pointer-events: none;
        }
        .volume-slider-thumb {
            position: absolute;
            top: 50%;
            width: 14px;
            height: 14px;
            border-radius: 50%;
            transform: translate(-50%, -50%);
            box-shadow: -2px 0 6px rgba(0, 0, 0, 0.28), 0 1px 2px rgba(0, 0, 0, 0.2);
            filter: blur(0.5px);
            pointer-events: none;
            transition: transform 0.1s ease;
        }
        .volume-slider-track:hover .volume-slider-thumb,
        .volume-slider-track:active .volume-slider-thumb {
            transform: translate(-50%, -50%) scale(1.1);
        }
        .volume-pct {
            font-size: 13px;
            font-weight: 600;
            color: rgba(255, 255, 255, 0.9);
            min-width: 32px;
            text-align: right;
            margin-left: 2px;
            margin-right: 2px;
            user-select: none;
            flex-shrink: 0;
            font-variant-numeric: tabular-nums;
        }

        /* --- Progress bar with seek handle --- */
        .progress-container {
            cursor: pointer;
            position: relative;
            width: 100%;
            padding: 4px 0;
            box-sizing: border-box;
            touch-action: none;
            z-index: 10;
        }
        .progress-container.readonly {
            cursor: default;
        }
        .progress-container.readonly .seek-handle {
            display: none;
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
            position: relative;
            z-index: 10;
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
            min-height: 140px;
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
            min-height: 0;
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
            .empty-state {
                padding: 14px 10px !important;
                min-height: 120px !important;
            }
            .empty-state .logo-container.full-logo {
                display: none;
            }
            .empty-state .logo-container.mini-icon {
                display: flex;
                opacity: 0.9;
                margin-bottom: 8px;
            }
            .empty-state img {
                max-width: 64px;
            }
            .empty-state p {
                font-size: 0.85rem;
                line-height: 1.25;
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

        /* Adjust layout when very narrow / minimized */
        @container now-playing (max-width: 380px) {
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
            .header-badge {
                font-size: 0.7rem;
                padding: 1px 5px;
            }
            .volume-slider-track,
            .volume-slider-thumb,
            .volume-slider-fill {
                display: none !important;
            }
            .volume-capsule {
                gap: 6px !important;
                padding: 0 8px !important;
                margin-top: 6px !important;
                margin-bottom: 6px !important;
            }
            .volume-pct {
                flex: 1 !important;
                text-align: center !important;
                margin: 0 !important;
            }
        }

        ha-card.compact-width .volume-slider-track,
        ha-card.tall-narrow .volume-slider-track,
        ha-card.very-tall-narrow .volume-slider-track,
        ha-card.micro-height .volume-slider-track,
        ha-card.compact-width .volume-slider-thumb,
        ha-card.tall-narrow .volume-slider-thumb,
        ha-card.very-tall-narrow .volume-slider-thumb,
        ha-card.micro-height .volume-slider-thumb,
        ha-card.compact-width .volume-slider-fill,
        ha-card.tall-narrow .volume-slider-fill,
        ha-card.very-tall-narrow .volume-slider-fill,
        ha-card.micro-height .volume-slider-fill {
            display: none !important;
        }
        ha-card.compact-width .volume-capsule,
        ha-card.tall-narrow .volume-capsule,
        ha-card.very-tall-narrow .volume-capsule,
        ha-card.micro-height .volume-capsule {
            gap: 6px !important;
            padding: 0 8px !important;
            margin-top: 6px !important;
            margin-bottom: 6px !important;
        }
        ha-card.compact-width .volume-pct,
        ha-card.tall-narrow .volume-pct,
        ha-card.very-tall-narrow .volume-pct,
        ha-card.micro-height .volume-pct {
            flex: 1 !important;
            text-align: center !important;
            margin: 0 !important;
        }

        ha-card:not(.empty-state):not(.error-state).compact-height .card-header {
            display: none !important;
        }
        ha-card:not(.empty-state):not(.error-state).compact-height .card-content,
        ha-card:not(.empty-state):not(.error-state).compact-height .jellyha-now-playing.has-background .card-content,
        .jellyha-now-playing.has-background ha-card:not(.empty-state):not(.error-state).compact-height .card-content {
            gap: 6px !important;
            padding: 10px 14px 8px !important;
        }
        ha-card:not(.empty-state):not(.error-state).compact-height .title-row {
            gap: 6px !important;
            align-items: center !important;
        }
        ha-card:not(.empty-state):not(.error-state).compact-height .title {
            font-size: 1.25rem !important;
            line-height: 1.2 !important;
            margin: 0 !important;
        }
        ha-card:not(.empty-state):not(.error-state).compact-height .header-actions {
            margin: 0 !important;
            height: 26px !important;
        }
        ha-card:not(.empty-state):not(.error-state).compact-height .header-badge {
            margin-top: 0 !important;
            font-size: 0.75rem !important;
            padding: 1px 6px !important;
        }
        ha-card:not(.empty-state):not(.error-state).compact-height .main-container {
            gap: 12px !important;
        }
        ha-card:not(.empty-state):not(.error-state).compact-height .poster-container {
            min-height: 0;
            --short-badge-padding: 1px !important;
        }
        ha-card:not(.empty-state):not(.error-state).compact-height .playback-controls {
            margin-bottom: 3px !important;
            gap: 8px !important;
        }
        ha-card:not(.empty-state):not(.error-state).compact-height .volume-capsule {
            margin-top: 3px !important;
            margin-bottom: 3px !important;
        }
        ha-card:not(.empty-state):not(.error-state).compact-height .progress-container {
            padding: 2px 0 !important;
            position: relative;
            z-index: 10;
        }
        ha-card:not(.empty-state):not(.error-state).compact-height .timestamps {
            margin-top: 2px !important;
            line-height: 1.1 !important;
            position: relative;
            z-index: 10;
        }

        /* Ultra-Compact Micro Mode (Overlay controls on poster) */
        @container now-playing (max-width: 250px) {
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
            .volume-slider-track,
            .volume-slider-thumb,
            .volume-slider-fill {
                display: none !important;
            }
            .volume-capsule {
                gap: 6px !important;
                padding: 0 8px !important;
                margin-top: 6px !important;
                margin-bottom: 6px !important;
            }
            .volume-pct {
                flex: 1 !important;
                text-align: center !important;
                margin: 0 !important;
            }
        }

        /* Height-Based Compact Mode */
        ha-card:not(.empty-state):not(.error-state).micro-height {
            .card-header {
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
            .volume-slider-track,
            .volume-slider-thumb,
            .volume-slider-fill {
                display: none !important;
            }
            .volume-capsule {
                gap: 6px !important;
                padding: 0 8px !important;
                margin-top: 6px !important;
                margin-bottom: 6px !important;
            }
            .volume-pct {
                flex: 1 !important;
                text-align: center !important;
                margin: 0 !important;
            }
        }

        /* Tall but Narrow Mode */
        ha-card:not(.empty-state):not(.error-state).tall-narrow {
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
            .volume-slider-track,
            .volume-slider-thumb,
            .volume-slider-fill {
                display: none !important;
            }
            .volume-capsule {
                gap: 6px !important;
                padding: 0 8px !important;
                margin-top: 6px !important;
                margin-bottom: 6px !important;
            }
            .volume-pct {
                flex: 1 !important;
                text-align: center !important;
                margin: 0 !important;
            }
        }

        /* Very Tall but Narrow Mode */
        ha-card:not(.empty-state):not(.error-state).very-tall-narrow {
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
            .volume-slider-track,
            .volume-slider-thumb,
            .volume-slider-fill {
                display: none !important;
            }
            .volume-capsule {
                gap: 6px !important;
                padding: 0 8px !important;
                margin-top: 6px !important;
                margin-bottom: 6px !important;
            }
            .volume-pct {
                flex: 1 !important;
                text-align: center !important;
                margin: 0 !important;
            }
        }

        /* =========================================================================
           Ambient Idle Showcase Styles
           ========================================================================= */
        .idle-showcase-card {
            position: relative;
            min-height: 180px;
            overflow: hidden;
            display: flex;
            flex-direction: column;
            justify-content: flex-end !important;
            box-sizing: border-box;
            cursor: default;
            user-select: none;
            border-radius: var(--ha-card-border-radius, 12px);
            background: #111;
        }

        .idle-backdrop-container {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            overflow: hidden;
            pointer-events: none;
        }

        .idle-backdrop-img {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            object-fit: cover;
            object-position: center;
            opacity: 1;
            transition: opacity 0.8s ease-in-out;
            will-change: opacity;
        }

        .idle-backdrop-img.prev-backdrop {
            z-index: 2;
        }

        .idle-backdrop-img.prev-backdrop.fade-out {
            opacity: 0;
        }

        .idle-backdrop-scrim {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: linear-gradient(
                180deg,
                rgba(0, 0, 0, 0.35) 0%,
                rgba(0, 0, 0, 0) 25%,
                rgba(0, 0, 0, 0) 55%,
                rgba(0, 0, 0, 0.22) 72%,
                rgba(0, 0, 0, 0.55) 88%,
                rgba(0, 0, 0, 0.82) 100%
            );
            pointer-events: none;
            z-index: 3;
        }

        .idle-bottom-content {
            position: relative;
            z-index: 4;
            padding: 16px 20px 20px 20px;
            display: flex;
            flex-direction: column;
            gap: 0 !important;
            margin-top: auto;
        }

        ha-card .idle-title,
        .idle-title {
            margin: 0 !important;
            padding: 0 !important;
            font-size: 1.35rem;
            font-weight: 700;
            line-height: 1.2;
            color: #ffffff !important;
            text-shadow: 0 1px 3px rgba(0, 0, 0, 0.65);
            display: -webkit-box;
            -webkit-line-clamp: 2;
            -webkit-box-orient: vertical;
            overflow: hidden;
        }

        ${qt}

        .idle-overview {
            margin: 2px 0 0 0 !important;
            font-size: 12px !important;
            line-height: 1.35;
            color: rgba(255, 255, 255, 0.72);
            text-shadow: 0 1px 3px rgba(0, 0, 0, 0.85);
            display: -webkit-box;
            -webkit-line-clamp: 2;
            -webkit-box-orient: vertical;
            overflow: hidden;
        }

        .idle-card-mode {
            cursor: default;
        }

        .idle-card-mode .info-container {
            justify-content: flex-start;
        }

        .idle-card-mode .poster-container {
            position: relative;
            overflow: hidden;
        }

        .idle-card-mode .poster-container .idle-poster-img {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            object-fit: cover;
            border-radius: 8px;
        }

        .idle-card-mode .poster-container .idle-poster-img.prev-poster {
            z-index: 2;
            opacity: 1;
            transition: opacity 0.8s ease-in-out;
            will-change: opacity;
        }

        .idle-card-mode .poster-container .idle-poster-img.prev-poster.fade-out {
            opacity: 0;
        }

        .idle-card-mode .idle-card-bg-container {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            overflow: hidden;
            pointer-events: none;
            z-index: 0;
            border-radius: var(--ha-card-border-radius, 12px);
            background: #111;
        }

        .idle-card-mode .idle-card-bg-img {
            position: absolute;
            top: -5%;
            left: -5%;
            width: 110%;
            height: 110%;
            object-fit: cover;
            object-position: center;
            filter: blur(5px) brightness(0.72);
            opacity: 1;
        }

        .idle-card-mode .card-overlay {
            background: linear-gradient(to bottom, rgba(0, 0, 0, 0.22) 0%, rgba(0, 0, 0, 0.52) 100%);
        }

        .idle-card-mode .idle-card-bg-img.prev-bg {
            z-index: 1;
            opacity: 1;
            transition: opacity 0.8s ease-in-out;
            will-change: opacity;
        }

        .idle-card-mode .idle-card-bg-img.prev-bg.fade-out {
            opacity: 0;
        }

        .idle-card-mode .title {
            color: #ffffff !important;
            text-shadow: 0 1px 3px rgba(0, 0, 0, 0.65);
            margin-top: 4px;
            margin-bottom: 0;
            line-height: 1.25;
        }

        .idle-showcase-card .subtitle-row,
        .idle-card-mode .subtitle-row {
            margin-top: 5px;
            margin-bottom: 0;
        }

        .idle-showcase-card .subtitle,
        .idle-card-mode .subtitle,
        .idle-bottom-content .subtitle {
            font-size: 1.05rem;
            font-weight: 400;
            color: rgba(255, 255, 255, 0.78);
            text-shadow: 0 1px 3px rgba(0, 0, 0, 0.85);
            margin: 0;
            line-height: 1.25;
            display: inline-block;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            max-width: 100%;
        }

        /* Movie / no subtitle: Title followed directly by meta row */
        .idle-card-mode .title-row + .meta-line,
        .idle-card-mode .title-row + .idle-meta-row,
        .idle-showcase-card .title-row + .idle-meta-row {
            margin-top: 8px !important;
            margin-bottom: 6px !important;
        }

        /* Episode / with subtitle: Subtitle row followed by meta row */
        .idle-card-mode .subtitle-row + .meta-line,
        .idle-card-mode .subtitle-row + .idle-meta-row,
        .idle-showcase-card .subtitle-row + .idle-meta-row {
            margin-top: 5px !important;
            margin-bottom: 6px !important;
        }

        .idle-card-desc {
            font-size: 12px !important;
            color: rgba(255, 255, 255, 0.72);
            line-height: 1.35;
            margin-top: 2px;
            display: -webkit-box;
            -webkit-line-clamp: 3;
            -webkit-box-orient: vertical;
            overflow: hidden;
            text-shadow: 0 1px 2px rgba(0, 0, 0, 0.8);
        }

        .idle-showcase-card .idle-meta-row,
        .idle-card-mode .idle-meta-row,
        .idle-card-mode .meta-line,
        .idle-showcase-card .meta-text,
        .idle-card-mode .meta-text,
        .idle-showcase-card .meta-dot,
        .idle-card-mode .meta-dot,
        .idle-showcase-card .rating-pill,
        .idle-card-mode .rating-pill,
        .idle-showcase-card .genre-pill,
        .idle-card-mode .genre-pill {
            font-size: 12px !important;
        }

        @container now-playing (max-width: 320px) {
            .idle-overview {
                display: none !important;
            }
            .idle-title {
                font-size: 1.15rem !important;
            }
        }

        @container now-playing (max-width: 250px) {
            .idle-meta-row .idle-genre-pill {
                display: none !important;
            }
            .idle-bottom-content {
                padding: 10px !important;
            }
            .idle-title {
                font-size: 1rem !important;
            }
        }

        /* =========================================================================
           Full Artwork Playback Mode Styles
           ========================================================================= */
        .full-art-playing-card {
            position: relative;
            height: 100%;
            min-height: 0;
            overflow: hidden;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            box-sizing: border-box;
            border-radius: var(--ha-card-border-radius, 12px);
            background: #111;
        }

        .full-art-playing-card .full-art-backdrop-container {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            overflow: hidden;
            pointer-events: none;
            z-index: 0;
        }

        .full-art-playing-card .full-art-hero-img {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            object-fit: cover;
            object-position: center center;
            opacity: 1;
            transition: opacity 0.5s ease;
        }

        .full-art-playing-card .full-art-hero-img.poster-source {
            object-position: center 15%;
        }

        .full-art-playing-card .full-art-scrim {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: linear-gradient(
                180deg,
                rgba(0, 0, 0, 0.72) 0%,
                rgba(0, 0, 0, 0.45) 22%,
                rgba(0, 0, 0, 0.12) 42%,
                rgba(0, 0, 0, 0.45) 68%,
                rgba(0, 0, 0, 0.82) 88%,
                rgba(0, 0, 0, 0.95) 100%
            );
            pointer-events: none;
            z-index: 1;
        }

        .full-art-playing-card .full-art-top-overlay {
            position: relative;
            z-index: 3;
            display: flex;
            flex-direction: column;
            gap: 4px;
            padding: 12px 16px 0 16px;
            box-sizing: border-box;
        }

        .full-art-playing-card .full-art-top-overlay .card-header {
            margin: 0 0 2px 0;
            padding: 0;
            color: #fff;
            text-shadow: 0 1px 3px rgba(0, 0, 0, 0.85);
            font-size: 1.05rem;
            font-weight: 500;
        }

        .full-art-playing-card .full-art-header-row {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            min-height: 28px;
        }

        .full-art-playing-card .full-art-header-row .title-row {
            display: flex;
            align-items: center;
            gap: 8px;
            flex: 1;
            min-width: 0;
            margin: 0;
        }

        .full-art-playing-card .full-art-header-row .title {
            font-size: 1.35rem;
            font-weight: 700;
            line-height: 1.2;
            color: #ffffff;
            text-shadow: 0 1px 3px rgba(0, 0, 0, 0.85);
            display: -webkit-box;
            -webkit-line-clamp: 2;
            -webkit-box-orient: vertical;
            overflow: hidden;
            margin: 0;
        }

        .full-art-playing-card .full-art-header-row .header-actions {
            display: flex;
            align-items: center;
            gap: 8px;
            margin-left: auto;
            flex-shrink: 0;
        }

        .full-art-playing-card .full-art-top-overlay .subtitle {
            font-size: 0.95rem;
            font-weight: 400;
            color: rgba(255, 255, 255, 0.85);
            text-shadow: 0 1px 2px rgba(0, 0, 0, 0.8);
            line-height: 1.2;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .full-art-playing-card .full-art-top-overlay .client-line {
            font-size: 0.8rem;
            color: rgba(255, 255, 255, 0.75);
            text-shadow: 0 1px 2px rgba(0, 0, 0, 0.8);
            line-height: 1.2;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .full-art-playing-card .full-art-overview {
            font-size: 12px;
            color: rgba(255, 255, 255, 0.75);
            line-height: 1.35;
            display: -webkit-box;
            -webkit-line-clamp: 2;
            -webkit-box-orient: vertical;
            overflow: hidden;
            text-shadow: 0 1px 2px rgba(0, 0, 0, 0.8);
        }

        .full-art-playing-card .full-art-bottom-overlay {
            position: relative;
            z-index: 3;
            padding: 8px 16px 12px 16px;
            display: flex;
            flex-direction: column;
            gap: 4px;
            margin-top: auto;
            box-sizing: border-box;
            flex-shrink: 0;
        }

        .full-art-playing-card .playback-controls {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 12px;
            margin: 2px 0;
            flex-shrink: 0;
        }

        .full-art-playing-card .volume-capsule {
            margin: 2px 0 !important;
            flex-shrink: 0;
        }

        .full-art-playing-card .progress-container {
            width: 100%;
            margin-top: 2px;
            flex-shrink: 0;
            box-sizing: border-box;
        }

        .full-art-playing-card .timestamps {
            display: flex;
            justify-content: space-between;
            font-size: 0.75rem;
            color: rgba(255, 255, 255, 0.85);
            text-shadow: 0 1px 2px rgba(0, 0, 0, 0.7);
            margin-top: 2px;
            margin-bottom: 2px;
            line-height: 1.2;
            flex-shrink: 0;
            padding: 0 2px;
            overflow: visible;
        }

        @container now-playing (max-width: 380px) {
            .full-art-playing-card .full-art-top-overlay {
                padding: 10px 12px 0 12px;
                gap: 3px;
            }
            .full-art-playing-card .full-art-header-row .title {
                font-size: 1.15rem;
            }
            .full-art-playing-card .full-art-bottom-overlay {
                padding: 6px 12px 10px 12px;
                gap: 3px;
            }
            .full-art-playing-card .playback-controls {
                gap: 6px;
            }
        }

    `;
M([
  V({ attribute: !1 })
], E.prototype, "hass", 2);
M([
  f()
], E.prototype, "_config", 2);
M([
  f()
], E.prototype, "_rewindActive", 2);
M([
  f()
], E.prototype, "_overflowState", 2);
M([
  f()
], E.prototype, "_dominantColor", 2);
M([
  f()
], E.prototype, "_longPressProgress", 2);
M([
  f()
], E.prototype, "_stopPulse", 2);
M([
  f()
], E.prototype, "_isDragging", 2);
M([
  f()
], E.prototype, "_dragPercentage", 2);
M([
  f()
], E.prototype, "_optimisticSeekPercent", 2);
M([
  f()
], E.prototype, "_isSeeking", 2);
M([
  f()
], E.prototype, "_powerActivating", 2);
M([
  f()
], E.prototype, "_isVolumeDragging", 2);
M([
  f()
], E.prototype, "_dragVolumePercent", 2);
M([
  f()
], E.prototype, "_optimisticVolume", 2);
M([
  f()
], E.prototype, "_idleItems", 2);
M([
  f()
], E.prototype, "_currentIdleIndex", 2);
M([
  f()
], E.prototype, "_prevIdleIndex", 2);
M([
  f()
], E.prototype, "_idleFadeOut", 2);
E = M([
  ge("jellyha-now-playing-card")
], E);
function ke(e) {
  const t = e.shadowRoot;
  if (!t) return;
  const i = t.querySelector(".progress-slider");
  if (!i) return;
  if ((i.hasAttribute("disabled") || i.disabled) && (i.removeAttribute("disabled"), i.disabled = !1), i.style.pointerEvents = "auto", i.style.cursor = "pointer", i.shadowRoot) {
    i.shadowRoot.querySelectorAll("[disabled]").forEach((r) => {
      r.removeAttribute("disabled"), r.disabled = !1;
    });
    const a = i.shadowRoot.querySelector("#slider");
    a && a.classList.contains("disabled") && a.classList.remove("disabled");
  }
  const o = e._browserPlayer?.player;
  if (o && Number.isFinite(o.duration) && o.duration > 0 && (i.max = o.duration), e._browserPlayer) {
    const s = e._browserPlayer.constructor;
    s && !s.prototype.seek && (s.prototype.seek = function(a) {
      this.player && (this.player.currentTime = a);
    });
  }
  if (!i._jellyhaObserver) {
    const s = new MutationObserver((a) => {
      for (const r of a)
        if (r.type === "attributes" && r.attributeName === "disabled" && (i.hasAttribute("disabled") && (i.removeAttribute("disabled"), i.disabled = !1), i.shadowRoot)) {
          const n = i.shadowRoot.querySelector("#slider");
          n && n.classList.contains("disabled") && n.classList.remove("disabled");
        }
    });
    s.observe(i, { attributes: !0, attributeFilter: ["disabled"] }), i._jellyhaObserver = s;
  }
  if (!i._jellyhaEventsAttached) {
    i._jellyhaEventsAttached = !0;
    let s = !1;
    i._isJellyHaDragging = () => s;
    const a = () => {
      s = !0;
    }, r = (n) => {
      if (!s) return;
      s = !1;
      const c = Number(n.detail?.value ?? i.value ?? n.target?.value);
      Number.isFinite(c) && e._browserPlayer?.player && (e._browserPlayer.player.currentTime = c);
    };
    i.addEventListener("pointerdown", a, { passive: !0 }), i.addEventListener("touchstart", a, { passive: !0 }), i.addEventListener("mousedown", a, { passive: !0 }), i.addEventListener("pointerup", r, { passive: !0 }), i.addEventListener("touchend", r, { passive: !0 }), i.addEventListener("mouseup", r, { passive: !0 }), i.addEventListener("change", (n) => {
      const c = Number(n.detail?.value ?? i.value ?? n.target?.value);
      Number.isFinite(c) && e._browserPlayer?.player && (e._browserPlayer.player.currentTime = c);
    }), i.addEventListener("click", (n) => {
      queueMicrotask(() => {
        const c = Number(i.value ?? n.detail?.value ?? n.target?.value);
        Number.isFinite(c) && e._browserPlayer?.player && (e._browserPlayer.player.currentTime = c);
      });
    }), i.addEventListener("input", (n) => {
      const c = Number(n.detail?.value ?? i.value ?? n.target?.value);
      if (Number.isFinite(c)) {
        const p = e.shadowRoot?.querySelector("#CurrentProgress");
        if (p) {
          const u = Math.floor(c / 60), _ = Math.floor(c % 60);
          p.innerHTML = `${u}:${_ < 10 ? "0" : ""}${_}`;
        }
      }
    });
  }
}
function Ge(e) {
  if (!e || e._jellyhaSeekPatched) return;
  e._jellyhaSeekPatched = !0;
  const t = e.prototype._handleMediaSeekChanged;
  e.prototype._handleMediaSeekChanged = function(n) {
    if (this.entityId === "browser" && this._browserPlayer?.player) {
      const c = Number(n.detail?.value ?? n.target?.value);
      if (Number.isFinite(c) && (this._browserPlayer.player.currentTime = c, this._currentProgress)) {
        const p = Math.floor(c / 60), u = Math.floor(c % 60);
        this._currentProgress.innerHTML = `${p}:${u < 10 ? "0" : ""}${u}`;
      }
      return;
    }
    t && t.call(this, n);
  };
  const i = Object.getOwnPropertyDescriptor(e.prototype, "_stateObj");
  if (i && i.get) {
    const n = i.get;
    Object.defineProperty(e.prototype, "_stateObj", {
      get() {
        const c = n.call(this);
        return this.entityId === "browser" && c && (c.attributes || (c.attributes = {}), c.attributes.supported_features = (c.attributes.supported_features || 0) | 2), c;
      },
      configurable: !0,
      enumerable: !0
    });
  }
  const o = e.prototype._updateProgressBar;
  e.prototype._updateProgressBar = function() {
    const n = this._progressBar;
    n?._isJellyHaDragging && n._isJellyHaDragging() || (o && o.call(this), this.entityId === "browser" && ke(this));
  };
  const s = e.prototype.updated;
  e.prototype.updated = function(n) {
    s && s.call(this, n), this.entityId === "browser" && ke(this);
  };
  const a = e.prototype.render;
  a && (e.prototype.render = function() {
    const n = a.call(this);
    return this.entityId === "browser" && (queueMicrotask(() => ke(this)), requestAnimationFrame(() => ke(this))), n;
  });
  const r = Object.getOwnPropertyDescriptor(e.prototype, "_progressBar");
  if (r && r.get) {
    const n = r.get;
    Object.defineProperty(e.prototype, "_progressBar", {
      get() {
        const c = n.call(this);
        return this.entityId === "browser" && c && ke(this), c;
      },
      configurable: !0,
      enumerable: !0
    });
  }
  console.info("JellyHA: Successfully installed ha-bar-media-player seek polyfill.");
}
const Lt = customElements.get("ha-bar-media-player");
if (Lt)
  Ge(Lt);
else if (typeof customElements.whenDefined == "function" && customElements.whenDefined("ha-bar-media-player").then(() => {
  const e = customElements.get("ha-bar-media-player");
  e && Ge(e);
}).catch(() => {
}), !customElements.define.__jellyha_bar_patched) {
  const e = customElements, t = e.define.bind(e), i = e.get.bind(e), o = function(s, a, r) {
    if (s !== "ha-bar-media-player")
      return t(s, a, r);
    if (i(s)) {
      Ge(a);
      return;
    }
    t(s, a, r), Ge(a);
  };
  o.__jellyha_bar_patched = !0, customElements.define = o;
}
function Nt() {
  document.querySelectorAll("ha-bar-media-player").forEach((t) => {
    t.entityId === "browser" && ke(t);
  });
}
typeof window < "u" && (window.addEventListener("location-changed", () => setTimeout(Nt, 150)), window.addEventListener("popstate", () => setTimeout(Nt, 150)));
//# sourceMappingURL=jellyha-cards.js.map
