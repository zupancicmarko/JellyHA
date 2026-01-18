/**
 * @license
 * Copyright 2019 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const U = globalThis, F = U.ShadowRoot && (U.ShadyCSS === void 0 || U.ShadyCSS.nativeShadow) && "adoptedStyleSheets" in Document.prototype && "replace" in CSSStyleSheet.prototype, Y = Symbol(), tt = /* @__PURE__ */ new WeakMap();
let ut = class {
  constructor(t, i, s) {
    if (this._$cssResult$ = !0, s !== Y) throw Error("CSSResult is not constructable. Use `unsafeCSS` or `css` instead.");
    this.cssText = t, this.t = i;
  }
  get styleSheet() {
    let t = this.o;
    const i = this.t;
    if (F && t === void 0) {
      const s = i !== void 0 && i.length === 1;
      s && (t = tt.get(i)), t === void 0 && ((this.o = t = new CSSStyleSheet()).replaceSync(this.cssText), s && tt.set(i, t));
    }
    return t;
  }
  toString() {
    return this.cssText;
  }
};
const yt = (e) => new ut(typeof e == "string" ? e : e + "", void 0, Y), q = (e, ...t) => {
  const i = e.length === 1 ? e[0] : t.reduce((s, a, o) => s + ((r) => {
    if (r._$cssResult$ === !0) return r.cssText;
    if (typeof r == "number") return r;
    throw Error("Value passed to 'css' function must be a 'css' function result: " + r + ". Use 'unsafeCSS' to pass non-literal values, but take care to ensure page security.");
  })(a) + e[o + 1], e[0]);
  return new ut(i, e, Y);
}, wt = (e, t) => {
  if (F) e.adoptedStyleSheets = t.map((i) => i instanceof CSSStyleSheet ? i : i.styleSheet);
  else for (const i of t) {
    const s = document.createElement("style"), a = U.litNonce;
    a !== void 0 && s.setAttribute("nonce", a), s.textContent = i.cssText, e.appendChild(s);
  }
}, et = F ? (e) => e : (e) => e instanceof CSSStyleSheet ? ((t) => {
  let i = "";
  for (const s of t.cssRules) i += s.cssText;
  return yt(i);
})(e) : e;
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const { is: bt, defineProperty: xt, getOwnPropertyDescriptor: $t, getOwnPropertyNames: Ct, getOwnPropertySymbols: St, getPrototypeOf: Pt } = Object, H = globalThis, it = H.trustedTypes, At = it ? it.emptyScript : "", kt = H.reactiveElementPolyfillSupport, T = (e, t) => e, R = { toAttribute(e, t) {
  switch (t) {
    case Boolean:
      e = e ? At : null;
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
} }, V = (e, t) => !bt(e, t), st = { attribute: !0, type: String, converter: R, reflect: !1, useDefault: !1, hasChanged: V };
Symbol.metadata ??= Symbol("metadata"), H.litPropertyMetadata ??= /* @__PURE__ */ new WeakMap();
let P = class extends HTMLElement {
  static addInitializer(t) {
    this._$Ei(), (this.l ??= []).push(t);
  }
  static get observedAttributes() {
    return this.finalize(), this._$Eh && [...this._$Eh.keys()];
  }
  static createProperty(t, i = st) {
    if (i.state && (i.attribute = !1), this._$Ei(), this.prototype.hasOwnProperty(t) && ((i = Object.create(i)).wrapped = !0), this.elementProperties.set(t, i), !i.noAccessor) {
      const s = Symbol(), a = this.getPropertyDescriptor(t, s, i);
      a !== void 0 && xt(this.prototype, t, a);
    }
  }
  static getPropertyDescriptor(t, i, s) {
    const { get: a, set: o } = $t(this.prototype, t) ?? { get() {
      return this[i];
    }, set(r) {
      this[i] = r;
    } };
    return { get: a, set(r) {
      const c = a?.call(this);
      o?.call(this, r), this.requestUpdate(t, c, s);
    }, configurable: !0, enumerable: !0 };
  }
  static getPropertyOptions(t) {
    return this.elementProperties.get(t) ?? st;
  }
  static _$Ei() {
    if (this.hasOwnProperty(T("elementProperties"))) return;
    const t = Pt(this);
    t.finalize(), t.l !== void 0 && (this.l = [...t.l]), this.elementProperties = new Map(t.elementProperties);
  }
  static finalize() {
    if (this.hasOwnProperty(T("finalized"))) return;
    if (this.finalized = !0, this._$Ei(), this.hasOwnProperty(T("properties"))) {
      const i = this.properties, s = [...Ct(i), ...St(i)];
      for (const a of s) this.createProperty(a, i[a]);
    }
    const t = this[Symbol.metadata];
    if (t !== null) {
      const i = litPropertyMetadata.get(t);
      if (i !== void 0) for (const [s, a] of i) this.elementProperties.set(s, a);
    }
    this._$Eh = /* @__PURE__ */ new Map();
    for (const [i, s] of this.elementProperties) {
      const a = this._$Eu(i, s);
      a !== void 0 && this._$Eh.set(a, i);
    }
    this.elementStyles = this.finalizeStyles(this.styles);
  }
  static finalizeStyles(t) {
    const i = [];
    if (Array.isArray(t)) {
      const s = new Set(t.flat(1 / 0).reverse());
      for (const a of s) i.unshift(et(a));
    } else t !== void 0 && i.push(et(t));
    return i;
  }
  static _$Eu(t, i) {
    const s = i.attribute;
    return s === !1 ? void 0 : typeof s == "string" ? s : typeof t == "string" ? t.toLowerCase() : void 0;
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
    for (const s of i.keys()) this.hasOwnProperty(s) && (t.set(s, this[s]), delete this[s]);
    t.size > 0 && (this._$Ep = t);
  }
  createRenderRoot() {
    const t = this.shadowRoot ?? this.attachShadow(this.constructor.shadowRootOptions);
    return wt(t, this.constructor.elementStyles), t;
  }
  connectedCallback() {
    this.renderRoot ??= this.createRenderRoot(), this.enableUpdating(!0), this._$EO?.forEach((t) => t.hostConnected?.());
  }
  enableUpdating(t) {
  }
  disconnectedCallback() {
    this._$EO?.forEach((t) => t.hostDisconnected?.());
  }
  attributeChangedCallback(t, i, s) {
    this._$AK(t, s);
  }
  _$ET(t, i) {
    const s = this.constructor.elementProperties.get(t), a = this.constructor._$Eu(t, s);
    if (a !== void 0 && s.reflect === !0) {
      const o = (s.converter?.toAttribute !== void 0 ? s.converter : R).toAttribute(i, s.type);
      this._$Em = t, o == null ? this.removeAttribute(a) : this.setAttribute(a, o), this._$Em = null;
    }
  }
  _$AK(t, i) {
    const s = this.constructor, a = s._$Eh.get(t);
    if (a !== void 0 && this._$Em !== a) {
      const o = s.getPropertyOptions(a), r = typeof o.converter == "function" ? { fromAttribute: o.converter } : o.converter?.fromAttribute !== void 0 ? o.converter : R;
      this._$Em = a;
      const c = r.fromAttribute(i, o.type);
      this[a] = c ?? this._$Ej?.get(a) ?? c, this._$Em = null;
    }
  }
  requestUpdate(t, i, s, a = !1, o) {
    if (t !== void 0) {
      const r = this.constructor;
      if (a === !1 && (o = this[t]), s ??= r.getPropertyOptions(t), !((s.hasChanged ?? V)(o, i) || s.useDefault && s.reflect && o === this._$Ej?.get(t) && !this.hasAttribute(r._$Eu(t, s)))) return;
      this.C(t, i, s);
    }
    this.isUpdatePending === !1 && (this._$ES = this._$EP());
  }
  C(t, i, { useDefault: s, reflect: a, wrapped: o }, r) {
    s && !(this._$Ej ??= /* @__PURE__ */ new Map()).has(t) && (this._$Ej.set(t, r ?? i ?? this[t]), o !== !0 || r !== void 0) || (this._$AL.has(t) || (this.hasUpdated || s || (i = void 0), this._$AL.set(t, i)), a === !0 && this._$Em !== t && (this._$Eq ??= /* @__PURE__ */ new Set()).add(t));
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
        for (const [a, o] of this._$Ep) this[a] = o;
        this._$Ep = void 0;
      }
      const s = this.constructor.elementProperties;
      if (s.size > 0) for (const [a, o] of s) {
        const { wrapped: r } = o, c = this[a];
        r !== !0 || this._$AL.has(a) || c === void 0 || this.C(a, void 0, o, c);
      }
    }
    let t = !1;
    const i = this._$AL;
    try {
      t = this.shouldUpdate(i), t ? (this.willUpdate(i), this._$EO?.forEach((s) => s.hostUpdate?.()), this.update(i)) : this._$EM();
    } catch (s) {
      throw t = !1, this._$EM(), s;
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
P.elementStyles = [], P.shadowRootOptions = { mode: "open" }, P[T("elementProperties")] = /* @__PURE__ */ new Map(), P[T("finalized")] = /* @__PURE__ */ new Map(), kt?.({ ReactiveElement: P }), (H.reactiveElementVersions ??= []).push("2.1.2");
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const G = globalThis, at = (e) => e, L = G.trustedTypes, ot = L ? L.createPolicy("lit-html", { createHTML: (e) => e }) : void 0, ft = "$lit$", w = `lit$${Math.random().toFixed(9).slice(2)}$`, gt = "?" + w, Et = `<${gt}>`, C = document, j = () => C.createComment(""), M = (e) => e === null || typeof e != "object" && typeof e != "function", J = Array.isArray, Tt = (e) => J(e) || typeof e?.[Symbol.iterator] == "function", B = `[ 	
\f\r]`, E = /<(?:(!--|\/[^a-zA-Z])|(\/?[a-zA-Z][^>\s]*)|(\/?$))/g, rt = /-->/g, nt = />/g, b = RegExp(`>|${B}(?:([^\\s"'>=/]+)(${B}*=${B}*(?:[^ 	
\f\r"'\`<>=]|("|')|))|$)`, "g"), lt = /'/g, ct = /"/g, _t = /^(?:script|style|textarea|title)$/i, jt = (e) => (t, ...i) => ({ _$litType$: e, strings: t, values: i }), n = jt(1), A = Symbol.for("lit-noChange"), l = Symbol.for("lit-nothing"), dt = /* @__PURE__ */ new WeakMap(), x = C.createTreeWalker(C, 129);
function mt(e, t) {
  if (!J(e) || !e.hasOwnProperty("raw")) throw Error("invalid template strings array");
  return ot !== void 0 ? ot.createHTML(t) : t;
}
const Mt = (e, t) => {
  const i = e.length - 1, s = [];
  let a, o = t === 2 ? "<svg>" : t === 3 ? "<math>" : "", r = E;
  for (let c = 0; c < i; c++) {
    const d = e[c];
    let p, u, h = -1, g = 0;
    for (; g < d.length && (r.lastIndex = g, u = r.exec(d), u !== null); ) g = r.lastIndex, r === E ? u[1] === "!--" ? r = rt : u[1] !== void 0 ? r = nt : u[2] !== void 0 ? (_t.test(u[2]) && (a = RegExp("</" + u[2], "g")), r = b) : u[3] !== void 0 && (r = b) : r === b ? u[0] === ">" ? (r = a ?? E, h = -1) : u[1] === void 0 ? h = -2 : (h = r.lastIndex - u[2].length, p = u[1], r = u[3] === void 0 ? b : u[3] === '"' ? ct : lt) : r === ct || r === lt ? r = b : r === rt || r === nt ? r = E : (r = b, a = void 0);
    const v = r === b && e[c + 1].startsWith("/>") ? " " : "";
    o += r === E ? d + Et : h >= 0 ? (s.push(p), d.slice(0, h) + ft + d.slice(h) + w + v) : d + w + (h === -2 ? c : v);
  }
  return [mt(e, o + (e[i] || "<?>") + (t === 2 ? "</svg>" : t === 3 ? "</math>" : "")), s];
};
class D {
  constructor({ strings: t, _$litType$: i }, s) {
    let a;
    this.parts = [];
    let o = 0, r = 0;
    const c = t.length - 1, d = this.parts, [p, u] = Mt(t, i);
    if (this.el = D.createElement(p, s), x.currentNode = this.el.content, i === 2 || i === 3) {
      const h = this.el.content.firstChild;
      h.replaceWith(...h.childNodes);
    }
    for (; (a = x.nextNode()) !== null && d.length < c; ) {
      if (a.nodeType === 1) {
        if (a.hasAttributes()) for (const h of a.getAttributeNames()) if (h.endsWith(ft)) {
          const g = u[r++], v = a.getAttribute(h).split(w), z = /([.?@])?(.*)/.exec(g);
          d.push({ type: 1, index: o, name: z[2], strings: v, ctor: z[1] === "." ? It : z[1] === "?" ? Ot : z[1] === "@" ? zt : W }), a.removeAttribute(h);
        } else h.startsWith(w) && (d.push({ type: 6, index: o }), a.removeAttribute(h));
        if (_t.test(a.tagName)) {
          const h = a.textContent.split(w), g = h.length - 1;
          if (g > 0) {
            a.textContent = L ? L.emptyScript : "";
            for (let v = 0; v < g; v++) a.append(h[v], j()), x.nextNode(), d.push({ type: 2, index: ++o });
            a.append(h[g], j());
          }
        }
      } else if (a.nodeType === 8) if (a.data === gt) d.push({ type: 2, index: o });
      else {
        let h = -1;
        for (; (h = a.data.indexOf(w, h + 1)) !== -1; ) d.push({ type: 7, index: o }), h += w.length - 1;
      }
      o++;
    }
  }
  static createElement(t, i) {
    const s = C.createElement("template");
    return s.innerHTML = t, s;
  }
}
function k(e, t, i = e, s) {
  if (t === A) return t;
  let a = s !== void 0 ? i._$Co?.[s] : i._$Cl;
  const o = M(t) ? void 0 : t._$litDirective$;
  return a?.constructor !== o && (a?._$AO?.(!1), o === void 0 ? a = void 0 : (a = new o(e), a._$AT(e, i, s)), s !== void 0 ? (i._$Co ??= [])[s] = a : i._$Cl = a), a !== void 0 && (t = k(e, a._$AS(e, t.values), a, s)), t;
}
class Dt {
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
    const { el: { content: i }, parts: s } = this._$AD, a = (t?.creationScope ?? C).importNode(i, !0);
    x.currentNode = a;
    let o = x.nextNode(), r = 0, c = 0, d = s[0];
    for (; d !== void 0; ) {
      if (r === d.index) {
        let p;
        d.type === 2 ? p = new O(o, o.nextSibling, this, t) : d.type === 1 ? p = new d.ctor(o, d.name, d.strings, this, t) : d.type === 6 && (p = new Nt(o, this, t)), this._$AV.push(p), d = s[++c];
      }
      r !== d?.index && (o = x.nextNode(), r++);
    }
    return x.currentNode = C, a;
  }
  p(t) {
    let i = 0;
    for (const s of this._$AV) s !== void 0 && (s.strings !== void 0 ? (s._$AI(t, s, i), i += s.strings.length - 2) : s._$AI(t[i])), i++;
  }
}
class O {
  get _$AU() {
    return this._$AM?._$AU ?? this._$Cv;
  }
  constructor(t, i, s, a) {
    this.type = 2, this._$AH = l, this._$AN = void 0, this._$AA = t, this._$AB = i, this._$AM = s, this.options = a, this._$Cv = a?.isConnected ?? !0;
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
    t = k(this, t, i), M(t) ? t === l || t == null || t === "" ? (this._$AH !== l && this._$AR(), this._$AH = l) : t !== this._$AH && t !== A && this._(t) : t._$litType$ !== void 0 ? this.$(t) : t.nodeType !== void 0 ? this.T(t) : Tt(t) ? this.k(t) : this._(t);
  }
  O(t) {
    return this._$AA.parentNode.insertBefore(t, this._$AB);
  }
  T(t) {
    this._$AH !== t && (this._$AR(), this._$AH = this.O(t));
  }
  _(t) {
    this._$AH !== l && M(this._$AH) ? this._$AA.nextSibling.data = t : this.T(C.createTextNode(t)), this._$AH = t;
  }
  $(t) {
    const { values: i, _$litType$: s } = t, a = typeof s == "number" ? this._$AC(t) : (s.el === void 0 && (s.el = D.createElement(mt(s.h, s.h[0]), this.options)), s);
    if (this._$AH?._$AD === a) this._$AH.p(i);
    else {
      const o = new Dt(a, this), r = o.u(this.options);
      o.p(i), this.T(r), this._$AH = o;
    }
  }
  _$AC(t) {
    let i = dt.get(t.strings);
    return i === void 0 && dt.set(t.strings, i = new D(t)), i;
  }
  k(t) {
    J(this._$AH) || (this._$AH = [], this._$AR());
    const i = this._$AH;
    let s, a = 0;
    for (const o of t) a === i.length ? i.push(s = new O(this.O(j()), this.O(j()), this, this.options)) : s = i[a], s._$AI(o), a++;
    a < i.length && (this._$AR(s && s._$AB.nextSibling, a), i.length = a);
  }
  _$AR(t = this._$AA.nextSibling, i) {
    for (this._$AP?.(!1, !0, i); t !== this._$AB; ) {
      const s = at(t).nextSibling;
      at(t).remove(), t = s;
    }
  }
  setConnected(t) {
    this._$AM === void 0 && (this._$Cv = t, this._$AP?.(t));
  }
}
class W {
  get tagName() {
    return this.element.tagName;
  }
  get _$AU() {
    return this._$AM._$AU;
  }
  constructor(t, i, s, a, o) {
    this.type = 1, this._$AH = l, this._$AN = void 0, this.element = t, this.name = i, this._$AM = a, this.options = o, s.length > 2 || s[0] !== "" || s[1] !== "" ? (this._$AH = Array(s.length - 1).fill(new String()), this.strings = s) : this._$AH = l;
  }
  _$AI(t, i = this, s, a) {
    const o = this.strings;
    let r = !1;
    if (o === void 0) t = k(this, t, i, 0), r = !M(t) || t !== this._$AH && t !== A, r && (this._$AH = t);
    else {
      const c = t;
      let d, p;
      for (t = o[0], d = 0; d < o.length - 1; d++) p = k(this, c[s + d], i, d), p === A && (p = this._$AH[d]), r ||= !M(p) || p !== this._$AH[d], p === l ? t = l : t !== l && (t += (p ?? "") + o[d + 1]), this._$AH[d] = p;
    }
    r && !a && this.j(t);
  }
  j(t) {
    t === l ? this.element.removeAttribute(this.name) : this.element.setAttribute(this.name, t ?? "");
  }
}
class It extends W {
  constructor() {
    super(...arguments), this.type = 3;
  }
  j(t) {
    this.element[this.name] = t === l ? void 0 : t;
  }
}
class Ot extends W {
  constructor() {
    super(...arguments), this.type = 4;
  }
  j(t) {
    this.element.toggleAttribute(this.name, !!t && t !== l);
  }
}
class zt extends W {
  constructor(t, i, s, a, o) {
    super(t, i, s, a, o), this.type = 5;
  }
  _$AI(t, i = this) {
    if ((t = k(this, t, i, 0) ?? l) === A) return;
    const s = this._$AH, a = t === l && s !== l || t.capture !== s.capture || t.once !== s.once || t.passive !== s.passive, o = t !== l && (s === l || a);
    a && this.element.removeEventListener(this.name, this, s), o && this.element.addEventListener(this.name, this, t), this._$AH = t;
  }
  handleEvent(t) {
    typeof this._$AH == "function" ? this._$AH.call(this.options?.host ?? this.element, t) : this._$AH.handleEvent(t);
  }
}
class Nt {
  constructor(t, i, s) {
    this.element = t, this.type = 6, this._$AN = void 0, this._$AM = i, this.options = s;
  }
  get _$AU() {
    return this._$AM._$AU;
  }
  _$AI(t) {
    k(this, t);
  }
}
const Ut = G.litHtmlPolyfillSupport;
Ut?.(D, O), (G.litHtmlVersions ??= []).push("3.3.2");
const vt = (e, t, i) => {
  const s = i?.renderBefore ?? t;
  let a = s._$litPart$;
  if (a === void 0) {
    const o = i?.renderBefore ?? null;
    s._$litPart$ = a = new O(t.insertBefore(j(), o), o, void 0, i ?? {});
  }
  return a._$AI(e), a;
};
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const K = globalThis;
class $ extends P {
  constructor() {
    super(...arguments), this.renderOptions = { host: this }, this._$Do = void 0;
  }
  createRenderRoot() {
    const t = super.createRenderRoot();
    return this.renderOptions.renderBefore ??= t.firstChild, t;
  }
  update(t) {
    const i = this.render();
    this.hasUpdated || (this.renderOptions.isConnected = this.isConnected), super.update(t), this._$Do = vt(i, this.renderRoot, this.renderOptions);
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
$._$litElement$ = !0, $.finalized = !0, K.litElementHydrateSupport?.({ LitElement: $ });
const Rt = K.litElementPolyfillSupport;
Rt?.({ LitElement: $ });
(K.litElementVersions ??= []).push("4.2.2");
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const Z = (e) => (t, i) => {
  i !== void 0 ? i.addInitializer(() => {
    customElements.define(e, t);
  }) : customElements.define(e, t);
};
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const Lt = { attribute: !0, type: String, converter: R, reflect: !1, hasChanged: V }, Ht = (e = Lt, t, i) => {
  const { kind: s, metadata: a } = i;
  let o = globalThis.litPropertyMetadata.get(a);
  if (o === void 0 && globalThis.litPropertyMetadata.set(a, o = /* @__PURE__ */ new Map()), s === "setter" && ((e = Object.create(e)).wrapped = !0), o.set(i.name, e), s === "accessor") {
    const { name: r } = i;
    return { set(c) {
      const d = t.get.call(this);
      t.set.call(this, c), this.requestUpdate(r, d, e, !0, c);
    }, init(c) {
      return c !== void 0 && this.C(r, void 0, e, c), c;
    } };
  }
  if (s === "setter") {
    const { name: r } = i;
    return function(c) {
      const d = this[r];
      t.call(this, c), this.requestUpdate(r, d, e, !0, c);
    };
  }
  throw Error("Unsupported decorator location: " + s);
};
function X(e) {
  return (t, i) => typeof i == "object" ? Ht(e, t, i) : ((s, a, o) => {
    const r = a.hasOwnProperty(o);
    return a.constructor.createProperty(o, s), r ? Object.getOwnPropertyDescriptor(a, o) : void 0;
  })(e, t, i);
}
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
function f(e) {
  return X({ ...e, state: !0, attribute: !1 });
}
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const Wt = (e, t, i) => (i.configurable = !0, i.enumerable = !0, Reflect.decorate && typeof t != "object" && Object.defineProperty(e, t, i), i);
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
function Xt(e, t) {
  return (i, s, a) => {
    const o = (r) => r.renderRoot?.querySelector(e) ?? null;
    return Wt(i, s, { get() {
      return o(this);
    } });
  };
}
const Bt = q`
  :host {
    display: block;
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
    box-shadow: 0 0 8px rgba(var(--rgb-primary-color, 3, 169, 244), 0.4);
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

  /* Now Playing Overlay on Poster */
  .now-playing-overlay {
    position: absolute;
    inset: 0;
    background: rgba(0, 0, 0, 0.4);
    backdrop-filter: blur(2px);
    -webkit-backdrop-filter: blur(2px);
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
    color: #fff;
  }

  .now-playing-controls ha-icon {
    --mdc-icon-size: 32px;
    cursor: pointer;
    transition: transform 0.2s ease, color 0.2s ease;
  }

  .now-playing-controls ha-icon:hover {
    transform: scale(1.1);
    color: var(--jf-primary);
  }

  .now-playing-controls ha-icon.stop:hover {
    color: #f44336;
  }

  .now-playing-status {
    font-size: 0.75rem;
    font-weight: 700;
    color: var(--jf-primary);
    text-transform: uppercase;
    letter-spacing: 1px;
    background: rgba(0, 0, 0, 0.4);
    padding: 2px 8px;
    border-radius: 4px;
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
`, N = {
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
function ht(e, t) {
  const i = e.split("-")[0].toLowerCase();
  return N[i]?.[t] ? N[i][t] : N.en?.[t] ? N.en[t] : t;
}
var Ft = Object.defineProperty, Yt = Object.getOwnPropertyDescriptor, S = (e, t, i, s) => {
  for (var a = s > 1 ? void 0 : s ? Yt(t, i) : t, o = e.length - 1, r; o >= 0; o--)
    (r = e[o]) && (a = (s ? r(t, i, a) : r(a)) || a);
  return s && a && Ft(t, i, a), a;
};
let y = class extends $ {
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
        const s = new URL(t);
        s.hostname.includes("youtube.com") ? i = s.searchParams.get("v") || "" : s.hostname.includes("youtu.be") && (i = s.pathname.slice(1));
      } catch {
      }
      if (i) {
        const s = navigator.userAgent || navigator.vendor || window.opera, a = /android/i.test(s), o = /iPad|iPhone|iPod/.test(s) && !window.MSStream;
        if (a) {
          window.open(`vnd.youtube:${i}`, "_blank");
          return;
        }
        if (o) {
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
      (s) => this.hass.states[s].attributes.integration === "jellyha" || s.startsWith("sensor.jellyha_")
      // Fallback convention
    ), i = t.length > 0 ? t[0] : "sensor.jellyha_library";
    try {
      const s = await this.hass.callWS({
        type: "jellyha/get_next_up",
        entity_id: i,
        series_id: e.id
      });
      s && s.item && (this._nextUpItem = s.item);
    } catch (s) {
      console.warn("Failed to fetch Next Up:", s);
    }
  }
  updated() {
    this._portalContainer && vt(this._renderDialogContent(), this._portalContainer);
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
    if (!this._open || !this._item) return n``;
    const e = this._item, t = e.type === "Series", i = e.year || (e.date_added ? new Date(e.date_added).getFullYear() : "");
    return n`
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
                            ${this._confirmDelete ? n`
                                <div class="confirmation-box">
                                    <span>Delete?</span>
                                    <button class="confirm-btn confirm-yes" @click=${this._handleDeleteConfirm}>Yes</button>
                                    <button class="confirm-btn" @click=${() => this._confirmDelete = !1}>No</button>
                                </div>
                              ` : n`
                                <button class="action-btn" @click=${this._handlePlay} title="Play on Chromecast">
                                    <ha-icon icon="mdi:play"></ha-icon>
                                </button>
                                
                                ${e.trailer_url ? n`
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
                                ${i ? n`<span>${i}</span>` : l}
                                <span class="badge">${e.type}</span>
                                ${e.official_rating ? n`<span class="badge">${e.official_rating}</span>` : l}
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
                                <ha-icon icon="mdi:play-circle-outline" style="font-size: 32px; opacity: 0.8;"></ha-icon>
                            </div>
                        ` : l}

                        <div class="stats-row">
                            <div class="stat-item">
                                <ha-icon icon="mdi:star" style="color: #FBC02D;"></ha-icon>
                                <span>${e.rating ? e.rating.toFixed(1) : "N/A"}</span>
                            </div>
                            ${t ? n`
                                <div class="stat-item">
                                    <ha-icon icon="mdi:television-classic"></ha-icon>
                                    <span>${e.unplayed_count !== void 0 ? e.unplayed_count + " Unplayed" : ""}</span>
                                </div>
                             ` : n`
                                <div class="stat-item">
                                    <ha-icon icon="mdi:clock-outline"></ha-icon>
                                    <span>${this._formatRuntime(e.runtime_minutes)}</span>
                                </div>
                             `}
                        </div>

                         ${e.description ? n`<div class="description">${e.description}</div>` : l}

                         ${e.genres && e.genres.length > 0 ? n`
                            <div class="genres-list">
                                ${e.genres.map((s) => n`<span class="genre-tag">${s}</span>`)}
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
    return (e.media_streams || []).forEach((s) => {
      s.Type === "Video" ? (t.push(n`<div class="info-pair"><b>Video</b><span>${s.Codec?.toUpperCase()}</span></div>`), t.push(n`<div class="info-pair"><b>Resolution</b><span>${s.Width}x${s.Height}</span></div>`)) : s.Type === "Audio" && s.Index === 1 && (t.push(n`<div class="info-pair"><b>Audio</b><span>${s.Codec?.toUpperCase()}</span></div>`), t.push(n`<div class="info-pair"><b>Channels</b><span>${s.Channels} ch</span></div>`));
    }), t;
  }
};
y.styles = q`
        /* Styles handled in _getPortalStyles */
    `;
S([
  X({ attribute: !1 })
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
  Z("jellyha-item-details-modal")
], y);
var qt = Object.defineProperty, Vt = Object.getOwnPropertyDescriptor, Q = (e, t, i, s) => {
  for (var a = s > 1 ? void 0 : s ? Vt(t, i) : t, o = e.length - 1, r; o >= 0; o--)
    (r = e[o]) && (a = (s ? r(t, i, a) : r(a)) || a);
  return s && a && qt(t, i, a), a;
};
function Gt(e, t, i) {
  const s = new CustomEvent(t, {
    bubbles: !0,
    composed: !0,
    detail: i
  });
  e.dispatchEvent(s);
}
let I = class extends $ {
  setConfig(e) {
    this._config = e;
  }
  render() {
    if (!this.hass || !this._config)
      return n``;
    const e = this._config.click_action || "more-info", t = this._config.hold_action || "jellyfin";
    return n`
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

        ${this._config.layout === "grid" || this._config.layout === "list" ? n`
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

        ${e === "cast" || t === "cast" ? n`
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
    this._config = i, Gt(this, "config-changed", { config: i });
  }
};
I.styles = q`
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
Q([
  X({ attribute: !1 })
], I.prototype, "hass", 2);
Q([
  f()
], I.prototype, "_config", 2);
I = Q([
  Z("jellyha-library-editor")
], I);
var Jt = Object.defineProperty, Kt = Object.getOwnPropertyDescriptor, m = (e, t, i, s) => {
  for (var a = s > 1 ? void 0 : s ? Kt(t, i) : t, o = e.length - 1, r; o >= 0; o--)
    (r = e[o]) && (a = (s ? r(t, i, a) : r(a)) || a);
  return s && a && Jt(t, i, a), a;
};
const Zt = "1.0.0";
console.info(
  `%c JELLYHA-LIBRARY-CARD %c v${Zt} `,
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
const pt = {
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
let _ = class extends $ {
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
    const t = this._filterItems(this._items || []), i = this._config.items_per_page || this._itemsPerPage, s = this._config.max_pages || 10, a = Math.min(Math.ceil(t.length / i), s);
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
    const s = e === "next" ? "-30px" : "30px";
    i.style.transition = "transform 0.2s ease-out, opacity 0.2s ease-out", i.style.transform = `translateX(${s})`, i.style.opacity = "0", await new Promise((o) => setTimeout(o, 200)), t(), await this.updateComplete, this._setScrollPosition(e === "next" ? "start" : "end");
    const a = e === "next" ? "30px" : "-30px";
    i.style.transition = "none", i.style.opacity = "0", i.style.transform = `translateX(${a})`, i.offsetHeight, i.style.transition = "transform 0.25s ease-out, opacity 0.25s ease-out", i.style.transform = "translateX(0)", i.style.opacity = "1", await new Promise((o) => setTimeout(o, 250)), i.style.transition = "", i.style.transform = "", i.style.opacity = "";
  }
  /**
   * Helper to get total pages (used for elastic check)
   */
  _getTotalPages() {
    if (!this._config?.entity || !this.hass || !this.hass.states[this._config.entity]) return 1;
    const t = this._filterItems(this._items || []), i = this._config.items_per_page || this._itemsPerPage, s = this._config.max_pages || 10;
    return Math.min(Math.ceil(t.length / i), s);
  }
  // Touch/Swipe handlers
  _handleTouchStart(e) {
    this._touchStartX = e.touches[0].clientX, this._touchStartY = e.touches[0].clientY, this._isSwiping = !1, this._isOverscrolling = !1, this._elasticAnchorX = 0;
  }
  _handleTouchMove(e) {
    if (!this._touchStartX) return;
    const t = e.touches[0].clientX - this._touchStartX, i = e.touches[0].clientY - this._touchStartY;
    if (Math.abs(t) > Math.abs(i)) {
      const s = this.shadowRoot?.querySelector(".carousel, .grid-wrapper");
      if (s && Math.abs(t) > 0) {
        const { scrollLeft: a, scrollWidth: o, clientWidth: r } = s, c = o - r, d = a <= 5, p = a >= c - 5, u = this._config.show_pagination !== !1;
        let h = !1;
        if (u) {
          const g = this._getTotalPages();
          d && t > 0 && this._currentPage === 0 && (h = !0), p && t < 0 && this._currentPage >= g - 1 && (h = !0);
        } else
          d && t > 0 && (h = !0), p && t < 0 && (h = !0);
        if (h) {
          this._isOverscrolling || (this._isOverscrolling = !0, this._elasticAnchorX = t), e.preventDefault();
          const g = 0.3, v = t - this._elasticAnchorX;
          s.style.transition = "none", s.style.transform = `translateX(${v * g}px)`;
          return;
        }
      }
      Math.abs(t) > 30 && (this._isSwiping = !0);
    }
  }
  _handleTouchEnd(e) {
    if (this._isOverscrolling) {
      const a = this.shadowRoot?.querySelector(".carousel, .grid-wrapper");
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
    const t = e.changedTouches[0].clientX - this._touchStartX, i = 50, s = this.shadowRoot?.querySelector(".carousel, .grid-wrapper");
    if (t < -i)
      if (s) {
        const { scrollLeft: a, scrollWidth: o, clientWidth: r } = s;
        a + r >= o - 10 && this._nextPage();
      } else
        this._nextPage();
    else t > i && (s ? s.scrollLeft <= 10 && this._prevPage() : this._prevPage());
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
      const s = this.shadowRoot?.querySelector(".carousel, .grid-wrapper");
      if (s && Math.abs(t) > 0) {
        const { scrollLeft: a, scrollWidth: o, clientWidth: r } = s, c = o - r, d = a <= 5, p = a >= c - 5, u = this._config.show_pagination !== !1;
        let h = !1;
        if (u) {
          const g = this._getTotalPages();
          d && t > 0 && this._currentPage === 0 && (h = !0), p && t < 0 && this._currentPage >= g - 1 && (h = !0);
        } else
          d && t > 0 && (h = !0), p && t < 0 && (h = !0);
        if (h) {
          this._isOverscrolling || (this._isOverscrolling = !0, this._elasticAnchorX = t), e.preventDefault();
          const g = 0.3, v = t - this._elasticAnchorX;
          s.style.transition = "none", s.style.transform = `translateX(${v * g}px)`;
          return;
        }
      }
      Math.abs(t) > 30 && (this._isSwiping = !0);
    }
  }
  _handlePointerUp(e) {
    if (e.target.releasePointerCapture?.(e.pointerId), this._isOverscrolling) {
      const a = this.shadowRoot?.querySelector(".carousel, .grid-wrapper");
      a && (a.style.transition = "transform 0.4s cubic-bezier(0.25, 0.8, 0.5, 1)", a.style.transform = ""), this._isOverscrolling = !1, this._elasticAnchorX = 0, this._touchStartX = 0, this._isSwiping = !1;
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
    const t = e.clientX - this._touchStartX, i = 50, s = this.shadowRoot?.querySelector(".carousel, .grid-wrapper");
    if (t < -i)
      if (s) {
        const { scrollLeft: a, scrollWidth: o, clientWidth: r } = s;
        a + r >= o - 10 && this._nextPage();
      } else
        this._nextPage();
    else t > i && (s ? s.scrollLeft <= 10 && this._prevPage() : this._prevPage());
    this._touchStartX = 0, this._isSwiping = !1;
  }
  // Scroll handler for elastic dot indicator
  _handleScroll(e) {
    const t = e.target, i = t.scrollWidth, s = t.clientWidth, a = t.scrollLeft, o = i > s + 10;
    if (o !== this._hasScrollableContent && (this._hasScrollableContent = o), o) {
      const r = i - s;
      let c = a / r;
      (r - a < 10 || c > 0.98) && (c = 1), (a < 10 || c < 0.02) && (c = 0), c = Math.min(1, Math.max(0, c)), this._scrollProgress = c;
    }
  }
  // Render scroll indicator for non-paginated scrollable content
  _renderScrollIndicator() {
    if (!this._hasScrollableContent) return n``;
    const e = this.SCROLL_INDICATOR_DOTS, t = this._scrollProgress, i = Math.round(t * (e - 1));
    return n`
      <div class="scroll-indicator">
        ${Array.from({ length: e }, (s, a) => {
      const o = a === i, r = a === 0 && t < 0.1 || a === e - 1 && t > 0.9;
      return n`
        <span 
          class="scroll-dot ${o ? "active" : ""} ${r ? "pill" : ""}"
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
        const a = Math.max(2, Math.floor(i / 160));
        if (a !== this._itemsPerPage && (this._itemsPerPage = a, this.requestUpdate()), this._config) {
          const o = this._config.columns || 1, r = 300;
          if (o > 1) {
            const c = Math.max(1, Math.floor(i / r)), d = Math.min(o, c);
            d !== this._effectiveListColumns && (this._effectiveListColumns = d, this.requestUpdate());
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
    this._config = { ...pt, ...e }, this._effectiveListColumns = this._config.columns || 1;
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
      ...pt
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
        const i = t.states[this._config.entity], s = this.hass.states[this._config.entity], a = this._config.default_cast_device;
        if (a) {
          const o = t.states[a], r = this.hass.states[a];
          if (o !== r) return !0;
        }
        return i !== s;
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
        const i = t.attributes.entry_id, s = t.attributes.last_updated;
        (s !== this._lastUpdate || this._items.length === 0 && i) && (this._lastUpdate = s, this._fetchItems());
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
      return n``;
    if (!this.hass.states[this._config.entity])
      return this._renderError(`Entity not found: ${this._config.entity}`);
    if (this._error)
      return this._renderError(this._error);
    const t = this._filterItems(this._items || []);
    return n`
      <ha-card>
        <div class="card-inner">
            ${this._config.title ? n`
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
    this._config.media_type === "movies" ? t = t.filter((o) => o.type === "Movie") : this._config.media_type === "series" && (t = t.filter((o) => o.type === "Series")), this._config.filter_favorites && (t = t.filter((o) => o.is_favorite === !0));
    const i = this._config.status_filter || "all";
    i === "unwatched" ? t = t.filter((o) => !o.is_played) : i === "watched" && (t = t.filter((o) => o.is_played === !0)), this._config.filter_newly_added && (t = t.filter((o) => this._isNewItem(o)));
    const s = this._config.sort_option || "date_added_desc";
    t.sort((o, r) => {
      switch (s) {
        case "date_added_asc":
          return (o.date_added || "").localeCompare(r.date_added || "");
        case "date_added_desc":
          return (r.date_added || "").localeCompare(o.date_added || "");
        case "title_asc":
          return (o.name || "").localeCompare(r.name || "");
        case "title_desc":
          return (r.name || "").localeCompare(o.name || "");
        case "year_asc":
          return (o.year || 0) - (r.year || 0);
        case "year_desc":
          return (r.year || 0) - (o.year || 0);
        case "last_played_asc":
          return (o.last_played_date || "").localeCompare(r.last_played_date || "");
        case "last_played_desc":
          return (r.last_played_date || "").localeCompare(o.last_played_date || "");
        default:
          return 0;
      }
    });
    const a = this._config.max_pages;
    if (a != null && a > 0) {
      const o = (this._config.items_per_page || 5) * a;
      t = t.slice(0, o);
    }
    return t;
  }
  /**
   * Render layout based on config
   */
  _renderLayout(e) {
    const t = this._config.layout || "carousel", i = this._config.show_pagination !== !1;
    return t === "carousel" ? this._renderCarousel(e, i) : t === "list" ? this._renderList(e, i) : t === "grid" ? this._renderGrid(e, i) : n`
      <div class="${t}">
        ${e.map((s) => this._renderMediaItem(s))}
      </div>
    `;
  }
  /**
   * Render carousel with optional pagination
   */
  _renderCarousel(e, t) {
    const i = this._config.items_per_page || this._itemsPerPage, s = this._config.max_pages, a = s ? Number(s) : 0, o = a > 0 ? a : 1 / 0, r = Math.min(Math.ceil(e.length / i), o), c = this._currentPage * i, d = t ? e.slice(c, c + i) : e;
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
          class="carousel ${t ? "paginated" : "scrollable"}"
          @scroll="${t ? l : this._handleScroll}"
        >
          ${d.map((p) => this._renderMediaItem(p))}
        </div>
        ${t && r > 1 ? this._renderPagination(r) : l}
        ${t ? l : this._renderScrollIndicator()}
      </div>
    `;
  }
  /**
   * Render list with optional pagination
   */
  _renderList(e, t) {
    const i = this._config.items_per_page || this._itemsPerPage, s = this._config.max_pages, a = s ? Number(s) : 0, o = a > 0 ? a : 1 / 0, r = Math.min(Math.ceil(e.length / i), o), c = this._currentPage * i, d = t ? e.slice(c, c + i) : e, p = this._effectiveListColumns, u = p === 1;
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
          class="list ${t ? "paginated" : ""} ${u ? "single-column" : ""}"
          style="--jf-list-columns: ${p}"
        >
          ${d.map((h) => this._renderListItem(h))}
        </div>
        ${t && r > 1 ? this._renderPagination(r) : l}
      </div>
    `;
  }
  /**
   * Render grid with optional pagination
   */
  _renderGrid(e, t) {
    const i = this._config.items_per_page || this._itemsPerPage, s = this._config.max_pages, a = s ? Number(s) : 0, o = a > 0 ? a : 1 / 0, r = Math.min(Math.ceil(e.length / i), o), c = this._currentPage * i, d = t ? e.slice(c, c + i) : e, p = this._config.columns || 1, u = p === 1;
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
          @scroll="${t ? l : this._handleScroll}"
        >
          <div
            class="grid ${t ? "paginated" : ""} ${u ? "auto-columns" : ""}"
            style="--jf-columns: ${p}"
          >
            ${d.map((h) => this._renderMediaItem(h))}
          </div>
        </div>
        ${t && r > 1 ? this._renderPagination(r) : l}
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
    return n`
      <div class="pagination-dots">
        ${Array.from({ length: e }, (t, i) => n`
          <button
            type="button"
            class="pagination-dot ${i === this._currentPage ? "active" : ""}"
            data-page="${i}"
            @click="${this._onDotClick}"
            aria-label="Go to page ${i + 1}"
          ></button>
        `)}
      </div>
    `;
  }
  /**
   * Render Smart Sliding Pagination (iOS Style)
   */
  _renderSmartPagination(e) {
    const c = -(this._currentPage * 16) + 32;
    return n`
      <div class="pagination-container smart" style="width: ${72}px">
        <div 
          class="pagination-track" 
          style="transform: translateX(${c}px); width: ${e * 16}px"
        >
          ${Array.from({ length: e }, (d, p) => {
      const u = Math.abs(p - this._currentPage);
      let h = "smart-dot";
      return p === this._currentPage ? h += " active" : u > 2 ? h += " hidden" : u === 2 && (h += " small"), n`
              <button
                type="button"
                class="${h}"
                data-page="${p}"
                @click="${this._onDotClick}"
                aria-label="Go to page ${p + 1}"
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
    const t = this._isNewItem(e), i = this._getRating(e), s = this._config.show_media_type_badge !== !1, a = this._isItemPlaying(e);
    return n`
      <div
        class="media-item list-item ${a ? "playing" : ""} ${this._config.show_title ? "" : "no-title"} ${this._config.metadata_position === "above" ? "metadata-above" : ""}"
        tabindex="0"
        role="button"
        aria-label="${e.name}"
        @mousedown="${(o) => this._handleMouseDown(o, e)}"
        @mouseup="${(o) => this._handleMouseUp(o, e)}"
        @touchstart="${(o) => this._handleTouchStartItem(o, e)}"
        @touchmove="${(o) => this._handleTouchMoveItem(o, e)}"
        @touchend="${(o) => this._handleTouchEndItem(o, e)}"
        @touchcancel="${(o) => this._handleTouchEndItem(o, e)}"
        @keydown="${(o) => this._handleKeydown(o, e)}"
      >
        <div class="list-poster-wrapper">
          ${this._config.metadata_position === "above" && this._config.show_date_added && e.date_added ? n`<p class="list-date-added">${this._formatDate(e.date_added)}</p>` : l}
          <div class="poster-container" id="poster-${e.id}">
            <div class="poster-inner">
              <img
                class="poster"
                src="${e.poster_url}"
                alt="${e.name}"
                loading="lazy"
                @load="${this._handleImageLoad}"
                @error="${this._handleImageError}"
              />
              <div class="poster-skeleton"></div>
              
              ${s && !a ? n`<span class="list-type-badge ${e.type === "Movie" ? "movie" : "series"}">
                  ${e.type === "Movie" ? "Movie" : "Series"}
                </span>` : l}
              
              ${a ? l : this._renderStatusBadge(e, t)}
              ${this._renderNowPlayingOverlay(e)}
            </div>
          </div>
          ${this._config.metadata_position !== "above" && this._config.show_date_added && e.date_added ? n`<p class="list-date-added">${this._formatDate(e.date_added)}</p>` : l}
        </div>
        
        <div class="list-info">
          ${this._config.show_title ? n`<h3 class="list-title">${e.name}</h3>` : l}
          
          <div class="list-metadata">
            ${s && !a ? n`<span class="list-type-badge ${e.type === "Movie" ? "movie" : "series"}">
                  ${e.type === "Movie" ? "Movie" : "Series"}
                </span>` : l}
            ${this._config.show_year && e.year ? n`<span class="list-year">${e.year}</span>` : l}
            ${this._config.show_ratings && i ? n`<span class="list-rating">
                  <ha-icon icon="mdi:star"></ha-icon>
                  ${i.toFixed(1)}
                </span>` : l}
            ${this._config.show_runtime && e.runtime_minutes ? n`<span class="list-runtime">
                  <ha-icon icon="mdi:clock-outline"></ha-icon>
                  ${this._formatRuntime(e.runtime_minutes)}
                </span>` : l}
          </div>
          
          ${this._config.show_genres && e.genres && e.genres.length > 0 ? n`<p class="list-genres">${e.genres.slice(0, 3).join(", ")}</p>` : l}
          
          ${this._config.show_description_on_hover !== !1 && e.description ? n`<p class="list-description">${e.description}</p>` : l}
        </div>
      </div>
    `;
  }
  /**
   * Render status badge (watched checkmark, unplayed count, or new badge)
   */
  _renderStatusBadge(e, t) {
    const i = this._config.show_watched_status !== !1;
    return i && e.is_played ? n`
        <div class="status-badge watched">
          <ha-icon icon="mdi:check-bold"></ha-icon>
        </div>
      ` : i && e.type === "Series" && (e.unplayed_count || 0) > 0 ? n`
        <div class="status-badge unplayed">
          ${e.unplayed_count}
        </div>
      ` : t ? n`<span class="new-badge">${ht(this.hass.language, "new")}</span>` : n``;
  }
  /**
   * Render individual media item
   */
  _renderMediaItem(e) {
    const t = this._isNewItem(e), i = this._getRating(e), s = this._config.show_media_type_badge !== !1, a = this._isItemPlaying(e);
    return n`
      <div
        class="media-item ${a ? "playing" : ""}"
        tabindex="0"
        role="button"
        aria-label="${e.name}"
        @mousedown="${(o) => this._handleMouseDown(o, e)}"
        @mouseup="${(o) => this._handleMouseUp(o, e)}"
        @touchstart="${(o) => this._handleTouchStartItem(o, e)}"
        @touchmove="${(o) => this._handleTouchMoveItem(o, e)}"
        @touchend="${(o) => this._handleTouchEndItem(o, e)}"
        @touchcancel="${(o) => this._handleTouchEndItem(o, e)}"
        @keydown="${(o) => this._handleKeydown(o, e)}"
      >
        ${this._config.metadata_position === "above" ? n`
              <div class="media-info-above">
                ${this._config.show_title ? n`<p class="media-title">${e.name}</p>` : l}
                ${this._config.show_year && e.year ? n`<p class="media-year">${e.year}</p>` : l}
                ${this._config.show_date_added && e.date_added ? n`<p class="media-date-added">${this._formatDate(e.date_added)}</p>` : l}
              </div>
            ` : l}
        <div class="poster-container" id="poster-${e.id}">
          <div class="poster-inner">
            <img
              class="poster"
              src="${e.poster_url}"
              alt="${e.name}"
              loading="lazy"
              @load="${this._handleImageLoad}"
              @error="${this._handleImageError}"
            />
            <div class="poster-skeleton"></div>
            
            ${s && !a ? n`<span class="media-type-badge ${e.type === "Movie" ? "movie" : "series"}">
                  ${e.type === "Movie" ? "Movie" : "Series"}
                </span>` : l}
            
            ${a ? l : this._renderStatusBadge(e, t)}
            
            ${this._config.show_ratings && i && !a ? n`
                  <span class="rating">
                    <ha-icon icon="mdi:star"></ha-icon>
                    ${i.toFixed(1)}
                  </span>
                ` : l}
            
            ${this._config.show_runtime && e.runtime_minutes && !a ? n`
                  <span class="runtime">
                    <ha-icon icon="mdi:clock-outline"></ha-icon>
                    ${this._formatRuntime(e.runtime_minutes)}
                  </span>
                ` : l}
            
            ${a ? l : n`
            <div class="hover-overlay">
                    ${e.year ? n`<span class="overlay-year">${e.year}</span>` : l}
                    <h3 class="overlay-title">${e.name}</h3>
                    ${this._config.show_genres && e.genres && e.genres.length > 0 ? n`<span class="overlay-genres">${e.genres.slice(0, 3).join(", ")}</span>` : l}
                    ${this._config.show_description_on_hover !== !1 && e.description ? n`<p class="overlay-description">${e.description}</p>` : l}
            </div>`}

            ${this._renderNowPlayingOverlay(e)}
          </div>
        </div>
        
        ${this._config.metadata_position === "below" ? n`
              <div class="media-info-below">
                ${this._config.show_title ? n`<p class="media-title">${e.name}</p>` : l}
                ${this._config.show_year && e.year ? n`<p class="media-year">${e.year}</p>` : l}
                ${this._config.show_date_added && e.date_added ? n`<p class="media-date-added">${this._formatDate(e.date_added)}</p>` : l}
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
      return t.toLocaleDateString(i, {
        year: "numeric",
        month: "short",
        day: "numeric"
      });
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
      const i = Math.abs(e.touches[0].clientX - this._itemTouchStartX), s = Math.abs(e.touches[0].clientY - this._itemTouchStartY);
      (i > 10 || s > 10) && (this._clearHoldTimer(), e.currentTarget.classList.remove("active-press"));
    }
  }
  _handleTouchEndItem(e, t) {
    e.currentTarget.classList.remove("active-press"), this._holdTimer && (clearTimeout(this._holdTimer), this._holdTimer = void 0);
    let s = 0;
    if (e.changedTouches.length > 0) {
      const a = e.changedTouches[0].clientX - this._itemTouchStartX, o = e.changedTouches[0].clientY - this._itemTouchStartY;
      s = Math.sqrt(a * a + o * o);
    }
    if (e.preventDefault(), this._isHoldActive) {
      this._isHoldActive = !1;
      return;
    }
    s > 10 || this._performAction(t, "click");
  }
  /**
   * Check if item is currently playing
   */
  _isItemPlaying(e) {
    if (!this._config.default_cast_device || !this.hass) return !1;
    const t = this.hass.states[this._config.default_cast_device];
    if (!t || t.state !== "playing" && t.state !== "paused" && t.state !== "buffering")
      return !1;
    const i = t.attributes.media_title, s = t.attributes.media_series_title;
    return e.name && (i === e.name || s === e.name) || e.type === "Series" && s === e.name;
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
    const s = t === "click" ? this._config.click_action : this._config.hold_action;
    switch (console.log("JellyHA: performAction", { type: t, action: s, config: this._config, item: e }), s) {
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
    return n`
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
          <ha-icon
            class="${this._rewindActive ? "spinning" : ""}"
            icon="${this._rewindActive ? "mdi:loading" : t.state === "playing" ? "mdi:pause" : "mdi:play"}"
            @click="${(i) => {
      i.stopPropagation(), this._handlePlayPause(this._config.default_cast_device);
    }}"
          ></ha-icon>
          <ha-icon
            class="stop"
            icon="mdi:stop"
            @click="${(i) => {
      i.stopPropagation(), this._handleStop(this._config.default_cast_device);
    }}"
          ></ha-icon>
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
      const s = i.attributes.media_position, a = i.attributes.media_position_updated_at;
      let o = s;
      if (a) {
        const c = (/* @__PURE__ */ new Date()).getTime(), d = new Date(a).getTime(), p = (c - d) / 1e3;
        i.state === "playing" && (o += p);
      }
      const r = Math.max(0, o - 20);
      this.hass.callService("media_player", "media_seek", {
        entity_id: e,
        seek_position: r
      });
    }
  }
  /**
   * Render empty state
   */
  _renderEmpty() {
    return n`
      <div class="empty">
        <ha-icon icon="mdi:movie-open-outline"></ha-icon>
        <p>${ht(this.hass.language, "no_media")}</p>
      </div>
    `;
  }
  /**
   * Render error state
   */
  _renderError(e) {
    return n`
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
_.styles = Bt;
m([
  X({ attribute: !1 })
], _.prototype, "hass", 2);
m([
  f()
], _.prototype, "_config", 2);
m([
  f()
], _.prototype, "_currentPage", 2);
m([
  f()
], _.prototype, "_itemsPerPage", 2);
m([
  f()
], _.prototype, "_pressStartTime", 2);
m([
  f()
], _.prototype, "_holdTimer", 2);
m([
  f()
], _.prototype, "_isHoldActive", 2);
m([
  f()
], _.prototype, "_rewindActive", 2);
m([
  f()
], _.prototype, "_items", 2);
m([
  f()
], _.prototype, "_error", 2);
m([
  f()
], _.prototype, "_lastUpdate", 2);
m([
  Xt("jellyha-item-details-modal")
], _.prototype, "_modal", 2);
m([
  f()
], _.prototype, "_scrollProgress", 2);
m([
  f()
], _.prototype, "_hasScrollableContent", 2);
_ = m([
  Z("jellyha-library-card")
], _);
//# sourceMappingURL=jellyha-cards.js.map
