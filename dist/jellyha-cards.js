/**
 * @license
 * Copyright 2019 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const G = globalThis, it = G.ShadowRoot && (G.ShadyCSS === void 0 || G.ShadyCSS.nativeShadow) && "adoptedStyleSheets" in Document.prototype && "replace" in CSSStyleSheet.prototype, at = Symbol(), dt = /* @__PURE__ */ new WeakMap();
let xt = class {
  constructor(t, i, a) {
    if (this._$cssResult$ = !0, a !== at) throw Error("CSSResult is not constructable. Use `unsafeCSS` or `css` instead.");
    this.cssText = t, this.t = i;
  }
  get styleSheet() {
    let t = this.o;
    const i = this.t;
    if (it && t === void 0) {
      const a = i !== void 0 && i.length === 1;
      a && (t = dt.get(i)), t === void 0 && ((this.o = t = new CSSStyleSheet()).replaceSync(this.cssText), a && dt.set(i, t));
    }
    return t;
  }
  toString() {
    return this.cssText;
  }
};
const jt = (e) => new xt(typeof e == "string" ? e : e + "", void 0, at), W = (e, ...t) => {
  const i = e.length === 1 ? e[0] : t.reduce((a, s, o) => a + ((n) => {
    if (n._$cssResult$ === !0) return n.cssText;
    if (typeof n == "number") return n;
    throw Error("Value passed to 'css' function must be a 'css' function result: " + n + ". Use 'unsafeCSS' to pass non-literal values, but take care to ensure page security.");
  })(s) + e[o + 1], e[0]);
  return new xt(i, e, at);
}, Et = (e, t) => {
  if (it) e.adoptedStyleSheets = t.map((i) => i instanceof CSSStyleSheet ? i : i.styleSheet);
  else for (const i of t) {
    const a = document.createElement("style"), s = G.litNonce;
    s !== void 0 && a.setAttribute("nonce", s), a.textContent = i.cssText, e.appendChild(a);
  }
}, ht = it ? (e) => e : (e) => e instanceof CSSStyleSheet ? ((t) => {
  let i = "";
  for (const a of t.cssRules) i += a.cssText;
  return jt(i);
})(e) : e;
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const { is: Tt, defineProperty: Mt, getOwnPropertyDescriptor: zt, getOwnPropertyNames: Dt, getOwnPropertySymbols: It, getPrototypeOf: Ot } = Object, K = globalThis, pt = K.trustedTypes, Rt = pt ? pt.emptyScript : "", Ht = K.reactiveElementPolyfillSupport, O = (e, t) => e, J = { toAttribute(e, t) {
  switch (t) {
    case Boolean:
      e = e ? Rt : null;
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
} }, st = (e, t) => !Tt(e, t), gt = { attribute: !0, type: String, converter: J, reflect: !1, useDefault: !1, hasChanged: st };
Symbol.metadata ??= Symbol("metadata"), K.litPropertyMetadata ??= /* @__PURE__ */ new WeakMap();
let T = class extends HTMLElement {
  static addInitializer(t) {
    this._$Ei(), (this.l ??= []).push(t);
  }
  static get observedAttributes() {
    return this.finalize(), this._$Eh && [...this._$Eh.keys()];
  }
  static createProperty(t, i = gt) {
    if (i.state && (i.attribute = !1), this._$Ei(), this.prototype.hasOwnProperty(t) && ((i = Object.create(i)).wrapped = !0), this.elementProperties.set(t, i), !i.noAccessor) {
      const a = Symbol(), s = this.getPropertyDescriptor(t, a, i);
      s !== void 0 && Mt(this.prototype, t, s);
    }
  }
  static getPropertyDescriptor(t, i, a) {
    const { get: s, set: o } = zt(this.prototype, t) ?? { get() {
      return this[i];
    }, set(n) {
      this[i] = n;
    } };
    return { get: s, set(n) {
      const d = s?.call(this);
      o?.call(this, n), this.requestUpdate(t, d, a);
    }, configurable: !0, enumerable: !0 };
  }
  static getPropertyOptions(t) {
    return this.elementProperties.get(t) ?? gt;
  }
  static _$Ei() {
    if (this.hasOwnProperty(O("elementProperties"))) return;
    const t = Ot(this);
    t.finalize(), t.l !== void 0 && (this.l = [...t.l]), this.elementProperties = new Map(t.elementProperties);
  }
  static finalize() {
    if (this.hasOwnProperty(O("finalized"))) return;
    if (this.finalized = !0, this._$Ei(), this.hasOwnProperty(O("properties"))) {
      const i = this.properties, a = [...Dt(i), ...It(i)];
      for (const s of a) this.createProperty(s, i[s]);
    }
    const t = this[Symbol.metadata];
    if (t !== null) {
      const i = litPropertyMetadata.get(t);
      if (i !== void 0) for (const [a, s] of i) this.elementProperties.set(a, s);
    }
    this._$Eh = /* @__PURE__ */ new Map();
    for (const [i, a] of this.elementProperties) {
      const s = this._$Eu(i, a);
      s !== void 0 && this._$Eh.set(s, i);
    }
    this.elementStyles = this.finalizeStyles(this.styles);
  }
  static finalizeStyles(t) {
    const i = [];
    if (Array.isArray(t)) {
      const a = new Set(t.flat(1 / 0).reverse());
      for (const s of a) i.unshift(ht(s));
    } else t !== void 0 && i.push(ht(t));
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
    return Et(t, this.constructor.elementStyles), t;
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
    const a = this.constructor.elementProperties.get(t), s = this.constructor._$Eu(t, a);
    if (s !== void 0 && a.reflect === !0) {
      const o = (a.converter?.toAttribute !== void 0 ? a.converter : J).toAttribute(i, a.type);
      this._$Em = t, o == null ? this.removeAttribute(s) : this.setAttribute(s, o), this._$Em = null;
    }
  }
  _$AK(t, i) {
    const a = this.constructor, s = a._$Eh.get(t);
    if (s !== void 0 && this._$Em !== s) {
      const o = a.getPropertyOptions(s), n = typeof o.converter == "function" ? { fromAttribute: o.converter } : o.converter?.fromAttribute !== void 0 ? o.converter : J;
      this._$Em = s;
      const d = n.fromAttribute(i, o.type);
      this[s] = d ?? this._$Ej?.get(s) ?? d, this._$Em = null;
    }
  }
  requestUpdate(t, i, a, s = !1, o) {
    if (t !== void 0) {
      const n = this.constructor;
      if (s === !1 && (o = this[t]), a ??= n.getPropertyOptions(t), !((a.hasChanged ?? st)(o, i) || a.useDefault && a.reflect && o === this._$Ej?.get(t) && !this.hasAttribute(n._$Eu(t, a)))) return;
      this.C(t, i, a);
    }
    this.isUpdatePending === !1 && (this._$ES = this._$EP());
  }
  C(t, i, { useDefault: a, reflect: s, wrapped: o }, n) {
    a && !(this._$Ej ??= /* @__PURE__ */ new Map()).has(t) && (this._$Ej.set(t, n ?? i ?? this[t]), o !== !0 || n !== void 0) || (this._$AL.has(t) || (this.hasUpdated || a || (i = void 0), this._$AL.set(t, i)), s === !0 && this._$Em !== t && (this._$Eq ??= /* @__PURE__ */ new Set()).add(t));
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
        for (const [s, o] of this._$Ep) this[s] = o;
        this._$Ep = void 0;
      }
      const a = this.constructor.elementProperties;
      if (a.size > 0) for (const [s, o] of a) {
        const { wrapped: n } = o, d = this[s];
        n !== !0 || this._$AL.has(s) || d === void 0 || this.C(s, void 0, o, d);
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
T.elementStyles = [], T.shadowRootOptions = { mode: "open" }, T[O("elementProperties")] = /* @__PURE__ */ new Map(), T[O("finalized")] = /* @__PURE__ */ new Map(), Ht?.({ ReactiveElement: T }), (K.reactiveElementVersions ??= []).push("2.1.2");
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const ot = globalThis, ut = (e) => e, V = ot.trustedTypes, mt = V ? V.createPolicy("lit-html", { createHTML: (e) => e }) : void 0, $t = "$lit$", S = `lit$${Math.random().toFixed(9).slice(2)}$`, Ct = "?" + S, Nt = `<${Ct}>`, A = document, R = () => A.createComment(""), H = (e) => e === null || typeof e != "object" && typeof e != "function", nt = Array.isArray, Lt = (e) => nt(e) || typeof e?.[Symbol.iterator] == "function", Q = `[ 	
\f\r]`, I = /<(?:(!--|\/[^a-zA-Z])|(\/?[a-zA-Z][^>\s]*)|(\/?$))/g, ft = /-->/g, _t = />/g, k = RegExp(`>|${Q}(?:([^\\s"'>=/]+)(${Q}*=${Q}*(?:[^ 	
\f\r"'\`<>=]|("|')|))|$)`, "g"), vt = /'/g, wt = /"/g, St = /^(?:script|style|textarea|title)$/i, Ut = (e) => (t, ...i) => ({ _$litType$: e, strings: t, values: i }), r = Ut(1), M = Symbol.for("lit-noChange"), l = Symbol.for("lit-nothing"), yt = /* @__PURE__ */ new WeakMap(), P = A.createTreeWalker(A, 129);
function kt(e, t) {
  if (!nt(e) || !e.hasOwnProperty("raw")) throw Error("invalid template strings array");
  return mt !== void 0 ? mt.createHTML(t) : t;
}
const Wt = (e, t) => {
  const i = e.length - 1, a = [];
  let s, o = t === 2 ? "<svg>" : t === 3 ? "<math>" : "", n = I;
  for (let d = 0; d < i; d++) {
    const c = e[d];
    let p, g, h = -1, m = 0;
    for (; m < c.length && (n.lastIndex = m, g = n.exec(c), g !== null); ) m = n.lastIndex, n === I ? g[1] === "!--" ? n = ft : g[1] !== void 0 ? n = _t : g[2] !== void 0 ? (St.test(g[2]) && (s = RegExp("</" + g[2], "g")), n = k) : g[3] !== void 0 && (n = k) : n === k ? g[0] === ">" ? (n = s ?? I, h = -1) : g[1] === void 0 ? h = -2 : (h = n.lastIndex - g[2].length, p = g[1], n = g[3] === void 0 ? k : g[3] === '"' ? wt : vt) : n === wt || n === vt ? n = k : n === ft || n === _t ? n = I : (n = k, s = void 0);
    const v = n === k && e[d + 1].startsWith("/>") ? " " : "";
    o += n === I ? c + Nt : h >= 0 ? (a.push(p), c.slice(0, h) + $t + c.slice(h) + S + v) : c + S + (h === -2 ? d : v);
  }
  return [kt(e, o + (e[i] || "<?>") + (t === 2 ? "</svg>" : t === 3 ? "</math>" : "")), a];
};
class N {
  constructor({ strings: t, _$litType$: i }, a) {
    let s;
    this.parts = [];
    let o = 0, n = 0;
    const d = t.length - 1, c = this.parts, [p, g] = Wt(t, i);
    if (this.el = N.createElement(p, a), P.currentNode = this.el.content, i === 2 || i === 3) {
      const h = this.el.content.firstChild;
      h.replaceWith(...h.childNodes);
    }
    for (; (s = P.nextNode()) !== null && c.length < d; ) {
      if (s.nodeType === 1) {
        if (s.hasAttributes()) for (const h of s.getAttributeNames()) if (h.endsWith($t)) {
          const m = g[n++], v = s.getAttribute(h).split(S), X = /([.?@])?(.*)/.exec(m);
          c.push({ type: 1, index: o, name: X[2], strings: v, ctor: X[1] === "." ? Ft : X[1] === "?" ? Xt : X[1] === "@" ? Yt : Z }), s.removeAttribute(h);
        } else h.startsWith(S) && (c.push({ type: 6, index: o }), s.removeAttribute(h));
        if (St.test(s.tagName)) {
          const h = s.textContent.split(S), m = h.length - 1;
          if (m > 0) {
            s.textContent = V ? V.emptyScript : "";
            for (let v = 0; v < m; v++) s.append(h[v], R()), P.nextNode(), c.push({ type: 2, index: ++o });
            s.append(h[m], R());
          }
        }
      } else if (s.nodeType === 8) if (s.data === Ct) c.push({ type: 2, index: o });
      else {
        let h = -1;
        for (; (h = s.data.indexOf(S, h + 1)) !== -1; ) c.push({ type: 7, index: o }), h += S.length - 1;
      }
      o++;
    }
  }
  static createElement(t, i) {
    const a = A.createElement("template");
    return a.innerHTML = t, a;
  }
}
function z(e, t, i = e, a) {
  if (t === M) return t;
  let s = a !== void 0 ? i._$Co?.[a] : i._$Cl;
  const o = H(t) ? void 0 : t._$litDirective$;
  return s?.constructor !== o && (s?._$AO?.(!1), o === void 0 ? s = void 0 : (s = new o(e), s._$AT(e, i, a)), a !== void 0 ? (i._$Co ??= [])[a] = s : i._$Cl = s), s !== void 0 && (t = z(e, s._$AS(e, t.values), s, a)), t;
}
class Bt {
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
    const { el: { content: i }, parts: a } = this._$AD, s = (t?.creationScope ?? A).importNode(i, !0);
    P.currentNode = s;
    let o = P.nextNode(), n = 0, d = 0, c = a[0];
    for (; c !== void 0; ) {
      if (n === c.index) {
        let p;
        c.type === 2 ? p = new B(o, o.nextSibling, this, t) : c.type === 1 ? p = new c.ctor(o, c.name, c.strings, this, t) : c.type === 6 && (p = new qt(o, this, t)), this._$AV.push(p), c = a[++d];
      }
      n !== c?.index && (o = P.nextNode(), n++);
    }
    return P.currentNode = A, s;
  }
  p(t) {
    let i = 0;
    for (const a of this._$AV) a !== void 0 && (a.strings !== void 0 ? (a._$AI(t, a, i), i += a.strings.length - 2) : a._$AI(t[i])), i++;
  }
}
class B {
  get _$AU() {
    return this._$AM?._$AU ?? this._$Cv;
  }
  constructor(t, i, a, s) {
    this.type = 2, this._$AH = l, this._$AN = void 0, this._$AA = t, this._$AB = i, this._$AM = a, this.options = s, this._$Cv = s?.isConnected ?? !0;
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
    t = z(this, t, i), H(t) ? t === l || t == null || t === "" ? (this._$AH !== l && this._$AR(), this._$AH = l) : t !== this._$AH && t !== M && this._(t) : t._$litType$ !== void 0 ? this.$(t) : t.nodeType !== void 0 ? this.T(t) : Lt(t) ? this.k(t) : this._(t);
  }
  O(t) {
    return this._$AA.parentNode.insertBefore(t, this._$AB);
  }
  T(t) {
    this._$AH !== t && (this._$AR(), this._$AH = this.O(t));
  }
  _(t) {
    this._$AH !== l && H(this._$AH) ? this._$AA.nextSibling.data = t : this.T(A.createTextNode(t)), this._$AH = t;
  }
  $(t) {
    const { values: i, _$litType$: a } = t, s = typeof a == "number" ? this._$AC(t) : (a.el === void 0 && (a.el = N.createElement(kt(a.h, a.h[0]), this.options)), a);
    if (this._$AH?._$AD === s) this._$AH.p(i);
    else {
      const o = new Bt(s, this), n = o.u(this.options);
      o.p(i), this.T(n), this._$AH = o;
    }
  }
  _$AC(t) {
    let i = yt.get(t.strings);
    return i === void 0 && yt.set(t.strings, i = new N(t)), i;
  }
  k(t) {
    nt(this._$AH) || (this._$AH = [], this._$AR());
    const i = this._$AH;
    let a, s = 0;
    for (const o of t) s === i.length ? i.push(a = new B(this.O(R()), this.O(R()), this, this.options)) : a = i[s], a._$AI(o), s++;
    s < i.length && (this._$AR(a && a._$AB.nextSibling, s), i.length = s);
  }
  _$AR(t = this._$AA.nextSibling, i) {
    for (this._$AP?.(!1, !0, i); t !== this._$AB; ) {
      const a = ut(t).nextSibling;
      ut(t).remove(), t = a;
    }
  }
  setConnected(t) {
    this._$AM === void 0 && (this._$Cv = t, this._$AP?.(t));
  }
}
class Z {
  get tagName() {
    return this.element.tagName;
  }
  get _$AU() {
    return this._$AM._$AU;
  }
  constructor(t, i, a, s, o) {
    this.type = 1, this._$AH = l, this._$AN = void 0, this.element = t, this.name = i, this._$AM = s, this.options = o, a.length > 2 || a[0] !== "" || a[1] !== "" ? (this._$AH = Array(a.length - 1).fill(new String()), this.strings = a) : this._$AH = l;
  }
  _$AI(t, i = this, a, s) {
    const o = this.strings;
    let n = !1;
    if (o === void 0) t = z(this, t, i, 0), n = !H(t) || t !== this._$AH && t !== M, n && (this._$AH = t);
    else {
      const d = t;
      let c, p;
      for (t = o[0], c = 0; c < o.length - 1; c++) p = z(this, d[a + c], i, c), p === M && (p = this._$AH[c]), n ||= !H(p) || p !== this._$AH[c], p === l ? t = l : t !== l && (t += (p ?? "") + o[c + 1]), this._$AH[c] = p;
    }
    n && !s && this.j(t);
  }
  j(t) {
    t === l ? this.element.removeAttribute(this.name) : this.element.setAttribute(this.name, t ?? "");
  }
}
class Ft extends Z {
  constructor() {
    super(...arguments), this.type = 3;
  }
  j(t) {
    this.element[this.name] = t === l ? void 0 : t;
  }
}
class Xt extends Z {
  constructor() {
    super(...arguments), this.type = 4;
  }
  j(t) {
    this.element.toggleAttribute(this.name, !!t && t !== l);
  }
}
class Yt extends Z {
  constructor(t, i, a, s, o) {
    super(t, i, a, s, o), this.type = 5;
  }
  _$AI(t, i = this) {
    if ((t = z(this, t, i, 0) ?? l) === M) return;
    const a = this._$AH, s = t === l && a !== l || t.capture !== a.capture || t.once !== a.once || t.passive !== a.passive, o = t !== l && (a === l || s);
    s && this.element.removeEventListener(this.name, this, a), o && this.element.addEventListener(this.name, this, t), this._$AH = t;
  }
  handleEvent(t) {
    typeof this._$AH == "function" ? this._$AH.call(this.options?.host ?? this.element, t) : this._$AH.handleEvent(t);
  }
}
class qt {
  constructor(t, i, a) {
    this.element = t, this.type = 6, this._$AN = void 0, this._$AM = i, this.options = a;
  }
  get _$AU() {
    return this._$AM._$AU;
  }
  _$AI(t) {
    z(this, t);
  }
}
const Gt = ot.litHtmlPolyfillSupport;
Gt?.(N, B), (ot.litHtmlVersions ??= []).push("3.3.2");
const Pt = (e, t, i) => {
  const a = i?.renderBefore ?? t;
  let s = a._$litPart$;
  if (s === void 0) {
    const o = i?.renderBefore ?? null;
    a._$litPart$ = s = new B(t.insertBefore(R(), o), o, void 0, i ?? {});
  }
  return s._$AI(e), s;
};
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const rt = globalThis;
class b extends T {
  constructor() {
    super(...arguments), this.renderOptions = { host: this }, this._$Do = void 0;
  }
  createRenderRoot() {
    const t = super.createRenderRoot();
    return this.renderOptions.renderBefore ??= t.firstChild, t;
  }
  update(t) {
    const i = this.render();
    this.hasUpdated || (this.renderOptions.isConnected = this.isConnected), super.update(t), this._$Do = Pt(i, this.renderRoot, this.renderOptions);
  }
  connectedCallback() {
    super.connectedCallback(), this._$Do?.setConnected(!0);
  }
  disconnectedCallback() {
    super.disconnectedCallback(), this._$Do?.setConnected(!1);
  }
  render() {
    return M;
  }
}
b._$litElement$ = !0, b.finalized = !0, rt.litElementHydrateSupport?.({ LitElement: b });
const Jt = rt.litElementPolyfillSupport;
Jt?.({ LitElement: b });
(rt.litElementVersions ??= []).push("4.2.2");
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const D = (e) => (t, i) => {
  i !== void 0 ? i.addInitializer(() => {
    customElements.define(e, t);
  }) : customElements.define(e, t);
};
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const Vt = { attribute: !0, type: String, converter: J, reflect: !1, hasChanged: st }, Kt = (e = Vt, t, i) => {
  const { kind: a, metadata: s } = i;
  let o = globalThis.litPropertyMetadata.get(s);
  if (o === void 0 && globalThis.litPropertyMetadata.set(s, o = /* @__PURE__ */ new Map()), a === "setter" && ((e = Object.create(e)).wrapped = !0), o.set(i.name, e), a === "accessor") {
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
function x(e) {
  return (t, i) => typeof i == "object" ? Kt(e, t, i) : ((a, s, o) => {
    const n = s.hasOwnProperty(o);
    return s.constructor.createProperty(o, a), n ? Object.getOwnPropertyDescriptor(s, o) : void 0;
  })(e, t, i);
}
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
function u(e) {
  return x({ ...e, state: !0, attribute: !1 });
}
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const Zt = (e, t, i) => (i.configurable = !0, i.enumerable = !0, Reflect.decorate && typeof t != "object" && Object.defineProperty(e, t, i), i);
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
function Qt(e, t) {
  return (i, a, s) => {
    const o = (n) => n.renderRoot?.querySelector(e) ?? null;
    return Zt(i, a, { get() {
      return o(this);
    } });
  };
}
function tt(e, t) {
  if (!t || !e.date_added)
    return !1;
  const i = new Date(e.date_added);
  return ((/* @__PURE__ */ new Date()).getTime() - i.getTime()) / (1e3 * 60 * 60 * 24) <= t;
}
function Y(e, t = "en") {
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
function et(e) {
  if (e < 60)
    return `${e}m`;
  const t = Math.floor(e / 60), i = e % 60;
  return i > 0 ? `${t}h ${i}m` : `${t}h`;
}
const At = W`
  :host {
    display: block;
    height: 100%;
    --jf-card-bg: var(--ha-card-background, var(--card-background-color, #1c1c1c));
    --jf-primary: var(--primary-color, #18BCF2);
    --jf-text: var(--primary-text-color, #fff);
    --jf-text-secondary: var(--secondary-text-color, rgba(255, 255, 255, 0.7));
    --jf-divider: var(--divider-color, rgba(255, 255, 255, 0.12));
    --jf-poster-radius: var(--ha-card-border-radius, 12px);
    --jf-transition: 0.2s ease-out;
    --jf-movie-badge: #AA5CC3;
    --jf-series-badge: #F2A218;
    --jf-border-color: var(--divider-color, rgba(255, 255, 255, 0.15));
  }

  ha-card {
    background: var(--jf-card-bg);
    border-radius: var(--ha-card-border-radius, 12px);
    position: relative;
    z-index: 0;
    box-shadow: var(--ha-card-box-shadow, none);
    border: var(--ha-card-border, 1px solid var(--ha-card-border-color, var(--divider-color, #e0e0e0)));
    overflow-y: auto;
    height: 100%;
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
  .media-item.list-item .poster-inner::after {
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
`, q = {
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
    rewinding: "REWINDING"
  },
  de: {
    loading: "Laden…",
    no_media: "Keine neuen Medien gefunden",
    error: "Fehler beim Laden der Medien",
    new: "Neu",
    minutes: "Min",
    play: "Abspielen",
    pause: "Pause",
    stop: "Stopp",
    nothing_playing: "Nichts wird abgespielt",
    entity_not_found: "Entität nicht gefunden",
    rewinding: "RUCKLING"
  },
  fr: {
    loading: "Chargement…",
    no_media: "Aucun média récent trouvé",
    error: "Erreur lors du chargement des médias",
    new: "Nouveau",
    minutes: "min",
    play: "Jouer",
    pause: "Pause",
    stop: "Arrêt",
    nothing_playing: "Rien en cours de lecture",
    entity_not_found: "Entité introuvable",
    rewinding: "BOBINAGE"
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
    nothing_playing: "Nada reproduciéndose",
    entity_not_found: "Entidad no encontrada",
    rewinding: "REBOBINANDO"
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
function $(e, t) {
  const i = e.split("-")[0].toLowerCase();
  return q[i]?.[t] ? q[i][t] : q.en?.[t] ? q.en[t] : t;
}
var te = Object.defineProperty, ee = Object.getOwnPropertyDescriptor, E = (e, t, i, a) => {
  for (var s = a > 1 ? void 0 : a ? ee(t, i) : t, o = e.length - 1, n; o >= 0; o--)
    (n = e[o]) && (s = (a ? n(t, i, s) : n(s)) || s);
  return a && s && te(t, i, s), s;
};
let C = class extends b {
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
        const a = navigator.userAgent || navigator.vendor || window.opera, s = /android/i.test(a), o = /iPad|iPhone|iPod/.test(a) && !window.MSStream;
        if (s) {
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
    this._portalContainer && Pt(this._renderDialogContent(), this._portalContainer);
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
C.styles = W`
        /* Styles handled in _getPortalStyles */
    `;
E([
  x({ attribute: !1 })
], C.prototype, "hass", 2);
E([
  u()
], C.prototype, "_item", 2);
E([
  u()
], C.prototype, "_nextUpItem", 2);
E([
  u()
], C.prototype, "_defaultCastDevice", 2);
E([
  u()
], C.prototype, "_open", 2);
E([
  u()
], C.prototype, "_confirmDelete", 2);
C = E([
  D("jellyha-item-details-modal")
], C);
var ie = Object.defineProperty, ae = Object.getOwnPropertyDescriptor, lt = (e, t, i, a) => {
  for (var s = a > 1 ? void 0 : a ? ae(t, i) : t, o = e.length - 1, n; o >= 0; o--)
    (n = e[o]) && (s = (a ? n(t, i, s) : n(s)) || s);
  return a && s && ie(t, i, s), s;
};
function se(e, t, i) {
  const a = new CustomEvent(t, {
    bubbles: !0,
    composed: !0,
    detail: i
  });
  e.dispatchEvent(a);
}
let L = class extends b {
  setConfig(e) {
    this._config = e;
  }
  render() {
    if (!this.hass || !this._config)
      return r``;
    const e = this._config.click_action || "more-info", t = this._config.hold_action || "jellyfin", a = this._config.layout === "grid" && this._config.enable_pagination === !1 && (this._config.auto_swipe_interval || 0) > 0 ? "Rows" : "Columns";
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

        <div class="side-by-side">
          <div class="form-row">
            <ha-select
              label="Layout"
              .value=${this._config.layout || "carousel"}
              @selected=${this._layoutChanged}
              @closed=${(s) => s.stopPropagation()}
            >
              <mwc-list-item value="carousel">Carousel</mwc-list-item>
              <mwc-list-item value="grid">Grid</mwc-list-item>
              <mwc-list-item value="list">List</mwc-list-item>
            </ha-select>
          </div>

          <div class="form-row">
            <ha-select
              label="Media Type"
              .value=${this._config.media_type || "both"}
              @selected=${this._mediaTypeChanged}
              @closed=${(s) => s.stopPropagation()}
            >
              <mwc-list-item value="both">Movies & TV Shows</mwc-list-item>
              <mwc-list-item value="movies">Movies Only</mwc-list-item>
              <mwc-list-item value="series">TV Shows Only</mwc-list-item>
            </ha-select>
          </div>
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
                <span>${a}: ${(this._config.columns || 1) === 1 ? "Auto" : this._config.columns}</span>
              </div>
            ` : ""}

        <div class="side-by-side">
          <div class="form-row">
            <ha-textfield
              label="Items Per Page"
              type="number"
              min="1"
              required
              .value=${this._config.items_per_page !== void 0 && this._config.items_per_page !== null ? String(this._config.items_per_page) : ""}
              @input=${this._itemsPerPageChanged}
            ></ha-textfield>
          </div>

          <div class="form-row">
            <ha-textfield
              label="Max Pages (0 = no limit)"
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
              label="Auto Swipe (sec, 0 = off)"
              type="number"
              min="0"
              max="60"
              .value=${String(this._config.auto_swipe_interval || 0)}
              @input=${this._autoSwipeIntervalChanged}
            ></ha-textfield>
          </div>

          <div class="form-row">
            <ha-textfield
              label="New Badge Days (0 = off)"
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
              label="Short Press (Click)"
              .value=${e}
              @selected=${this._clickActionChanged}
              @closed=${(s) => s.stopPropagation()}
            >
              <mwc-list-item value="jellyfin">Open in Jellyfin</mwc-list-item>
              <mwc-list-item value="cast">Cast to Chromecast</mwc-list-item>
              <mwc-list-item value="more-info">More Information</mwc-list-item>
              <mwc-list-item value="none">No Action</mwc-list-item>
            </ha-select>
          </div>

          <div class="form-row">
            <ha-select
              label="Long Press (Hold)"
              .value=${t}
              @selected=${this._holdActionChanged}
              @closed=${(s) => s.stopPropagation()}
            >
              <mwc-list-item value="jellyfin">Open in Jellyfin</mwc-list-item>
              <mwc-list-item value="cast">Cast to Chromecast</mwc-list-item>
              <mwc-list-item value="more-info">More Information</mwc-list-item>
              <mwc-list-item value="none">No Action</mwc-list-item>
            </ha-select>
          </div>
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
        .checked=${this._config.show_ratings !== !1}
        @change=${this._showRatingsChanged}
      ></ha-switch>
      <span>Show Rating</span>
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
        .checked=${this._config.show_date_added === !0}
        @change=${this._showDateAddedChanged}
      ></ha-switch>
      <span>Show Date Added</span>
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
        .checked=${this._config.show_description_on_hover !== !1}
        @change=${this._showDescriptionOnHoverChanged}
      ></ha-switch>
      <span>Show Description</span>
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

    <div class="side-by-side">
      <div class="form-row">
        <ha-select
          label="Metadata Position"
          .value=${this._config.metadata_position || "below"}
          @selected=${this._metadataPositionChanged}
          @closed=${(s) => s.stopPropagation()}
        >
          <mwc-list-item value="below">Below</mwc-list-item>
          <mwc-list-item value="above">Above</mwc-list-item>
        </ha-select>
      </div>

      <div class="form-row">
        <ha-select
          label="Sort Order"
          .value=${this._config.sort_option || "date_added_desc"}
          @selected=${this._sortOptionChanged}
          @closed=${(s) => s.stopPropagation()}
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

    <div class="side-by-side">
      <div class="checkbox-row">
        <ha-switch
          .checked=${this._config.enable_pagination !== !1}
          @change=${this._enablePaginationChanged}
        ></ha-switch>
        <span>Enable Pagination</span>
      </div>

      <div class="checkbox-row">
        <ha-switch
          .checked=${this._config.show_pagination_dots !== !1}
          @change=${this._showPaginationDotsChanged}
        ></ha-switch>
        <span>Show Pagination Dots</span>
      </div>
    </div>

    <div class="form-row">
      <ha-select
        label="Filter Watch Status"
        .value=${this._config.status_filter || "all"}
        @selected=${this._statusFilterChanged}
        @closed=${(s) => s.stopPropagation()}
      >
        <mwc-list-item value="all">All</mwc-list-item>
        <mwc-list-item value="unwatched">Unwatched</mwc-list-item>
        <mwc-list-item value="watched">Watched</mwc-list-item>
      </ha-select>
    </div>

    <div class="side-by-side">
      <div class="checkbox-row">
        <ha-switch
          .checked=${this._config.filter_favorites === !0}
          @change=${this._filterFavoritesChanged}
        ></ha-switch>
        <span>Filter Favorites</span>
      </div>

      <div class="checkbox-row">
        <ha-switch
          .checked=${this._config.filter_newly_added === !0}
          @change=${this._filterNewlyAddedChanged}
        ></ha-switch>
        <span>Filter New Items</span>
      </div>
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
    const i = e.target.value.trim();
    i !== "" ? this._updateConfig("items_per_page", Number(i)) : this._updateConfig("items_per_page", null);
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
    this._config = i, se(this, "config-changed", { config: i });
  }
};
L.styles = W`
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
lt([
  x({ attribute: !1 })
], L.prototype, "hass", 2);
lt([
  u()
], L.prototype, "_config", 2);
L = lt([
  D("jellyha-library-editor")
], L);
var oe = Object.defineProperty, ne = Object.getOwnPropertyDescriptor, y = (e, t, i, a) => {
  for (var s = a > 1 ? void 0 : a ? ne(t, i) : t, o = e.length - 1, n; o >= 0; o--)
    (n = e[o]) && (s = (a ? n(t, i, s) : n(s)) || s);
  return a && s && oe(t, i, s), s;
};
let w = class extends b {
  constructor() {
    super(...arguments), this.layout = "grid", this._pressStartTime = 0, this._isHoldActive = !1, this._itemTouchStartX = 0, this._itemTouchStartY = 0, this._rewindActive = !1;
  }
  render() {
    return !this.item || !this.config || !this.hass ? r`` : this.layout === "list" ? this._renderListItem() : this._renderMediaItem();
  }
  _renderListItem() {
    const e = this.item, t = tt(e, this.config.new_badge_days || 0), i = this._getRating(e), a = this.config.show_media_type_badge !== !1, s = this._isItemPlaying(e);
    return r`
      <div
        class="media-item list-item ${s ? "playing" : ""} ${this.config.show_title ? "" : "no-title"} ${this.config.metadata_position === "above" ? "metadata-above" : ""}"
        tabindex="0"
        role="button"
        aria-label="${e.name}"
        @mousedown="${this._handleMouseDown}"
        @mouseup="${this._handleMouseUp}"
        @touchstart="${this._handleTouchStart}"
        @touchmove="${this._handleTouchMove}"
        @touchend="${this._handleTouchEnd}"
        @touchcancel="${this._handleTouchEnd}"
        @keydown="${this._handleKeydown}"
      >
        <div class="list-poster-wrapper">
          ${this.config.metadata_position === "above" && this.config.show_date_added && e.date_added ? r`<p class="list-date-added">${Y(e.date_added, this.hass?.language)}</p>` : l}
          <div class="poster-container" id="poster-${e.id}">
            <div class="poster-inner">
              <img
                class="poster"
                src="${e.poster_url}&width=300&format=webp"
                alt="${e.name}"
                width="80"
                height="120"
                loading="lazy"
                decoding="async"
                @load="${this._handleImageLoad}"
                @error="${this._handleImageError}"
              />
              <div class="poster-skeleton"></div>
              
              ${a && !s ? r`<span class="list-type-badge ${e.type === "Movie" ? "movie" : "series"}">
                    ${e.type === "Movie" ? "Movie" : "Series"}
                  </span>` : l}
              
              ${s ? l : this._renderStatusBadge(e, t)}
              ${this._renderNowPlayingOverlay(e)}
            </div>
          </div>
          ${this.config.metadata_position !== "above" && this.config.show_date_added && e.date_added ? r`<p class="list-date-added">${Y(e.date_added, this.hass?.language)}</p>` : l}
        </div>
        
        <div class="list-info">
          ${this.config.show_title ? r`<h3 class="list-title">${e.name}</h3>` : l}
          
          <div class="list-metadata">
            ${a && !s ? r`<span class="list-type-badge ${e.type === "Movie" ? "movie" : "series"}">
                  ${e.type === "Movie" ? "Movie" : "Series"}
                </span>` : l}
            ${this.config.show_year && e.year ? r`<span class="list-year">${e.year}</span>` : l}
            ${this.config.show_ratings && i ? r`<span class="list-rating">
                  <ha-icon icon="mdi:star"></ha-icon>
                  ${i.toFixed(1)}
                </span>` : l}
            ${this.config.show_runtime && e.runtime_minutes ? r`<span class="list-runtime">
                  <ha-icon icon="mdi:clock-outline"></ha-icon>
                  ${et(e.runtime_minutes)}
                </span>` : l}
          </div>
          
          ${this.config.show_genres && e.genres && e.genres.length > 0 ? r`<p class="list-genres">${e.genres.slice(0, 3).join(", ")}</p>` : l}
          
          ${this.config.show_description_on_hover !== !1 && e.description ? r`<p class="list-description">${e.description}</p>` : l}
        </div>
      </div>
    `;
  }
  _renderMediaItem() {
    const e = this.item, t = tt(e, this.config.new_badge_days || 0), i = this._getRating(e), a = this.config.show_media_type_badge !== !1, s = this._isItemPlaying(e);
    return r`
      <div
        class="media-item ${s ? "playing" : ""}"
        tabindex="0"
        role="button"
        aria-label="${e.name}"
        @mousedown="${this._handleMouseDown}"
        @mouseup="${this._handleMouseUp}"
        @touchstart="${this._handleTouchStart}"
        @touchmove="${this._handleTouchMove}"
        @touchend="${this._handleTouchEnd}"
        @touchcancel="${this._handleTouchEnd}"
        @keydown="${this._handleKeydown}"
      >
        ${this.config.metadata_position === "above" ? r`
              <div class="media-info-above">
                ${this.config.show_title ? r`<p class="media-title">${e.name}</p>` : l}
                ${this.config.show_year && e.year ? r`<p class="media-year">${e.year}</p>` : l}
                ${this.config.show_date_added && e.date_added ? r`<p class="media-date-added">${Y(e.date_added, this.hass?.language)}</p>` : l}
              </div>
            ` : l}
        <div class="poster-container" id="poster-${e.id}">
          <div class="poster-inner">
            <img
              class="poster"
              src="${e.poster_url}&width=300&format=webp"
              alt="${e.name}"
              width="140"
              height="210"
              loading="lazy"
              decoding="async"
              @load="${this._handleImageLoad}"
              @error="${this._handleImageError}"
            />
            <div class="poster-skeleton"></div>
            
            ${a && !s ? r`<span class="media-type-badge ${e.type === "Movie" ? "movie" : "series"}">
                  ${e.type === "Movie" ? "Movie" : "Series"}
                </span>` : l}
            
            ${s ? l : this._renderStatusBadge(e, t)}
            
            ${this.config.show_ratings && i && !s ? r`
                  <span class="rating">
                    <ha-icon icon="mdi:star"></ha-icon>
                    ${i.toFixed(1)}
                  </span>
                ` : l}
            
            ${this.config.show_runtime && e.runtime_minutes && !s ? r`
                  <span class="runtime">
                    <ha-icon icon="mdi:clock-outline"></ha-icon>
                    ${et(e.runtime_minutes)}
                  </span>
                ` : l}
            
            ${s ? l : r`
            <div class="hover-overlay">
              ${e.year ? r`<span class="overlay-year">${e.year}</span>` : l}
              <h3 class="overlay-title">${e.name}</h3>
              ${this.config.show_genres && e.genres && e.genres.length > 0 ? r`<span class="overlay-genres">${e.genres.slice(0, 3).join(", ")}</span>` : l}
              ${this.config.show_description_on_hover !== !1 && e.description ? r`<p class="overlay-description">${e.description}</p>` : l}
            </div>`}

            ${this._renderNowPlayingOverlay(e)}
          </div>
        </div>
        
        ${this.config.metadata_position === "below" ? r`
              <div class="media-info-below">
                ${this.config.show_title ? r`<p class="media-title">${e.name}</p>` : l}
                ${this.config.show_year && e.year ? r`<p class="media-year">${e.year}</p>` : l}
                ${this.config.show_date_added && e.date_added ? r`<p class="media-date-added">${Y(e.date_added, this.hass?.language)}</p>` : l}
              </div>
            ` : l}
      </div>
    `;
  }
  _renderStatusBadge(e, t) {
    const i = this.config.show_watched_status !== !1;
    return i && e.is_played ? r`
        <div class="status-badge watched">
          <ha-icon icon="mdi:check-bold"></ha-icon>
        </div>
      ` : i && e.type === "Series" && (e.unplayed_count || 0) > 0 ? r`
        <div class="status-badge unplayed">
          ${e.unplayed_count}
        </div>
      ` : t ? r`<span class="new-badge">${$(this.hass.language, "new")}</span>` : r``;
  }
  _renderNowPlayingOverlay(e) {
    if (!this.config.show_now_playing || !this._isItemPlaying(e))
      return l;
    const t = this.hass.states[this.config.default_cast_device];
    return r`
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
          ${this._rewindActive ? "REWINDING" : t.state}
        </span>
        <div class="now-playing-controls">
          <ha-icon-button
            class="${this._rewindActive ? "spinning" : ""}"
            .label=${"Play/Pause"}
            @click="${(i) => {
      i.stopPropagation(), this._handlePlayPause(this.config.default_cast_device);
    }}"
          >
            <ha-icon icon="${this._rewindActive ? "mdi:loading" : t.state === "playing" ? "mdi:pause" : "mdi:play"}"></ha-icon>
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
  _isItemPlaying(e) {
    if (!this.config.default_cast_device || !this.hass) return !1;
    const t = this.hass.states[this.config.default_cast_device];
    if (!t || t.state !== "playing" && t.state !== "paused" && t.state !== "buffering")
      return !1;
    const i = t.attributes.media_title, a = t.attributes.media_series_title;
    return e.name && (i === e.name || a === e.name) || e.type === "Series" && a === e.name;
  }
  _getRating(e) {
    return this.config.rating_source === "auto", e.rating || null;
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
    this._pressStartTime = Date.now(), this._isHoldActive = !1, this._holdTimer = window.setTimeout(() => {
      this._isHoldActive = !0, this._fireAction("hold");
    }, 500);
  }
  _clearHoldTimer() {
    this._holdTimer && (clearTimeout(this._holdTimer), this._holdTimer = void 0);
  }
  _handleMouseDown(e) {
    e.button === 0 && this._startHoldTimer();
  }
  _handleMouseUp(e) {
    this._isHoldActive ? (e.preventDefault(), e.stopPropagation()) : Date.now() - this._pressStartTime < 500 && this._fireAction("click"), this._clearHoldTimer();
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
      const a = e.changedTouches[0].clientX - this._itemTouchStartX, s = e.changedTouches[0].clientY - this._itemTouchStartY;
      i = Math.sqrt(a * a + s * s);
    }
    if (e.preventDefault(), this._isHoldActive) {
      this._isHoldActive = !1;
      return;
    }
    i > 10 || this._fireAction("click");
  }
  _handleKeydown(e) {
    (e.key === "Enter" || e.key === " ") && (e.preventDefault(), this._fireAction("click"));
  }
  _handleImageLoad(e) {
    e.target.classList.add("loaded");
  }
  _handleImageError(e) {
    const t = e.target;
    t.style.display = "none";
  }
  /* --- Playback Control Handlers --- */
  _stopPropagation(e) {
    e.stopPropagation();
  }
  _handlePlayPause(e) {
    this._dispatchHaptic(), this.hass.callService("media_player", "media_play_pause", { entity_id: e });
  }
  _handleStop(e) {
    this._dispatchHaptic(), this.hass.callService("media_player", "turn_off", { entity_id: e });
  }
  _handleRewind(e) {
    this._rewindActive = !0, setTimeout(() => {
      this._rewindActive = !1;
    }, 2e3), this._dispatchHaptic();
    const t = this.hass.states[e];
    if (t && t.attributes.media_position) {
      const i = t.attributes.media_position, a = t.attributes.media_position_updated_at;
      let s = i;
      if (a) {
        const n = (/* @__PURE__ */ new Date()).getTime(), d = new Date(a).getTime(), c = (n - d) / 1e3;
        t.state === "playing" && (s += c);
      }
      const o = Math.max(0, s - 20);
      this.hass.callService("media_player", "media_seek", {
        entity_id: e,
        seek_position: o
      });
    }
  }
  _dispatchHaptic() {
    const e = new CustomEvent("haptic", {
      detail: "selection",
      bubbles: !0,
      composed: !0
    });
    this.dispatchEvent(e);
  }
};
w.styles = At;
y([
  x({ attribute: !1 })
], w.prototype, "hass", 2);
y([
  x({ attribute: !1 })
], w.prototype, "config", 2);
y([
  x({ attribute: !1 })
], w.prototype, "item", 2);
y([
  x({ type: String })
], w.prototype, "layout", 2);
y([
  u()
], w.prototype, "_pressStartTime", 2);
y([
  u()
], w.prototype, "_holdTimer", 2);
y([
  u()
], w.prototype, "_isHoldActive", 2);
y([
  u()
], w.prototype, "_itemTouchStartX", 2);
y([
  u()
], w.prototype, "_itemTouchStartY", 2);
y([
  u()
], w.prototype, "_rewindActive", 2);
w = y([
  D("jellyha-media-item")
], w);
var re = Object.defineProperty, le = Object.getOwnPropertyDescriptor, _ = (e, t, i, a) => {
  for (var s = a > 1 ? void 0 : a ? le(t, i) : t, o = e.length - 1, n; o >= 0; o--)
    (n = e[o]) && (s = (a ? n(t, i, s) : n(s)) || s);
  return a && s && re(t, i, s), s;
};
const ce = "1.0.0";
console.info(
  `%c JELLYHA-LIBRARY-CARD %c v${ce} `,
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
const bt = {
  title: "Jellyfin Library",
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
let f = class extends b {
  constructor() {
    super(), this._currentPage = 0, this._itemsPerPage = 5, this._pressStartTime = 0, this._isHoldActive = !1, this._rewindActive = !1, this._items = [], this._lastUpdate = "", this._touchStartX = 0, this._touchStartY = 0, this._isOverscrolling = !1, this._elasticAnchorX = 0, this._itemTouchStartX = 0, this._itemTouchStartY = 0, this._containerWidth = 0, this.ITEM_WIDTH = 148, this.LIST_ITEM_MIN_WIDTH = 380, this._effectiveListColumns = 1, this._isSwiping = !1, this._autoSwipePaused = !1, this._lastFrameTime = 0, this._scrollAccumulator = 0, this._scrollProgress = 0, this._hasScrollableContent = !1, this.SCROLL_INDICATOR_DOTS = 5, this._handleMouseEnter = () => {
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
    const e = this._config?.auto_swipe_interval;
    !e || e <= 0 || (this._config.enable_pagination !== !1 ? this._autoSwipeTimer = window.setInterval(() => {
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
        const a = this.shadowRoot?.querySelector(".carousel, .grid-wrapper, .list-wrapper");
        if (a) {
          const { scrollLeft: s, scrollWidth: o, clientWidth: n } = a;
          Math.abs(this._scrollAccumulator - s) > 10 && (this._scrollAccumulator = s);
          const c = n / (this._config.auto_swipe_interval * 1e3) * i, p = o / 2;
          this._scrollAccumulator += c, this._scrollAccumulator >= p ? (this._scrollAccumulator = this._scrollAccumulator - p, a.scrollLeft = this._scrollAccumulator) : a.scrollLeft = this._scrollAccumulator;
        }
      }
      this._animationFrameId = requestAnimationFrame(e);
    };
    this._animationFrameId = requestAnimationFrame(e);
  }
  /* Pagination Auto Swipe Logic */
  async _handleAutoSwipePage() {
    const e = this._items || [], t = this._config.items_per_page || this._itemsPerPage, i = this._config.max_pages || 10, a = Math.min(Math.ceil(e.length / t), i);
    this._currentPage >= a - 1 ? await this._animatePageChange("next", () => {
      this._currentPage = 0;
    }) : this._nextPage();
  }
  /* Pagination Handlers */
  async _nextPage() {
    if (!this._config?.entity || !this.hass || !this.hass.states[this._config.entity]) return;
    const t = this._filterItems(this._items || []), i = this._config.items_per_page || this._itemsPerPage, a = this._config.max_pages || 10, s = Math.min(Math.ceil(t.length / i), a);
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
    i.style.transition = "transform 0.2s ease-out, opacity 0.2s ease-out", i.style.transform = `translateX(${a})`, i.style.opacity = "0", await new Promise((o) => setTimeout(o, 200)), t(), await this.updateComplete, this._setScrollPosition(e === "next" ? "start" : "end");
    const s = e === "next" ? "30px" : "-30px";
    i.style.transition = "none", i.style.opacity = "0", i.style.transform = `translateX(${s})`, i.offsetHeight, i.style.transition = "transform 0.25s ease-out, opacity 0.25s ease-out", i.style.transform = "translateX(0)", i.style.opacity = "1", await new Promise((o) => setTimeout(o, 250)), i.style.transition = "", i.style.transform = "", i.style.opacity = "";
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
        const { scrollLeft: s, scrollWidth: o, clientWidth: n } = a, d = o - n, c = s <= 5, p = s >= d - 5, g = this._config.show_pagination !== !1;
        let h = !1;
        if (g) {
          const m = this._getTotalPages();
          c && t > 0 && this._currentPage === 0 && (h = !0), p && t < 0 && this._currentPage >= m - 1 && (h = !0);
        } else
          c && t > 0 && (h = !0), p && t < 0 && (h = !0);
        if (h) {
          this._isOverscrolling || (this._isOverscrolling = !0, this._elasticAnchorX = t), e.preventDefault();
          const m = 0.3, v = t - this._elasticAnchorX;
          a.style.transition = "none", a.style.transform = `translateX(${v * m}px)`;
          return;
        }
      }
      Math.abs(t) > 30 && (this._isSwiping = !0);
    }
  }
  _handleTouchEnd(e) {
    if (this._isOverscrolling) {
      const s = this.shadowRoot?.querySelector(".carousel, .grid-wrapper");
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
    const t = e.changedTouches[0].clientX - this._touchStartX, i = 50, a = this.shadowRoot?.querySelector(".carousel, .grid-wrapper");
    if (t < -i)
      if (a) {
        const { scrollLeft: s, scrollWidth: o, clientWidth: n } = a;
        s + n >= o - 10 && this._nextPage();
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
        const { scrollLeft: s, scrollWidth: o, clientWidth: n } = a, d = o - n, c = s <= 5, p = s >= d - 5, g = this._config.show_pagination !== !1;
        let h = !1;
        if (g) {
          const m = this._getTotalPages();
          c && t > 0 && this._currentPage === 0 && (h = !0), p && t < 0 && this._currentPage >= m - 1 && (h = !0);
        } else
          c && t > 0 && (h = !0), p && t < 0 && (h = !0);
        if (h) {
          this._isOverscrolling || (this._isOverscrolling = !0, this._elasticAnchorX = t), e.preventDefault();
          const m = 0.3, v = t - this._elasticAnchorX;
          a.style.transition = "none", a.style.transform = `translateX(${v * m}px)`;
          return;
        }
      }
      Math.abs(t) > 30 && (this._isSwiping = !0);
    }
  }
  _handlePointerUp(e) {
    if (e.target.releasePointerCapture?.(e.pointerId), this._isOverscrolling) {
      const s = this.shadowRoot?.querySelector(".carousel, .grid-wrapper");
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
    const t = e.clientX - this._touchStartX, i = 50, a = this.shadowRoot?.querySelector(".carousel, .grid-wrapper");
    if (t < -i)
      if (a) {
        const { scrollLeft: s, scrollWidth: o, clientWidth: n } = a;
        s + n >= o - 10 && this._nextPage();
      } else
        this._nextPage();
    else t > i && (a ? a.scrollLeft <= 10 && this._prevPage() : this._prevPage());
    this._touchStartX = 0, this._isSwiping = !1;
  }
  // Scroll handler for elastic dot indicator
  _handleScroll(e) {
    const t = e.target, i = t.scrollWidth, a = t.clientWidth, s = t.scrollLeft, o = i > a + 10;
    if (o !== this._hasScrollableContent && (this._hasScrollableContent = o), o) {
      const n = i - a;
      let d = s / n;
      (n - s < 10 || d > 0.98) && (d = 1), (s < 10 || d < 0.02) && (d = 0), d = Math.min(1, Math.max(0, d)), this._scrollProgress = d;
    }
  }
  // Render scroll indicator for non-paginated scrollable content
  _renderScrollIndicator() {
    if (!this._hasScrollableContent || this._config.show_pagination_dots === !1) return r``;
    const e = this.SCROLL_INDICATOR_DOTS, t = this._scrollProgress, i = Math.round(t * (e - 1));
    return r`
      <div class="scroll-indicator">
        ${Array.from({ length: e }, (a, s) => {
      const o = s === i, n = s === 0 && t < 0.1 || s === e - 1 && t > 0.9;
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
      const t = this.getBoundingClientRect().width;
      if (t === 0) return;
      const i = Math.max(0, t - 32);
      if (i !== this._containerWidth) {
        this._containerWidth = i;
        const s = Math.max(2, Math.floor(i / 160));
        if (s !== this._itemsPerPage && (this._itemsPerPage = s, this.requestUpdate()), this._config) {
          const o = this._config.columns || 1, n = 300;
          if (o > 1) {
            const d = Math.max(1, Math.floor(i / n)), c = Math.min(o, d);
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
    this._config = { ...bt, ...e }, this._effectiveListColumns = this._config.columns || 1;
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
      ...bt
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
      min_rows: 5
    };
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
        const i = t.states[this._config.entity], a = this.hass.states[this._config.entity], s = this._config.default_cast_device;
        if (s) {
          const o = t.states[s], n = this.hass.states[s];
          if (o !== n) return !0;
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
    this._config.media_type === "movies" ? t = t.filter((o) => o.type === "Movie") : this._config.media_type === "series" && (t = t.filter((o) => o.type === "Series")), this._config.filter_favorites && (t = t.filter((o) => o.is_favorite === !0));
    const i = this._config.status_filter || "all";
    i === "unwatched" ? t = t.filter((o) => !o.is_played) : i === "watched" && (t = t.filter((o) => o.is_played === !0)), this._config.filter_newly_added && (t = t.filter((o) => tt(o, this._config.new_badge_days || 0)));
    const a = this._config.sort_option || "date_added_desc";
    t.sort((o, n) => {
      switch (a) {
        case "date_added_asc":
          return (o.date_added || "").localeCompare(n.date_added || "");
        case "date_added_desc":
          return (n.date_added || "").localeCompare(o.date_added || "");
        case "title_asc":
          return (o.name || "").localeCompare(n.name || "");
        case "title_desc":
          return (n.name || "").localeCompare(o.name || "");
        case "year_asc":
          return (o.year || 0) - (n.year || 0);
        case "year_desc":
          return (n.year || 0) - (o.year || 0);
        case "last_played_asc":
          return (o.last_played_date || "").localeCompare(n.last_played_date || "");
        case "last_played_desc":
          return (n.last_played_date || "").localeCompare(o.last_played_date || "");
        default:
          return 0;
      }
    });
    const s = this._config.max_pages;
    if (s != null && s > 0) {
      const o = (this._config.items_per_page || 5) * s;
      t = t.slice(0, o);
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
    return t === "carousel" ? this._renderCarousel(e, i) : t === "list" ? this._renderList(e, i) : t === "grid" ? this._renderGrid(e, i) : r`
      <div class="${t}">
        ${e.map((a) => r`
            <jellyha-media-item
                .hass=${this.hass}
                .config=${this._config}
                .item=${a}
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
    const i = this._config.items_per_page || this._itemsPerPage, a = this._config.max_pages, s = a ? Number(a) : 0, o = s > 0 ? s : 1 / 0, n = Math.min(Math.ceil(e.length / i), o), d = this._currentPage * i, c = !t && (this._config.auto_swipe_interval || 0) > 0, p = t ? e.slice(d, d + i) : c ? [...e, ...e] : e;
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
          ${p.map((g) => r`
            <jellyha-media-item
                .hass=${this.hass}
                .config=${this._config}
                .item=${g}
                .layout=${"grid"}
                @jellyha-action=${this._handleItemAction}
            ></jellyha-media-item>
          `)}
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
    const i = this._config.items_per_page || this._itemsPerPage, a = this._config.max_pages, s = a ? Number(a) : 0, o = s > 0 ? s : 1 / 0, n = Math.min(Math.ceil(e.length / i), o), d = this._currentPage * i, c = !t && (this._config.auto_swipe_interval || 0) > 0, p = t ? e.slice(d, d + i) : c ? [...e, ...e] : e, g = this._effectiveListColumns, h = g === 1;
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
          class="list ${t ? "paginated" : ""} ${h ? "single-column" : ""}"
          style="--jf-list-columns: ${g}"
        >
          ${p.map((m) => r`
            <jellyha-media-item
                .hass=${this.hass}
                .config=${this._config}
                .item=${m}
                .layout=${"list"}
                @jellyha-action=${this._handleItemAction}
            ></jellyha-media-item>
          `)}
        </div>
        ${t && n > 1 ? this._renderPagination(n) : l}
      </div>
    `;
  }
  /**
   * Render grid with optional pagination
   */
  _renderGrid(e, t) {
    const i = this._config.items_per_page || this._itemsPerPage, a = this._config.max_pages, s = a ? Number(a) : 0, o = s > 0 ? s : 1 / 0, n = Math.min(Math.ceil(e.length / i), o), d = this._currentPage * i, c = !t && (this._config.auto_swipe_interval || 0) > 0, p = t ? e.slice(d, d + i) : c ? [...e, ...e] : e, g = this._config.columns || 1, h = g === 1, m = !t && (this._config.auto_swipe_interval || 0) > 0;
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
            class="grid ${t ? "paginated" : ""} ${h ? "auto-columns" : ""} ${m ? "horizontal" : ""}"
            style="--jf-columns: ${g}; --jf-grid-rows: ${g}"
          >
            ${p.map((v) => r`
                <jellyha-media-item
                    .hass=${this.hass}
                    .config=${this._config}
                    .item=${v}
                    .layout=${"grid"}
                    @jellyha-action=${this._handleItemAction}
                ></jellyha-media-item>
            `)}
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
    return this._config.show_pagination_dots === !1 ? r`` : e <= 5 ? this._renderStandardPagination(e) : this._renderSmartPagination(e);
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
   * Perform configured action
   */
  _performAction(e, t) {
    switch (t === "click" ? this._config.click_action : this._config.hold_action) {
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
   * Render empty state
   */
  _renderEmpty() {
    return r`
      <div class="empty">
        <ha-icon icon="mdi:movie-open-outline"></ha-icon>
        <p>${$(this.hass.language, "no_media")}</p>
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
f.styles = At;
_([
  x({ attribute: !1 })
], f.prototype, "hass", 2);
_([
  u()
], f.prototype, "_config", 2);
_([
  u()
], f.prototype, "_currentPage", 2);
_([
  u()
], f.prototype, "_itemsPerPage", 2);
_([
  u()
], f.prototype, "_pressStartTime", 2);
_([
  u()
], f.prototype, "_holdTimer", 2);
_([
  u()
], f.prototype, "_isHoldActive", 2);
_([
  u()
], f.prototype, "_rewindActive", 2);
_([
  u()
], f.prototype, "_items", 2);
_([
  u()
], f.prototype, "_error", 2);
_([
  u()
], f.prototype, "_lastUpdate", 2);
_([
  Qt("jellyha-item-details-modal")
], f.prototype, "_modal", 2);
_([
  u()
], f.prototype, "_scrollProgress", 2);
_([
  u()
], f.prototype, "_hasScrollableContent", 2);
f = _([
  D("jellyha-library-card")
], f);
var de = Object.defineProperty, he = Object.getOwnPropertyDescriptor, ct = (e, t, i, a) => {
  for (var s = a > 1 ? void 0 : a ? he(t, i) : t, o = e.length - 1, n; o >= 0; o--)
    (n = e[o]) && (s = (a ? n(t, i, s) : n(s)) || s);
  return a && s && de(t, i, s), s;
};
function pe(e, t, i) {
  const a = new CustomEvent(t, {
    bubbles: !0,
    composed: !0,
    detail: i
  });
  e.dispatchEvent(a);
}
let U = class extends b {
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
    this._config = i, pe(this, "config-changed", { config: i });
  }
};
U.styles = W`
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
ct([
  x({ attribute: !1 })
], U.prototype, "hass", 2);
ct([
  u()
], U.prototype, "_config", 2);
U = ct([
  D("jellyha-now-playing-editor")
], U);
var ge = Object.defineProperty, ue = Object.getOwnPropertyDescriptor, F = (e, t, i, a) => {
  for (var s = a > 1 ? void 0 : a ? ue(t, i) : t, o = e.length - 1, n; o >= 0; o--)
    (n = e[o]) && (s = (a ? n(t, i, s) : n(s)) || s);
  return a && s && ge(t, i, s), s;
};
window.customCards = window.customCards || [];
window.customCards.push({
  type: "jellyha-now-playing-card",
  name: "JellyHA Now Playing",
  description: "Display currently playing media from Jellyfin",
  preview: !0
});
let j = class extends b {
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
      return this._renderError($(this.hass.language, "entity_not_found") || "Entity not found");
    const i = t.attributes;
    if (!!!i.item_id)
      return this._renderEmpty();
    const s = i.progress_percent || 0, o = i.image_url, n = i.backdrop_url ? `${i.backdrop_url}&width=1280&format=webp` : void 0, d = this._config.show_background && n, c = i.is_paused;
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
                        ${o ? r`
                            <div class="poster-container" @click=${this._handlePosterRewind}>
                                <img src="${o}&width=400&format=webp" alt="${i.title}" loading="eager" fetchpriority="high" />
                                ${this._rewindActive ? r`
                                    <div class="rewind-overlay">
                                        <span>${$(this.hass.language, "rewinding")}</span>
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
                                            <span class="meta-item meta-priority-2">${et(i.runtime_minutes)}</span>
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
                                            <ha-icon-button class="spinning" .label=${$(this.hass.language, "loading")}>
                                                <ha-icon icon="mdi:loading"></ha-icon>
                                            </ha-icon-button>
                                        ` : c ? r`
                                            <ha-icon-button .label=${$(this.hass.language, "play")} @click=${() => this._handleControl("Unpause")}>
                                                <ha-icon icon="mdi:play"></ha-icon>
                                            </ha-icon-button>
                                        ` : r`
                                            <ha-icon-button .label=${$(this.hass.language, "pause")} @click=${() => this._handleControl("Pause")}>
                                                <ha-icon icon="mdi:pause"></ha-icon>
                                            </ha-icon-button>
                                        `}
                                        <ha-icon-button .label=${$(this.hass.language, "stop")} @click=${() => this._handleControl("Stop")}>
                                            <ha-icon icon="mdi:stop"></ha-icon>
                                        </ha-icon-button>
                                    </div>
                                </div>

                                <div class="progress-container" @click=${this._handleSeek}>
                                    <div class="progress-bar">
                                        <div class="progress-fill" style="width: ${s}%"></div>
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
        const e = await fetch("/jellyha_static/phrases.json");
        e.ok && (this._phrases = await e.json());
      } catch (e) {
        console.warn("JellyHA: Could not fetch phrases.json", e);
      }
  }
  _renderEmpty() {
    this._fetchPhrases();
    const t = this.hass.themes?.darkMode ? "https://raw.githubusercontent.com/home-assistant/brands/master/custom_integrations/jellyha/dark_logo.png" : "https://raw.githubusercontent.com/home-assistant/brands/master/custom_integrations/jellyha/logo.png", i = "https://raw.githubusercontent.com/home-assistant/brands/master/custom_integrations/jellyha/icon.png";
    let a = $(this.hass.language, "nothing_playing");
    if (this._phrases.length > 0) {
      const o = Math.floor(Date.now() / 864e5) % this._phrases.length;
      a = this._phrases[o];
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
    const s = a.attributes, o = s.session_id, n = s.position_ticks || 0, d = s.progress_percent || 1, c = n / d * 100;
    if (!o || !c) return;
    const p = Math.round(c * i);
    await this.hass.callService("jellyha", "session_seek", {
      session_id: o,
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
    const s = new CustomEvent("haptic", {
      detail: "selection",
      bubbles: !0,
      composed: !0
    });
    this.dispatchEvent(s);
    const o = 20 * 1e7, n = Math.max(0, a - o);
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
    let m = 0;
    h > n && (m = 1), g > n && (m = 2), this._overflowState !== m && (this._overflowState = m);
  }
};
j.styles = W`
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
            box-shadow: var(--ha-card-box-shadow, none);
            border: var(--ha-card-border, 1px solid var(--ha-card-border-color, var(--divider-color, #e0e0e0)));
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
F([
  x({ attribute: !1 })
], j.prototype, "hass", 2);
F([
  u()
], j.prototype, "_config", 2);
F([
  u()
], j.prototype, "_rewindActive", 2);
F([
  u()
], j.prototype, "_overflowState", 2);
j = F([
  D("jellyha-now-playing-card")
], j);
//# sourceMappingURL=jellyha-cards.js.map
