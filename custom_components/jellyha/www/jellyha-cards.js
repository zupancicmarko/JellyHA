/**
 * @license
 * Copyright 2019 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const oe = globalThis, ue = oe.ShadowRoot && (oe.ShadyCSS === void 0 || oe.ShadyCSS.nativeShadow) && "adoptedStyleSheets" in Document.prototype && "replace" in CSSStyleSheet.prototype, ge = Symbol(), Ae = /* @__PURE__ */ new WeakMap();
let He = class {
  constructor(t, i, a) {
    if (this._$cssResult$ = !0, a !== ge) throw Error("CSSResult is not constructable. Use `unsafeCSS` or `css` instead.");
    this.cssText = t, this.t = i;
  }
  get styleSheet() {
    let t = this.o;
    const i = this.t;
    if (ue && t === void 0) {
      const a = i !== void 0 && i.length === 1;
      a && (t = Ae.get(i)), t === void 0 && ((this.o = t = new CSSStyleSheet()).replaceSync(this.cssText), a && Ae.set(i, t));
    }
    return t;
  }
  toString() {
    return this.cssText;
  }
};
const Ze = (e) => new He(typeof e == "string" ? e : e + "", void 0, ge), K = (e, ...t) => {
  const i = e.length === 1 ? e[0] : t.reduce((a, o, s) => a + ((r) => {
    if (r._$cssResult$ === !0) return r.cssText;
    if (typeof r == "number") return r;
    throw Error("Value passed to 'css' function must be a 'css' function result: " + r + ". Use 'unsafeCSS' to pass non-literal values, but take care to ensure page security.");
  })(o) + e[s + 1], e[0]);
  return new He(i, e, ge);
}, Ke = (e, t) => {
  if (ue) e.adoptedStyleSheets = t.map((i) => i instanceof CSSStyleSheet ? i : i.styleSheet);
  else for (const i of t) {
    const a = document.createElement("style"), o = oe.litNonce;
    o !== void 0 && a.setAttribute("nonce", o), a.textContent = i.cssText, e.appendChild(a);
  }
}, Ee = ue ? (e) => e : (e) => e instanceof CSSStyleSheet ? ((t) => {
  let i = "";
  for (const a of t.cssRules) i += a.cssText;
  return Ze(i);
})(e) : e;
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const { is: Qe, defineProperty: et, getOwnPropertyDescriptor: tt, getOwnPropertyNames: it, getOwnPropertySymbols: at, getPrototypeOf: ot } = Object, ne = globalThis, Te = ne.trustedTypes, st = Te ? Te.emptyScript : "", rt = ne.reactiveElementPolyfillSupport, J = (e, t) => e, se = { toAttribute(e, t) {
  switch (t) {
    case Boolean:
      e = e ? st : null;
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
} }, me = (e, t) => !Qe(e, t), Me = { attribute: !0, type: String, converter: se, reflect: !1, useDefault: !1, hasChanged: me };
Symbol.metadata ??= Symbol("metadata"), ne.litPropertyMetadata ??= /* @__PURE__ */ new WeakMap();
let L = class extends HTMLElement {
  static addInitializer(t) {
    this._$Ei(), (this.l ??= []).push(t);
  }
  static get observedAttributes() {
    return this.finalize(), this._$Eh && [...this._$Eh.keys()];
  }
  static createProperty(t, i = Me) {
    if (i.state && (i.attribute = !1), this._$Ei(), this.prototype.hasOwnProperty(t) && ((i = Object.create(i)).wrapped = !0), this.elementProperties.set(t, i), !i.noAccessor) {
      const a = Symbol(), o = this.getPropertyDescriptor(t, a, i);
      o !== void 0 && et(this.prototype, t, o);
    }
  }
  static getPropertyDescriptor(t, i, a) {
    const { get: o, set: s } = tt(this.prototype, t) ?? { get() {
      return this[i];
    }, set(r) {
      this[i] = r;
    } };
    return { get: o, set(r) {
      const h = o?.call(this);
      s?.call(this, r), this.requestUpdate(t, h, a);
    }, configurable: !0, enumerable: !0 };
  }
  static getPropertyOptions(t) {
    return this.elementProperties.get(t) ?? Me;
  }
  static _$Ei() {
    if (this.hasOwnProperty(J("elementProperties"))) return;
    const t = ot(this);
    t.finalize(), t.l !== void 0 && (this.l = [...t.l]), this.elementProperties = new Map(t.elementProperties);
  }
  static finalize() {
    if (this.hasOwnProperty(J("finalized"))) return;
    if (this.finalized = !0, this._$Ei(), this.hasOwnProperty(J("properties"))) {
      const i = this.properties, a = [...it(i), ...at(i)];
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
      for (const o of a) i.unshift(Ee(o));
    } else t !== void 0 && i.push(Ee(t));
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
    return Ke(t, this.constructor.elementStyles), t;
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
      const s = (a.converter?.toAttribute !== void 0 ? a.converter : se).toAttribute(i, a.type);
      this._$Em = t, s == null ? this.removeAttribute(o) : this.setAttribute(o, s), this._$Em = null;
    }
  }
  _$AK(t, i) {
    const a = this.constructor, o = a._$Eh.get(t);
    if (o !== void 0 && this._$Em !== o) {
      const s = a.getPropertyOptions(o), r = typeof s.converter == "function" ? { fromAttribute: s.converter } : s.converter?.fromAttribute !== void 0 ? s.converter : se;
      this._$Em = o;
      const h = r.fromAttribute(i, s.type);
      this[o] = h ?? this._$Ej?.get(o) ?? h, this._$Em = null;
    }
  }
  requestUpdate(t, i, a, o = !1, s) {
    if (t !== void 0) {
      const r = this.constructor;
      if (o === !1 && (s = this[t]), a ??= r.getPropertyOptions(t), !((a.hasChanged ?? me)(s, i) || a.useDefault && a.reflect && s === this._$Ej?.get(t) && !this.hasAttribute(r._$Eu(t, a)))) return;
      this.C(t, i, a);
    }
    this.isUpdatePending === !1 && (this._$ES = this._$EP());
  }
  C(t, i, { useDefault: a, reflect: o, wrapped: s }, r) {
    a && !(this._$Ej ??= /* @__PURE__ */ new Map()).has(t) && (this._$Ej.set(t, r ?? i ?? this[t]), s !== !0 || r !== void 0) || (this._$AL.has(t) || (this.hasUpdated || a || (i = void 0), this._$AL.set(t, i)), o === !0 && this._$Em !== t && (this._$Eq ??= /* @__PURE__ */ new Set()).add(t));
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
        const { wrapped: r } = s, h = this[o];
        r !== !0 || this._$AL.has(o) || h === void 0 || this.C(o, void 0, s, h);
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
L.elementStyles = [], L.shadowRootOptions = { mode: "open" }, L[J("elementProperties")] = /* @__PURE__ */ new Map(), L[J("finalized")] = /* @__PURE__ */ new Map(), rt?.({ ReactiveElement: L }), (ne.reactiveElementVersions ??= []).push("2.1.2");
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const fe = globalThis, ze = (e) => e, re = fe.trustedTypes, Ie = re ? re.createPolicy("lit-html", { createHTML: (e) => e }) : void 0, Fe = "$lit$", z = `lit$${Math.random().toFixed(9).slice(2)}$`, Be = "?" + z, nt = `<${Be}>`, U = document, Y = () => U.createComment(""), q = (e) => e === null || typeof e != "object" && typeof e != "function", be = Array.isArray, lt = (e) => be(e) || typeof e?.[Symbol.iterator] == "function", he = `[ 	
\f\r]`, B = /<(?:(!--|\/[^a-zA-Z])|(\/?[a-zA-Z][^>\s]*)|(\/?$))/g, De = /-->/g, Ue = />/g, I = RegExp(`>|${he}(?:([^\\s"'>=/]+)(${he}*=${he}*(?:[^ 	
\f\r"'\`<>=]|("|')|))|$)`, "g"), Le = /'/g, Ne = /"/g, We = /^(?:script|style|textarea|title)$/i, dt = (e) => (t, ...i) => ({ _$litType$: e, strings: t, values: i }), n = dt(1), N = Symbol.for("lit-noChange"), d = Symbol.for("lit-nothing"), Re = /* @__PURE__ */ new WeakMap(), D = U.createTreeWalker(U, 129);
function Je(e, t) {
  if (!be(e) || !e.hasOwnProperty("raw")) throw Error("invalid template strings array");
  return Ie !== void 0 ? Ie.createHTML(t) : t;
}
const ct = (e, t) => {
  const i = e.length - 1, a = [];
  let o, s = t === 2 ? "<svg>" : t === 3 ? "<math>" : "", r = B;
  for (let h = 0; h < i; h++) {
    const c = e[h];
    let p, u, _ = -1, m = 0;
    for (; m < c.length && (r.lastIndex = m, u = r.exec(c), u !== null); ) m = r.lastIndex, r === B ? u[1] === "!--" ? r = De : u[1] !== void 0 ? r = Ue : u[2] !== void 0 ? (We.test(u[2]) && (o = RegExp("</" + u[2], "g")), r = I) : u[3] !== void 0 && (r = I) : r === I ? u[0] === ">" ? (r = o ?? B, _ = -1) : u[1] === void 0 ? _ = -2 : (_ = r.lastIndex - u[2].length, p = u[1], r = u[3] === void 0 ? I : u[3] === '"' ? Ne : Le) : r === Ne || r === Le ? r = I : r === De || r === Ue ? r = B : (r = I, o = void 0);
    const f = r === I && e[h + 1].startsWith("/>") ? " " : "";
    s += r === B ? c + nt : _ >= 0 ? (a.push(p), c.slice(0, _) + Fe + c.slice(_) + z + f) : c + z + (_ === -2 ? h : f);
  }
  return [Je(e, s + (e[i] || "<?>") + (t === 2 ? "</svg>" : t === 3 ? "</math>" : "")), a];
};
class V {
  constructor({ strings: t, _$litType$: i }, a) {
    let o;
    this.parts = [];
    let s = 0, r = 0;
    const h = t.length - 1, c = this.parts, [p, u] = ct(t, i);
    if (this.el = V.createElement(p, a), D.currentNode = this.el.content, i === 2 || i === 3) {
      const _ = this.el.content.firstChild;
      _.replaceWith(..._.childNodes);
    }
    for (; (o = D.nextNode()) !== null && c.length < h; ) {
      if (o.nodeType === 1) {
        if (o.hasAttributes()) for (const _ of o.getAttributeNames()) if (_.endsWith(Fe)) {
          const m = u[r++], f = o.getAttribute(_).split(z), b = /([.?@])?(.*)/.exec(m);
          c.push({ type: 1, index: s, name: b[2], strings: f, ctor: b[1] === "." ? pt : b[1] === "?" ? _t : b[1] === "@" ? ut : le }), o.removeAttribute(_);
        } else _.startsWith(z) && (c.push({ type: 6, index: s }), o.removeAttribute(_));
        if (We.test(o.tagName)) {
          const _ = o.textContent.split(z), m = _.length - 1;
          if (m > 0) {
            o.textContent = re ? re.emptyScript : "";
            for (let f = 0; f < m; f++) o.append(_[f], Y()), D.nextNode(), c.push({ type: 2, index: ++s });
            o.append(_[m], Y());
          }
        }
      } else if (o.nodeType === 8) if (o.data === Be) c.push({ type: 2, index: s });
      else {
        let _ = -1;
        for (; (_ = o.data.indexOf(z, _ + 1)) !== -1; ) c.push({ type: 7, index: s }), _ += z.length - 1;
      }
      s++;
    }
  }
  static createElement(t, i) {
    const a = U.createElement("template");
    return a.innerHTML = t, a;
  }
}
function R(e, t, i = e, a) {
  if (t === N) return t;
  let o = a !== void 0 ? i._$Co?.[a] : i._$Cl;
  const s = q(t) ? void 0 : t._$litDirective$;
  return o?.constructor !== s && (o?._$AO?.(!1), s === void 0 ? o = void 0 : (o = new s(e), o._$AT(e, i, a)), a !== void 0 ? (i._$Co ??= [])[a] = o : i._$Cl = o), o !== void 0 && (t = R(e, o._$AS(e, t.values), o, a)), t;
}
class ht {
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
    const { el: { content: i }, parts: a } = this._$AD, o = (t?.creationScope ?? U).importNode(i, !0);
    D.currentNode = o;
    let s = D.nextNode(), r = 0, h = 0, c = a[0];
    for (; c !== void 0; ) {
      if (r === c.index) {
        let p;
        c.type === 2 ? p = new Q(s, s.nextSibling, this, t) : c.type === 1 ? p = new c.ctor(s, c.name, c.strings, this, t) : c.type === 6 && (p = new gt(s, this, t)), this._$AV.push(p), c = a[++h];
      }
      r !== c?.index && (s = D.nextNode(), r++);
    }
    return D.currentNode = U, o;
  }
  p(t) {
    let i = 0;
    for (const a of this._$AV) a !== void 0 && (a.strings !== void 0 ? (a._$AI(t, a, i), i += a.strings.length - 2) : a._$AI(t[i])), i++;
  }
}
class Q {
  get _$AU() {
    return this._$AM?._$AU ?? this._$Cv;
  }
  constructor(t, i, a, o) {
    this.type = 2, this._$AH = d, this._$AN = void 0, this._$AA = t, this._$AB = i, this._$AM = a, this.options = o, this._$Cv = o?.isConnected ?? !0;
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
    t = R(this, t, i), q(t) ? t === d || t == null || t === "" ? (this._$AH !== d && this._$AR(), this._$AH = d) : t !== this._$AH && t !== N && this._(t) : t._$litType$ !== void 0 ? this.$(t) : t.nodeType !== void 0 ? this.T(t) : lt(t) ? this.k(t) : this._(t);
  }
  O(t) {
    return this._$AA.parentNode.insertBefore(t, this._$AB);
  }
  T(t) {
    this._$AH !== t && (this._$AR(), this._$AH = this.O(t));
  }
  _(t) {
    this._$AH !== d && q(this._$AH) ? this._$AA.nextSibling.data = t : this.T(U.createTextNode(t)), this._$AH = t;
  }
  $(t) {
    const { values: i, _$litType$: a } = t, o = typeof a == "number" ? this._$AC(t) : (a.el === void 0 && (a.el = V.createElement(Je(a.h, a.h[0]), this.options)), a);
    if (this._$AH?._$AD === o) this._$AH.p(i);
    else {
      const s = new ht(o, this), r = s.u(this.options);
      s.p(i), this.T(r), this._$AH = s;
    }
  }
  _$AC(t) {
    let i = Re.get(t.strings);
    return i === void 0 && Re.set(t.strings, i = new V(t)), i;
  }
  k(t) {
    be(this._$AH) || (this._$AH = [], this._$AR());
    const i = this._$AH;
    let a, o = 0;
    for (const s of t) o === i.length ? i.push(a = new Q(this.O(Y()), this.O(Y()), this, this.options)) : a = i[o], a._$AI(s), o++;
    o < i.length && (this._$AR(a && a._$AB.nextSibling, o), i.length = o);
  }
  _$AR(t = this._$AA.nextSibling, i) {
    for (this._$AP?.(!1, !0, i); t !== this._$AB; ) {
      const a = ze(t).nextSibling;
      ze(t).remove(), t = a;
    }
  }
  setConnected(t) {
    this._$AM === void 0 && (this._$Cv = t, this._$AP?.(t));
  }
}
class le {
  get tagName() {
    return this.element.tagName;
  }
  get _$AU() {
    return this._$AM._$AU;
  }
  constructor(t, i, a, o, s) {
    this.type = 1, this._$AH = d, this._$AN = void 0, this.element = t, this.name = i, this._$AM = o, this.options = s, a.length > 2 || a[0] !== "" || a[1] !== "" ? (this._$AH = Array(a.length - 1).fill(new String()), this.strings = a) : this._$AH = d;
  }
  _$AI(t, i = this, a, o) {
    const s = this.strings;
    let r = !1;
    if (s === void 0) t = R(this, t, i, 0), r = !q(t) || t !== this._$AH && t !== N, r && (this._$AH = t);
    else {
      const h = t;
      let c, p;
      for (t = s[0], c = 0; c < s.length - 1; c++) p = R(this, h[a + c], i, c), p === N && (p = this._$AH[c]), r ||= !q(p) || p !== this._$AH[c], p === d ? t = d : t !== d && (t += (p ?? "") + s[c + 1]), this._$AH[c] = p;
    }
    r && !o && this.j(t);
  }
  j(t) {
    t === d ? this.element.removeAttribute(this.name) : this.element.setAttribute(this.name, t ?? "");
  }
}
class pt extends le {
  constructor() {
    super(...arguments), this.type = 3;
  }
  j(t) {
    this.element[this.name] = t === d ? void 0 : t;
  }
}
class _t extends le {
  constructor() {
    super(...arguments), this.type = 4;
  }
  j(t) {
    this.element.toggleAttribute(this.name, !!t && t !== d);
  }
}
class ut extends le {
  constructor(t, i, a, o, s) {
    super(t, i, a, o, s), this.type = 5;
  }
  _$AI(t, i = this) {
    if ((t = R(this, t, i, 0) ?? d) === N) return;
    const a = this._$AH, o = t === d && a !== d || t.capture !== a.capture || t.once !== a.once || t.passive !== a.passive, s = t !== d && (a === d || o);
    o && this.element.removeEventListener(this.name, this, a), s && this.element.addEventListener(this.name, this, t), this._$AH = t;
  }
  handleEvent(t) {
    typeof this._$AH == "function" ? this._$AH.call(this.options?.host ?? this.element, t) : this._$AH.handleEvent(t);
  }
}
class gt {
  constructor(t, i, a) {
    this.element = t, this.type = 6, this._$AN = void 0, this._$AM = i, this.options = a;
  }
  get _$AU() {
    return this._$AM._$AU;
  }
  _$AI(t) {
    R(this, t);
  }
}
const mt = fe.litHtmlPolyfillSupport;
mt?.(V, Q), (fe.litHtmlVersions ??= []).push("3.3.2");
const Ge = (e, t, i) => {
  const a = i?.renderBefore ?? t;
  let o = a._$litPart$;
  if (o === void 0) {
    const s = i?.renderBefore ?? null;
    a._$litPart$ = o = new Q(t.insertBefore(Y(), s), s, void 0, i ?? {});
  }
  return o._$AI(e), o;
};
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const ve = globalThis;
class T extends L {
  constructor() {
    super(...arguments), this.renderOptions = { host: this }, this._$Do = void 0;
  }
  createRenderRoot() {
    const t = super.createRenderRoot();
    return this.renderOptions.renderBefore ??= t.firstChild, t;
  }
  update(t) {
    const i = this.render();
    this.hasUpdated || (this.renderOptions.isConnected = this.isConnected), super.update(t), this._$Do = Ge(i, this.renderRoot, this.renderOptions);
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
T._$litElement$ = !0, T.finalized = !0, ve.litElementHydrateSupport?.({ LitElement: T });
const ft = ve.litElementPolyfillSupport;
ft?.({ LitElement: T });
(ve.litElementVersions ??= []).push("4.2.2");
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const O = (e) => (t, i) => {
  i !== void 0 ? i.addInitializer(() => {
    customElements.define(e, t);
  }) : customElements.define(e, t);
};
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const bt = { attribute: !0, type: String, converter: se, reflect: !1, hasChanged: me }, vt = (e = bt, t, i) => {
  const { kind: a, metadata: o } = i;
  let s = globalThis.litPropertyMetadata.get(o);
  if (s === void 0 && globalThis.litPropertyMetadata.set(o, s = /* @__PURE__ */ new Map()), a === "setter" && ((e = Object.create(e)).wrapped = !0), s.set(i.name, e), a === "accessor") {
    const { name: r } = i;
    return { set(h) {
      const c = t.get.call(this);
      t.set.call(this, h), this.requestUpdate(r, c, e, !0, h);
    }, init(h) {
      return h !== void 0 && this.C(r, void 0, e, h), h;
    } };
  }
  if (a === "setter") {
    const { name: r } = i;
    return function(h) {
      const c = this[r];
      t.call(this, h), this.requestUpdate(r, c, e, !0, h);
    };
  }
  throw Error("Unsupported decorator location: " + a);
};
function j(e) {
  return (t, i) => typeof i == "object" ? vt(e, t, i) : ((a, o, s) => {
    const r = o.hasOwnProperty(s);
    return o.constructor.createProperty(s, a), r ? Object.getOwnPropertyDescriptor(o, s) : void 0;
  })(e, t, i);
}
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
function g(e) {
  return j({ ...e, state: !0, attribute: !1 });
}
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const yt = (e, t, i) => (i.configurable = !0, i.enumerable = !0, Reflect.decorate && typeof t != "object" && Object.defineProperty(e, t, i), i);
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
function wt(e, t) {
  return (i, a, o) => {
    const s = (r) => r.renderRoot?.querySelector(e) ?? null;
    return yt(i, a, { get() {
      return s(this);
    } });
  };
}
function pe(e, t) {
  if (!t || !e.date_added)
    return !1;
  const i = new Date(e.date_added);
  return ((/* @__PURE__ */ new Date()).getTime() - i.getTime()) / (1e3 * 60 * 60 * 24) <= t;
}
function ie(e, t = "en") {
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
function _e(e) {
  if (e < 60)
    return `${e}m`;
  const t = Math.floor(e / 60), i = e % 60;
  return i > 0 ? `${t}h ${i}m` : `${t}h`;
}
function G(e, t) {
  if (!e || e.includes("width=")) return e;
  const i = e.includes("?") ? "&" : "?";
  return `${e}${i}width=${t}`;
}
const Ye = K`
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
`, ae = {
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
    "editor.action_cast": "Cast to Chromecast",
    "editor.action_more_info": "More Information",
    "editor.action_trailer": "Watch Trailer",
    "editor.action_none": "No Action",
    "editor.action_call_service": "Run Script",
    "editor.service_to_call": "Script",
    "editor.service_data": 'Service Data (Optional JSON, e.g. {"player":"tv"})',
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
    "editor.action_cast": "An Chromecast senden",
    "editor.action_more_info": "Mehr Informationen",
    "editor.action_trailer": "Trailer ansehen",
    "editor.action_none": "Keine Aktion",
    "editor.action_call_service": "Skript ausführen",
    "editor.service_to_call": "Skript",
    "editor.service_data": 'Servicedaten (Optional JSON, z.B. {"player":"tv"})',
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
    "editor.action_cast": "Caster sur Chromecast",
    "editor.action_more_info": "Plus d'informations",
    "editor.action_trailer": "Voir la bande-annonce",
    "editor.action_none": "Aucune action",
    "editor.action_call_service": "Exécuter un script",
    "editor.service_to_call": "Script",
    "editor.service_data": 'Données du service (JSON optionnel, ex: {"player":"tv"})',
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
    "editor.action_cast": "Cast a Chromecast",
    "editor.action_more_info": "Más información",
    "editor.action_trailer": "Ver tráiler",
    "editor.action_none": "Ninguna acción",
    "editor.action_call_service": "Ejecutar script",
    "editor.service_to_call": "Script",
    "editor.service_data": 'Datos del servicio (JSON opcional, ej. {"player":"tv"})',
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
    "editor.action_cast": "Cast su Chromecast",
    "editor.action_more_info": "Più informazioni",
    "editor.action_trailer": "Guarda il trailer",
    "editor.action_none": "Nessuna azione",
    "editor.action_call_service": "Esegui script",
    "editor.service_to_call": "Script",
    "editor.service_data": 'Dati del servizio (JSON opzionale, es. {"player":"tv"})',
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
    "editor.action_cast": "Casten naar Chromecast",
    "editor.action_more_info": "Meer informatie",
    "editor.action_trailer": "Bekijk trailer",
    "editor.action_none": "Geen actie",
    "editor.action_call_service": "Script uitvoeren",
    "editor.service_to_call": "Script",
    "editor.service_data": 'Servicegegevens (Optioneel JSON, bijv. {"player":"tv"})',
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
    "editor.action_cast": "Predvajaj na Chromecast",
    "editor.action_more_info": "Več informacij",
    "editor.action_trailer": "Poglej napovednik",
    "editor.action_none": "Brez akcije",
    "editor.action_call_service": "Zaženi skript",
    "editor.service_to_call": "Skript",
    "editor.service_data": 'Podatki servisa (Opcijski JSON, npr. {"player":"tv"})',
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
    "editor.action_cast": "Трансляция на Chromecast",
    "editor.action_more_info": "Больше информации",
    "editor.action_trailer": "Посмотреть трейлер",
    "editor.action_none": "Нет действия",
    "editor.action_call_service": "Запустить скрипт",
    "editor.service_to_call": "Скрипт",
    "editor.service_data": 'Данные сервиса (Опциональный JSON, напр. {"player":"tv"})',
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
    "search.placeholder_title": "Поиск по названию",
    "search.placeholder_genre": "Жанр",
    "search.all_genres": "Все жанры"
  }
};
function l(e, t, i) {
  if (!t) return i || "";
  const a = (e || "en").split("-")[0].toLowerCase();
  return ae[a]?.[t] ? ae[a][t] : ae.en?.[t] ? ae.en[t] : i !== void 0 ? i : "";
}
var xt = Object.defineProperty, $t = Object.getOwnPropertyDescriptor, x = (e, t, i, a) => {
  for (var o = a > 1 ? void 0 : a ? $t(t, i) : t, s = e.length - 1, r; s >= 0; s--)
    (r = e[s]) && (o = (a ? r(t, i, o) : r(o)) || o);
  return a && o && xt(t, i, o), o;
};
let y = class extends T {
  constructor() {
    super(...arguments), this._open = !1, this._confirmDelete = !1, this._viewMode = "default", this._episodes = [], this._selectedSeason = "all", this._touchStartY = 0, this._currentTranslateY = 0, this._isDragging = !1, this._swipeClosingThreshold = 100, this._portalContainer = null, this._handleKeyDown = (e) => {
      e.key === "Escape" && this._open && this.closeDialog();
    }, this.closeDialog = () => {
      this._open = !1, this._confirmDelete = !1, document.body.style.overflow = "", this.dispatchEvent(new CustomEvent("closed", { bubbles: !0, composed: !0 })), this.requestUpdate();
    }, this._toggleEpisodesView = (e) => {
      e && (e.stopPropagation(), e.preventDefault()), this._viewMode === "default" ? this._fetchEpisodes() : this._viewMode = "default";
    }, this._handlePlayEpisode = async (e) => {
      if (this._haptic(), !this._defaultCastDevice) {
        this.dispatchEvent(new CustomEvent("hass-notification", {
          detail: { message: "No Chromecast device selected. Please configure a cast device in the card editor." },
          bubbles: !0,
          composed: !0
        }));
        return;
      }
      try {
        const t = {
          entity_id: this._defaultCastDevice,
          item_id: e.id,
          subtitle_mode: this._subtitleMode || "auto",
          ...this._subtitleLanguage ? { subtitle_language: this._subtitleLanguage } : {}
        };
        (e.config_entry_id || this._item?.config_entry_id) && (t.config_entry_id = e.config_entry_id || this._item?.config_entry_id), this._serverEntityId && (t.server_entity_id = this._serverEntityId), await this.hass.callService("jellyha", "play_on_chromecast", t), this.closeDialog();
      } catch (t) {
        console.error("Failed to cast episode", t), this.dispatchEvent(new CustomEvent("hass-notification", {
          detail: { message: "Failed to cast episode. Check logs." },
          bubbles: !0,
          composed: !0
        }));
      }
    }, this._handlePlay = async () => {
      this._haptic();
      const e = this._item?.type === "Series" && this._nextUpItem ? this._nextUpItem : this._item;
      if (!e || !this._defaultCastDevice) {
        this._defaultCastDevice || this.dispatchEvent(new CustomEvent("hass-notification", {
          detail: { message: "No Chromecast device selected. Please configure a cast device in the card editor." },
          bubbles: !0,
          composed: !0
        }));
        return;
      }
      try {
        const t = {
          entity_id: this._defaultCastDevice,
          item_id: e.id,
          subtitle_mode: this._subtitleMode || "auto",
          ...this._subtitleLanguage ? { subtitle_language: this._subtitleLanguage } : {}
        };
        (e.config_entry_id || this._item?.config_entry_id) && (t.config_entry_id = e.config_entry_id || this._item?.config_entry_id), this._serverEntityId && (t.server_entity_id = this._serverEntityId), await this.hass.callService("jellyha", "play_on_chromecast", t), this.closeDialog();
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
        const e = {
          entity_id: this._defaultCastDevice,
          item_id: this._nextUpItem.id,
          subtitle_mode: this._subtitleMode || "auto",
          ...this._subtitleLanguage ? { subtitle_language: this._subtitleLanguage } : {}
        };
        (this._nextUpItem.config_entry_id || this._item?.config_entry_id) && (e.config_entry_id = this._nextUpItem.config_entry_id || this._item?.config_entry_id), this._serverEntityId && (e.server_entity_id = this._serverEntityId), await this.hass.callService("jellyha", "play_on_chromecast", e), this.closeDialog();
      } catch (e) {
        console.error("Failed to cast next up", e);
      }
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
      const e = this._item.id;
      this.closeDialog();
      const t = {
        item_id: e
      };
      this._item.config_entry_id && (t.config_entry_id = this._item.config_entry_id), this._serverEntityId && (t.entity_id = this._serverEntityId, t.server_entity_id = this._serverEntityId), await this.hass.callService("jellyha", "delete_item", t);
    }, this._handleWatchTrailer = () => {
      this._haptic();
      const e = this._item;
      if (!e?.trailer_url) return;
      let t = e.trailer_url.trim();
      !t.startsWith("http://") && !t.startsWith("https://") && (t = "https://" + t);
      let i = "";
      try {
        const a = new URL(t);
        a.hostname.includes("youtube.com") ? a.searchParams.has("v") ? i = a.searchParams.get("v") || "" : a.pathname.startsWith("/embed/") ? i = a.pathname.split("/embed/")[1]?.split("/")[0] || "" : a.pathname.startsWith("/shorts/") && (i = a.pathname.split("/shorts/")[1]?.split("/")[0] || "") : a.hostname.includes("youtu.be") && (i = a.pathname.replace(/^\/+/, "").split("/")[0] || "");
      } catch {
      }
      if (i) {
        const a = navigator.userAgent || navigator.vendor || window.opera;
        if (/android/i.test(a)) {
          window.open(`vnd.youtube:${i}`, "_blank");
          return;
        }
        window.open(`https://www.youtube.com/watch?v=${i}`, "_blank");
        return;
      }
      window.open(t, "_blank");
    }, this._handleMarkEpisodeWatched = async (e) => {
      this._haptic();
      const t = !e.is_played;
      if (this._episodes = this._episodes.map(
        (a) => a.id === e.id ? { ...a, is_played: t, unplayed_count: t ? 0 : 1 } : a
      ), t && this._nextUpItem && e.id === this._nextUpItem.id) {
        const a = this._episodes.findIndex((o) => o.id === e.id);
        a !== -1 && a < this._episodes.length - 1 && (this._nextUpItem = this._episodes[a + 1]);
      } else if (!t && this._nextUpItem && e.id !== this._nextUpItem.id) {
        const a = this._episodes.findIndex((s) => s.id === e.id), o = this._episodes.findIndex((s) => s.id === this._nextUpItem.id);
        a !== -1 && o !== -1 && a < o && (this._nextUpItem = this._episodes[a]);
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
    this._item = e.item, this.hass = e.hass, this._defaultCastDevice = e.defaultCastDevice, this._serverEntityId = e.serverEntityId, this._subtitleMode = e.subtitleMode, this._subtitleLanguage = e.subtitleLanguage, this._open = !0, this._nextUpItem = void 0, this._viewMode = "default", this._episodes = [], this._selectedSeason = "all", document.body.style.overflow = "hidden", this._item.type === "Series" && this._fetchNextUp(this._item), this._fetchFullDetails(this._item.id), await this.updateComplete;
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
      (a) => (this.hass.states[a].attributes.integration === "jellyha" || a.startsWith("sensor.jellyha_")) && this.hass.states[a].attributes.entry_id
    ), i = this._serverEntityId || (t.length > 0 ? t[0] : "sensor.jellyha_library");
    try {
      const a = await this.hass.callWS({
        type: "jellyha/get_next_up",
        entity_id: i,
        server_entity_id: this._serverEntityId,
        ...this._item?.config_entry_id ? { config_entry_id: this._item.config_entry_id } : {},
        series_id: e.id
      });
      a && a.item && (this._nextUpItem = a.item);
    } catch (a) {
      console.warn("Failed to fetch Next Up:", a);
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
        const o = this._nextUpItem?.season || 1;
        i = await this.hass.callWS({
          type: "jellyha/get_episodes",
          entity_id: t,
          server_entity_id: this._serverEntityId,
          ...this._item?.config_entry_id ? { config_entry_id: this._item.config_entry_id } : {},
          series_id: this._item.id,
          season: o
        });
      }
      i && i.items ? this._episodes = i.items : this._episodes = [], this.requestUpdate();
    } catch (i) {
      console.warn("Failed to fetch episodes:", i), this._episodes = [], this.requestUpdate();
    }
  }
  updated() {
    if (this._portalContainer) {
      Ge(this._renderDialogContent(), this._portalContainer);
      const e = this._portalContainer.querySelector(".jellyha-modal-surface");
      e && (e.removeEventListener("touchstart", this._handleModalTouchStart), e.removeEventListener("touchmove", this._handleModalTouchMove), e.removeEventListener("touchend", this._handleModalTouchEnd), e.addEventListener("touchstart", this._handleModalTouchStart, { passive: !0 }), e.addEventListener("touchmove", this._handleModalTouchMove, { passive: !1 }), e.addEventListener("touchend", this._handleModalTouchEnd, { passive: !0 }));
    }
  }
  render() {
    return n``;
  }
  _getPortalStyles() {
    return n`
        <style>
            .jellyha-modal-scrim {
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                z-index: 99999;
                background: rgba(0, 0, 0, 0.72);
                backdrop-filter: blur(8px);
                -webkit-backdrop-filter: blur(8px);
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
                border-radius: 24px;
                box-shadow: 0 24px 72px rgba(0, 0, 0, 0.8), 0 0 0 1px rgba(255, 255, 255, 0.1);
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
                background: linear-gradient(135deg, #0288d1 0%, #00acc1 100%);
                color: #ffffff;
                border: none;
                border-radius: 24px;
                font-size: 0.95rem;
                font-weight: 600;
                cursor: pointer;
                box-shadow: 0 4px 16px rgba(2, 136, 209, 0.45);
                transition: all 0.2s ease;
            }
            .primary-play-btn:hover {
                filter: brightness(1.12);
                box-shadow: 0 6px 20px rgba(2, 136, 209, 0.6);
                transform: translateY(-1px);
            }
            .primary-play-btn:active {
                transform: scale(0.98);
            }
            .primary-play-btn ha-icon {
                --mdc-icon-size: 20px;
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
            }
            .next-up-play-overlay {
                position: absolute;
                inset: 0;
                background: rgba(0, 0, 0, 0.4);
                display: flex;
                align-items: center;
                justify-content: center;
                opacity: 0;
                transition: opacity 0.2s ease;
            }
            .next-up-card:hover .next-up-play-overlay {
                opacity: 1;
            }
            .next-up-play-overlay ha-icon {
                --mdc-icon-size: 32px;
                color: #ffffff;
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
                font-size: 0.8rem;
                font-weight: 600;
                color: #9ea4b5;
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
                transition: all 0.2s ease;
                padding: 0;
            }
            .next-up-cast-btn:hover {
                background: #03a9f4;
                color: #ffffff;
                box-shadow: 0 0 12px rgba(3, 169, 244, 0.5);
                transform: scale(1.05);
            }
            .next-up-cast-btn ha-icon {
                --mdc-icon-size: 20px;
            }

            /* Episodes View specific */
            .jellyha-modal-surface.episodes {
                overflow: hidden !important; 
                padding: 28px;
                max-height: min(90vh, 880px);
                box-sizing: border-box;
            }

            /* Episode List Styles */
            .episodes-header {
                 display: flex;
                 align-items: center;
                 gap: 14px;
                 margin-bottom: 18px;
                 padding-right: 52px;
            }
            .back-btn {
                background: rgba(255, 255, 255, 0.08);
                border: 1px solid rgba(255, 255, 255, 0.15);
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
            }
            .back-btn:hover {
                background: rgba(255, 255, 255, 0.2);
                border-color: rgba(255, 255, 255, 0.35);
                transform: scale(1.06);
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
            .episodes-list {
                display: flex;
                flex-direction: column;
                gap: 12px;
                overflow-y: auto;
                flex: 1;
                min-height: 0;
                padding-right: 4px;
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
            }
            .episode-row:hover {
                background: rgba(255, 255, 255, 0.09);
                border-color: rgba(255, 255, 255, 0.2);
            }
            .episode-row.next-up-highlight {
                background: rgba(3, 169, 244, 0.12);
                border-left: 4px solid #03a9f4;
            }
            .episode-thumb {
                width: 120px;
                aspect-ratio: 16/9;
                object-fit: cover;
                border-radius: 8px;
                flex-shrink: 0; 
                background: rgba(0, 0, 0, 0.4);
                border: 1px solid rgba(255, 255, 255, 0.12);
            }
            .episode-content {
                flex: 1;
                min-width: 0;
                display: flex;
                flex-direction: column;
                justify-content: center;
                gap: 4px;
            }
            .episode-title {
                margin: 0;
                font-size: 1rem;
                font-weight: 600;
                line-height: 1.3;
                color: #ffffff;
            }
            .episode-footer {
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            .episode-meta {
                font-size: 0.85rem;
                color: #9ea4b5;
                display: flex;
                align-items: center;
            }
            .episode-actions {
                display: flex;
                gap: 8px;
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
                background: rgba(255, 255, 255, 0.2);
                transform: scale(1.08);
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
        </style>
        `;
  }
  _renderDialogContent() {
    return !this._open || !this._item ? n`` : n`
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
      return e ? n`
                            <div class="backdrop-hero">
                                <img class="backdrop-img" src="${e}" alt="" />
                            </div>
                        ` : d;
    })()}
                    ${this._viewMode === "episodes" ? this._renderEpisodesContent() : this._renderDefaultContent()}
                </div>
            </div>
        `;
  }
  _renderDefaultContent() {
    if (!this._item) return n``;
    const e = this._item, t = e.type === "Series", i = e.year || (e.date_added ? new Date(e.date_added).getFullYear() : "");
    return n`
        <div class="default-layout">
            <div class="poster-col">
                <img class="poster-img" src="${e.poster_url}" alt="${e.name}" />

                <div class="poster-actions">
                    ${this._confirmDelete ? n`
                            <div class="confirmation-box">
                                <span>Delete item?</span>
                                <button class="confirm-btn confirm-yes" @click=${this._handleDeleteConfirm}>Yes</button>
                                <button class="confirm-btn" @click=${() => this._confirmDelete = !1}>No</button>
                            </div>
                        ` : n`
                            <!-- Primary Play / Cast Button -->
                            <button class="primary-play-btn" @click=${this._handlePlay} title="Play on Chromecast">
                                <ha-icon icon="mdi:cast"></ha-icon>
                                <span>Play on Cast</span>
                            </button>

                            <!-- Secondary Action Icons Toolbar -->
                            <div class="actions-icon-row">
                                ${t ? n`
                                    <button class="action-btn" @click=${(a) => {
      this._haptic(), this._toggleEpisodesView(a);
    }} title="View All Episodes" type="button">
                                        <ha-icon icon="mdi:format-list-bulleted"></ha-icon>
                                    </button>
                                ` : d}

                                ${e.trailer_url ? n`
                                    <button class="action-btn" @click=${this._handleWatchTrailer} title="Watch Trailer">
                                        <ha-icon icon="mdi:filmstrip"></ha-icon>
                                    </button>
                                ` : d}

                                <button class="action-btn ${e.is_played ? "active" : ""}" @click=${this._handleWatched} title="${e.is_played ? "Mark Unwatched" : "Mark Watched"}">
                                    <ha-icon icon="mdi:check"></ha-icon>
                                </button>

                                <button class="action-btn favorite-btn ${e.is_favorite ? "active" : ""}" @click=${this._handleFavorite} title="${e.is_favorite ? "Remove Favorite" : "Add to Favorites"}">
                                    <ha-icon icon="${e.is_favorite ? "mdi:heart" : "mdi:heart-outline"}"></ha-icon>
                                </button>

                                <a href="javascript:void(0)" class="action-btn" title="Open in Jellyfin" @click=${(a) => {
      a.preventDefault(), this._haptic(), this._openExternalUrl(e.jellyfin_url);
    }}>
                                    <ha-icon icon="mdi:open-in-new"></ha-icon>
                                </a>

                                <button class="action-btn btn-danger" @click=${() => {
      this._haptic(), this._confirmDelete = !0;
    }} title="Delete Item">
                                    <ha-icon icon="mdi:trash-can-outline"></ha-icon>
                                </button>
                            </div>
                        `}
                </div>
            </div>

            <div class="details-col">
                <div class="header-group">
                    <h1>${e.name}</h1>
                    <div class="header-sub">
                        ${e.series_name ? n`<span>${e.series_name}</span>` : d}
                        ${e.type === "Episode" && e.season != null && e.episode != null ? n`<span class="badge">S${String(e.season).padStart(2, "0")}E${String(e.episode).padStart(2, "0")}</span>` : d}
                        ${i ? n`<span>${i}</span>` : d}
                        <span class="badge">${e.type}</span>
                        ${e.official_rating ? n`<span class="badge">${e.official_rating}</span>` : d}
                    </div>
                </div>
                
                ${this._nextUpItem ? n`
                    <div class="next-up-card" @click=${this._playNextUp}>
                        <div class="next-up-thumb-wrap">
                            <img class="next-up-thumb" src="${this._nextUpItem.poster_url || this._nextUpItem.backdrop_url || this._item.poster_url}" alt="${this._nextUpItem.name}" />
                            <div class="next-up-play-overlay">
                                <ha-icon icon="mdi:play"></ha-icon>
                            </div>
                        </div>
                        <div class="next-up-info">
                            <div class="next-up-header-row">
                                <span class="next-up-badge">NEXT UP</span>
                                ${this._nextUpItem.season != null && this._nextUpItem.episode != null ? n`
                                    <span class="next-up-ep-code">S${this._nextUpItem.season}:E${this._nextUpItem.episode}</span>
                                ` : d}
                            </div>
                            <h3 class="next-up-title">${this._nextUpItem.name}</h3>
                            <div class="next-up-sub">
                                ${this._nextUpItem.runtime_minutes ? n`<span>${this._formatRuntime(this._nextUpItem.runtime_minutes)}</span>` : d}
                                ${this._nextUpItem.rating ? n`
                                    <span>•</span>
                                    <span class="next-up-rating"><ha-icon icon="mdi:star"></ha-icon> ${this._nextUpItem.rating.toFixed(1)}</span>
                                ` : d}
                            </div>
                        </div>
                        <button class="next-up-cast-btn" title="Cast Next Up" @click=${(a) => {
      a.stopPropagation(), this._playNextUp();
    }}>
                            <ha-icon icon="mdi:cast"></ha-icon>
                        </button>
                    </div>
                ` : d}

                <div class="stats-row">
                    ${e.rating ? n`
                        <div class="stat-item">
                            <ha-icon icon="mdi:star" style="color: #FBC02D;"></ha-icon>
                            <span>${e.rating.toFixed(1)}</span>
                        </div>
                    ` : d}
                    ${t ? n`
                        ${e.unplayed_count !== void 0 ? n`
                            <div class="stat-item">
                                <ha-icon icon="mdi:television-classic"></ha-icon>
                                <span>${e.unplayed_count} Unplayed</span>
                            </div>
                        ` : d}
                    ` : n`
                        ${e.runtime_minutes ? n`
                            <div class="stat-item">
                                <ha-icon icon="mdi:clock-outline"></ha-icon>
                                <span>${this._formatRuntime(e.runtime_minutes)}</span>
                            </div>
                        ` : d}
                    `}
                </div>

                ${e.description ? n`<div class="description">${e.description}</div>` : d}

                ${e.genres && e.genres.length > 0 ? n`
                    <div class="genres-list">
                        ${e.genres.map((a) => n`<span class="genre-tag">${a}</span>`)}
                    </div>
                ` : d}

                ${this._renderMediaDetails(t && this._nextUpItem ? this._nextUpItem : e)}
            </div>
        </div>
        `;
  }
  _renderEpisodesContent() {
    if (!this._item) return n``;
    const e = this._item.name, t = Array.from(
      new Set(
        this._episodes.map((a) => a.season).filter((a) => typeof a == "number" && !isNaN(a))
      )
    ).sort((a, o) => a - o), i = this._selectedSeason && this._selectedSeason !== "all" ? this._episodes.filter((a) => a.season === this._selectedSeason) : this._episodes;
    return n`
            <div style="display: flex; flex-direction: column; height: 100%; overflow: hidden; position: relative; z-index: 1;">
                <div class="episodes-header">
                    <button class="back-btn" @click=${(a) => this._toggleEpisodesView(a)} type="button" title="Back to Details">
                        <ha-icon icon="mdi:arrow-left"></ha-icon>
                    </button>
                    <h2 class="episodes-title">${e}</h2>
                </div>

                ${t.length > 1 ? n`
                    <div class="season-selector">
                        <button class="season-tab ${this._selectedSeason === "all" || !this._selectedSeason ? "active" : ""}" @click=${() => {
      this._selectedSeason = "all", this.requestUpdate();
    }}>All</button>
                        ${t.map((a) => n`
                            <button class="season-tab ${this._selectedSeason === a ? "active" : ""}" @click=${() => {
      this._selectedSeason = a, this.requestUpdate();
    }}>Season ${a}</button>
                        `)}
                    </div>
                ` : d}
                
                <div class="episodes-list">
                    ${i.length === 0 ? n`
                        <div style="text-align: center; color: rgba(255,255,255,0.6); padding: 40px 20px;">
                            No episodes found.
                        </div>
                    ` : i.map((a) => n`
                        <div class="episode-row ${this._nextUpItem && a.id === this._nextUpItem.id ? "next-up-highlight" : ""}" @click=${(o) => {
      o.stopPropagation(), this._handlePlayEpisode(a);
    }}>
                            <img class="episode-thumb" src="${a.poster_url || a.backdrop_url || this._item.poster_url}" alt="${a.name || ""}" />
                            
                            <div class="episode-content">
                                <h4 class="episode-title">
                                    ${a.season ? `S${a.season}:E${a.episode || a.index_number || ""}` : `${a.episode || a.index_number || ""}`}. ${a.name || "Episode"}
                                    ${this._nextUpItem && a.id === this._nextUpItem.id ? n`<span style="font-size: 0.7em; background: var(--primary-color, #03a9f4); color: white; padding: 2px 6px; border-radius: 4px; margin-left: 8px; vertical-align: middle; white-space: nowrap;">NEXT UP</span>` : d}
                                </h4>
                                
                                <div class="episode-footer">
                                    <div class="episode-meta">
                                        <span>${this._formatRuntime(a.runtime_minutes)}</span>
                                        ${a.rating ? n` <ha-icon icon="mdi:star" style="--mdc-icon-size: 14px; color: #FBC02D; margin-left: 6px; transform: translateY(-1px);"></ha-icon> ${a.rating.toFixed(1)}` : d}
                                    </div>

                                    <div class="episode-actions">
                                        <button class="play-episode-btn watched-btn ${a.is_played ? "active" : ""}" @click=${(o) => {
      o.stopPropagation(), this._handleMarkEpisodeWatched(a);
    }} type="button" title="${a.is_played ? "Mark Unwatched" : "Mark Watched"}">
                                            <ha-icon icon="mdi:check"></ha-icon>
                                        </button>

                                        <button class="play-episode-btn" @click=${(o) => {
      o.stopPropagation(), this._handlePlayEpisode(a);
    }} type="button" title="Play Episode">
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
  _formatRuntime(e) {
    if (!e) return "";
    const t = Math.floor(e / 60), i = e % 60;
    return t > 0 ? `${t}h ${i}m` : `${i} min`;
  }
  _renderMediaDetails(e) {
    const t = [], i = e.media_streams || [], a = i.find((s) => s.Type?.toLowerCase() === "video");
    if (a) {
      if (a.Width && a.Height) {
        let u = "";
        a.Width >= 3800 || a.Height >= 2e3 ? u = "4K UHD" : a.Height >= 1e3 || a.Width >= 1900 ? u = "1080p" : a.Height >= 700 || a.Width >= 1200 ? u = "720p" : u = `${a.Width}x${a.Height}`, t.push(n`<span class="tech-chip"><ha-icon icon="mdi:video-outline"></ha-icon>${u}</span>`);
      }
      const s = (a.VideoRangeType || "").toUpperCase(), r = (a.VideoRange || "").toUpperCase(), h = (a.ColorTransfer || "").toLowerCase(), c = a.DvProfile;
      let p = e.dynamic_range || "";
      p || (s.startsWith("DOVI") || c != null ? p = "Dolby Vision" : s === "HDR10PLUS" || s === "HDR10+" ? p = "HDR10+" : s === "HDR10" || h === "smpte2084" ? p = "HDR10" : s === "HLG" || h === "arib-std-b67" ? p = "HLG" : r === "HDR" && (p = "HDR")), p && p !== "SDR" && t.push(n`<span class="tech-chip tech-chip-hdr"><ha-icon icon="mdi:hdr"></ha-icon>${p}</span>`), a.Codec && t.push(n`<span class="tech-chip">${a.Codec.toUpperCase()}</span>`);
    }
    const o = i.find((s) => s.Type?.toLowerCase() === "audio" && !!s.IsDefault) || i.find((s) => s.Type?.toLowerCase() === "audio");
    if (o && (o.Codec && t.push(n`<span class="tech-chip"><ha-icon icon="mdi:volume-high"></ha-icon>${o.Codec.toUpperCase()}</span>`), o.Channels)) {
      let s = `${o.Channels} ch`;
      o.Channels === 6 ? s = "5.1" : o.Channels === 8 ? s = "7.1" : o.Channels === 2 && (s = "Stereo"), t.push(n`<span class="tech-chip">${s}</span>`);
    }
    return t.length === 0 ? n`` : n`
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
    this.dispatchEvent(t);
  }
  _openExternalUrl(e) {
    if (!e) return;
    try {
      const i = new URL(e);
      if (i.hostname.includes("youtube.com") || i.hostname.includes("youtu.be") || i.hostname.includes("vimeo.com")) {
        window.open(e, "_blank");
        return;
      }
    } catch {
    }
    let t;
    if (this.hass && this.hass.states) {
      for (const i in this.hass.states)
        if (i.startsWith("sensor.") && this.hass.states[i].attributes?.config_external_url) {
          t = this.hass.states[i].attributes.config_external_url;
          break;
        }
    }
    if (t && t.trim() !== "")
      try {
        const i = new URL(e), a = new URL(t);
        i.protocol = a.protocol, i.host = a.host, i.port = a.port || "";
        const o = a.pathname === "/" ? "" : a.pathname;
        o && !i.pathname.startsWith(o) && (i.pathname = o + i.pathname), window.open(i.toString(), "_blank");
        return;
      } catch (i) {
        console.warn("JellyHA: Failed to parse URLs to inject external URL override", i);
      }
    window.open(e, "_blank");
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
y.styles = K`
        /* Styles handled in _getPortalStyles */
    `;
x([
  j({ attribute: !1 })
], y.prototype, "hass", 2);
x([
  g()
], y.prototype, "_item", 2);
x([
  g()
], y.prototype, "_nextUpItem", 2);
x([
  g()
], y.prototype, "_defaultCastDevice", 2);
x([
  g()
], y.prototype, "_serverEntityId", 2);
x([
  g()
], y.prototype, "_subtitleMode", 2);
x([
  g()
], y.prototype, "_subtitleLanguage", 2);
x([
  g()
], y.prototype, "_open", 2);
x([
  g()
], y.prototype, "_confirmDelete", 2);
x([
  g()
], y.prototype, "_viewMode", 2);
x([
  g()
], y.prototype, "_episodes", 2);
x([
  g()
], y.prototype, "_selectedSeason", 2);
x([
  g()
], y.prototype, "_touchStartY", 2);
x([
  g()
], y.prototype, "_currentTranslateY", 2);
x([
  g()
], y.prototype, "_isDragging", 2);
y = x([
  O("jellyha-item-details-modal")
], y);
var kt = Object.defineProperty, St = Object.getOwnPropertyDescriptor, ye = (e, t, i, a) => {
  for (var o = a > 1 ? void 0 : a ? St(t, i) : t, s = e.length - 1, r; s >= 0; s--)
    (r = e[s]) && (o = (a ? r(t, i, o) : r(o)) || o);
  return a && o && kt(t, i, o), o;
};
function Ct(e, t, i) {
  const a = new CustomEvent(t, {
    bubbles: !0,
    composed: !0,
    detail: i
  });
  e.dispatchEvent(a);
}
let X = class extends T {
  constructor() {
    super(...arguments), this._filterCastDevices = (e) => {
      const t = e?.entity_id;
      if (!t || !t.startsWith("media_player."))
        return !1;
      if (t === this._config?.default_cast_device)
        return !0;
      const i = this.hass?.entities?.[t]?.platform;
      return i ? i === "cast" : !t.startsWith("media_player.jellyha_");
    };
  }
  setConfig(e) {
    this._config = e;
  }
  render() {
    if (!this.hass || !this._config)
      return n``;
    const e = this._config.click_action || "more-info", t = this._config.hold_action || "jellyfin", i = this._config.double_tap_action || "none", a = e === "cast" || t === "cast" || i === "cast", o = this.hass.locale?.language || this.hass.language;
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
          <ha-selector
            .hass=${this.hass}
            .selector=${{ text: {} }}
            .value=${this._config.title || ""}
            .label=${l(o, "editor.title")}
            label="${l(o, "editor.title")}"
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
          { value: "carousel", label: l(o, "editor.layout_carousel") },
          { value: "grid", label: l(o, "editor.layout_grid") },
          { value: "list", label: l(o, "editor.layout_list") }
        ]
      }
    }}
              .value=${this._config.layout || "carousel"}
              .label=${l(o, "editor.layout")}
              label="${l(o, "editor.layout")}"
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
          { value: "both", label: l(o, "editor.media_type_both") },
          { value: "movies", label: l(o, "editor.media_type_movies") },
          { value: "series", label: l(o, "editor.media_type_series") },
          { value: "next_up", label: l(o, "editor.media_type_next_up") }
        ]
      }
    }}
              .value=${this._config.media_type || "both"}
              .label=${l(o, "editor.media_type")}
              label="${l(o, "editor.media_type")}"
              @value-changed=${this._mediaTypeChanged}
            ></ha-selector>
          </div>
        </div>

        ${!this._config.layout || this._config.layout === "carousel" ? n`
          <div class="form-row">
            <ha-selector
              .hass=${this.hass}
              .selector=${{
      select: {
        mode: "dropdown",
        options: [
          { value: "center", label: l(o, "editor.alignment_center") || "Center" },
          { value: "left", label: l(o, "editor.alignment_left") || "Left" }
        ]
      }
    }}
              .value=${this._config.horizontal_alignment || "center"}
              .label=${l(o, "editor.horizontal_alignment") || "Carousel Alignment"}
              label="${l(o, "editor.horizontal_alignment") || "Carousel Alignment"}"
              @value-changed=${this._horizontalAlignmentChanged}
            ></ha-selector>
          </div>
        ` : ""}

        ${this._config.media_type === "series" || this._config.media_type === "both" || !this._config.media_type ? n`
          <div class="form-row">
            <ha-selector
              .hass=${this.hass}
              .selector=${{
      select: {
        mode: "dropdown",
        options: [
          { value: "series", label: l(o, "editor.tv_content_series") },
          { value: "episodes", label: l(o, "editor.tv_content_episodes") }
        ]
      }
    }}
              .value=${this._config.tv_content || "series"}
              .label=${l(o, "editor.tv_content")}
              label="${l(o, "editor.tv_content")}"
              @value-changed=${this._tvContentChanged}
            ></ha-selector>
          </div>
        ` : ""}

        ${this._config.layout === "grid" || this._config.layout === "list" ? n`
              <div class="form-row">
                <ha-selector
                  .hass=${this.hass}
                  .selector=${{
      number: {
        min: 1,
        max: this._config.layout === "list" ? 8 : 12,
        mode: "slider"
      }
    }}
                  .value=${this._config.columns || 1}
                  .label=${`${columnsLabel}: ${(this._config.columns || 1) === 1 ? l(o, "editor.auto") : this._config.columns}`}
                  label="${`${columnsLabel}: ${(this._config.columns || 1) === 1 ? l(o, "editor.auto") : this._config.columns}`}"
                  @value-changed=${this._columnsChanged}
                ></ha-selector>
              </div>
            ` : ""}

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
              .label=${l(o, "editor.items_per_page")}
              label="${l(o, "editor.items_per_page")}"
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
              .label=${l(o, "editor.max_pages")}
              label="${l(o, "editor.max_pages")}"
              @value-changed=${this._maxPagesChanged}
            ></ha-selector>
          </div>
        </div>

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
              .label=${l(o, "editor.auto_swipe")}
              label="${l(o, "editor.auto_swipe")}"
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
              .label=${l(o, "editor.new_badge_days")}
              label="${l(o, "editor.new_badge_days")}"
              @value-changed=${this._newBadgeDaysChanged}
            ></ha-selector>
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
          { value: "jellyfin", label: l(o, "editor.action_jellyfin") },
          { value: "cast", label: l(o, "editor.action_cast") },
          { value: "more-info", label: l(o, "editor.action_more_info") },
          { value: "trailer", label: l(o, "editor.action_trailer") },
          { value: "call-service", label: l(o, "editor.action_call_service") },
          { value: "none", label: l(o, "editor.action_none") }
        ]
      }
    }}
              .value=${e}
              .label=${l(o, "editor.click_action")}
              label="${l(o, "editor.click_action")}"
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
          { value: "jellyfin", label: l(o, "editor.action_jellyfin") },
          { value: "cast", label: l(o, "editor.action_cast") },
          { value: "more-info", label: l(o, "editor.action_more_info") },
          { value: "trailer", label: l(o, "editor.action_trailer") },
          { value: "call-service", label: l(o, "editor.action_call_service") },
          { value: "none", label: l(o, "editor.action_none") }
        ]
      }
    }}
              .value=${t}
              .label=${l(o, "editor.hold_action")}
              label="${l(o, "editor.hold_action")}"
              @value-changed=${this._holdActionChanged}
            ></ha-selector>
          </div>
        </div>

        <div class="side-by-side">
          <div class="form-row ${a ? "double-tap-aligned" : ""}">
            <ha-selector
              .hass=${this.hass}
              .selector=${{
      select: {
        mode: "dropdown",
        options: [
          { value: "jellyfin", label: l(o, "editor.action_jellyfin") },
          { value: "cast", label: l(o, "editor.action_cast") },
          { value: "more-info", label: l(o, "editor.action_more_info") },
          { value: "trailer", label: l(o, "editor.action_trailer") },
          { value: "call-service", label: l(o, "editor.action_call_service") },
          { value: "none", label: l(o, "editor.action_none") }
        ]
      }
    }}
              .value=${i}
              .label=${l(o, "editor.double_tap_action")}
              label="${l(o, "editor.double_tap_action")}"
              @value-changed=${this._doubleTapActionChanged}
            ></ha-selector>
          </div>

          ${a ? n`
                <div class="form-row">
                  <ha-entity-picker
                    .hass=${this.hass}
                    .value=${this._config.default_cast_device}
                    .includeDomains=${["media_player"]}
                    .entityFilter=${this._filterCastDevices}
                    .label=${l(o, "editor.default_cast_device") || "Default Cast Device"}
                    label="${l(o, "editor.default_cast_device") || "Default Cast Device"}"
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
          { value: "auto", label: l(o, "editor.subtitles_auto") || "Auto (Jellyfin User Profile)" },
          { value: "none", label: l(o, "editor.subtitles_none") || "None (Disabled)" },
          { value: "forced_only", label: l(o, "editor.subtitles_forced_only") || "Forced Only" },
          { value: "custom", label: l(o, "editor.subtitles_custom") || "Custom Language List" }
        ]
      }
    }}
                    .value=${this._config.subtitle_mode || "auto"}
                    .label=${l(o, "editor.subtitles") || "Cast Subtitles"}
                    label="${l(o, "editor.subtitles") || "Cast Subtitles"}"
                    @value-changed=${this._subtitleModeChanged}
                  ></ha-selector>
                </div>

                ${this._config.subtitle_mode === "custom" ? n`
                    <div class="form-row">
                      <ha-selector
                        .hass=${this.hass}
                        .selector=${{ text: {} }}
                        .value=${this._config.subtitle_language || ""}
                        .label=${l(o, "editor.subtitle_languages") || "Cast Subtitle Priority (e.g. sl, en)"}
                        label="${l(o, "editor.subtitle_languages") || "Cast Subtitle Priority (e.g. sl, en)"}"
                        @value-changed=${this._subtitleLanguageChanged}
                      ></ha-selector>
                    </div>
                  ` : ""}
              ` : n`<div></div>`}
        </div>

        ${e === "call-service" ? n`
            <div class="form-row">
              <ha-selector
                .hass=${this.hass}
                .selector=${{
      entity: {
        domain: "script"
      }
    }}
                .value=${this._config.click_service || this._config.service || ""}
                .label=${`${l(o, "editor.click_action")}: ${l(o, "editor.service_to_call")}`}
                label="${l(o, "editor.click_action")}: ${l(o, "editor.service_to_call")}"
                @value-changed=${this._clickServiceChanged}
              ></ha-selector>
            </div>
          ` : ""}

        ${t === "call-service" ? n`
            <div class="form-row">
              <ha-selector
                .hass=${this.hass}
                .selector=${{
      entity: {
        domain: "script"
      }
    }}
                .value=${this._config.hold_service || this._config.service || ""}
                .label=${`${l(o, "editor.hold_action")}: ${l(o, "editor.service_to_call")}`}
                label="${l(o, "editor.hold_action")}: ${l(o, "editor.service_to_call")}"
                @value-changed=${this._holdServiceChanged}
              ></ha-selector>
            </div>
          ` : ""}

        ${i === "call-service" ? n`
            <div class="form-row">
              <ha-selector
                .hass=${this.hass}
                .selector=${{
      entity: {
        domain: "script"
      }
    }}
                .value=${this._config.double_tap_service || this._config.service || ""}
                .label=${`${l(o, "editor.double_tap_action")}: ${l(o, "editor.service_to_call")}`}
                label="${l(o, "editor.double_tap_action")}: ${l(o, "editor.service_to_call")}"
                @value-changed=${this._doubleTapServiceChanged}
              ></ha-selector>
            </div>
          ` : ""}

        ${e === "cast" || t === "cast" || i === "cast" ? n`
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
        .checked=${this._config.show_runtime !== !1}
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
        .checked=${this._config.show_genres !== !1}
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
        <ha-selector
          .hass=${this.hass}
          .selector=${{
      select: {
        mode: "dropdown",
        options: [
          { value: "below", label: l(o, "editor.metadata_below") },
          { value: "above", label: l(o, "editor.metadata_above") }
        ]
      }
    }}
          .value=${this._config.metadata_position || "below"}
          .label=${l(o, "editor.metadata_position")}
          label="${l(o, "editor.metadata_position")}"
          @value-changed=${this._metadataPositionChanged}
        ></ha-selector>
      </div>

      <div class="form-row">
        ${this._config.media_type !== "next_up" ? n`
            <ha-selector
              .hass=${this.hass}
              .selector=${{
      select: {
        mode: "dropdown",
        options: [
          { value: "date_added_desc", label: l(o, "editor.sort_date_added_desc") },
          { value: "date_added_asc", label: l(o, "editor.sort_date_added_asc") },
          { value: "title_asc", label: l(o, "editor.sort_title_asc") },
          { value: "title_desc", label: l(o, "editor.sort_title_desc") },
          { value: "year_desc", label: l(o, "editor.sort_year_desc") },
          { value: "year_asc", label: l(o, "editor.sort_year_asc") },
          { value: "last_played_desc", label: l(o, "editor.sort_last_played_desc") },
          { value: "last_played_asc", label: l(o, "editor.sort_last_played_asc") }
        ]
      }
    }}
              .value=${this._config.sort_option || "date_added_desc"}
              .label=${l(o, "editor.sort_order")}
              label="${l(o, "editor.sort_order")}"
              @value-changed=${this._sortOptionChanged}
            ></ha-selector>
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
      <ha-selector
        .hass=${this.hass}
        .selector=${{
      select: {
        mode: "dropdown",
        options: [
          { value: "all", label: l(o, "editor.filter_all") },
          { value: "unwatched", label: l(o, "editor.filter_unwatched") },
          { value: "watched", label: l(o, "editor.filter_watched") }
        ]
      }
    }}
        .value=${this._config.status_filter || "all"}
        .label=${l(o, "editor.filter_watch_status")}
        label="${l(o, "editor.filter_watch_status")}"
        @value-changed=${this._statusFilterChanged}
      ></ha-selector>
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

    ${this._config.media_type === "next_up" || (this._config.media_type === "series" || this._config.media_type === "both" || !this._config.media_type) && this._config.tv_content === "episodes" ? n`
          <div class="checkbox-row">
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
    const t = e.detail?.value !== void 0 ? e.detail.value : e.target?.value;
    t !== void 0 && this._updateConfig("metadata_position", t);
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
  _updateConfig(e, t) {
    if (!this._config)
      return;
    const i = { ...this._config, [e]: t };
    this._config = i, Ct(this, "config-changed", { config: i });
  }
};
X.styles = K`
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
    .side-by-side > .form-row.double-tap-aligned {
      margin-top: 24px;
      align-self: end;
    }
  `;
ye([
  j({ attribute: !1 })
], X.prototype, "hass", 2);
ye([
  g()
], X.prototype, "_config", 2);
X = ye([
  O("jellyha-library-editor")
], X);
var Pt = Object.defineProperty, jt = Object.getOwnPropertyDescriptor, C = (e, t, i, a) => {
  for (var o = a > 1 ? void 0 : a ? jt(t, i) : t, s = e.length - 1, r; s >= 0; s--)
    (r = e[s]) && (o = (a ? r(t, i, o) : r(o)) || o);
  return a && o && Pt(t, i, o), o;
};
let k = class extends T {
  constructor() {
    super(...arguments), this.layout = "grid", this.isNextUpHighlight = !1, this._pressStartTime = 0, this._isHoldActive = !1, this._itemTouchStartX = 0, this._itemTouchStartY = 0, this._rewindActive = !1;
  }
  render() {
    return !this.item || !this.config || !this.hass ? n`` : this.layout === "list" ? this._renderListItem() : this._renderMediaItem();
  }
  _renderListItem() {
    const e = this.item, t = pe(e, this.config.new_badge_days || 0), i = this._getRating(e), a = this.config.show_media_type_badge !== !1, o = this._isItemPlaying(e);
    return n`
      <div
        class="media-item list-item ${o ? "playing" : ""} ${this.config.show_title ? "" : "no-title"} ${this.config.metadata_position === "above" ? "metadata-above" : ""}"
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
        @contextmenu="${this._handleContextMenu}"
      >
        <div class="list-poster-wrapper">
          ${this.config.metadata_position === "above" && this.config.show_date_added && e.date_added ? n`<p class="list-date-added">${ie(e.date_added, this.hass?.locale?.language || this.hass?.language)}</p>` : d}
          <div class="poster-container" id="poster-${e.id}">
            <div class="poster-inner">
              <img
                class="poster"
                src="${G(
      this.config.use_series_image && e.series_poster_url ? e.series_poster_url : e.poster_url,
      160
    )}"
                alt="${e.name}"
                width="80"
                height="120"
                loading="lazy"
                decoding="async"
                @load="${this._handleImageLoad}"
                @error="${this._handleImageError}"
              />
              <div class="poster-skeleton"></div>
              
              ${a && !o && !e.series_name ? n`<span class="list-type-badge ${e.series_name ? "series" : e.type === "Movie" ? "movie" : "series"}">
                    ${e.series_name && e.season !== void 0 && e.episode !== void 0 ? `S${String(e.season).padStart(2, "0")}E${String(e.episode).padStart(2, "0")}` : e.type === "Movie" ? "Movie" : "Series"}
                  </span>` : d}

              ${e.series_name && !o ? n`
            <div class="censor-bar list-bar ${this.isNextUpHighlight ? "highlight" : ""}">
              <span>${e.series_name}</span>
            </div>
              ` : d}
              
              ${o ? d : this._renderStatusBadge(e, t)}
              ${this._renderNowPlayingOverlay(e)}
            </div>
          </div>
          ${this.config.metadata_position !== "above" && this.config.show_date_added && e.date_added ? n`<p class="list-date-added">${ie(e.date_added, this.hass?.locale?.language || this.hass?.language)}</p>` : d}
        </div>
        
        <div class="list-info">
          ${this.config.show_title ? n`<h3 class="list-title">${e.name}</h3>` : d}
          
          <div class="list-metadata">
            ${a && !o ? n`<span class="list-type-badge ${e.series_name ? "series" : e.type === "Movie" ? "movie" : "series"}">
                  ${e.series_name && e.season !== void 0 && e.episode !== void 0 ? `S${String(e.season).padStart(2, "0")}E${String(e.episode).padStart(2, "0")}` : e.type === "Movie" ? "Movie" : "Series"}
                </span>` : d}
            ${this.config.show_year && e.year ? n`<span class="list-year">${e.year}</span>` : d}
            ${this.config.show_ratings && i ? n`<span class="list-rating">
                  <ha-icon icon="mdi:star"></ha-icon>
                  ${i.toFixed(1)}
                </span>` : d}
            ${this.config.show_runtime && e.runtime_minutes ? n`<span class="list-runtime">
                  <ha-icon icon="mdi:clock-outline"></ha-icon>
                  ${_e(e.runtime_minutes)}
                </span>` : d}
          </div>
          
          ${this.config.show_genres && e.genres && e.genres.length > 0 ? n`<p class="list-genres">${e.genres.slice(0, 3).join(", ")}</p>` : d}
          
          ${this.config.show_description_on_hover !== !1 && e.description ? n`<p class="list-description">${e.description}</p>` : d}
        </div>
      </div>
    `;
  }
  _renderMediaItem() {
    const e = this.item, t = pe(e, this.config.new_badge_days || 0), i = this._getRating(e), a = this.config.show_media_type_badge !== !1, o = this._isItemPlaying(e);
    return n`
      <div
        class="media-item ${o ? "playing" : ""}"
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
        @contextmenu="${this._handleContextMenu}"
      >
        ${this.config.metadata_position === "above" ? n`
              <div class="media-info-above">
                ${this.config.show_title ? n`<p class="media-title">${e.name}</p>` : d}
                ${this.config.show_year && e.year ? n`<p class="media-year">${e.year}</p>` : d}
                ${this.config.show_date_added && e.date_added ? n`<p class="media-date-added">${ie(e.date_added, this.hass?.locale?.language || this.hass?.language)}</p>` : d}
              </div>
            ` : d}
        <div class="poster-container" id="poster-${e.id}">
          <div class="poster-inner">
            <img
              class="poster"
              src="${G(
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
            
            ${a && !o ? n`
            <span class="media-type-badge ${e.series_name ? "series" : e.type === "Movie" ? "movie" : "series"}">
              ${e.series_name && e.season !== void 0 && e.episode !== void 0 ? `S${String(e.season).padStart(2, "0")}E${String(e.episode).padStart(2, "0")}` : e.type === "Movie" ? "Movie" : "Series"}
            </span>
          ` : d}

            ${e.series_name && !o ? n`
            <div class="censor-bar ${this.isNextUpHighlight ? "highlight" : ""}">
              <span>${e.series_name}</span>
            </div>
              ` : d}
            
            ${o ? d : this._renderStatusBadge(e, t)}
            
            ${this.config.show_ratings && i && !o ? n`
                  <span class="rating">
                    <ha-icon icon="mdi:star"></ha-icon>
                    ${i.toFixed(1)}
                  </span>
                ` : d}
            
            ${this.config.show_runtime && e.runtime_minutes && !o ? n`
                  <span class="runtime">
                    <ha-icon icon="mdi:clock-outline"></ha-icon>
                    ${_e(e.runtime_minutes)}
                  </span>
                ` : d}
            
            ${o ? d : n`
            <div class="hover-overlay">
              ${e.year ? n`<span class="overlay-year">${e.year}</span>` : d}
              <h3 class="overlay-title">${e.name}</h3>
              ${this.config.show_genres && e.genres && e.genres.length > 0 ? n`<span class="overlay-genres">${e.genres.slice(0, 3).join(", ")}</span>` : d}
              ${this.config.show_description_on_hover !== !1 && e.description ? n`<p class="overlay-description">${e.description}</p>` : d}
            </div>`}

            ${this._renderNowPlayingOverlay(e)}
          </div>
        </div>
        
        ${this.config.metadata_position === "below" ? n`
              <div class="media-info-below">
                ${this.config.show_title ? n`<p class="media-title">${e.name}</p>` : d}
                ${this.config.show_year && e.year ? n`<p class="media-year">${e.year}</p>` : d}
                ${this.config.show_date_added && e.date_added ? n`<p class="media-date-added">${ie(e.date_added, this.hass?.locale?.language || this.hass?.language)}</p>` : d}
              </div>
            ` : d}
      </div>
    `;
  }
  _renderStatusBadge(e, t) {
    const i = this.config.show_watched_status !== !1;
    return i && e.is_played ? n`
        <div class="status-badge watched">
          <ha-icon icon="mdi:check-bold"></ha-icon>
        </div>
      ` : i && e.type === "Series" && (e.unplayed_count || 0) > 0 ? n`
        <div class="status-badge unplayed">
          ${e.unplayed_count}
        </div>
      ` : t ? n`<span class="new-badge">${l(this.hass.locale?.language || this.hass.language, "new")}</span>` : n``;
  }
  _renderNowPlayingOverlay(e) {
    if (!this.config.show_now_playing || !this._isItemPlaying(e))
      return d;
    const t = this.hass.states[this.config.default_cast_device];
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
      this._isHoldActive = !0;
      const e = this.shadowRoot?.querySelector(`#poster-${this.item.id}`);
      e && (e.classList.add("hold-pulse"), setTimeout(() => {
        e.classList.remove("hold-pulse");
      }, 300)), this._dispatchHaptic("medium"), this._fireAction("hold");
    }, 500);
  }
  _clearHoldTimer() {
    this._holdTimer && (clearTimeout(this._holdTimer), this._holdTimer = void 0);
  }
  _handleMouseDown(e) {
    e.button === 0 && this._startHoldTimer();
  }
  _handleMouseUp(e) {
    this._isHoldActive ? (e.preventDefault(), e.stopPropagation()) : Date.now() - this._pressStartTime < 500 && this._handleTap(), this._clearHoldTimer();
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
      const a = e.changedTouches[0].clientX - this._itemTouchStartX, o = e.changedTouches[0].clientY - this._itemTouchStartY;
      i = Math.sqrt(a * a + o * o);
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
      let o = i;
      if (a) {
        const r = (/* @__PURE__ */ new Date()).getTime(), h = new Date(a).getTime(), c = (r - h) / 1e3;
        t.state === "playing" && (o += c);
      }
      const s = Math.max(0, o - 20);
      this.hass.callService("media_player", "media_seek", {
        entity_id: e,
        seek_position: s
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
};
k.styles = Ye;
C([
  j({ attribute: !1 })
], k.prototype, "hass", 2);
C([
  j({ attribute: !1 })
], k.prototype, "config", 2);
C([
  j({ attribute: !1 })
], k.prototype, "item", 2);
C([
  j({ type: String })
], k.prototype, "layout", 2);
C([
  j({ type: Boolean })
], k.prototype, "isNextUpHighlight", 2);
C([
  g()
], k.prototype, "_pressStartTime", 2);
C([
  g()
], k.prototype, "_holdTimer", 2);
C([
  g()
], k.prototype, "_isHoldActive", 2);
C([
  g()
], k.prototype, "_itemTouchStartX", 2);
C([
  g()
], k.prototype, "_itemTouchStartY", 2);
C([
  g()
], k.prototype, "_clickTimer", 2);
C([
  g()
], k.prototype, "_rewindActive", 2);
k = C([
  O("jellyha-media-item")
], k);
var At = Object.defineProperty, Et = Object.getOwnPropertyDescriptor, w = (e, t, i, a) => {
  for (var o = a > 1 ? void 0 : a ? Et(t, i) : t, s = e.length - 1, r; s >= 0; s--)
    (r = e[s]) && (o = (a ? r(t, i, o) : r(o)) || o);
  return a && o && At(t, i, o), o;
};
const Tt = "1.0.0";
console.info(
  `%c JELLYHA-LIBRARY-CARD %c v${Tt} `,
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
const Oe = {
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
  metadata_position: "below",
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
  show_now_playing: !0,
  use_series_image: !1,
  show_search: !1,
  filter_favorites: !1,
  status_filter: "all",
  filter_newly_added: !1,
  sort_option: "date_added_desc"
};
function W(e, t, i) {
  const a = new CustomEvent(t, {
    bubbles: !0,
    composed: !0,
    detail: i
  });
  e.dispatchEvent(a);
}
let v = class extends T {
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
          const { scrollLeft: o, scrollWidth: s, clientWidth: r } = a;
          Math.abs(this._scrollAccumulator - o) > 10 && (this._scrollAccumulator = o);
          const c = r / (this._config.auto_swipe_interval * 1e3) * i, p = s / 2;
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
    const t = this.shadowRoot?.querySelector(".carousel, .grid-wrapper, .list-wrapper");
    t && (e === "start" ? t.scrollLeft = 0 : t.scrollLeft = t.scrollWidth);
  }
  /**
   * Helper to animate page changes (Slide & Fade)
   **/
  async _animatePageChange(e, t) {
    const i = this.shadowRoot?.querySelector(".carousel, .grid-wrapper, .list-wrapper");
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
      const a = this.shadowRoot?.querySelector(".carousel, .grid-wrapper, .list-wrapper");
      if (a && Math.abs(t) > 0) {
        const { scrollLeft: o, scrollWidth: s, clientWidth: r } = a, h = s - r, c = o <= 5, p = o >= h - 5, u = this._config.show_pagination !== !1;
        let _ = !1;
        if (u) {
          const m = this._getTotalPages();
          c && t > 0 && this._currentPage === 0 && (_ = !0), p && t < 0 && this._currentPage >= m - 1 && (_ = !0);
        } else
          c && t > 0 && (_ = !0), p && t < 0 && (_ = !0);
        if (_) {
          this._isOverscrolling || (this._isOverscrolling = !0, this._elasticAnchorX = t), e.cancelable && e.preventDefault();
          const m = 0.3, f = t - this._elasticAnchorX;
          a.style.transition = "none", a.style.transform = `translateX(${f * m}px)`;
          return;
        }
      }
      Math.abs(t) > 30 && (this._isSwiping = !0);
    }
  }
  _handleTouchEnd(e) {
    if (this._isOverscrolling) {
      const o = this.shadowRoot?.querySelector(".carousel, .grid-wrapper, .list-wrapper");
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
    const t = e.changedTouches[0].clientX - this._touchStartX, i = 50, a = this.shadowRoot?.querySelector(".carousel, .grid-wrapper, .list-wrapper");
    if (t < -i)
      if (a) {
        const { scrollLeft: o, scrollWidth: s, clientWidth: r } = a;
        o + r >= s - 10 && this._nextPage();
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
      const a = this.shadowRoot?.querySelector(".carousel, .grid-wrapper, .list-wrapper");
      if (a && Math.abs(t) > 0) {
        const { scrollLeft: o, scrollWidth: s, clientWidth: r } = a, h = s - r, c = o <= 5, p = o >= h - 5, u = this._config.show_pagination !== !1;
        let _ = !1;
        if (u) {
          const m = this._getTotalPages();
          c && t > 0 && this._currentPage === 0 && (_ = !0), p && t < 0 && this._currentPage >= m - 1 && (_ = !0);
        } else
          c && t > 0 && (_ = !0), p && t < 0 && (_ = !0);
        if (_) {
          this._isOverscrolling || (this._isOverscrolling = !0, this._elasticAnchorX = t), e.cancelable && e.preventDefault();
          const m = 0.3, f = t - this._elasticAnchorX;
          a.style.transition = "none", a.style.transform = `translateX(${f * m}px)`;
          return;
        }
      }
      Math.abs(t) > 30 && (this._isSwiping = !0);
    }
  }
  _handlePointerUp(e) {
    if (e.target.releasePointerCapture?.(e.pointerId), this._isOverscrolling) {
      const o = this.shadowRoot?.querySelector(".carousel, .grid-wrapper, .list-wrapper");
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
    const t = e.clientX - this._touchStartX, i = 50, a = this.shadowRoot?.querySelector(".carousel, .grid-wrapper, .list-wrapper");
    if (t < -i)
      if (a) {
        const { scrollLeft: o, scrollWidth: s, clientWidth: r } = a;
        o + r >= s - 10 && this._nextPage();
      } else
        this._nextPage();
    else t > i && (a ? a.scrollLeft <= 10 && this._prevPage() : this._prevPage());
    this._touchStartX = 0, this._isSwiping = !1;
  }
  // Scroll handler for elastic dot indicator
  _handleScroll(e) {
    const t = e.target, i = t.scrollWidth, a = t.clientWidth, o = t.scrollLeft, s = i > a + 10;
    if (s !== this._hasScrollableContent && (this._hasScrollableContent = s), s) {
      let r = 0;
      const h = this._config.enable_pagination === !1 && (this._config.auto_swipe_interval || 0) > 0;
      if (h) {
        const c = i / 2;
        r = o / c;
      } else {
        const c = i - a;
        r = o / c;
      }
      !h && (i - a - o < 10 || r > 0.98) && (r = 1), (o < 10 || r < 0.02) && (r = 0), r = Math.min(1, Math.max(0, r)), this._scrollProgress = r;
    }
  }
  // Render scroll indicator for non-paginated scrollable content
  _renderScrollIndicator() {
    if (!this._hasScrollableContent || this._config.show_pagination_dots === !1) return n``;
    const e = this.SCROLL_INDICATOR_DOTS, t = this._scrollProgress, i = Math.round(t * (e - 1));
    return n`
      <div class="scroll-indicator">
        ${Array.from({ length: e }, (a, o) => {
      const s = o === i, r = o === 0 && t < 0.1 || o === e - 1 && t > 0.9;
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
      const t = this.getBoundingClientRect().width;
      if (t === 0) return;
      const i = Math.max(0, t - 32);
      if (i !== this._containerWidth) {
        this._containerWidth = i;
        const o = Math.max(2, Math.floor(i / 160));
        if (o !== this._itemsPerPage && (this._itemsPerPage = o, this.requestUpdate()), this._config) {
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
    this._config = { ...Oe, ...e }, this._effectiveListColumns = this._config.columns || 1;
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
      ...Oe
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
  shouldUpdate(e) {
    if (!this._config)
      return !1;
    if (e.has("_currentPage") || e.has("_itemsPerPage") || e.has("_items") || e.has("_error") || e.has("_searchQuery") || e.has("_searchGenre") || e.has("_scrollProgress") || e.has("_hasScrollableContent"))
      return !0;
    if (e.has("hass")) {
      const t = e.get("hass");
      if (t) {
        const i = t.states[this._config.entity], a = this.hass.states[this._config.entity], o = this._config.default_cast_device;
        if (o) {
          const s = t.states[o], r = this.hass.states[o];
          if (s !== r) return !0;
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
        const i = t.attributes.entry_id, a = t.attributes.last_updated;
        let o = !1;
        if (a !== this._lastUpdate || this._items.length === 0 && i)
          this._lastUpdate = a, o = !0;
        else if (e.has("_config")) {
          const s = e.get("_config");
          s && (s.media_type !== this._config?.media_type || s.tv_content !== this._config?.tv_content || s.entity !== this._config?.entity) && (o = !0);
        }
        o && this._fetchItems();
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
                ` : d}
            ${this._config.show_search ? this._renderSearchBar(t) : d}
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
      const s = this._searchQuery.toLowerCase();
      t = t.filter((r) => r.name.toLowerCase().includes(s));
    }
    this._searchGenre && (t = t.filter((s) => s.genres && s.genres.includes(this._searchGenre))), this._config.media_type === "movies" ? t = t.filter((s) => s.type === "Movie") : this._config.media_type === "series" ? this._config.tv_content === "episodes" ? t = t.filter((s) => s.type === "Episode") : t = t.filter((s) => s.type === "Series") : this._config.media_type === "both" || !this._config.media_type ? this._config.tv_content === "episodes" ? t = t.filter((s) => s.type === "Movie" || s.type === "Episode") : t = t.filter((s) => s.type !== "Episode") : this._config.media_type, this._config.filter_favorites && (t = t.filter((s) => s.is_favorite === !0));
    const i = this._config.status_filter || "all";
    if (i === "unwatched" ? t = t.filter((s) => !s.is_played) : i === "watched" && (t = t.filter((s) => s.is_played === !0)), this._config.filter_newly_added && (t = t.filter((s) => pe(s, this._config.new_badge_days || 0))), this._config.media_type === "next_up") {
      const s = this._config.max_pages;
      if (s != null && s > 0) {
        const r = (this._config.items_per_page || 5) * s;
        t = t.slice(0, r);
      }
      return t;
    }
    const a = this._config.sort_option || "date_added_desc";
    t.sort((s, r) => {
      switch (a) {
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
    const o = this._config.max_pages;
    if (o != null && o > 0) {
      const s = (this._config.items_per_page || 5) * o;
      t = t.slice(0, s);
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
    return t === "carousel" ? this._renderCarousel(e, i) : t === "list" ? this._renderList(e, i) : t === "grid" ? this._renderGrid(e, i) : n`
      <div class="${t}">
        ${e.map((a) => n`
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
    const i = this._config.items_per_page || this._itemsPerPage, a = this._config.max_pages, o = a ? Number(a) : 0, s = o > 0 ? o : 1 / 0, r = Math.min(Math.ceil(e.length / i), s), h = this._currentPage * i, c = !t && (this._config.auto_swipe_interval || 0) > 0, p = t ? e.slice(h, h + i) : c ? [...e, ...e] : e;
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
          @scroll="${t ? d : this._handleScroll}"
        >
          ${p.map((u) => n`
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
        ${t && r > 1 ? this._renderPagination(r) : d}
        ${t ? d : this._renderScrollIndicator()}
      </div>
    `;
  }
  /**
   * Render list with optional pagination
   */
  _renderList(e, t) {
    const i = this._config.items_per_page || this._itemsPerPage, a = this._config.max_pages, o = a ? Number(a) : 0, s = o > 0 ? o : 1 / 0, r = Math.min(Math.ceil(e.length / i), s), h = this._currentPage * i, c = !t && (this._config.auto_swipe_interval || 0) > 0, p = t ? e.slice(h, h + i) : c ? [...e, ...e] : e, u = this._effectiveListColumns, _ = u === 1;
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
          class="list ${t ? "paginated" : ""} ${_ ? "single-column" : ""}"
          style="--jf-list-columns: ${u}"
        >
          ${p.map((m) => n`
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
        ${t && r > 1 ? this._renderPagination(r) : d}
      </div>
    `;
  }
  /**
   * Render grid with optional pagination
   */
  _renderGrid(e, t) {
    const i = this._config.items_per_page || this._itemsPerPage, a = this._config.max_pages, o = a ? Number(a) : 0, s = o > 0 ? o : 1 / 0, r = Math.min(Math.ceil(e.length / i), s), h = this._currentPage * i, c = !t && (this._config.auto_swipe_interval || 0) > 0, p = t ? e.slice(h, h + i) : c ? [...e, ...e] : e, u = this._config.columns || 1, _ = u === 1, m = !t && (this._config.auto_swipe_interval || 0) > 0;
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
          @scroll="${t ? d : this._handleScroll}"
        >
          <div
            class="grid ${t ? "paginated" : ""} ${_ ? "auto-columns" : ""} ${m ? "horizontal" : ""}"
            style="--jf-columns: ${u}; --jf-grid-rows: ${u}"
          >
            ${p.map((f) => n`
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
        ${t && r > 1 ? this._renderPagination(r) : d}
        ${t ? d : this._renderScrollIndicator()}
      </div>
    `;
  }
  /**
   * Main Pagination Render Dispatcher
   * Decides between standard and smart pagination based on page count
   */
  _renderPagination(e) {
    return this._config.show_pagination_dots === !1 ? n`` : e <= 5 ? this._renderStandardPagination(e) : this._renderSmartPagination(e);
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
    const h = -(this._currentPage * 16) + 32;
    return n`
      <div class="pagination-container smart" style="width: ${72}px">
        <div 
          class="pagination-track" 
          style="transform: translateX(${h}px); width: ${e * 16}px"
        >
          ${Array.from({ length: e }, (c, p) => {
      const u = Math.abs(p - this._currentPage);
      let _ = "smart-dot";
      return p === this._currentPage ? _ += " active" : u > 2 ? _ += " hidden" : u === 2 && (_ += " small"), n`
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
        this._openExternalUrl(e.jellyfin_url);
        break;
      case "cast":
        this._castMedia(e, t);
        break;
      case "more-info":
        this._showItemDetails(e);
        break;
      case "trailer":
        e.trailer_url ? window.open(e.trailer_url, "_blank") : W(this, "hass-notification", {
          message: l(this.hass.locale?.language || this.hass.language, "no_trailer")
        });
        break;
      case "call-service":
        this._callCustomService(e, t);
        break;
    }
  }
  async _callCustomService(e, t) {
    let i = "", a = {};
    t === "click" ? (i = this._config.click_service || this._config.service || "", a = this._config.click_service_data || this._config.service_data || {}) : t === "hold" ? (i = this._config.hold_service || this._config.service || "", a = this._config.hold_service_data || this._config.service_data || {}) : t === "double_tap" && (i = this._config.double_tap_service || this._config.service || "", a = this._config.double_tap_service_data || this._config.service_data || {});
    const o = {
      ...a,
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
      config_entry_id: e.config_entry_id || e.entry_id || null,
      action_type: t
    };
    if (W(this, "jellyha_item_clicked", o), !i) {
      console.warn('JellyHA: "call-service" action selected but no action/service configured.'), W(this, "hass-notification", {
        message: 'No script configured for "Run Script" action. Please select a script in the card editor.'
      });
      return;
    }
    const s = i.trim().split("."), r = s[0], h = s.slice(1).join(".");
    if (!r || !h) {
      console.error(`JellyHA: Invalid service name "${i}". Expected format: domain.service (e.g. script.my_script)`), W(this, "hass-notification", {
        message: `Invalid script/service name: "${i}". Expected format: script.your_script_name`
      });
      return;
    }
    try {
      await this.hass.callService(r, h, o);
    } catch (c) {
      console.error(`JellyHA: Failed to call service ${i}`, c), W(this, "hass-notification", {
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
    let a = this._config.subtitle_mode || "auto", o = this._config.subtitle_language;
    t === "click" ? (this._config.click_subtitle_mode && (a = this._config.click_subtitle_mode), this._config.click_subtitle_language && (o = this._config.click_subtitle_language)) : t === "hold" ? (this._config.hold_subtitle_mode && (a = this._config.hold_subtitle_mode), this._config.hold_subtitle_language && (o = this._config.hold_subtitle_language)) : t === "double_tap" && (this._config.double_tap_subtitle_mode && (a = this._config.double_tap_subtitle_mode), this._config.double_tap_subtitle_language && (o = this._config.double_tap_subtitle_language));
    try {
      await this.hass.callService("jellyha", "play_on_chromecast", {
        entity_id: i,
        item_id: e.id,
        server_entity_id: this._config.entity,
        ...e.config_entry_id ? { config_entry_id: e.config_entry_id } : {},
        subtitle_mode: a,
        ...o ? { subtitle_language: o } : {}
      });
    } catch (s) {
      console.error("JellyHA: Failed to cast media", s);
    }
  }
  _openExternalUrl(e) {
    if (!e) return;
    try {
      const a = new URL(e);
      if (a.hostname.includes("youtube.com") || a.hostname.includes("youtu.be") || a.hostname.includes("vimeo.com")) {
        window.open(e, "_blank");
        return;
      }
    } catch {
    }
    const i = this.hass?.states[this._config?.entity]?.attributes?.config_external_url;
    if (i && i.trim() !== "")
      try {
        const a = new URL(e), o = new URL(i);
        a.protocol = o.protocol, a.host = o.host, a.port = o.port || "";
        const s = o.pathname === "/" ? "" : o.pathname;
        s && !a.pathname.startsWith(s) && (a.pathname = s + a.pathname), window.open(a.toString(), "_blank");
        return;
      } catch (a) {
        console.warn("JellyHA: Failed to parse URLs to inject external URL override, falling back to original", a);
      }
    window.open(e, "_blank");
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
    if (this._modal) {
      let t = this._config.subtitle_mode || "auto", i = this._config.subtitle_language;
      this._config.click_subtitle_mode && (t = this._config.click_subtitle_mode), this._config.click_subtitle_language && (i = this._config.click_subtitle_language), this._modal.showDialog({
        item: e,
        hass: this.hass,
        defaultCastDevice: this._config.default_cast_device,
        serverEntityId: this._config.entity,
        subtitleMode: t,
        subtitleLanguage: i
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
    (this._items || []).forEach((o) => {
      o.genres && o.genres.forEach((s) => t.add(s));
    });
    const i = Array.from(t).sort(), a = this.hass.locale?.language || this.hass.language;
    return n`
      <div class="search-container">
        <div class="search-input-wrapper">
          <ha-icon icon="mdi:magnify" class="search-icon"></ha-icon>
          <input 
            type="text" 
            class="search-input" 
            placeholder="${l(a, "search.placeholder_title")}"
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
             <option value="">${l(a, "search.all_genres")}</option>
             ${i.map((o) => n`
               <option value="${o}">${o}</option>
             `)}
          </select>
          <ha-icon icon="mdi:chevron-down" class="select-icon"></ha-icon>
        </div>
      </div>
    `;
  }
};
v.styles = Ye;
w([
  j({ attribute: !1 })
], v.prototype, "hass", 2);
w([
  g()
], v.prototype, "_config", 2);
w([
  g()
], v.prototype, "_currentPage", 2);
w([
  g()
], v.prototype, "_itemsPerPage", 2);
w([
  g()
], v.prototype, "_pressStartTime", 2);
w([
  g()
], v.prototype, "_holdTimer", 2);
w([
  g()
], v.prototype, "_isHoldActive", 2);
w([
  g()
], v.prototype, "_rewindActive", 2);
w([
  g()
], v.prototype, "_items", 2);
w([
  g()
], v.prototype, "_error", 2);
w([
  g()
], v.prototype, "_lastUpdate", 2);
w([
  g()
], v.prototype, "_mostRecentNextUpItemId", 2);
w([
  g()
], v.prototype, "_searchQuery", 2);
w([
  g()
], v.prototype, "_searchGenre", 2);
w([
  wt("jellyha-item-details-modal")
], v.prototype, "_modal", 2);
w([
  g()
], v.prototype, "_scrollProgress", 2);
w([
  g()
], v.prototype, "_hasScrollableContent", 2);
v = w([
  O("jellyha-library-card")
], v);
var Mt = Object.defineProperty, zt = Object.getOwnPropertyDescriptor, we = (e, t, i, a) => {
  for (var o = a > 1 ? void 0 : a ? zt(t, i) : t, s = e.length - 1, r; s >= 0; s--)
    (r = e[s]) && (o = (a ? r(t, i, o) : r(o)) || o);
  return a && o && Mt(t, i, o), o;
};
function It(e, t, i) {
  const a = new CustomEvent(t, {
    bubbles: !0,
    composed: !0,
    detail: i
  });
  e.dispatchEvent(a);
}
let Z = class extends T {
  setConfig(e) {
    this._config = e;
  }
  render() {
    if (!this.hass || !this._config)
      return n``;
    const e = Object.keys(this.hass.states).filter(
      (s) => s.startsWith("media_player.jellyha_") && !s.includes("_library_browser") && !s.endsWith("_browser")
    ), t = Object.keys(this.hass.states).filter(
      (s) => s.startsWith("sensor.jellyha_") && s.includes("now_playing")
    ), i = [
      ...e.map((s) => ({
        entity: s,
        label: `${this.hass.states[s]?.attributes.friendly_name || s} (Media Player)`
      })),
      ...t.map((s) => ({
        entity: s,
        label: `${this.hass.states[s]?.attributes.friendly_name || s} (Legacy Sensor)`
      }))
    ];
    this._config.entity && !i.some((s) => s.entity === this._config.entity) && i.unshift({
      entity: this._config.entity,
      label: String(this.hass.states[this._config.entity]?.attributes?.friendly_name || this._config.entity)
    });
    const a = this.hass.locale?.language || this.hass.language, o = l(a, "editor.media_player") || "Media Player";
    return n`
      <div class="card-config">
        <div class="form-row">
          <ha-selector
            .hass=${this.hass}
            .selector=${{
      select: {
        mode: "dropdown",
        custom_value: !0,
        options: i.map((s) => ({
          value: s.entity,
          label: s.label
        }))
      }
    }}
            .value=${this._config.entity || ""}
            .label=${o}
            label="${o}"
            @value-changed=${this._entityChanged}
          ></ha-selector>
        </div>

        <div class="form-row">
          <ha-selector
            .hass=${this.hass}
            .selector=${{ text: {} }}
            .value=${this._config.title || ""}
            .label="${l(a, "editor.title")} (Optional)"
            label="${l(a, "editor.title")} (Optional)"
            @value-changed=${this._titleChanged}
          ></ha-selector>
        </div>

        <div class="checkbox-pair">
          <div class="checkbox-row">
            <ha-switch
              .checked=${this._config.show_title !== !1}
              @change=${this._showTitleChanged}
            ></ha-switch>
            <span>${l(a, "editor.show_title")}</span>
          </div>
          <div class="checkbox-row">
            <ha-switch
              .checked=${this._config.show_subtitle !== !1}
              @change=${this._showSubtitleChanged}
            ></ha-switch>
            <span>${l(a, "editor.show_subtitle")}</span>
          </div>
        </div>

        <div class="checkbox-row">
          <ha-switch
            .checked=${this._config.show_media_type_badge !== !1}
            @change=${this._showMediaTypeBadgeChanged}
          ></ha-switch>
          <span>${l(a, "editor.show_media_type_badge")}</span>
        </div>

        <div class="checkbox-pair">
          <div class="checkbox-row">
            <ha-switch
              .checked=${this._config.show_year !== !1}
              @change=${this._showYearChanged}
            ></ha-switch>
            <span>${l(a, "editor.show_year")}</span>
          </div>
          <div class="checkbox-row">
            <ha-switch
              .checked=${this._config.show_genres !== !1}
              @change=${this._showGenresChanged}
            ></ha-switch>
            <span>${l(a, "editor.show_genres")}</span>
          </div>
        </div>

        <div class="checkbox-row">
          <ha-switch
            .checked=${this._config.show_runtime !== !1}
            @change=${this._showRuntimeChanged}
          ></ha-switch>
          <span>${l(a, "editor.show_runtime")}</span>
        </div>

        <div class="checkbox-row">
          <ha-switch
            .checked=${this._config.show_ratings !== !1}
            @change=${this._showRatingsChanged}
          ></ha-switch>
          <span>${l(a, "editor.show_rating")}</span>
        </div>

        <div class="checkbox-pair">
          <div class="checkbox-row">
            <ha-switch
              .checked=${this._config.show_user !== !1}
              @change=${this._showUserChanged}
            ></ha-switch>
            <span>${l(a, "editor.show_user")}</span>
          </div>
          <div class="checkbox-row">
            <ha-switch
              .checked=${this._config.show_client !== !1}
              @change=${this._showClientChanged}
            ></ha-switch>
            <span>${l(a, "editor.show_client")}</span>
          </div>
        </div>

        <div class="checkbox-row">
          <ha-switch
            .checked=${this._config.show_time === !0}
            @change=${this._showTimeChanged}
          ></ha-switch>
          <span>${l(a, "editor.show_time")}</span>
        </div>

        <div class="checkbox-row">
          <ha-switch
            .checked=${this._config.show_background !== !1}
            @change=${this._showBackgroundChanged}
          ></ha-switch>
          <span>${l(a, "editor.show_background")}</span>
        </div>

        <div class="checkbox-row">
          <ha-switch
            .checked=${this._config.use_series_image === !0}
            @change=${this._useSeriesImageChanged}
          ></ha-switch>
          <span>${l(a, "editor.use_series_image")}</span>
        </div>

        <div class="checkbox-row">
          <ha-switch
            .checked=${this._config.show_controls !== !1}
            @change=${this._showControlsChanged}
          ></ha-switch>
          <span>${l(a, "editor.show_controls") || "Show Playback Controls"}</span>
        </div>
      </div>
    `;
  }
  _showControlsChanged(e) {
    const t = e.target;
    this._updateConfig("show_controls", t.checked);
  }
  _entityChanged(e) {
    const t = e.detail?.value !== void 0 ? e.detail.value : e.target?.value;
    t !== void 0 && this._updateConfig("entity", t);
  }
  _titleChanged(e) {
    const t = e.detail?.value !== void 0 ? e.detail.value : e.target?.value;
    this._updateConfig("title", t);
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
  _showUserChanged(e) {
    const t = e.target;
    this._updateConfig("show_user", t.checked);
  }
  _showClientChanged(e) {
    const t = e.target;
    this._updateConfig("show_client", t.checked);
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
  _updateConfig(e, t) {
    if (!this._config)
      return;
    const i = { ...this._config, [e]: t };
    this._config = i, It(this, "config-changed", { config: i });
  }
};
Z.styles = K`
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
we([
  j({ attribute: !1 })
], Z.prototype, "hass", 2);
we([
  g()
], Z.prototype, "_config", 2);
Z = we([
  O("jellyha-now-playing-editor")
], Z);
var Dt = Object.defineProperty, Ut = Object.getOwnPropertyDescriptor, A = (e, t, i, a) => {
  for (var o = a > 1 ? void 0 : a ? Ut(t, i) : t, s = e.length - 1, r; s >= 0; s--)
    (r = e[s]) && (o = (a ? r(t, i, o) : r(o)) || o);
  return a && o && Dt(t, i, o), o;
};
window.customCards = window.customCards || [];
window.customCards.push({
  type: "jellyha-now-playing-card",
  name: "JellyHA Now Playing",
  description: "Display currently playing media from Jellyfin",
  preview: !0
});
let S = class extends T {
  constructor() {
    super(...arguments), this._rewindActive = !1, this._overflowState = 0, this._dominantColor = "var(--primary-color)", this._longPressProgress = 0, this._stopPulse = !1, this._isDragging = !1, this._dragPercentage = 0, this._optimisticSeekPercent = null, this._longPressRaf = null, this._longPressConsumed = !1, this._optimisticFavorites = {}, this._resolvedImages = {}, this._fetchingImageKey = null, this._phrases = [];
  }
  setConfig(e) {
    this._config = {
      show_title: !0,
      show_subtitle: !0,
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
      show_controls: !0,
      ...e
    };
  }
  static getConfigElement() {
    return document.createElement("jellyha-now-playing-editor");
  }
  static getStubConfig(e) {
    const t = Object.keys(e.states);
    return {
      entity: t.find((a) => a.startsWith("media_player.jellyha_") && !a.includes("_library_browser") && !a.endsWith("_browser")) || t.find((a) => a.startsWith("sensor.jellyha_now_playing_")) || "",
      show_title: !0,
      show_subtitle: !0,
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
      show_controls: !0
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
    const e = this._config.entity;
    if (!e)
      return this._renderError("Please configure a JellyHA Now Playing entity");
    const t = this.hass.states[e];
    if (!t)
      return this._renderError(l(this.hass.locale?.language || this.hass.language, "entity_not_found") || "Entity not found");
    const i = t.attributes, a = e.startsWith("media_player.");
    if (!(a && (t.state === "playing" || t.state === "paused") || !!i.item_id))
      return this._renderEmpty();
    const s = this._getDurationSeconds(t), r = this._getCurrentPositionSeconds(t);
    let h = 0;
    this._optimisticSeekPercent !== null ? h = this._optimisticSeekPercent : s > 0 ? h = Math.min(100, Math.max(0, r / s * 100)) : typeof i.progress_percent == "number" && (h = i.progress_percent);
    const c = this._isDragging && s > 0 ? this._dragPercentage / 100 * s : this._optimisticSeekPercent !== null && s > 0 ? this._optimisticSeekPercent / 100 * s : r, { seriesImageUrl: p, episodeImageUrl: u } = this._resolveImages(t), _ = this._config.use_series_image && p ? p : u || i.image_url || t.attributes.entity_picture, m = _, f = i.item_id || t.attributes.media_content_id, b = `${f}_${this._config.use_series_image ? "series" : "item"}`;
    if (b !== this._cachedItemId) {
      this._cachedItemId = b;
      const te = i.backdrop_url || _;
      this._cachedBackdropUrl = te ? G(te, 640) : void 0;
    }
    b !== this._cachedColorItemId && m && (this._cachedColorItemId = b, this._extractDominantColor(G(m, 80)));
    const P = this._cachedBackdropUrl, $ = this._config.show_background !== !1 && P, H = a ? t.state === "paused" : i.is_paused, E = (i.media_type || t.attributes.media_content_type || "").toLowerCase(), F = E === "audio" || E === "music", xe = i.title || t.attributes.media_title || "", $e = this._config.show_subtitle !== !1 && (i.artist_name || t.attributes.media_artist || i.series_title || t.attributes.media_series_title) || "", qe = this._config.show_year !== !1 && i.year ? String(i.year) : "", Ve = this._config.show_genres !== !1 && i.genres?.length ? i.genres.slice(0, 2).join(", ") : "", ke = [qe, Ve].filter(Boolean).join(" • "), ee = this._config.show_user !== !1 && i.user_name || "", de = this._config.show_client !== !1 && i.client || "", Se = i.season !== void 0 ? i.season : t.attributes.media_season, Ce = i.episode !== void 0 ? i.episode : t.attributes.media_episode, Pe = (E === "episode" || E === "tvshow") && Se !== void 0 && Ce !== void 0 ? `S${String(Se).padStart(2, "0")}E${String(Ce).padStart(2, "0")}` : i.media_type || "", ce = f && this._optimisticFavorites[f] !== void 0 ? this._optimisticFavorites[f] : i.is_favorite || !1, je = 125.66, Xe = je * (1 - this._longPressProgress), M = this._supportsRemote(t);
    return n`
            <ha-card class="jellyha-now-playing ${$ ? "has-background" : ""} ${this._config.title ? "has-title" : ""}" style="--card-dominant-color: ${this._dominantColor};">
                ${$ ? n`
                    <div class="card-background" style="background-image: url('${P}')"></div>
                    <div class="card-overlay"></div>
                ` : d}
                
                <div class="card-content">
                    ${this._config.title ? n`
                        <div class="card-header">${this._config.title}</div>
                    ` : d}
                    
                    <div class="main-container">
                        ${m ? n`
                            <div class="poster-container ${M ? "" : "no-rewind"}" @click=${M ? this._handlePosterRewind : void 0}>
                                <img src="${G(m, 160)}" alt="${xe}" loading="eager" fetchpriority="high" />
                                
                                ${this._config.show_media_type_badge !== !1 && Pe ? n`
                                    <span class="poster-badge media-type-badge ${E}">${Pe}</span>
                                
                                ` : d}
                                ${this._config.show_ratings !== !1 && i.community_rating ? n`
                                    <span class="poster-badge rating-badge">
                                        <ha-icon icon="mdi:star"></ha-icon>
                                        ${i.community_rating.toFixed(1)}
                                    </span>
                                ` : d}
                                ${this._config.show_runtime !== !1 && (i.runtime_minutes || s > 0) ? n`
                                    <span class="poster-badge runtime-badge">
                                        <ha-icon icon="mdi:clock-outline"></ha-icon>
                                        ${E === "audio" && s > 0 ? `${Math.floor(s / 60)}m ${Math.floor(s % 60)}s` : _e(i.runtime_minutes || Math.round(s / 60))}
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
                                    ${this._config.show_title !== !1 ? n`<div class="title">${xe}</div>` : d}
                                    ${$e ? n`<div class="subtitle">${$e}</div>` : d}
                                    ${this._overflowState < 1 && ke ? n`<div class="meta-line">${ke}</div>` : d}
                                    ${this._overflowState < 1 && (ee || de) ? n`<div class="client-line">${ee ? n`<strong>${ee}</strong>` : d}${ee && de ? " " : ""}${de || d}</div>` : d}
                                </div>
                            </div>

                            <div class="info-bottom">
                                ${M && this._config.show_controls !== !1 ? n`
                                    <div class="playback-controls">
                                        ${F ? n`
                                            <ha-icon-button class="music-subtle-btn ${ce ? "active" : ""}" .label=${"Favorite"} @click=${() => this._handleFavoriteToggle(i.item_id, ce)}>
                                                <ha-icon icon="${ce ? "mdi:heart" : "mdi:heart-outline"}"></ha-icon>
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
                                            @contextmenu=${(te) => te.preventDefault()}
                                        >
                                            ${this._rewindActive ? n`
                                                <ha-icon-button class="play-pause-btn spinning" .label=${l(this.hass.locale?.language || this.hass.language, "loading")}>
                                                    <ha-icon icon="mdi:loading"></ha-icon>
                                                </ha-icon-button>
                                            ` : H ? n`
                                                <ha-icon-button class="play-pause-btn" .label=${l(this.hass.locale?.language || this.hass.language, "play")} @click=${() => {
      if (this._longPressConsumed) {
        this._longPressConsumed = !1;
        return;
      }
      this._handleControl(F ? "PlayPause" : "Unpause");
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
                                                        stroke-dasharray="${je}"
                                                        stroke-dashoffset="${Xe}"
                                                        stroke-linecap="round"
                                                        transform="rotate(-90 22 22)" />
                                                </svg>
                                            ` : d}
                                        </div>

                                        ${F ? n`
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
                                ` : d}

                                <div class="progress-container ${M ? "" : "readonly"}"
                                    @pointerdown=${M ? this._startDrag : void 0}
                                    @pointermove=${M ? this._handleDrag : void 0}
                                    @pointerup=${M ? this._endDrag : void 0}
                                    @pointercancel=${M ? this._cancelDrag : void 0}
                                >
                                    <div class="progress-bar">
                                        <div class="progress-fill" style="width: ${this._isDragging ? this._dragPercentage : h}%; transition: ${this._isDragging ? "none" : "width 1s linear"}; background: ${this._dominantColor}"></div>
                                        <div class="seek-handle" style="left: ${this._isDragging ? this._dragPercentage : h}%; transition: ${this._isDragging ? "none" : "left 1s linear"}; transform: translate(-50%, -50%) ${this._isDragging ? "scale(1.3)" : "scale(1)"}; background: ${this._dominantColor}"></div>
                                    </div>
                                </div>

                                ${this._config.show_time && s > 0 ? n`
                                    <div class="timestamps">
                                        <span class="time-elapsed">${this._formatSeconds(c)}</span>
                                        <span class="time-remaining">${this._formatSeconds(-(s - c))}</span>
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
        const e = await fetch("/jellyha_static/phrases.json");
        e.ok && (this._phrases = await e.json());
      } catch (e) {
        console.warn("JellyHA: Could not fetch phrases.json", e);
      }
  }
  _renderEmpty() {
    this._fetchPhrases();
    const t = this.hass.themes?.darkMode ? "https://raw.githubusercontent.com/home-assistant/brands/master/custom_integrations/jellyha/dark_logo.png" : "https://raw.githubusercontent.com/home-assistant/brands/master/custom_integrations/jellyha/logo.png", i = "https://raw.githubusercontent.com/home-assistant/brands/master/custom_integrations/jellyha/icon.png";
    let a = l(this.hass.locale?.language || this.hass.language, "nothing_playing");
    if (this._phrases.length > 0) {
      const s = Math.floor(Date.now() / 864e5) % this._phrases.length;
      a = this._phrases[s];
      const r = this._config?.entity || "";
      let h = "";
      if (r.startsWith("sensor."))
        h = r.replace(/_now_playing.*$/, "");
      else if (r.startsWith("media_player.")) {
        const _ = r.replace(/^media_player\./, "");
        h = `sensor.${_.includes("_") ? _.substring(0, _.lastIndexOf("_")) : _}`;
      }
      const c = h ? `${h}_unwatched` : "";
      let p = c && this.hass.states[c] ? c : "";
      p || (p = Object.keys(this.hass.states).find((_) => _.startsWith("sensor.") && _.endsWith("_unwatched")) || "");
      const u = p ? this.hass.states[p].state : "0";
      a = a.replace(/\[number\]/g, u);
    }
    return n`
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
    return n`
            <ha-card class="error-state">
                <div class="card-content">
                    <p>${e}</p>
                </div>
            </ha-card>
        `;
  }
  _resolveImages(e) {
    const t = e.attributes;
    let i = t.series_image_url, a = t.image_url;
    const o = (t.media_type || e.attributes.media_content_type || "").toLowerCase(), s = t.series_title || e.attributes.media_series_title, r = t.title || e.attributes.media_title, h = o === "episode" || o === "tvshow" || !!s || e.attributes.media_season !== void 0, c = e.attributes.media_content_id || "", p = e.attributes.entity_picture || "", u = t.item_id || c || s || e.entity_id;
    if (u && this._resolvedImages[u] && (i || (i = this._resolvedImages[u].seriesImageUrl), a || (a = this._resolvedImages[u].episodeImageUrl)), !h || i && a)
      return { seriesImageUrl: i, episodeImageUrl: a };
    const _ = c.match(/^(https?:\/\/[^\/]+)\/(?:Videos|Items)\/([a-zA-Z0-9_-]+)/i), m = p.match(/^(https?:\/\/[^\/]+)\/Items\/([a-zA-Z0-9_-]+)\/Images\/Primary/i), f = _ ? _[1] : m ? m[1] : "", b = _ ? _[2] : t.item_id || null, P = m ? m[2] : null, $ = c.match(/[?&](?:api_key|ApiKey)=([a-zA-Z0-9]+)/i) || p.match(/[?&](?:api_key|ApiKey)=([a-zA-Z0-9]+)/i), H = $ ? `&api_key=${$[1]}` : "";
    if (f && b) {
      const E = `${f}/Items/${b}/Images/Primary?maxHeight=300&quality=90${H}`;
      a || (P === b ? a = p : a = E), P && P !== b && !i && (i = p);
    } else m && !a && !i && (a = p);
    return u && (i || a) && (this._resolvedImages[u] = {
      ...this._resolvedImages[u],
      ...i ? { seriesImageUrl: i } : {},
      ...a ? { episodeImageUrl: a } : {}
    }), h && (!i || !a) && this._fetchingImageKey !== u && this._fetchMissingImages(s, r, u), { seriesImageUrl: i, episodeImageUrl: a };
  }
  async _fetchMissingImages(e, t, i) {
    if (i) {
      this._fetchingImageKey = i;
      try {
        if (t) {
          const o = (await this.hass.callWS({
            type: "jellyha/search_media",
            query: t,
            media_type: "Episode",
            limit: 1
          }))?.items;
          if (o && o.length > 0) {
            const s = o[0], r = s.poster_url || s.image_url, h = s.series_poster_url;
            if (r || h) {
              this._resolvedImages[i] = {
                ...this._resolvedImages[i],
                ...r ? { episodeImageUrl: r } : {},
                ...h ? { seriesImageUrl: h } : {}
              }, this.requestUpdate();
              return;
            }
          }
        }
        if (e && !this._resolvedImages[i]?.seriesImageUrl) {
          const o = (await this.hass.callWS({
            type: "jellyha/search_media",
            query: e,
            media_type: "Series",
            limit: 1
          }))?.items;
          if (o && o.length > 0) {
            const s = o[0].poster_url || o[0].series_poster_url || o[0].image_url;
            s && (this._resolvedImages[i] = {
              ...this._resolvedImages[i],
              seriesImageUrl: s
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
    return !(t.supports_remote_control === !1 || e.entity_id.startsWith("media_player.") && t.supported_features !== void 0 && t.supported_features === 0);
  }
  async _handleControl(e) {
    this._haptic("light");
    const t = this._config.entity, i = this.hass.states[t];
    if (!i || !this._supportsRemote(i)) return;
    if (t.startsWith("media_player.")) {
      let s = "";
      if (e === "Pause" ? s = "media_pause" : e === "Unpause" || e === "Play" ? s = "media_play" : e === "PlayPause" ? s = "media_play_pause" : e === "Stop" ? s = "media_stop" : e === "NextTrack" ? s = "media_next_track" : e === "PreviousTrack" && (s = "media_previous_track"), s) {
        await this.hass.callService("media_player", s, {
          entity_id: t
        });
        return;
      }
    }
    const o = i?.attributes.session_id;
    o && await this.hass.callService("jellyha", "session_control", {
      entity_id: t,
      session_id: o,
      command: e
    });
  }
  async _handleRepeatMode(e, t) {
    let i = "RepeatAll", a = "all";
    t === "RepeatAll" || t === "all" ? (i = "RepeatOne", a = "one") : (t === "RepeatOne" || t === "one") && (i = "RepeatNone", a = "off");
    const o = this._config.entity;
    if (o.startsWith("media_player.")) {
      await this.hass.callService("media_player", "repeat_set", {
        entity_id: o,
        repeat: a
      });
      return;
    }
    await this.hass.callService("jellyha", "session_general_command", {
      entity_id: o,
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
  _getDragPercent(e) {
    const i = e.currentTarget.getBoundingClientRect();
    let a = e.clientX - i.left;
    return a < 10 && (a = 0), a > i.width - 10 && (a = i.width), Math.max(0, Math.min(100, a / i.width * 100));
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
    let a = 0, o;
    const s = e.attributes.media_position;
    if (typeof s == "number" ? (a = s, o = e.attributes.media_position_updated_at || e.last_updated) : typeof t.position_ticks == "number" ? (a = t.position_ticks / 1e7, o = e.last_updated) : typeof t.progress_percent == "number" && i > 0 && (a = t.progress_percent / 100 * i, o = e.last_updated), (e.entity_id.startsWith("media_player.") ? e.state === "playing" : !t.is_paused && !!t.item_id) && o) {
      const c = new Date(o).getTime();
      if (!isNaN(c)) {
        const p = Math.max(0, (Date.now() - c) / 1e3), u = a + p;
        return i > 0 ? Math.min(i, Math.max(0, u)) : Math.max(0, u);
      }
    }
    return i > 0 ? Math.min(i, Math.max(0, a)) : Math.max(0, a);
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
    const a = this._config.entity, o = this.hass.states[a];
    if (!o) return;
    const s = this._getDurationSeconds(o);
    if (s <= 0) return;
    const h = o.attributes.session_id;
    if (a.startsWith("media_player.")) {
      const p = Math.round(s * (i / 100));
      await this.hass.callService("media_player", "media_seek", {
        entity_id: a,
        seek_position: p
      });
      return;
    }
    if (!h) return;
    const c = Math.round(s * 1e7 * (i / 100));
    await this.hass.callService("jellyha", "session_seek", {
      entity_id: a,
      session_id: h,
      position_ticks: c
    });
  }
  _setOptimisticSeek(e) {
    this._optimisticSeekTimer && clearTimeout(this._optimisticSeekTimer), this._optimisticSeekPercent = e, this.requestUpdate(), this._optimisticSeekTimer = window.setTimeout(() => {
      this._optimisticSeekPercent = null, this.requestUpdate();
    }, 2500);
  }
  async _handleSeekRelative(e) {
    this._haptic("light");
    const t = this._config.entity, i = this.hass.states[t];
    if (!i || !this._supportsRemote(i)) return;
    const a = this._getDurationSeconds(i), o = this._getCurrentPositionSeconds(i), s = Math.max(
      0,
      a > 0 ? Math.min(a, o + e) : o + e
    );
    if (a > 0 && this._setOptimisticSeek(s / a * 100), t.startsWith("media_player.")) {
      await this.hass.callService("media_player", "media_seek", {
        entity_id: t,
        seek_position: Math.round(s)
      });
      return;
    }
    const h = i.attributes.session_id;
    h && await this.hass.callService("jellyha", "session_seek", {
      entity_id: t,
      session_id: h,
      position_ticks: Math.round(s * 1e7)
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
      const a = Date.now() - e;
      if (this._longPressProgress = Math.min(a / t, 1), this._longPressProgress >= 1) {
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
    const t = new Image();
    t.crossOrigin = "anonymous", t.onload = () => {
      try {
        const i = document.createElement("canvas");
        i.width = 50, i.height = 50;
        const a = i.getContext("2d");
        if (!a) return;
        a.drawImage(t, 0, 0, 50, 50);
        const o = a.getImageData(0, 0, 50, 50).data;
        let s = 0, r = 0, h = 0, c = 0;
        for (let p = 0; p < o.length; p += 16) {
          const u = o[p], _ = o[p + 1], m = o[p + 2], f = Math.max(u, _, m), b = Math.min(u, _, m), P = f === 0 ? 0 : (f - b) / f, $ = f / 255;
          P > c && $ > 0.15 && $ < 0.95 && (c = P, s = u, r = _, h = m);
        }
        if (c > 0.1) {
          const p = s / 255, u = r / 255, _ = h / 255, m = Math.max(p, u, _), f = Math.min(p, u, _);
          let b = 0;
          const P = (m + f) / 2, $ = m - f, H = $ === 0 ? 0 : $ / (1 - Math.abs(2 * P - 1));
          $ !== 0 && (m === p ? b = ((u - _) / $ + (u < _ ? 6 : 0)) * 60 : m === u ? b = ((_ - p) / $ + 2) * 60 : b = ((p - u) / $ + 4) * 60);
          const E = Math.max(P * 100, 70), F = Math.max(H * 100, 60);
          this._dominantColor = `hsl(${Math.round(b)}, ${Math.round(F)}%, ${Math.round(E)}%)`;
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
    }), this._resizeObserver.observe(this), this._startProgressTimer();
  }
  disconnectedCallback() {
    super.disconnectedCallback(), this._resizeObserver && this._resizeObserver.disconnect(), this._stopProgressTimer(), this._endLongPress();
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
    super.updated(e), e.has("hass") && this._checkLayout();
  }
  _checkLayout() {
    requestAnimationFrame(() => {
      this._doLayoutCheck();
    });
  }
  _doLayoutCheck() {
    const e = this.getBoundingClientRect(), t = this.shadowRoot?.querySelector("ha-card");
    t && e.height > 0 && (t.classList.toggle("compact-height", e.height <= 195), t.classList.toggle("micro-height", e.height <= 180), t.classList.toggle("tall-narrow", e.height >= 240 && e.width <= 400), t.classList.toggle("very-tall-narrow", e.height >= 300 && e.width <= 450));
    const i = this.shadowRoot?.querySelector(".title"), a = this.shadowRoot?.querySelector(".info-bottom");
    if (!i || !a) return;
    const o = i.getBoundingClientRect(), h = a.getBoundingClientRect().top - e.top - 8, c = 20, p = 18, _ = o.bottom - e.top + 22, f = _ + c + p;
    let b = 0;
    f > h && (b = 1), _ > h && (b = 2), this._overflowState !== b && (this._overflowState = b);
  }
  _formatSeconds(e) {
    const t = e < 0, i = Math.floor(Math.abs(e)), a = Math.floor(i / 3600), o = Math.floor(i % 3600 / 60), s = i % 60, r = t ? "-" : "";
    return a > 0 ? `${r}${a}:${String(o).padStart(2, "0")}:${String(s).padStart(2, "0")}` : `${r}${o}:${String(s).padStart(2, "0")}`;
  }
  _formatTicks(e) {
    return this._formatSeconds(e / 1e7);
  }
};
S.styles = K`
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
            transition: all 0.3s ease-out;
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
            justify-content: space-between;
            align-self: stretch;
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
                min-height: 0;
                --short-badge-padding: 1px !important;
            }
        }
        ha-card.compact-height .meta-line,
        ha-card.compact-height .client-line,
        ha-card.compact-height .card-header {
            display: none !important;
        }
        ha-card.compact-height .title {
            font-size: 1.2rem;
            line-height: 1.1;
            margin-bottom: 2px;
        }
        ha-card.compact-height .main-container {
            gap: 12px;
        }
        ha-card.compact-height .card-content {
            gap: 8px;
        }
        ha-card.compact-height .poster-container {
            min-height: 0;
            --short-badge-padding: 1px !important;
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
  j({ attribute: !1 })
], S.prototype, "hass", 2);
A([
  g()
], S.prototype, "_config", 2);
A([
  g()
], S.prototype, "_rewindActive", 2);
A([
  g()
], S.prototype, "_overflowState", 2);
A([
  g()
], S.prototype, "_dominantColor", 2);
A([
  g()
], S.prototype, "_longPressProgress", 2);
A([
  g()
], S.prototype, "_stopPulse", 2);
A([
  g()
], S.prototype, "_isDragging", 2);
A([
  g()
], S.prototype, "_dragPercentage", 2);
A([
  g()
], S.prototype, "_optimisticSeekPercent", 2);
S = A([
  O("jellyha-now-playing-card")
], S);
//# sourceMappingURL=jellyha-cards.js.map
