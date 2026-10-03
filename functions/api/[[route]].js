// Cloudflare Pages Function: /api/delivery-quote, /api/create-order, /api/payu-return, /api/payu-webhook, /api/check-payment, /api/my-orders, /api/update-order-status
// PayU hosted-page payments. Every payment is verified on the server (PayU signature + PayU verify_payment API) before an order is marked PAID.
// Shop owners (users/{uid}.type === "shop") get SHOP_OFF % off every product.
const SHOP_OFF = 50;
const enc = new TextEncoder();
const J = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { "Content-Type": "application/json" } });
const b64u = (b) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

/* ---------- Firestore REST helpers ---------- */
const fromV = (v) => "stringValue" in v ? v.stringValue : "integerValue" in v ? +v.integerValue : "doubleValue" in v ? v.doubleValue
  : "booleanValue" in v ? v.booleanValue : "nullValue" in v ? null : "timestampValue" in v ? v.timestampValue
  : "arrayValue" in v ? (v.arrayValue.values || []).map(fromV) : "mapValue" in v ? fromF(v.mapValue.fields || {}) : null;
const fromF = (f) => Object.fromEntries(Object.entries(f).map(([k, v]) => [k, fromV(v)]));
const toV = (v) => v === null ? { nullValue: null } : v instanceof Date ? { timestampValue: v.toISOString() }
  : typeof v === "string" ? { stringValue: v } : typeof v === "boolean" ? { booleanValue: v }
  : typeof v === "number" ? (Number.isInteger(v) ? { integerValue: String(v) } : { doubleValue: v })
  : Array.isArray(v) ? { arrayValue: { values: v.map(toV) } } : { mapValue: { fields: toF(v) } };
const toF = (o) => Object.fromEntries(Object.entries(o).map(([k, v]) => [k, toV(v)]));
const FS = (env) => `https://firestore.googleapis.com/v1/projects/${env.FIREBASE_PROJECT_ID}/databases/(default)/documents`;

async function accessToken(env) {
  const now = Math.floor(Date.now() / 1000);
  const head = b64u(enc.encode(JSON.stringify({ alg: "RS256", typ: "JWT" })));
  const claim = b64u(enc.encode(JSON.stringify({ iss: env.FIREBASE_CLIENT_EMAIL, scope: "https://www.googleapis.com/auth/datastore", aud: "https://oauth2.googleapis.com/token", iat: now, exp: now + 3600 })));
  const pem = env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n").replace(/-----[^-]+-----/g, "").replace(/\s/g, "");
  const key = await crypto.subtle.importKey("pkcs8", Uint8Array.from(atob(pem), (c) => c.charCodeAt(0)), { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, enc.encode(head + "." + claim));
  const r = await fetch("https://oauth2.googleapis.com/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=" + head + "." + claim + "." + b64u(sig) });
  const d = await r.json();
  if (!d.access_token) throw new Error("Firebase service account auth failed");
  return d.access_token;
}
const H = (t) => ({ Authorization: "Bearer " + t, "Content-Type": "application/json" });
async function fsGet(env, t, path, fields) {
  const q = fields ? "?" + fields.map((f) => "mask.fieldPaths=" + f).join("&") : "";
  const r = await fetch(`${FS(env)}/${path}${q}`, { headers: H(t) });
  if (r.status === 404) return null;
  if (!r.ok) throw new Error("Firestore read failed " + r.status);
  return fromF((await r.json()).fields || {});
}
async function fsCreate(env, t, col, id, obj) {
  const r = await fetch(`${FS(env)}/${col}?documentId=${encodeURIComponent(id)}`, { method: "POST", headers: H(t), body: JSON.stringify({ fields: toF(obj) }) });
  if (!r.ok) throw new Error("Firestore create failed " + r.status);
}
async function fsPatch(env, t, path, obj) {
  const q = Object.keys(obj).map((k) => "updateMask.fieldPaths=" + k).join("&");
  const r = await fetch(`${FS(env)}/${path}?${q}`, { method: "PATCH", headers: H(t), body: JSON.stringify({ fields: toF(obj) }) });
  if (!r.ok) throw new Error("Firestore update failed " + r.status);
}

/* ---------- crypto / auth ---------- */
async function hmacHex(secret, msg) {
  const k = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return [...new Uint8Array(await crypto.subtle.sign("HMAC", k, enc.encode(msg)))].map((b) => b.toString(16).padStart(2, "0")).join("");
}
const sha512 = async (x) => [...new Uint8Array(await crypto.subtle.digest("SHA-512", enc.encode(x)))].map((b) => b.toString(16).padStart(2, "0")).join("");
const same = (a, b) => { if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i); return d === 0; };
async function whoIs(env, idToken) {
  const r = await fetch("https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=" + env.FIREBASE_API_KEY, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ idToken }) });
  const d = await r.json(), u = d.users && d.users[0];
  if (!u) throw "Please sign in again.";
  return { uid: u.localId, email: (u.email || "").toLowerCase(), verified: !!u.emailVerified };
}
async function fsGetRaw(env, t, path) {
  const r = await fetch(`${FS(env)}/${path}`, { headers: H(t) });
  if (r.status === 404) return null;
  if (!r.ok) throw new Error("Firestore read failed " + r.status);
  const j = await r.json();
  return { data: fromF(j.fields || {}), updateTime: j.updateTime };
}
// Marks the order PAID and reduces stock in ONE atomic commit. The updateTime precondition makes it
// safe if the browser return and the PayU webhook arrive at the same moment: only one of them wins.
async function markPaid(env, t, orderId, paymentId) {
  const cur = await fsGetRaw(env, t, "orders/" + orderId);
  if (!cur || cur.data.paymentStatus === "PAID") return;
  const o = cur.data, base = `projects/${env.FIREBASE_PROJECT_ID}/databases/(default)/documents`;
  const inc = (path, field, n) => ({ transform: { document: `${base}/${path}`, fieldTransforms: [{ fieldPath: field, increment: { integerValue: String(n) } }] } });
  const upd = { paymentStatus: "PAID", payuPaymentId: paymentId, paidAt: new Date() };
  const writes = [{ update: { name: `${base}/orders/${orderId}`, fields: toF(upd) }, updateMask: { fieldPaths: Object.keys(upd) }, currentDocument: { updateTime: cur.updateTime } }];
  o.items.forEach((i) => writes.push(inc("products/" + i.productId, "stock", -i.qty)));
  if (o.couponCode) writes.push(inc("coupons/" + o.couponCode, "used", 1));
  const r = await fetch(`https://firestore.googleapis.com/v1/${base}:commit`, { method: "POST", headers: H(t), body: JSON.stringify({ writes }) });
  if (!r.ok && r.status !== 400 && r.status !== 409 && r.status !== 412) throw new Error("Firestore commit failed " + r.status);
}

// Asks PayU directly: "was this txnid really paid?"  Returns "success" | "failed" | "pending".
async function payuStatus(env, txnid) {
  const command = "verify_payment", hash = await sha512([env.PAYU_KEY, command, txnid, env.PAYU_SALT].join("|"));
  const url = env.PAYU_VERIFY_URL || ((env.PAYU_URL || "").includes("test") ? "https://test.payu.in/merchant/postservice?form=2" : "https://info.payu.in/merchant/postservice?form=2");
  const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ key: env.PAYU_KEY, command, var1: txnid, hash }) });
  const d = await r.json().catch(() => null), x = d && d.transaction_details && d.transaction_details[txnid];
  if (!x) return { state: "pending" };
  const st = String(x.status || "").toLowerCase();
  if (st === "success") return { state: "success", amount: parseFloat(x.amt || x.transaction_amount), id: String(x.mihpayid || "") };
  if (["failure", "failed", "bounced", "usercancelled", "dropped"].includes(st)) return { state: "failed" };
  return { state: "pending" };   // pending / initiated / in progress
}
// Single place that decides an order's final state, always by asking PayU. Returns "success" | "failed" | "pending".
async function settleOrder(env, t, txnid) {
  const o = await fsGet(env, t, "orders/" + txnid);
  if (!o) return "failed";
  if (o.paymentStatus === "PAID") return "success";
  const v = await payuStatus(env, txnid);
  if (v.state === "success" && Math.round(v.amount * 100) === o.amount) { await markPaid(env, t, txnid, v.id); return "success"; }
  if (v.state === "success") return "failed";          // amount mismatch: never confirm
  if (v.state === "failed") { if (o.paymentStatus === "PENDING") await fsPatch(env, t, "orders/" + txnid, { paymentStatus: "FAILED" }); return "failed"; }
  return "pending";
}

/* ---------- delivery charge by distance ---------- */
const DEF = { shopPincode: "141001", slabs: [{ km: 50, charge: 100, extra: 30 }, { km: 100, charge: 150, extra: 50 }, { km: 200, charge: 250, extra: 80 }], beyond: 400, beyondExtra: 120, fallback: 200, freeAbove: 0 };
const hav = (a, b) => { const R = 6371, r = (x) => x * Math.PI / 180, dA = r(b.lat - a.lat), dO = r(b.lng - a.lng),
  h = Math.sin(dA / 2) ** 2 + Math.cos(r(a.lat)) * Math.cos(r(b.lat)) * Math.sin(dO / 2) ** 2; return 2 * R * Math.asin(Math.sqrt(h)); };
async function geo(env, t, pin) {
  const c = await fsGet(env, t, "pincodeCache/" + pin);
  if (c && c.lat) return c;
  const r = await fetch(`https://nominatim.openstreetmap.org/search?postalcode=${pin}&country=India&format=json&limit=1`, { headers: { "User-Agent": "spare-parts-shop/1.0" } });
  const a = await r.json().catch(() => []);
  if (!a[0]) return null;
  const g = { lat: +a[0].lat, lng: +a[0].lon };
  await fsPatch(env, t, "pincodeCache/" + pin, g).catch(() => {});
  return g;
}
// Returns charge in paise = slab price for the first kg + extra per additional kg (weight rounded up).
// Road distance is estimated as straight-line x 1.3.
async function quote(env, t, pin, subtotal, grams) {
  const s = { ...DEF, ...((await fsGet(env, t, "settings/delivery")) || {}) };
  const kg = Math.max(1, Math.ceil((grams || 0) / 1000)), more = kg - 1;
  if (s.freeAbove > 0 && subtotal >= s.freeAbove * 100) return { charge: 0, km: 0, kg, free: true };
  if (!/^[1-9]\d{5}$/.test(pin)) throw "Enter a valid 6-digit pincode.";
  const [a, b] = await Promise.all([geo(env, t, String(s.shopPincode)), geo(env, t, pin)]);
  if (!a || !b) return { charge: (s.fallback + more * (s.beyondExtra || 0)) * 100, km: 0, kg, approx: true };
  const km = Math.round(hav(a, b) * 1.3);
  const slab = [...s.slabs].sort((x, y) => x.km - y.km).find((x) => km <= x.km);
  const base = slab ? slab.charge : s.beyond, extra = slab ? (slab.extra || 0) : (s.beyondExtra || 0);
  return { charge: (base + more * extra) * 100, km, kg };
}

/* ---------- routes ---------- */
const isShop = (p) => !!p && (p.type === "shop" || (!p.type && !!p.shopCode));
async function authUser(env, t, idToken) {
  const me = await whoIs(env, idToken);
  const prof = await fsGet(env, t, "users/" + me.uid);
  const admins = (env.ADMIN_EMAILS || "").toLowerCase().split(",").map((x) => x.trim());
  if (!((prof && prof.is_verified && !prof.is_banned) || (me.verified && admins.includes(me.email)))) throw "Your account is not allowed to order.";
  return { me, prof };
}
async function priceItems(env, t, items, off = 0) {
  if (!Array.isArray(items) || !items.length || items.length > 50) throw "Cart is empty.";
  const lines = []; let sub = 0, grams = 0;
  for (const it of items) {
    const qty = Math.floor(+it.qty);
    if (!(qty >= 1 && qty <= 999)) throw "Invalid quantity.";
    const p = await fsGet(env, t, "products/" + encodeURIComponent(it.id), ["name", "price", "stock", "weight"]);
    if (!p) throw "A product is no longer available.";
    if (p.stock < qty) throw `Only ${p.stock} left of ${p.name}.`;
    const price = Math.round(p.price * (100 - off) / 100);
    lines.push({ productId: it.id, name: p.name, price, qty }); sub += price * qty; grams += (p.weight || 0) * qty;
  }
  return { lines, sub, grams };
}
async function applyCoupon(env, t, raw, sub) {
  const code = String(raw || "").trim().toUpperCase();
  if (!code) return { discount: 0, percent: 0, code: "" };
  if (!/^[A-Z0-9_-]{3,20}$/.test(code)) throw "Invalid or expired code.";
  const c = await fsGet(env, t, "coupons/" + code);
  if (!c || !c.active || (c.maxUses > 0 && (c.used || 0) >= c.maxUses)) throw "Invalid or expired code.";
  const percent = Math.min(Math.max(+c.percent || 0, 0), 90);
  return { discount: Math.floor(sub * percent / 100), percent, code };
}
async function deliveryQuote(env, req) {
  const { idToken, items, pincode, coupon } = await req.json(), t = await accessToken(env);
  const { prof } = await authUser(env, t, idToken);
  const off = isShop(prof) ? SHOP_OFF : 0;
  const { sub, grams } = await priceItems(env, t, items, off);
  let cp = { discount: 0, percent: 0, code: "" }, couponError = "";
  try { cp = await applyCoupon(env, t, coupon, sub); } catch (e) { if (typeof e !== "string") throw e; couponError = e; }
  const pin = String(pincode || "").trim();
  if (!/^[1-9]\d{5}$/.test(pin)) return { charge: 0, km: 0, nopin: true, subtotal: sub, ...cp, couponError };
  const q = await quote(env, t, pin, sub - cp.discount, grams);
  return { ...q, subtotal: sub, ...cp, couponError };
}
async function createOrder(env, req) {
  const { idToken, items, shipping, coupon } = await req.json(), t = await accessToken(env);
  const { me, prof } = await authUser(env, t, idToken);
  const off = isShop(prof) ? SHOP_OFF : 0;
  const { lines, sub, grams } = await priceItems(env, t, items, off);
  const cp = await applyCoupon(env, t, coupon, sub);
  const s = shipping || {};
  const q = await quote(env, t, String(s.pincode || "").trim(), sub - cp.discount, grams);
  const amount = sub - cp.discount + q.charge;
  if (amount < 100) throw "Invalid amount.";
  const txnid = crypto.randomUUID().replace(/-/g, "").slice(0, 24), amt = (amount / 100).toFixed(2), info = "Spare parts order";
  const fn = String(s.name || "").replace(/[^A-Za-z0-9 ]/g, "").trim().slice(0, 40) || "Customer";
  const phone = String(s.phone || "").replace(/\D/g, "").slice(-10);
  const hash = await sha512([env.PAYU_KEY, txnid, amt, info, fn, me.email, "", "", "", "", "", "", "", "", "", "", env.PAYU_SALT].join("|"));
  await fsCreate(env, t, "orders", txnid, { userId: me.uid, email: me.email, shopCode: (prof && prof.shopCode) || (prof ? "" : "ADMIN"), shopOff: off, items: lines, itemsTotal: sub,
    couponCode: cp.code, couponPercent: cp.percent, discount: cp.discount, shippingCharge: q.charge, distanceKm: q.km, weightGrams: grams, amount, paymentStatus: "PENDING",
    shipping: { name: String(s.name || "").slice(0, 100), phone: String(s.phone || "").slice(0, 20), address: String(s.address || "").slice(0, 300), city: String(s.city || "").slice(0, 80), pincode: String(s.pincode || "").slice(0, 10) },
    payuTxnId: txnid, createdAt: new Date() });
  const back = new URL(req.url).origin + "/api/payu-return";
  return { action: env.PAYU_URL || "https://secure.payu.in/_payment", fields: { key: env.PAYU_KEY, txnid, amount: amt, productinfo: info, firstname: fn, email: me.email, phone, surl: back, furl: back, hash } };
}
// PayU sends the customer back here (surl/furl) with a signed result. We check the signature with our Salt,
// then confirm with PayU's own verify API (never trust the browser). Outcome: success / pending / failed.
async function payuReturn(env, req) {
  const origin = new URL(req.url).origin; let oid = "";
  const go = (r) => new Response(null, { status: 303, headers: { Location: origin + "/?pay=" + r + (oid ? "&o=" + oid : "") } });
  try {
    const f = Object.fromEntries(await req.formData());
    if (!/^[A-Za-z0-9]{10,25}$/.test(String(f.txnid))) return go("failed");
    oid = f.txnid;
    const seq = [env.PAYU_SALT, f.status, "", "", "", "", "", f.udf5 || "", f.udf4 || "", f.udf3 || "", f.udf2 || "", f.udf1 || "", f.email, f.firstname, f.productinfo, f.amount, f.txnid, env.PAYU_KEY];
    if (f.additionalCharges) seq.unshift(f.additionalCharges);
    if (!same(await sha512(seq.join("|")), String(f.hash || "").toLowerCase())) return go("failed");
    return go(await settleOrder(env, await accessToken(env), f.txnid));
  } catch (e) { return go("pending"); }   // could not verify right now: never say "failed" for a payment that may have gone through
}
// PayU server-to-server callback (set this URL in PayU dashboard > Webhooks). Works even if the customer closes the browser.
async function payuWebhook(env, req) {
  const ct = req.headers.get("content-type") || "";
  const b = ct.includes("json") ? await req.json().catch(() => ({})) : Object.fromEntries(await req.formData().catch(() => []));
  const txnid = String(b.txnid || (b.payload && b.payload.txnid) || "");
  if (/^[A-Za-z0-9]{10,25}$/.test(txnid)) await settleOrder(env, await accessToken(env), txnid);
  return J({ ok: true });
}
// Customer-facing "check my payment status" button / auto-check.
async function checkPayment(env, req) {
  const { idToken, orderId } = await req.json(), t = await accessToken(env);
  const me = await whoIs(env, idToken), id = String(orderId || "");
  if (!/^[A-Za-z0-9]{10,25}$/.test(id)) throw "Order not found.";
  const o = await fsGet(env, t, "orders/" + id, ["userId"]);
  if (!o || o.userId !== me.uid) throw "Order not found.";
  return { status: await settleOrder(env, t, id) };
}
/* ---------- order tracking: My Orders + admin status updates ---------- */
const TRACK = ["placed", "packed", "shipped", "out_for_delivery", "delivered"];
const TRACK_TIME = { packed: "packedAt", shipped: "shippedAt", out_for_delivery: "outAt", delivered: "deliveredAt" };
const OWNERS = ["ekamsinghlehal@gmail.com", "displaywallahoffical@gmail.com"];
async function myOrders(env, req) {
  const { idToken } = await req.json(), t = await accessToken(env), me = await whoIs(env, idToken);
  const r = await fetch(`${FS(env)}:runQuery`, { method: "POST", headers: H(t), body: JSON.stringify({ structuredQuery: {
    from: [{ collectionId: "orders" }], where: { fieldFilter: { field: { fieldPath: "userId" }, op: "EQUAL", value: { stringValue: me.uid } } }, limit: 100 } }) });
  if (!r.ok) throw new Error("Firestore query failed " + r.status);
  const orders = (await r.json()).filter((x) => x.document).map((x) => ({ id: x.document.name.split("/").pop(), ...fromF(x.document.fields || {}) }))
    .filter((o) => o.paymentStatus === "PAID")
    .sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)))
    .map((o) => ({ id: o.id, createdAt: o.createdAt, items: o.items || [], itemsTotal: o.itemsTotal || 0, discount: o.discount || 0, couponCode: o.couponCode || "",
      shippingCharge: o.shippingCharge || 0, amount: o.amount || 0, shipping: o.shipping || {}, trackStatus: TRACK.includes(o.trackStatus) ? o.trackStatus : "placed",
      paidAt: o.paidAt || o.createdAt, packedAt: o.packedAt || null, shippedAt: o.shippedAt || null, outAt: o.outAt || null, deliveredAt: o.deliveredAt || null }));
  return { orders };
}
async function updateOrderStatus(env, req) {
  const { idToken, orderId, status } = await req.json(), t = await accessToken(env), me = await whoIs(env, idToken);
  const envAdmins = (env.ADMIN_EMAILS || "").toLowerCase().split(",").map((x) => x.trim());
  const isAdm = me.verified && (OWNERS.includes(me.email) || envAdmins.includes(me.email) || !!(await fsGet(env, t, "admins/" + encodeURIComponent(me.email), ["email"])));
  if (!isAdm) throw "Only admins can update order status.";
  const id = String(orderId || ""), i = TRACK.indexOf(status);
  if (!/^[A-Za-z0-9]{10,25}$/.test(id)) throw "Order not found.";
  if (i < 0) throw "Invalid status.";
  const o = await fsGet(env, t, "orders/" + id, ["paymentStatus"]);
  if (!o) throw "Order not found.";
  if (o.paymentStatus !== "PAID") throw "Only paid orders can be tracked.";
  const upd = { trackStatus: status, trackUpdatedAt: new Date() };
  TRACK.forEach((k, j) => { if (TRACK_TIME[k]) upd[
