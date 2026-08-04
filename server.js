const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const url = require('url');
const crypto = require('crypto');

require('./lib/env').loadEnv(path.join(__dirname, '.env'));

const Router = require('./lib/router');
const db = require('./lib/db');
const auth = require('./lib/auth');
const products = require('./data/products');

const PORT = process.env.PORT || 3000;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'owner@leelamart.com';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const DELIVERY_WAIT_MS = 5 * 60 * 1000; // 5 minutes, same as the original demo
const TAX_RATE = 0.18;
const DELIVERY_FEE = 100;
const RAZORPAY_KEY_ID = process.env.RAZORPAY_KEY_ID || '';
const RAZORPAY_KEY_SECRET = process.env.RAZORPAY_KEY_SECRET || '';
const GIFTMINT_PARTNER_KEY = process.env.GIFTMINT_PARTNER_KEY || '';

const router = new Router();

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------
function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(body);
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', chunk => {
      data += chunk;
      if (data.length > 2_000_000) { // 2MB safety cap
        reject(new Error('Body too large'));
        req.destroy();
      }
    });
    req.on('end', () => {
      if (!data) return resolve({});
      try { resolve(JSON.parse(data)); }
      catch (e) { reject(new Error('Invalid JSON body')); }
    });
    req.on('error', reject);
  });
}

// Like readJsonBody, but hands back the raw string too - needed for Razorpay
// signature verification, which is computed over the exact bytes received.
function readRawBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', chunk => {
      data += chunk;
      if (data.length > 2_000_000) {
        reject(new Error('Body too large'));
        req.destroy();
      }
    });
    req.on('end', () => resolve(data));
    req.on('error', reject);
  });
}

function verifyRazorpaySignature(rawBody, signatureHeader, secret) {
  if (!signatureHeader) return false;
  const expected = crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
  const a = Buffer.from(signatureHeader, 'hex');
  const b = Buffer.from(expected, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

async function getCurrentUser(req) {
  const cookies = auth.parseCookies(req);
  return db.getUserByToken(cookies.session);
}

async function isAdmin(req) {
  const cookies = auth.parseCookies(req);
  return db.isAdminSessionValid(cookies.admin_session);
}

function computeItemsFromCart(cartItems) {
  // cartItems: [{productId, qty}] from the client - we NEVER trust client-sent
  // prices, always look the authoritative price up server-side.
  const items = [];
  for (const ci of cartItems) {
    const p = products.find(x => x.id === Number(ci.productId));
    if (!p) throw new Error(`Unknown product id ${ci.productId}`);
    const qty = Math.max(1, parseInt(ci.qty, 10) || 1);
    items.push({ id: p.id, name: p.name, price: p.price, qty });
  }
  if (items.length === 0) throw new Error('No items in order');
  return items;
}

// Timestamp + 4 random bytes of entropy - safe against collisions even
// when many orders (e.g. a burst of webhook payments) are created in the
// same millisecond, unlike a plain Date.now() slice.
function newOrderId(prefix) {
  return prefix + Date.now().toString(36) + crypto.randomBytes(4).toString('hex');
}

// Always formats in IST regardless of the server's own OS timezone (e.g.
// most hosts run in UTC) - without an explicit timeZone, toLocaleString
// uses the server's local time, which is wrong for Indian customers.
function formatOrderDate() {
  return new Date().toLocaleString('en-IN', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit', timeZone: 'Asia/Kolkata' });
}

const ADDRESS_POOL = [
  { city: 'Mumbai', state: 'Maharashtra', pin: '400001' },
  { city: 'New Delhi', state: 'Delhi', pin: '110001' },
  { city: 'Bengaluru', state: 'Karnataka', pin: '560001' },
  { city: 'Chennai', state: 'Tamil Nadu', pin: '600001' },
  { city: 'Kolkata', state: 'West Bengal', pin: '700001' },
  { city: 'Hyderabad', state: 'Telangana', pin: '500001' },
  { city: 'Pune', state: 'Maharashtra', pin: '411001' },
  { city: 'Jaipur', state: 'Rajasthan', pin: '302001' },
  { city: 'Lucknow', state: 'Uttar Pradesh', pin: '226001' },
  { city: 'Kochi', state: 'Kerala', pin: '682001' }
];
const STREET_POOL = ['MG Road', 'Park Street', 'Station Road', 'Civil Lines', 'Sector 21', 'Gandhi Nagar', 'Nehru Place', 'Ring Road'];
function randomAddress() {
  const a = ADDRESS_POOL[Math.floor(Math.random() * ADDRESS_POOL.length)];
  const houseNo = Math.floor(Math.random() * 450) + 1;
  const street = STREET_POOL[Math.floor(Math.random() * STREET_POOL.length)];
  return `${houseNo}, ${street}, ${a.city}, ${a.state} - ${a.pin}`;
}

function toTitleCase(s) {
  return String(s).trim().replace(/\s+/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

// A real (or auto) account's delivery address is assigned once, the first
// time they get an order, and reused for every order after that - not
// re-randomized each time, which is what a real customer would expect.
async function getOrAssignAddress(user) {
  if (user.address) return user.address;
  const address = randomAddress();
  await db.updateUserAddress(user.email, address);
  user.address = address;
  return address;
}

// Pulls the payer name + paid amount (in rupees) out of a Razorpay
// `payment.captured` webhook payload. Also accepts a flat {name, amount}
// body so the flow can be smoke-tested with curl before Razorpay is wired up.
function extractRazorpayPaymentDetails(body) {
  const entity = body && body.payload && body.payload.payment && body.payload.payment.entity;
  if (entity) {
    const amount = typeof entity.amount === 'number' ? entity.amount / 100 : null;
    const notes = entity.notes;
    const notesName = notes && !Array.isArray(notes) && (notes.name || notes.customer_name);
    const emailName = entity.email ? entity.email.split('@')[0].replace(/[._]+/g, ' ') : null;
    // Real Razorpay QR/UPI payments carry no name, email, or contact at
    // all - the only thing that's ever actually populated is the payer's
    // VPA (UPI ID, e.g. "raj.kumar-14@okaxis"). Not a real name, but it's
    // the only field that differs per payer, so it's what attributes each
    // scan to a distinct "customer" instead of lumping everyone into one
    // generic account.
    const vpa = entity.vpa || (entity.upi && entity.upi.vpa);
    const vpaName = vpa ? vpa.split('@')[0].replace(/[._-]+/g, ' ') : null;
    const name = notesName || emailName || vpaName || null;
    return { amount, name: name ? toTitleCase(name) : null, event: body.event || null };
  }
  if (body && body.amount != null) {
    return { amount: Number(body.amount), name: body.name ? toTitleCase(body.name) : null, event: 'manual' };
  }
  return { amount: null, name: null, event: null };
}

// Builds a realistic "shopping basket" of real catalog products (any mix,
// any quantities) that fills up to a target subtotal.
function fillBasket(targetSubtotal, cheapestPrice) {
  const shuffled = [...products].sort(() => Math.random() - 0.5);
  const basket = [];
  let remaining = targetSubtotal;
  for (const p of shuffled) {
    if (remaining < p.price) continue;
    const maxQty = Math.min(Math.floor(remaining / p.price), 10);
    const qty = Math.floor(Math.random() * maxQty) + 1;
    basket.push({ id: p.id, name: p.name, price: p.price, qty });
    remaining -= p.price * qty;
    if (remaining < cheapestPrice) break;
  }
  return basket;
}

// Turns a captured payment amount into a priced order that always sums to
// exactly that amount - the real money received is the only source of
// truth, never something the catalog/GST math is allowed to drift from.
//
// When the amount is big enough to plausibly include 18% GST + Rs.100
// delivery on top of at least one real product, it fills a realistic
// basket and reconciles tax to make the total exact. When it's too small
// for that (e.g. a Rs.11 UPI payment, cheaper than any single catalog
// item), there's no honest way to add tax/delivery on top - instead it
// picks the closest-priced real product and prices that one line item at
// exactly what was paid, as if it sold at a discount.
function priceWebhookOrder(amount) {
  const cheapestPrice = products.reduce((min, p) => Math.min(min, p.price), Infinity);
  const targetSubtotal = Math.round((amount - DELIVERY_FEE) / (1 + TAX_RATE));

  if (targetSubtotal >= cheapestPrice) {
    const items = fillBasket(targetSubtotal, cheapestPrice);
    const basketSubtotal = items.reduce((s, i) => s + i.price * i.qty, 0);
    const delivery = DELIVERY_FEE;
    const tax = Math.max(0, Math.round(amount - basketSubtotal - delivery));
    return { items, subtotal: basketSubtotal, tax, delivery, grandTotal: basketSubtotal + tax + delivery };
  }

  // Too small for a normal GST + delivery breakdown - sell one real
  // product "at a discount" for exactly the amount paid instead.
  const closest = products.reduce((a, b) => Math.abs(a.price - amount) < Math.abs(b.price - amount) ? a : b);
  return {
    items: [{ id: closest.id, name: closest.name, price: amount, qty: 1 }],
    subtotal: amount, tax: 0, delivery: 0, grandTotal: amount
  };
}

// Finds (or auto-creates) a user account under the payer's name so the
// webhook-generated order shows up as a normal customer order. Synthetic
// accounts get a random password (nobody needs to log into them - they
// exist purely so the order is attributed and visible on the dashboard).
// Picks an email domain for an auto-created account that looks like a real
// address instead of an obviously-synthetic one - but deterministically
// from the slug, so the same payer always lands on the same domain (and
// therefore the same account) across repeat payments, not a new random one
// each time. Numeric slugs (a bare phone number, e.g. a VPA with no name
// in it) get gmail.com specifically - a real person owning the exact same
// digits as their own Gmail username is rare enough to accept; everyone
// else is spread across a few other common providers for variety.
const AUTO_USER_DOMAINS = ['icloud.com', 'outlook.com', 'yahoo.com', 'leelamart.com'];
function pickAutoUserDomain(slug) {
  if (/^\d+$/.test(slug)) return 'gmail.com';
  let hash = 0;
  for (let i = 0; i < slug.length; i++) hash = (hash * 31 + slug.charCodeAt(i)) >>> 0;
  return AUTO_USER_DOMAINS[hash % AUTO_USER_DOMAINS.length];
}

async function findOrCreateAutoUser(name) {
  const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '.').replace(/^\.+|\.+$/g, '') || 'customer';
  const email = `${slug}@${pickAutoUserDomain(slug)}`;
  let user = await db.getUserByEmail(email);
  if (!user) {
    const { salt, hash } = auth.hashPassword(auth.newToken());
    try {
      await db.createUser({ email, name, passwordSalt: salt, passwordHash: hash, auto: true });
      user = { email, name, passwordSalt: salt, passwordHash: hash, auto: true };
    } catch (e) {
      // Two payments for the same person landed at the same instant and
      // both tried to create this account - the other one won, so just use
      // what it created instead of failing this request.
      if (e.code !== 'ER_DUP_ENTRY') throw e;
      user = await db.getUserByEmail(email);
    }
  }
  return user;
}

// Calls the Razorpay REST API using key/secret Basic Auth. No SDK - just the
// built-in https module.
function razorpayApiRequest(method, pathname, bodyObj) {
  return new Promise((resolve, reject) => {
    const payload = bodyObj ? JSON.stringify(bodyObj) : null;
    const authHeader = 'Basic ' + Buffer.from(`${RAZORPAY_KEY_ID}:${RAZORPAY_KEY_SECRET}`).toString('base64');
    const req = https.request({
      hostname: 'api.razorpay.com',
      path: pathname,
      method,
      headers: Object.assign(
        { Authorization: authHeader },
        payload ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } : {}
      )
    }, res => {
      let data = '';
      res.on('data', c => { data += c; });
      res.on('end', () => {
        let parsed;
        try { parsed = data ? JSON.parse(data) : {}; } catch (e) { parsed = { raw: data }; }
        resolve({ status: res.statusCode, body: parsed });
      });
    });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

// Razorpay order_id -> priced cart, kept in memory only until the payment is
// verified (or abandoned). Server-computed pricing is what actually gets
// charged and later turned into the real order - the client never gets to
// dictate the amount.
const pendingPayments = new Map();
const PENDING_PAYMENT_TTL_MS = 30 * 60 * 1000;
function prunePendingPayments() {
  const cutoff = Date.now() - PENDING_PAYMENT_TTL_MS;
  for (const [id, p] of pendingPayments) {
    if (p.createdAt < cutoff) pendingPayments.delete(id);
  }
}

// ---------------------------------------------------------------------------
// Auth routes
// ---------------------------------------------------------------------------
router.post('/api/auth/signup', async (req, res) => {
  const body = await readJsonBody(req);
  const email = String(body.email || '').trim().toLowerCase();
  const name = String(body.name || '').trim();
  const password = String(body.password || '');

  if (!email || !auth.isValidGmail(email)) return sendJson(res, 400, { error: 'Please enter a valid @gmail.com email address.' });
  if (!name) return sendJson(res, 400, { error: 'Please enter your name.' });
  if (!password) return sendJson(res, 400, { error: 'Please enter a password.' });
  if (await db.getUserByEmail(email)) return sendJson(res, 400, { error: 'An account with this email already exists. Please login instead.' });

  const { salt, hash } = auth.hashPassword(password);
  const token = auth.newToken();
  await db.createUser({ email, name, passwordSalt: salt, passwordHash: hash });
  await db.addSession(email, token);
  auth.setCookie(res, 'session', token, 60 * 60 * 24 * 30);
  sendJson(res, 200, { name, email });
});

router.post('/api/auth/login', async (req, res) => {
  const body = await readJsonBody(req);
  const email = String(body.email || '').trim().toLowerCase();
  const password = String(body.password || '');

  if (!email || !auth.isValidGmail(email)) return sendJson(res, 400, { error: 'Please enter a valid @gmail.com email address.' });
  const u = await db.getUserByEmail(email);
  if (!u || !auth.verifyPassword(password, u.passwordSalt, u.passwordHash)) {
    return sendJson(res, 401, { error: 'Invalid email or password. New here? Sign up instead.' });
  }
  const token = auth.newToken();
  await db.addSession(email, token);
  auth.setCookie(res, 'session', token, 60 * 60 * 24 * 30);
  sendJson(res, 200, { name: u.name, email: u.email });
});

router.post('/api/auth/forgot-password', async (req, res) => {
  const body = await readJsonBody(req);
  const email = String(body.email || '').trim().toLowerCase();
  const newPassword = String(body.newPassword || '');

  if (!email || !auth.isValidGmail(email)) return sendJson(res, 400, { error: 'Please enter a valid @gmail.com email address.' });
  const u = await db.getUserByEmail(email);
  if (!u) return sendJson(res, 404, { error: 'No account found with this Gmail address. Please sign up instead.' });
  if (!newPassword || newPassword.length < 4) return sendJson(res, 400, { error: 'Password must be at least 4 characters.' });

  const { salt, hash } = auth.hashPassword(newPassword);
  await db.updateUserPassword(email, salt, hash);
  const token = auth.newToken();
  await db.addSession(email, token);
  auth.setCookie(res, 'session', token, 60 * 60 * 24 * 30);
  sendJson(res, 200, { name: u.name, email: u.email });
});

router.post('/api/auth/logout', async (req, res) => {
  const cookies = auth.parseCookies(req);
  if (cookies.session) await db.removeSession(cookies.session);
  auth.clearCookie(res, 'session');
  sendJson(res, 200, { ok: true });
});

router.get('/api/auth/me', async (req, res) => {
  const u = await getCurrentUser(req);
  if (!u) return sendJson(res, 200, { user: null });
  sendJson(res, 200, { user: { name: u.name, email: u.email, address: u.address || '', photo: u.photo || null } });
});

router.post('/api/auth/profile', async (req, res) => {
  const u = await getCurrentUser(req);
  if (!u) return sendJson(res, 401, { error: 'Please log in.' });

  const body = await readJsonBody(req);
  const fields = {};

  if (body.name !== undefined) {
    const name = String(body.name || '').trim();
    if (!name) return sendJson(res, 400, { error: 'Name cannot be empty.' });
    if (name.length > 100) return sendJson(res, 400, { error: 'Name is too long.' });
    fields.name = name;
  }
  if (body.address !== undefined) {
    const address = String(body.address || '').trim();
    if (!address) return sendJson(res, 400, { error: 'Address cannot be empty.' });
    if (address.length > 500) return sendJson(res, 400, { error: 'Address is too long.' });
    fields.address = address;
  }
  if (body.photo !== undefined) {
    const photo = String(body.photo || '').trim();
    if (photo && !photo.startsWith('data:image/')) return sendJson(res, 400, { error: 'Invalid photo data.' });
    if (photo.length > 500_000) return sendJson(res, 400, { error: 'Photo is too large.' });
    fields.photo = photo || null;
  }

  if (Object.keys(fields).length === 0) return sendJson(res, 400, { error: 'Nothing to update.' });

  await db.updateUserProfile(u.email, fields);
  sendJson(res, 200, {
    name: fields.name || u.name,
    email: u.email,
    address: fields.address !== undefined ? fields.address : (u.address || ''),
    photo: fields.photo !== undefined ? fields.photo : (u.photo || null)
  });
});

// ---------------------------------------------------------------------------
// Products
// ---------------------------------------------------------------------------
router.get('/api/products', async (req, res) => {
  sendJson(res, 200, products);
});

// ---------------------------------------------------------------------------
// Orders (customer) - actual order creation only happens after a verified
// Razorpay payment (see /api/payments/verify below). There is deliberately
// no "create order for free" endpoint here.
// ---------------------------------------------------------------------------
// Razorpay Standard Checkout: create-order -> checkout.js modal -> verify
// ---------------------------------------------------------------------------
router.post('/api/payments/create-order', async (req, res) => {
  if (!RAZORPAY_KEY_ID || !RAZORPAY_KEY_SECRET) {
    return sendJson(res, 500, { error: 'Razorpay is not configured on this server (missing RAZORPAY_KEY_ID/RAZORPAY_KEY_SECRET).' });
  }
  const u = await getCurrentUser(req);
  if (!u) return sendJson(res, 401, { error: 'Please log in to pay.' });

  const body = await readJsonBody(req);
  let items;
  try { items = computeItemsFromCart(body.items || []); }
  catch (e) { return sendJson(res, 400, { error: e.message }); }

  const subtotal = items.reduce((s, i) => s + i.price * i.qty, 0);
  const tax = Math.round(subtotal * TAX_RATE);
  const delivery = DELIVERY_FEE;
  const grandTotal = subtotal + tax + delivery;
  const amountPaise = Math.round(grandTotal * 100);
  if (amountPaise < 100) return sendJson(res, 400, { error: 'Order amount must be at least Rs. 1.' });

  prunePendingPayments();
  let rzpRes;
  try {
    rzpRes = await razorpayApiRequest('POST', '/v1/orders', {
      amount: amountPaise, currency: 'INR', receipt: 'LM-' + Date.now().toString(36)
    });
  } catch (e) {
    return sendJson(res, 500, { error: 'Could not reach Razorpay: ' + e.message });
  }
  if (rzpRes.status === 401) {
    return sendJson(res, 401, { error: 'Razorpay authentication failed - check RAZORPAY_KEY_ID / RAZORPAY_KEY_SECRET.' });
  }
  if (rzpRes.status >= 400) {
    const msg = (rzpRes.body && rzpRes.body.error && rzpRes.body.error.description) || 'Razorpay order creation failed.';
    return sendJson(res, 500, { error: msg });
  }

  pendingPayments.set(rzpRes.body.id, { userEmail: u.email, items, subtotal, tax, delivery, grandTotal, createdAt: Date.now() });

  sendJson(res, 200, {
    key_id: RAZORPAY_KEY_ID,
    order_id: rzpRes.body.id,
    amount: rzpRes.body.amount,
    currency: rzpRes.body.currency,
    name: u.name,
    email: u.email
  });
});

router.post('/api/payments/verify', async (req, res) => {
  const u = await getCurrentUser(req);
  if (!u) return sendJson(res, 401, { error: 'Please log in.' });

  const body = await readJsonBody(req);
  const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = body;
  if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
    return sendJson(res, 400, { error: 'Missing payment verification fields.' });
  }

  const pending = pendingPayments.get(razorpay_order_id);
  if (!pending || pending.userEmail !== u.email) {
    return sendJson(res, 400, { error: 'No matching pending payment found for this order.' });
  }

  const expected = crypto.createHmac('sha256', RAZORPAY_KEY_SECRET)
    .update(`${razorpay_order_id}|${razorpay_payment_id}`)
    .digest('hex');
  const a = Buffer.from(expected, 'hex');
  const b = Buffer.from(String(razorpay_signature), 'hex');
  const valid = a.length === b.length && crypto.timingSafeEqual(a, b);
  if (!valid) return sendJson(res, 400, { error: 'Payment signature verification failed.' });

  pendingPayments.delete(razorpay_order_id);

  const order = {
    orderId: newOrderId('LM'), orderDate: formatOrderDate(), createdAt: Date.now(),
    address: await getOrAssignAddress(u),
    items: pending.items, subtotal: pending.subtotal, tax: pending.tax, delivery: pending.delivery, grandTotal: pending.grandTotal,
    deliverAt: Date.now() + DELIVERY_WAIT_MS,
    status: 'Processing', offline: false,
    source: 'razorpay-checkout', razorpayOrderId: razorpay_order_id, razorpayPaymentId: razorpay_payment_id,
    userEmail: u.email, customerName: u.name, customerEmail: u.email
  };
  await db.createOrder(order);

  // Send this customer a GiftMint bonus gift code for their purchase.
  // Fire-and-forget - agar GiftMint ka server down ho, Leela Mart ka apna
  // checkout fail nahi hona chahiye, isliye try/catch me wrap kiya hai.
  try {
    await fetch('https://firebrick-loris-129124.hostingersite.com/api/partner/bonus-code', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Partner-Key': GIFTMINT_PARTNER_KEY
      },
      body: JSON.stringify({
        partnerOrderRef: order.orderId,
        customerName: u.name,
        customerEmail: u.email,
        orderValue: order.grandTotal
      })
    });
  } catch (e) {
    console.error('GiftMint bonus code request failed:', e.message);
  }

  sendJson(res, 200, order);
});

router.get('/api/orders/mine', async (req, res) => {
  const u = await getCurrentUser(req);
  if (!u) return sendJson(res, 401, { error: 'Please log in.' });
  await db.refreshStatuses();
  const orders = await db.getOrdersForUser(u.email);
  sendJson(res, 200, orders);
});

router.get('/api/orders/:id', async (req, res, params) => {
  const u = await getCurrentUser(req);
  if (!u) return sendJson(res, 401, { error: 'Please log in.' });
  await db.refreshStatuses();
  const order = await db.getOrderById(params.id);
  if (!order || order.customerEmail !== u.email) return sendJson(res, 404, { error: 'Order not found.' });
  sendJson(res, 200, order);
});

// ---------------------------------------------------------------------------
// Admin / Owner dashboard
// ---------------------------------------------------------------------------
router.post('/api/admin/login', async (req, res) => {
  const body = await readJsonBody(req);
  const email = String(body.email || '').trim().toLowerCase();
  const password = String(body.password || '');
  if (email !== ADMIN_EMAIL.toLowerCase() || password !== ADMIN_PASSWORD) {
    return sendJson(res, 401, { error: 'Invalid admin email or password.' });
  }
  const token = auth.newToken();
  await db.addAdminSession(token);
  auth.setCookie(res, 'admin_session', token, 60 * 60 * 8);
  sendJson(res, 200, { ok: true });
});

router.post('/api/admin/logout', async (req, res) => {
  const cookies = auth.parseCookies(req);
  if (cookies.admin_session) await db.removeAdminSession(cookies.admin_session);
  auth.clearCookie(res, 'admin_session');
  sendJson(res, 200, { ok: true });
});

// Cheap check the frontend calls on page load to tell whether the owner is
// still validly logged in (and, since isAdmin() renews the idle timer,
// this call itself counts as activity).
router.get('/api/admin/me', async (req, res) => {
  if (!(await isAdmin(req))) return sendJson(res, 401, { error: 'Not logged in.' });
  sendJson(res, 200, { ok: true });
});

// Customer-facing label for the internal `source` tag, so the invoice
// reads like a normal receipt instead of showing an implementation detail
// like "razorpay-webhook".
const ORDER_SOURCE_LABELS = {
  'razorpay-checkout': 'Razorpay Checkout',
  'razorpay-webhook': 'UPI Payment',
  'sms-paste': 'Bank SMS (Manual Entry)',
  'manual': 'Manual Entry'
};

// Renders a standalone, print-ready Tax Invoice page for one order. Works
// for every order (self-placed, offline, or Razorpay) since it's looked up
// from the admin's own view rather than a customer session - the
// auto/synthetic accounts webhooks create have no real login, so this is
// the only way to ever see their invoice.
function renderInvoiceHtml(o) {
  const esc = v => String(v).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const rows = o.items.map(i => `<tr><td>${esc(i.name)}</td><td>${i.qty}</td><td>Rs. ${i.price.toLocaleString('en-IN')}</td><td>Rs. ${(i.price * i.qty).toLocaleString('en-IN')}</td></tr>`).join('');
  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Invoice ${esc(o.orderId)} - Leela Mart</title>
<style>
  body{font-family:Arial,Helvetica,sans-serif;color:#222;max-width:700px;margin:24px auto;padding:0 16px;}
  h1{font-size:22px;margin:0 0 2px;}
  .sub{color:#666;font-size:13px;margin-bottom:18px;}
  .row{display:flex;justify-content:space-between;gap:24px;margin-bottom:18px;flex-wrap:wrap;}
  .box h4{font-size:11px;text-transform:uppercase;color:#888;margin:0 0 4px;letter-spacing:.5px;}
  .box p{margin:0;font-size:13.5px;line-height:1.6;}
  table{width:100%;border-collapse:collapse;margin:16px 0;font-size:13.5px;}
  th{text-align:left;border-bottom:2px solid #ddd;padding:8px 6px;color:#666;font-size:11px;text-transform:uppercase;}
  td{padding:8px 6px;border-bottom:1px solid #eee;}
  .totals{margin-left:auto;width:260px;}
  .totals div{display:flex;justify-content:space-between;padding:4px 0;font-size:13.5px;}
  .totals .grand{font-size:17px;font-weight:800;border-top:2px solid #ddd;margin-top:6px;padding-top:8px;}
  .status{display:inline-block;padding:4px 10px;border-radius:4px;font-size:12px;font-weight:700;margin-bottom:16px;}
  .status.delivered{background:#e8f5e9;color:#2e7d32;}
  .status.processing{background:#fff3e0;color:#ef6c00;}
  .disclaimer{margin-top:28px;font-size:11px;color:#999;border-top:1px solid #eee;padding-top:10px;}
  .print-bar{text-align:right;margin-bottom:16px;}
  .print-bar button{padding:9px 18px;border:none;border-radius:6px;background:#6a1b9a;color:#fff;font-weight:700;font-size:13px;cursor:pointer;}
  @media print{.print-bar{display:none;}}
</style></head>
<body>
  <div class="print-bar"><button onclick="window.print()">Download / Print as PDF</button></div>
  <h1>Leela Mart</h1>
  <div class="sub">Tax Invoice &middot; Order ID: ${esc(o.orderId)} &middot; ${esc(o.orderDate)}</div>
  <span class="status ${o.status === 'Delivered' ? 'delivered' : 'processing'}">${esc(o.status)}</span>
  <div class="row">
    <div class="box"><h4>Billed To</h4><p>${esc(o.customerName)}<br>${esc(o.customerEmail)}</p></div>
    <div class="box"><h4>Delivery Address</h4><p>${esc(o.address)}</p></div>
    <div class="box"><h4>Source</h4><p>${esc(o.offline ? 'Offline' : 'Online')}${o.source ? ' &middot; ' + esc(ORDER_SOURCE_LABELS[o.source] || o.source) : ''}</p></div>
  </div>
  <table><thead><tr><th>Item</th><th>Qty</th><th>Price</th><th>Total</th></tr></thead><tbody>${rows}</tbody></table>
  <div class="totals">
    <div><span>Subtotal</span><span>Rs. ${o.subtotal.toLocaleString('en-IN')}</span></div>
    <div><span>GST (18%)</span><span>Rs. ${o.tax.toLocaleString('en-IN')}</span></div>
    <div><span>Delivery Charge</span><span>Rs. ${o.delivery}</span></div>
    <div class="grand"><span>Grand Total</span><span>Rs. ${o.grandTotal.toLocaleString('en-IN')}</span></div>
  </div>
  <div class="disclaimer">Mock invoice generated for a college demo / academic project. No real transaction occurred.</div>
</body></html>`;
}

router.get('/api/admin/invoice/:orderId', async (req, res, params) => {
  if (!(await isAdmin(req))) { res.writeHead(401); return res.end('Admin login required.'); }
  const order = await db.getOrderById(params.orderId);
  if (!order) { res.writeHead(404); return res.end('Order not found.'); }
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(renderInvoiceHtml(order));
});

const ADMIN_PAGE_SIZE = 20;

router.get('/api/admin/orders', async (req, res) => {
  if (!(await isAdmin(req))) return sendJson(res, 401, { error: 'Admin login required.' });
  await db.refreshStatuses();

  const parsed = url.parse(req.url, true);
  const from = parsed.query.from ? Number(parsed.query.from) : null;
  const to = parsed.query.to ? Number(parsed.query.to) : null;
  const range = (from != null && to != null && !isNaN(from) && !isNaN(to)) ? { from, to } : null;
  const search = String(parsed.query.search || '').trim();
  const sortKey = String(parsed.query.sortKey || '');
  const sortDir = String(parsed.query.sortDir || '');
  const page = Math.max(1, Number(parsed.query.page) || 1);

  const { orders, total } = await db.getAllOrders(range, {
    search, sortKey, sortDir, limit: ADMIN_PAGE_SIZE, offset: (page - 1) * ADMIN_PAGE_SIZE
  });
  const orderStats = await db.getOrderStats(range);
  const stats = {
    totalOrders: orderStats.totalOrders,
    totalRevenue: orderStats.totalRevenue,
    processingCount: orderStats.processingCount,
    deliveredCount: orderStats.deliveredCount,
    // Within a date range, "customers" means distinct buyers in that
    // window, not the all-time registered count.
    totalCustomers: range ? orderStats.distinctCustomers : await db.countUsers()
  };
  sendJson(res, 200, { orders, stats, page, pageSize: ADMIN_PAGE_SIZE, total });
});

router.get('/api/admin/users', async (req, res) => {
  if (!(await isAdmin(req))) return sendJson(res, 401, { error: 'Admin login required.' });
  const parsed = url.parse(req.url, true);
  const search = String(parsed.query.search || '').trim();
  const sortKey = String(parsed.query.sortKey || '');
  const sortDir = String(parsed.query.sortDir || '');
  const page = Math.max(1, Number(parsed.query.page) || 1);

  const { users, total } = await db.getAllUsersWithStats({
    search, sortKey, sortDir, limit: ADMIN_PAGE_SIZE, offset: (page - 1) * ADMIN_PAGE_SIZE
  });
  const typeCounts = await db.getUserTypeCounts();
  sendJson(res, 200, { users, page, pageSize: ADMIN_PAGE_SIZE, total, typeCounts });
});

router.get('/api/admin/failed-payments', async (req, res) => {
  if (!(await isAdmin(req))) return sendJson(res, 401, { error: 'Admin login required.' });
  const failedPayments = await db.getFailedPayments();
  sendJson(res, 200, { failedPayments });
});

router.post('/api/admin/offline-orders', async (req, res) => {
  if (!(await isAdmin(req))) return sendJson(res, 401, { error: 'Admin login required.' });
  const body = await readJsonBody(req);
  const name = String(body.customerName || '').trim() || 'Walk-in Customer';
  const amount = parseFloat(body.amount);
  const smsText = String(body.smsText || '').trim();
  const note = String(body.note || '').trim() || (smsText ? ('Bank SMS: ' + smsText.slice(0, 80)) : 'Offline Sale');

  if (!amount || amount <= 0) return sendJson(res, 400, { error: 'Please enter a valid amount.' });

  const order = {
    orderId: newOrderId('LM-OFF'), orderDate: formatOrderDate(), createdAt: Date.now(),
    address: 'N/A — Offline / in-store payment',
    items: [{ name: note, qty: 1, price: amount }],
    subtotal: amount, tax: 0, delivery: 0, grandTotal: amount,
    status: 'Delivered', offline: true,
    customerName: name, customerEmail: '—', source: smsText ? 'sms-paste' : 'manual'
  };
  await db.createOrder(order);
  sendJson(res, 200, order);
});

router.get('/api/admin/orders/export.csv', async (req, res) => {
  if (!(await isAdmin(req))) { res.writeHead(401); return res.end('Admin login required.'); }
  const parsed = url.parse(req.url, true);
  const from = parsed.query.from ? Number(parsed.query.from) : null;
  const to = parsed.query.to ? Number(parsed.query.to) : null;
  const range = (from != null && to != null && !isNaN(from) && !isNaN(to)) ? { from, to } : null;
  const { orders } = await db.getAllOrders(range); // no limit - export gets every matching row
  const header = ['Order ID', 'Customer Name', 'Customer Email', 'Date', 'Items', 'Item Count', 'Subtotal', 'GST', 'Delivery', 'Grand Total', 'Source', 'Status', 'Delivery Address'];
  const esc = v => {
    const s = String(v);
    return (s.includes(',') || s.includes('"') || s.includes('\n')) ? '"' + s.replace(/"/g, '""') + '"' : s;
  };
  const rows = orders.map(o => [
    o.orderId, o.customerName, o.customerEmail, o.orderDate,
    o.items.map(i => `${i.name} x${i.qty}`).join(' | '),
    o.items.reduce((s, i) => s + i.qty, 0),
    o.subtotal, o.tax, o.delivery, o.grandTotal,
    o.offline ? 'Offline' : 'Online', o.status, o.address
  ]);
  const csv = [header, ...rows].map(r => r.map(esc).join(',')).join('\n');
  res.writeHead(200, {
    'Content-Type': 'text/csv; charset=utf-8',
    'Content-Disposition': `attachment; filename="leela-mart-orders-${Date.now()}.csv"`
  });
  res.end(csv);
});

// Owner-facing endpoint to fetch the Razorpay webhook secret, in case it's
// still running in query-secret testing mode (no RAZORPAY_WEBHOOK_SECRET set).
router.get('/api/admin/webhook-info', async (req, res) => {
  if (!(await isAdmin(req))) return sendJson(res, 401, { error: 'Admin login required.' });
  sendJson(res, 200, { razorpaySecret: await db.getOrCreateRazorpaySecret() });
});

// ---------------------------------------------------------------------------
// Razorpay webhook: fires on `payment.captured` - turns a real payment into
// an auto-attributed customer order with catalog products matching the paid
// amount.
// ---------------------------------------------------------------------------
router.post('/api/webhook/razorpay-payment', async (req, res) => {
  const raw = await readRawBody(req);
  let body;
  try { body = raw ? JSON.parse(raw) : {}; }
  catch (e) { return sendJson(res, 400, { error: 'Invalid JSON body' }); }

  const RAZORPAY_WEBHOOK_SECRET = process.env.RAZORPAY_WEBHOOK_SECRET;
  if (RAZORPAY_WEBHOOK_SECRET) {
    // Production path: verify the HMAC-SHA256 signature Razorpay sends in
    // the X-Razorpay-Signature header, signed with the secret configured in
    // the Razorpay dashboard's webhook settings.
    const signature = req.headers['x-razorpay-signature'];
    if (!verifyRazorpaySignature(raw, signature, RAZORPAY_WEBHOOK_SECRET)) {
      return sendJson(res, 401, { error: 'Invalid Razorpay signature.' });
    }
  } else {
    // No production secret configured yet - fall back to a shared-secret
    // query param so this can be smoke-tested with curl before Razorpay is
    // wired up for real.
    const parsed = url.parse(req.url, true);
    const razorpaySecret = await db.getOrCreateRazorpaySecret();
    if (parsed.query.secret !== razorpaySecret) {
      return sendJson(res, 401, { error: 'Invalid or missing webhook secret.' });
    }
  }

  const details = extractRazorpayPaymentDetails(body);
  if (body.event && details.event !== 'manual' && body.event !== 'payment.captured') {
    if (body.event === 'payment.failed') {
      const entity = body.payload && body.payload.payment && body.payload.payment.entity;
      await db.recordFailedPayment({
        razorpayPaymentId: entity && entity.id,
        amount: entity && typeof entity.amount === 'number' ? entity.amount / 100 : null,
        name: entity && entity.notes && (entity.notes.name || entity.notes.customer_name),
        email: entity && entity.email,
        reason: entity && (entity.error_description || entity.error_reason)
      });
    }
    return sendJson(res, 200, { ok: true, ignored: true, event: body.event });
  }
  if (!details.amount || details.amount <= 0) {
    return sendJson(res, 400, { error: 'Could not find a valid payment amount.', body });
  }

  const name = details.name || 'Razorpay Customer';
  const user = await findOrCreateAutoUser(name);
  const priced = priceWebhookOrder(details.amount);

  const order = {
    orderId: newOrderId('LM-RP'), orderDate: formatOrderDate(), createdAt: Date.now(),
    address: await getOrAssignAddress(user),
    items: priced.items, subtotal: priced.subtotal, tax: priced.tax, delivery: priced.delivery, grandTotal: priced.grandTotal,
    deliverAt: Date.now() + DELIVERY_WAIT_MS,
    status: 'Processing', offline: false, source: 'razorpay-webhook',
    userEmail: user.email, customerName: user.name, customerEmail: user.email
  };
  await db.createOrder(order);

  // Send this customer a GiftMint bonus gift code for their purchase.
  // Fire-and-forget - agar GiftMint ka server down ho, Leela Mart ka apna
  // checkout fail nahi hona chahiye, isliye try/catch me wrap kiya hai.
  try {
    await fetch('https://firebrick-loris-129124.hostingersite.com/api/partner/bonus-code', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Partner-Key': GIFTMINT_PARTNER_KEY
      },
      body: JSON.stringify({
        partnerOrderRef: order.orderId,
        customerName: order.customerName,
        customerEmail: order.customerEmail,
        orderValue: order.grandTotal
      })
    });
  } catch (e) {
    console.error('GiftMint bonus code request failed:', e.message);
  }

  sendJson(res, 200, {
    ok: true, amount: details.amount, name: user.name, email: user.email,
    orderId: order.orderId, items: priced.items.map(i => `${i.name} x${i.qty}`)
  });
});

// ---------------------------------------------------------------------------
// HTTP server / static file serving
// ---------------------------------------------------------------------------
const PUBLIC_DIR = path.join(__dirname, 'public');
const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json' };

function serveStatic(req, res, pathname) {
  let filePath = pathname === '/' ? '/index.html' : pathname;
  filePath = path.join(PUBLIC_DIR, filePath);
  if (!filePath.startsWith(PUBLIC_DIR)) { res.writeHead(403); return res.end('Forbidden'); }
  fs.readFile(filePath, (err, content) => {
    if (err) {
      // SPA fallback: unknown non-API GET routes serve index.html
      fs.readFile(path.join(PUBLIC_DIR, 'index.html'), (err2, indexContent) => {
        if (err2) { res.writeHead(404); return res.end('Not found'); }
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(indexContent);
      });
      return;
    }
    const ext = path.extname(filePath);
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
    res.end(content);
  });
}

const server = http.createServer(async (req, res) => {
  const parsed = url.parse(req.url, true);
  const pathname = parsed.pathname;

  if (pathname.startsWith('/api/')) {
    const match = router.match(req.method, pathname);
    if (!match) return sendJson(res, 404, { error: 'Not found' });
    try {
      await match.handler(req, res, match.params);
    } catch (e) {
      console.error(e);
      sendJson(res, 500, { error: 'Server error: ' + e.message });
    }
    return;
  }

  if (req.method === 'GET') return serveStatic(req, res, pathname);
  res.writeHead(404); res.end('Not found');
});

async function start() {
  await db.init();

  // Sweep for orders that finished "processing" even with no active requests.
  setInterval(() => { db.refreshStatuses().catch(e => console.error('refreshStatuses failed:', e.message)); }, 15_000);

  server.listen(PORT, async () => {
    console.log(`\nLeela Mart backend running at http://localhost:${PORT}`);
    console.log(`Owner login: ${ADMIN_EMAIL} / ${ADMIN_PASSWORD}`);
    if (process.env.RAZORPAY_WEBHOOK_SECRET) {
      console.log(`Razorpay webhook URL (signature-verified): https://<your-domain>/api/webhook/razorpay-payment`);
    } else {
      const razorpaySecret = await db.getOrCreateRazorpaySecret();
      console.log(`Razorpay webhook secret (testing only, no signature check yet): ${razorpaySecret}`);
      console.log(`Razorpay test webhook URL: https://<your-domain>/api/webhook/razorpay-payment?secret=${razorpaySecret}`);
      console.log(`Set RAZORPAY_WEBHOOK_SECRET env var once Razorpay is wired up for real (enables signature verification).`);
    }
    console.log('');
  });
}

start().catch(e => {
  console.error('Failed to start server:', e);
  process.exit(1);
});
