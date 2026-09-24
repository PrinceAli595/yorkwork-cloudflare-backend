/**
 * Yorkwork backend — Cloudflare Workers version
 * ---------------------------------------------------------------
 * Migrated from the original Node/Express backend. Key differences
 * from that version, and why:
 *
 *  - Database: the old JSON file (data/db.json) is replaced with D1
 *    (Cloudflare's SQL database) — Workers have no local filesystem.
 *  - Image cache: local disk caching is replaced with the Workers
 *    Cache API (`caches.default`), which is edge-native and free.
 *  - Email: Nodemailer/SMTP is replaced with Resend's REST API via
 *    fetch() — Workers cannot open raw TCP sockets, so SMTP libraries
 *    don't work here regardless of provider.
 *  - Sessions: HMAC signing uses the Web Crypto API (SubtleCrypto)
 *    instead of Node's `crypto` module, for full Workers compatibility.
 *  - Stripe: uses Stripe's built-in fetch-based HTTP client, which is
 *    officially supported for edge/Workers runtimes.
 *
 * Deploy: npx wrangler deploy   (after running the D1 migration and
 * setting secrets — see README.md)
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { getCookie, setCookie, deleteCookie } from 'hono/cookie';
import Stripe from 'stripe';

const app = new Hono();

/* ------------------------------------------------------------------ */
/* CORS                                                                */
/* ------------------------------------------------------------------ */

app.use('*', async (c, next) => {
  const allowed = (c.env.ALLOWED_ORIGIN || '*').split(',').map((s) => s.trim());
  return cors({ origin: allowed.length === 1 ? allowed[0] : allowed, credentials: true })(c, next);
});

/* ------------------------------------------------------------------ */
/* Rate limiting — simple in-memory best-effort.                      */
/* Note: Workers isolates aren't guaranteed to persist between         */
/* requests, so this is a soft limit, not a hard guarantee. Cloudflare */
/* itself also provides platform-level abuse protection at the edge.  */
/* ------------------------------------------------------------------ */

const rateBuckets = new Map();
function rateLimit(key, windowMs, max) {
  const now = Date.now();
  const bucket = rateBuckets.get(key) || [];
  const recent = bucket.filter((t) => now - t < windowMs);
  if (recent.length >= max) return false;
  recent.push(now);
  rateBuckets.set(key, recent);
  return true;
}

function rateLimitMiddleware(windowMs, max) {
  return async (c, next) => {
    const ip = c.req.header('cf-connecting-ip') || 'unknown';
    const key = `${c.req.path}:${ip}`;
    if (!rateLimit(key, windowMs, max)) {
      return c.json({ ok: false, error: 'Too many requests. Please try again shortly.' }, 429);
    }
    await next();
  };
}

/* ------------------------------------------------------------------ */
/* Admin auth — HMAC-signed cookie via Web Crypto, no session store   */
/* ------------------------------------------------------------------ */

const SESSION_MAX_AGE_MS = 12 * 60 * 60 * 1000; // 12 hours

async function hmacSign(value, secret) {
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(value));
  const hex = [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, '0')).join('');
  return `${value}.${hex}`;
}

async function hmacVerify(signed, secret) {
  if (!signed || typeof signed !== 'string') return null;
  const idx = signed.lastIndexOf('.');
  if (idx === -1) return null;
  const value = signed.slice(0, idx);
  const expected = await hmacSign(value, secret);
  if (expected.length !== signed.length) return null;
  // Constant-time-ish comparison — good enough at this string length for a session cookie.
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ signed.charCodeAt(i);
  return diff === 0 ? value : null;
}

async function requireAdmin(c, next) {
  const token = getCookie(c, 'yw_admin');
  const value = await hmacVerify(token, c.env.SESSION_SECRET);
  if (!value) return c.json({ ok: false, error: 'Not authenticated.' }, 401);
  const [, expiresAt] = value.split('|');
  if (Date.now() > Number(expiresAt)) return c.json({ ok: false, error: 'Session expired.' }, 401);
  await next();
}

/* ------------------------------------------------------------------ */
/* D1 helpers                                                          */
/* ------------------------------------------------------------------ */

function newId() {
  return crypto.randomUUID();
}

/* ------------------------------------------------------------------ */
/* PUBLIC: health check                                                */
/* ------------------------------------------------------------------ */

app.get('/api/health', (c) => c.json({ ok: true, time: new Date().toISOString() }));

/* ------------------------------------------------------------------ */
/* PUBLIC: checkout (Stripe)                                           */
/* ------------------------------------------------------------------ */
// Server-side price list — mirrors index.html's PRODUCTS array exactly,
// including the "hidden" variant entries. Prices are always looked up
// here, never trusted from the browser.

const PRODUCT_CATALOG = [
  {id:1,title:'New Levelling Survey Aluminium Staff, 5m 5-Section',price:28.88},
  {id:2,title:'Aluminium Tripod for Dumpy/Laser Level',price:39.35},
  {id:3,title:'Heavy Duty Wooden Survey Tripod Stand',price:94.89},
  {id:4,title:'Water Proof Flag Markers / Survey Flags',price:8.89},
  {id:5,title:'Bracket Mounting Clamp for Laser Detector, PLS',price:22.89},
  {id:6,title:'Laser Detector / Receiver for Rotating Laser Level',price:41.89},
  {id:7,title:'Cone for Slump Testing Concrete Consistency',price:18.88},
  {id:8,title:'Retro Survey Targets for Site Survey & Control Stations',price:7.89},
  {id:9,title:'Plastic Barrier Mesh Safety Fence Netting',price:12.89},
  {id:10,title:'Scoop for Slump Testing or Cube Making',price:11.89},
  {id:11,title:'Warehouse Trolley 300kg Folding Platform Cart',price:42.89},
  {id:12,title:'Rotating Laser Level, UK Calibration + Detector (Vevor)',price:310.89},
  {id:13,title:'Magnetic Bracket for 12-Line 3D Laser Level',price:12.96},
  {id:14,title:'Concrete Test Cube Mould, 150x150mm, Cast Iron',price:52.88},
  {id:15,title:'New Prism for Robotic Total Station EDM',price:39.89},
  {id:16,title:'New 360° Mini Prism for Robotic Total Station',price:138.89},
  {id:17,title:'Replacement Battery for GEB212 (EDM), VAT Invoice',price:53.99},
  {id:18,title:'Pack of 5x Push Buttons for Aluminium Levelling Staff',price:10.89},
  {id:19,title:'Bipod for Surveying Staffs, Freestanding',price:39.39},
  {id:20,title:'Prism Detail Pole, Telescopic, 600mm, VAT Invoice',price:48.89},
  {id:21,title:'10x Pack Woven Geotextile Weed Control Membrane',price:32.79},
  {id:22,title:'10x Steel Metal Barrier Fencing Fence Pins, 1200mm',price:17.89},
  {id:23,title:'Fiberglass Electric Cable Rodder Fish Tape',price:39.39},
  {id:24,title:'Charger Only for 3D Laser Level Battery, 12-Line',price:14.59},
  {id:25,title:'Cross Lines 360° 3D Laser Level, 12 Green Line',price:56.89},
  {id:26,title:'Brown Tape Parcel Packing Tape 48mm x 66m',price:39.88},
  {id:27,title:'Clear Parcel Tape Packing Sellotape 48mm x 66m',price:39.88},
  {id:28,title:'Electric Fence Energiser, 12V, 1.0J, 12-Mile',price:41.89},
  {id:29,title:'RC Fishing Bait Boat, 2 Motors, Wireless Control',price:85.85},
  {id:30,title:'7.4V Battery 5200mAh for RC Bait Boat',price:21.89},
  {id:31,title:'Remote Controller for RC Fishing Bait Boat',price:18.89},
  {id:32,title:'Carry Bag for Bait Boat',price:18.89},
  {id:33,title:'2x Hinges with Screws & Nuts, for Hopper',price:14.89},
  {id:34,title:'2x Weed Protection (Weed Guard) Only',price:12.29},
  {id:35,title:'Replacement Aerial / Antenna',price:15.89},
  {id:36,title:'USB Charging Cable for 5200mAh Battery',price:18.89},
  {id:37,title:'Water Leak Sensor, Wireless (Seed Alarm)',price:14.89},
  {id:38,title:'Emergency SOS Button, Wireless (Seed Alarm)',price:14.89},
  {id:39,title:'Door Sensor, Wireless Magnetic (Seed Alarm)',price:14.27},
  {id:40,title:'Smoke Alarm Sensor, Wireless (Seed Alarm)',price:15.89},
  {id:41,title:'New Swimming Pool, Inflatable Jumbo Family Size',price:36.89},
  {id:42,title:'Folding Picnic Table, Portable, with Carry Handle',price:25.29},
  {id:43,title:'Folding Wall-Mounted Shower Stool',price:28.89},
  {id:44,title:'Petrainer Remote Pet Training Collar, LCD Display',price:22.89},
  {id:45,title:'10x Spare Brass Jet for NPG Burner',price:19.89},
  {id:46,title:'10x Spare Brass Jet for LPG Burner Replacement Tip',price:23.89},
  {id:47,title:'Green Beam Laser Detector / Receiver for Rotating Laser Level',price:55.89},
  {id:48,title:'Brand New Hopper for RC Bait Boat',price:18.89},
  {id:49,title:'Dog Treat Camera Dispenser, WiFi Remote Pet Camera',price:43.99},
  {id:50,title:'Battery 5600mAh Replacement for GEB221',price:49.89},
  {id:51,title:'Fence Energiser, Mains Powered Electric, 12 Miles',price:41.89},
  {id:52,title:'Solar CCTV with SIM Card, Night Vision and App',price:88.88},
  {id:53,title:'20x Double-Sided Sticky Tape, 20mm White',price:18.89},
  {id:401,title:'Water Proof Flag Markers / Survey Flags — 30 pack',price:8.89},
  {id:402,title:'Water Proof Flag Markers / Survey Flags — 50 pack',price:15.89},
  {id:403,title:'Water Proof Flag Markers / Survey Flags — 100 pack',price:22.89},
  {id:404,title:'Water Proof Flag Markers / Survey Flags — 200 pack',price:43.89},
  {id:405,title:'Water Proof Flag Markers / Survey Flags — 300 pack',price:66.89},
  {id:801,title:'Retro Survey Targets — 20×20mm, 20 pack',price:7.89},
  {id:802,title:'Retro Survey Targets — 20×20mm, 50 pack',price:13.89},
  {id:803,title:'Retro Survey Targets — 20×20mm, 100 pack',price:16.89},
  {id:804,title:'Retro Survey Targets — 20×20mm, 200 pack',price:31.89},
  {id:805,title:'Retro Survey Targets — 20×20mm, 30 pack',price:11.79},
  {id:806,title:'Retro Survey Targets — 30×30mm, 20 pack',price:8.89},
  {id:807,title:'Retro Survey Targets — 30×30mm, 30 pack',price:12.89},
  {id:808,title:'Retro Survey Targets — 30×30mm, 50 pack',price:17.89},
  {id:809,title:'Retro Survey Targets — 30×30mm, 100 pack',price:29.89},
  {id:810,title:'Retro Survey Targets — 50×50mm, 20 pack',price:13.89},
  {id:811,title:'Retro Survey Targets — 50×50mm, 30 pack',price:18.89},
  {id:812,title:'Retro Survey Targets — 50×50mm, 50 pack',price:32.89},
  {id:813,title:'Retro Survey Targets — 100×100mm Yellow, 10 pack',price:32.89},
  {id:814,title:'Retro Survey Targets — 100×100mm Yellow, 20 pack',price:63.89},
  {id:815,title:'Retro Survey Targets — 100×100mm Yellow Magnetic, 10 pack',price:36.89},
  {id:816,title:'Retro Survey Targets — 100×100mm Yellow Magnetic, 20 pack',price:71.89},
  {id:901,title:'Plastic Barrier Mesh — Orange mesh netting only',price:21.89},
  {id:902,title:'Plastic Barrier Mesh — Orange mesh + 10 pins',price:39.39},
  {id:903,title:'Plastic Barrier Mesh — 5 Metal Pins',price:12.89},
  {id:904,title:'Plastic Barrier Mesh — 10 Metal Pins',price:18.89},
  {id:1501,title:'Robotic Total Station Prism — GRZ4 Big Prism',price:157.89},
  {id:1502,title:'Robotic Total Station Prism — Mini Prism with metal poles',price:129.89},
  {id:1503,title:'Robotic Total Station Prism — Mini Pogo',price:39.89},
  {id:2301,title:'Fiberglass Cable Rodder — 80m',price:39.39},
  {id:2302,title:'Fiberglass Cable Rodder — 100m',price:49.49},
  {id:2303,title:'Fiberglass Cable Rodder — 120m',price:79.79},
  {id:2601,title:'Brown Tape Parcel Packing Tape — 24 rolls',price:16.59},
  {id:2602,title:'Brown Tape Parcel Packing Tape — 36 rolls',price:26.89},
  {id:2603,title:'Brown Tape Parcel Packing Tape — 72 rolls',price:39.88},
  {id:2604,title:'Brown Tape Parcel Packing Tape — 144 rolls',price:75.75},
  {id:2701,title:'Clear Parcel Tape — 24 rolls',price:16.59},
  {id:2702,title:'Clear Parcel Tape — 36 rolls',price:26.89},
  {id:2703,title:'Clear Parcel Tape — 72 rolls',price:39.88},
  {id:2704,title:'Clear Parcel Tape — 144 rolls',price:75.75},
  {id:3301,title:'Hopper Hinges — With Screws & Nuts',price:14.89},
  {id:3302,title:'Hopper Hinges — Without Screws',price:11.89},
];

function findProduct(id) {
  return PRODUCT_CATALOG.find((p) => p.id === Number(id));
}

app.post('/api/create-checkout-session', rateLimitMiddleware(60 * 1000, 15), async (c) => {
  const stripeKey = c.env.STRIPE_SECRET_KEY;
  if (!stripeKey) return c.json({ ok: false, error: 'Payments are not configured yet.' }, 503);
  const stripe = new Stripe(stripeKey, { httpClient: Stripe.createFetchHttpClient() });

  const body = await c.req.json().catch(() => ({}));
  const { items, email, delivery } = body;
  if (!Array.isArray(items) || items.length === 0) {
    return c.json({ ok: false, error: 'Basket is empty.' }, 400);
  }

  const lineItems = [];
  for (const item of items) {
    const product = findProduct(item.id);
    const qty = Math.max(1, Math.min(999, Number(item.qty) || 1));
    if (!product) continue;
    // Non-price choices (colour, type...) — descriptive only; the price always comes from the catalog above
    const opts = typeof item.options === 'string' ? item.options.replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, 150) : '';
    lineItems.push({
      price_data: {
        currency: 'gbp',
        product_data: { name: (product.title + (opts ? ` — ${opts}` : '')).slice(0, 250) },
        unit_amount: Math.round(product.price * 100),
      },
      quantity: qty,
    });
  }
  if (lineItems.length === 0) return c.json({ ok: false, error: 'No valid items in basket.' }, 400);

  // Delivery details from the checkout form, attached to the payment so each order shows where to send it
  const clean = (v, n = 200) => (typeof v === 'string' ? v.replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, n) : '');
  const dl = delivery && typeof delivery === 'object' ? delivery : {};
  const ship = {
    name: clean(dl.name, 100), phone: clean(dl.phone, 40),
    line1: clean(dl.address1), line2: clean(dl.address2), city: clean(dl.city, 100), postcode: clean(dl.postcode, 20).toUpperCase(),
  };
  const hasAddress = ship.name && ship.line1 && ship.city && ship.postcode;

  try {
    const session = await stripe.checkout.sessions.create({
      mode: 'payment',
      payment_method_types: ['card'],
      line_items: lineItems,
      customer_email: email && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ? email : undefined,
      ...(hasAddress ? {
        payment_intent_data: {
          shipping: {
            name: ship.name, phone: ship.phone || undefined,
            address: { line1: ship.line1, line2: ship.line2 || undefined, city: ship.city, postal_code: ship.postcode, country: 'GB' },
          },
        },
        metadata: {
          delivery_name: ship.name, delivery_phone: ship.phone,
          delivery_address: [ship.line1, ship.line2, ship.city, ship.postcode].filter(Boolean).join(', ').slice(0, 490),
        },
      } : {}),
      success_url: `${c.env.FRONTEND_URL}/#/order-confirmed?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${c.env.FRONTEND_URL}/#/checkout`,
    });
    return c.json({ ok: true, url: session.url });
  } catch (err) {
    console.error('[STRIPE] Failed to create checkout session:', err.message);
    return c.json({ ok: false, error: 'Could not start checkout. Please try again.' }, 500);
  }
});

app.get('/api/checkout-session/:id', rateLimitMiddleware(60 * 1000, 30), async (c) => {
  const stripeKey = c.env.STRIPE_SECRET_KEY;
  if (!stripeKey) return c.json({ ok: false, error: 'Payments are not configured yet.' }, 503);
  const stripe = new Stripe(stripeKey, { httpClient: Stripe.createFetchHttpClient() });

  try {
    const session = await stripe.checkout.sessions.retrieve(c.req.param('id'), { expand: ['line_items'] });
    const paid = session.payment_status === 'paid';

    if (paid) {
      const existing = await c.env.DB.prepare('SELECT session_id FROM orders WHERE session_id = ?')
        .bind(session.id).first();
      if (!existing) {
        const itemsJson = JSON.stringify((session.line_items?.data || []).map((li) => ({
          name: li.description, qty: li.quantity, amount: (li.amount_total || 0) / 100,
        })));
        const md = session.metadata || {};
        const delivery = [md.delivery_name, md.delivery_phone, md.delivery_address].filter(Boolean).join(' · ');
        await c.env.DB.prepare(
          'INSERT INTO orders (session_id, email, amount, items_json, created_at, delivery) VALUES (?, ?, ?, ?, ?, ?)'
        ).bind(
          session.id, session.customer_details?.email || '', (session.amount_total || 0) / 100,
          itemsJson, new Date().toISOString(), delivery
        ).run();
      }
    }

    return c.json({
      ok: true, paid,
      amount: (session.amount_total || 0) / 100,
      email: session.customer_details?.email || '',
    });
  } catch (err) {
    console.error('[STRIPE] Failed to retrieve checkout session:', err.message);
    return c.json({ ok: false, error: 'Order not found.' }, 404);
  }
});

/* ------------------------------------------------------------------ */
/* PUBLIC: product images — proxied from Google Drive, cached at the   */
/* edge via the Workers Cache API instead of local disk.               */
/* ------------------------------------------------------------------ */

const DRIVE_IMAGE_IDS = {
  1: '1j1L0SPiJ8rm6eFj6_zhObVT_nLbeJiGB',
  2: '1Kc-SIKwQLBmAn5dI6xGyk1nogQqB2_5m',
  3: '1yk2XsFDVt29x6KWJH0mQz2xP4lxkFVD3',
  4: '1tya-m28gMuZjiLTqfgcfFxj4pWTCw5Re',
  5: '1dtSlJrrGKqRDLQJoRYpb1VeYssFqor--',
  6: '1M73iYME8hCNb_oApjjxZqVmP4PAPuaD9',
  7: '1HZipEc5e20a5oTUimeLdcJhcNfdOIcDE',
  8: '1Xysyo5pItygsvMrx0KlDBpS1T2qxfWMw',
  9: '13xnJEmvvrMgfvfbro3AYqo4sfixr6vS3',
  10: '1LPNjWvmtQZq7aj2Qt2ZBZoZWNPDg7apQ',
  11: '1SY-VpU0Xbmt5Gi2xUD9S2YfLX4ESahSd',
  12: '1mHBsdIK82QdV-b4qiFWfFSxOzh_9Q_b5',
  13: '1AXGApdCi-NU0oxBktKH4-v6nhdkdNTfF',
  14: '19JZptPFckQ5qPNeBKgvrpczTT417NgFi',
  15: '1QSPgVS-U1nAN7wvvZpZ4kwIDd-8jQnex',
  16: '1v-cxZKG7QL-DLcYA6wTch3B8pTD5dmGE',
  17: '1tTMDHUk08d9p3WnTtXWvUsDAKhOJmI8j',
  18: '1ALgmRhpWQEVdNe0COjj5VmH5XlATWAKh',
  19: '1kGtfD8y6lmReeMx_eIoZN0D7add5SSuE',
  20: '1YUGLhBZU-2X8cCx6ieStAl38SOtgd1x6',
  21: '1Uq2ryK77OQBP5Xsl4f1dGKcd51JvocCB',
  22: '1SAQH8_VNO4XeHTq6eubxMbWQaOl35S7s',
  23: '1XdUOgoBysuSQHIuASNR2PQwFJifsBhRk',
  24: '1EZVqphTAMbigncXvXdIpzl_xUVvYmYwl',
  25: '1VqSqicOR-hgVWI142vKT1ImeqT067gTM',
  26: '1Bbcww_jH11wo8FLvC_fikPE5jmNkWmBn',
  27: '1nJbQG_CdXox3FTrkymbFAVuBZBC1GYce',
  28: '1NtWd7QUpHIWMz3EX3UU263FxpwWFSy8h',
  29: '1MnpshAIdUplkY2Nh5laMdXQmbUf3IuPJ',
  30: '1OsZ_BfZdq1t-KUv6xGKUqrIelgLQT2w1',
  31: '1FlVi_DnFHloiFOalRIivWXpmC34-Vqhs',
  32: '1WThK4WqJAgxwEvpidcq3etV2DR0JrE6L',
  33: '1C--QPetAfxOKNUf9DVQzRbMP2Hwz38Sk',
  34: '1FwO9Gref_QmR-9NUmb7GpctRRTkb8dEp',
  35: '1Y6VgsWtNZeVSf_T0Iu14NTClnZWwWJFj',
  36: '1qBcGM8qPnpBoavvtp_iXZaSSxVESnwZL',
  37: '1HNEjJ7gOZl3qC26wNLlPbw_k3pmrUdtN',
  38: '1TdLazxok1mS7cEAuku25M3ZDW9rJSRUb',
  39: '1hmDfsoz7oBLnRyXgSph1O1-oBAB4F1kJ',
  40: '1SU3svitdt4GkEz9WjP3awsA7etjfyXGO',
  41: '1yFapYgZ5Z52kcP0Gowr88b1GT83XsEjl',
  42: '1SrJcPsZpmnnXCwEYO-_2Qt2eCZlyV1Nc',
  43: '1EszqzINRlYd_zvvNcXm4200TKymWmrnP',
  44: '1a7aUe0zVQpcsa6TbbE4R1lp1nWmKrQIF',
  45: '1wD5VP4Vw5HXhAZ_sFcWVfIgHQ6jcN3_U',
  46: '1GF9SbaQoAV-PTV1NuYyAqsaU4RGmmrSP',
  47: '1liMx_fl5Pe_LluP6i0-r0G5encXM6byS',
  48: '1QObOTCjPWciTAHrqgMCoKTIlDKm-BhNT',
  49: '1Z8dl5HPPQJpNUgvCOBgQip56RnEL2GHq',
  50: '1t1lVwg9W3vBsqQ1GZZ7pXHDWN3nTNX9Q',
  51: '1XA69YzP3oLCAKoUbYRGQv8XX6eh3RLvS',
  52: '195LpreZ4DDshciXSQ5sRjRHffnG-m7lT',
  53: '1lubbHNX8qut-pLDeTUwtF1PbKcAd_lGp',
  // Quantity/length variants that don't visually differ from their base product —
  // reuse the same photo rather than needing a separate one
  401: '1tya-m28gMuZjiLTqfgcfFxj4pWTCw5Re',
  402: '1tya-m28gMuZjiLTqfgcfFxj4pWTCw5Re',
  403: '1tya-m28gMuZjiLTqfgcfFxj4pWTCw5Re',
  404: '1tya-m28gMuZjiLTqfgcfFxj4pWTCw5Re',
  405: '1tya-m28gMuZjiLTqfgcfFxj4pWTCw5Re',
  801: '1Xysyo5pItygsvMrx0KlDBpS1T2qxfWMw',
  802: '1Xysyo5pItygsvMrx0KlDBpS1T2qxfWMw',
  803: '1Xysyo5pItygsvMrx0KlDBpS1T2qxfWMw',
  804: '1Xysyo5pItygsvMrx0KlDBpS1T2qxfWMw',
  805: '1Xysyo5pItygsvMrx0KlDBpS1T2qxfWMw',
  806: '1Xysyo5pItygsvMrx0KlDBpS1T2qxfWMw',
  807: '1Xysyo5pItygsvMrx0KlDBpS1T2qxfWMw',
  808: '1Xysyo5pItygsvMrx0KlDBpS1T2qxfWMw',
  809: '1Xysyo5pItygsvMrx0KlDBpS1T2qxfWMw',
  810: '1Xysyo5pItygsvMrx0KlDBpS1T2qxfWMw',
  811: '1Xysyo5pItygsvMrx0KlDBpS1T2qxfWMw',
  812: '1Xysyo5pItygsvMrx0KlDBpS1T2qxfWMw',
  813: '1Xysyo5pItygsvMrx0KlDBpS1T2qxfWMw',
  814: '1Xysyo5pItygsvMrx0KlDBpS1T2qxfWMw',
  815: '1Xysyo5pItygsvMrx0KlDBpS1T2qxfWMw',
  816: '1Xysyo5pItygsvMrx0KlDBpS1T2qxfWMw',
  2301: '1XdUOgoBysuSQHIuASNR2PQwFJifsBhRk',
  2302: '1XdUOgoBysuSQHIuASNR2PQwFJifsBhRk',
  2303: '1XdUOgoBysuSQHIuASNR2PQwFJifsBhRk',
  2601: '1Bbcww_jH11wo8FLvC_fikPE5jmNkWmBn',
  2602: '1Bbcww_jH11wo8FLvC_fikPE5jmNkWmBn',
  2603: '1Bbcww_jH11wo8FLvC_fikPE5jmNkWmBn',
  2604: '1Bbcww_jH11wo8FLvC_fikPE5jmNkWmBn',
  2701: '1nJbQG_CdXox3FTrkymbFAVuBZBC1GYce',
  2702: '1nJbQG_CdXox3FTrkymbFAVuBZBC1GYce',
  2703: '1nJbQG_CdXox3FTrkymbFAVuBZBC1GYce',
  2704: '1nJbQG_CdXox3FTrkymbFAVuBZBC1GYce',
  3301: '1C--QPetAfxOKNUf9DVQzRbMP2Hwz38Sk', // Hopper Hinges: with screws (same as base id 33)
  3302: '1OZNJMFj9GEFhfdVl6d8izCo2NbhdIsg5', // Hopper Hinges: without screws
  // Priced-variant entries — same Drive folder, keyed by the variant's own id
  901: '13xnJEmvvrMgfvfbro3AYqo4sfixr6vS3', // Barrier Mesh: orange mesh only (same photo as base id 9)
  902: '1Vr6wajGCoFKPVx4yhq_pQ17FKc1YSiCI', // Barrier Mesh: orange mesh + 10 pins
  903: '1ky3DrW8taVcolovAQ3pp5vO5OmvWJIa6', // Barrier Mesh: 5 Metal Pins
  904: '1ky3DrW8taVcolovAQ3pp5vO5OmvWJIa6', // Barrier Mesh: 10 Metal Pins (same photo as 5 Metal Pins)
  1501: '1JIrkbbhQ4H1UV9xdTcQMacnAJBiCx3Yh', // Prism: GRZ4 Big Prism
  1502: '1ZZDdPm7b0WSEOEMFl0DmKBSYSLiUheUt', // Prism: Mini Prism with metal poles
  1503: '1s1rd_5I9gFPRI5TZS_nZaUoXyv_9jo83', // Prism: Mini Pogo (own photo, from eBay listing)
  1504: '1s1rd_5I9gFPRI5TZS_nZaUoXyv_9jo83', // Prism: Mini Pogo (fresh cache key for the option photo)
  4001: '1SSRnVlebOkLuozS6ximsNz7nwjy202JM', // Flag colour: Red
  4002: '1omv7aGhOUwvpXrT2-f9QlOt3COKJ60Ao', // Flag colour: Blue
  4003: '1p2Tpm4SHqBc8AfiCyCmQ2f6kSJwZfHsB', // Flag colour: Pink
  4004: '1fZmpu_hDSFZoImaRJZNva4FUbJnFxG-A', // Flag colour: Orange
  8005: '1W-j1b6kR4TYUr9PljMSbyNj1DlrPBeB5', // Target type: Silver
  8004: '16sF-P3ZvfkEYck6YV10MzM9dGkOncrKh', // Target type: Red
  8003: '1CGT80Xitj-UQzUD5kDcP6Jy7kXEINmTj', // Target type: Orange w/ Triangles
  8002: '1suzN03yOjCSUOU-PPwgcvxP5Yhg2reYg', // Target type: Orange
  8001: '1Nt_aM1asUcliQI5esy-wJcB-Dgpk5g9o', // Target type: Blue
  8006: '1cLed4jh5Bajt6GZBmqcWm3iwr01wUHEj', // Target type: Yellow Magnetic
  8007: '1Z4VuRsbmFIELLTjD0cd694pSIZKNfXT1', // Target type: Silver w/ Triangles
};

app.get('/images/:id{[0-9]+\\.jpg}', async (c) => {
  const idParam = c.req.param('id'); // e.g. "901.jpg"
  const id = parseInt(idParam, 10);
  const driveId = DRIVE_IMAGE_IDS[id];
  if (!driveId) return c.notFound();

  const cacheKey = new Request(c.req.url, c.req.raw);
  const cache = caches.default;
  const cached = await cache.match(cacheKey);
  if (cached) return cached;

  try {
    const driveUrl = `https://drive.google.com/uc?export=download&id=${driveId}`;
    const driveRes = await fetch(driveUrl, { redirect: 'follow' });
    if (!driveRes.ok) throw new Error(`Drive returned ${driveRes.status}`);
    const contentType = driveRes.headers.get('content-type') || '';
    if (!contentType.startsWith('image/')) {
      throw new Error('Drive did not return an image — check sharing settings.');
    }
    const buffer = await driveRes.arrayBuffer();
    const response = new Response(buffer, {
      headers: { 'Content-Type': contentType, 'Cache-Control': 'public, max-age=2592000' },
    });
    c.executionCtx.waitUntil(cache.put(cacheKey, response.clone()));
    return response;
  } catch (err) {
    console.error(`[IMAGES] Failed to fetch image ${id} from Drive:`, err.message);
    return c.text('Could not fetch image.', 502);
  }
});

/* ------------------------------------------------------------------ */
/* PUBLIC: contact form (via Resend REST API, not SMTP)                */
/* ------------------------------------------------------------------ */

app.post('/api/contact', rateLimitMiddleware(60 * 1000, 5), async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const { name, email, phone, subject, message } = body;
  if (!name || !message) return c.json({ ok: false, error: 'Name and message are required.' }, 400);

  const id = newId();
  const createdAt = new Date().toISOString();

  await c.env.DB.prepare(
    'INSERT INTO contacts (id, name, email, phone, subject, message, read, email_sent, created_at) VALUES (?, ?, ?, ?, ?, ?, 0, 0, ?)'
  ).bind(id, name, email || '', phone || '', subject || '', message, createdAt).run();

  // Send via Resend's REST API, to every configured forwarding address.
  let emailSent = false;
  const resendKey = c.env.RESEND_API_KEY;
  const forwardRow = await c.env.DB.prepare("SELECT value FROM settings WHERE key = 'forwardEmails'").first();
  const forwardEmails = forwardRow ? JSON.parse(forwardRow.value) : [];

  if (resendKey && forwardEmails.length > 0) {
    try {
      const res = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${resendKey}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          from: c.env.SMTP_FROM || 'Yorkwork <onboarding@resend.dev>',
          to: forwardEmails,
          subject: `[Yorkwork] New enquiry: ${subject || 'General enquiry'}`,
          html: `<p>New contact form submission from the Yorkwork website.</p>
                 <p><b>Name:</b> ${name}<br><b>Email:</b> ${email || '—'}<br><b>Phone:</b> ${phone || '—'}</p>
                 <p><b>Message:</b><br>${message.replace(/\n/g, '<br>')}</p>`,
        }),
      });
      emailSent = res.ok;
      if (!res.ok) console.error('[RESEND] Failed to send:', await res.text());
    } catch (err) {
      console.error('[RESEND] Error sending email:', err.message);
    }
  }

  if (emailSent) {
    await c.env.DB.prepare('UPDATE contacts SET email_sent = 1 WHERE id = ?').bind(id).run();
  }

  return c.json({ ok: true, sent: emailSent });
});

/* ------------------------------------------------------------------ */
/* PUBLIC: pageview tracking                                           */
/* ------------------------------------------------------------------ */

app.post('/api/track', rateLimitMiddleware(10 * 1000, 20), async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const { path, referrer, utmSource, utmMedium, sessionId } = body;
  if (!path) return c.body(null, 204);

  await c.env.DB.prepare(
    'INSERT INTO pageviews (id, path, referrer, utm_source, utm_medium, session_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).bind(newId(), path, referrer || '', utmSource || '', utmMedium || '', sessionId || '', new Date().toISOString()).run();

  return c.body(null, 204);
});

/* ------------------------------------------------------------------ */
/* ADMIN: auth                                                         */
/* ------------------------------------------------------------------ */

app.post('/api/admin/login', rateLimitMiddleware(60 * 1000, 10), async (c) => {
  const body = await c.req.json().catch(() => ({}));
  if (body.password !== c.env.ADMIN_PASSWORD) {
    return c.json({ ok: false, error: 'Incorrect password.' }, 401);
  }
  const expiresAt = Date.now() + SESSION_MAX_AGE_MS;
  const token = await hmacSign(`admin|${expiresAt}`, c.env.SESSION_SECRET);
  setCookie(c, 'yw_admin', token, {
    httpOnly: true, secure: true, sameSite: 'Strict', maxAge: SESSION_MAX_AGE_MS / 1000, path: '/',
  });
  return c.json({ ok: true });
});

app.post('/api/admin/logout', (c) => {
  deleteCookie(c, 'yw_admin', { path: '/' });
  return c.json({ ok: true });
});

app.get('/api/admin/me', requireAdmin, (c) => c.json({ ok: true }));

/* ------------------------------------------------------------------ */
/* ADMIN: stats                                                        */
/* ------------------------------------------------------------------ */

app.get('/api/admin/stats', requireAdmin, async (c) => {
  const days = Math.min(90, Math.max(1, Number(c.req.query('days')) || 30));
  const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();

  const recent = await c.env.DB.prepare(
    'SELECT path, referrer, utm_source, utm_medium, session_id, created_at FROM pageviews WHERE created_at >= ?'
  ).bind(since).all();
  const rows = recent.results || [];

  const byDay = {}, byPath = {}, byReferrer = {}, bySource = {};
  const sessions = new Set();
  for (const v of rows) {
    const day = v.created_at.slice(0, 10);
    byDay[day] = (byDay[day] || 0) + 1;
    byPath[v.path] = (byPath[v.path] || 0) + 1;
    if (v.session_id) sessions.add(v.session_id);
    let refKey = 'Direct / unknown';
    if (v.utm_source) {
      refKey = v.utm_source + (v.utm_medium ? ` (${v.utm_medium})` : '');
      bySource[refKey] = (bySource[refKey] || 0) + 1;
    } else if (v.referrer) {
      try { refKey = new URL(v.referrer).hostname.replace(/^www\./, ''); }
      catch { refKey = v.referrer.slice(0, 60); }
    }
    byReferrer[refKey] = (byReferrer[refKey] || 0) + 1;
  }

  const top = (obj, n = 10) => Object.entries(obj).sort((a, b) => b[1] - a[1]).slice(0, n).map(([key, count]) => ({ key, count }));

  const unreadRow = await c.env.DB.prepare('SELECT COUNT(*) as n FROM contacts WHERE read = 0').first();
  const totalContactsRow = await c.env.DB.prepare('SELECT COUNT(*) as n FROM contacts').first();
  const orderStats = await c.env.DB.prepare('SELECT COUNT(*) as n, COALESCE(SUM(amount),0) as total FROM orders').first();

  return c.json({
    ok: true,
    rangeDays: days,
    totalPageviews: rows.length,
    uniqueSessions: sessions.size,
    unreadContacts: unreadRow?.n || 0,
    totalContacts: totalContactsRow?.n || 0,
    totalOrders: orderStats?.n || 0,
    totalRevenue: orderStats?.total || 0,
    visitsPerDay: Object.entries(byDay).sort((a, b) => (a[0] < b[0] ? -1 : 1)),
    topPages: top(byPath),
    topReferrers: top(byReferrer),
    topCampaignSources: top(bySource),
  });
});

/* ------------------------------------------------------------------ */
/* ADMIN: contacts                                                     */
/* ------------------------------------------------------------------ */

app.get('/api/admin/contacts', requireAdmin, async (c) => {
  const rows = await c.env.DB.prepare('SELECT * FROM contacts ORDER BY created_at DESC').all();
  const contacts = (rows.results || []).map((r) => ({
    id: r.id, name: r.name, email: r.email, phone: r.phone, subject: r.subject,
    message: r.message, read: !!r.read, emailSent: !!r.email_sent, createdAt: r.created_at,
  }));
  return c.json({ ok: true, contacts });
});

app.post('/api/admin/contacts/:id/read', requireAdmin, async (c) => {
  await c.env.DB.prepare('UPDATE contacts SET read = 1 WHERE id = ?').bind(c.req.param('id')).run();
  return c.json({ ok: true });
});

app.delete('/api/admin/contacts/:id', requireAdmin, async (c) => {
  const before = await c.env.DB.prepare('SELECT id FROM contacts WHERE id = ?').bind(c.req.param('id')).first();
  await c.env.DB.prepare('DELETE FROM contacts WHERE id = ?').bind(c.req.param('id')).run();
  return c.json({ ok: true, deleted: !!before });
});

/* ------------------------------------------------------------------ */
/* ADMIN: orders                                                       */
/* ------------------------------------------------------------------ */

app.get('/api/admin/orders', requireAdmin, async (c) => {
  const rows = await c.env.DB.prepare('SELECT * FROM orders ORDER BY created_at DESC').all();
  const orders = (rows.results || []).map((r) => ({
    sessionId: r.session_id, email: r.email, amount: r.amount,
    items: JSON.parse(r.items_json), createdAt: r.created_at, delivery: r.delivery || '',
  }));
  const totalRevenue = orders.reduce((sum, o) => sum + o.amount, 0);
  return c.json({ ok: true, orders, totalRevenue, count: orders.length });
});

/* ------------------------------------------------------------------ */
/* ADMIN: forwarding email settings                                    */
/* ------------------------------------------------------------------ */

app.get('/api/admin/settings/emails', requireAdmin, async (c) => {
  const row = await c.env.DB.prepare("SELECT value FROM settings WHERE key = 'forwardEmails'").first();
  return c.json({ ok: true, emails: row ? JSON.parse(row.value) : [] });
});

app.post('/api/admin/settings/emails', requireAdmin, async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const emails = body.emails;
  if (!Array.isArray(emails)) return c.json({ ok: false, error: 'emails must be an array.' }, 400);
  const cleaned = [...new Set(
    emails.map((e) => String(e).trim()).filter((e) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e))
  )].slice(0, 20);
  await c.env.DB.prepare("UPDATE settings SET value = ? WHERE key = 'forwardEmails'")
    .bind(JSON.stringify(cleaned)).run();
  return c.json({ ok: true, emails: cleaned });
});

/* ------------------------------------------------------------------ */
/* ADMIN: static dashboard                                             */
/* Served via a Workers Assets binding (configured in wrangler.toml)   */
/* rather than express.static — Workers have no local filesystem, so   */
/* static files are uploaded as build-time assets instead.             */
/* ------------------------------------------------------------------ */
// No explicit route needed here — see wrangler.toml `[assets]` config
// and README.md for how public/admin/index.html is served at /admin.

app.get('/admin', (c) => c.env.ASSETS.fetch(c.req.raw));
app.get('/admin/*', (c) => c.env.ASSETS.fetch(c.req.raw));

export default app;
