// routes/checkout.js — Checkout completion (marketing funnel, no account yet).
// Called by checkout.js the moment the "Order received" screen is shown. Records
// a pending order (user_id NULL until the buyer registers) and emails the buyer
// the registration link.
module.exports = ({ app, CRYPTO_PLAN_PRICES, CRYPTO_SKU_COMP,
                    HYBRID_EXTRA_DEVICE_AMOUNT, HYBRID_EXTRA_DEVICE_ANNUAL_PRICE, HYBRID_EXTRA_DEVICE_PRICE,
                    HYBRID_FLAT_LEGACY_PRICES, HYBRID_INCLUDED_DEVICES, HYBRID_LEGACY_EXTRA_DEVICE_PRICE,
                    HYBRID_LEGACY9_EXTRA_DEVICE_PRICE, HYBRID_REQUIRES_SUPPORT_ACCESS_MSG,
                    NOWPAYMENTS_API_KEY, NOWPAYMENTS_IPN_SECRET,
                    PLAN_KEY_BY_PRICE, PLAN_META, STRIPE_PLANS, STRIPE_TRIAL_DAYS,
                    THREE_DEVICE_EXTRA_AMOUNT, THREE_DEVICE_EXTRA_PRICE, TRIAL_DAYS_ACCOUNT,
                    TRIAL_WIPE_GRACE_MS, TRACKER_DOMAIN,
                    UNLIMITED_EXTRA_DEVICE_AMOUNT, UNLIMITED_EXTRA_DEVICE_ANNUAL_PRICE, UNLIMITED_EXTRA_DEVICE_PRICE,
                    UNLIMITED_FLAT_LEGACY_PRICES, UNLIMITED_INCLUDED_DEVICES,
                    businessModeQualifies, compSlotRow, compSubInfo,
                    contactRateLimit, cors, crypto, db, decryptText, express, genRef,
                    getUserSubscriptionRow, hasSupportAccessGranted, hybridExtraDevices,
                    invalidPlanMessage, log, notifyAdmin, notifyAdminForUser, notifyPush,
                    requireAuth, sendPurchaseEmail, sessionUserEmail, shopStmts, slotRowCount, stripe,
                    STRIPE_PUBLISHABLE_KEY, stripeSubOut, threeDeviceExtraDevices, trialInfo, unlimitedExtraDevices, upsertStripeSubscription }) => {
// Dedupe map for slot-overage admin alerts (in-memory; resets on restart, which is fine —
// alerts re-fire on the next loadSubscription call after restart).
const PUBLIC_SITE_URL = process.env.PUBLIC_SITE_URL || 'http://localhost:3000';
const PUBLIC_API_URL  = process.env.PUBLIC_API_URL  || PUBLIC_SITE_URL;
const _slotOverageAlerted = new Set();
// Normalize a requested device count: 1..1000 (default 1). Used by every per-device checkout
// path (Stripe base + add-on lines, crypto amount, comp slots) so caps always match what was paid.
function normalizeDevices(v) {
  const n = Math.floor(Number(v));
  return (Number.isFinite(n) && n >= 1 && n <= 1000) ? n : 1;
}
// Add-on (extra device) price for a plan key + billing interval. Returns null for plans that
// have no per-device add-on (legacy tiers).
function extraDevicePriceFor(planKey, interval) {
  const annual = interval === 'year';
  if (String(planKey).startsWith('hybrid'))
    return annual ? HYBRID_EXTRA_DEVICE_ANNUAL_PRICE : HYBRID_EXTRA_DEVICE_PRICE;
  if (String(planKey).startsWith('unlimited'))
    return annual ? UNLIMITED_EXTRA_DEVICE_ANNUAL_PRICE : UNLIMITED_EXTRA_DEVICE_PRICE;
  return null;
}
// ── Checkout completion (marketing funnel, no account yet) ───────────────────
// Called by checkout.js the moment the "Order received" screen is shown. Records
// a pending order (user_id NULL until the buyer registers) and emails the buyer
// the registration link — bound to the email they paid with. No admin action and
// no account are required: the buyer registers themselves from the email link.
app.options('/api/checkout/complete', (req, res) => { cors(res).sendStatus(204); });
app.post('/api/checkout/complete', contactRateLimit, async (req, res) => {
  cors(res);
  const name  = String(req.body?.name  || '').trim().slice(0, 120);
  const email = String(req.body?.email || '').trim().slice(0, 200);
  if (!email || !email.includes('@') || email.length > 200)
    return res.status(400).json({ error: 'Valid email is required' });
  const orderType = req.body?.order_type === 'hardware' ? 'hardware' : 'digital';
  const sku    = req.body?.sku ? String(req.body.sku).slice(0, 64) : null;
  const amount = Number.isFinite(+req.body?.amount_cents) && +req.body.amount_cents >= 0
    ? Math.round(+req.body.amount_cents) : null;
  const now = Date.now();
  let orderRef = null;
  try {
    orderRef = genRef('ORD');
    (await shopStmts.insertOrder.run({
      order_ref: orderRef, user_id: null, email,
      order_type: orderType, product_sku: sku, amount_cents: amount, currency: 'usd',
      status: 'pending', carrier: null, tracking_number: null,
      shipped_at: null, delivered_at: null, created_at: now, updated_at: now,
    }));
  } catch (e) { log('warn', 'Checkout order insert failed (continuing to email)', { err: e.message }); }
  // Fire the welcome/registration email. Don't fail the response if SMTP is down —
  // the buyer still sees "Order received"; admin is alerted to follow up.
  const sent = await sendPurchaseEmail(email, name).catch(() => false);
  if (!sent) log('warn', 'Purchase email not sent (SMTP?)', { email, orderRef });
  notifyAdmin(`🧾 New order — registration email ${sent ? 'sent' : 'NOT sent (check SMTP)'}\nName: ${name || '(none)'}\nEmail: ${email}\nPlan: ${sku || orderType}\nRef: ${orderRef || '(insert failed)'}`);
  (await notifyPush('enrollment', '🧾 New paid order', `${name || email} — ${sku || orderType}`, '/'));
  log('info', 'Checkout completed', { orderRef, email, orderType, sku, emailed: sent });
  res.json({ ok: true, emailed: sent });
});

// Stripe Checkout — start a subscription with a 30-day free trial (card saved, $0 today).
app.options('/api/checkout/create-session', (req, res) => { cors(res).sendStatus(204); });
app.post('/api/checkout/create-session', contactRateLimit, async (req, res) => {
  cors(res);
  if (!stripe) return res.status(503).json({ error: 'Billing is not configured yet.' });
  const email = String(req.body?.email || '').trim().toLowerCase();
  const name  = String(req.body?.name  || '').trim().slice(0, 120);
  const plan  = String(req.body?.plan  || 'unlimited_monthly');
  const devices = normalizeDevices(req.body?.devices);
  const priceId = STRIPE_PLANS[plan];
  if (!email || !email.includes('@')) return res.status(400).json({ error: 'A valid email is required' });
  if (!priceId) return res.status(400).json({ error: invalidPlanMessage(plan) });
  // Pre-account marketing checkout can never satisfy the "already granted support access"
  // requirement (no account/ZK key exists yet to grant it from) — Hybrid Managed is dashboard-only,
  // after signup + granting support access. Matches the marketing UI, which never offers a direct
  // Hybrid buy button (trial-first only); this closes the API-level bypass of that same intent.
  if (plan.startsWith('hybrid'))
    return res.status(400).json({ error: 'Hybrid Managed requires an account first — start your free trial, then subscribe to Hybrid Managed from your dashboard.' });
  try {
    // Per-device plans: base price covers the first device; the requested extra devices ride
    // on the plan's per-unit add-on line so the subscription is created with the full slot
    // count up front (and the webhook mirrors it into the account cap).
    const lineItems = [{ price: priceId, quantity: 1 }];
    const addonPrice = extraDevicePriceFor(plan, String(plan).endsWith('_annual') ? 'year' : 'month');
    if (devices > 1 && addonPrice) lineItems.push({ price: addonPrice, quantity: devices - 1 });
    const sess = await stripe.checkout.sessions.create({
      mode: 'subscription',
      line_items: lineItems,
      subscription_data: { trial_period_days: STRIPE_TRIAL_DAYS },
      customer_email: email,
      allow_promotion_codes: true,
      success_url: `${PUBLIC_SITE_URL}/childsafe?checkout=success`,
      cancel_url:  `${PUBLIC_SITE_URL}/childsafe/pricing?checkout=cancel`,
      metadata: { name, plan, devices: String(devices) },
    });
    log('info', 'Stripe checkout session created', { email, plan, devices });
    res.json({ url: sess.url });
  } catch (e) { log('error', 'create-session failed', { err: e.message }); res.status(500).json({ error: 'Could not start checkout — please try again.' }); }
});

// Crypto checkout — create a NOWPayments invoice and redirect to their hosted page.
// Supports FamilySafe plans (by plan key) and custom amounts (sku + amount_cents).
// Crypto payments are one-time prepaid — no auto-renewal.
app.options('/api/checkout/create-crypto-session', (req, res) => { cors(res).sendStatus(204); });
app.post('/api/checkout/create-crypto-session', contactRateLimit, async (req, res) => {
  cors(res);
  if (!NOWPAYMENTS_API_KEY) return res.status(503).json({ error: 'Crypto payments are not configured yet.' });
  const email = String(req.body?.email || '').trim().toLowerCase();
  const name  = String(req.body?.name  || '').trim().slice(0, 120);
  const plan  = String(req.body?.plan  || '');
  const sku   = req.body?.sku ? String(req.body.sku).slice(0, 64) : null;
  const devices = normalizeDevices(req.body?.devices);
  const customAmountCents = Number.isFinite(+req.body?.amount_cents) && +req.body.amount_cents > 0
    ? Math.round(+req.body.amount_cents) : null;

  if (!email || !email.includes('@')) return res.status(400).json({ error: 'A valid email is required' });

  let usdAmount, description, productSku;
  if (plan && CRYPTO_PLAN_PRICES[plan]) {
    // Per-device plans (Per Device $3, Hybrid $15): amount = per-device × count, and the SKU
    // encodes the count (`plan:devices`) so the IPN can materialize the right slot cap.
    const perDevice = String(plan).startsWith('unlimited') || String(plan).startsWith('hybrid');
    usdAmount   = CRYPTO_PLAN_PRICES[plan].usd * (perDevice ? devices : 1);
    description = CRYPTO_PLAN_PRICES[plan].label + (perDevice ? ` — ${devices} device${devices > 1 ? 's' : ''}` : '');
    productSku  = perDevice ? `${plan}:${devices}` : plan;
  } else if (customAmountCents) {
    usdAmount   = customAmountCents / 100;
    description = sku ? `SentinelMDM — ${sku}` : 'SentinelMDM order';
    productSku  = sku;
  } else {
    return res.status(400).json({ error: 'A valid plan or amount is required' });
  }

  const orderRef = genRef('CRY');
  const now = Date.now();
  try {
    (await shopStmts.insertOrder.run({
      order_ref: orderRef, user_id: null, email,
      order_type: 'digital', product_sku: productSku,
      amount_cents: Math.round(usdAmount * 100), currency: 'usd',
      status: 'pending', carrier: null, tracking_number: null,
      shipped_at: null, delivered_at: null, created_at: now, updated_at: now,
    }));
  } catch (e) { log('warn', 'Crypto order pre-insert failed', { err: e.message }); }

  try {
    const invoiceBody = {
      price_amount: usdAmount,
      price_currency: 'usd',
      order_id: orderRef,
      order_description: description,
      payer_email: email,
      success_url: `${PUBLIC_SITE_URL}/childsafe?checkout=success`,
      cancel_url:  `${PUBLIC_SITE_URL}/childsafe/pricing?checkout=cancel`,
      ipn_callback_url: `${PUBLIC_API_URL}/api/nowpayments/webhook`,
    };
    const r = await fetch('https://api.nowpayments.io/v1/invoice', {
      method: 'POST',
      headers: { 'x-api-key': NOWPAYMENTS_API_KEY, 'Content-Type': 'application/json' },
      body: JSON.stringify(invoiceBody),
    });
    const d = /** @type {any} */ (await r.json().catch(() => ({})));
    if (!r.ok || !d.invoice_url) {
      const msg = d.message || d.error || JSON.stringify(d) || 'Invoice creation failed';
      log('error', 'NOWPayments API error', { status: r.status, body: JSON.stringify(d).slice(0, 500) });
      throw new Error(msg);
    }
    // Store the NOWPayments invoice id in stripe_session_id for traceability
    (await db.prepare('UPDATE orders SET stripe_session_id=? WHERE order_ref=?').run(String(d.id), orderRef));
    log('info', 'NOWPayments invoice created', { email, plan: productSku, orderRef, invoiceId: d.id });
    res.json({ url: d.invoice_url });
  } catch (e) {
    log('error', 'create-crypto-session failed', { err: e.message });
    res.status(500).json({ error: `Could not start crypto checkout — ${e.message}` });
  }
});

// Grant (or EXTEND) a comp entitlement from a confirmed crypto payment. Resolves the owning public
// account by the order's linked user_id, falling back to a (plaintext, lowercased) email match. A
// renewal STACKS on any existing finite comp (adds the period onto the later of now / current
// expiry); a perpetual admin-granted comp is left untouched (never shortened). No-op (returns null)
// for custom-amount / hardware SKUs or when no public account can be resolved. Returns
// { userId, plan, expiresAt } on grant, { userId, kept:true } when a perpetual comp was preserved.
async function grantCryptoCompForOrder(order) {
  // Per-device SKUs arrive as `plan:devices` (see create-crypto-session / renew-crypto).
  const raw = String(order && order.product_sku || '');
  const [skuBase, devicesPart] = raw.includes(':') ? raw.split(':') : [raw, null];
  const map = CRYPTO_SKU_COMP[skuBase];
  if (!map) return null;                                  // not a subscription-plan SKU
  const devices = normalizeDevices(devicesPart);         // 1 when absent (flat legacy SKUs)
  let u = order.user_id
    ? (await db.prepare("SELECT id,username,account_type,comp_plan,comp_expires_at FROM users WHERE id=?").get(order.user_id))
    : null;
  if (!u && order.email)                                  // marketing checkout inserts user_id=null
    u = (await db.prepare("SELECT id,username,account_type,comp_plan,comp_expires_at FROM users WHERE LOWER(email)=? AND account_type='public' ORDER BY created_at LIMIT 1").get(String(order.email).toLowerCase()));
  if (!u) { log('warn', 'Crypto comp: no account for paid order', { orderRef: order.order_ref, email: order.email }); return null; }
  if (u.account_type !== 'public') return null;           // comps apply to FamilySafe (public) accounts only
  const hasComp = !!u.comp_plan;
  if (hasComp && u.comp_expires_at == null) {             // perpetual admin comp in force → don't shorten it
    log('info', 'Crypto comp: perpetual comp already in force — left as-is', { userId: u.id, orderRef: order.order_ref });
    return { userId: u.id, kept: true };
  }
  // Anchor to the later of now / current finite expiry so a renewal extends rather than truncates.
  const base = (hasComp && Number(u.comp_expires_at) > Date.now()) ? Number(u.comp_expires_at) : Date.now();
  const d = new Date(base); d.setMonth(d.getMonth() + map.months);
  const expiresAt = d.getTime();
  (await db.prepare('UPDATE users SET comp_plan=?, comp_expires_at=?, comp_granted_by=?, comp_granted_at=? WHERE id=?')
    .run(map.plan, expiresAt, 'crypto:' + (order.order_ref || 'order'), Date.now(), u.id));
  // Per-device comps: record the purchased device count (TOTAL, so cap = 1 + extra) in
  // crypto_slots:{uid}. deviceLimitForUser's comp branch reads it: no row = unlimited
  // (admin-granted comp), row = cap of exactly the devices paid for. Written even for 1.
  if (map.plan === 'unlimited' || map.plan === 'hybrid') {
    (await db.prepare("INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
      .run(`crypto_slots:${u.id}`, String(Math.max(0, devices - 1))));
  }
  // Clear any "1 day left" trial-warning flag so a later lapse can't make the account instantly
  // wipe-eligible — it would have to be re-warned first (mirrors the admin comp-grant route).
  try { (await db.prepare('UPDATE users SET trial_1d_alerted_at=NULL WHERE id=?').run(u.id)); } catch {}
  log('info', 'Crypto comp granted/extended', { userId: u.id, username: u.username, plan: map.plan, months: map.months, devices, expiresAt, orderRef: order.order_ref });
  return { userId: u.id, plan: map.plan, expiresAt, devices };
}

// NOWPayments IPN webhook — fires when a crypto payment is confirmed.
// Registered before requireAuth; IPN comes from NOWPayments servers (no session).
app.post('/api/nowpayments/webhook', express.json(), async (req, res) => {
  // SECURITY: fail CLOSED. With no IPN secret configured we cannot verify authenticity, so
  // reject rather than process an unsigned (forgeable) payment confirmation that would mark
  // arbitrary orders paid. See assessment finding #3.
  if (!NOWPAYMENTS_IPN_SECRET) {
    log('warn', 'NOWPayments IPN rejected — no IPN secret configured (cannot verify signature)');
    return res.status(503).end();
  }
  {
    const sig = req.headers['x-nowpayments-sig'];
    if (!sig) { log('warn', 'NOWPayments IPN missing signature'); return res.status(400).end(); }
    const sortedPayload = JSON.stringify(
      Object.keys(req.body || {}).sort().reduce((obj, k) => { obj[k] = req.body[k]; return obj; }, {})
    );
    const expected = crypto.createHmac('sha512', NOWPAYMENTS_IPN_SECRET).update(sortedPayload).digest('hex');
    // Constant-time compare (avoid leaking the expected HMAC via response timing).
    const sigBuf = Buffer.from(String(sig));
    const expBuf = Buffer.from(expected);
    if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
      log('warn', 'NOWPayments IPN signature mismatch'); return res.status(400).end();
    }
  }
  const { payment_status, order_id, payment_id, actually_paid, pay_currency } = req.body || {};
  if (!['finished', 'confirmed'].includes(payment_status)) return res.status(200).json({ received: true });
  if (!order_id) return res.status(200).json({ received: true });

  const order = (await db.prepare('SELECT * FROM orders WHERE order_ref=?').get(order_id));
  if (!order) { log('warn', 'NOWPayments IPN for unknown order', { order_id }); return res.status(200).end(); }
  if (order.status === 'paid') return res.status(200).json({ received: true }); // idempotent

  (await db.prepare('UPDATE orders SET status=?, stripe_payment_intent=?, updated_at=? WHERE order_ref=?')
    .run('paid', String(payment_id || ''), Date.now(), order_id));
  log('info', 'Crypto payment confirmed', { order_id, payment_id, pay_currency, actually_paid });

  // Materialize the paid period as a comp entitlement so the buyer is exempt from the trial
  // lock + auto-wipe (crypto is prepaid/one-time → no `subscriptions` row to recognize them).
  let comp = null;
  try { comp = await grantCryptoCompForOrder(order); }
  catch (e) { log('error', 'Crypto comp grant failed', { orderRef: order_id, err: e.message }); }
  const compLine = comp && comp.plan
    ? `Comp: ${comp.plan} until ${new Date(comp.expiresAt).toISOString().slice(0, 10)}`
    : (comp && comp.kept ? 'Comp: perpetual (kept)' : 'Comp: NOT applied — no public account matched (resolve manually)');

  const sent = await sendPurchaseEmail(order.email, order.email).catch(() => false);
  if (!sent) log('warn', 'Purchase email not sent after crypto payment', { email: order.email, orderRef: order_id });
  notifyAdminForUser(`💰 Crypto payment confirmed\nOrder: ${order_id}\nEmail: ${order.email}\nPlan: ${order.product_sku}\nCoin: ${pay_currency || '?'}\nAmount: ${actually_paid || '?'}\n${compLine}\nEmail sent: ${sent}`, order.user_id);
  (await notifyPush('enrollment', '💰 Crypto payment confirmed', `${order.email} — ${order.product_sku}`, '/'));
  res.status(200).json({ received: true });
});

// Buyer subscription status + cancel (public users).
app.get('/api/subscription', requireAuth, async (req, res) => {
  if (req.session.account_type !== 'public') return res.json({ subscription: null });
  const userRow = (await db.prepare('SELECT id, email, trial_enabled, trial_started_at, business_mode, comp_plan, comp_expires_at FROM users WHERE id=?').get(req.session.userId));
  const subRow  = (await getUserSubscriptionRow(req));
  const comp    = (await compSubInfo(req.session.userId));             // admin comp | null — overrides trial/billing
  const subscribed = !!comp || (!!subRow && ['trialing', 'active', 'past_due'].includes(subRow.status));
  const t = userRow ? trialInfo(userRow) : null;                       // {state,deadline,ms_remaining,days_remaining} | null
  const locked  = !subscribed && !!t && t.state === 'expired';        // trial over, no sub/comp → 48h wipe countdown
  // Per-device slot info for the plan the account is actually on. Legacy FLAT Hybrid/Unlimited
  // subscribers report unlimited:true (grandfathered, no cap); per-device subscribers report
  // included_devices + extra_devices + per-slot price so the dashboard renders the slot counter.
  const ownedDevices = async () =>
    (await db.prepare('SELECT COUNT(*) AS n FROM devices WHERE owner_user_id=? AND COALESCE(is_demo,0)=0').get(req.session.userId)).n;
  let hybrid = null;
  if (subRow && String(PLAN_KEY_BY_PRICE[subRow.price_id] || '').startsWith('hybrid') && ['trialing', 'active', 'past_due'].includes(subRow.status)) {
    const m = PLAN_META[subRow.price_id] || {};
    if (HYBRID_FLAT_LEGACY_PRICES.has(subRow.price_id)) {
      hybrid = { unlimited: true, included_devices: null, extra_devices: 0,
                 extra_device_amount: HYBRID_EXTRA_DEVICE_AMOUNT, amount: m.amount || 39999, devices_owned: await ownedDevices() };
    } else {
      hybrid = { unlimited: false, included_devices: HYBRID_INCLUDED_DEVICES,
                 extra_devices: await hybridExtraDevices(req.session.userId),
                 extra_device_amount: HYBRID_EXTRA_DEVICE_AMOUNT, amount: m.amount || HYBRID_EXTRA_DEVICE_AMOUNT,
                 devices_owned: await ownedDevices() };
    }
  }
  let perDevice = null;
  if (subRow && String(PLAN_KEY_BY_PRICE[subRow.price_id] || '').startsWith('unlimited') && ['trialing', 'active', 'past_due'].includes(subRow.status)) {
    const m = PLAN_META[subRow.price_id] || {};
    if (UNLIMITED_FLAT_LEGACY_PRICES.has(subRow.price_id)) {
      perDevice = { unlimited: true, included_devices: null, extra_devices: 0,
                    extra_device_amount: UNLIMITED_EXTRA_DEVICE_AMOUNT, amount: m.amount || 5999, devices_owned: await ownedDevices() };
    } else {
      perDevice = { unlimited: false, included_devices: UNLIMITED_INCLUDED_DEVICES,
                    extra_devices: await unlimitedExtraDevices(req.session.userId),
                    extra_device_amount: UNLIMITED_EXTRA_DEVICE_AMOUNT, amount: m.amount || UNLIMITED_EXTRA_DEVICE_AMOUNT,
                    devices_owned: await ownedDevices() };
    }
  }
  let threeDevice = null;
  if (subRow && String(PLAN_KEY_BY_PRICE[subRow.price_id] || '').startsWith('1device') && ['trialing', 'active', 'past_due'].includes(subRow.status)) {
    const m = PLAN_META[subRow.price_id] || {};
    threeDevice = {
      included_devices:      5,
      extra_devices:         await threeDeviceExtraDevices(req.session.userId),
      extra_device_amount:   THREE_DEVICE_EXTRA_AMOUNT,
      amount:                m.amount || 1499,
      devices_owned:         await ownedDevices(),
    };
  }
  // ── Slot overage detection + admin alert ──────────────────────────────────────
  // If the account has more devices than paid slots, flag it in the response and
  // alert the admin (once per user, deduped via an in-memory map that resets on restart).
  let slotOverage = 0;
  const h = hybrid || perDevice || threeDevice;
  if (h && !h.unlimited) {
    const slots = (h.included_devices || 0) + (h.extra_devices || 0);
    const owned = await ownedDevices();
    slotOverage = Math.max(0, owned - slots);
    if (slotOverage > 0) {
      const userKey = `slot_overage_alerted:${req.session.userId}`;
      if (!_slotOverageAlerted.has(userKey)) {
        _slotOverageAlerted.add(userKey);
        const planLabel = hybrid ? 'Hybrid Managed' : perDevice ? 'Per Device' : '5 Devices';
        const email = (await sessionUserEmail(req)) || 'unknown';
        notifyAdmin(`⚠️ Slot overage — ${email}\n${planLabel}: ${slots} slot(s) paid, ${owned} device(s) on account (${slotOverage} over).\nUser must add slots or delete excess devices.`)
          .catch(() => {});
      }
    } else {
      // Resolved — clear dedupe so if overage recurs it alerts again
      _slotOverageAlerted.delete(`slot_overage_alerted:${req.session.userId}`);
    }
  }
  res.json({
    subscription:    stripeSubOut(subRow),
    hybrid,                                                            // null | Hybrid Managed device-slot info (see above)
    per_device:      perDevice,                                        // null | Per Device plan slot info (1 included + $3/mo extras)
    three_device:    threeDevice,                                      // null | 5 Devices (legacy) slot info (5 included + $5/mo extras)
    slot_overage:    slotOverage,                                      // 0 = OK, >0 = N devices exceed paid slots
    comp,                                                              // null | {plan,label,expires_at} — admin-granted free plan
    email:           (await sessionUserEmail(req)) || null,            // confirms the account it binds to
    trial:           t,                                                // null | {state:'pending'|'active'|'expired', deadline, ms_remaining, days_remaining}
    trial_days:      TRIAL_DAYS_ACCOUNT,                               // 30
    trial_locked:    locked,
    wipe_at:         (locked && t && t.deadline) ? t.deadline + TRIAL_WIPE_GRACE_MS : null,
    subscribed,
    billing_enabled: !!stripe,
    crypto_enabled:  !!NOWPAYMENTS_API_KEY,
    // Business Account mode requires an annual or Unlimited plan (see businessModeQualifies) —
    // already-on accounts report eligible:true too so the client never shows an upgrade prompt
    // for a feature they've already activated.
    business_mode_eligible: !!userRow?.business_mode || (userRow ? (await businessModeQualifies(userRow)) : false),
  });
});
app.post('/api/subscription/resume', requireAuth, async (req, res) => {
  if (req.session.account_type !== 'public') return res.status(403).json({ error: 'public account required' });
  if (!stripe) return res.status(503).json({ error: 'Billing not configured' });
  const row = (await getUserSubscriptionRow(req));
  if (!row || !row.stripe_subscription_id) return res.status(404).json({ error: 'No subscription found' });
  if (!row.cancel_at_period_end) return res.json({ ok: true });
  try {
    const sub = await stripe.subscriptions.update(row.stripe_subscription_id, { cancel_at_period_end: false });
    (await upsertStripeSubscription(sub, row.email));
    log('info', 'Subscription resumption — cancel_at_period_end cleared', { sid: sub.id, by: req.session.username });
    res.json({ ok: true });
  } catch (e) {
    if (e.statusCode === 404 || /no such subscription/i.test(e.message)) {
      await db.prepare("UPDATE subscriptions SET status='canceled' WHERE id=?").run(row.id);
      return res.status(400).json({ error: 'Subscription not found in Stripe — cleared locally. Start a new subscription.' });
    }
    log('error', 'subscription resume failed', { err: e.message }); res.status(500).json({ error: 'Resume failed — please try again.' });
  }
});
app.post('/api/subscription/cancel', requireAuth, async (req, res) => {
  if (req.session.account_type !== 'public') return res.status(403).json({ error: 'public account required' });
  if (!stripe) return res.status(503).json({ error: 'Billing not configured' });
  const row = (await getUserSubscriptionRow(req));
  if (!row || !row.stripe_subscription_id) return res.status(404).json({ error: 'No subscription found' });
  if (['canceled', 'incomplete_expired'].includes(row.status)) return res.json({ ok: true, status: row.status });
  try {
    const sub = await stripe.subscriptions.update(row.stripe_subscription_id, { cancel_at_period_end: true });
    (await upsertStripeSubscription(sub, row.email));
    log('info', 'Subscription set to cancel at period end', { sid: sub.id, by: req.session.username });
    res.json({ ok: true, status: sub.status, cancel_at_period_end: true });
  } catch (e) {
    // If Stripe can't find the subscription (e.g. test-mode ID on live Stripe or vice-versa),
    // treat it as already gone and clear the local record so the user isn't stuck.
    if (e.statusCode === 404 || /no such subscription/i.test(e.message)) {
      await db.prepare("UPDATE subscriptions SET status='canceled' WHERE id=?").run(row.id);
      log('info', 'Stale subscription cleared locally (not found in Stripe)', { sid: row.stripe_subscription_id, by: req.session.username });
      return res.json({ ok: true, status: 'canceled', cancel_at_period_end: false });
    }
    log('error', 'subscription cancel failed', { err: e.message }); res.status(500).json({ error: 'Cancel failed — please try again.' });
  }
});

app.post('/api/subscription/change-plan', requireAuth, async (req, res) => {
  if (req.session.account_type !== 'public') return res.status(403).json({ error: 'public account required' });
  if (!stripe) return res.status(503).json({ error: 'Billing not configured' });
  const plan = String(req.body?.plan || '');
  const priceId = STRIPE_PLANS[plan];
  if (!priceId) return res.status(400).json({ error: invalidPlanMessage(plan) });
  if (plan.startsWith('hybrid') && !(await hasSupportAccessGranted(req.session.userId)))
    return res.status(400).json({ error: HYBRID_REQUIRES_SUPPORT_ACCESS_MSG });
  const row = (await getUserSubscriptionRow(req));
  if (!row || !row.stripe_subscription_id) return res.status(404).json({ error: 'No active subscription' });
  if (['canceled', 'incomplete_expired'].includes(row.status)) return res.status(400).json({ error: 'Subscription is not active — please start a new subscription.' });
  if (row.price_id === priceId) return res.json({ ok: true, subscription: stripeSubOut(row) });
  try {
    const sub = await stripe.subscriptions.retrieve(row.stripe_subscription_id);
    const itemId = sub.items.data[0].id;
    const updated = await stripe.subscriptions.update(row.stripe_subscription_id, {
      items: [{ id: itemId, price: priceId }],
      proration_behavior: 'always_invoice',
    });
    (await upsertStripeSubscription(updated, row.email));
    log('info', 'Subscription plan changed', { plan, sid: updated.id, by: req.session.username });
    res.json({ ok: true, subscription: stripeSubOut((await getUserSubscriptionRow(req))) });
  } catch (e) {
    if (e.statusCode === 404 || /no such subscription/i.test(e.message)) {
      await db.prepare("UPDATE subscriptions SET status='canceled' WHERE id=?").run(row.id);
      return res.status(400).json({ error: 'Subscription not found in Stripe — cleared locally. Start a new subscription.' });
    }
    log('error', 'plan change failed', { err: e.message }); res.status(500).json({ error: 'Plan change failed — please try again.' });
  }
});

// Buy / remove extra device slots on a per-device plan (Hybrid Managed / Per Device) or the
// legacy 5 Devices plan. Each extra slot = one add-on line item on the SAME Stripe subscription
// (quantity = extra devices); the prorated difference for an increase is invoiced immediately,
// a decrease credits the proration at the next renewal. The add-on quantity on the subscription
// is the source of truth — upsertStripeSubscription mirrors it into the settings table, and
// deviceLimitForUser reads it back as the cap increase. Subscribers whose add-on line predates
// the current add-on price keep their old price (grandfathered) — quantity changes on that line
// don't migrate it. Legacy FLAT Hybrid/Unlimited subscribers are unlimited (no slots to buy).
app.post('/api/subscription/extra-devices', requireAuth, async (req, res) => {
  if (req.session.account_type !== 'public') return res.status(403).json({ error: 'public account required' });
  if (!stripe) return res.status(503).json({ error: 'Billing not configured' });
  const want = Math.floor(Number(req.body?.extra_devices));
  if (!Number.isFinite(want) || want < 0 || want > 1000)
    return res.status(400).json({ error: 'Enter a device-slot count between 0 and 1000.' });
  const row = (await getUserSubscriptionRow(req));
  if (!row || !row.stripe_subscription_id) return res.status(404).json({ error: 'No active subscription' });
  const planKey = PLAN_KEY_BY_PRICE[row.price_id];
  let included, addonPrice, legacyAddonPrices, label;
  if (planKey && planKey.startsWith('hybrid')) {
    if (HYBRID_FLAT_LEGACY_PRICES.has(row.price_id))
      return res.status(400).json({ error: 'Your Hybrid Managed subscription includes unlimited devices — no extra slots needed.' });
    included = HYBRID_INCLUDED_DEVICES; label = 'Hybrid Managed';
    legacyAddonPrices = [HYBRID_LEGACY_EXTRA_DEVICE_PRICE, HYBRID_LEGACY9_EXTRA_DEVICE_PRICE];
  } else if (planKey && planKey.startsWith('unlimited')) {
    if (UNLIMITED_FLAT_LEGACY_PRICES.has(row.price_id))
      return res.status(400).json({ error: 'Your Unlimited subscription includes unlimited devices — no extra slots needed.' });
    included = UNLIMITED_INCLUDED_DEVICES; label = 'Per Device';
    legacyAddonPrices = [];
  } else if (planKey && planKey.startsWith('1device')) {
    included = 5; label = '5 Devices';
    legacyAddonPrices = [];
  } else {
    return res.status(400).json({ error: 'Extra device slots are available on per-device plans only.' });
  }
  if (['canceled', 'incomplete_expired'].includes(row.status))
    return res.status(400).json({ error: 'Subscription is not active — please start a new subscription.' });
  try {
    const sub = await stripe.subscriptions.retrieve(row.stripe_subscription_id);
    const baseItem = (sub.items && sub.items.data || []).find(it => it.price && PLAN_KEY_BY_PRICE[it.price.id] === planKey);
    if (!baseItem) return res.status(400).json({ error: `Could not locate your ${label} subscription line.` });
    // Add-on price follows the base plan's billing interval (monthly vs annual).
    const interval = baseItem.price && baseItem.price.recurring && baseItem.price.recurring.interval;
    addonPrice = planKey.startsWith('1device')
      ? THREE_DEVICE_EXTRA_PRICE
      : extraDevicePriceFor(planKey, interval === 'year' ? 'year' : 'month');
    const extraItem = (sub.items && sub.items.data || []).find(it =>
      it.price && (it.price.id === addonPrice || legacyAddonPrices.includes(it.price.id)));
    const items = /** @type {any[]} */ ([{ id: baseItem.id, price: baseItem.price.id, quantity: 1 }]);
    if (want > 0) {
      if (extraItem) items.push({ id: extraItem.id, quantity: want });
      else if (addonPrice) items.push({ price: addonPrice, quantity: want });
      else return res.status(400).json({ error: 'Extra device slots aren\'t set up yet — please contact support.' });
    } else if (extraItem) {
      items.push({ id: extraItem.id, deleted: true });
    }
    const updated = await stripe.subscriptions.update(row.stripe_subscription_id, {
      items,
      proration_behavior: 'always_invoice',
    });
    (await upsertStripeSubscription(updated, row.email));
    log('info', 'Extra device slots updated', { sid: updated.id, extra_devices: want, plan: planKey, by: req.session.username });
    res.json({ ok: true, extra_devices: want, included_devices: included, subscription: stripeSubOut((await getUserSubscriptionRow(req))) });
  } catch (e) {
    log('error', 'extra-devices update failed', { err: e.message });
    res.status(500).json({ error: 'Could not update device slots — please try again.' });
  }
});

// Backward-compatible alias — the WebUI (app.js) calls this name.
app.post('/api/subscription/hybrid-devices', requireAuth, (req, res) => {
  // Forward to the generalized endpoint
  app.handle(Object.assign(req, { url: '/api/subscription/extra-devices', method: 'POST', body: req.body }), res);
});

// Build a Stripe Checkout session for the logged-in public user. The resulting subscription
// is bound to their account via client_reference_id + subscription metadata, so the webhook
// sets user_id directly — association never relies on email-matching alone. Returns to the
// dashboard (not the marketing site) so the user lands back where they started.
async function createSubCheckoutSession(req, plan, devices = 1) {
  const priceId = STRIPE_PLANS[plan];
  if (!priceId) return { error: invalidPlanMessage(plan), code: 400 };
  if (String(plan).startsWith('hybrid') && !(await hasSupportAccessGranted(req.session.userId)))
    return { error: HYBRID_REQUIRES_SUPPORT_ACCESS_MSG, code: 400 };
  const email = (await sessionUserEmail(req));
  if (!email) return { error: 'No email on your account — contact support.', code: 400 };
  const uid = String(req.session.userId);
  const subData = { metadata: { user_id: uid } };
  // First charge lands when the user's CURRENT free coverage ends — the later of any remaining
  // free-trial time and an active (finite) complimentary period — so subscribing early, even while
  // comped, never double-pays and the paid sub seamlessly takes over the moment the comp/trial runs
  // out (no gap, no last-minute scramble). (<49h left is below Stripe's trial_end floor → bill at
  // signup. A perpetual comp has no end date for Stripe to bill against, so it also falls through to
  // billing at signup — the dashboard only offers subscribe for FINITE comps.)
  // SKIP trial extension when devices are already connected — the trial started when the first
  // device enrolled; extending it just makes Stripe show "Start free trial" instead of "Subscribe".
  const u  = (await db.prepare('SELECT trial_enabled, trial_started_at, comp_plan, comp_expires_at FROM users WHERE id=?').get(req.session.userId));
  const ti = u ? trialInfo(u) : null;
  const hasDevices = (await db.prepare('SELECT 1 FROM devices WHERE owner_user_id=? AND COALESCE(is_demo,0)=0 LIMIT 1').get(req.session.userId));
  let coverEnd = (hasDevices && ti && ti.state !== 'expired' && ti.deadline) ? ti.deadline : 0;
  if (u && u.comp_plan && u.comp_expires_at != null && Number(u.comp_expires_at) > Date.now())
    coverEnd = Math.max(coverEnd, Number(u.comp_expires_at));
  if (coverEnd > Date.now() + 49 * 3600 * 1000)
    subData.trial_end = Math.floor(coverEnd / 1000);
  // Per-device plans: base covers the first device; requested extra devices ride on the
  // matching per-unit add-on line so the subscription is created with the full slot count
  // (the webhook mirrors it into the account cap).
  const lineItems = [{ price: priceId, quantity: 1 }];
  const addonPrice = extraDevicePriceFor(plan, String(plan).endsWith('_annual') ? 'year' : 'month');
  const n = normalizeDevices(devices);
  if (n > 1 && addonPrice) lineItems.push({ price: addonPrice, quantity: n - 1 });
  const sess = await stripe.checkout.sessions.create({
    mode: 'subscription',
    customer_email: email,                                            // pre-filled & read-only at Checkout
    line_items: lineItems,
    subscription_data: subData,
    client_reference_id: uid,                                         // → webhook binds the row to this user
    allow_promotion_codes: true,
    success_url: `${PUBLIC_API_URL}/?checkout=success`,
    cancel_url:  `${PUBLIC_SITE_URL}/pricing`,
  });
  return { url: sess.url };
}

// Start a NEW subscription straight from the dashboard (30-day free trial, card saved, $0 today).
// Auto-bound to the logged-in public user — no email entry, no external pricing page.
app.post('/api/subscription/start', requireAuth, async (req, res) => {
  if (req.session.account_type !== 'public') return res.status(403).json({ error: 'public account required' });
  if (!stripe) return res.status(503).json({ error: 'Billing is not configured yet.' });
  const existing = (await getUserSubscriptionRow(req));
  if (existing && existing.stripe_subscription_id && ['active', 'trialing', 'past_due'].includes(existing.status))
    return res.status(400).json({ error: 'You already have a subscription on file — manage it from this panel.' });
  try {
    const r = (await createSubCheckoutSession(req, String(req.body?.plan || 'unlimited_monthly'), req.body?.devices));
    if (r.error) return res.status(r.code || 400).json({ error: r.error });
    log('info', 'Subscription checkout session created', { user: req.session.username, plan: req.body?.plan, devices: normalizeDevices(req.body?.devices) });
    res.json({ url: r.url });
  } catch (e) { log('error', 'subscription start failed', { err: e.message }); res.status(500).json({ error: 'Could not start checkout — please try again.' }); }
});

app.post('/api/subscription/resubscribe', requireAuth, async (req, res) => {
  if (req.session.account_type !== 'public') return res.status(403).json({ error: 'public account required' });
  if (!stripe) return res.status(503).json({ error: 'Billing not configured' });
  try {
    const r = (await createSubCheckoutSession(req, String(req.body?.plan || 'unlimited_monthly'), req.body?.devices));
    if (r.error) return res.status(r.code || 400).json({ error: r.error });
    log('info', 'Resubscribe checkout session created', { user: req.session.username, plan: req.body?.plan, devices: normalizeDevices(req.body?.devices) });
    res.json({ url: r.url });
  } catch (e) { log('error', 'resubscribe session failed', { err: e.message }); res.status(500).json({ error: 'Could not start checkout — please try again.' }); }
});

// Crypto renewal — authenticated user pays for the next period with crypto.
// Creates a NOWPayments invoice using the user's session email and chosen plan.
app.post('/api/subscription/renew-crypto', requireAuth, async (req, res) => {
  if (req.session.account_type !== 'public') return res.status(403).json({ error: 'public account required' });
  if (!NOWPAYMENTS_API_KEY) return res.status(503).json({ error: 'Crypto payments not configured' });
  const plan = String(req.body?.plan || '');
  const planInfo = CRYPTO_PLAN_PRICES[plan];
  if (!planInfo) return res.status(400).json({ error: 'Invalid plan' });
  if (plan.startsWith('hybrid') && !(await hasSupportAccessGranted(req.session.userId)))
    return res.status(400).json({ error: HYBRID_REQUIRES_SUPPORT_ACCESS_MSG });
  // Per-device plans bill per-device × count; the SKU encodes the count so the IPN can
  // materialize the right slot cap (see grantCryptoCompForOrder).
  const perDevice = plan.startsWith('unlimited') || plan.startsWith('hybrid');
  const devices = perDevice ? normalizeDevices(req.body?.devices) : 1;
  const userRow = (await db.prepare('SELECT email FROM users WHERE id=?').get(req.session.userId));
  const email = (userRow && decryptText(userRow.email)) || '';
  if (!email) return res.status(400).json({ error: 'No email on account' });
  const orderRef = genRef('CRY');
  const now = Date.now();
  try {
    (await shopStmts.insertOrder.run({
      order_ref: orderRef, user_id: req.session.userId, email,
      order_type: 'digital', product_sku: perDevice ? `${plan}:${devices}` : plan,
      amount_cents: Math.round(planInfo.usd * (perDevice ? devices : 1) * 100), currency: 'usd',
      status: 'pending', carrier: null, tracking_number: null,
      shipped_at: null, delivered_at: null, created_at: now, updated_at: now,
    }));
  } catch (e) { log('warn', 'Crypto renewal order insert failed', { err: e.message }); }
  try {
    const invoiceBody = {
      price_amount: planInfo.usd * (perDevice ? devices : 1),
      price_currency: 'usd',
      order_id: orderRef,
      order_description: planInfo.label + (perDevice ? ` — ${devices} device${devices > 1 ? 's' : ''}` : '') + ' — Renewal',
      success_url: `https://${TRACKER_DOMAIN}/`,
      cancel_url:  `https://${TRACKER_DOMAIN}/`,
      ipn_callback_url: `${PUBLIC_API_URL}/api/nowpayments/webhook`,
    };
    const r = await fetch('https://api.nowpayments.io/v1/invoice', {
      method: 'POST',
      headers: { 'x-api-key': NOWPAYMENTS_API_KEY, 'Content-Type': 'application/json' },
      body: JSON.stringify(invoiceBody),
    });
    const d = /** @type {any} */ (await r.json().catch(() => ({})));
    if (!r.ok || !d.invoice_url) throw new Error(d.message || 'Invoice creation failed');
    (await db.prepare('UPDATE orders SET stripe_session_id=? WHERE order_ref=?').run(String(d.id), orderRef));
    log('info', 'Crypto renewal invoice created', { email, plan, orderRef, invoiceId: d.id });
    res.json({ url: d.invoice_url });
  } catch (e) {
    log('error', 'renew-crypto failed', { err: e.message });
    res.status(500).json({ error: 'Could not start crypto checkout — please try again.' });
  }
});

// ── In-app Stripe card payment (no redirect) ──────────────────────────────────
// Returns the Stripe publishable key for the dashboard to initialize Elements.
app.get('/api/stripe-key', (req, res) => {
  res.json({ publishableKey: STRIPE_PUBLISHABLE_KEY || null });
});

// Create a subscription directly from an in-app card form. The dashboard collects
// the card via Stripe.js Elements (PaymentMethod), then POSTs here with the
// PaymentMethod ID + plan + devices. Server creates/attaches the customer,
// sets the default payment method, and creates the subscription — no redirect.
app.post('/api/subscription/create-payment', requireAuth, async (req, res) => {
  if (req.session.account_type !== 'public') return res.status(403).json({ error: 'public account required' });
  if (!stripe) return res.status(503).json({ error: 'Billing is not configured' });
  const plan = String(req.body?.plan || '');
  const paymentMethodId = String(req.body?.paymentMethodId || '');
  const devices = normalizeDevices(req.body?.devices);
  const priceId = STRIPE_PLANS[plan];
  if (!priceId) return res.status(400).json({ error: invalidPlanMessage(plan) });
  if (!paymentMethodId || !paymentMethodId.startsWith('pm_'))
    return res.status(400).json({ error: 'Invalid payment method' });
  if (plan.startsWith('hybrid') && !(await hasSupportAccessGranted(req.session.userId)))
    return res.status(400).json({ error: HYBRID_REQUIRES_SUPPORT_ACCESS_MSG });

  try {
    const email = (await sessionUserEmail(req));
    if (!email) return res.status(400).json({ error: 'No email on account' });
    const uid = String(req.session.userId);

    // Find or create Stripe customer
    const existing = (await getUserSubscriptionRow(req));
    let customerId = existing?.stripe_customer_id || null;
    if (!customerId) {
      // Search by email
      const search = await stripe.customers.list({ email, limit: 1 });
      if (search.data.length) customerId = search.data[0].id;
    }
    if (!customerId) {
      const customer = await stripe.customers.create({ email, metadata: { user_id: uid } });
      customerId = customer.id;
    }

    // Attach payment method to customer + set as default
    await stripe.paymentMethods.attach(paymentMethodId, { customer: customerId });
    await stripe.customers.update(customerId, {
      invoice_settings: { default_payment_method: paymentMethodId },
    });

    // Build line items: base + extras
    const lineItems = [{ price: priceId, quantity: 1 }];
    const addonPrice = extraDevicePriceFor(plan, String(plan).endsWith('_annual') ? 'year' : 'month');
    if (devices > 1 && addonPrice) lineItems.push({ price: addonPrice, quantity: devices - 1 });

    // Create subscription — no trial when creating via card (user already has trial if they have devices)
    const sub = await stripe.subscriptions.create({
      customer: customerId,
      items: lineItems.map(it => ({ price: it.price, quantity: it.quantity })),
      default_payment_method: paymentMethodId,
      payment_behavior: 'error_if_incomplete',
      proration_behavior: 'create_prorations',
      metadata: { user_id: uid, plan, devices: String(devices) },
    });

    // Mirror the subscription into our DB
    await upsertStripeSubscription(sub, email, req.session.userId);

    log('info', 'In-app subscription created', { user: req.session.username, plan, devices, subId: sub.id });
    res.json({ ok: true, subscription: stripeSubOut((await getUserSubscriptionRow(req))) });
  } catch (e) {
    log('error', 'create-payment failed', { err: e.message, stack: e.stack });
    const msg = e.type === 'card_error' ? e.message : 'Payment failed — please try again.';
    res.status(400).json({ error: msg });
  }
});

};
