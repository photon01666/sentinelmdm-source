// routes/admin-commerce.js — admin management of products / orders / RMA / trials (admin-only).
// Extracted verbatim from server.js. All routes are requireAdmin. Deps injected (no TDZ).

module.exports = function registerAdminCommerceRoutes({ app, db, shopStmts, requireAdmin, CRYPTO_PLAN_PRICES, DAY_MS, PLAN_META, STRIPE_PLANS, computePrice, daysRemaining, decryptBuffer, decryptText, hwidHmac, log, notifyAdmin, r2Get, rmaWindowState }) {
// ════════════════ ADMIN — products / orders / RMA / trials ════════════════════
// Manual pricing CRUD
app.get('/api/admin/products', requireAdmin, async (_req, res) => {
  res.json({ products: (await shopStmts.allProducts.all()).map(p => ({ ...p, computed_price_cents: computePrice(p) })) });
});
app.post('/api/admin/products', requireAdmin, async (req, res) => {
  const b = req.body || {};
  if (!b.sku || !b.title) return res.status(400).json({ error: 'sku and title required' });
  const row = {
    sku: String(b.sku).slice(0, 64), title: String(b.title).slice(0, 200),
    model_series: b.model_series || null,
    base_cost_cents: parseInt(b.base_cost_cents) || 0,
    markup_cents: (b.markup_cents == null ? 5000 : parseInt(b.markup_cents) || 0),
    price_cents: parseInt(b.price_cents) || 0,
    currency: b.currency || 'usd', active: b.active === false ? 0 : 1,
    sort_order: parseInt(b.sort_order) || 0, updated_at: Date.now(),
  };
  (await shopStmts.upsertProduct.run(row));
  log('info', 'Product upserted', { sku: row.sku });
  res.json({ ok: true });
});
app.delete('/api/admin/products/:id', requireAdmin, async (req, res) => {
  (await shopStmts.deleteProduct.run(req.params.id));
  res.json({ ok: true });
});

// Orders + shipment tracking (delivered_at starts the 14-day RMA window)
app.get('/api/admin/orders', requireAdmin, async (_req, res) => {
  const userById = db.prepare('SELECT id,username,email FROM users WHERE id=?');
  res.json({ orders: await Promise.all((await shopStmts.allOrders.all()).map(async o => {
    const u = o.user_id ? (await userById.get(o.user_id)) : null;
    return { ...o, return_window: rmaWindowState(o),
             account_username: u?.username || null,
             account_email: u?.email || o.email || null };
  })) });
});
app.patch('/api/admin/orders/:id/shipment', requireAdmin, async (req, res) => {
  const o = (await shopStmts.orderById.get(req.params.id));
  if (!o) return res.status(404).json({ error: 'order not found' });
  const b = req.body || {};
  const carrier   = b.carrier ?? o.carrier;
  const tracking  = b.tracking_number ?? o.tracking_number;
  const shippedAt = b.shipped_at != null ? Number(b.shipped_at) : o.shipped_at;
  const delivAt   = b.delivered_at != null ? Number(b.delivered_at) : o.delivered_at;
  const status    = b.status || (delivAt ? 'delivered' : shippedAt ? 'shipped' : o.status);
  (await shopStmts.setOrderShipment.run(carrier, tracking, shippedAt, delivAt, status, Date.now(), o.id));
  res.json({ ok: true });
});
// Delete an order + every row that references it, FK-safe and atomic. Admin cleanup of
// test/abandoned orders. Cascade: rma_photos → rma_requests → tos_acceptances → entitlements → order.
app.delete('/api/admin/orders/:id', requireAdmin, async (req, res) => {
  const o = (await shopStmts.orderById.get(req.params.id));
  if (!o) return res.status(404).json({ error: 'order not found' });
  try {
    await db.transaction(async () => {
      const rmas = (await db.prepare('SELECT id FROM rma_requests WHERE order_id=?').all(o.id));
      for (const r of rmas) (await db.prepare('DELETE FROM rma_photos WHERE rma_id=?').run(r.id));
      (await db.prepare('DELETE FROM rma_requests WHERE order_id=?').run(o.id));
      (await db.prepare('DELETE FROM tos_acceptances WHERE order_id=?').run(o.id));
      (await db.prepare('DELETE FROM entitlements WHERE order_id=?').run(o.id));
      (await db.prepare('DELETE FROM orders WHERE id=?').run(o.id));
    })();
    log('info', 'Order deleted by admin', { orderId: o.id, orderRef: o.order_ref, by: req.session.username });
    res.json({ ok: true });
  } catch (e) { log('error', 'order delete failed', { orderId: o.id, err: e.message }); res.status(500).json({ error: 'Delete failed' }); }
});

// Subscription orders ONLY — Stripe subscriptions + NOWPayments crypto sub payments. Deliberately
// excludes phone/hardware orders (this admin view is about subscriptions, not shipments).
app.get('/api/admin/sub-orders', requireAdmin, async (_req, res) => {
  const userById = db.prepare('SELECT id,username,email FROM users WHERE id=?');
  // Crypto (NOWPayments) prepaid sub payments = orders whose SKU is a subscription plan key.
  const planIn = Object.keys(STRIPE_PLANS).map(k => `'${k}'`).join(',');
  const cryptoRows = (await db.prepare(`SELECT * FROM orders WHERE product_sku IN (${planIn}) ORDER BY created_at DESC`).all());
  const crypto = await Promise.all(cryptoRows.map(async o => {
    const u = o.user_id ? (await userById.get(o.user_id)) : null;
    return { source: 'crypto', id: o.id, ref: o.order_ref,
             account_username: u?.username || null,
             account_email: (u ? decryptText(u.email) : null) || o.email || null,
             plan_label: (CRYPTO_PLAN_PRICES[o.product_sku]?.label) || o.product_sku,
             amount_cents: o.amount_cents, status: o.status, created_at: o.created_at, deletable: true };
  }));
  // Stripe subscriptions.
  const subRows = (await db.prepare('SELECT * FROM subscriptions ORDER BY created_at DESC').all());
  const stripe = await Promise.all(subRows.map(async s => {
    const u = s.user_id ? (await userById.get(s.user_id)) : null;
    const meta = /** @type {any} */ (PLAN_META[s.price_id] || {});
    return { source: 'stripe', id: s.id, ref: s.stripe_subscription_id || ('sub#' + s.id),
             account_username: u?.username || null,
             account_email: (u ? decryptText(u.email) : null) || s.email || null,
             plan_label: meta.label ? `${meta.label}${meta.interval ? ' · ' + meta.interval : ''}` : (s.price_id || '—'),
             amount_cents: meta.amount || null, status: s.status,
             current_period_end: s.current_period_end || null, created_at: s.created_at, deletable: true };
  }));
  res.json({ orders: [...crypto, ...stripe].sort((a, b) => (b.created_at || 0) - (a.created_at || 0)) });
});
// Delete a local Stripe-subscription row (admin cleanup of stale/canceled records).
app.delete('/api/admin/subscriptions/:id', requireAdmin, async (req, res) => {
  (await db.prepare('DELETE FROM subscriptions WHERE id=?').run(req.params.id));
  res.json({ ok: true });
});

// RMA review queue + detail
app.get('/api/admin/rma', requireAdmin, async (_req, res) => {
  res.json({ rmas: await Promise.all((await shopStmts.allRma.all()).map(async r => {
    const o = (await shopStmts.orderById.get(r.order_id));
    return { ...r, order_ref: o?.order_ref || null, order: o ? { ...o, return_window: rmaWindowState(o) } : null,
             photo_count: (await shopStmts.photosByRma.all(r.id)).length };
  })) });
});
app.get('/api/admin/rma/:id', requireAdmin, async (req, res) => {
  const r = (await shopStmts.rmaById.get(req.params.id));
  if (!r) return res.status(404).json({ error: 'RMA not found' });
  const o = (await shopStmts.orderById.get(r.order_id));
  res.json({ rma: { ...r, order: o ? { ...o, return_window: rmaWindowState(o) } : null },
             photos: (await shopStmts.photosByRma.all(r.id)).map(p => ({ id: p.id, slot: p.slot, content_type: p.content_type, uploaded_at: p.uploaded_at })) });
});
// Stream a decrypted RMA photo (admin only)
app.get('/api/admin/rma/:id/photo/:photoId', requireAdmin, async (req, res) => {
  const p = (await shopStmts.photoById.get(req.params.photoId));
  if (!p || String(p.rma_id) !== String(req.params.id))
    return res.status(404).json({ error: 'photo not found' });
  try {
    const enc = await r2Get(p.r2_key);
    if (!enc) return res.status(404).json({ error: 'photo bytes missing' });
    const buf = decryptBuffer(enc);
    res.setHeader('Content-Type', p.content_type || 'image/jpeg');
    res.setHeader('Cache-Control', 'private, no-store');
    res.send(buf);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Mark the RETURNED device delivered → Pending_Inspection (no auto-refund)
app.patch('/api/admin/rma/:id/delivered', requireAdmin, async (req, res) => {
  const r = (await shopStmts.rmaById.get(req.params.id));
  if (!r) return res.status(404).json({ error: 'RMA not found' });
  (await shopStmts.setRmaDelivered.run(Number(req.body?.delivered_at) || Date.now(), Date.now(), r.id));
  log('info', 'RMA return delivered → Pending_Inspection', { rmaRef: r.rma_ref });
  res.json({ ok: true, status: 'Pending_Inspection' });
});

// Inspection — admin records serial cross-reference + condition. Serial is
// cross-checked against the order's bound device (Phase-2 hwidHmac) when present.
app.post('/api/admin/rma/:id/inspect', requireAdmin, async (req, res) => {
  const r = (await shopStmts.rmaById.get(req.params.id));
  if (!r) return res.status(404).json({ error: 'RMA not found' });
  const b = req.body || {};
  let serialVerified = b.serial_verified ? 1 : 0;
  let autoMatch = null;
  if (b.returned_serial) {
    const hmac = hwidHmac(String(b.returned_serial));
    const bound = (await shopStmts.entByOrder.all(r.order_id));
    if (bound.length) { autoMatch = bound.some(e => e.hardware_id_hmac === hmac); if (autoMatch) serialVerified = 1; }
  }
  const condPass = b.condition_pass == null ? null : (b.condition_pass ? 1 : 0);
  (await shopStmts.setRmaInspection.run(serialVerified, condPass, String(b.notes || '').slice(0, 1000),
    req.session.username || 'admin', Date.now(), r.id));
  if (condPass === 0) (await shopStmts.setRmaStatus.run('Rejected', Date.now(), r.id));
  log('info', 'RMA inspected', { rmaRef: r.rma_ref, serialVerified, condPass, autoMatch });
  res.json({ ok: true, serial_verified: serialVerified, serial_auto_match: autoMatch, condition_pass: condPass });
});

// Release refund — HARD GATE: never automated. Requires a completed inspection
// with serial verified AND condition pass. Admin clicks this explicitly.
app.post('/api/admin/rma/:id/release-refund', requireAdmin, async (req, res) => {
  const r = (await shopStmts.rmaById.get(req.params.id));
  if (!r) return res.status(404).json({ error: 'RMA not found' });
  if (r.status === 'Refunded') return res.json({ ok: true, already: true });
  if (r.condition_pass !== 1)
    return res.status(409).json({ error: 'Cannot release refund: device has not passed inspection (condition_pass).' });
  if (r.serial_verified !== 1)
    return res.status(409).json({ error: 'Cannot release refund: returned serial not verified against shipment.' });
  (await shopStmts.releaseRefund.run(Date.now(), req.session.username || 'admin', Date.now(), r.id));
  notifyAdmin(`💸 Refund released\nRMA: ${r.rma_ref}\nBy: ${req.session.username || 'admin'}`).catch(() => {});
  log('info', 'Refund released', { rmaRef: r.rma_ref, by: req.session.username });
  res.json({ ok: true, status: 'Refunded' });
});
app.post('/api/admin/rma/:id/reject', requireAdmin, async (req, res) => {
  const r = (await shopStmts.rmaById.get(req.params.id));
  if (!r) return res.status(404).json({ error: 'RMA not found' });
  (await shopStmts.setRmaStatus.run('Rejected', Date.now(), r.id));
  res.json({ ok: true, status: 'Rejected' });
});

// ── ADMIN trials — extend / expire / reactivate (NEVER auto-disabled) ───────
app.get('/api/admin/trials', requireAdmin, async (_req, res) => {
  res.json({ trials: await Promise.all((await shopStmts.allEntsAdmin.all()).map(async e => {
    let username = null;
    try { username = (await db.prepare('SELECT username FROM users WHERE id=?').get(e.user_id))?.username || null; } catch {}
    const past = e.software_trial_deadline ? Date.now() > e.software_trial_deadline : false;
    return { id: e.id, license_key: e.license_key, user_id: e.user_id, username,
             trial_type: e.trial_type, status: e.status, device_id: e.device_id,
             trial_start_date: e.trial_start_date, software_trial_deadline: e.software_trial_deadline,
             days_remaining: daysRemaining(e.software_trial_deadline),
             lapsed: past, lapsed_alerted_at: e.lapsed_alerted_at };
  })) });
});
app.post('/api/admin/trials/:id/extend', requireAdmin, async (req, res) => {
  const e = (await shopStmts.entById.get(req.params.id));
  if (!e) return res.status(404).json({ error: 'entitlement not found' });
  const days = parseInt(req.body?.days);
  if (!days || days < 1 || days > 3650) return res.status(400).json({ error: 'days must be 1–3650' });
  const base = Math.max(Date.now(), e.software_trial_deadline || Date.now());
  const newDeadline = base + days * DAY_MS;
  (await shopStmts.extendEnt.run(newDeadline, e.id));   // also clears lapsed flag + sets Active
  log('info', 'Trial extended', { licenseKey: e.license_key, days, by: req.session.username });
  res.json({ ok: true, software_trial_deadline: newDeadline, days_remaining: daysRemaining(newDeadline) });
});
app.post('/api/admin/trials/:id/expire', requireAdmin, async (req, res) => {
  const e = (await shopStmts.entById.get(req.params.id));
  if (!e) return res.status(404).json({ error: 'entitlement not found' });
  (await shopStmts.setEntStatus.run('Expired', e.id));   // ONLY way a license becomes invalid
  log('info', 'Trial expired by admin', { licenseKey: e.license_key, by: req.session.username });
  res.json({ ok: true, status: 'Expired' });
});
app.post('/api/admin/trials/:id/reactivate', requireAdmin, async (req, res) => {
  const e = (await shopStmts.entById.get(req.params.id));
  if (!e) return res.status(404).json({ error: 'entitlement not found' });
  (await shopStmts.setEntStatus.run('Active', e.id));
  res.json({ ok: true, status: 'Active' });
});
};
