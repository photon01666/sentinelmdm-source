// routes/commerce.js — E-commerce pricing + RMA pipeline + catalog + orders (customer-facing).
module.exports = ({ app, DAY_MS, db, encryptBuffer, genRef, log, notifyAdminForUser,
                    r2Put, recordTosAcceptance, shopStmts, computePrice, rmaWindowState, RETURN_WINDOW_DAYS }) => {
// ── Phase 3: E-commerce pricing + RMA pipeline ───────────────────────────────
// Pricing is MANUAL (admin-set base cost + markup). No third-party scraping.

function publicRma(r) {
  return { id: r.id, rma_ref: r.rma_ref, order_id: r.order_id, status: r.status,
           reason: r.reason, return_carrier: r.return_carrier, return_tracking: r.return_tracking,
           created_at: r.created_at, updated_at: r.updated_at };
}

// ── Catalog (read) — any authenticated session ──────────────────────────────
app.get('/api/shop/products', async (req, res) => {
  const rows = (await shopStmts.activeProducts.all()).map(p => ({
    id: p.id, sku: p.sku, title: p.title, model_series: p.model_series,
    price_cents: computePrice(p), currency: p.currency || 'usd',
  }));
  res.json({ products: rows });
});

// ── Orders (customer) ───────────────────────────────────────────────────────
// Create an order tied to the logged-in public account. (Stripe webhook can also
// create/confirm orders later; this is the same-origin record + ToS evidence.)
app.post('/api/orders', async (req, res) => {
  if (req.session.account_type !== 'public')
    return res.status(403).json({ error: 'public account required' });
  const { product_sku = null, order_type = 'hardware', amount_cents = null, tos = null } = req.body || {};
  const now = Date.now();
  const ref = genRef('ORD');
  let amount = amount_cents;
  if (product_sku && amount == null) {
    const p = (await db.prepare('SELECT * FROM products WHERE sku=?').get(product_sku));
    if (p) amount = computePrice(p);
  }
  const { id: id } = (await shopStmts.insertOrder.get({
    order_ref: ref, user_id: req.session.userId, email: req.session.username || null,
    order_type, product_sku, amount_cents: amount, currency: 'usd', status: 'pending',
    carrier: null, tracking_number: null, shipped_at: null, delivered_at: null,
    created_at: now, updated_at: now,
  }));
  if (tos && tos.accepted) {
    (await recordTosAcceptance(req, { userId: req.session.userId, orderId: id, email: req.session.username || null,
      policyKey: tos.policy_key || 'physical_damage_voids_return',
      policyVersion: tos.policy_version || '1', policyText: tos.policy_text || null }));
  }
  log('info', 'Order created', { orderRef: ref, userId: req.session.userId, order_type });
  res.json({ ok: true, order_id: id, order_ref: ref, amount_cents: amount });
});

app.get('/api/orders/mine', async (req, res) => {
  if (req.session.account_type !== 'public')
    return res.status(403).json({ error: 'public account required' });
  const rows = await Promise.all((await shopStmts.ordersByUser.all(req.session.userId)).map(async o => {
    const w = rmaWindowState(o);
    const rma = (await shopStmts.rmaByOrder.all(o.id))[0] || null;
    return { id: o.id, order_ref: o.order_ref, order_type: o.order_type, product_sku: o.product_sku,
             amount_cents: o.amount_cents, status: o.status, carrier: o.carrier,
             tracking_number: o.tracking_number, shipped_at: o.shipped_at, delivered_at: o.delivered_at,
             created_at: o.created_at, return_window: w, rma: rma ? publicRma(rma) : null };
  }));
  res.json({ orders: rows });
});

// ── RMA request (customer) — enforces the 14-day-from-delivery gate ─────────
app.post('/api/orders/:id/rma', async (req, res) => {
  if (req.session.account_type !== 'public')
    return res.status(403).json({ error: 'public account required' });
  const order = (await shopStmts.orderById.get(req.params.id));
  if (!order || order.user_id !== req.session.userId)
    return res.status(404).json({ error: 'order not found' });
  const w = rmaWindowState(order);
  if (!w.delivered)
    return res.status(409).json({ error: 'This order is not marked delivered yet — no return window has started.' });
  if (!w.withinWindow)
    return res.status(403).json({ error: `Return window closed. Hardware returns must be requested within ${RETURN_WINDOW_DAYS} days of delivery (the software trial may still be active, but the hardware return window has passed).` });
  const existing = (await shopStmts.rmaByOrder.all(order.id)).find(r => !['Rejected'].includes(r.status));
  if (existing) return res.json({ ok: true, rma_ref: existing.rma_ref, rma_id: existing.id, status: existing.status });
  const now = Date.now();
  const ref = genRef('RMA');
  const { id: id } = (await shopStmts.insertRma.get(ref, order.id, req.session.userId,
    String(req.body?.reason || '').slice(0, 500), 'Requested', now, now));
  notifyAdminForUser(`📦 RMA requested\nRMA: ${ref}\nOrder: ${order.order_ref}\nUser: ${req.session.username || req.session.userId}\nReason: ${req.body?.reason || '—'}`, req.session.userId).catch(() => {});
  log('info', 'RMA requested', { rmaRef: ref, orderId: order.id });
  res.json({ ok: true, rma_ref: ref, rma_id: id, status: 'Requested',
             required_photos: ['screen', 'back', 'powered_on'] });
});

app.get('/api/rma/mine', async (req, res) => {
  if (req.session.account_type !== 'public')
    return res.status(403).json({ error: 'public account required' });
  const rows = await Promise.all((await shopStmts.rmaByUser.all(req.session.userId)).map(async r => ({
    ...publicRma(r), photos: (await shopStmts.photosByRma.all(r.id)).map(p => ({ slot: p.slot, uploaded_at: p.uploaded_at })),
  })));
  res.json({ rmas: rows });
});

// Pre-RMA photo upload (customer). Body: { slot, base64, content_type }.
// Slots: screen | back | powered_on. Bytes stored ENC: in R2; DB holds the key.
app.post('/api/rma/:id/photos', async (req, res) => {
  if (req.session.account_type !== 'public')
    return res.status(403).json({ error: 'public account required' });
  const rma = (await shopStmts.rmaById.get(req.params.id));
  if (!rma || rma.user_id !== req.session.userId)
    return res.status(404).json({ error: 'RMA not found' });
  if (['Refunded', 'Rejected'].includes(rma.status))
    return res.status(409).json({ error: 'RMA is closed' });
  const slot = String(req.body?.slot || '');
  if (!['screen', 'back', 'powered_on'].includes(slot))
    return res.status(400).json({ error: 'slot must be screen|back|powered_on' });
  const b64 = req.body?.base64;
  if (!b64 || typeof b64 !== 'string')
    return res.status(400).json({ error: 'base64 image required' });
  let buf;
  try { buf = Buffer.from(b64, 'base64'); } catch { return res.status(400).json({ error: 'bad base64' }); }
  if (!buf.length || buf.length > 12 * 1024 * 1024)
    return res.status(400).json({ error: 'image must be 1 byte–12 MB' });
  const key = `rma/${rma.id}/${slot}-${Date.now()}.bin`;
  await r2Put(key, encryptBuffer(buf));
  (await shopStmts.insertRmaPhoto.run(rma.id, slot, key, String(req.body?.content_type || 'image/jpeg').slice(0, 60), Date.now()));
  // Once all three slots are present, advance the status.
  const have = new Set((await shopStmts.photosByRma.all(rma.id)).map(p => p.slot));
  if (['screen', 'back', 'powered_on'].every(s => have.has(s)) && rma.status === 'Requested')
    (await shopStmts.setRmaStatus.run('Photos_Submitted', Date.now(), rma.id));
  res.json({ ok: true, slot, have: [...have] });
});

};
