module.exports = ({ app, STRIPE_WEBHOOK_SECRET, express, log, notifyAdminForUser, sendPurchaseEmail, stripe, upsertStripeSubscription }) => {
// Stripe webhook — registered BEFORE express.json so it receives the raw body for
// signature verification. If no webhook secret is set yet, accept unverified (dev only).
app.post('/api/stripe/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  if (!stripe) return res.status(503).end();
  // SECURITY: fail CLOSED. Never accept an unverified (JSON.parse'd) event — without the
  // webhook secret a client could forge checkout/subscription events. Require the secret.
  if (!STRIPE_WEBHOOK_SECRET) {
    log('warn', 'Stripe webhook rejected — STRIPE_WEBHOOK_SECRET not configured (cannot verify signature)');
    return res.status(503).end();
  }
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], STRIPE_WEBHOOK_SECRET);
  } catch (e) { log('warn', 'Stripe webhook verify failed', { err: e.message }); return res.status(400).send(`Webhook Error: ${e.message}`); }
  try {
    const obj = /** @type {any} */ (event.data && event.data.object);
    if (event.type === 'checkout.session.completed' && obj && obj.subscription) {
      const email = (obj.customer_details && obj.customer_details.email) || obj.customer_email || '';
      const cref  = parseInt(obj.client_reference_id, 10);  // set when checkout started from the logged-in dashboard
      stripe.subscriptions.retrieve(obj.subscription).then(async sub => {
        (await upsertStripeSubscription(sub, email, Number.isInteger(cref) ? cref : null));
        if (email) sendPurchaseEmail(email, (obj.customer_details && obj.customer_details.name) || '').catch(() => {});
        // Free trials never grant hybrid, so this alert is suppressed for public accounts per the
        // alert policy; a null/unknown user just routes to the general admin group.
        notifyAdminForUser(`💳 New 30-day trial started — ${email || 'unknown'}`, Number.isInteger(cref) ? cref : null).catch(() => {});
      }).catch(e => log('warn', 'subscription retrieve failed', { err: e.message }));
    } else if (obj && (event.type === 'customer.subscription.created' || event.type === 'customer.subscription.updated' || event.type === 'customer.subscription.deleted')) {
      const muid = obj.metadata ? parseInt(obj.metadata.user_id, 10) : NaN;  // set via subscription_data.metadata at checkout
      (await upsertStripeSubscription(obj, null, Number.isInteger(muid) ? muid : null));
    }
  } catch (e) { log('warn', 'Stripe webhook handler error', { err: e.message }); }
  res.json({ received: true });
});
};
