// routes/push.js — Web Push + FCM token subscription endpoints (authed).
// Extracted from server.js. Registered via require('./routes/push')({ app, db }) at the same point
// the routes previously sat (after app.use(requireAuth)). Deps: just app + db (raw db.prepare);
// each route is scoped to req.session.userId so one account can't touch another's subscriptions.

module.exports = function registerPushRoutes({ app, db }) {
  app.post('/api/push/subscribe', async (req, res) => {
    const { endpoint, keys } = req.body || {};
    if (!endpoint || !keys?.p256dh || !keys?.auth) return res.status(400).json({ error: 'Invalid subscription' });
    try {
      (await db.prepare('INSERT INTO push_subscriptions (user_id,endpoint,p256dh,auth) VALUES (?,?,?,?) ON CONFLICT(endpoint) DO UPDATE SET user_id=excluded.user_id, p256dh=excluded.p256dh, auth=excluded.auth')
        .run(req.session.userId, endpoint, keys.p256dh, keys.auth));
      res.json({ ok: true });
    } catch(e) { res.status(500).json({ error: 'Failed to save' }); }
  });

  app.delete('/api/push/unsubscribe', async (req, res) => {
    const { endpoint } = req.body || {};
    if (endpoint) (await db.prepare('DELETE FROM push_subscriptions WHERE user_id=? AND endpoint=?').run(req.session.userId, endpoint));
    res.json({ ok: true });
  });

  app.post('/api/push/fcm-token', async (req, res) => {
    const { token } = req.body || {};
    if (!token) return res.status(400).json({ error: 'token required' });
    try {
      (await db.prepare('INSERT INTO fcm_tokens (user_id,token) VALUES (?,?) ON CONFLICT(token) DO UPDATE SET user_id=excluded.user_id').run(req.session.userId, token));
      res.json({ ok: true });
    } catch(e) { res.status(500).json({ error: 'Failed to save' }); }
  });

  // Companion-app "push off" — drop this device's FCM token so the server stops
  // sending to it. Scoped to the session user so one account can't unregister another's.
  app.delete('/api/push/fcm-token', async (req, res) => {
    const { token } = req.body || {};
    if (!token) return res.status(400).json({ error: 'token required' });
    try {
      (await db.prepare('DELETE FROM fcm_tokens WHERE user_id=? AND token=?').run(req.session.userId, token));
      res.json({ ok: true });
    } catch(e) { res.status(500).json({ error: 'Failed to delete' }); }
  });
};
