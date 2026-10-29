// routes/support-access.js — Account support-access (grant/revoke delegate access).
module.exports = ({ app, AUTH_SCHEME_PREHASH, PLAN_KEY_BY_PRICE, STRIPE_PLANS, bcrypt, db,
                    encryptText, getUserSubscriptionRow, isValidWrapEnvelope, log,
                    looksLikeAuthHash, looksLikeAuthSalt, notifyAdminForUser, requireAuth,
                    revokeUserSessions, stmts, stripe, upsertStripeSubscription,
                    SUPPORT_DELEGATE_FULL_PERMS }) => {
const supportDelegateLogin = (ownerId) => `support+u${ownerId}@sentinelmdm-support.local`;

app.post('/api/account/support-access', requireAuth, async (req, res) => {
  if (req.session?.account_type !== 'public' || !req.session.userId)
    return res.status(403).json({ error: 'Public account required' });
  const owner = (await db.prepare('SELECT id, zk_public_key FROM users WHERE id=?').get(req.session.userId));
  if (!owner) return res.status(404).json({ error: 'Account not found' });
  if (!owner.zk_public_key) return res.status(400).json({ error: 'Your account has no encryption key yet — sign in again first.' });

  const { auth_hash, auth_salt, zk_encrypted_priv_key, zk_salt, support_code_payload, support_code_dek_support } = req.body || {};
  if (!looksLikeAuthHash(auth_hash) || !looksLikeAuthSalt(auth_salt))
    return res.status(400).json({ error: 'Invalid credential data — please reload and try again.' });
  if (typeof zk_encrypted_priv_key !== 'string' || !zk_encrypted_priv_key || typeof zk_salt !== 'string' || !zk_salt)
    return res.status(400).json({ error: 'Invalid encryption data — please reload and try again.' });
  // The code, delivered to admin via GENUINE E2E (client-side AES-256-GCM under a random DEK,
  // DEK ECDH-wrapped to the shared Support pubkey) — same wire format as the E2E Conversations
  // chat's dek_support. Server stores/relays this ciphertext; it can never decrypt it. Requires
  // Support E2E to be enabled — if it isn't, there's no key to encrypt to, so refuse the grant
  // rather than accept a code admin has no way to ever receive.
  if (typeof support_code_payload !== 'string' || support_code_payload.length < 1 || support_code_payload.length > 2000)
    return res.status(400).json({ error: 'Invalid support code data — please reload and try again.' });
  if (!isValidWrapEnvelope(support_code_dek_support))
    return res.status(400).json({ error: 'Invalid support code data — please reload and try again.' });
  const supportPubRow = (await db.prepare("SELECT value FROM settings WHERE key='support_zk_public'").get());
  if (!supportPubRow?.value)
    return res.status(400).json({ error: 'Support E2E encryption isn\'t enabled yet — contact us so we can turn it on before you grant access.' });

  const existing = (await db.prepare('SELECT id FROM users WHERE parent_owner_id=? AND is_support_delegate=1').get(owner.id));
  if (existing) return res.status(409).json({ error: 'Support access is already active. Revoke it first to set a new code.' });

  const login = supportDelegateLogin(owner.id);
  if ((await stmts.userByName.get(login))) return res.status(409).json({ error: 'A stale support identity exists — revoke support access, then try again.' });

  // Seed full perms over the owner's current devices. This stored map is only a starting point —
  // applySupportDelegatePerms() (requireAuth) rebuilds it live on every request, so devices added
  // AFTER the grant ARE covered without a revoke+re-grant. Do not "optimise" that away by trusting
  // this snapshot: it goes stale the moment the owner enrolls another device.
  const devs = (await db.prepare('SELECT id FROM devices WHERE owner_user_id=?').all(owner.id));
  const permsMap = {};
  for (const d of devs) permsMap[d.id] = { ...SUPPORT_DELEGATE_FULL_PERMS };

  const hash = bcrypt.hashSync(auth_hash, 10);
  const { id } = (await db.prepare(
    `INSERT INTO users (username,email,password_hash,role,permissions,created_at,pw_scheme,auth_salt,
                         account_type,parent_owner_id,status,zk_public_key,zk_encrypted_priv_key,zk_salt,is_support_delegate,
                         support_code_payload,support_code_dek_support)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) RETURNING id`
  ).get(login, login, hash, 'user', encryptText(JSON.stringify(permsMap)), Date.now(), AUTH_SCHEME_PREHASH, auth_salt,
        'business_sub', owner.id, 'active', owner.zk_public_key, zk_encrypted_priv_key, zk_salt, 1,
        support_code_payload, JSON.stringify(support_code_dek_support)));
  log('info', 'Support access granted', { delegateUserId: id, ownerUserId: owner.id, devices: devs.length });
  notifyAdminForUser(`🛟 Support Access Granted\n"${req.session.username}" granted SentinelMDM support access (${devs.length} device(s)).`, req.session.userId);
  res.json({ ok: true, login, granted_devices: devs.length });
});

app.get('/api/account/support-access', requireAuth, async (req, res) => {
  if (req.session?.account_type !== 'public') return res.status(403).json({ error: 'Public account required' });
  const row = (await db.prepare('SELECT id, username, created_at, permissions FROM users WHERE parent_owner_id=? AND is_support_delegate=1').get(req.session.userId));
  if (!row) return res.json({ active: false });
  // LIVE count, not the grant-time snapshot in row.permissions — support access covers every
  // device the owner currently owns (see applySupportDelegatePerms), so the panel must say so.
  const { n: devices } = (await db.prepare('SELECT COUNT(*) AS n FROM devices WHERE owner_user_id=?').get(req.session.userId));
  res.json({ active: true, login: row.username, created_at: row.created_at, devices: Number(devices) || 0 });
});

app.delete('/api/account/support-access', requireAuth, async (req, res) => {
  if (req.session?.account_type !== 'public') return res.status(403).json({ error: 'Public account required' });
  const row = (await db.prepare('SELECT id, username FROM users WHERE parent_owner_id=? AND is_support_delegate=1').get(req.session.userId));
  if (!row) return res.status(404).json({ error: 'No support access is active.' });

  // Hybrid Managed's whole product IS support access — revoking it while still subscribed can't
  // leave the plan half-delivered, so it forces a downgrade to Unlimited (same device entitlement,
  // just without the managed-support layer) rather than letting them keep Hybrid pricing with
  // nothing to back it. proration_behavior:'none' deliberately gives NO credit for the unused
  // time — closes an abuse loop (subscribe → grant → use support once → revoke → refund).
  const sub = (await getUserSubscriptionRow(req));
  let downgraded = false;
  if (sub && sub.stripe_subscription_id && ['trialing', 'active', 'past_due'].includes(sub.status)) {
    const planKey = PLAN_KEY_BY_PRICE[sub.price_id];
    if (planKey && planKey.startsWith('hybrid') && stripe) {
      const unlimitedPriceId = STRIPE_PLANS['unlimited_monthly'];
      try {
        const liveSub = await stripe.subscriptions.retrieve(sub.stripe_subscription_id);
        const itemId = liveSub.items.data[0].id;
        const updated = await stripe.subscriptions.update(sub.stripe_subscription_id, {
          items: [{ id: itemId, price: unlimitedPriceId }],
          proration_behavior: 'none',
        });
        (await upsertStripeSubscription(updated, sub.email));
        downgraded = true;
        log('info', 'Hybrid subscription auto-downgraded on support-access revoke', { ownerUserId: req.session.userId, subId: sub.stripe_subscription_id });
      } catch (e) {
        log('error', 'Auto-downgrade on support-access revoke failed', { err: e.message, ownerUserId: req.session.userId });
        return res.status(500).json({ error: 'Could not revoke — downgrading your plan failed, please try again or contact support.' });
      }
    }
  }

  (await db.prepare('DELETE FROM users WHERE id=?').run(row.id));
  (await revokeUserSessions(row.id));
  log('info', 'Support access revoked', { delegateUserId: row.id, by: req.session.userId, downgraded });
  notifyAdminForUser(`🛟 Support Access Revoked\n"${req.session.username}" revoked SentinelMDM support access.${downgraded ? ' Hybrid Managed auto-downgraded to Unlimited (no proration credit).' : ''}`, req.session.userId);
  res.json({ ok: true, downgraded });
});

};
