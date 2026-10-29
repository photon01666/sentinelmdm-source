// helpers/ts-api-token.js — Tailscale API bearer token exchange (OAuth
// client_credentials), cached until near expiry.
//
// A HELPER module, not a route module: it registers nothing. server.js owns
// the consumers. Only the token-fetch function moves.
//
//   getTsApiToken   export   returns a cached/refreshed Tailscale API token
//
// ctx is available at this module's own position in server.js (X >= L3056,
// X <= L3648) — nothing had to move (IN-PLACE splice).
//
// 3 ctx deps: TS_API_TOKEN, log — STABLE (const/destructure above the wiring
// line, never reassigned). getTsTokenCache / setTsTokenCache — LIVE read+write
// pair.
//
// getTsTokenCache/setTsTokenCache are a LIVE dep pair:
// _tsTokenCache (L3055) is runtime-reassigned at 1 site (L3071 — the cache
// swap after a successful token exchange). A by-value capture would return the
// initial `{ token: null }` forever and re-fetch on every call. The getter
// reads the top-level `let _tsTokenCache` at call time; the setter writes it
// back.
//   — R5: live vs stable documented here; R3: get/set are called ONLY inside
//     getTsApiToken's body, never at factory/module scope.
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ TS_API_TOKEN, getTsTokenCache, log, setTsTokenCache }) => {

async function getTsApiToken() {
  if (getTsTokenCache().token && Date.now() < getTsTokenCache().expiresAt - 60_000) return getTsTokenCache().token;
  if (!TS_API_TOKEN) return null;
  try {
    // Parse clientId from the tskey-client-<clientId>-<rest> format.
    const match = TS_API_TOKEN.match(/^tskey-client-([^-]+)-/);
    const clientId = match ? match[1] : '';
    const credentials = Buffer.from(`${clientId}:${TS_API_TOKEN}`).toString('base64');
    const resp = await fetch('https://api.tailscale.com/api/v2/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': `Basic ${credentials}` },
      body: 'grant_type=client_credentials',
    });
    if (!resp.ok) { log('warn', 'Tailscale API token exchange failed', { status: resp.status }); return null; }
    const data = /** @type {any} */ (await resp.json());
    setTsTokenCache({ token: data.access_token, expiresAt: Date.now() + (data.expires_in || 3600) * 1000 });
    return getTsTokenCache().token;
  } catch (e) { log('warn', 'Tailscale token exchange error', { err: e.message }); return null; }
}

return { getTsApiToken };

};