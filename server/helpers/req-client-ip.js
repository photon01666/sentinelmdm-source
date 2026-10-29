// helpers/req-client-ip.js — real client IP behind Cloudflare/Traefik.
//
// A HELPER module, not a route module: it registers nothing and has NO ctx deps
// (pure function of its argument) — hence it is wired ABOVE its earliest eager
// consumer (the nodered-alert wiring, originally L227): several load-time ctx
// captures read it (nodered-alert L227, signal-alert L508), so a const below
// them would boot-TDZ. Relocated by the Batch-B 3-step (apply-move in place,
// then cut+paste the single require line above L227).
//
//   reqClientIp   export   prefers CF-Connecting-IP -> XFF[0] -> socket -> req.ip
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = () => {

function reqClientIp(req) {
  // Behind Cloudflare (edge -> cloudflared tunnel -> Traefik -> here) the first
  // x-forwarded-for hop is a Cloudflare/tunnel address, NOT the visitor. Cloudflare
  // always sends the true client in CF-Connecting-IP, so prefer it. The origin is only
  // reachable via the tunnel, so external clients cannot spoof this header.
  return (req.headers?.['cf-connecting-ip'] || '').trim()
    || ((req.headers?.['x-forwarded-for'] || '').split(',')[0].trim())
    || req.socket?.remoteAddress || req.ip || null;
}

return { reqClientIp };

};
