// helpers/signal-alert.js — admin alert with IP/UA context.
//
// A HELPER module, not a route module: it registers nothing. server.js owns the
// call sites (failed unlock, lock violations, unauthorized socket connections,
// route wirings) — only the function moves.
//
//   signalAlert   export   admin alert via notifyAdminExempt + browser push on sign-ins
//
// The block's own position (L299) sits BELOW its deps: notifyAdminExempt (var
// L601) and notifyPush (var L612) are bootstrap assignments after the block, so
// the require was RELOCATED to X in [L613, L2434] (fresh plan window; earliest
// consumer L2435). All deps are initialised above the wiring line and are never
// reassigned — passed BY VALUE (no getters, no refs object). reqClientIp is a
// hoisted function (L1793), usable from any line.
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ notifyAdminExempt, notifyPush, reqClientIp }) => {

// Admin alert with IP/UA context. When a `deviceId` is supplied, the alert is device-scoped and
// routes through notifyAdminExempt — the only signalAlert call sites that pass a deviceId are
// security/lineage/admin-critical events (lock violations, blocked reassignment, impersonation,
// device released by admin, ...). Suppressed for hybrid accounts since 2026-08-02 (hybrid scope
// = security class + logins only); non-hybrid public and admin-fleet devices keep the general
// admin group. Without a deviceId (logins, unlock, unauth access) it stays on the general group.
async function signalAlert(title, description, req, deviceId) {
  const ip  = reqClientIp(req) || 'unknown';   // prefers CF-Connecting-IP -> the real visitor
  const ua  = (req.headers?.['user-agent'] || 'unknown').slice(0, 200);
  await notifyAdminExempt(`${title}\n${description}\nIP: ${ip}\nUA: ${ua}`, deviceId);
  // Always-on browser push for successful sign-ins. 'login' is forced-on in
  // getNotifyPrefs() and bypasses the toggle gate in notifyPush().
  if (/Successful Login/i.test(title)) {
    (await notifyPush('login', '🔓 Dashboard sign-in', `${description.replace(/`/g, '')}  •  ${ip}`, '/'));
  }
}

return { signalAlert };

};
