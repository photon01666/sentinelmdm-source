// routes/unlock-page.js — GET /unlock, the encryption-passphrase unlock page (pre-auth,
// served while the server is locked). Extracted verbatim from server.js; registered in place
// immediately after app.use(requireUnlocked) and well before app.use(requireAuth), so the
// ordering that keeps this page reachable while locked is unchanged. The block's only module-
// scope dep besides app is sendAuthPage (server.js) — shared with routes/login.js and
// routes/register.js, so it stays in server.js and is injected by value; it is a plain
// function declaration that is never rebound, so the by-value capture is stable.
module.exports = ({ app, sendAuthPage }) => {
app.get('/unlock', (_req, res) => {
  sendAuthPage(res, 'unlock.html');
});
};
