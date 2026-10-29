// Email HTML templates — pure strings, zero runtime dependencies.
// Extracted from server.js to keep template markup out of the main server file.

const TRACKER_DOMAIN = process.env.TRACKER_DOMAIN || 'localhost:3000';
const TRACKER_REGISTER_URL = `https://${TRACKER_DOMAIN}/register`;
const TRACKER_LOGIN_URL = `https://${TRACKER_DOMAIN}/login`;
const SECURE_ACCOUNT_URL = `${TRACKER_LOGIN_URL}?next=${encodeURIComponent('/?secure=account')}`;
const SETUP_GUIDE_URL = (process.env.PUBLIC_SITE_URL || 'http://localhost:3000') + '/docs/device-owner-setup';

function esc(s) { return String(s || '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

const DEFAULT_APPROVAL_SUBJECT = 'Your SentinelMDM account has been approved';

const DEFAULT_APPROVAL_TEMPLATE = `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><style>
  body{font-family:Arial,sans-serif;background:#0a0d12;color:#e2e8f0;margin:0;padding:0}
  .wrap{max-width:560px;margin:40px auto;background:#0d1117;border:1px solid rgba(255,255,255,.1);border-radius:12px;overflow:hidden}
  .hdr{background:#0d6efd;padding:32px;text-align:center}
  .hdr img{height:48px;width:auto}
  .hdr h1{color:#fff;font-size:1.3rem;margin:12px 0 0}
  .body{padding:32px}
  .body p{line-height:1.7;margin:0 0 16px;color:#cbd5e1}
  .step{display:flex;gap:16px;margin:20px 0}
  .num{flex-shrink:0;width:32px;height:32px;background:rgba(13,110,253,.15);border:1px solid rgba(13,110,253,.3);border-radius:50%;display:flex;align-items:center;justify-content:center;color:#3d8bfd;font-weight:700;font-size:.85rem}
  .step-body h3{margin:0 0 4px;color:#f1f5f9;font-size:.95rem}
  .step-body p{margin:0;font-size:.85rem;color:#94a3b8}
  .cta{text-align:center;margin:32px 0 24px}
  .cta a{background:#0d6efd;color:#fff;text-decoration:none;padding:14px 32px;border-radius:8px;font-weight:600;font-size:1rem;display:inline-block}
  .note{background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.08);border-radius:8px;padding:14px;margin:20px 0;font-size:.8rem;color:#94a3b8}
  .ftr{text-align:center;padding:20px 32px;font-size:.75rem;color:#475569;border-top:1px solid rgba(255,255,255,.06)}
</style></head>
<body>
<div class="wrap">
  <div class="hdr">
    <h1>Account Approved</h1>
  </div>
  <div class="body">
    <p>Hi <strong style="color:#f1f5f9">{{username}}</strong>,</p>
    <p>Good news — your SentinelMDM account has been <strong style="color:#f1f5f9">approved</strong> and is now active. You're all set — just sign in to your dashboard.</p>

    <div class="cta">
      <a href="{{login_url}}">Sign in to your dashboard →</a>
    </div>

    <p style="text-align:center;margin:0 0 24px">
      New here? <a href="{{setup_url}}" style="color:#3d8bfd">Read the device setup guide →</a> to enroll your first device.
    </p>

    <div class="note">
      Sign in with <strong style="color:#e2e8f0">{{email}}</strong> and the password you chose when you registered. Your password is your zero-knowledge encryption key — it can't be reset or recovered, so keep it somewhere safe.
    </div>

    <p>If you have any questions, just reply to this email and we'll help you get set up.</p>
    <p style="margin-bottom:0">— The SentinelMDM Team</p>
  </div>
  <div class="ftr">SentinelMDM · Zero-Knowledge Device Management · <a href="{{login_url}}" style="color:#3d8bfd">{{tracker_domain}}</a></div>
</div>
</body></html>`;

const DEFAULT_PURCHASE_SUBJECT = 'Welcome to SentinelMDM — your 30-day free trial';
const DEFAULT_PURCHASE_TEMPLATE = `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><style>
  body{font-family:Arial,sans-serif;background:#0a0d12;color:#e2e8f0;margin:0;padding:0}
  .wrap{max-width:560px;margin:40px auto;background:#0d1117;border:1px solid rgba(255,255,255,.1);border-radius:12px;overflow:hidden}
  .hdr{background:#0d6efd;padding:32px;text-align:center}
  .hdr h1{color:#fff;font-size:1.3rem;margin:0}
  .body{padding:32px}
  .body p{line-height:1.7;margin:0 0 16px;color:#cbd5e1}
  .step{display:flex;gap:16px;margin:20px 0}
  .num{flex-shrink:0;width:32px;height:32px;background:rgba(13,110,253,.15);border:1px solid rgba(13,110,253,.3);border-radius:50%;display:flex;align-items:center;justify-content:center;color:#3d8bfd;font-weight:700;font-size:.85rem}
  .step-body h3{margin:0 0 4px;color:#f1f5f9;font-size:.95rem}
  .step-body p{margin:0;font-size:.85rem;color:#94a3b8}
  .cta{text-align:center;margin:32px 0 24px}
  .cta a{background:#0d6efd;color:#fff;text-decoration:none;padding:14px 32px;border-radius:8px;font-weight:600;font-size:1rem;display:inline-block}
  .note{background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.08);border-radius:8px;padding:14px;margin:20px 0;font-size:.8rem;color:#94a3b8}
  .ftr{text-align:center;padding:20px 32px;font-size:.75rem;color:#475569;border-top:1px solid rgba(255,255,255,.06)}
</style></head>
<body>
<div class="wrap">
  <div class="hdr"><h1>Welcome — your free trial is ready</h1></div>
  <div class="body">
    <p>Hi <strong style="color:#f1f5f9">{{name}}</strong>,</p>
    <p><strong style="color:#f1f5f9">No payment was taken</strong> — every new account starts with a <strong style="color:#f1f5f9">30-day free trial</strong>. Follow the steps below to create your dashboard account; your free trial begins the moment your first device connects.</p>

    <div class="step">
      <div class="num">1</div>
      <div class="step-body">
        <h3>Create your account</h3>
        <p>Visit the registration page and sign up using <strong style="color:#e2e8f0">{{email}}</strong> — the exact email address you signed up with.</p>
      </div>
    </div>

    <div class="step">
      <div class="num">2</div>
      <div class="step-body">
        <h3>Set your encryption key</h3>
        <p>Choose a strong password on the registration page. This password is your zero-knowledge encryption key — it cannot be reset or recovered. Store it somewhere safe.</p>
      </div>
    </div>

    <div class="step">
      <div class="num">3</div>
      <div class="step-body">
        <h3>Sign in and enroll your device</h3>
        <p>Once registered, sign in to your dashboard and follow the setup guide to enroll your first device — it will appear live within seconds.</p>
      </div>
    </div>

    <div class="cta"><a href="{{register_url}}">Create your account →</a></div>

    <div class="note">
      <strong style="color:#e2e8f0">Important:</strong> Use exactly <strong style="color:#e2e8f0">{{email}}</strong> when registering. Your account, license, and enrolled devices are bound to this address.
    </div>

    <p>If you have any questions, reply to this email and we'll help you get set up.</p>
    <p style="margin-bottom:0">— The SentinelMDM Team</p>
  </div>
  <div class="ftr">SentinelMDM · Zero-Knowledge Device Management · <a href="{{register_url}}" style="color:#3d8bfd">{{tracker_domain}}</a></div>
</div>
</body></html>`;

function renderAlertEmailHtml(title, message) {
  const safeMsg = esc(String(message || '')).replace(/\n/g, '<br>');
  return `
  <div style="font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;max-width:520px;margin:0 auto;background:#0d1117;color:#e6edf3;border-radius:12px;overflow:hidden;border:1px solid #30363d">
    <div style="background:#161b22;padding:16px 20px;border-bottom:1px solid #30363d">
      <span style="font-weight:700;font-size:16px;color:#fff">SentinelMDM</span>
    </div>
    <div style="padding:20px">
      <div style="font-size:16px;font-weight:600;margin-bottom:10px">${esc(title)}</div>
      <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px 14px;font-size:14px;line-height:1.6;color:#c9d1d9">${safeMsg}</div>
      <p style="margin:16px 0 0;font-size:12px;color:#8b949e;line-height:1.5">
        This alert contains <strong>metadata only</strong> — event type, device, and time.
        Photos, audio, messages and other captured data are end-to-end encrypted and can only be
        viewed by signing in to your dashboard. They are never sent by email.
      </p>
      <a href="${TRACKER_LOGIN_URL}" style="display:inline-block;margin-top:16px;background:#1f6feb;color:#fff;text-decoration:none;font-weight:600;font-size:14px;padding:10px 18px;border-radius:8px">Open dashboard &rarr;</a>
    </div>
    <div style="background:#161b22;padding:12px 20px;border-top:1px solid #30363d;font-size:11px;color:#6e7681">
      You're receiving this because email alerts are enabled for your account. They can be turned off in Notification Preferences.
    </div>
  </div>`;
}

function renderAiReportEmailHtml(title, deviceName, bodyText) {
  const safeBody = esc(String(bodyText || '')).replace(/\n/g, '<br>');
  return `
  <div style="font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;max-width:560px;margin:0 auto;background:#0d1117;color:#e6edf3;border-radius:12px;overflow:hidden;border:1px solid #30363d">
    <div style="background:#161b22;padding:16px 20px;border-bottom:1px solid #30363d">
      <span style="font-weight:700;font-size:16px;color:#fff">SentinelMDM</span>
      <span style="color:#8b949e;font-size:13px;margin-left:6px">AI report</span>
    </div>
    <div style="padding:20px">
      <div style="font-size:16px;font-weight:600;margin-bottom:4px">${esc(title)}</div>
      <div style="font-size:13px;color:#8b949e;margin-bottom:12px">${esc(deviceName || '')}</div>
      <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:14px 16px;font-size:14px;line-height:1.7;color:#c9d1d9">${safeBody}</div>
      <a href="${TRACKER_LOGIN_URL}" style="display:inline-block;margin-top:16px;background:#1f6feb;color:#fff;text-decoration:none;font-weight:600;font-size:14px;padding:10px 18px;border-radius:8px">Open dashboard &rarr;</a>
    </div>
    <div style="background:#161b22;padding:12px 20px;border-top:1px solid #30363d;font-size:11px;color:#6e7681">
      You're receiving this because AI report emails are enabled for this device. They can be turned off in Notification Preferences.
    </div>
  </div>`;
}

function renderLoginEmailHtml(username, ip, when) {
  return `
  <div style="font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;max-width:520px;margin:0 auto;background:#0d1117;color:#e6edf3;border-radius:12px;overflow:hidden;border:1px solid #30363d">
    <div style="background:#161b22;padding:16px 20px;border-bottom:1px solid #30363d">
      <span style="font-weight:700;font-size:16px;color:#fff">SentinelMDM</span>
      <span style="color:#8b949e;font-size:13px;margin-left:6px">Security alert</span>
    </div>
    <div style="padding:20px">
      <div style="font-size:16px;font-weight:600;margin-bottom:10px">New sign-in to your account</div>
      <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px 14px;font-size:14px;line-height:1.9;color:#c9d1d9">
        <div><span style="color:#8b949e">Account:</span> ${esc(username)}</div>
        <div><span style="color:#8b949e">Time:</span> ${esc(when)}</div>
        <div><span style="color:#8b949e">IP address:</span> ${esc(ip)}</div>
      </div>
      <p style="margin:16px 0 0;font-size:13px;color:#c9d1d9;line-height:1.6">
        If this was you, no action is needed. <strong>If you don't recognise this sign-in</strong>,
        <a href="${SECURE_ACCOUNT_URL}" style="color:#f0856f;font-weight:600">secure your account now</a> —
        because your data is end-to-end encrypted, this rotates your keys and signs out every session
        (the intruder's included). You'll set up again with the same email.
      </p>
      <div style="margin-top:16px">
        <a href="${SECURE_ACCOUNT_URL}" style="display:inline-block;background:#b42318;color:#fff;text-decoration:none;font-weight:600;font-size:14px;padding:10px 18px;border-radius:8px">Secure my account &rarr;</a>
        <a href="${TRACKER_LOGIN_URL}" style="display:inline-block;margin-left:6px;color:#8b949e;text-decoration:none;font-size:13px;padding:10px 6px">Open dashboard</a>
      </div>
    </div>
    <div style="background:#161b22;padding:12px 20px;border-top:1px solid #30363d;font-size:11px;color:#6e7681">
      You're receiving this because someone signed in to your SentinelMDM account. Sign-in alerts are always sent for your security.
    </div>
  </div>`;
}

function renderEmailVerifyHtml(code) {
  return `
  <div style="font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;max-width:480px;margin:0 auto;background:#0d1117;color:#e6edf3;border-radius:12px;overflow:hidden;border:1px solid #30363d">
    <div style="background:#161b22;padding:16px 20px;border-bottom:1px solid #30363d">
      <span style="font-weight:700;font-size:16px;color:#fff">SentinelMDM</span>
    </div>
    <div style="padding:22px 20px">
      <div style="font-size:16px;font-weight:600;margin-bottom:8px">Verify your email</div>
      <p style="font-size:14px;line-height:1.6;color:#c9d1d9;margin:0 0 16px">Enter this code to confirm you own this email address. It expires in 15 minutes.</p>
      <div style="font-size:30px;font-weight:700;letter-spacing:8px;text-align:center;background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;color:#fff">${esc(code)}</div>
      <p style="font-size:12px;color:#8b949e;line-height:1.5;margin:16px 0 0">If you didn't request this, you can ignore this email. Your address is the identity your devices stay locked to, so this code is the only way to prove ownership.</p>
    </div>
  </div>`;
}

module.exports = {
  TRACKER_DOMAIN,
  TRACKER_REGISTER_URL,
  TRACKER_LOGIN_URL,
  SECURE_ACCOUNT_URL,
  SETUP_GUIDE_URL,
  esc,
  DEFAULT_APPROVAL_SUBJECT,
  DEFAULT_APPROVAL_TEMPLATE,
  DEFAULT_PURCHASE_SUBJECT,
  DEFAULT_PURCHASE_TEMPLATE,
  renderAlertEmailHtml,
  renderAiReportEmailHtml,
  renderLoginEmailHtml,
  renderEmailVerifyHtml,
  PUBLIC_USER_DEFAULT_FEATURES: {
    location: true, photos: true, audio: true, screenshots: true,
    stream: true, network: true, files: true, calls: true, sms: true,
    apps: true, contacts: true, notifications: true,
    keylogs: true, screentext: true, geofences: true,
    schedules: true, timeline: true, commands: true,
    connect: true, security: true,
    edr: true, applocker: true,
    file_backup: true, s3_drive: true, bitlocker: true,
  },
};
