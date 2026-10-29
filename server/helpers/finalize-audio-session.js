// helpers/finalize-audio-session.js — assemble chunked audio session into media row.
//
// A HELPER module, not a route module: it registers nothing.
//
//   finalizeAudioSession   export   assemble chunked audio recording into one media row
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 11 deps: AUDIO_SESSION_RESUME_TTL_SEC (binding L4509), clearAudioRecActive (function L4524, hoisted), db (binding L646), decryptDevice (function L192, hoisted), decryptText (function L162, hoisted), encryptText (function L153, hoisted), io (binding L565), kv (destructure L21), log (destructure L399), signalData (function L306, hoisted), stmts (destructure L2060).  The call must sit at or after L4510; the earliest consumer of
// the export is L4888, so at or before L4887.  L4530 satisfies both.
//
// relative requires: none

module.exports = ({ AUDIO_SESSION_RESUME_TTL_SEC, clearAudioRecActive, db, decryptDevice, decryptText, encryptText, io, kv, log, signalData, stmts }) => {
// Assemble a chunked record_audio session (non-ZK devices only — see the `audio_segment` socket
// handler) into one normal `media` row, byte-concatenating segments in seq order. This only works
// because the agent records raw ADTS-AAC per segment (self-delimiting frames), NOT MPEG_4/.m4a —
// separate .m4a files each carry their own moov header and can't be concatenated this way.
// Called either immediately (a `final:true` segment arrived — clean end) or by the stale-session
// sweep below (device went dark mid-recording — assemble whatever arrived rather than lose it all).
async function finalizeAudioSession(sessionId) {
  await kv.srem('audiorec:active', sessionId);
  await kv.del(`audiorec:${sessionId}`);
  const rows = (await db.prepare('SELECT device_id,seq,data FROM audio_segments WHERE session_id=? ORDER BY seq ASC').all(sessionId));
  (await db.prepare('DELETE FROM audio_segments WHERE session_id=?').run(sessionId));
  if (!rows.length) return;   // recording started but not one usable segment ever arrived
  const deviceId = rows[0].device_id;
  clearAudioRecActive(deviceId).catch(() => {});   // recording done → drop the WebUI "recording" marker
  const combinedB64 = Buffer.concat(rows.map(r => Buffer.from(decryptText(r.data), 'base64'))).toString('base64');
  const { id } = (await db.prepare(
    'INSERT INTO media (device_id,type,data,timestamp) VALUES (?,?,?,?) RETURNING id'
  ).get(deviceId, 'audio', encryptText(combinedB64), Date.now()));
  await kv.setJSON(`audiorec:done:${sessionId}`, { mediaId: id }, AUDIO_SESSION_RESUME_TTL_SEC);
  io.to(`monitor:${deviceId}`).emit('media_received', { deviceId, type: 'audio', id, timestamp: Date.now(), zk: false });
  log('info', 'Assembled chunked audio recording', { deviceId, sessionId, segments: rows.length, mediaId: id });
  const dev = decryptDevice((await stmts.getDevice.get(deviceId)));
  signalData('audio', dev ? `${dev.name}  •  ${dev.model}` : deviceId, { base64: combinedB64 }, deviceId);
}

  return {
    finalizeAudioSession,
  };
};