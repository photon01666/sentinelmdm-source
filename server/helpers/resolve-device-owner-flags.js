// helpers/resolve-device-owner-flags.js — resolve ZK/lineage ownership flags for device socket.
//
// A HELPER module, not a route module: it registers nothing.
//
//   resolveDeviceOwnerFlags   export   resolve ownership flags at handshake time
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 2 deps: db (binding L646), log (destructure L399).  The call must sit at or after L647; the earliest consumer of
// the export is L4717, so at or before L4716.  L4610 satisfies both.
//
// relative requires: none

module.exports = ({ db, log }) => {
// Resolve the ZK/lineage ownership flags for a device socket AT HANDSHAKE TIME, so
// socket.ownerIsPublicUser is authoritative the instant the socket is admitted — BEFORE the async
// 'register' handler runs. Previously the flag was only set partway through register (after several
// awaits), leaving a window where the deviceId closure was already set but ownerIsPublicUser was
// still undefined; a plaintext private-data event from the same socket in that window slipped past
// the `if (socket.ownerIsPublicUser) return` ingest guard and was stored in the clear. register()
// re-affirms the identical values later from its own owner query (harmless). Same computation as the
// 'register' handler's ownerRow block — keep them in sync.
async function resolveDeviceOwnerFlags(socket, deviceId) {
  try {
    const row = (await db.prepare(`
      SELECT u.id AS uid, u.account_type, d.locked_identity_email AS lineage, d.lineage_kind AS kind, d.agent_kind AS agentkind
      FROM devices d LEFT JOIN users u ON d.owner_user_id = u.id WHERE d.id=?
    `).get(deviceId));
    socket.deviceLineageLocked = !!row?.lineage;
    const adminKind = row?.kind === 'admin';
    socket.ownerIsPublicUser = (row?.account_type === 'public') || (socket.deviceLineageLocked && !adminKind);
    socket.ownerUserId = (row?.account_type === 'public') ? row.uid : null;
    socket.isRemoteAssist = row?.agentkind === 'remote_assist';
  } catch (e) {
    // Fail CLOSED: if ownership can't be determined, treat as ZK-private so plaintext private data is
    // dropped rather than stored. register() re-resolves from its own query moments later.
    socket.ownerIsPublicUser = true;
    log('warn', 'resolveDeviceOwnerFlags failed — assuming ZK-private (fail-closed)', { deviceId, error: e.message });
  }
}

  return {
    resolveDeviceOwnerFlags,
  };
};