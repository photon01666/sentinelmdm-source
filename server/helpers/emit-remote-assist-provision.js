// helpers/emit-remote-assist-provision.js — emit RA provision event.
//
// A HELPER module, not a route module: it registers nothing.
//
//   emitRemoteAssistProvision   export   emit RA provision event to device
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 5 deps: XRAY_REMOTEASSIST_UUID (binding L3508), deviceEmit (binding L718), emitToDevice (binding L719), log (destructure L399), remoteAssistTransportCommand (destructure L3522).  The call must sit at or after L3523; the earliest consumer of
// the export is L3685, so at or before L3684.  L3524 satisfies both.
//
// REBASE note: The block lazily requires ./bastionClient — rebased to ../bastionClient
// (bastionClient.js lives at the server root; verified resolvable from helpers/).

module.exports = ({ XRAY_REMOTEASSIST_UUID, deviceEmit, emitToDevice, log, remoteAssistTransportCommand }) => {
// The Linux daemon uses its own provisioning contract, unrelated to the Windows
// 'set_remote_assist_transport' command above. This is the server-side implementation of
// that contract; without it the daemon never receives the event it waits on and its Hop-1
// tunnel never comes up. nodeIndex is always 0: every REALITY relay node routes the
// remote-assist VLESS UUID to the same support service, so there is no per-node
// reachability difference to rotate for. adminPubKey arms the daemon's standing Hop-2
// admin trust (no TTL, mirroring the Windows client) so automated support actions work
// without a human in the loop.
async function emitRemoteAssistProvision(deviceId, platform, forwardPort, socket) {
  if (platform === 'linux') {
    let adminPubKey = '';
    try {
      const bastionClient = require('../bastionClient');
      adminPubKey = (await bastionClient.adminSupportPubKey()) || '';
    } catch (e) {
      log('warn', 'remote-assist: failed to fetch bastion admin support pubkey for linux provision', { deviceId, error: e.message });
    }
    const payload = { egressUuid: XRAY_REMOTEASSIST_UUID, nodeIndex: 0, forwardPort, adminPubKey };
    if (socket) deviceEmit(socket, 'remote_assist_provision', payload);
    else emitToDevice(deviceId, 'remote_assist_provision', payload);
  } else {
    if (socket) deviceEmit(socket, 'command', remoteAssistTransportCommand(forwardPort));
    else emitToDevice(deviceId, 'command', remoteAssistTransportCommand(forwardPort));
  }
}

  return {
    emitRemoteAssistProvision,
  };
};