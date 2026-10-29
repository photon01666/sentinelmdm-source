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
// Linux's sentineld daemon uses its OWN provisioning contract, unrelated to the Windows
// 'set_remote_assist_transport' command above — see remoteAssistProvisionEvent's doc comment in
// swarm-stacks/ssh-bastion-client-linux/sentineld/cmd/sentineld/daemon.go. This is the server-side
// implementation of that contract; without it the Linux daemon never receives the event it's
// waiting on and its Hop-1 tunnel never comes up (found live 2026-07-29 — see docs/ARCHITECTURE.md). nodeIndex is always 0: every REALITY relay node routes
// the remoteassist@sentinel VLESS UUID straight to the same bastion:22022 service over the swarm
// overlay mesh (xray-relay config.template.json's 'to-bastion-ssh' outbound), so unlike the tracker
// control channel there's no per-node reachability difference to rotate for. adminPubKey arms the
// daemon's STANDING Hop-2 admin trust (no TTL, mirrors Windows' baked-in ADMIN_SUPPORT_KEY) so
// bastion-initiated automated actions (IT Audit, fleet bash exec) work with no human in the loop.
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