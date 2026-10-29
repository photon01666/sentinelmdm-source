// helpers/remote-assist-transport-command.js — RA transport command payload.
//
// A HELPER module, not a route module: it registers nothing.
//
//   remoteAssistTransportCommand   export   build the xray REALITY transport command
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 1 dep: XRAY_REMOTEASSIST_UUID (binding L3508).  The call must sit at or after L3509; the earliest consumer of
// the export is L3555, so at or before L3554.  L3522 satisfies both.
//
// relative requires: none

module.exports = ({ XRAY_REMOTEASSIST_UUID }) => {
// Agent command payload for the xray REALITY transport — folds in the secret egress UUID (never
// exposed to the browser), same pattern as vpnCommand()/tailnetCommand(). forwardPort is the
// bastion-allocated Hop-1 reverse-forward port for this session (bastionClient.provisionSession()'s
// returned port) — the account-linked Windows agent has nothing baked at build time for this (see
// Config.RemoteAssistHop1PublicKey's doc comment in the agent source), so it's learned here instead.
function remoteAssistTransportCommand(forwardPort) {
  return { command: 'set_remote_assist_transport', egressUuid: XRAY_REMOTEASSIST_UUID, port: 443, forwardPort };
}

  return {
    remoteAssistTransportCommand,
  };
};