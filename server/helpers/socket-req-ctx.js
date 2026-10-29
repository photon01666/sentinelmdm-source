// helpers/socket-req-ctx.js — synthesize req-like context from socket.
//
// A HELPER module, not a route module: it registers nothing.
//
//   socketReqCtx   export   build a req-like context object from a socket handshake
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 0 deps.  The call must sit at or after L1; the earliest consumer of
// the export is L4716, so at or before L4715.  L4606 satisfies both.
//
// relative requires: none

module.exports = () => {
// Synthesize a req-like context so signalAlert() can extract IP/UA from a socket handshake.
function socketReqCtx(socket) {
  return {
    headers: socket.handshake?.headers || {},
    ip: socket.handshake?.address,
    socket: { remoteAddress: socket.handshake?.address },
  };
}

  return {
    socketReqCtx,
  };
};