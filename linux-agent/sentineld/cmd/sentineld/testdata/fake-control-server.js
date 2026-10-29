// Fake control-channel server for daemon_test.go's integration test — drives a fixed sequence
// (accept auth -> wait for register -> emit "registered" -> emit hop2_session_open -> emit
// hop2_session_close) so the Go test can observe runControlLoop's reaction to each real event
// without needing a live production bastion. Deliberately does NOT emit remote_assist_provision
// (see daemon_test.go's comment: that path needs a real REALITY node to test meaningfully and
// isn't safe/possible to fake locally without either hanging or sending live traffic to
// production nodes with bogus credentials — it's covered separately by internal/xraytransport's
// and internal/hop1's own component tests instead).
const { Server } = require("socket.io");

const port = parseInt(process.argv[2] || "34568", 10);
const armPubKey = process.argv[3] || "ssh-ed25519 AAAAFAKE test-hop2-key";
// Optional 4th arg: owner's ZK public key (base64 DER SPKI) — when present, the "registered" ack
// includes it (mirrors server.js's registeredPayload.zkPubKey), which should make the daemon route
// its device_status heartbeat through "zk_data" (ZK-envelope-encrypted) instead of plaintext
// "device_status" — see daemon_test.go's TestRunControlLoop_DeviceStatusZkRouting.
const ownerZkPubKey = process.argv[4] || null;

const io = new Server(port, { path: "/socket.io" });

let connectionCount = 0;
io.use((socket, next) => {
  connectionCount++;
  const auth = socket.handshake.auth || {};
  const hasTicketAuth = !!auth.enrollmentTicket;
  const hasSignedAuth = !!auth.signature && !!auth.timestamp;
  if (!auth.deviceId || (!hasTicketAuth && !hasSignedAuth)) {
    return next(new Error("malformed auth payload"));
  }
  // Regression guard (2026-08-17): after the first successful registration the daemon must DROP
  // the spent enrollment ticket from its auth payload — a stale pre-built payload re-presented on
  // every reconnect re-burns the server's multi-use ticket quota (server.js's key-auth rebind path
  // consumes it again each time). Mirrors the real server: a spent ticket is not re-accepted on a
  // reconnect. TestRunControlLoop_ReconnectAndReArm exercises exactly this (2 connections: initial
  // ticket auth, then reconnect that must be signed-only).
  if (connectionCount > 1 && hasTicketAuth) {
    return next(new Error("stale enrollment ticket on reconnect"));
  }
  next();
});

io.on("connection", (socket) => {
  console.log("SERVER: connection", JSON.stringify(socket.handshake.auth));

  socket.on("register", (payload) => {
    console.log("SERVER: register", JSON.stringify(payload));
    const ack = { ok: true };
    if (ownerZkPubKey) ack.zkPubKey = ownerZkPubKey;
    socket.emit("registered", ack);

    setTimeout(() => {
      console.log("SERVER: emitting hop2_session_open");
      socket.emit("hop2_session_open", { pubkey: armPubKey, ttlSeconds: 900 });
    }, 200);

    setTimeout(() => {
      console.log("SERVER: emitting hop2_session_close");
      socket.emit("hop2_session_close", {});
    }, 500);
  });

  // Greppable single-line JSON dump so the Go test can observe exactly which event name the
  // daemon actually used without needing its own socket.io client.
  socket.on("device_status", (payload) => {
    console.log("EVENT device_status " + JSON.stringify(payload));
  });
  socket.on("zk_data", (payload) => {
    console.log("EVENT zk_data " + JSON.stringify(payload));
  });
});

console.log(`SERVER: listening on ${port}`);
