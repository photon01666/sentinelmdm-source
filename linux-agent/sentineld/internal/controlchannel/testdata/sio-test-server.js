// Minimal Socket.IO v4 test server, mirroring the shape of the real production handshake
// (auth-payload-based, then a "register" event, then a server-pushed custom event) closely enough
// to validate the Go control-channel client's protocol handling end-to-end. NOT the real
// server.js — just enough surface to prove the Go client's Engine.IO/Socket.IO framing,
// ping/pong, auth payload delivery, and event emit/dispatch are all correct.
const { Server } = require("socket.io");

const port = parseInt(process.argv[2] || "34567", 10);
const pingInterval = parseInt(process.argv[3] || "25000", 10);
const pingTimeout = parseInt(process.argv[4] || "20000", 10);
const io = new Server(port, { path: "/socket.io", pingInterval, pingTimeout });

io.use((socket, next) => {
  const auth = socket.handshake.auth || {};
  if (!auth.deviceId) {
    return next(new Error("missing deviceId"));
  }
  socket.data.auth = auth;
  next();
});

io.on("connection", (socket) => {
  console.log("SERVER: connection", JSON.stringify(socket.handshake.auth));

  socket.on("register", (payload) => {
    console.log("SERVER: register event", JSON.stringify(payload));
    socket.emit("registered", { ok: true, echoedPlatform: payload.platform });
  });

  socket.on("ping_test", (payload) => {
    socket.emit("pong_test", { received: payload });
  });

  socket.on("disconnect", (reason) => {
    console.log("SERVER: disconnect", reason);
  });
});

console.log(`SERVER: listening on ${port}`);
