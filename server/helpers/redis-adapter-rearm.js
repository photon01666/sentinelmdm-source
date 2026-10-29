// helpers/redis-adapter-rearm.js
// Re-arm the Socket.IO Redis adapter's pub/sub subscriptions after a
// reconnect or Sentinel failover.
//
// ioredis normally auto-resubscribes, but on 2026-10-25 a network/Redis reset
// left 2 of the 3 tracker replicas with no adapter subscriptions at all:
// io.fetchSockets() then saw only local sockets, and the 30s presence sweep
// reaped devices that were still connected to a peer replica — the dashboard
// flapped online/offline. subscribe/psubscribe are idempotent on Redis, so
// re-issuing them on every reconnect and once a minute is cheap and safe.
module.exports = function redisAdapterRearm({ io, subClient, log }) {
  const adapter = io.of('/').adapter;
  if (!adapter || !adapter.channel || !adapter.requestChannel) return;

  const rearm = () => {
    try {
      subClient.subscribe(adapter.requestChannel).catch(() => {});
      subClient.psubscribe(adapter.channel + '*').catch(() => {});
    } catch (e) {
      if (log) log('warn', 'redis adapter re-arm failed', { err: e.message });
    }
  };

  subClient.on('ready', rearm);
  rearm();
  setInterval(rearm, 60_000).unref();
};
