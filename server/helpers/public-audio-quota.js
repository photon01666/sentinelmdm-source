// helpers/public-audio-quota.js — public-user daily audio-recording quota helpers.
//
// A HELPER module, not a route module: it registers nothing. fmtHm is also injected
// into workers/monitor-and-arp.
//
//   checkPublicAudioQuota   export   Enforce per-account daily audio cap
//   fmtHm                   export   Format seconds as "Xh Ym" (rounded to minutes)
//
// ctx deps (2):
//   PUBLIC_AUDIO_DAILY_CAP_SEC   binding    server.js L4600
//   kv                           destructure server.js L21
//
// The require call must sit at or after L4601 (last non-hoisted dep PUBLIC_AUDIO_DAILY_CAP_SEC
// is initialised at L4600) and at or before L4637 (earliest export consumer is L4638).
//
// relative requires: none

module.exports = ({ PUBLIC_AUDIO_DAILY_CAP_SEC, kv }) => {

function fmtHm(sec) {
  // Round to the nearest whole MINUTE first, then split into h/m — rounding h and (sec%3600)
  // separately let a value like 3600 (exactly 1h) come out as "1h 1m" (Math.max(1,...) forcing a
  // floor of 1 minute even when the true remainder is 0), and let 3599 come out as "0h 60m".
  const totalMin = Math.round(sec / 60);
  const h = Math.floor(totalMin / 60), m = totalMin % 60;
  if (!h) return `${Math.max(1, m)}m`;
  return m ? `${h}h ${m}m` : `${h}h`;
}
async function checkPublicAudioQuota(userId, durationSec) {
  const key = `audiorec:${userId}`;
  const used = (await kv.getNum(key));
  const remaining = PUBLIC_AUDIO_DAILY_CAP_SEC - used;
  if (durationSec > Math.max(0, remaining)) {
    const ttl = (await kv.ttl(key));
    const resetIn = ttl > 0 ? fmtHm(ttl) : '24h';
    const capLabel = fmtHm(PUBLIC_AUDIO_DAILY_CAP_SEC);
    const remainMsg = remaining > 0
      ? `Only ${fmtHm(remaining)} left of your ${capLabel} daily audio recording limit`
      : `Daily ${capLabel} audio recording limit reached`;
    return { ok: false, error: `${remainMsg} — resets in ${resetIn}. Pick a shorter duration.` };
  }
  await kv.incrByWindow(key, durationSec, 24 * 60 * 60);
  return { ok: true };
}

  return { checkPublicAudioQuota, fmtHm };
};