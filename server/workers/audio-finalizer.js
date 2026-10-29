// workers/audio-finalizer.js - worker-only finalizer for abandoned chunked recordings.
//
// The agent uploads ~60s segments as a recording progresses. If the device goes dark
// mid-recording (reboot, network loss, process death) no `final:true` segment ever arrives,
// so a session would sit open forever. This finalizes any session quiet for longer than
// AUDIO_SEGMENT_STALE_MS, turning its partial segments into a visible, playable clip.
//
// AUDIO_SEGMENT_STALE_MS moves with this module: its only executable use is below, so keeping
// it in server.js would leave a constant nothing reads.
//
// A WORKER module: it registers a timer, not a route, and registers nothing when IS_WORKER is
// unset — which is also what keeps web replicas from racing to finalize the same session twice.
//
// The replacement call sits at the block's OWN first line (L8550), preserving registration
// order against the server.js lines around it.
//
// ctx: 4 deps. `finalizeAudioSession` is a `function` and hoists; `kv` is a destructure at L21;
// `log` is a `function` at L447; `IS_WORKER` is a binding at L28. All are far above L8550, so
// the call must sit at or after L29. It does.
//
// No relative require to rebase — this block contains none.

module.exports = ({ IS_WORKER, finalizeAudioSession, kv, log }) => {
// ── Chunked record_audio — stale-session finalizer (worker only — one instance) ───────────
// The agent uploads ~60s segments as a recording progresses (see `audio_segment` above) instead
// of one blob at the end. If the device goes dark mid-recording (reboot, network loss, killed
// process) no `final:true` segment ever arrives, so a session would sit open forever — this sweep
// finalizes (assembles whatever arrived into one clip) any session that's been quiet for longer
// than AUDIO_SEGMENT_STALE_MS. Mirrors the surveillance loop's IS_WORKER pattern above so the 3
// web replicas never race to finalize the same session twice.
// NOT a data-integrity safety net anymore: a segment arriving after this fires still appends onto
// the already-finalized clip (see appendToAudioMedia / audiorec:done:<id>), so no outage length can
// split a recording in two regardless of this value. Its only remaining jobs are (1) eventually
// turning a genuinely-abandoned recording's partial segments into a visible, playable clip instead
// of leaving them stuck in audio_segments forever, and (2) staying comfortably above the agent's
// ~60s cadence so ordinary timing jitter doesn't trigger a pointless finalize-then-immediately-
// append on every segment of a perfectly normal recording.
const AUDIO_SEGMENT_STALE_MS = 2.5 * 60 * 1000;
if (IS_WORKER) setInterval(async () => {
  let ids;
  try { ids = (await kv.smembers('audiorec:active')); } catch { return; }
  const now = Date.now();
  for (const sessionId of ids) {
    try {
      const meta = (await kv.getJSON(`audiorec:${sessionId}`));
      if (!meta || now - meta.lastSegmentAt >= AUDIO_SEGMENT_STALE_MS) {
        log('info', 'Audio session went quiet — finalizing with whatever arrived', { sessionId });
        await finalizeAudioSession(sessionId);
      }
    } catch (e) { log('warn', 'audio session finalize sweep error', { sessionId, error: e.message }); }
  }
}, 30000);

  // Nothing to return: registering the interval IS the side effect.
};
