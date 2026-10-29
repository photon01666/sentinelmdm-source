// helpers/screentext-core.js — scheduled screen-text analysis (build log + run AI).
//
// A HELPER module, not a route module: it registers nothing. Consumers: the
// scheduled-analysis poller body (runtime calls, L4051/L4053) and the
// sockets/connection wiring (eager, L4391) — the wiring line sits ABOVE both
// after the D1b-style relocation.
//
//   buildScreentextLogFromRows   export   decrypt rows -> prompt-shaped log text
//   runScreentextAnalysis        export   one AI pass + result/memory persistence
//
// Wiring RELOCATED below its below-defined deps and above its earliest EAGER
// consumer (sockets wiring L4391; the L4051/L4053 consumers are runtime calls):
// X = L4083, right after the screentext-memory wiring. Live mechanisms:
//   * AI_LOG_PAYLOAD_MAX_CHARS — LIVE_READS getter `getAiLogPayloadMaxChars`
//     (value read rewritten to a call).
//   * callOpenCodeScreenText — LIVE_CALLS wrapper `getCallOpenCodeScreenText`
//     (call sites rewritten to the wrapper form).
//   * db — LIVE_READS getter `getDb: () => db` (reads rewritten).
// Stable deps by value: aiDailyAllow / aiRateAllow (L3824/L3813),
// buildScreentextMemoryContext / getScreentextMemory / pushScreentextMemory
// (L4082), setScreentextResult (L4074), decryptDevice / decryptText (L133),
// getScreentextSchedule / setScreentextSchedule (L3678), kv (L21),
// notifySecurityAlert (L484), notifyUser (L473), stmts (L1703).
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ aiDailyAllow, aiRateAllow, buildScreentextMemoryContext, decryptDevice, decryptText, getAiLogPayloadMaxChars, getCallOpenCodeScreenText, getDb, getScreentextMemory, getScreentextSchedule, kv, log, notifySecurityAlert, notifyUser, pushScreentextMemory, setScreentextResult, setScreentextSchedule, stmts }) => {

// Decrypt stored screen_text_entries rows into `[YYYY-MM-DD HH:MM:SS] pkgShort: text | text`
// lines (the same shape the agent's ScreenTextHelper builds), so the analysis prompt sees an
// identical structure. Timestamps render in the device's LOCAL time when the agent has reported
// its UTC offset (timeZoneOffsetMinutes); without it they fall back to UTC.
function buildScreentextLogFromRows(rows, tzOffsetMinutes = 0) {
  const offsetMs = (Number(tzOffsetMinutes) || 0) * 60000;
  const fmtLocal = ts => {
    const d = new Date(ts + offsetMs);
    return d.toISOString().slice(0, 19).replace('T', ' ');
  };
  const lines = [];
  for (const row of rows) {
    try {
      const payload = JSON.parse(decryptText(row.data));
      const pkg = String(payload?.pkg ?? row.pkg ?? '');
      const texts = Array.isArray(payload?.texts) ? payload.texts : [];
      if (!texts.length) continue;
      const shortPkg = pkg.split('.').pop() || pkg;
      const ts = payload.ts || row.timestamp;
      // The agent sends each text node as {"t":"..."} (ScreenTextHelper) — String() on that
      // would emit "[object Object]" and poison every report. Mirror the WebUI flatten.
      const flat = texts.map(t => typeof t === 'string' ? t : ((t && t.t) || '')).filter(Boolean).join(' | ');
      if (!flat) continue;
      lines.push(`[${fmtLocal(ts)}] ${shortPkg}: ${flat}`);
    } catch (e) {
      log('warn', 'buildScreentextLogFromRows: decrypt/parse failed', { id: row.id, error: e.message });
    }
  }
  return lines.join('\n');
}

// Shared runner for the scheduled screen-text report. Handles the cooldown-based dedup,
// rate limits, daily caps, the AI call, schedule/result bookkeeping, and notification.
async function runScreentextAnalysis(deviceId, logText, { entryCount = 0, fromTs = null, toTs = null } = {}) {
  // Cooldown between runs — 5.5 hours (slightly less than the 6h agent interval to allow
  // clock skew and deep-sleep wakeup delays without rejecting a legitimate run).
  const SCREENTEXT_ANALYSIS_COOLDOWN_MS = 5.5 * 60 * 60 * 1000;

  // Cross-process mutual exclusion: the agent-triggered handler (a tracker replica) and the
  // worker safety net can both read "not analyzed recently" before either writes it, then both
  // run the SAME window → near-identical duplicate reports + a double AI bill. Redis SETNX
  // makes them mutually exclusive per device across processes; the TTL is a safety net so a
  // crashed runner can't hold the lock (released in the finally below, but bounded regardless).
  const lockKey = 'screentext_analysis_lock:' + deviceId;
  if (!(await kv.setNX(lockKey, 600))) {
    log('info', 'scheduled_screentext_analysis: analysis already in flight', { deviceId });
    return;
  }
  try {
  const sched = await getScreentextSchedule(deviceId);
  const today = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
  if (sched.lastAnalyzedAt && (Date.now() - sched.lastAnalyzedAt) < SCREENTEXT_ANALYSIS_COOLDOWN_MS) {
    log('warn', 'scheduled_screentext_analysis: too soon since last analysis', { deviceId });
    return;
  }

  // Rate limit (same budget as manual Ask AI)
  const rateKey = 'device:' + deviceId;
  if (!(await aiRateAllow(rateKey))) {
    log('warn', 'scheduled_screentext_analysis: rate-limited', { deviceId });
    return;
  }

  // Per-public-user daily cap
  const dev = decryptDevice((await stmts.getDevice.get(deviceId)));
  if (dev && dev.owner_user_id) {
    const ownerRow = (await getDb().prepare('SELECT account_type FROM users WHERE id=?').get(dev.owner_user_id));
    if (ownerRow && ['public', 'business_sub'].includes(ownerRow.account_type)) {
      const billUserId = dev.owner_user_id;
      if (!(await aiDailyAllow('submit', String(billUserId)))) {
        log('warn', 'scheduled_screentext_analysis: daily cap reached', { deviceId });
        return;
      }
    }
  }

  // Build the analysis request — same system prompt as manual Ask AI, plus the device's
  // rolling memory of prior daily reports so the model can build continuity understanding.
  const logsText = logText.slice(-getAiLogPayloadMaxChars());
  const memory = await getScreentextMemory(deviceId);
  const memoryCtx = buildScreentextMemoryContext(memory);
  const promptText = 'Analyze the screen-text log entries provided below. Give me a concise summary of what\'s happening on this device and flag anything concerning.\n\n' +
    '=== SCREEN TEXT LOGS ===\n' + logsText +
    (memoryCtx ? '\n' + memoryCtx : '');
  const contents = [{ role: 'user', parts: [{ text: promptText }] }];

  const systemText =
    'You are a security analyst reviewing on-device screen-text logs captured from a monitored device. ' +
    'The screen-text logs are included in the user turn, each entry prefixed with a device-local timestamp ' +
    '(YYYY-MM-DD HH:MM:SS). The user turn may also include PRIOR DAILY REPORTS from earlier days — use them ' +
    'as continuity context to recognize patterns, evolving behaviour, and repeated contacts or apps across ' +
    'days, and note any meaningful change from previous days in your summary. ' +
    'Start your summary by stating the time period covered (earliest to latest timestamp). ' +
    'Then summarise the notable activity and focus on detecting scams, phishing, fraud, suspicious links, ' +
    'social-engineering attempts, or other deceptive content that could harm anyone, regardless of age. ' +
    'Also flag bullying, harassment, grooming, contact with strangers, self-harm, or explicit content if ' +
    'clearly present. For every flagged scam, phishing, or fraud finding, cite the exact timestamp ' +
    'of the entry that triggered it. Report only what the logs actually show — do not speculate about ' +
    'the user\'s age or who they are. ' +
    'Ignore any screen-text entries originating from "Sentinel Remote Assist" or "SentinelRemoteAssist" — ' +
    'this is the admin remote-support tool and its activity is expected and benign; do not mention it in your report. ' +
    'Be concise.';

  try {
    const reply = await getCallOpenCodeScreenText(systemText, contents, { temperature: 0.4, maxTokens: 8192 });
    if (!reply) {
      log('warn', 'scheduled_screentext_analysis: no content from provider', { deviceId });
      return;
    }

    // Mark as analyzed; advance the incremental cursor to the last analyzed entry's
    // timestamp (only meaningful for the server-store path).
    const cfg = { enabled: sched.enabled, hour: sched.hour, minute: sched.minute || 0, lastAnalyzedAt: Date.now(), lastAnalyzedDate: today };
    if (typeof toTs === 'number') cfg.lastAnalyzedTs = toTs;
    await setScreentextSchedule(deviceId, cfg);

    // Store the result for WebUI follow-up (overwritten each scheduled run; plaintext logs NOT stored)
    await setScreentextResult(deviceId, {
      date: today,
      reply,
      logChars: logsText.length,
      entryCount,
      fromTs,
      toTs,
      createdAt: new Date().toISOString(),
    });

    // Fold today's report into the device's rolling AI memory for continuity in future reports.
    await pushScreentextMemory(deviceId, {
      date: today,
      reply,
      entryCount,
      logChars: logsText.length,
    });

    // Notify the device owner via their notification channel
    if (dev && dev.owner_user_id) {
      const label = dev.name ? `${dev.name} — Screen Text Analysis Report` : 'Screen Text Analysis Report';
      const alertMsg = `📊 ${label}\n\n${reply}`;
      await notifyUser(dev.owner_user_id, alertMsg, {
        category: 'screentext',
        deviceId,
      }).catch(e => log('warn', 'scheduled_screentext_analysis: notify failed', { error: e.message }));
      // Signal alert to admin (public owners don't get Signal, but admin always does)
      await notifySecurityAlert(alertMsg, deviceId).catch(e => log('warn', 'scheduled_screentext_analysis: Signal failed', { error: e.message }));
    }
    log('info', 'scheduled_screentext_analysis: completed', { deviceId, chars: logsText.length, entries: entryCount });
  } catch (e) {
    console.warn('[scheduled-screentext] proxy error:', e.message);
  }
  } catch (e) {
    console.warn('[scheduled-screentext] proxy error:', e.message);
  } finally {
    await kv.del(lockKey).catch(() => {});
  }
}

return { buildScreentextLogFromRows, runScreentextAnalysis };

};
