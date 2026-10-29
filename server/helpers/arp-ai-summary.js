// helpers/arp-ai-summary.js - the once-a-day-per-device ARP scan AI network summary.
//
// A HELPER module, not a route module: it registers nothing. It exists to serve
// routes/remote-assist and the ARP reporting path, which receive these as ctx deps.
//
//   arpAiSummaryDue      export   is the per-device once/day throttle already expired?
//   generateArpAiSummary export   ask the model for a single-shot network summary and persist it
//
// Deliberately a single-shot text summary (system + one user turn, no conversation state),
// unlike the Ask-AI screen-text/logs flows: an ARP scan is plain network-infrastructure
// metadata for an admin-managed Windows RA endpoint, not child-monitoring data, so it is
// fine to persist in `arp_ai_summaries`.
//
// ARP_AI_SUMMARY_MIN_INTERVAL_MS moves with this module: both of its uses are below, so
// keeping it in server.js would leave a constant nothing reads.
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 3 of the 5 deps are `function` declarations and hoist (log L447, opencodeApiKey L4233,
// postOpencode L4250); the other two, OPENCODE_MODEL (L4224) and db (L723), are bindings
// above L6226. So the call must sit at or after L4225 -- and the earliest consumer of the
// exports is L8204, so at or before L8203. L6226 satisfies both.
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ OPENCODE_FALLBACK_MODELS, OPENCODE_MODEL, db, log, opencodeApiKey, postOpencode }) => {
// ── ARP scan AI network summary — rate-limited to at most once/day per device ────────────────
// Deliberately a single-shot text summary (system+one user turn, no conversation state), unlike
// the Ask-AI screen-text/logs flows above it — those are consent-gated, user-driven, per-session
// chats over PRIVATE ZK data that's explicitly never persisted server-side. An ARP scan roster is
// plain network-infrastructure metadata for an admin-managed Windows RA endpoint, not private
// child-monitoring data, so it's fine to persist (arp_ai_summaries) and generate unattended.
const ARP_AI_SUMMARY_MIN_INTERVAL_MS = 24 * 60 * 60 * 1000;

async function arpAiSummaryDue(deviceId) {
  const last = (await db.prepare('SELECT generated_at FROM arp_ai_summaries WHERE device_id=? ORDER BY generated_at DESC LIMIT 1').get(deviceId));
  return !last || (Date.now() - last.generated_at) >= ARP_AI_SUMMARY_MIN_INTERVAL_MS;
}

async function generateArpAiSummary(deviceId) {
  const apiKey = opencodeApiKey();
  if (!apiKey) return null;
  const since = Date.now() - ARP_AI_SUMMARY_MIN_INTERVAL_MS;
  const roster = (await db.prepare('SELECT mac_address,ip_address,hostname,open_ports,web_ui,first_seen,last_seen FROM arp_neighbors WHERE device_id=? ORDER BY last_seen DESC').all(deviceId));
  if (!roster.length) return null;
  const events = (await db.prepare('SELECT event_type,mac_address,ip_address,prior_value,timestamp FROM arp_events WHERE device_id=? AND timestamp>=? ORDER BY timestamp DESC LIMIT 200').all(deviceId, since));
  const rosterText = roster.map(r => {
    let extra = '';
    try {
      const ports = r.open_ports ? JSON.parse(r.open_ports) : [];
      const web = r.web_ui ? JSON.parse(r.web_ui) : [];
      if (ports.length) extra += ` open ports ${ports.join(',')}`;
      if (web.length) extra += ' web UI: ' + web.map(w => `${w.url} title="${w.title || ''}"${w.server ? ` server=${w.server}` : ''}`).join('; ');
    } catch (_) {}
    return `- ${r.ip_address}  ${r.mac_address}  ${r.hostname || '(no hostname)'}${extra}  first seen ${new Date(r.first_seen).toISOString()}  last seen ${new Date(r.last_seen).toISOString()}`;
  }).join('\n');
  const eventsText = events.length
    ? events.map(e => {
        const ts = new Date(e.timestamp).toISOString();
        if (e.event_type === 'arp_sweep') return `- [${ts}] arp_sweep mac=${e.mac_address} ${e.prior_value || ''} (first target ip=${e.ip_address})`;
        return `- [${ts}] ${e.event_type} mac=${e.mac_address} ip=${e.ip_address}${e.prior_value ? ` (was ${e.prior_value})` : ''}`;
      }).join('\n')
    : '(none in the last 24 hours)';
  const systemText =
    'You are a home/small-office network analyst reviewing an ARP-scan-derived device inventory ' +
    'for one local network, for the network\'s owner. Where you reasonably can, identify likely ' +
    'device types or vendors from MAC address OUI prefixes, hostnames, open TCP ports, and any ' +
    'hosted web UI titles/servers (e.g. port 554 + RTSP suggests an IP camera, 9100/631 a printer, ' +
    '5000/5001 a NAS, 8123 Home Assistant, 8096 media server, 80/443 with a router-branded title a ' +
    'router/gateway). Call out anything that ' +
    'looks like a new or unexpected device. Specifically explain any "mac_changed_for_ip" events: ' +
    'note that this is the classic ARP/MAC-spoofing indicator (a different device now answering ' +
    'for an IP address a known device used to hold) but ALSO that the mundane explanation — an ' +
    'old device leaving the network and a new one picking up the same DHCP-leased IP address — is ' +
    'common and not itself evidence of an attack, so the owner should treat it as worth a look, ' +
    'not a confirmed compromise. Explain any "canary_hit" events as a HIGH-confidence signal: these ' +
    'are deliberately-unused decoy IP addresses on this network that should never answer, so a ' +
    'device claiming one is a much stronger sign of an unauthorized or newly-connected device than ' +
    'routine DHCP churn. Explain any "arp_sweep" events as a likely network reconnaissance/scanning ' +
    'tool (such as Nmap) running from that MAC address: it broadcast ARP "who has" requests for many ' +
    'different addresses in a very short window, which legitimate devices essentially never do — ' +
    'flag it as worth investigating which device that MAC address belongs to. Be concise: a short ' +
    'paragraph plus a bullet list of anything notable, not an exhaustive restatement of every row.';
  const userText = `Current known devices on this network:\n${rosterText}\n\nEvents in the last 24 hours:\n${eventsText}`;
  const models = [OPENCODE_MODEL, ...OPENCODE_FALLBACK_MODELS.filter(m => m !== OPENCODE_MODEL)];
  for (const model of models) {
    try {
      const resp = await postOpencode({
        model,
        messages: [
          { role: 'system', content: systemText },
          { role: 'user', content: userText },
        ],
        temperature: 0.4,
        max_tokens: 4096,
      });
      if (!resp.ok) { log('warn', 'ARP AI summary: OpenCode HTTP error', { deviceId, status: resp.status, model }); continue; }
      const body = await resp.json();
      const summary = ((body?.choices || [{}])[0]?.message?.content || '').trim();
      if (!summary) { log('warn', 'ARP AI summary: empty response', { deviceId, model }); continue; }
      const generated_at = Date.now();
      (await db.prepare('INSERT INTO arp_ai_summaries (device_id,summary,generated_at) VALUES (?,?,?)').run(deviceId, summary, generated_at));
      return { summary, generated_at };
    } catch (e) {
      log('warn', 'ARP AI summary: OpenCode call failed', { deviceId, model, err: e.message });
    }
  }
  return null;
}

  return {
    arpAiSummaryDue,
    generateArpAiSummary,
  };
};
