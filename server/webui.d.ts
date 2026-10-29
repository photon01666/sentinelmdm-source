// Ambient globals for the WebUI (server/public/app.js) — checked via tsconfig.webui.json only
// (excluded from the strict gate). app.js is a classic <script>-loaded browser script with no
// module syntax, so these `declare const`s name the external libs it pulls in via <script> tags,
// and the Window index signature covers the many app-defined globals it hangs off `window`
// (_zkPrivKey, _deviceList, _zk* stream state, …). Keeps the looser check focused on real DOM /
// type errors instead of undeclared-global noise — same spirit as `db: any` in server.js.
declare const google: any;          // Google Maps JS API (loaded via <script>)
declare const bootstrap: any;       // Bootstrap 5 JS
declare const Stripe: any;          // Stripe.js
declare const io: any;              // Socket.IO client
declare const SentinelPasskey: any; // from the sibling webauthn-client.js <script>

interface Window {
  [key: string]: any;
}

interface Element {
  // app.js does ~840 direct getElementById/querySelector accesses, then reads subtype props
  // (.value/.checked/.getContext/.dataset/.style/.src/…) that don't exist on the base
  // Element/HTMLElement type. One index signature suppresses that noise (db: any equivalent),
  // leaving the real DOM-API / logic errors visible.
  [key: string]: any;
}

// event.target / e.currentTarget are typed EventTarget (the minimal base); app.js reads element
// props off them (.id/.value/.closest/.style/…). Same permissive treatment as Element.
interface EventTarget {
  [key: string]: any;
}
interface GlobalEventHandlers {
  [key: string]: any;
}

// loadCalendar/loadClipboard/loadUsageStats are referenced bare behind `typeof X === 'function'`
// guards but defined conditionally (feature-gated / separate script), so declare them ambient.
// (The ZK-overridden loaders loadCalls/loadSms/… are plain `var` in app.js now, so their
// in-place reassignment is legal without an ambient declaration.)
declare var loadCalendar: any;
declare var loadClipboard: any;
declare var loadUsageStats: any;
