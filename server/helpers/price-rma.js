// helpers/price-rma.js — e-commerce pricing and RMA window state.
//
// A HELPER module, not a route module: it registers nothing.
//
//   computePrice, rmaWindowState   members
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 1 dep: DAY_MS (binding L1991).  The call must sit at or after L1992; the earliest consumer of
// the export is L3268, so at or before L3267.  L3255 satisfies both.
//
// relative requires: none

module.exports = ({ DAY_MS }) => {
function computePrice(p) {
  const base = p.base_cost_cents || 0, markup = (p.markup_cents == null ? 5000 : p.markup_cents);
  return p.price_cents && p.price_cents > 0 ? p.price_cents : base + markup;
}
function rmaWindowState(order) {
  const RETURN_WINDOW_DAYS = 14;
  if (!order || !order.delivered_at)
    return { delivered: false, withinWindow: false, deadline: null, daysLeft: null };
  const deadline = order.delivered_at + RETURN_WINDOW_DAYS * DAY_MS;
  return { delivered: true, withinWindow: Date.now() <= deadline, deadline,
           daysLeft: Math.max(0, Math.ceil((deadline - Date.now()) / DAY_MS)) };
}

  return {
    computePrice,
    rmaWindowState,
  };
};