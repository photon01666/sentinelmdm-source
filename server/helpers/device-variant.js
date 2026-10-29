// helpers/device-variant.js — map a device to its required APK variant + build.
//
// A HELPER module, not a route module: it registers nothing. Consumers: the
// device-commands route wiring and the apk-mass-update route wiring — both now
// BELOW the wiring line (the device-commands wiring was moved DOWN past this
// block by the sanctioned consumer-down relocation).
//
//   deviceVariant          export   signer-authoritative variant, else model/os
//   selectBuildForDevice   export   the device's variant's active build (or null)
//
// IN-PLACE splice at the block position (X = L3500, comment absorbed). Deps are
// above: SIGNER_TO_VARIANT (L3491, const) and getActiveBuildForVariant
// (apk-build-variants wiring L3498). The only obstacle was the eager
// device-commands ctx capture at L2872; it was moved below this line
// (route-order verified: no in-between module registers /api/enrollment or
// /api/devices/:id/command|audio-record-state, no app.use shadowing, the
// wiring's exports are unused, server.listen stays far below).
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ SIGNER_TO_VARIANT, getActiveBuildForVariant }) => {

// Map a device → its required variant. Signer is authoritative (and OTA-safe); else fall back to
// model + os_build (a Graphene/SentinelOS build number is all-digits, e.g. 2026053006). NB:
// device.model is ENC: at rest — pass the DECRYPTED model in.
function deviceVariant(dev) {
  const signer = (dev.apk_signer || '').toLowerCase();
  if (SIGNER_TO_VARIANT[signer]) return SIGNER_TO_VARIANT[signer];
  const model   = (dev.model || '').toLowerCase();
  const osBuild = String(dev.os_build || '');
  const isCustomOs = /^\d{8,}$/.test(osBuild);              // GrapheneOS/SentinelOS build number
  if (isCustomOs && /pixel\s*6\s*pro/.test(model)) return 'raven';
  if (isCustomOs && /pixel\s*10\s*a/.test(model))  return 'stallion';
  if (isCustomOs && /pixel\s*9\s*a/.test(model))   return 'tegu';
  if (isCustomOs && /pixel\s*tablet/.test(model))  return 'tangorpro';
  return 'stock';                                           // everything else (incl. stock Pixels)
}
// Pick the build a device should receive (its variant's active build), or null if none hosted.
async function selectBuildForDevice(dev) { return await getActiveBuildForVariant(deviceVariant(dev)); }

return { deviceVariant, selectBuildForDevice };

};
