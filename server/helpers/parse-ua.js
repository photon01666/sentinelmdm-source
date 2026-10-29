// helpers/parse-ua.js — parse User-Agent string into browser, os, device_type.
//
// A HELPER module, not a route module: it registers nothing.
//
//   parseUA   export   parse a User-Agent string into { browser, os, device_type }
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 0 deps.  The call must sit at or after L1; the earliest consumer of
// the export is L3170, so at or before L3169.  L1963 satisfies both.
//
// relative requires: none

module.exports = () => {
function parseUA(ua) {
  const u = (ua || '').toLowerCase();
  let browser = 'Unknown';
  if (u.includes('edg/') || u.includes('edge/')) browser = 'Edge';
  else if (u.includes('firefox'))                 browser = 'Firefox';
  else if (u.includes('opr/') || u.includes('opera')) browser = 'Opera';
  else if (u.includes('chrome'))                  browser = 'Chrome';
  else if (u.includes('safari'))                  browser = 'Safari';
  let os = 'Unknown';
  if (u.includes('windows'))              os = 'Windows';
  else if (u.includes('android'))         os = 'Android';
  else if (u.includes('iphone') || u.includes('ipad')) os = 'iOS';
  else if (u.includes('mac os'))          os = 'macOS';
  else if (u.includes('linux'))           os = 'Linux';
  const device_type = /mobile|android|iphone|ipad|tablet/i.test(ua || '') ? 'mobile' : 'desktop';
  return { browser, os, device_type };
}

  return {
    parseUA,
  };
};