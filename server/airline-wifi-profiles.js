/**
 * Airline WiFi Login Profiles
 * 
 * Pre-configured profiles for major airlines that require free account login.
 * Each profile contains:
 *   - ssidPatterns: regex patterns to match the airline's WiFi SSID
 *   - name: display name
 *   - portalUrl: the captive portal URL
 *   - loginUrl: the actual login endpoint (if different from portal)
 *   - fields: form field definitions (name, label, type, required, placeholder)
 *   - submitMethod: GET or POST
 *   - submitBodyTemplate: template string with {field} placeholders
 *   - successIndicators: strings that indicate successful login
 *   - notes: any special instructions
 */
const AIRLINE_WIFI_PROFILES = [
  {
    id: 'southwest',
    name: 'Southwest Airlines',
    ssidPatterns: [/^Southwest[_ -]?Wi[_ -]?Fi(\.com)?$/i],
    portalUrl: 'https://southwestwifi.com',
    loginUrl: 'https://starlink.southwestwifi.com/login',
    fields: [
      {
        name: 'rapid_rewards_number',
        label: 'Rapid Rewards Number',
        type: 'text',
        required: true,
        placeholder: 'XXXXXXXXXX',
        autocomplete: 'username'
      },
      {
        name: 'password',
        label: 'Password',
        type: 'password',
        required: true,
        placeholder: 'Your Rapid Rewards password',
        autocomplete: 'current-password'
      }
    ],
    altFields: [
      {
        name: 'confirmation_code',
        label: 'Confirmation Code (6-digit)',
        type: 'text',
        required: true,
        placeholder: 'ABC123',
        autocomplete: 'off'
      }
    ],
    submitMethod: 'POST',
    submitBodyTemplate: 'rapid_rewards_number={rapid_rewards_number}&password={password}',
    altSubmitBodyTemplate: 'confirmation_code={confirmation_code}',
    successIndicators: ['success', 'connected', 'internet access'],
    errorIndicators: ['invalid', 'error', 'failed', 'incorrect'],
    notes: 'FREE for Rapid Rewards members (free to join). T-Mobile partnership since Oct 2025. Sign up at rapidrewards.com or inflight.',
    freeTier: true,
    freeEntertainment: true
  },
  {
    id: 'delta',
    name: 'Delta Air Lines',
    ssidPatterns: [/^Delta[_ -]?Wi[_ -]?Fi(\.com)?$/i],
    portalUrl: 'https://wifi.delta.com',
    loginUrl: 'https://wifi.delta.com/login',
    fields: [
      {
        name: 'skyMilesNumber',
        label: 'SkyMiles Number',
        type: 'text',
        required: true,
        placeholder: 'XXXXXX',
        autocomplete: 'username'
      },
      {
        name: 'password',
        label: 'Password',
        type: 'password',
        required: false,
        placeholder: 'Optional for free messaging',
        autocomplete: 'current-password'
      }
    ],
    submitMethod: 'POST',
    submitBodyTemplate: 'skyMilesNumber={skyMilesNumber}&password={password}',
    successIndicators: ['welcome', 'connected', 'you are online'],
    errorIndicators: ['invalid', 'error', 'not found'],
    notes: 'FREE for SkyMiles members (free to join). Delta Sync WiFi powered by T-Mobile. Free on all domestic and most international flights.',
    freeTier: true,
    freeEntertainment: true
  },
  {
    id: 'united',
    name: 'United Airlines',
    ssidPatterns: [/^United[_ -]?Wi[_ -]?Fi(\.com)?$/i, /^United[_ -]?Connected$/i],
    portalUrl: 'https://unitedwifi.com',
    loginUrl: 'https://unitedwifi.com/login',
    fields: [
      {
        name: 'mileagePlusNumber',
        label: 'MileagePlus Number',
        type: 'text',
        required: true,
        placeholder: 'XXXXXXX',
        autocomplete: 'username'
      },
      {
        name: 'password',
        label: 'Password',
        type: 'password',
        required: true,
        placeholder: 'Your MileagePlus password',
        autocomplete: 'current-password'
      }
    ],
    submitMethod: 'POST',
    submitBodyTemplate: 'mileagePlusNumber={mileagePlusNumber}&password={password}',
    successIndicators: ['welcome', 'connected', 'enjoy your flight'],
    errorIndicators: ['invalid', 'error', 'incorrect'],
    notes: 'Free for MileagePlus members on most flights. Premier members get priority.',
    freeTier: true,
    freeEntertainment: true
  },
  {
    id: 'american',
    name: 'American Airlines',
    ssidPatterns: [/^aainflight\.com$/i, /^AA[-_ ]?Inflight(\.com)?$/i, /^AA[_-]?Wi[_-]?Fi(\.com)?$/i, /^American[_ -]?Airlines$/i],
    portalUrl: 'https://wifi.aa.com',
    loginUrl: 'https://wifi.aa.com/login',
    fields: [
      {
        name: 'aadvantageNumber',
        label: 'AAdvantage Number',
        type: 'text',
        required: true,
        placeholder: 'XXXXXXXXXX',
        autocomplete: 'username'
      },
      {
        name: 'password',
        label: 'Password',
        type: 'password',
        required: true,
        placeholder: 'Your AAdvantage password',
        autocomplete: 'current-password'
      }
    ],
    submitMethod: 'POST',
    submitBodyTemplate: 'aadvantageNumber={aadvantageNumber}&password={password}',
    successIndicators: ['welcome', 'connected', 'online'],
    errorIndicators: ['invalid', 'error', 'not recognized'],
    notes: 'Free for AAdvantage members on most domestic flights.',
    freeTier: true,
    freeEntertainment: true
  },
  {
    id: 'jetblue',
    name: 'JetBlue Airways',
    ssidPatterns: [/^Fly[_-]?Fi(\.com)?$/i, /^JetBlue[_ -]?Fly[_-]?Fi(\.com)?$/i],
    portalUrl: 'https://flyfi.com',
    loginUrl: 'https://flyfi.com/login',
    fields: [],  // No login required — free for everyone
    submitMethod: 'GET',
    submitBodyTemplate: '',
    successIndicators: ['welcome', 'connected', 'enjoy'],
    errorIndicators: [],
    notes: 'FREE for everyone — no account needed. JetBlue has offered free WiFi to all passengers since 2013. Just connect and accept terms.',
    freeTier: true,
    freeEntertainment: true,
    noLoginRequired: true
  },
  {
    id: 'spirit',
    name: 'Spirit Airlines',
    ssidPatterns: [/^Spirit[_ -]?Wi[_ -]?Fi$/i, /^Spirit[_ -]?Hotspot$/i],
    portalUrl: 'https://wifispirit.com',
    loginUrl: 'https://wifispirit.com/login',
    fields: [
      {
        name: 'email',
        label: 'Email Address',
        type: 'email',
        required: true,
        placeholder: 'your@email.com',
        autocomplete: 'email'
      }
    ],
    submitMethod: 'POST',
    submitBodyTemplate: 'email={email}',
    successIndicators: ['welcome', 'connected'],
    errorIndicators: ['invalid', 'error'],
    notes: 'PAID WiFi ($6.99-$12.99 per flight). No free tier available.',
    freeTier: false,
    freeEntertainment: false
  },
  {
    id: 'frontier',
    name: 'Frontier Airlines',
    ssidPatterns: [/^Frontier[_ -]?Wi[_ -]?Fi$/i, /^Frontier[_ -]?Hotspot$/i],
    portalUrl: 'https://wififrontier.com',
    loginUrl: 'https://wififrontier.com/login',
    fields: [
      {
        name: 'email',
        label: 'Email Address',
        type: 'email',
        required: true,
        placeholder: 'your@email.com',
        autocomplete: 'email'
      }
    ],
    submitMethod: 'POST',
    submitBodyTemplate: 'email={email}',
    successIndicators: ['welcome', 'connected'],
    errorIndicators: ['invalid', 'error'],
    notes: 'PAID WiFi ($5.99-$14.99 per flight). No free tier available.',
    freeTier: false,
    freeEntertainment: false
  },
  {
    id: 'alaska',
    name: 'Alaska Airlines',
    ssidPatterns: [/^Alaska[_ -]?Wi[_ -]?Fi$/i, /^Alaska[_ -]?Hotspot$/i, /^Alaska[_ -]?Airlines$/i],
    portalUrl: 'https://wifialaska.com',
    loginUrl: 'https://wifialaska.com/login',
    fields: [
      {
        name: 'mileagePlanNumber',
        label: 'Mileage Plan Number',
        type: 'text',
        required: true,
        placeholder: 'XXXXXXX',
        autocomplete: 'username'
      },
      {
        name: 'password',
        label: 'Password',
        type: 'password',
        required: true,
        placeholder: 'Your Mileage Plan password',
        autocomplete: 'current-password'
      }
    ],
    submitMethod: 'POST',
    submitBodyTemplate: 'mileagePlanNumber={mileagePlanNumber}&password={password}',
    successIndicators: ['welcome', 'connected', 'online'],
    errorIndicators: ['invalid', 'error', 'incorrect'],
    notes: 'PAID WiFi ($8-$16 per flight). No free tier announced.',
    freeTier: false,
    freeEntertainment: false
  },
  {
    id: 'generic',
    name: 'Generic Airline WiFi',
    ssidPatterns: [/^gogoinflight$/i, /^gogo[_ -]?inflight$/i, /^inflight[_ -]?wi[_ -]?fi$/i],
    portalUrl: '',
    loginUrl: '',
    fields: [
      {
        name: 'username',
        label: 'Username / Email',
        type: 'text',
        required: true,
        placeholder: 'Username or email',
        autocomplete: 'username'
      },
      {
        name: 'password',
        label: 'Password',
        type: 'password',
        required: false,
        placeholder: 'Password (if required)',
        autocomplete: 'current-password'
      }
    ],
    submitMethod: 'POST',
    submitBodyTemplate: 'username={username}&password={password}',
    successIndicators: ['success', 'connected', 'welcome'],
    errorIndicators: ['invalid', 'error', 'failed'],
    notes: 'Generic profile for unrecognized airline WiFi networks.',
    freeTier: false,
    freeEntertainment: false
  }
];

/**
 * Detect airline from SSID
 * @param {string} ssid - The WiFi network SSID
 * @returns {object|null} The matching airline profile or null
 */
function detectAirline(ssid) {
  if (!ssid) return null;
  const cleaned = String(ssid).trim().replace(/^"|"$/g, '');
  for (const profile of AIRLINE_WIFI_PROFILES) {
    if (profile.id === 'generic') continue; // never auto-match cafe/airport *wifi SSIDs
    for (const pattern of profile.ssidPatterns) {
      if (pattern.test(cleaned)) {
        return profile;
      }
    }
  }
  return null;
}

/**
 * Get all airline profiles
 * @returns {array} Array of airline profiles
 */
function getAirlineProfiles() {
  return AIRLINE_WIFI_PROFILES;
}

/**
 * Get airline profile by ID
 * @param {string} id - The airline profile ID
 * @returns {object|null} The airline profile or null
 */
function getAirlineProfile(id) {
  return AIRLINE_WIFI_PROFILES.find(p => p.id === id) || null;
}

/**
 * Validate airline credentials by attempting login to the airline's website.
 * Returns { valid: boolean|null, message: string }
 *
 * ⚠️ Honest-answer version (2026-09-11, agent 2.26.0.16): the previous implementation POSTed
 * credentials to fabricated endpoints (www.delta.com/login/api/validate,
 * www.united.com/api/auth/validate, www.aa.com/login/api/validate, …) that do not exist — they
 * always failed or misreported. Real airline auth is tokenized (Ping/Federate flowId flows) and
 * only reachable against the inflight captive portal from on board, so server-side validation is
 * not possible. Credentials are validated on-device during the flight instead.
 */
async function validateCredentials(airlineId, credentials, useAlt) {
  const profile = getAirlineProfile(airlineId);
  if (!profile) return { valid: false, message: 'Unknown airline' };
  if (profile.noLoginRequired) {
    return { valid: true, message: `${profile.name} requires no login — the portal is click-through` };
  }
  const filled = Object.values(credentials || {}).filter(v => String(v).trim() !== '').length;
  if (filled === 0) {
    return { valid: false, message: 'No credential values provided' };
  }
  return {
    valid: null,
    message: `Can't validate ${profile.name} credentials from the server — they are checked on-device against the inflight portal during the flight (server-side login endpoints are tokenized and not reachable from the ground)`
  };
}

module.exports = {
  AIRLINE_WIFI_PROFILES,
  detectAirline,
  getAirlineProfiles,
  getAirlineProfile,
  validateCredentials
};
