'use strict';
const assert = require('assert');
const { detectAirline } = require('./airline-wifi-profiles');

const cases = [
  ['SouthwestWiFi', 'southwest'],
  ['Southwest WiFi', 'southwest'],
  ['Southwest_Wi-Fi', 'southwest'],
  ['DeltaWiFi.com', 'delta'],
  ['Delta Wi-Fi', 'delta'],
  ['DeltaWiFi', 'delta'],
  ['United_Wi-Fi', 'united'],
  ['United Wi-Fi', 'united'],
  ['unitedwifi.com', 'united'],
  ['aainflight.com', 'american'],
  ['AA-Inflight', 'american'],
  ['AAWiFi', 'american'],
  ['Fly-Fi', 'jetblue'],
  ['Fly-Fi.com', 'jetblue'],
  ['FlyFi', 'jetblue'],
  ['Spirit WiFi', 'spirit'],
  ['Alaska_WiFi', 'alaska'],
  ['Coffee Shop WiFi', null],
  ['xfinitywifi', null],
  ['gogoinflight', null], // generic vendor — not auto-detected as a specific airline
];

let failed = 0;
for (const [ssid, expect] of cases) {
  const got = detectAirline(ssid);
  const id = got ? got.id : null;
  if (id !== expect) {
    failed++;
    console.error(`FAIL  ${JSON.stringify(ssid)} → ${id} (expected ${expect})`);
  } else {
    console.log(`ok    ${JSON.stringify(ssid)} → ${id}`);
  }
}

assert.strictEqual(failed, 0, `${failed} SSID detection case(s) failed`);
console.log(`\n${cases.length} cases passed`);
