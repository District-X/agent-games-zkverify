'use strict';
// Downloads the official Gatekeeper circuit artifacts and exports the
// verification key. The artifacts are also committed to this repo (wasm
// 1,755,820 bytes + zkey 309,750 bytes — small enough to ship, and shipping
// them removes a network dependency at deploy/startup time). Run this script
// only to refresh them from the official source.
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const INFO_URL = 'https://agentgames.zkverify.io/api/circuit-info';
const DIR = path.join(__dirname, '..', 'circuits');

async function main() {
  const info = await (await fetch(INFO_URL)).json();
  const gk = info.circuits.gatekeeper;
  console.log('official vkHash:', gk.vkHash);
  fs.mkdirSync(DIR, { recursive: true });
  for (const [file, url] of [['gatekeeper.wasm', gk.artifacts.wasm], ['gatekeeper_final.zkey', gk.artifacts.zkey]]) {
    const buf = Buffer.from(await (await fetch(url)).arrayBuffer());
    fs.writeFileSync(path.join(DIR, file), buf);
    console.log('downloaded', file, buf.length, 'bytes');
  }
  const snarkjsBin = path.join(__dirname, '..', 'node_modules', '.bin', 'snarkjs');
  execFileSync(snarkjsBin, ['zkey', 'export', 'verificationkey',
    path.join(DIR, 'gatekeeper_final.zkey'), path.join(DIR, 'verification_key.json')], { stdio: 'inherit' });
  console.log('exported circuits/verification_key.json');
}
main().catch((e) => { console.error(e); process.exit(1); });
