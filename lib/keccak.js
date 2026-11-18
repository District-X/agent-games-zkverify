'use strict';
// Pure-JS Keccak-256 (original Keccak padding 0x01, NOT NIST SHA3-256).
// Implemented with BigInt lanes so the project needs no extra dependency.
// Verified in test/prooftest.js against the canonical empty-string vector:
// keccak256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470

const MASK64 = (1n << 64n) - 1n;

const RC = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];
// rotation offsets r[x][y]
const R = [
  [0, 36, 3, 41, 18],
  [1, 44, 10, 45, 2],
  [62, 6, 43, 15, 61],
  [28, 55, 25, 21, 56],
  [27, 20, 39, 8, 14],
];

function rotl(v, n) {
  if (n === 0) return v;
  const b = BigInt(n);
  return ((v << b) | (v >> (64n - b))) & MASK64;
}

function keccakF(state) {
  // state: array of 25 BigInt lanes, index x + 5*y
  for (let round = 0; round < 24; round++) {
    // theta
    const c = new Array(5);
    for (let x = 0; x < 5; x++) c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
    for (let x = 0; x < 5; x++) {
      const d = c[(x + 4) % 5] ^ rotl(c[(x + 1) % 5], 1);
      for (let y = 0; y < 5; y++) state[x + 5 * y] ^= d;
    }
    // rho + pi
    const b = new Array(25);
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(state[x + 5 * y], R[x][y]);
      }
    }
    // chi
    for (let y = 0; y < 5; y++) {
      for (let x = 0; x < 5; x++) {
        state[x + 5 * y] = b[x + 5 * y] ^ ((~b[((x + 1) % 5) + 5 * y] & MASK64) & b[((x + 2) % 5) + 5 * y]);
      }
    }
    // iota
    state[0] ^= RC[round];
  }
}

function keccak256(data) {
  // data: Buffer or string (utf8)
  const input = Buffer.isBuffer(data) ? data : Buffer.from(String(data), 'utf8');
  const rate = 136; // 1088 bits for 256-bit output
  const state = new Array(25).fill(0n);
  // pad10*1 with Keccak domain byte 0x01
  const padded = Buffer.concat([input, Buffer.from([0x01])]);
  const padLen = rate - (padded.length % rate);
  const full = Buffer.concat([padded, Buffer.alloc(padLen === 0 ? 0 : padLen - 0, 0)]);
  const buf = Buffer.from(full);
  if (buf.length % rate !== 0) buf.push(0);
  buf[buf.length - 1] |= 0x80;
  for (let off = 0; off < buf.length; off += rate) {
    for (let i = 0; i < rate / 8; i++) {
      let lane = 0n;
      for (let j = 7; j >= 0; j--) lane = (lane << 8n) | BigInt(buf[off + i * 8 + j]);
      state[i] ^= lane;
    }
    keccakF(state);
  }
  const out = Buffer.alloc(32);
  for (let i = 0; i < 4; i++) {
    let lane = state[i];
    for (let j = 0; j < 8; j++) { out[i * 8 + j] = Number(lane & 0xffn); lane >>= 8n; }
  }
  return out;
}

function keccak256Hex(data) {
  return '0x' + keccak256(data).toString('hex');
}

module.exports = { keccak256, keccak256Hex };
