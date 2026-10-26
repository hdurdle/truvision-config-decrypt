#!/usr/bin/env node

// Decrypt a TruVision / Hikvision configurationData export and list the
// camera logins stored in it. The recorder encrypts the file with AES-128-ECB.
// The key is the export password, UTF-8, truncated or zero-padded to 16 bytes.
// No npm packages: Node's crypto is enough.

import { createDecipheriv } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';

const USER_LEN = 32;
const PASS_LEN = 16;
const NAME_LEN = 32;
const PORT_8000 = 0x1f40;
const MIN_STRIDE = 0x100;

function usage() {
  return `Usage: node decrypt-config.mjs <configurationData> <export-password> [--json | --csv] [--decrypt-out <file>]

The export password is the one set in the recorder's config backup dialog.
Prints each camera channel's name, address, username and password.
--decrypt-out writes the full decrypted config as well.`;
}

function parseArgs(argv) {
  const positional = [];
  let format = 'table';
  let decryptOut = '';
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') return { help: true };
    if (arg === '--json') format = 'json';
    else if (arg === '--csv') format = 'csv';
    else if (arg === '--decrypt-out') {
      decryptOut = argv[++i];
      if (!decryptOut) throw new Error('--decrypt-out needs a file path');
    } else if (arg.startsWith('-')) {
      throw new Error(`Unknown option ${arg}`);
    } else positional.push(arg);
  }
  if (positional.length !== 2) throw new Error(usage());
  return { file: positional[0], password: positional[1], format, decryptOut };
}

function decrypt(data, password) {
  if (data.length === 0 || data.length % 16 !== 0) {
    throw new Error('Config file length is not a multiple of the AES block size');
  }
  const key = Buffer.alloc(16);
  Buffer.from(password, 'utf8').copy(key, 0, 0, 16);
  const decipher = createDecipheriv('aes-128-ecb', key, null);
  decipher.setAutoPadding(false);
  return Buffer.concat([decipher.update(data), decipher.final()]);
}

// Printable C string capped at len. Bytes after the first NUL are ignored:
// on some channels the username slot also holds short tags such as sync_type.
function readField(buf, off, len) {
  if (off < 0 || off + len > buf.length) return null;
  let end = 0;
  while (end < len && buf[off + end] !== 0) {
    const b = buf[off + end];
    if (b < 0x20 || b > 0x7e) return null;
    end++;
  }
  return buf.toString('latin1', off, off + end);
}

function formatIp(buf, off) {
  const n = buf.readUInt32LE(off);
  return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

// userOff points at the 32-byte username. Layout, relative to that:
//   -0x18  IPv4, little-endian
//   -0x0c  management port, uint16 LE (8000 on every slot, used or not)
//   +0x00  username (32)
//   +0x20  password (16)
//   +0x30  channel name (32)
function parseRecord(buf, userOff) {
  if (userOff < 0x18 || userOff + 0x30 + NAME_LEN > buf.length) return null;
  if (buf.readUInt16LE(userOff - 0x0c) !== PORT_8000) return null;
  const username = readField(buf, userOff, USER_LEN);
  const password = readField(buf, userOff + USER_LEN, PASS_LEN);
  const name = readField(buf, userOff + USER_LEN + PASS_LEN, NAME_LEN);
  if (username === null || password === null || name === null || name.length === 0) return null;
  return {
    ip: formatIp(buf, userOff - 0x18),
    username,
    password,
    name,
  };
}

function findRecords(buf) {
  const hits = [];
  for (let i = 0; i + 2 < buf.length; i++) {
    if (buf[i] !== 0x40 || buf[i + 1] !== 0x1f) continue;
    const userOff = i + 0x0c;
    const rec = parseRecord(buf, userOff);
    if (rec) hits.push({ off: userOff, ...rec });
  }
  hits.sort((a, b) => a.off - b.off);

  const diffCount = new Map();
  for (let i = 1; i < hits.length; i++) {
    const d = hits[i].off - hits[i - 1].off;
    if (d >= MIN_STRIDE) diffCount.set(d, (diffCount.get(d) || 0) + 1);
  }
  let stride = 0;
  let strideVotes = 0;
  for (const [d, n] of diffCount) {
    if (n > strideVotes) {
      stride = d;
      strideVotes = n;
    }
  }
  if (!stride) return hits;

  const byOff = new Map(hits.map((h) => [h.off, h]));
  let chain = [];
  for (const h of hits) {
    if (byOff.has(h.off - stride)) continue;
    const run = [];
    for (let off = h.off; byOff.has(off); off += stride) run.push(byOff.get(off));
    if (run.length > chain.length) chain = run;
  }
  return chain;
}

function csvCell(value) {
  const s = String(value ?? '');
  if (/[",\r\n]/.test(s)) return `"${s.replaceAll('"', '""')}"`;
  return s;
}

function formatTable(rows) {
  const header = ['Ch', 'IP', 'Username', 'Password', 'Name'];
  const body = rows.map((r) => [String(r.channel), r.ip, r.username, r.password, r.name]);
  const widths = header.map((h, i) => Math.max(h.length, ...body.map((row) => row[i].length)));
  const line = (cols) => cols.map((c, i) => c.padEnd(widths[i])).join('  ');
  return [line(header), ...body.map(line)].join('\n');
}

function formatCsv(rows) {
  const header = ['channel', 'ip', 'username', 'password', 'name'];
  const lines = [header.join(',')];
  for (const r of rows) {
    lines.push([r.channel, r.ip, r.username, r.password, r.name].map(csvCell).join(','));
  }
  return lines.join('\n');
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) {
    console.log(usage());
    return;
  }
  const encrypted = readFileSync(opts.file);
  const plain = decrypt(encrypted, opts.password);
  if (plain.subarray(0, 4).toString('latin1') !== 'SWKH') {
    throw new Error('Decrypted data does not start with the SWKH header. The export password is wrong, or this is not a configurationData file.');
  }
  if (opts.decryptOut) writeFileSync(opts.decryptOut, plain);

  const chain = findRecords(plain);
  if (chain.length === 0) {
    throw new Error('No camera records found in the decrypted config.');
  }
  const rows = chain.map((rec, i) => ({
    channel: i + 1,
    ip: rec.ip,
    username: rec.username,
    password: rec.password,
    name: rec.name,
  }));

  if (opts.format === 'json') console.log(JSON.stringify(rows, null, 2));
  else if (opts.format === 'csv') console.log(formatCsv(rows));
  else console.log(formatTable(rows));
}

try {
  main();
} catch (err) {
  console.error(err.message);
  process.exit(1);
}
