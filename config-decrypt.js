// TruVision / Hikvision configurationData decrypt and camera-login export.
// Loaded as a classic script by decrypt-config.html. On HTTPS the decrypt uses
// Web Crypto (AES-CBC, then an XOR to undo the chaining — the API has no ECB).
// Without crypto.subtle it uses the AES below. The export password is UTF-8,
// truncated or zero-padded to 16 bytes.

(function (root) {
  const USER_LEN = 32;
  const PASS_LEN = 16;
  const NAME_LEN = 32;
  const PORT_8000 = 0x1f40;
  const MIN_STRIDE = 0x100;

  const SBOX = new Uint8Array([
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
  ]);

  const INV_SBOX = new Uint8Array(256);
  for (let i = 0; i < 256; i++) INV_SBOX[SBOX[i]] = i;

  const RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

  function xtime(a) {
    return ((a << 1) ^ ((a & 0x80) ? 0x1b : 0)) & 0xff;
  }

  function mul(a, b) {
    let p = 0;
    for (let i = 0; i < 8; i++) {
      if (b & 1) p ^= a;
      a = xtime(a);
      b >>= 1;
    }
    return p;
  }

  const MUL9 = new Uint8Array(256);
  const MULB = new Uint8Array(256);
  const MULD = new Uint8Array(256);
  const MULE = new Uint8Array(256);
  for (let i = 0; i < 256; i++) {
    MUL9[i] = mul(i, 0x09);
    MULB[i] = mul(i, 0x0b);
    MULD[i] = mul(i, 0x0d);
    MULE[i] = mul(i, 0x0e);
  }

  function expandKey(key) {
    const w = new Uint8Array(176);
    w.set(key.subarray(0, 16));
    let n = 16;
    let rconI = 1;
    const t = new Uint8Array(4);
    while (n < 176) {
      t[0] = w[n - 4];
      t[1] = w[n - 3];
      t[2] = w[n - 2];
      t[3] = w[n - 1];
      if (n % 16 === 0) {
        const x = t[0];
        t[0] = SBOX[t[1]] ^ RCON[rconI++];
        t[1] = SBOX[t[2]];
        t[2] = SBOX[t[3]];
        t[3] = SBOX[x];
      }
      for (let i = 0; i < 4; i++) w[n] = w[n - 16] ^ t[i], n++;
    }
    return w;
  }

  function invShiftRows(s) {
    let t = s[1];
    s[1] = s[13];
    s[13] = s[9];
    s[9] = s[5];
    s[5] = t;

    t = s[2];
    s[2] = s[10];
    s[10] = t;
    t = s[6];
    s[6] = s[14];
    s[14] = t;

    t = s[3];
    s[3] = s[7];
    s[7] = s[11];
    s[11] = s[15];
    s[15] = t;
  }

  function invSubBytes(s) {
    for (let i = 0; i < 16; i++) s[i] = INV_SBOX[s[i]];
  }

  function addRoundKey(s, w, round) {
    const off = round * 16;
    for (let i = 0; i < 16; i++) s[i] ^= w[off + i];
  }

  function invMixColumns(s) {
    for (let c = 0; c < 16; c += 4) {
      const a = s[c];
      const b = s[c + 1];
      const d = s[c + 2];
      const e = s[c + 3];
      s[c] = MULE[a] ^ MULB[b] ^ MULD[d] ^ MUL9[e];
      s[c + 1] = MUL9[a] ^ MULE[b] ^ MULB[d] ^ MULD[e];
      s[c + 2] = MULD[a] ^ MUL9[b] ^ MULE[d] ^ MULB[e];
      s[c + 3] = MULB[a] ^ MULD[b] ^ MUL9[d] ^ MULE[e];
    }
  }

  function decryptBlock(s, w) {
    addRoundKey(s, w, 10);
    for (let round = 9; round >= 1; round--) {
      invShiftRows(s);
      invSubBytes(s);
      addRoundKey(s, w, round);
      invMixColumns(s);
    }
    invShiftRows(s);
    invSubBytes(s);
    addRoundKey(s, w, 0);
  }

  function passwordKey(password) {
    const key = new Uint8Array(16);
    const bytes = new TextEncoder().encode(password);
    key.set(bytes.subarray(0, Math.min(16, bytes.length)));
    return key;
  }

  function aes128EcbDecryptJs(data, password) {
    const w = expandKey(passwordKey(password));
    const out = new Uint8Array(data.length);
    const s = new Uint8Array(16);
    for (let off = 0; off < data.length; off += 16) {
      for (let i = 0; i < 16; i++) s[i] = data[off + i];
      decryptBlock(s, w);
      out.set(s, off);
    }
    return out;
  }

  // Web Crypto only offers AES-CBC, and it always checks PKCS7 padding.
  // CBC-decrypt with a zero IV, then XOR each block with the previous
  // ciphertext block, is ECB. A trailing padding block is appended so the
  // API removes that instead of the real last block.
  async function aes128EcbDecryptSubtle(data, password, subtle) {
    const raw = passwordKey(password);
    const key = await subtle.importKey('raw', raw, { name: 'AES-CBC', length: 128 }, false, ['encrypt', 'decrypt']);
    const last = data.subarray(data.length - 16);
    const pad = new Uint8Array(16);
    pad.fill(0x10);
    const encPad = new Uint8Array(await subtle.encrypt({ name: 'AES-CBC', iv: last }, key, pad));
    const joined = new Uint8Array(data.length + 16);
    joined.set(data, 0);
    joined.set(encPad.subarray(0, 16), data.length);
    const cbc = new Uint8Array(await subtle.decrypt(
      { name: 'AES-CBC', iv: new Uint8Array(16) },
      key,
      joined
    ));
    const out = new Uint8Array(data.length);
    out.set(cbc.subarray(0, 16));
    for (let off = 16; off < data.length; off += 16) {
      const prev = off - 16;
      for (let i = 0; i < 16; i++) out[off + i] = cbc[off + i] ^ data[prev + i];
    }
    return out;
  }

  async function aes128EcbDecrypt(data, password) {
    if (data.length === 0 || data.length % 16 !== 0) {
      throw new Error('Config file length is not a multiple of the AES block size');
    }
    const subtle = root.crypto && root.crypto.subtle;
    if (subtle) return aes128EcbDecryptSubtle(data, password, subtle);
    return aes128EcbDecryptJs(data, password);
  }

  function readField(buf, off, len) {
    if (off < 0 || off + len > buf.length) return null;
    let end = 0;
    while (end < len && buf[off + end] !== 0) {
      const b = buf[off + end];
      if (b < 0x20 || b > 0x7e) return null;
      end++;
    }
    let s = '';
    for (let i = 0; i < end; i++) s += String.fromCharCode(buf[off + i]);
    return s;
  }

  function formatIp(buf, off) {
    return [buf[off + 3], buf[off + 2], buf[off + 1], buf[off]].join('.');
  }

  function parseRecord(buf, userOff) {
    if (userOff < 0x18 || userOff + 0x30 + NAME_LEN > buf.length) return null;
    const port = buf[userOff - 0x0c] | (buf[userOff - 0x0b] << 8);
    if (port !== PORT_8000) return null;
    const username = readField(buf, userOff, USER_LEN);
    const password = readField(buf, userOff + USER_LEN, PASS_LEN);
    const name = readField(buf, userOff + USER_LEN + PASS_LEN, NAME_LEN);
    if (username === null || password === null || name === null || name.length === 0) return null;
    return { ip: formatIp(buf, userOff - 0x18), username, password, name };
  }

  function findRecords(buf) {
    const hits = [];
    for (let i = 0; i + 2 < buf.length; i++) {
      if (buf[i] !== 0x40 || buf[i + 1] !== 0x1f) continue;
      const rec = parseRecord(buf, i + 0x0c);
      if (rec) hits.push({ off: i + 0x0c, ...rec });
    }
    hits.sort((a, b) => a.off - b.off);

    const diffCount = new Map();
    for (let i = 1; i < hits.length; i++) {
      const d = hits[i].off - hits[i - 1].off;
      if (d >= MIN_STRIDE) diffCount.set(d, (diffCount.get(d) || 0) + 1);
    }
    let stride = 0;
    let votes = 0;
    for (const [d, n] of diffCount) {
      if (n > votes) {
        stride = d;
        votes = n;
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

  function cameraRows(plain) {
    if (plain.length < 4 || plain[0] !== 0x53 || plain[1] !== 0x57 || plain[2] !== 0x4b || plain[3] !== 0x48) {
      throw new Error('Decrypted data does not start with the SWKH header. The export password is wrong, or this is not a configurationData file.');
    }
    const chain = findRecords(plain);
    if (chain.length === 0) throw new Error('No camera records found in the decrypted config.');
    return chain.map((rec, i) => ({
      channel: i + 1,
      ip: rec.ip,
      username: rec.username,
      password: rec.password,
      name: rec.name,
    }));
  }

  function csvCell(value) {
    const s = String(value ?? '');
    if (/[",\r\n]/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
    return s;
  }

  function toCsv(rows) {
    const lines = ['channel,ip,username,password,name'];
    for (const r of rows) {
      lines.push([r.channel, r.ip, r.username, r.password, r.name].map(csvCell).join(','));
    }
    return lines.join('\n') + '\n';
  }

  async function decryptExport(data, password) {
    const plain = await aes128EcbDecrypt(data, password);
    return { plain, rows: cameraRows(plain) };
  }

  root.TruVisionConfig = { decryptExport, toCsv };
})(typeof globalThis !== 'undefined' ? globalThis : this);
