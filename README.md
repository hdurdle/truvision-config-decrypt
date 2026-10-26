# TruVision

TruVision recorders (a Hikvision OEM, including the TVN 22) will not show a camera password in the web UI or the ISAPI channel list. The password is only in an exported configuration backup.

That file is usually named configurationData. It is AES-128-ECB, encrypted with the export password chosen at backup time (secretkey on /ISAPI/System/configurationData). A decrypted file starts with the SWKH header. This tool decrypts it and prints each channel's name, IP address, username and password. There is a Node command-line tool and a browser page. The backup is not uploaded.

There is nothing to `npm install`. Node 18 or newer is enough for the CLI.
The browser page has no dependencies.

## What's here

| File | What it does |
|---|---|
| `decrypt-config.mjs` | CLI. Decrypts a backup and prints the camera logins. Uses Node's `crypto`. |
| `decrypt-config.html` | Same job in the browser. The file is read locally and is not uploaded. |
| `config-decrypt.js` | Decrypt and record parser for the page. Loaded as a classic script beside the HTML. |
| `package.json` | Package name and `node` engine only. No dependencies. |

`decrypt-config.mjs` and `config-decrypt.js` both understand the same file.
The CLI calls Node's AES. The page uses the Web Crypto API when the browser
provides it, and the AES in `config-decrypt.js` otherwise.

## Export a backup

On the recorder: **Maintenance → Backup**, set an export password, and save
the file. The password is whatever was typed into that dialog (1–16
characters). It is not the camera password and not the recorder's admin
password.

The file is usually named `configurationData`. It is about 10 MB of ciphertext.

## Command line

From this folder, or pass a path to the script:

```powershell
node .\decrypt-config.mjs .\configurationData_2026 <export-password>
```

`--json` and `--csv` change the output. `--decrypt-out <file>` also writes
the full decrypted config. That file is the whole recorder database, not
just the camera table, so treat it like a secret and do not commit it.

A wrong export password fails the run. The decrypted bytes have to start
with the `SWKH` header.

Columns are channel, name, IP, username and password. Empty slots stay in
the list (address `0.0.0.0`, blank password, name `IPCamera N`) so the
channel numbers match the recorder. Configured cameras on the TVN 22 use
username `admin` and management port 8000.

## Browser

Host `decrypt-config.html` and `config-decrypt.js` in the same directory
over HTTPS. Open the page, choose the backup, enter the export password.

The page lists the same channels and can download `truvision-cameras.csv`.
Decryption happens in the browser. The backup is not sent anywhere.

On HTTPS the page decrypts with Web Crypto. That API has no AES-ECB, so it
does one AES-CBC decrypt with a zero IV and XORs each block with the
previous ciphertext block, which is ECB. A trailing padding block is added
first because Web Crypto always strips PKCS7 padding. On plain HTTP, or if
the page is opened from disk, `crypto.subtle` is missing and
`config-decrypt.js` decrypts with its own AES instead.

## How the backup is encrypted

AES-128-ECB, no padding. The key is the export password as UTF-8, cut at 16
bytes or padded with zero bytes out to 16. A decrypted file starts with the
four bytes `SWKH`.

Camera slots are fixed records on a constant stride (0x67b0 on a TVN 22P,
firmware V2.13.a). The parser finds them rather than trusting one offset.
Relative to the username field:

| Offset | Contents |
|---|---|
| −0x18 | IPv4, little-endian |
| −0x0c | Management port, uint16, 8000 on every slot |
| +0x00 | Username, C string, 32-byte window. Bytes after the first NUL are other tags, not padding |
| +0x20 | Password, C string, 16-byte window |
| +0x30 | Channel name, C string, 32-byte window |

Records are kept when the port is 8000 and the name is non-empty. The
longest run at the usual stride becomes the channel list, numbered from 1.
