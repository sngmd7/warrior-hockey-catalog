import { readFileSync, writeFileSync } from 'node:fs';
import { createCipheriv, pbkdf2Sync, randomBytes } from 'node:crypto';
import { basename, resolve } from 'node:path';

const [sourceArg, passwordArg] = process.argv.slice(2);

if (!sourceArg || !passwordArg) {
  console.error('Usage: node scripts/build-protected-page.mjs <source-html> <password>');
  process.exit(1);
}

const sourcePath = resolve(sourceArg);
const password = Buffer.from(passwordArg, 'utf8');
const html = readFileSync(sourcePath);
const salt = randomBytes(16);
const iv = randomBytes(12);
const iterations = 310000;
const key = pbkdf2Sync(password, salt, iterations, 32, 'sha256');
const cipher = createCipheriv('aes-256-gcm', key, iv);
const encrypted = Buffer.concat([cipher.update(html), cipher.final()]);
const tag = cipher.getAuthTag();
const payload = {
  version: 1,
  source: basename(sourcePath),
  kdf: 'PBKDF2-SHA-256',
  iterations,
  salt: salt.toString('base64'),
  iv: iv.toString('base64'),
  tag: tag.toString('base64'),
  data: encrypted.toString('base64'),
};

const page = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex, nofollow">
  <title>Warrior Hockey Catalog | Secondslide</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #0b0f14;
      --panel: #121923;
      --line: rgba(255,255,255,.14);
      --text: #f5f8fb;
      --muted: #9ba8b5;
      --accent: #00b7ea;
      --bad: #ff6f72;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      background: linear-gradient(135deg, #080b10, #101923 54%, #11151b);
      color: var(--text);
      padding: 24px;
    }
    main {
      width: min(420px, 100%);
      border: 1px solid var(--line);
      background: rgba(18,25,35,.94);
      border-radius: 8px;
      padding: 28px;
      box-shadow: 0 24px 80px rgba(0,0,0,.34);
    }
    h1 {
      margin: 0 0 8px;
      font-size: 24px;
      line-height: 1.15;
      letter-spacing: 0;
    }
    p {
      margin: 0 0 22px;
      color: var(--muted);
      line-height: 1.45;
      font-size: 14px;
    }
    label {
      display: block;
      margin: 0 0 8px;
      font-size: 13px;
      font-weight: 700;
    }
    input {
      width: 100%;
      height: 44px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #090d12;
      color: var(--text);
      padding: 0 12px;
      font: inherit;
    }
    button {
      width: 100%;
      height: 44px;
      margin-top: 14px;
      border: 0;
      border-radius: 6px;
      background: var(--accent);
      color: #001018;
      font: inherit;
      font-weight: 800;
      cursor: pointer;
    }
    button:disabled {
      cursor: wait;
      opacity: .72;
    }
    .error {
      min-height: 20px;
      margin-top: 12px;
      color: var(--bad);
      font-size: 13px;
      line-height: 1.35;
    }
  </style>
</head>
<body>
  <main>
    <h1>Warrior Hockey Catalog</h1>
    <p>Enter the access password to view the Secondslide customer catalog.</p>
    <form id="gate">
      <label for="password">Password</label>
      <input id="password" name="password" type="password" autocomplete="current-password" autofocus required>
      <button id="submit" type="submit">Open Catalog</button>
      <div id="error" class="error" role="status" aria-live="polite"></div>
    </form>
  </main>
  <script id="encrypted-catalog" type="application/json">${JSON.stringify(payload)}</script>
  <script>
    const form = document.getElementById('gate');
    const input = document.getElementById('password');
    const button = document.getElementById('submit');
    const error = document.getElementById('error');
    const payload = JSON.parse(document.getElementById('encrypted-catalog').textContent);
    const decoder = new TextDecoder();

    function bytes(base64) {
      return Uint8Array.from(atob(base64), (char) => char.charCodeAt(0));
    }

    async function deriveKey(password) {
      const baseKey = await crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(password),
        'PBKDF2',
        false,
        ['deriveKey']
      );
      return crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: bytes(payload.salt), iterations: payload.iterations, hash: 'SHA-256' },
        baseKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt']
      );
    }

    async function openCatalog(password) {
      const key = await deriveKey(password);
      const cipherText = bytes(payload.data);
      const tag = bytes(payload.tag);
      const combined = new Uint8Array(cipherText.length + tag.length);
      combined.set(cipherText);
      combined.set(tag, cipherText.length);
      const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: bytes(payload.iv), tagLength: 128 },
        key,
        combined
      );
      document.open();
      document.write(decoder.decode(decrypted));
      document.close();
    }

    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      error.textContent = '';
      button.disabled = true;
      button.textContent = 'Opening...';
      try {
        await openCatalog(input.value);
      } catch {
        error.textContent = 'That password did not work. Check it and try again.';
        button.disabled = false;
        button.textContent = 'Open Catalog';
        input.select();
      }
    });
  </script>
</body>
</html>
`;

writeFileSync(resolve('index.html'), page);
