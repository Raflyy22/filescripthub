const json = (body, status = 200, extraHeaders = {}) =>
  new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store, no-cache, must-revalidate',
      'X-Content-Type-Options': 'nosniff',
      ...extraHeaders
    }
  });

const clean = (value) => String(value ?? '').trim();
const COOKIE = 'fsh_admin_session';
const MAX_AGE = 60 * 60 * 8;
const WINDOW_MS = 10 * 60 * 1000;
const MAX_ATTEMPTS = 8;

// Best-effort burst protection. Netlify Functions are stateless, so this is not a
// replacement for an external rate limiter, but it blocks repeated attempts within a warm instance.
const attempts = globalThis.__fshAdminAttempts || new Map();
globalThis.__fshAdminAttempts = attempts;

const b64url = (bytes) => {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
};
const fromB64url = (value) => {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((value.length + 3) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, c => c.charCodeAt(0));
};
async function hmac(secret, text) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(text)));
}
function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
async function makeSession(secret) {
  const exp = Math.floor(Date.now() / 1000) + MAX_AGE;
  const nonce = crypto.randomUUID();
  const payload = `${exp}.${nonce}`;
  const sig = b64url(await hmac(secret, payload));
  return `${payload}.${sig}`;
}
async function validSession(secret, req) {
  const raw = clean(req.headers.get('cookie'));
  const match = raw.match(new RegExp(`(?:^|;\\s*)${COOKIE}=([^;]+)`));
  if (!match) return false;
  const parts = decodeURIComponent(match[1]).split('.');
  if (parts.length !== 3) return false;
  const [expText, nonce, sigText] = parts;
  const exp = Number(expText);
  if (!Number.isFinite(exp) || exp < Math.floor(Date.now() / 1000) || !nonce || !sigText) return false;
  try {
    const expected = await hmac(secret, `${expText}.${nonce}`);
    return constantTimeEqual(fromB64url(sigText), expected);
  } catch { return false; }
}
const sessionCookie = (value) => `${COOKIE}=${encodeURIComponent(value)}; Max-Age=${MAX_AGE}; Path=/; HttpOnly; Secure; SameSite=Lax`;
const clearCookie = `${COOKIE}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax`;

function clientKey(req) {
  return clean(req.headers.get('x-nf-client-connection-ip')) || clean(req.headers.get('x-forwarded-for')).split(',')[0] || 'unknown';
}
function allowedAttempt(key) {
  const now = Date.now();
  const current = attempts.get(key);
  if (!current || now - current.started > WINDOW_MS) {
    attempts.set(key, { started: now, count: 1 });
    return true;
  }
  current.count += 1;
  return current.count <= MAX_ATTEMPTS;
}

export default async (req) => {
  if (req.method !== 'POST') return json({ ok: false, message: 'Method not allowed.' }, 405);

  const adminKey = clean(process.env.ADMIN_KEY);
  const owner = clean(process.env.GITHUB_USER);
  const repo = clean(process.env.GITHUB_REPO);
  const token = clean(process.env.GITHUB_TOKEN);
  const missing = [];
  if (!adminKey) missing.push('ADMIN_KEY');
  if (!owner) missing.push('GITHUB_USER');
  if (!repo) missing.push('GITHUB_REPO');
  if (missing.length) return json({ ok: false, message: `Environment Variables belum lengkap: ${missing.join(', ')}.` }, 500);

  let body = {};
  try { body = await req.json(); } catch { return json({ ok: false, message: 'JSON request tidak valid.' }, 400); }

  if (body.action === 'login') {
    const key = clientKey(req);
    if (!allowedAttempt(key)) return json({ ok: false, message: 'Terlalu banyak percobaan login. Coba lagi beberapa menit.' }, 429, { 'Retry-After': '600' });
    const suppliedKey = clean(req.headers.get('x-admin-key'));
    if (!suppliedKey || suppliedKey !== adminKey) return json({ ok: false, message: 'Kunci admin tidak valid.' }, 401);
    const session = await makeSession(adminKey);
    attempts.delete(key);
    return json({ ok: true, message: 'Admin key valid.', expiresIn: MAX_AGE }, 200, { 'Set-Cookie': sessionCookie(session) });
  }

  if (body.action === 'logout') return json({ ok: true, message: 'Sesi admin dihapus.' }, 200, { 'Set-Cookie': clearCookie });
  if (!(await validSession(adminKey, req))) return json({ ok: false, message: 'Sesi admin tidak valid atau sudah kedaluwarsa.' }, 401);
  if (body.action === 'verify') return json({ ok: true, message: 'Sesi admin valid.', expiresIn: MAX_AGE });

  if (body.action === 'checkLinks') {
    if (!Array.isArray(body.links)) return json({ ok: false, message: 'Daftar link tidak valid.' }, 400);
    const links = body.links.slice(0, 40);
    const results = [];
    for (const entry of links) {
      const title = clean(entry?.title) || 'Tanpa judul';
      const url = clean(entry?.url);
      let parsed;
      try { parsed = new URL(url); } catch { parsed = null; }
      if (!parsed || !['http:', 'https:'].includes(parsed.protocol)) { results.push({ title, url, ok: false, status: 400, message: 'URL tidak valid.' }); continue; }
      try {
        let response = await fetch(parsed.href, { method: 'HEAD', redirect: 'follow', signal: AbortSignal.timeout(7000), headers: { 'User-Agent': 'FileScriptHub-V20-LinkMonitor' } });
        if (response.status === 405 || response.status === 403) response = await fetch(parsed.href, { method: 'GET', redirect: 'follow', signal: AbortSignal.timeout(7000), headers: { 'User-Agent': 'FileScriptHub-V20-LinkMonitor', Range: 'bytes=0-0' } });
        results.push({ title, url, ok: response.ok, status: response.status, finalUrl: response.url });
      } catch (error) { results.push({ title, url, ok: false, status: 0, message: String(error?.message || 'Request gagal').slice(0, 120) }); }
    }
    return json({ ok: true, results });
  }

  if (body.action === 'health') {
    if (!token) return json({ ok: false, message: 'GITHUB_TOKEN belum diset di Netlify.' }, 500);
    const api = `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`;
    try {
      const check = await fetch(api, { headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'FileScriptHub-V20' } });
      if (!check.ok) return json({ ok: false, message: `Repository GitHub tidak dapat diakses (${check.status}).` }, check.status);
      const info = await check.json();
      return json({ ok: true, message: `Terhubung ke ${info.full_name || `${owner}/${repo}`}.` });
    } catch (error) { return json({ ok: false, message: 'Gagal menghubungi GitHub.', detail: String(error?.message || error).slice(0, 200) }, 502); }
  }

  if (body.action !== 'save' || !body.data) return json({ ok: false, message: 'Action tidak valid.' }, 400);
  if (!token) return json({ ok: false, message: 'GITHUB_TOKEN belum diset di Netlify.' }, 500);
  const path = 'database.json';
  const api = `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/contents/${path}`;
  const headers = { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'FileScriptHub-V20' };
  try {
    const getRes = await fetch(api, { headers });
    if (!getRes.ok) return json({ ok: false, message: `Tidak dapat membaca database dari GitHub (${getRes.status}).` }, getRes.status);
    const file = await getRes.json();
    const content = btoa(unescape(encodeURIComponent(JSON.stringify(body.data, null, 2))));
    const putRes = await fetch(api, { method: 'PUT', headers: { ...headers, 'Content-Type': 'application/json' }, body: JSON.stringify({ message: body.message || 'Update FileScriptHub Database V20', content, sha: file.sha }) });
    if (!putRes.ok) return json({ ok: false, message: `GitHub menolak perubahan (${putRes.status}).` }, putRes.status);
    return json({ ok: true, message: 'Database berhasil disimpan ke GitHub.' });
  } catch (error) { return json({ ok: false, message: 'Terjadi kesalahan saat menghubungi GitHub.', detail: String(error?.message || error).slice(0, 300) }, 502); }
};
