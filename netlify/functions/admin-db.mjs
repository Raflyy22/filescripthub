const json = (body, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store, no-cache, must-revalidate'
    }
  });

const clean = (value) => String(value ?? '').trim();

export default async (req) => {
  // V10 uses the modern Netlify Functions Request/Response API.
  if (req.method !== 'POST') {
    return json({ ok: false, message: 'Method not allowed.' }, 405);
  }

  const adminKey = clean(process.env.ADMIN_KEY);
  const owner = clean(process.env.GITHUB_USER);
  const repo = clean(process.env.GITHUB_REPO);
  const token = clean(process.env.GITHUB_TOKEN);

  // Never return secret values. Only report which configuration is missing.
  const missing = [];
  if (!adminKey) missing.push('ADMIN_KEY');
  if (!owner) missing.push('GITHUB_USER');
  if (!repo) missing.push('GITHUB_REPO');

  if (missing.length) {
    return json({
      ok: false,
      message: `Environment Variables belum lengkap: ${missing.join(', ')}.`
    }, 500);
  }

  const suppliedKey = clean(req.headers.get('x-admin-key'));
  if (!suppliedKey || suppliedKey !== adminKey) {
    return json({ ok: false, message: 'Kunci admin tidak valid.' }, 401);
  }

  let body = {};
  try {
    body = await req.json();
  } catch {
    return json({ ok: false, message: 'JSON request tidak valid.' }, 400);
  }

  // This action is intentionally lightweight so login does not require GitHub.
  if (body.action === 'verify') {
    return json({ ok: true, message: 'Admin key valid.' });
  }

  if (body.action === 'health') {
    if (!token) return json({ ok: false, message: 'GITHUB_TOKEN belum diset di Netlify.' }, 500);
    const api = `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`;
    try {
      const check = await fetch(api, { headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'FileScriptHub-V12' } });
      if (!check.ok) return json({ ok: false, message: `Repository GitHub tidak dapat diakses (${check.status}).` }, check.status);
      const info = await check.json();
      return json({ ok: true, message: `Terhubung ke ${info.full_name || `${owner}/${repo}`}.` });
    } catch (error) {
      return json({ ok: false, message: 'Gagal menghubungi GitHub.', detail: String(error?.message || error).slice(0, 200) }, 502);
    }
  }

  if (body.action !== 'save' || !body.data) {
    return json({ ok: false, message: 'Action tidak valid.' }, 400);
  }

  if (!token) {
    return json({ ok: false, message: 'GITHUB_TOKEN belum diset di Netlify.' }, 500);
  }

  const path = 'database.json';
  const api = `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/contents/${path}`;
  const headers = {
    Authorization: `Bearer ${token}`,
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'FileScriptHub-V12'
  };

  try {
    const getRes = await fetch(api, { headers });
    if (!getRes.ok) {
      const detail = await getRes.text();
      return json({
        ok: false,
        message: `Tidak dapat membaca database dari GitHub (${getRes.status}).`,
        detail: detail.slice(0, 500)
      }, getRes.status);
    }

    const file = await getRes.json();
    const content = btoa(unescape(encodeURIComponent(JSON.stringify(body.data, null, 2))));

    const putRes = await fetch(api, {
      method: 'PUT',
      headers: { ...headers, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        message: body.message || 'Update FileScriptHub Database V10',
        content,
        sha: file.sha
      })
    });

    if (!putRes.ok) {
      const detail = await putRes.text();
      return json({
        ok: false,
        message: `GitHub menolak perubahan (${putRes.status}).`,
        detail: detail.slice(0, 500)
      }, putRes.status);
    }

    return json({ ok: true, message: 'Database berhasil disimpan ke GitHub.' });
  } catch (error) {
    return json({
      ok: false,
      message: 'Terjadi kesalahan saat menghubungi GitHub.',
      detail: String(error?.message || error).slice(0, 300)
    }, 502);
  }
};
