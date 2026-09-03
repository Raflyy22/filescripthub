const json = (body, status = 200) => ({
  statusCode: status,
  headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  body: JSON.stringify(body)
});

const requiredEnv = ['ADMIN_KEY', 'GITHUB_USER', 'GITHUB_REPO'];

export default async (request) => {
  if (request.httpMethod !== 'POST') return json({ ok: false, message: 'Method not allowed' }, 405);
  if (requiredEnv.some(k => !process.env[k])) return json({ ok: false, message: 'Environment variable server belum lengkap.' }, 500);

  const supplied = request.headers['x-admin-key'] || request.headers['X-Admin-Key'] || '';
  if (!supplied || supplied !== process.env.ADMIN_KEY) return json({ ok: false, message: 'Kunci admin salah.' }, 401);

  let body;
  try { body = JSON.parse(request.body || '{}'); } catch { return json({ ok: false, message: 'JSON tidak valid.' }, 400); }

  const owner = process.env.GITHUB_USER;
  const repo = process.env.GITHUB_REPO;
  const path = 'database.json';
  const api = `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/contents/${path}`;
  const headers = {
    'Authorization': `Bearer ${process.env.GITHUB_TOKEN}`,
    'Accept': 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'CloudVault-V10'
  };
  if (!process.env.GITHUB_TOKEN) return json({ ok: false, message: 'GITHUB_TOKEN belum diset di Netlify.' }, 500);

  if (body.action === 'verify') return json({ ok: true });
  if (body.action !== 'save' || !body.data) return json({ ok: false, message: 'Action tidak valid.' }, 400);

  const getRes = await fetch(api, { headers });
  if (!getRes.ok) return json({ ok: false, message: 'Tidak dapat membaca database dari GitHub.' }, getRes.status);
  const file = await getRes.json();
  const content = Buffer.from(JSON.stringify(body.data, null, 2), 'utf8').toString('base64');

  const putRes = await fetch(api, {
    method: 'PUT',
    headers: { ...headers, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      message: body.message || 'Update CloudVault Database V10',
      content,
      sha: file.sha
    })
  });
  if (!putRes.ok) {
    const detail = await putRes.text();
    return json({ ok: false, message: `GitHub menolak perubahan (${putRes.status}).`, detail }, putRes.status);
  }
  return json({ ok: true });
};
