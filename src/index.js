// OmniLink Use Worker - useomniilink.omniilink.workers.dev
// Auth gate + reverse proxy to ProDesk tunnel

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-User-Keys',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    try {
      // Auth endpoints
      if (path === '/api/auth' && request.method === 'POST') {
        const { token } = await request.json();
        const session = await env.DB.prepare(
          'SELECT user_id FROM sessions WHERE token = ? AND expires_at > datetime(\'now\')'
        ).bind(token).first();
        if (!session) return jsonResp({ error: 'Invalid session' }, 401, corsHeaders);
        const keys = await env.DB.prepare('SELECT provider, api_key FROM user_api_keys WHERE user_id = ?')
          .bind(session.user_id).all();
        const backendSetting = await env.DB.prepare('SELECT value FROM settings WHERE key = ?').bind('backend_url').first();
        return jsonResp({
          valid: true,
          apiKeys: Object.fromEntries(keys.results.map(k => [k.provider, k.api_key])),
          backendUrl: backendSetting?.value || '',
        }, 200, corsHeaders);
      }

      if (path === '/api/set-backend' && request.method === 'POST') {
        const authHeader = request.headers.get('Authorization');
        if (!authHeader || !authHeader.startsWith('Bearer ')) return jsonResp({ error: 'Unauthorized' }, 401, corsHeaders);
        const token = authHeader.slice(7);
        const session = await env.DB.prepare(
          'SELECT user_id FROM sessions WHERE token = ? AND expires_at > datetime(\'now\')'
        ).bind(token).first();
        if (!session) return jsonResp({ error: 'Invalid session' }, 401, corsHeaders);
        const { backendUrl } = await request.json();
        if (!backendUrl || !backendUrl.startsWith('https://')) return jsonResp({ error: 'Invalid URL' }, 400, corsHeaders);
        await env.DB.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)').bind('backend_url', backendUrl).run();
        return jsonResp({ success: true }, 200, corsHeaders);
      }

      // All other routes: require auth token
      const token = getCookie(request, 'omnilink_token') || url.searchParams.get('token');
      if (!token) {
        return new Response(getAuthPage(), {
          headers: { 'Content-Type': 'text/html;charset=utf-8', ...corsHeaders },
        });
      }

      const session = await env.DB.prepare(
        'SELECT user_id FROM sessions WHERE token = ? AND expires_at > datetime(\'now\')'
      ).bind(token).first();
      if (!session) {
        return new Response(getAuthPage('Session expired. Please sign in again.'), {
          headers: { 'Content-Type': 'text/html;charset=utf-8', ...corsHeaders },
        });
      }

      const keys = await env.DB.prepare('SELECT provider, api_key FROM user_api_keys WHERE user_id = ?')
        .bind(session.user_id).all();
      const backendSetting = await env.DB.prepare('SELECT value FROM settings WHERE key = ?').bind('backend_url').first();
      const backendUrl = backendSetting?.value;

      if (!backendUrl) {
        return new Response(getSetupPage(token), {
          headers: { 'Content-Type': 'text/html;charset=utf-8', ...corsHeaders },
        });
      }

      // If just the root path, try to proxy (will fail if backend is down, that's fine)
      const apiKeys = Object.fromEntries(keys.results.map(k => [k.provider, k.api_key]));

      // Build proxy request
      const tunnelBase = new URL(backendUrl);
      const tunnelUrl = new URL(request.url);
      tunnelUrl.hostname = tunnelBase.hostname;
      tunnelUrl.protocol = 'https:';
      tunnelUrl.port = '';
      tunnelUrl.searchParams.delete('token');

      const proxyHeaders = new Headers();
      for (const [key, value] of request.headers) {
        const lower = key.toLowerCase();
        if (lower !== 'host' && lower !== 'cf-connecting-ip' && lower !== 'cf-ipcountry' && lower !== 'cf-ray' && lower !== 'cf-visitor') {
          proxyHeaders.set(key, value);
        }
      }
      proxyHeaders.set('Host', tunnelBase.hostname);
      proxyHeaders.set('X-User-Keys', JSON.stringify(apiKeys));

      const proxyReq = new Request(tunnelUrl.toString(), {
        method: request.method,
        headers: proxyHeaders,
        body: request.body,
        redirect: 'follow',
      });

      let resp;
      try {
        resp = await fetch(proxyReq, { signal: AbortSignal.timeout(30000) });
      } catch (e) {
        // Backend unreachable - show setup page for root, error for API
        if (path === '/' || path === '') {
          return new Response(getSetupPage(token, 'ProDesk server is offline. Enter the current tunnel URL.'), {
            headers: { 'Content-Type': 'text/html;charset=utf-8', ...corsHeaders },
          });
        }
        return jsonResp({ error: 'Backend server is offline' }, 502, corsHeaders);
      }

      const contentType = resp.headers.get('Content-Type') || '';

      // For HTML responses, inject tunnel URL info
      if (contentType.includes('text/html')) {
        let html = await resp.text();
        html = html.replace(
          "const API = '';",
          `const API = ''; window.__OMNILINK_TUNNEL = ${JSON.stringify(backendUrl)};`
        );
        const newRespHeaders = new Headers();
        newRespHeaders.set('Content-Type', 'text/html;charset=utf-8');
        newRespHeaders.set('Access-Control-Allow-Origin', '*');
        return new Response(html, { status: resp.status, headers: newRespHeaders });
      }

      // For all other responses (API, SSE, etc.), pass through directly
      const newHeaders = new Headers(resp.headers);
      newHeaders.set('Access-Control-Allow-Origin', '*');
      newHeaders.delete('content-security-policy');
      newHeaders.delete('x-frame-options');

      return new Response(resp.body, {
        status: resp.status,
        statusText: resp.statusText,
        headers: newHeaders,
      });
    } catch (err) {
      return new Response(getErrorPage('Error', 'Something went wrong.'), {
        headers: { 'Content-Type': 'text/html;charset=utf-8', ...corsHeaders },
      });
    }
  },
};

function jsonResp(data, status, corsHeaders) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders },
  });
}

function getCookie(request, name) {
  const cookie = request.headers.get('Cookie') || '';
  const match = cookie.match(new RegExp(`${name}=([^;]+)`));
  return match ? match[1] : null;
}

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function getSetupPage(token, error) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
<title>OmniLink - Setup</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#09090b;--bg2:#111113;--border:#27272a;--text:#fafafa;--text2:#a1a1aa;--accent:#2563eb;--accent2:#3b82f6;--radius:10px}
body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;min-height:100dvh;display:flex;align-items:center;justify-content:center;padding:20px;padding:20px env(safe-area-inset-right,20px) env(safe-area-inset-bottom,20px) env(safe-area-inset-left,20px)}
.box{background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);padding:32px;max-width:440px;width:100%}
.logo{display:flex;align-items:center;gap:10px;justify-content:center;margin-bottom:24px}
.logo svg{width:28px;height:28px}
.logo span{font-size:20px;font-weight:700}
h2{font-size:18px;margin-bottom:8px;text-align:center}
p{color:var(--text2);font-size:14px;margin-bottom:16px;text-align:center}
.err{background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);border-radius:8px;padding:12px;color:#ef4444;font-size:13px;margin-bottom:16px}
.input-group{display:flex;gap:8px;margin-bottom:16px}
input{flex:1;padding:10px 14px;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:14px;outline:none}
input:focus{border-color:var(--accent)}
.btn{padding:10px 20px;border:none;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;background:var(--accent);color:#fff;white-space:nowrap}
.btn:hover{background:var(--accent2)}
.btn:disabled{opacity:0.5;cursor:not-allowed}
.status{font-size:12px;color:var(--text2);text-align:center;margin-top:8px}
.status.ok{color:#22c55e}
.status.err2{color:#ef4444}
.help-link{display:block;text-align:center;margin-top:16px;color:var(--text2);font-size:13px;text-decoration:none}
.help-link:hover{color:var(--accent)}
@media(max-width:480px){.box{padding:24px 16px}.input-group{flex-direction:column}}
</style>
</head>
<body>
<div class="box">
  <div class="logo">
    <svg viewBox="0 0 24 24" fill="none"><rect width="24" height="24" rx="6" fill="#2563eb"/><path d="M7 8h10M7 12h10M7 16h6" stroke="#fff" stroke-width="2" stroke-linecap="round"/></svg>
    <span>OmniLink</span>
  </div>
  <h2>Connect to Server</h2>
  <p>Enter your ProDesk tunnel URL to start using OmniLink.</p>
  ${error ? '<div class="err">' + escapeHtml(error) + '</div>' : ''}
  <div class="input-group">
    <input type="url" id="url-input" placeholder="https://something.trycloudflare.com">
    <button class="btn" id="save-btn" onclick="saveUrl()">Connect</button>
  </div>
  <div class="status" id="status"></div>
  <a class="help-link" href="https://signupomniilink.omniilink.workers.dev">Back to Sign In</a>
</div>
<script>
async function saveUrl() {
  const btn = document.getElementById('save-btn');
  const input = document.getElementById('url-input');
  const status = document.getElementById('status');
  const url = input.value.trim();
  if (!url) { status.textContent = 'Please enter a URL'; status.className = 'status err2'; return; }
  btn.disabled = true; btn.textContent = 'Connecting...';
  try {
    const r = await fetch('/api/set-backend', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ${token}' },
      body: JSON.stringify({ backendUrl: url })
    });
    const data = await r.json();
    if (data.success) {
      status.textContent = 'Saved! Redirecting...'; status.className = 'status ok';
      setTimeout(() => { window.location.href = '/'; }, 1000);
    } else {
      status.textContent = data.error || 'Failed to save'; status.className = 'status err2';
    }
  } catch(e) {
    status.textContent = 'Error: ' + e.message; status.className = 'status err2';
  }
  btn.disabled = false; btn.textContent = 'Connect';
}
document.getElementById('url-input').addEventListener('keydown', e => { if (e.key === 'Enter') saveUrl(); });
</script>
</body>
</html>`;
}

function getAuthPage(error) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
<title>OmniLink - Sign In</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#09090b;--bg2:#111113;--border:#27272a;--text:#fafafa;--text2:#a1a1aa;--accent:#2563eb;--accent2:#3b82f6;--radius:10px}
body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;min-height:100dvh;display:flex;align-items:center;justify-content:center;padding:20px;padding:20px env(safe-area-inset-right,20px) env(safe-area-inset-bottom,20px) env(safe-area-inset-left,20px)}
.box{background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);padding:32px;max-width:400px;width:100%;text-align:center}
.logo{display:flex;align-items:center;gap:10px;justify-content:center;margin-bottom:16px}
.logo svg{width:32px;height:32px}
.logo span{font-size:20px;font-weight:700}
.box h2{margin-bottom:8px}
.box p{color:var(--text2);font-size:14px;margin-bottom:16px}
.btn{padding:10px 20px;border:none;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;background:var(--accent);color:#fff;text-decoration:none;display:inline-block}
.btn:hover{background:var(--accent2)}
.err{color:#ef4444;font-size:13px;margin-bottom:12px}
.links{margin-top:16px;font-size:13px;color:var(--text2)}
.links a{color:var(--accent);cursor:pointer;text-decoration:none}
</style>
</head>
<body>
<div class="box">
  <div class="logo">
    <svg viewBox="0 0 24 24" fill="none"><rect width="24" height="24" rx="6" fill="#2563eb"/><path d="M7 8h10M7 12h10M7 16h6" stroke="#fff" stroke-width="2" stroke-linecap="round"/></svg>
    <span>OmniLink</span>
  </div>
  ${error ? '<p class="err">' + escapeHtml(error) + '</p>' : ''}
  <p>Sign in to your OmniLink account to continue.</p>
  <a class="btn" href="https://signupomniilink.omniilink.workers.dev">Sign In</a>
  <div class="links"><a href="https://signupomniilink.omniilink.workers.dev">Don't have an account? Sign up</a></div>
</div>
</body>
</html>`;
}

function getErrorPage(title, msg) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OmniLink - Error</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#09090b;--bg2:#111113;--border:#27272a;--text:#fafafa;--text2:#a1a1aa;--accent:#2563eb;--accent2:#3b82f6;--radius:10px}
body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);height:100vh;display:flex;align-items:center;justify-content:center}
.box{background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);padding:32px;max-width:400px;text-align:center}
.box h2{margin-bottom:8px;color:#ef4444}
.box p{color:var(--text2);font-size:14px;margin-bottom:16px}
.btn{padding:10px 20px;border:none;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;background:var(--accent);color:#fff;text-decoration:none;display:inline-block}
.btn:hover{background:var(--accent2)}
</style>
</head>
<body>
<div class="box">
  <h2>${title}</h2>
  <p>${msg}</p>
  <a class="btn" href="/">Try Again</a>
</div>
</body>
</html>`;
}
