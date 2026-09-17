// Omniilink Use Worker - useomniilink.omniilink.workers.dev
// Auth gate + reverse proxy to ProDesk tunnel

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-User-Keys',
};

function jsonResp(data, status) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders },
  });
}

function parseUserKeys(header) {
  if (!header) return {};
  try { return JSON.parse(header); } catch(e) { return {}; }
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

function makeHtmlResponse(html, status = 200) {
  return new Response(html, {
    status,
    headers: { 'Content-Type': 'text/html;charset=utf-8', ...corsHeaders },
  });
}

function generateApiKey() {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let key = 'ml-';
  for (let i = 0; i < 48; i++) {
    key += chars[Math.floor(Math.random() * chars.length)];
  }
  return key;
}

async function getUserIdFromSession(env, request) {
  const token = getCookie(request, 'omnilink_token') || request.headers.get('Authorization')?.replace('Bearer ', '');
  if (!token) return null;
  const session = await env.DB.prepare(
    'SELECT user_id FROM sessions WHERE token = ? AND expires_at > datetime(\'now\')'
  ).bind(token).first();
  return session ? session.user_id : null;
}

async function getUserProviderKeys(env, userId) {
  const keys = await env.DB.prepare('SELECT provider, api_key FROM user_api_keys WHERE user_id = ?')
    .bind(userId).all();
  return Object.fromEntries(keys.results.map(k => [k.provider, k.api_key]));
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    try {
      // --- Auth endpoints ---
      if (path === '/api/auth' && request.method === 'POST') {
        const { token } = await request.json();
        if (!token) return jsonResp({ error: 'Token required' }, 400);
        const session = await env.DB.prepare(
          'SELECT user_id FROM sessions WHERE token = ? AND expires_at > datetime(\'now\')'
        ).bind(token).first();
        if (!session) return jsonResp({ error: 'Invalid session' }, 401);
        const keys = await env.DB.prepare('SELECT provider, api_key FROM user_api_keys WHERE user_id = ?')
          .bind(session.user_id).all();
        const backendSetting = await env.DB.prepare('SELECT value FROM settings WHERE key = ?').bind('backend_url').first();
        return jsonResp({
          valid: true,
          apiKeys: Object.fromEntries(keys.results.map(k => [k.provider, k.api_key])),
          backendUrl: backendSetting?.value || '',
        }, 200);
      }

      if (path === '/api/set-backend' && request.method === 'POST') {
        const authHeader = request.headers.get('Authorization');
        if (!authHeader || !authHeader.startsWith('Bearer ')) return jsonResp({ error: 'Unauthorized' }, 401);
        const token = authHeader.slice(7);
        const session = await env.DB.prepare(
          'SELECT user_id FROM sessions WHERE token = ? AND expires_at > datetime(\'now\')'
        ).bind(token).first();
        if (!session) return jsonResp({ error: 'Invalid session' }, 401);
        const { backendUrl } = await request.json();
        if (!backendUrl || !backendUrl.startsWith('https://')) return jsonResp({ error: 'Invalid URL. Must start with https://' }, 400);
        await env.DB.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)').bind('backend_url', backendUrl).run();
        return jsonResp({ success: true }, 200);
      }

      if (path === '/api/health') {
        const backendSetting = await env.DB.prepare('SELECT value FROM settings WHERE key = ?').bind('backend_url').first();
        const backendUrl = backendSetting?.value;
        if (!backendUrl) return jsonResp({ status: 'no_backend', backendUrl: null, healthy: false }, 200);
        try {
          const resp = await fetch(backendUrl + '/api/status', { method: 'GET', signal: AbortSignal.timeout(5000) });
          const updatedAt = await env.DB.prepare('SELECT value FROM settings WHERE key = ?').bind('backend_url_updated_at').first();
          return jsonResp({ status: 'ok', backendUrl, healthy: resp.ok, code: resp.status, updatedAt: updatedAt?.value || null }, 200);
        } catch (e) {
          const updatedAt = await env.DB.prepare('SELECT value FROM settings WHERE key = ?').bind('backend_url_updated_at').first();
          return jsonResp({ status: 'unreachable', backendUrl, healthy: false, error: e.message, updatedAt: updatedAt?.value || null }, 200);
        }
      }

      // --- API Key management (requires session auth) ---
      if (path === '/api/keys' && request.method === 'GET') {
        const userId = await getUserIdFromSession(env, request);
        if (!userId) return jsonResp({ error: 'Unauthorized' }, 401);
        const keys = await env.DB.prepare('SELECT id, key, name, created_at, last_used_at, request_count FROM api_keys WHERE user_id = ?')
          .bind(userId).all();

        const providerDefs = {
          gemini: { name: 'Google Gemini', env: 'GEMINI_API_KEY', models: 11 },
          openai: { name: 'OpenAI', env: 'OPENAI_API_KEY', models: 5 },
          anthropic: { name: 'Anthropic', env: 'ANTHROPIC_API_KEY', models: 5 },
          groq: { name: 'Groq', env: 'GROQ_API_KEY', models: 10 },
          mistral: { name: 'Mistral', env: 'MISTRAL_API_KEY', models: 5 },
          deepseek: { name: 'DeepSeek', env: 'DEEPSEEK_API_KEY', models: 3 },
          openrouter: { name: 'OpenRouter', env: 'OPENROUTER_API_KEY', models: 3 },
          together: { name: 'Together', env: 'TOGETHER_API_KEY', models: 3 },
          xai: { name: 'xAI', env: 'XAI_API_KEY', models: 3 },
          cohere: { name: 'Cohere', env: 'COHERE_API_KEY', models: 3 },
        };
        const userKeys = parseUserKeys(request.headers.get('x-user-keys'));
        const providers = {};
        for (const [id, def] of Object.entries(providerDefs)) {
          const hasBrowser = !!(userKeys[id]);
          const hasEnv = !!(env[def.env]);
          providers[id] = { name: def.name, configured: hasBrowser || hasEnv, models: def.models, source: hasBrowser ? 'browser' : hasEnv ? 'server' : null };
        }
        return jsonResp({ keys: keys.results, providers }, 200);
      }

      if (path === '/api/keys/generate' && request.method === 'POST') {
        const userId = await getUserIdFromSession(env, request);
        if (!userId) return jsonResp({ error: 'Unauthorized' }, 401);
        const body = await request.json().catch(() => ({}));
        const key = generateApiKey();
        const name = body.name || 'API Key';
        await env.DB.prepare('INSERT INTO api_keys (user_id, key, name) VALUES (?, ?, ?)')
          .bind(userId, key, name).run();
        return jsonResp({ key, name }, 200);
      }

      if (path === '/api/keys/revoke' && request.method === 'POST') {
        const userId = await getUserIdFromSession(env, request);
        if (!userId) return jsonResp({ error: 'Unauthorized' }, 401);
        const body = await request.json();
        if (!body.key) return jsonResp({ error: 'Key required' }, 400);
        await env.DB.prepare('DELETE FROM api_keys WHERE user_id = ? AND key = ?')
          .bind(userId, body.key).run();
        return jsonResp({ success: true }, 200);
      }

      // --- Determine auth method ---
      const isApiPath = path.startsWith('/v1/') || path.startsWith('/api/');
      let userId = null;
      let authMethod = null;

      // 1. Try permanent API key first (for /v1/* paths)
      const authHeader = request.headers.get('Authorization');
      if (authHeader && authHeader.startsWith('Bearer ml-')) {
        const apiKey = authHeader.slice(7);
        const keyRecord = await env.DB.prepare('SELECT user_id FROM api_keys WHERE key = ?').bind(apiKey).first();
        if (keyRecord) {
          userId = keyRecord.user_id;
          authMethod = 'api_key';
          await env.DB.prepare('UPDATE api_keys SET last_used_at = datetime(\'now\'), request_count = request_count + 1 WHERE key = ?')
            .bind(apiKey).run();
        } else {
          if (isApiPath) return jsonResp({ error: 'Invalid API key' }, 401);
          return makeHtmlResponse(getAuthPage('Invalid API key.'));
        }
      }

      // 2. Try session token (cookie or query param or Bearer)
      if (!userId) {
        const token = getCookie(request, 'omnilink_token') || url.searchParams.get('token')
          || (authHeader && authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null);
        if (!token) {
          if (isApiPath) return jsonResp({ error: 'Authentication required. Send Authorization: Bearer <api_key_or_session_token>' }, 401);
          return makeHtmlResponse(getAuthPage());
        }
        const session = await env.DB.prepare(
          'SELECT user_id FROM sessions WHERE token = ? AND expires_at > datetime(\'now\')'
        ).bind(token).first();
        if (!session) {
          if (isApiPath) return jsonResp({ error: 'Invalid or expired token' }, 401);
          return makeHtmlResponse(getAuthPage('Session expired. Please sign in again.'));
        }
        userId = session.user_id;
        authMethod = 'session';
      }

      const cookieHeader = `omnilink_token=${getCookie(request, 'omnilink_token') || ''}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400`;
      const hasCookie = getCookie(request, 'omnilink_token');

      // Get user's provider keys
      const dbKeys = await getUserProviderKeys(env, userId);

      const backendSetting = await env.DB.prepare('SELECT value FROM settings WHERE key = ?').bind('backend_url').first();
      const backendUrl = backendSetting?.value;

      if (!backendUrl) {
        if (isApiPath) return jsonResp({ error: 'No backend configured', code: 'NO_BACKEND' }, 503);
        const resp = makeHtmlResponse(getSetupPage(''));
        if (!hasCookie) resp.headers.append('Set-Cookie', cookieHeader);
        return resp;
      }

      // Merge: frontend-sent keys take priority, then D1 keys
      const frontendUserKeys = request.headers.get('X-User-Keys');
      let finalUserKeys;
      if (frontendUserKeys) {
        try { finalUserKeys = frontendUserKeys; } catch(e) { finalUserKeys = JSON.stringify(dbKeys); }
      } else if (Object.keys(dbKeys).length > 0) {
        finalUserKeys = JSON.stringify(dbKeys);
      } else {
        finalUserKeys = null;
      }

      // Build proxy request
      const tunnelBase = new URL(backendUrl);
      const tunnelUrl = new URL(request.url);
      tunnelUrl.hostname = tunnelBase.hostname;
      tunnelUrl.protocol = 'https:';
      tunnelUrl.port = '';
      tunnelUrl.searchParams.delete('token');

      const proxyHeaders = new Headers();
      const skipHeaders = new Set([
        'host', 'cf-connecting-ip', 'cf-ipcountry', 'cf-ray', 'cf-visitor',
        'cf-worker', 'x-forwarded-for', 'x-forwarded-proto', 'x-real-ip',
      ]);
      for (const [key, value] of request.headers) {
        if (!skipHeaders.has(key.toLowerCase())) {
          proxyHeaders.set(key, value);
        }
      }
      proxyHeaders.set('Host', tunnelBase.hostname);
      if (userId) proxyHeaders.set('X-User-Id', String(userId));
      if (finalUserKeys) proxyHeaders.set('X-User-Keys', finalUserKeys);

      const proxyReq = new Request(tunnelUrl.toString(), {
        method: request.method,
        headers: proxyHeaders,
        body: request.body,
        redirect: 'follow',
      });

      let resp;
      let proxyError = null;
      try {
        resp = await fetch(proxyReq, { signal: AbortSignal.timeout(30000) });
      } catch (e) {
        proxyError = e;
      }

      // Self-healing: on proxy failure, re-read URL from D1 and retry once
      if (proxyError) {
        const freshSetting = await env.DB.prepare('SELECT value FROM settings WHERE key = ?').bind('backend_url').first();
        const freshUrl = freshSetting?.value;
        if (freshUrl && freshUrl !== backendUrl) {
          console.log(`Self-healing: backend URL changed (${backendUrl} -> ${freshUrl}), retrying...`);
          const retryTunnelBase = new URL(freshUrl);
          const retryTunnelUrl = new URL(request.url);
          retryTunnelUrl.hostname = retryTunnelBase.hostname;
          retryTunnelUrl.protocol = 'https:';
          retryTunnelUrl.port = '';
          retryTunnelUrl.searchParams.delete('token');
          proxyHeaders.set('Host', retryTunnelBase.hostname);
          const retryProxyReq = new Request(retryTunnelUrl.toString(), {
            method: request.method,
            headers: proxyHeaders,
            body: request.body,
            redirect: 'follow',
          });
          try {
            resp = await fetch(retryProxyReq, { signal: AbortSignal.timeout(30000) });
            proxyError = null;
          } catch (e2) {
            proxyError = e2;
          }
        }
      }

      if (proxyError) {
        const e = proxyError;
        if (path === '/' || path === '') {
          const errResp = makeHtmlResponse(getSetupPage('Backend server is offline. Enter the current tunnel URL.'));
          if (!hasCookie) errResp.headers.append('Set-Cookie', cookieHeader);
          return errResp;
        }
        if (isApiPath) {
          const errResp = jsonResp({ error: 'Backend server is offline', code: 'BACKEND_OFFLINE' }, 502);
          if (!hasCookie) errResp.headers.append('Set-Cookie', cookieHeader);
          return errResp;
        }
        const errResp = makeHtmlResponse(getErrorPage('Server Offline', 'The backend server is unreachable.', 'Try again', '/'), 502);
        if (!hasCookie) errResp.headers.append('Set-Cookie', cookieHeader);
        return errResp;
      }

      const contentType = resp.headers.get('Content-Type') || '';

      if (contentType.includes('text/html')) {
        let html = await resp.text();
        const injection = `window.__OMNILINK_TUNNEL=${JSON.stringify(backendUrl)};`;
        if (html.includes('const API = \'\';') || html.includes("const API='';")) {
          html = html.replace("const API = '';", `const API = ''; ${injection}`);
          html = html.replace("const API='';", `const API=''; ${injection}`);
        } else if (html.includes('</head>')) {
          html = html.replace('</head>', `<script>${injection}</script></head>`);
        } else if (html.includes('</body>')) {
          html = html.replace('</body>', `<script>${injection}</script></body>`);
        } else {
          html = `<script>${injection}</script>${html}`;
        }
        const newHeaders = new Headers();
        newHeaders.set('Content-Type', 'text/html;charset=utf-8');
        newHeaders.set('Access-Control-Allow-Origin', '*');
        if (!hasCookie) newHeaders.append('Set-Cookie', cookieHeader);
        return new Response(html, { status: resp.status, headers: newHeaders });
      }

      const newHeaders = new Headers(resp.headers);
      newHeaders.set('Access-Control-Allow-Origin', '*');
      newHeaders.delete('content-security-policy');
      newHeaders.delete('x-frame-options');
      newHeaders.delete('x-content-security-policy');
      if (!hasCookie) newHeaders.append('Set-Cookie', cookieHeader);

      return new Response(resp.body, {
        status: resp.status,
        statusText: resp.statusText,
        headers: newHeaders,
      });
    } catch (err) {
      return makeHtmlResponse(getErrorPage('Something Went Wrong', 'An unexpected error occurred. Please try again.'), 500);
    }
  },
};

function getSetupPage(error) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>Omniilink - Setup</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#0a0a0c;--surface:#111114;--border:#232328;--text:#f0f0f4;--muted:#8e8e96;--accent:#3b6df5;--accent-hover:#4d7df6;--error:#e54545;--error-bg:rgba(229,69,69,0.08);--error-border:rgba(229,69,69,0.25);--success:#2dba4e;--radius:12px;--shadow:0 4px 24px rgba(0,0,0,0.4)}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;min-height:100dvh;display:flex;align-items:center;justify-content:center;padding:24px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:40px 32px;max-width:420px;width:100%;box-shadow:var(--shadow)}
.header{text-align:center;margin-bottom:28px}
.logo{display:inline-flex;align-items:center;gap:10px;margin-bottom:16px}
.logo-icon{width:36px;height:36px;border-radius:10px;background:var(--accent);display:flex;align-items:center;justify-content:center}
.logo-icon svg{width:20px;height:20px}
.logo-text{font-size:22px;font-weight:700;letter-spacing:-0.3px}
.header p{color:var(--muted);font-size:14px;line-height:1.5}
.alert-error{background:var(--error-bg);border:1px solid var(--error-border);border-radius:8px;padding:12px 14px;color:var(--error);font-size:13px;margin-bottom:20px}
.field{display:flex;gap:8px;margin-bottom:16px}
input[type=url]{flex:1;padding:11px 14px;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:14px;outline:none;transition:border-color .15s}
input[type=url]::placeholder{color:#555}
input[type=url]:focus{border-color:var(--accent)}
.btn{padding:11px 22px;border:none;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;transition:background .15s}
.btn-primary{background:var(--accent);color:#fff}
.btn-primary:hover{background:var(--accent-hover)}
.btn-primary:disabled{opacity:.5;cursor:not-allowed}
.msg{font-size:13px;text-align:center;margin-top:10px;min-height:18px}
.msg-ok{color:var(--success)}
.msg-err{color:var(--error)}
.footer{text-align:center;margin-top:20px}
.footer a{color:var(--muted);font-size:13px;text-decoration:none;transition:color .15s}
.footer a:hover{color:var(--accent)}
@media(max-width:480px){.card{padding:28px 20px}.field{flex-direction:column}}
</style>
</head>
<body>
<div class="card">
  <div class="header">
    <div class="logo">
      <div class="logo-icon"><svg viewBox="0 0 24 24" fill="none"><rect width="24" height="24" rx="6" fill="#3b6df5"/><path d="M7 8h10M7 12h10M7 16h6" stroke="#fff" stroke-width="2" stroke-linecap="round"/></svg></div>
      <span class="logo-text">Omniilink</span>
    </div>
    <p>Enter your ProDesk tunnel URL to connect to your server.</p>
  </div>
  ${error ? '<div class="alert-error">' + escapeHtml(error) + '</div>' : ''}
  <div class="field">
    <input type="url" id="url" placeholder="https://example.trycloudflare.com">
    <button class="btn btn-primary" id="btn" onclick="save()">Connect</button>
  </div>
  <div class="msg" id="msg"></div>
  <div class="footer"><a href="https://signupomniilink.omniilink.workers.dev">Back to Sign In</a></div>
</div>
<script>
async function save(){
  var btn=document.getElementById('btn'),input=document.getElementById('url'),msg=document.getElementById('msg');
  var u=input.value.trim();
  if(!u){msg.textContent='Please enter a URL';msg.className='msg msg-err';return}
  btn.disabled=true;btn.textContent='Connecting\u2026';msg.textContent='';
  try{
    var r=await fetch('/api/set-backend',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({backendUrl:u})});
    var d=await r.json();
    if(d.success){msg.textContent='Connected! Redirecting\u2026';msg.className='msg msg-ok';setTimeout(function(){window.location.href='/'},1000)}
    else{msg.textContent=d.error||'Failed';msg.className='msg msg-err'}
  }catch(e){msg.textContent='Network error';msg.className='msg msg-err'}
  btn.disabled=false;btn.textContent='Connect';
}
document.getElementById('url').addEventListener('keydown',function(e){if(e.key==='Enter')save()});
</script>
</body>
</html>`;
}

function getAuthPage(error) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>Omniilink - Sign In</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#0a0a0c;--surface:#111114;--border:#232328;--text:#f0f0f4;--muted:#8e8e96;--accent:#3b6df5;--accent-hover:#4d7df6;--error:#e54545;--error-bg:rgba(229,69,69,0.08);--error-border:rgba(229,69,69,0.25);--radius:12px;--shadow:0 4px 24px rgba(0,0,0,0.4)}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;min-height:100dvh;display:flex;align-items:center;justify-content:center;padding:24px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:40px 32px;max-width:380px;width:100%;text-align:center;box-shadow:var(--shadow)}
.logo{display:inline-flex;align-items:center;gap:10px;margin-bottom:20px}
.logo-icon{width:40px;height:40px;border-radius:10px;background:var(--accent);display:flex;align-items:center;justify-content:center}
.logo-icon svg{width:22px;height:22px}
.logo-text{font-size:24px;font-weight:700;letter-spacing:-0.3px}
.card h1{font-size:20px;margin-bottom:8px;font-weight:600}
.card p{color:var(--muted);font-size:14px;line-height:1.5;margin-bottom:20px}
.alert-error{background:var(--error-bg);border:1px solid var(--error-border);border-radius:8px;padding:12px 14px;color:var(--error);font-size:13px;margin-bottom:20px}
.btn{display:inline-block;padding:12px 28px;border:none;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;text-decoration:none;transition:background .15s}
.btn-primary{background:var(--accent);color:#fff}
.btn-primary:hover{background:var(--accent-hover)}
.links{margin-top:20px;font-size:13px;color:var(--muted)}
.links a{color:var(--accent);text-decoration:none;transition:color .15s}
.links a:hover{color:var(--accent-hover)}
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <div class="logo-icon"><svg viewBox="0 0 24 24" fill="none"><rect width="24" height="24" rx="6" fill="#3b6df5"/><path d="M7 8h10M7 12h10M7 16h6" stroke="#fff" stroke-width="2" stroke-linecap="round"/></svg></div>
    <span class="logo-text">Omniilink</span>
  </div>
  ${error ? '<div class="alert-error">' + escapeHtml(error) + '</div>' : ''}
  <h1>Welcome back</h1>
  <p>Sign in to access your Omniilink workspace.</p>
  <a class="btn btn-primary" href="https://signupomniilink.omniilink.workers.dev">Sign In</a>
  <div class="links">New here? <a href="https://signupomniilink.omniilink.workers.dev">Create an account</a></div>
</div>
</body>
</html>`;
}

function getErrorPage(title, msg, actionText, actionHref) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Omniilink - Error</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#0a0a0c;--surface:#111114;--border:#232328;--text:#f0f0f4;--muted:#8e8e96;--accent:#3b6df5;--accent-hover:#4d7df6;--error:#e54545;--radius:12px;--shadow:0 4px 24px rgba(0,0,0,0.4)}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:40px 32px;max-width:380px;width:100%;text-align:center;box-shadow:var(--shadow)}
.icon{width:56px;height:56px;border-radius:50%;background:rgba(229,69,69,0.1);display:inline-flex;align-items:center;justify-content:center;margin-bottom:20px}
.icon svg{width:28px;height:28px}
.card h2{font-size:18px;margin-bottom:8px;font-weight:600}
.card p{color:var(--muted);font-size:14px;line-height:1.5;margin-bottom:24px}
.btn{display:inline-block;padding:11px 24px;border:none;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;text-decoration:none;transition:background .15s}
.btn-primary{background:var(--accent);color:#fff}
.btn-primary:hover{background:var(--accent-hover)}
</style>
</head>
<body>
<div class="card">
  <div class="icon"><svg viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="10" stroke="#e54545" stroke-width="2"/><path d="M12 8v5M12 16v.01" stroke="#e54545" stroke-width="2" stroke-linecap="round"/></svg></div>
  <h2>${escapeHtml(title)}</h2>
  <p>${escapeHtml(msg)}</p>
  <a class="btn btn-primary" href="${escapeHtml(actionHref || '/')}">${escapeHtml(actionText || 'Try Again')}</a>
</div>
</body>
</html>`;
}
