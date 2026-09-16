// OmniLink Use Worker - use.omniilink.workers.dev
// Auth gate + redirects to ProDesk backend with user's API keys

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    try {
      if (path === '/api/auth' && request.method === 'POST') {
        const { token } = await request.json();
        const session = await env.DB.prepare(
          'SELECT user_id FROM sessions WHERE token = ? AND expires_at > datetime(\'now\')'
        ).bind(token).first();
        if (!session) return new Response(JSON.stringify({ error: 'Invalid session' }), {
          status: 401, headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });

        const keys = await env.DB.prepare('SELECT provider, api_key FROM user_api_keys WHERE user_id = ?')
          .bind(session.user_id).all();
        const backendSetting = await env.DB.prepare('SELECT value FROM settings WHERE key = ?').bind('backend_url').first();

        return new Response(JSON.stringify({
          valid: true,
          apiKeys: Object.fromEntries(keys.results.map(k => [k.provider, k.api_key])),
          backendUrl: backendSetting?.value || '',
        }), {
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      // Serve the app page
      return new Response(getUsePage(), {
        headers: { 'Content-Type': 'text/html;charset=utf-8', ...corsHeaders },
      });
    } catch (err) {
      return new Response(JSON.stringify({ error: err.message }), {
        status: 500, headers: { 'Content-Type': 'application/json', ...corsHeaders },
      });
    }
  },
};

function getUsePage() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
<title>OmniLink</title>
<link rel="icon" type="image/x-icon" href="FAVICON_URL">
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#09090b;--bg2:#111113;--bg3:#18181b;--border:#27272a;--text:#fafafa;--text2:#a1a1aa;--accent:#2563eb;--accent2:#3b82f6;--radius:10px}
body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);height:100vh;display:flex;align-items:center;justify-content:center}
.loading{text-align:center;color:var(--text2);font-size:14px}
.spinner{width:32px;height:32px;border:3px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin 0.8s linear infinite;margin:0 auto 16px}
@keyframes spin{to{transform:rotate(360deg)}}
.error-box{background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);padding:32px;max-width:400px;text-align:center}
.error-box h2{margin-bottom:8px}
.error-box p{color:var(--text2);font-size:14px;margin-bottom:16px}
.btn{padding:10px 20px;border:none;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;background:var(--accent);color:#fff;text-decoration:none;display:inline-block}
.btn:hover{background:var(--accent2)}
</style>
</head>
<body>
<div class="loading" id="state">
  <div class="spinner"></div>
  <p>Verifying your account...</p>
</div>
<script>
(async function() {
  const state = document.getElementById('state');
  const token = localStorage.getItem('omnilink_token');

  if (!token) {
    state.innerHTML = '<div class="error-box"><h2>Sign in required</h2><p>You need an OmniLink account to use this app.</p><a class="btn" href="https://signup.omniilink.workers.dev">Sign in</a></div>';
    return;
  }

  try {
    const r = await fetch('/api/auth', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token })
    });
    const data = await r.json();

    if (!data.valid || !data.backendUrl) {
      state.innerHTML = '<div class="error-box"><h2>Session expired</h2><p>Please sign in again.</p><a class="btn" href="https://signup.omniilink.workers.dev">Sign in</a></div>';
      localStorage.removeItem('omnilink_token');
      return;
    }

    // Store keys and redirect to backend
    localStorage.setItem('omnilink_apikeys', JSON.stringify(data.apiKeys));
    localStorage.setItem('omnilink_backend', data.backendUrl);

    // Load the full OmniLink app from the backend
    window.location.href = data.backendUrl + '?v=' + Date.now();
  } catch(e) {
    state.innerHTML = '<div class="error-box"><h2>Connection error</h2><p>Could not reach OmniLink servers. Try again later.</p><a class="btn" href="https://signup.omniilink.workers.dev">Back to sign in</a></div>';
  }
})();
</script>
</body>
</html>`;
}
