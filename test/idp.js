// A fake OIDC provider, just enough for hooks.js: discovery, token, userinfo.
// It issues no id_token, so the hook takes the userinfo path and the nonce
// check is skipped; what this test proves is that the hook starts, finds the
// n8n internals it needs, and issues a session cookie n8n accepts.
const http = require('http');
http.createServer((req, res) => {
  const j = (o) => { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify(o)); };
  if (req.url.startsWith('/.well-known/openid-configuration')) return j({
    authorization_endpoint: 'http://127.0.0.1:9999/authorize',
    token_endpoint: 'http://127.0.0.1:9999/token',
    userinfo_endpoint: 'http://127.0.0.1:9999/userinfo' });
  if (req.url.startsWith('/token')) return j({ access_token: 'at', token_type: 'Bearer' });
  if (req.url.startsWith('/userinfo')) return j({ email: 'tester@example.com', given_name: 'Test', family_name: 'User' });
  res.statusCode = 404; res.end();
}).listen(9999, '127.0.0.1');
