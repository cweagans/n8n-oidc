# n8n-oidc

The `hooks.js` file in this repository adds support for OIDC in n8n without having an enterprise license.

Environment Variables Required:

- `OIDC_ISSUER_URL`: The OIDC provider's issuer URL (e.g., <https://auth.example.com>)
- `OIDC_CLIENT_ID`: OAuth2 client ID
- `OIDC_CLIENT_SECRET`: OAuth2 client secret
- `OIDC_REDIRECT_URI`: The callback URL (e.g., <https://n8n.example.com/auth/oidc/callback>)
- `N8N_ADDITIONAL_NON_UI_ROUTES=auth`
- `EXTERNAL_FRONTEND_HOOKS_URLS=/assets/oidc-frontend-hook.js`

Optional:

- `OIDC_SCOPES`: Space-separated list of scopes (default: "openid email profile")
