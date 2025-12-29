# n8n-oidc

This project enables OpenID Connect (OIDC) authentication for [n8n](https://n8n.io/) without requiring an enterprise license. It uses n8n's external hooks system to inject OIDC support at runtime.

## Features

- Standard OIDC authorization code flow
- Automatic user provisioning (Just-In-Time)
- First user is automatically assigned the owner role
- Frontend customization to display an SSO login button
- Fallback to email/password login via `?showLogin=true`

## Requirements

- Docker and Docker Compose
- An OIDC provider (e.g., Keycloak, Authentik, [PocketID](https://pocket-id.org), Auth0, Okta)
- A configured OAuth2/OIDC client with your provider

## Setup

### 1. Configure your OIDC provider

Create an OAuth2/OIDC client application with your identity provider. Note the following values:

- **Client ID**
- **Client Secret**
- **Issuer URL** (e.g., `https://auth.example.com`)

Set the redirect URI to: `https://your-n8n-domain.com/auth/oidc/callback`

### 2. Set environment variables

Make sure the following environment variables are set:

```bash
EXTERNAL_HOOK_FILES=/path/to/hooks.js
OIDC_ISSUER_URL=https://auth.example.com
OIDC_CLIENT_ID=your-client-id
OIDC_CLIENT_SECRET=your-client-secret
OIDC_REDIRECT_URI=https://n8n.example.com/auth/oidc/callback
N8N_ADDITIONAL_NON_UI_ROUTES=auth
EXTERNAL_FRONTEND_HOOKS_URLS=/assets/oidc-frontend-hook.js
```

### 3. Restart n8n

Restart n8n to pick up the environment var changes + the new hooks.js.

## Environment Variables

### Required

| Variable | Description |
|----------|-------------|
| `OIDC_ISSUER_URL` | Your OIDC provider's issuer URL |
| `OIDC_CLIENT_ID` | OAuth2 client ID |
| `OIDC_CLIENT_SECRET` | OAuth2 client secret |
| `OIDC_REDIRECT_URI` | The URI that the identity provider will redirect back to. This must be the fully qualified URL with the path `/auth/oidc/callback` (e.g. `https://n8n.example.com/auth/oidc/callback`) |
| `N8N_ADDITIONAL_NON_UI_ROUTES` | This must be set to `auth` to ensure the OIDC URIs work (causes the frontend to not register routes for those paths) |
| `EXTERNAL_FRONTEND_HOOKS_URLS` | This must be set to `/assets/oidc-frontend-hook.js`, which is registered and handled by hooks.js |

### Optional

| Variable | Default | Description |
|----------|---------|-------------|
| `OIDC_SCOPES` | `openid email profile` | Space-separated list of OIDC scopes |

## How It Works

The `hooks.js` file uses n8n's external hooks feature to:

1. Register custom routes for OIDC authentication:
   - `GET /auth/oidc/login` - Initiates the OIDC flow
   - `GET /auth/oidc/callback` - Handles the authorization code exchange

2. Inject a frontend script that replaces the default login form with an SSO button

3. Automatically create user accounts on first login, deriving name and email from OIDC claims

## Accessing the Standard Login Form

To bypass SSO and use email/password authentication, append `?showLogin=true` to the sign-in URL:

```
https://your-n8n-domain.com/signin?showLogin=true
```

## Troubleshooting

**OIDC login button doesn't appear**

- Check that all required environment variables are set
- Verify the hooks.js file is mounted correctly
- Check n8n logs for `[OIDC Hook]` messages

**"Missing state cookies" error**

- Ensure cookies are enabled in your browser
- Check that `N8N_PROTOCOL` matches your actual protocol (http/https)
- If behind a reverse proxy, ensure `N8N_TRUST_PROXY=true` is set

**User creation fails**

- Verify your OIDC provider returns an `email` claim
- Check that the email claim contains a valid email address

## License

MIT License. See [LICENSE.md](LICENSE.md) for details.
