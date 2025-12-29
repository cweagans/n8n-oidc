/**
 * n8n External Hooks for OIDC Authentication
 *
 * This file implements OIDC authentication support for n8n using only built-in Node.js modules.
 * It provides:
 * - OIDC discovery endpoint support
 * - Authorization code flow
 * - User provisioning (JIT - Just In Time)
 * - Frontend customization to show OIDC login button
 *
 * Environment Variables Required:
 * - OIDC_ISSUER_URL: The OIDC provider's issuer URL (e.g., https://auth.example.com)
 * - OIDC_CLIENT_ID: OAuth2 client ID
 * - OIDC_CLIENT_SECRET: OAuth2 client secret
 * - OIDC_REDIRECT_URI: The callback URL (e.g., https://n8n.example.com/auth/oidc/callback)
 *
 * Optional:
 * - OIDC_SCOPES: Space-separated list of scopes (default: "openid email profile")
 */

const https = require('https');
const http = require('http');
const crypto = require('crypto');
const { URL, URLSearchParams } = require('url');

// Configuration from environment
const config = {
  issuerUrl: process.env.OIDC_ISSUER_URL,
  clientId: process.env.OIDC_CLIENT_ID,
  clientSecret: process.env.OIDC_CLIENT_SECRET,
  redirectUri: process.env.OIDC_REDIRECT_URI,
  scopes: process.env.OIDC_SCOPES || 'openid email profile',
};

// Validate configuration
function validateConfig() {
  const missing = [];
  if (!config.issuerUrl) missing.push('OIDC_ISSUER_URL');
  if (!config.clientId) missing.push('OIDC_CLIENT_ID');
  if (!config.clientSecret) missing.push('OIDC_CLIENT_SECRET');
  if (!config.redirectUri) missing.push('OIDC_REDIRECT_URI');
  return missing;
}

// Cache for OIDC discovery document
let discoveryCache = null;
let discoveryCacheTime = 0;
const DISCOVERY_CACHE_TTL = 3600000; // 1 hour

/**
 * Make an HTTP/HTTPS request
 * @param {string} url - The URL to request
 * @param {object} options - Request options
 * @returns {Promise<{statusCode: number, headers: object, body: string}>}
 */
function makeRequest(url, options = {}) {
  return new Promise((resolve, reject) => {
    const parsedUrl = new URL(url);
    const protocol = parsedUrl.protocol === 'https:' ? https : http;

    const reqOptions = {
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
      path: parsedUrl.pathname + parsedUrl.search,
      method: options.method || 'GET',
      headers: options.headers || {},
    };

    const req = protocol.request(reqOptions, (res) => {
      let body = '';
      res.on('data', (chunk) => (body += chunk));
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          body,
        });
      });
    });

    req.on('error', reject);

    if (options.body) {
      req.write(options.body);
    }

    req.end();
  });
}

/**
 * Fetch OIDC discovery document
 * @returns {Promise<object>}
 */
async function fetchDiscoveryDocument() {
  const now = Date.now();
  if (discoveryCache && now - discoveryCacheTime < DISCOVERY_CACHE_TTL) {
    return discoveryCache;
  }

  const discoveryUrl = config.issuerUrl.replace(/\/$/, '') + '/.well-known/openid-configuration';
  const response = await makeRequest(discoveryUrl);

  if (response.statusCode !== 200) {
    throw new Error(`Failed to fetch OIDC discovery document: ${response.statusCode}`);
  }

  discoveryCache = JSON.parse(response.body);
  discoveryCacheTime = now;
  return discoveryCache;
}

/**
 * Generate a random string for state/nonce
 * @param {number} length
 * @returns {string}
 */
function generateRandomString(length = 32) {
  return crypto.randomBytes(length).toString('hex');
}

/**
 * Base64URL encode
 * @param {Buffer|string} input
 * @returns {string}
 */
function base64UrlEncode(input) {
  const base64 = Buffer.isBuffer(input) ? input.toString('base64') : Buffer.from(input).toString('base64');
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Base64URL decode
 * @param {string} input
 * @returns {Buffer}
 */
function base64UrlDecode(input) {
  let base64 = input.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) {
    base64 += '=';
  }
  return Buffer.from(base64, 'base64');
}

/**
 * Decode JWT without verification (for extracting claims)
 * @param {string} token
 * @returns {object}
 */
function decodeJwt(token) {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid JWT format');
  }

  const payload = JSON.parse(base64UrlDecode(parts[1]).toString('utf8'));
  return payload;
}

/**
 * Exchange authorization code for tokens
 * @param {string} code
 * @param {object} discovery
 * @returns {Promise<object>}
 */
async function exchangeCodeForTokens(code, discovery) {
  const params = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: config.redirectUri,
    client_id: config.clientId,
    client_secret: config.clientSecret,
  });

  const response = await makeRequest(discovery.token_endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: params.toString(),
  });

  if (response.statusCode !== 200) {
    console.error('Token exchange failed:', response.body);
    throw new Error(`Token exchange failed: ${response.statusCode}`);
  }

  return JSON.parse(response.body);
}

/**
 * Fetch user info from OIDC provider
 * @param {string} accessToken
 * @param {object} discovery
 * @returns {Promise<object>}
 */
async function fetchUserInfo(accessToken, discovery) {
  const response = await makeRequest(discovery.userinfo_endpoint, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
  });

  if (response.statusCode !== 200) {
    console.error('UserInfo fetch failed:', response.body);
    throw new Error(`UserInfo fetch failed: ${response.statusCode}`);
  }

  return JSON.parse(response.body);
}

/**
 * Create a signed JWT for state/nonce storage
 * We use the JWT service from n8n when available, but for cookies we just use HMAC
 * @param {object} payload
 * @param {string} secret
 * @param {number} expiresInSeconds
 * @returns {string}
 */
function createSignedCookie(payload, secret, expiresInSeconds = 900) {
  const exp = Math.floor(Date.now() / 1000) + expiresInSeconds;
  const data = JSON.stringify({ ...payload, exp });
  const hmac = crypto.createHmac('sha256', secret);
  hmac.update(data);
  const signature = hmac.digest('hex');
  return base64UrlEncode(data) + '.' + signature;
}

/**
 * Verify and decode a signed cookie
 * @param {string} cookie
 * @param {string} secret
 * @returns {object|null}
 */
function verifySignedCookie(cookie, secret) {
  try {
    const [dataB64, signature] = cookie.split('.');
    const data = base64UrlDecode(dataB64).toString('utf8');

    const hmac = crypto.createHmac('sha256', secret);
    hmac.update(data);
    const expectedSignature = hmac.digest('hex');

    if (signature !== expectedSignature) {
      return null;
    }

    const payload = JSON.parse(data);
    if (payload.exp && payload.exp < Date.now() / 1000) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}

/**
 * Get or create the cookie signing secret
 * We derive it from the n8n encryption key if available
 * @param {object} context
 * @returns {string}
 */
function getCookieSecret(context) {
  // Use a combination of environment variables to create a stable secret
  const baseKey = process.env.N8N_ENCRYPTION_KEY || process.env.OIDC_CLIENT_SECRET || 'n8n-oidc-hook-secret';
  const hash = crypto.createHash('sha256').update(baseKey + '-oidc-state').digest('hex');
  return hash;
}

/**
 * Create the n8n auth cookie using n8n's JwtService
 * @param {object} user
 * @param {object} jwtService - n8n's JwtService instance
 * @returns {string}
 */
function createAuthToken(user, jwtService) {
  // n8n's JWT contains: { id, hash, browserId?, usedMfa? }
  const payload = {
    id: user.id,
    hash: createUserHash(user),
    usedMfa: false,
  };

  return jwtService.sign(payload, { expiresIn: '7d' });
}

/**
 * Create user hash for JWT (mimics n8n's AuthService.createJWTHash)
 * @param {object} user
 * @returns {string}
 */
function createUserHash(user) {
  const payload = [user.email, user.password || ''];
  if (user.mfaEnabled && user.mfaSecret) {
    payload.push(user.mfaSecret.substring(0, 3));
  }
  return crypto.createHash('sha256').update(payload.join(':')).digest('base64').substring(0, 10);
}

/**
 * Check if email is valid
 * @param {string} email
 * @returns {boolean}
 */
function isValidEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

// n8n module paths (specific to the Docker image)
const N8N_DI_PATH = '/usr/local/lib/node_modules/n8n/node_modules/@n8n/di';
const N8N_JWT_SERVICE_PATH = '/usr/local/lib/node_modules/n8n/dist/services/jwt.service.js';

// Export the hooks
module.exports = {
  n8n: {
    /**
     * Called when n8n is ready
     * We use this to register custom routes for OIDC
     */
    ready: [
      async function (server, n8nConfig) {
        const missing = validateConfig();
        if (missing.length > 0) {
          console.warn(`[OIDC Hook] Missing configuration: ${missing.join(', ')}. OIDC disabled.`);
          return;
        }

        console.log('[OIDC Hook] Initializing OIDC authentication...');

        // Get n8n's JwtService from the DI container
        const { Container } = require(N8N_DI_PATH);
        const { JwtService } = require(N8N_JWT_SERVICE_PATH);
        const jwtService = Container.get(JwtService);

        const { app } = server;
        const cookieSecret = getCookieSecret();

        // Cookie settings
        const cookieOptions = {
          httpOnly: true,
          secure: process.env.N8N_PROTOCOL === 'https',
          sameSite: 'lax',
          maxAge: 15 * 60 * 1000, // 15 minutes
        };

        const authCookieOptions = {
          httpOnly: true,
          secure: process.env.N8N_PROTOCOL === 'https',
          sameSite: 'lax',
          maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        };

        /**
         * OIDC Login endpoint - redirects to the OIDC provider
         */
        app.get('/auth/oidc/login', async (req, res) => {
          try {
            const discovery = await fetchDiscoveryDocument();

            const state = generateRandomString();
            const nonce = generateRandomString();

            // Store state and nonce in signed cookies
            const stateCookie = createSignedCookie({ state }, cookieSecret);
            const nonceCookie = createSignedCookie({ nonce }, cookieSecret);

            res.cookie('n8n-oidc-state', stateCookie, cookieOptions);
            res.cookie('n8n-oidc-nonce', nonceCookie, cookieOptions);

            // Build authorization URL
            const authUrl = new URL(discovery.authorization_endpoint);
            authUrl.searchParams.set('client_id', config.clientId);
            authUrl.searchParams.set('redirect_uri', config.redirectUri);
            authUrl.searchParams.set('response_type', 'code');
            authUrl.searchParams.set('scope', config.scopes);
            authUrl.searchParams.set('state', state);
            authUrl.searchParams.set('nonce', nonce);

            res.redirect(authUrl.toString());
          } catch (error) {
            console.error('[OIDC Hook] Login error:', error);
            res.status(500).send('OIDC configuration error. Please check the logs.');
          }
        });

        /**
         * OIDC Callback endpoint - handles the authorization code
         */
        app.get('/auth/oidc/callback', async (req, res) => {
          try {
            const { code, state, error, error_description } = req.query;

            // Handle OIDC errors
            if (error) {
              console.error('[OIDC Hook] OIDC error:', error, error_description);
              return res.redirect('/signin?error=' + encodeURIComponent(error_description || error));
            }

            if (!code || !state) {
              return res.redirect('/signin?error=' + encodeURIComponent('Missing authorization code or state'));
            }

            // Verify state
            const stateCookie = req.cookies['n8n-oidc-state'];
            const nonceCookie = req.cookies['n8n-oidc-nonce'];

            if (!stateCookie || !nonceCookie) {
              return res.redirect('/signin?error=' + encodeURIComponent('Missing state cookies - session expired'));
            }

            const statePayload = verifySignedCookie(stateCookie, cookieSecret);
            const noncePayload = verifySignedCookie(nonceCookie, cookieSecret);

            if (!statePayload || statePayload.state !== state) {
              return res.redirect('/signin?error=' + encodeURIComponent('Invalid state - possible CSRF attack'));
            }

            // Clear state cookies
            res.clearCookie('n8n-oidc-state');
            res.clearCookie('n8n-oidc-nonce');

            // Exchange code for tokens
            const discovery = await fetchDiscoveryDocument();
            const tokens = await exchangeCodeForTokens(code, discovery);

            // Verify nonce in ID token if present
            if (tokens.id_token) {
              const idTokenClaims = decodeJwt(tokens.id_token);
              if (noncePayload && idTokenClaims.nonce !== noncePayload.nonce) {
                return res.redirect('/signin?error=' + encodeURIComponent('Invalid nonce - possible replay attack'));
              }
            }

            // Get user info
            let userInfo;
            try {
              userInfo = await fetchUserInfo(tokens.access_token, discovery);
            } catch (e) {
              // Fall back to ID token claims if userinfo endpoint fails
              if (tokens.id_token) {
                userInfo = decodeJwt(tokens.id_token);
              } else {
                throw e;
              }
            }

            // Validate we have an email
            if (!userInfo.email || !isValidEmail(userInfo.email)) {
              return res.redirect('/signin?error=' + encodeURIComponent('No valid email in OIDC response'));
            }

            // Find or create user in n8n database
            const { User, Settings, Credentials, Workflow } = this.dbCollections;

            // Try to find existing user by email
            let user = await User.findOne({
              where: { email: userInfo.email },
              relations: ['role'],
            });

            if (!user) {
              // Check if this is the first user (should be owner)
              const userCount = await User.count();

              const userData = {
                email: userInfo.email,
                firstName: userInfo.given_name || userInfo.name?.split(' ')[0] || 'User',
                lastName: userInfo.family_name || userInfo.name?.split(' ').slice(1).join(' ') || '',
                password: crypto.randomBytes(32).toString('hex'), // Random password, can't be used
                role: { slug: userCount === 0 ? 'global:owner' : 'global:member' },
              };

              // Use createUserWithProject to create both user and personal project
              const result = await User.createUserWithProject(userData);
              user = result.user;

              console.log(`[OIDC Hook] Created ${userCount === 0 ? 'owner' : 'member'} user with personal project: ${userInfo.email}`);
            }

            if (!user) {
              return res.redirect('/signin?error=' + encodeURIComponent('Failed to create or find user'));
            }

            // Create auth token using n8n's JwtService
            const authToken = createAuthToken(user, jwtService);

            // Set the n8n auth cookie
            res.cookie('n8n-auth', authToken, authCookieOptions);

            // Redirect to home
            res.redirect('/');
          } catch (error) {
            console.error('[OIDC Hook] Callback error:', error);
            res.redirect('/signin?error=' + encodeURIComponent('Authentication failed: ' + error.message));
          }
        });

        /**
         * Serve the frontend customization script
         * This script will replace the login form with an OIDC button
         *
         * NOTE: The route must be under /assets/ or another non-UI route prefix
         * to avoid being intercepted by n8n's history API handler which would
         * serve index.html instead of our JavaScript file.
         */
        app.get('/assets/oidc-frontend-hook.js', (req, res) => {
          // Use res.type() for proper MIME type handling with nosniff
          res.type('text/javascript; charset=utf-8');
          res.set('Cache-Control', 'public, max-age=3600');
          res.send(getFrontendScript());
        });

        console.log('[OIDC Hook] OIDC routes registered:');
        console.log('  - GET /auth/oidc/login');
        console.log('  - GET /auth/oidc/callback');
        console.log('  - GET /assets/oidc-frontend-hook.js');
      },
    ],
  },

  frontend: {
    /**
     * Modify frontend settings to configure SSO display
     */
    settings: [
      async function (frontendSettings) {
        const missing = validateConfig();
        if (missing.length > 0) {
          return; // OIDC not configured, don't modify settings
        }

        // Enable OIDC login button by setting these properties
        // This tells the frontend that OIDC is available
        frontendSettings.sso = frontendSettings.sso || {};
        frontendSettings.sso.oidc = {
          loginEnabled: true,
          loginUrl: '/auth/oidc/login',
          callbackUrl: config.redirectUri,
        };

        // Set authentication method to OIDC so the frontend knows SSO is primary
        frontendSettings.userManagement = frontendSettings.userManagement || {};
        frontendSettings.userManagement.authenticationMethod = 'oidc';

        // Enable enterprise OIDC feature flag so the SSO button shows
        frontendSettings.enterprise = frontendSettings.enterprise || {};
        frontendSettings.enterprise.oidc = true;

        console.log('[OIDC Hook] Frontend settings configured for OIDC');
      },
    ],
  },
};

/**
 * Generate the frontend customization script
 * This script runs in the browser and customizes the login page
 */
function getFrontendScript() {
  return `
/**
 * n8n OIDC Frontend Customization
 *
 * This script surgically modifies the login form to show an SSO button.
 * To access the normal login form, add ?showLogin=true to the URL.
 */
(function() {
	'use strict';

	function shouldShowNormalLogin() {
		return new URLSearchParams(window.location.search).get('showLogin') === 'true';
	}

	function isSigninPage() {
		return window.location.pathname === '/signin' || window.location.pathname === '/login';
	}

	function displayError(form) {
		var error = new URLSearchParams(window.location.search).get('error');
		if (!error || !form || form.querySelector('#oidc-error')) return;

		var errorDiv = document.createElement('div');
		errorDiv.id = 'oidc-error';
		errorDiv.style.cssText = 'background: var(--color-danger-tint-1, #fee); border: 1px solid var(--color-danger, #fcc); color: var(--color-danger, #c00); padding: 12px; border-radius: 4px; margin: 16px 0;';
		errorDiv.textContent = decodeURIComponent(error);

		var heading = form.querySelector('div[class*="_heading_"]');
		if (heading) heading.after(errorDiv);
		else form.prepend(errorDiv);
	}

	function injectSsoButton() {
		if (shouldShowNormalLogin()) return;
		if (!isSigninPage()) return;

		var form = document.querySelector('[data-test-id="auth-form"]');
		if (!form || form.querySelector('#oidc-sso-button')) return;

		// Find existing button to clone its classes
		var existingButton = form.querySelector('[data-test-id="form-submit-button"]');
		var buttonClasses = existingButton ? existingButton.className : '';

		// Hide the form elements (inputs, buttons, forgot password)
		form.querySelectorAll('div[class*="_inputsContainer_"], div[class*="_buttonsContainer_"], div[class*="_actionContainer_"]')
			.forEach(function(el) { el.style.display = 'none'; });

		// Create SSO button container
		var ssoContainer = document.createElement('div');
		ssoContainer.id = 'oidc-sso-container';
		ssoContainer.style.cssText = 'text-align: center;';

		// Create button - use cloned classes or fallback styles
		var button = document.createElement('button');
		button.id = 'oidc-sso-button';
		button.type = 'button';
		button.textContent = 'Sign in with SSO';
		button.onclick = function() { window.location.href = '/auth/oidc/login'; };

		if (buttonClasses) {
			button.className = buttonClasses;
			button.style.width = '100%';
		} else {
			button.style.cssText = 'width: 100%; padding: 12px 24px; font-size: 14px; font-weight: 600; color: white; background: var(--color-primary, #ea4b30); border: none; border-radius: 4px; cursor: pointer;';
		}

		// Create admin link
		var adminLink = document.createElement('p');
		adminLink.style.cssText = 'margin-top: 16px; font-size: 12px; color: var(--color-text-light, #666);';
		adminLink.innerHTML = 'Admin? <a href="?showLogin=true" style="color: var(--color-primary, #ea4b30);">Sign in with email</a>';

		ssoContainer.appendChild(button);
		ssoContainer.appendChild(adminLink);

		// Insert after the heading
		var heading = form.querySelector('div[class*="_heading_"]');
		if (heading) heading.after(ssoContainer);
		else form.prepend(ssoContainer);

		displayError(form);
	}

	function observeAndInject() {
		if (shouldShowNormalLogin() || !isSigninPage()) return;

		injectSsoButton();

		var observer = new MutationObserver(function() {
			if (isSigninPage() && !shouldShowNormalLogin()) {
				var form = document.querySelector('[data-test-id="auth-form"]');
				if (form && !form.querySelector('#oidc-sso-button')) {
					injectSsoButton();
				}
			}
		});

		observer.observe(document.body, { childList: true, subtree: true });
		setTimeout(function() { observer.disconnect(); }, 10000);
	}

	function handleNavigation() {
		var origPush = history.pushState;
		var origReplace = history.replaceState;

		history.pushState = function() {
			origPush.apply(this, arguments);
			setTimeout(observeAndInject, 100);
		};

		history.replaceState = function() {
			origReplace.apply(this, arguments);
			setTimeout(observeAndInject, 100);
		};

		window.addEventListener('popstate', function() {
			setTimeout(observeAndInject, 100);
		});
	}

	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', function() {
			observeAndInject();
			handleNavigation();
		});
	} else {
		observeAndInject();
		handleNavigation();
	}

	setTimeout(observeAndInject, 500);
	setTimeout(observeAndInject, 1000);

	console.log('[OIDC Hook] Frontend customization loaded');
})();
`;
}
