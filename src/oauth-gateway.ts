#!/usr/bin/env node
/**
 * OAuth 2.0 Gateway for MCP
 *
 * Implements the Authorization Code + PKCE flow so Claude.ai (and other
 * OAuth-capable MCP clients) can connect without pre-sharing credentials.
 *
 * Flow:
 *   1. Claude.ai discovers /oauth/authorize via /.well-known/oauth-authorization-server
 *   2. Claude.ai redirects user to /oauth/authorize  →  HTML form (Metabase URL + key)
 *   3. User submits  →  server stores creds under a temp code  →  redirect back to client
 *   4. Claude.ai POSTs /oauth/token with code  →  server returns access + refresh JWT
 *   5. Claude.ai calls /mcp with  Authorization: Bearer <JWT>
 *   6. Gateway validates JWT, injects x-metabase-* headers, proxies to FastMCP
 *   7. When the access token expires, Claude.ai POSTs /oauth/token with
 *      grant_type=refresh_token  →  server returns a fresh pair (rotation)
 *
 * Environment variables:
 *   GATEWAY_URL            Public base URL of this gateway  (e.g. https://mcp.example.com)
 *   GATEWAY_PORT           Port to listen on                (default: 8080)
 *   MCP_UPSTREAM           FastMCP HTTP Stream URL          (default: http://localhost:8011)
 *   JWT_SECRET             Secret for signing tokens        (required — env var or vault)
 *   TOKEN_EXPIRY           Access token expiry              (default: 8h)
 *   REFRESH_TOKEN_EXPIRY   Refresh token expiry             (default: 30d)
 */

import express, { Request, Response, NextFunction } from 'express';
import http from 'http';
import { URL } from 'url';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { hydrateEnvFromVault, vaultName } from './utils/secrets.js';

const LOG_LEVEL = (process.env.LOG_LEVEL || 'info').toLowerCase();

function log(level: 'info' | 'warn' | 'error' | 'debug', msg: string) {
  if (level === 'debug' && LOG_LEVEL !== 'debug') return;
  const ts = new Date().toISOString();
  console.error(`${ts} [${level.toUpperCase()}] ${msg}`);
}

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ── Config ───────────────────────────────────────────────────────────────────

const GATEWAY_URL  = (process.env.GATEWAY_URL  || 'http://localhost:8080').replace(/\/$/, '');
const GATEWAY_PORT = parseInt(process.env.GATEWAY_PORT || '8080');
const MCP_UPSTREAM = (process.env.MCP_UPSTREAM  || 'http://localhost:8011').replace(/\/$/, '');
const TOKEN_EXPIRY = process.env.TOKEN_EXPIRY   || '8h';
const REFRESH_TOKEN_EXPIRY = process.env.REFRESH_TOKEN_EXPIRY || '30d';

// Resolves JWT_SECRET from Clay's Secrets Manager vaults (POL-SEC-001)
// unless it is already present in the environment.
const secretOrigin = await hydrateEnvFromVault({ JWT_SECRET: 'METABASE_MCP_GATEWAY_SECRET' });

if (!process.env.JWT_SECRET) {
  throw new Error(
    'JWT_SECRET is required. Set the JWT_SECRET environment variable, or register ' +
    `METABASE_MCP_GATEWAY_SECRET in ${vaultName()}.`
  );
}
const JWT_SECRET = process.env.JWT_SECRET;
log('info', `JWT_SECRET loaded from ${secretOrigin.JWT_SECRET}`);

// ── Pending authorization codes (in-memory, 10-min TTL) ─────────────────────

interface PendingCode {
  metabase_url: string;
  metabase_api_key?: string;
  metabase_username?: string;
  metabase_password?: string;
  metabase_session_token?: string;
  code_challenge?: string;   // PKCE
  redirect_uri: string;
  expires: number;
}

const pendingCodes = new Map<string, PendingCode>();

setInterval(() => {
  const now = Date.now();
  for (const [code, data] of pendingCodes) {
    if (data.expires < now) pendingCodes.delete(code);
  }
}, 5 * 60 * 1000);

// ── Helpers ──────────────────────────────────────────────────────────────────

function escapeHtml(str: string): string {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function verifyPkce(verifier: string, challenge: string): boolean {
  const computed = crypto
    .createHash('sha256')
    .update(verifier)
    .digest('base64url');
  return computed === challenge;
}

// ── Token issuance ───────────────────────────────────────────────────────────
// The JWT carries the Metabase credentials, so it *is* the credential: there is
// no server-side session to look up. Access tokens are therefore short-lived and
// renewed through a rotating refresh token rather than simply given a long life.

interface Credentials {
  metabase_url: string;
  metabase_api_key?: string;
  metabase_username?: string;
  metabase_password?: string;
  metabase_session_token?: string;
}

function credentialsFrom(src: Record<string, any>): Credentials {
  const creds: Credentials = { metabase_url: src.metabase_url };
  if (src.metabase_api_key)       creds.metabase_api_key       = src.metabase_api_key;
  if (src.metabase_username)      creds.metabase_username      = src.metabase_username;
  if (src.metabase_password)      creds.metabase_password      = src.metabase_password;
  if (src.metabase_session_token) creds.metabase_session_token = src.metabase_session_token;
  return creds;
}

// Stable, non-reversible id for a connection so logs can correlate one user's
// tokens across issuance, refresh and expiry without ever recording a credential.
function subjectOf(creds: Credentials): string {
  const material = [
    creds.metabase_url,
    creds.metabase_username || '',
    creds.metabase_api_key || creds.metabase_password || creds.metabase_session_token || '',
  ].join('|');
  return crypto.createHash('sha256').update(material).digest('hex').slice(0, 12);
}

function issueTokens(creds: Credentials) {
  const sub = subjectOf(creds);
  // A unique jti per token: HMAC over an identical payload is deterministic, so
  // without it two tokens minted in the same second are byte-identical and
  // rotating the refresh token would hand back the very token it replaces.
  const jti = () => crypto.randomBytes(16).toString('hex');
  const access  = jwt.sign({ ...creds, sub, jti: jti(), typ: 'access'  }, JWT_SECRET, { expiresIn: TOKEN_EXPIRY }         as jwt.SignOptions);
  const refresh = jwt.sign({ ...creds, sub, jti: jti(), typ: 'refresh' }, JWT_SECRET, { expiresIn: REFRESH_TOKEN_EXPIRY } as jwt.SignOptions);
  const { iat, exp } = jwt.decode(access)  as { iat: number; exp: number };
  const refreshExp   = (jwt.decode(refresh) as { exp: number }).exp;
  return {
    sub,
    body: {
      access_token: access,
      token_type: 'bearer',
      expires_in: exp - iat,
      refresh_token: refresh,
      refresh_expires_in: refreshExp - iat,
    },
  };
}

// ── Dynamic client registration (RFC 7591) ───────────────────────────────────
// Clients (e.g. Claude.ai) register automatically before starting the OAuth flow.
// We accept any registration and return a client_id; we don't validate client
// credentials because security comes from the Metabase credentials in the form.

const registeredClients = new Map<string, { redirect_uris: string[] }>();

app.post('/oauth/register', (req: Request, res: Response) => {
  const { redirect_uris, client_name } = req.body;
  if (!redirect_uris || !Array.isArray(redirect_uris) || redirect_uris.length === 0) {
    res.status(400).json({ error: 'invalid_client_metadata', error_description: 'redirect_uris required' });
    return;
  }
  const client_id = crypto.randomBytes(16).toString('hex');
  registeredClients.set(client_id, { redirect_uris });
  log('debug', `Client registered: ${client_name || 'unnamed'} (${client_id})`);
  res.status(201).json({
    client_id,
    client_id_issued_at: Math.floor(Date.now() / 1000),
    redirect_uris,
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    token_endpoint_auth_method: 'none',
  });
});

// ── OAuth Discovery ──────────────────────────────────────────────────────────

app.get('/.well-known/oauth-authorization-server', (_req: Request, res: Response) => {
  res.json({
    issuer: GATEWAY_URL,
    authorization_endpoint: `${GATEWAY_URL}/oauth/authorize`,
    token_endpoint: `${GATEWAY_URL}/oauth/token`,
    registration_endpoint: `${GATEWAY_URL}/oauth/register`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['none'],
  });
});

// Required by some clients that probe for OpenID Connect
app.get('/.well-known/openid-configuration', (_req: Request, res: Response) => {
  res.json({
    issuer: GATEWAY_URL,
    authorization_endpoint: `${GATEWAY_URL}/oauth/authorize`,
    token_endpoint: `${GATEWAY_URL}/oauth/token`,
    registration_endpoint: `${GATEWAY_URL}/oauth/register`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
  });
});

// ── Google SSO helpers ───────────────────────────────────────────────────────
// These two endpoints proxy requests to Metabase server-side to avoid CORS
// issues when the gateway and Metabase live on different origins.

// Returns the Google OAuth client ID configured in a given Metabase instance.
app.get('/oauth/metabase-properties', async (req: Request, res: Response) => {
  const { url } = req.query as Record<string, string>;
  if (!url) {
    res.status(400).json({ error: 'url required' });
    return;
  }
  try {
    const upstream = `${url.replace(/\/$/, '')}/api/session/properties`;
    const response = await fetch(upstream, { signal: AbortSignal.timeout(5000) });
    if (!response.ok) {
      res.status(response.status).json({ error: 'upstream error' });
      return;
    }
    const data = await response.json() as Record<string, any>;
    res.json({ 'google-auth-client-id': data['google-auth-client-id'] || null });
  } catch {
    res.status(502).json({ error: 'could not reach Metabase' });
  }
});

// Exchanges a Google ID token for a Metabase session token.
app.post('/oauth/metabase-google-auth', async (req: Request, res: Response) => {
  const { metabase_url, google_token } = req.body as Record<string, string>;
  if (!metabase_url || !google_token) {
    res.status(400).json({ error: 'metabase_url and google_token required' });
    return;
  }
  try {
    const upstream = `${metabase_url.replace(/\/$/, '')}/api/session/google_auth`;
    const response = await fetch(upstream, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: google_token }),
      signal: AbortSignal.timeout(10000),
    });
    if (!response.ok) {
      const detail = await response.text();
      res.status(response.status).json({ error: 'Metabase rejected the Google token', detail });
      return;
    }
    const data = await response.json() as Record<string, any>;
    res.json({ session_token: data.id });
  } catch {
    res.status(502).json({ error: 'could not reach Metabase' });
  }
});

// ── Authorization endpoint ───────────────────────────────────────────────────

app.get('/oauth/authorize', (req: Request, res: Response) => {
  const { redirect_uri, state, code_challenge, code_challenge_method } = req.query as Record<string, string>;

  if (!redirect_uri) {
    res.status(400).send('Missing redirect_uri');
    return;
  }

  const safeRedirect = escapeHtml(redirect_uri);
  const safeState    = escapeHtml(state || '');
  const safeChallenge = escapeHtml(code_challenge || '');
  const safeMethod   = escapeHtml(code_challenge_method || '');

  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(`<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Conectar Metabase · MCP</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #f5f5f5;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      padding: 1rem;
    }
    .card {
      background: #fff;
      border-radius: 12px;
      box-shadow: 0 4px 24px rgba(0,0,0,.10);
      padding: 2rem;
      width: 100%;
      max-width: 420px;
    }
    h1 { font-size: 1.25rem; margin-bottom: .25rem; }
    p.subtitle { color: #666; font-size: .875rem; margin-bottom: 1.5rem; }
    label { display: block; font-size: .875rem; font-weight: 500; margin-bottom: .25rem; margin-top: 1rem; }
    input[type=text], input[type=password], input[type=url] {
      width: 100%; padding: .6rem .75rem;
      border: 1px solid #d1d5db; border-radius: 8px;
      font-size: .875rem; outline: none;
    }
    input:focus { border-color: #6366f1; box-shadow: 0 0 0 3px rgba(99,102,241,.15); }
    .divider { display: flex; align-items: center; gap: .5rem; margin: 1.25rem 0 .5rem; color: #9ca3af; font-size: .75rem; }
    .divider::before, .divider::after { content: ''; flex: 1; height: 1px; background: #e5e7eb; }
    button[type=submit] {
      margin-top: 1.5rem; width: 100%;
      background: #6366f1; color: #fff;
      border: none; border-radius: 8px;
      padding: .75rem; font-size: 1rem; font-weight: 500;
      cursor: pointer; transition: background .15s;
    }
    button[type=submit]:hover { background: #4f46e5; }
    .error { color: #dc2626; font-size: .8rem; margin-top: .5rem; display: none; }
    .error.visible { display: block; }
    #google-sso-section { display: none; margin-top: .5rem; }
    .btn-google {
      display: flex; align-items: center; justify-content: center; gap: .6rem;
      width: 100%; padding: .65rem .75rem;
      background: #fff; color: #3c4043;
      border: 1px solid #dadce0; border-radius: 8px;
      font-size: .9rem; font-weight: 500; cursor: pointer;
      transition: background .15s, box-shadow .15s;
    }
    .btn-google:hover { background: #f8f9fa; box-shadow: 0 1px 3px rgba(0,0,0,.12); }
    .btn-google:disabled { opacity: .6; cursor: not-allowed; }
    .btn-google svg { flex-shrink: 0; }
    .sso-status { font-size: .78rem; margin-top: .5rem; color: #6b7280; min-height: 1.2em; }
    .sso-status.ok  { color: #16a34a; }
    .sso-status.err { color: #dc2626; }
    .btn-toggle {
      display: flex; align-items: center; gap: .4rem;
      background: none; border: none; padding: 0;
      color: #6b7280; font-size: .8rem; cursor: pointer;
      margin-top: 1.25rem;
    }
    .btn-toggle:hover { color: #374151; }
    .btn-toggle svg { transition: transform .2s; }
    .btn-toggle.open svg { transform: rotate(180deg); }
    .advanced { display: none; }
    .advanced.open { display: block; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Conectar Metabase</h1>
    <p class="subtitle">Ingresa las credenciales de tu instancia de Metabase para continuar.</p>

    <form method="POST" action="/oauth/authorize" id="form">
      <input type="hidden" name="redirect_uri"          value="${safeRedirect}">
      <input type="hidden" name="state"                 value="${safeState}">
      <input type="hidden" name="code_challenge"        value="${safeChallenge}">
      <input type="hidden" name="code_challenge_method" value="${safeMethod}">

      <label for="metabase_url">URL de Metabase</label>
      <input type="url" id="metabase_url" name="metabase_url"
             placeholder="https://analytics.example.com"
             value="https://analytics.clay.cl/" required>

      <button type="button" class="btn-google" id="btn-google" onclick="startGoogleSSO()" style="margin-top:1rem">
        <svg width="18" height="18" viewBox="0 0 48 48"><path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/><path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/><path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/><path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.18 1.48-4.97 2.35-8.16 2.35-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/><path fill="none" d="M0 0h48v48H0z"/></svg>
        Continuar con Google
      </button>
      <p class="sso-status" id="sso-status"></p>

      <button type="button" class="btn-toggle" id="btn-toggle" onclick="toggleAdvanced()">
        <svg width="14" height="14" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" clip-rule="evenodd"/></svg>
        Otras opciones de autenticación
      </button>

      <div class="advanced" id="advanced">
        <div class="divider">API Key</div>

        <label for="metabase_api_key">API Key</label>
        <input type="password" id="metabase_api_key" name="metabase_api_key"
               placeholder="mb_xxxxxxxx">

        <div class="divider">usuario y contraseña</div>

        <label for="metabase_username">Usuario</label>
        <input type="text" id="metabase_username" name="metabase_username"
               placeholder="admin@example.com">

        <label for="metabase_password">Contraseña</label>
        <input type="password" id="metabase_password" name="metabase_password">

        <div class="divider">token de sesión manual</div>

        <label for="metabase_session_token">Token de sesión</label>
        <input type="password" id="metabase_session_token" name="metabase_session_token"
               placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx">
        <p style="color:#6b7280;font-size:.75rem;margin-top:.4rem">
          DevTools → Application → Cookies → <code>metabase.SESSION</code>
        </p>
      </div>

      <p class="error" id="err">Debes ingresar una API Key, usuario + contraseña, o un token de sesión.</p>

      <button type="submit">Conectar</button>
    </form>
  </div>
  <script>
    // ── Advanced toggle ───────────────────────────────────────────────────────
    function toggleAdvanced() {
      var adv = document.getElementById('advanced');
      var btn = document.getElementById('btn-toggle');
      var open = adv.classList.toggle('open');
      btn.classList.toggle('open', open);
    }

    // ── Form validation ───────────────────────────────────────────────────────
    document.getElementById('form').addEventListener('submit', function(e) {
      var key     = document.getElementById('metabase_api_key').value.trim();
      var user    = document.getElementById('metabase_username').value.trim();
      var pass    = document.getElementById('metabase_password').value.trim();
      var session = document.getElementById('metabase_session_token').value.trim();
      if (!key && !(user && pass) && !session) {
        e.preventDefault();
        document.getElementById('err').classList.add('visible');
      }
    });

    // ── Google SSO client ID (fetched lazily on first click) ─────────────────
    var googleClientId = null;

    async function fetchClientId(url) {
      if (googleClientId) return googleClientId;
      var resp = await fetch('/oauth/metabase-properties?url=' + encodeURIComponent(url));
      var data = await resp.json();
      googleClientId = data['google-auth-client-id'] || null;
      return googleClientId;
    }

    // ── Google Sign-In flow ───────────────────────────────────────────────────
    function setStatus(msg, type) {
      var el = document.getElementById('sso-status');
      el.textContent = msg;
      el.className = 'sso-status' + (type ? ' ' + type : '');
    }

    function loadGSI(clientId) {
      return new Promise(function(resolve, reject) {
        if (typeof google !== 'undefined' && google.accounts) { resolve(); return; }
        var s = document.createElement('script');
        s.src = 'https://accounts.google.com/gsi/client';
        s.onload = resolve;
        s.onerror = reject;
        document.head.appendChild(s);
      });
    }

    async function startGoogleSSO() {
      var url = document.getElementById('metabase_url').value.trim();
      if (!url) { setStatus('Primero ingresa la URL de Metabase.', 'err'); return; }

      var btn = document.getElementById('btn-google');
      btn.disabled = true;
      setStatus('Cargando...', '');

      try {
        await fetchClientId(url);
        if (!googleClientId) {
          setStatus('Esta instancia de Metabase no tiene Google SSO habilitado.', 'err');
          btn.disabled = false;
          return;
        }

        setStatus('Abriendo ventana de Google...', '');
        await loadGSI(googleClientId);

        google.accounts.id.initialize({
          client_id: googleClientId,
          callback: async function(response) {
            setStatus('Autenticando con Metabase...', '');
            try {
              var authResp = await fetch('/oauth/metabase-google-auth', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ metabase_url: url, google_token: response.credential }),
              });
              var authData = await authResp.json();
              if (authData.session_token) {
                setStatus('Autenticado. Conectando...', 'ok');
                document.getElementById('metabase_session_token').value = authData.session_token;
                document.getElementById('form').submit();
              } else {
                setStatus('Error: ' + (authData.error || 'respuesta inesperada de Metabase'), 'err');
                btn.disabled = false;
              }
            } catch (e) {
              setStatus('Error al comunicarse con Metabase.', 'err');
              btn.disabled = false;
            }
          },
          auto_select: false,
          cancel_on_tap_outside: true,
        });

        google.accounts.id.prompt(function(notification) {
          if (notification.isNotDisplayed() || notification.isSkippedMoment()) {
            // One-tap not available — fall back to popup
            google.accounts.id.renderButton(
              document.getElementById('btn-google'),
              { theme: 'outline', size: 'large', width: 340 }
            );
            btn.disabled = false;
            setStatus('', '');
          }
        });

      } catch(e) {
        setStatus('No se pudo cargar Google Sign-In.', 'err');
        btn.disabled = false;
      }
    }
  </script>
</body>
</html>`);
});

app.post('/oauth/authorize', (req: Request, res: Response) => {
  const {
    redirect_uri,
    state,
    code_challenge,
    code_challenge_method,
    metabase_url,
    metabase_api_key,
    metabase_username,
    metabase_password,
    metabase_session_token,
  } = req.body as Record<string, string>;

  if (!redirect_uri) {
    res.status(400).send('Missing redirect_uri');
    return;
  }
  if (!metabase_url) {
    res.status(400).send('Metabase URL is required');
    return;
  }
  if (!metabase_api_key && !(metabase_username && metabase_password) && !metabase_session_token) {
    res.status(400).send('API key, username + password, or session token required');
    return;
  }

  const code = crypto.randomBytes(32).toString('hex');
  pendingCodes.set(code, {
    metabase_url,
    metabase_api_key:       metabase_api_key       || undefined,
    metabase_username:      metabase_username      || undefined,
    metabase_password:      metabase_password      || undefined,
    metabase_session_token: metabase_session_token || undefined,
    code_challenge:         code_challenge_method === 'S256' ? code_challenge : undefined,
    redirect_uri,
    expires: Date.now() + 10 * 60 * 1000,
  });

  const redirectUrl = new URL(redirect_uri);
  redirectUrl.searchParams.set('code', code);
  if (state) redirectUrl.searchParams.set('state', state);
  res.redirect(redirectUrl.toString());
});

// ── Token endpoint ───────────────────────────────────────────────────────────

// Refresh grant — the client trades a refresh token for a fresh pair. The refresh
// token is rotated on every use so that a leaked one has a bounded life.
function handleRefresh(req: Request, res: Response) {
  const { refresh_token } = req.body as Record<string, string>;

  if (!refresh_token) {
    res.status(400).json({ error: 'invalid_request', error_description: 'Missing refresh_token' });
    return;
  }

  let payload: Record<string, any>;
  try {
    payload = jwt.verify(refresh_token, JWT_SECRET) as Record<string, any>;
  } catch (err) {
    const expired = err instanceof jwt.TokenExpiredError;
    log('info', `token refresh rejected reason=${expired ? 'expired' : 'invalid'}`);
    res.status(400).json({
      error: 'invalid_grant',
      error_description: expired ? 'Refresh token expired' : 'Refresh token invalid',
    });
    return;
  }

  // An access token must never be spendable as a refresh token.
  if (payload.typ !== 'refresh') {
    log('info', `token refresh rejected reason=wrong_token_type sub=${payload.sub || '-'}`);
    res.status(400).json({ error: 'invalid_grant', error_description: 'Not a refresh token' });
    return;
  }

  const { sub, body } = issueTokens(credentialsFrom(payload));
  log('info', `token refreshed sub=${sub} expires_in=${body.expires_in}`);
  res.json(body);
}

app.post('/oauth/token', (req: Request, res: Response) => {
  const { grant_type, code, code_verifier } = req.body as Record<string, string>;

  if (grant_type === 'refresh_token') {
    handleRefresh(req, res);
    return;
  }
  if (grant_type !== 'authorization_code') {
    res.status(400).json({ error: 'unsupported_grant_type' });
    return;
  }
  if (!code) {
    res.status(400).json({ error: 'invalid_request', error_description: 'Missing code' });
    return;
  }

  const pending = pendingCodes.get(code);
  if (!pending || pending.expires < Date.now()) {
    pendingCodes.delete(code);
    res.status(400).json({ error: 'invalid_grant', error_description: 'Code expired or not found' });
    return;
  }

  // PKCE verification (required when code_challenge was provided)
  if (pending.code_challenge) {
    if (!code_verifier) {
      res.status(400).json({ error: 'invalid_grant', error_description: 'Missing code_verifier' });
      return;
    }
    if (!verifyPkce(code_verifier, pending.code_challenge)) {
      pendingCodes.delete(code);
      res.status(400).json({ error: 'invalid_grant', error_description: 'PKCE verification failed' });
      return;
    }
  }

  pendingCodes.delete(code);

  const { sub, body } = issueTokens(credentialsFrom(pending));
  log('info', `token issued grant=authorization_code sub=${sub} expires_in=${body.expires_in}`);
  res.json(body);
});

// ── MCP proxy ────────────────────────────────────────────────────────────────
// Validate Bearer JWT and inject x-metabase-* headers before proxying to FastMCP.

// ── MCP proxy ────────────────────────────────────────────────────────────────
// Manual HTTP proxy so we have full control over streaming and path handling.

app.use('/mcp', (req: Request, res: Response) => {
  const start = Date.now();
  const session = (req.headers['mcp-session-id'] as string || '').slice(0, 8) || '-';
  const method = (req.body as any)?.method || '-';

  // Populated by the auth checks below so the access log can say *why* a request
  // was rejected — an absent header and an expired token are different problems.
  let sub = '-';
  let denial = '';
  let denialDetail = '';

  res.on('finish', () => {
    const why = denial ? ` reason=${denial}${denialDetail}` : '';
    log('info', `${req.method} /mcp session=${session} sub=${sub} method=${method} status=${res.statusCode} ms=${Date.now() - start}${why}`);
  });

  // Tells the client this is an authentication problem it can recover from by
  // refreshing, rather than an opaque failure. Required by RFC 6750.
  const challenge = (error: string, description: string) =>
    res.setHeader('WWW-Authenticate', `Bearer realm="${GATEWAY_URL}", error="${error}", error_description="${description}"`);

  const auth = req.headers['authorization'] as string | undefined;
  if (!auth?.startsWith('Bearer ')) {
    denial = 'missing_bearer';
    challenge('invalid_request', 'Bearer token required');
    res.status(401).json({ error: 'Bearer token required' });
    return;
  }

  let payload: Record<string, string>;
  try {
    payload = jwt.verify(auth.slice(7), JWT_SECRET) as Record<string, string>;
  } catch (err) {
    // Recover the subject from the unverified payload: an expired token is exactly
    // the case worth correlating, and it is the one path where verification failed.
    // This is a log label only — never trusted for authorization.
    try {
      const stale = jwt.decode(auth.slice(7)) as Record<string, string> | null;
      if (stale?.sub) sub = stale.sub;
    } catch { /* unparseable token — leave sub unset */ }

    if (err instanceof jwt.TokenExpiredError) {
      denial = 'token_expired';
      denialDetail = ` expired_at=${err.expiredAt.toISOString()}`;
      challenge('invalid_token', 'Token expired');
      res.status(401).json({ error: 'invalid_token', error_description: 'Token expired' });
    } else {
      denial = 'token_invalid';
      challenge('invalid_token', 'Token invalid');
      res.status(401).json({ error: 'invalid_token', error_description: 'Token invalid' });
    }
    return;
  }

  sub = payload.sub || '-';

  // Refresh tokens are long-lived by design; they must not authenticate MCP calls.
  // Tokens issued before `typ` existed carry none, and stay valid until they expire.
  if (payload.typ && payload.typ !== 'access') {
    denial = 'wrong_token_type';
    challenge('invalid_token', 'Not an access token');
    res.status(401).json({ error: 'invalid_token', error_description: 'Not an access token' });
    return;
  }

  // notifications/initialized is a fire-and-forget notification — acknowledge immediately.
  // The upstream returns 400 when it receives this without a session context (stateless mode),
  // so we handle it at the gateway level instead of proxying.
  if (req.method === 'POST' && method === 'notifications/initialized') {
    res.status(202).end();
    return;
  }

  const upstream = new URL(MCP_UPSTREAM);
  const upstreamPath = '/mcp' + (req.url === '/' ? '' : req.url);

  const proxyHeaders: Record<string, string> = {};
  for (const [k, v] of Object.entries(req.headers)) {
    if (k === 'authorization') continue;
    if (typeof v === 'string') proxyHeaders[k] = v;
    else if (Array.isArray(v)) proxyHeaders[k] = v[0];
  }
  proxyHeaders['x-metabase-url'] = payload.metabase_url;
  if (payload.metabase_api_key)       proxyHeaders['x-metabase-api-key']       = payload.metabase_api_key;
  if (payload.metabase_username)      proxyHeaders['x-metabase-username']      = payload.metabase_username;
  if (payload.metabase_password)      proxyHeaders['x-metabase-password']      = payload.metabase_password;
  if (payload.metabase_session_token) proxyHeaders['x-metabase-session-token'] = payload.metabase_session_token;
  proxyHeaders['host'] = upstream.host;

  const isGet = req.method === 'GET';

  // express.json() already consumed req body — send it as string if present.
  const bodyStr = !isGet && req.body && Object.keys(req.body).length > 0
    ? JSON.stringify(req.body)
    : undefined;

  if (bodyStr) {
    proxyHeaders['content-length'] = Buffer.byteLength(bodyStr).toString();
  } else {
    // Remove any stale content-length/transfer-encoding for GET or bodyless requests
    delete proxyHeaders['content-length'];
    delete proxyHeaders['transfer-encoding'];
  }

  // Disable socket timeout for SSE (long-lived streams)
  if (res.socket) res.socket.setTimeout(0);

  const hopByHop = new Set(['transfer-encoding', 'connection', 'keep-alive', 'proxy-connection', 'upgrade', 'te', 'trailer']);

  // Forward a request to the upstream, returning a promise that resolves with the upstream response.
  // Buffers the body so we can retry on 400 (race condition during server startup in stateless mode).
  const doProxy = (attempt: number) => {
    const proxyReq = http.request({
      hostname: upstream.hostname,
      port:     upstream.port || 80,
      method:   req.method,
      path:     upstreamPath,
      headers:  proxyHeaders,
    }, (proxyRes) => {
      if (proxyRes.socket) proxyRes.socket.setTimeout(0);

      const status = proxyRes.statusCode || 200;

      // Retry once on 400 for non-initialize methods — upstream may not be ready yet (stateless race condition)
      if (status === 400 && method !== 'initialize' && attempt < 2) {
        log('debug', `Upstream 400 on ${method} (attempt ${attempt}), retrying in 60ms`);
        proxyRes.resume(); // drain the response
        setTimeout(() => doProxy(attempt + 1), 60);
        return;
      }

      const responseHeaders: Record<string, string | string[]> = {};
      for (const [k, v] of Object.entries(proxyRes.headers)) {
        if (!hopByHop.has(k.toLowerCase()) && v !== undefined) {
          responseHeaders[k] = v as string | string[];
        }
      }

      res.writeHead(status, responseHeaders);
      res.flushHeaders();
      proxyRes.pipe(res, { end: true });
    });

    proxyReq.setTimeout(0);
    proxyReq.on('error', (err) => {
      log('error', `Proxy error: ${err.message}`);
      if (!res.headersSent) res.status(502).json({ error: 'upstream_error' });
    });

    if (bodyStr) {
      proxyReq.end(bodyStr);
    } else {
      proxyReq.end();
    }
  };

  doProxy(1);
});

// ── Health ───────────────────────────────────────────────────────────────────

app.get('/health', (_req: Request, res: Response) => {
  res.json({ status: 'ok', upstream: MCP_UPSTREAM });
});

export { app };

// ── Start ────────────────────────────────────────────────────────────────────

if (process.argv[1] && new URL(import.meta.url).pathname === process.argv[1]) {
  app.listen(GATEWAY_PORT, () => {
    log('info', `OAuth MCP gateway on port ${GATEWAY_PORT}`);
    log('info', `Proxying /mcp  →  ${MCP_UPSTREAM}/mcp`);
    log('info', `Public URL: ${GATEWAY_URL}`);
  });
}
