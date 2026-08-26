import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import jwt from 'jsonwebtoken';

// Set env vars before importing the app
process.env.JWT_SECRET = 'test-secret-for-vitest';
process.env.GATEWAY_URL = 'https://mcp.example.com';
process.env.MCP_UPSTREAM = 'http://localhost:9999'; // unused in unit tests

const { app } = await import('../src/oauth-gateway.js');

// ── helpers ──────────────────────────────────────────────────────────────────

async function getAuthCode(opts: {
  apiKey?: string;
  username?: string;
  password?: string;
  codeChallenge?: string;
  state?: string;
} = { apiKey: 'mb_test_key' }) {
  const body: Record<string, string> = {
    redirect_uri: 'https://client.example.com/callback',
    metabase_url: 'https://metabase.example.com',
  };
  if (opts.apiKey)       body.metabase_api_key = opts.apiKey;
  if (opts.username)     body.metabase_username = opts.username;
  if (opts.password)     body.metabase_password = opts.password;
  if (opts.codeChallenge) {
    body.code_challenge = opts.codeChallenge;
    body.code_challenge_method = 'S256';
  }
  if (opts.state) body.state = opts.state;

  const res = await request(app).post('/oauth/authorize').send(body);
  const location = res.headers['location'] as string;
  const url = new URL(location);
  return url.searchParams.get('code') as string;
}

// ── Discovery ────────────────────────────────────────────────────────────────

describe('GET /.well-known/oauth-authorization-server', () => {
  it('returns required OAuth metadata fields', async () => {
    const res = await request(app).get('/.well-known/oauth-authorization-server');
    expect(res.status).toBe(200);
    expect(res.body.issuer).toBe('https://mcp.example.com');
    expect(res.body.authorization_endpoint).toContain('/oauth/authorize');
    expect(res.body.token_endpoint).toContain('/oauth/token');
    expect(res.body.registration_endpoint).toContain('/oauth/register');
    expect(res.body.code_challenge_methods_supported).toContain('S256');
  });
});

describe('GET /.well-known/openid-configuration', () => {
  it('returns OpenID configuration', async () => {
    const res = await request(app).get('/.well-known/openid-configuration');
    expect(res.status).toBe(200);
    expect(res.body.authorization_endpoint).toContain('/oauth/authorize');
  });
});

// ── Client registration ───────────────────────────────────────────────────────

describe('POST /oauth/register', () => {
  it('registers a client and returns client_id', async () => {
    const res = await request(app)
      .post('/oauth/register')
      .send({ redirect_uris: ['https://client.example.com/cb'], client_name: 'TestApp' });
    expect(res.status).toBe(201);
    expect(res.body.client_id).toBeTruthy();
    expect(res.body.redirect_uris).toEqual(['https://client.example.com/cb']);
    expect(res.body.grant_types).toContain('authorization_code');
  });

  it('rejects missing redirect_uris', async () => {
    const res = await request(app).post('/oauth/register').send({ client_name: 'NoUris' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_client_metadata');
  });

  it('rejects empty redirect_uris array', async () => {
    const res = await request(app).post('/oauth/register').send({ redirect_uris: [] });
    expect(res.status).toBe(400);
  });
});

// ── Authorization endpoint ────────────────────────────────────────────────────

describe('GET /oauth/authorize', () => {
  it('returns HTML login form when redirect_uri is provided', async () => {
    const res = await request(app)
      .get('/oauth/authorize')
      .query({ redirect_uri: 'https://client.example.com/callback' });
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toContain('text/html');
    expect(res.text).toContain('<form');
  });

  it('returns 400 when redirect_uri is missing', async () => {
    const res = await request(app).get('/oauth/authorize');
    expect(res.status).toBe(400);
  });

  it('escapes HTML in redirect_uri to prevent XSS', async () => {
    const res = await request(app)
      .get('/oauth/authorize')
      .query({ redirect_uri: 'https://x.com/cb?a=<script>alert(1)</script>' });
    expect(res.text).not.toContain('<script>alert(1)</script>');
    expect(res.text).toContain('&lt;script&gt;');
  });
});

describe('POST /oauth/authorize', () => {
  it('redirects with code when api_key is provided', async () => {
    const res = await request(app).post('/oauth/authorize').send({
      redirect_uri: 'https://client.example.com/callback',
      metabase_url: 'https://metabase.example.com',
      metabase_api_key: 'mb_test_key',
    });
    expect(res.status).toBe(302);
    const url = new URL(res.headers['location']);
    expect(url.searchParams.get('code')).toBeTruthy();
  });

  it('redirects with code when username+password is provided', async () => {
    const res = await request(app).post('/oauth/authorize').send({
      redirect_uri: 'https://client.example.com/callback',
      metabase_url: 'https://metabase.example.com',
      metabase_username: 'admin@example.com',
      metabase_password: 'secret',
    });
    expect(res.status).toBe(302);
    const url = new URL(res.headers['location']);
    expect(url.searchParams.get('code')).toBeTruthy();
  });

  it('includes state in redirect when provided', async () => {
    const res = await request(app).post('/oauth/authorize').send({
      redirect_uri: 'https://client.example.com/callback',
      metabase_url: 'https://metabase.example.com',
      metabase_api_key: 'mb_test',
      state: 'xyz123',
    });
    const url = new URL(res.headers['location']);
    expect(url.searchParams.get('state')).toBe('xyz123');
  });

  it('returns 400 when redirect_uri is missing', async () => {
    const res = await request(app).post('/oauth/authorize').send({
      metabase_url: 'https://metabase.example.com',
      metabase_api_key: 'mb_test',
    });
    expect(res.status).toBe(400);
  });

  it('returns 400 when metabase_url is missing', async () => {
    const res = await request(app).post('/oauth/authorize').send({
      redirect_uri: 'https://client.example.com/callback',
      metabase_api_key: 'mb_test',
    });
    expect(res.status).toBe(400);
  });

  it('returns 400 when no credentials are provided', async () => {
    const res = await request(app).post('/oauth/authorize').send({
      redirect_uri: 'https://client.example.com/callback',
      metabase_url: 'https://metabase.example.com',
    });
    expect(res.status).toBe(400);
  });

  it('returns 400 when only username is provided without password', async () => {
    const res = await request(app).post('/oauth/authorize').send({
      redirect_uri: 'https://client.example.com/callback',
      metabase_url: 'https://metabase.example.com',
      metabase_username: 'admin@example.com',
    });
    expect(res.status).toBe(400);
  });
});

// ── Token endpoint ────────────────────────────────────────────────────────────

describe('POST /oauth/token', () => {
  it('issues a JWT for a valid code (api_key flow)', async () => {
    const code = await getAuthCode({ apiKey: 'mb_real_key' });
    const res = await request(app).post('/oauth/token').send({
      grant_type: 'authorization_code',
      code,
    });
    expect(res.status).toBe(200);
    expect(res.body.access_token).toBeTruthy();
    expect(res.body.token_type).toBe('bearer');

    const decoded = jwt.verify(res.body.access_token, 'test-secret-for-vitest') as Record<string, string>;
    expect(decoded.metabase_url).toBe('https://metabase.example.com');
    expect(decoded.metabase_api_key).toBe('mb_real_key');
    expect(decoded.metabase_password).toBeUndefined();
  });

  it('issues a JWT for a valid code (username+password flow)', async () => {
    const code = await getAuthCode({ username: 'admin@example.com', password: 'secret' });
    const res = await request(app).post('/oauth/token').send({
      grant_type: 'authorization_code',
      code,
    });
    expect(res.status).toBe(200);
    const decoded = jwt.verify(res.body.access_token, 'test-secret-for-vitest') as Record<string, string>;
    expect(decoded.metabase_username).toBe('admin@example.com');
    expect(decoded.metabase_api_key).toBeUndefined();
  });

  it('rejects unsupported grant_type', async () => {
    const res = await request(app).post('/oauth/token').send({
      grant_type: 'client_credentials',
      code: 'whatever',
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('unsupported_grant_type');
  });

  it('rejects missing code', async () => {
    const res = await request(app).post('/oauth/token').send({
      grant_type: 'authorization_code',
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_request');
  });

  it('rejects invalid code', async () => {
    const res = await request(app).post('/oauth/token').send({
      grant_type: 'authorization_code',
      code: 'nonexistent-code',
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_grant');
  });

  it('rejects a code used twice (single use)', async () => {
    const code = await getAuthCode();
    await request(app).post('/oauth/token').send({ grant_type: 'authorization_code', code });
    const res2 = await request(app).post('/oauth/token').send({ grant_type: 'authorization_code', code });
    expect(res2.status).toBe(400);
    expect(res2.body.error).toBe('invalid_grant');
  });
});

// ── Refresh grant ────────────────────────────────────────────────────────────

describe('POST /oauth/token - refresh_token grant', () => {
  async function getTokenPair(opts = { apiKey: 'mb_refresh_key' }) {
    const code = await getAuthCode(opts);
    const res = await request(app).post('/oauth/token').send({ grant_type: 'authorization_code', code });
    return res.body;
  }

  it('issues a refresh token alongside the access token', async () => {
    const body = await getTokenPair();
    expect(body.refresh_token).toBeTruthy();
    expect(body.refresh_expires_in).toBeGreaterThan(body.expires_in);

    const decoded = jwt.verify(body.refresh_token, 'test-secret-for-vitest') as Record<string, string>;
    expect(decoded.typ).toBe('refresh');
  });

  it('marks access tokens with typ=access', async () => {
    const body = await getTokenPair();
    const decoded = jwt.verify(body.access_token, 'test-secret-for-vitest') as Record<string, string>;
    expect(decoded.typ).toBe('access');
  });

  it('exchanges a refresh token for a fresh access token', async () => {
    const body = await getTokenPair();
    const res = await request(app).post('/oauth/token').send({
      grant_type: 'refresh_token',
      refresh_token: body.refresh_token,
    });
    expect(res.status).toBe(200);
    expect(res.body.access_token).toBeTruthy();

    const decoded = jwt.verify(res.body.access_token, 'test-secret-for-vitest') as Record<string, string>;
    expect(decoded.typ).toBe('access');
    expect(decoded.metabase_api_key).toBe('mb_refresh_key');
  });

  it('carries every credential shape across a refresh', async () => {
    const body = await getTokenPair({ username: 'admin@example.com', password: 'secret' } as any);
    const res = await request(app).post('/oauth/token').send({
      grant_type: 'refresh_token',
      refresh_token: body.refresh_token,
    });
    const decoded = jwt.verify(res.body.access_token, 'test-secret-for-vitest') as Record<string, string>;
    expect(decoded.metabase_username).toBe('admin@example.com');
    expect(decoded.metabase_password).toBe('secret');
    expect(decoded.metabase_api_key).toBeUndefined();
  });

  it('rotates the refresh token on use', async () => {
    const body = await getTokenPair();
    const res = await request(app).post('/oauth/token').send({
      grant_type: 'refresh_token',
      refresh_token: body.refresh_token,
    });
    expect(res.body.refresh_token).toBeTruthy();
    expect(res.body.refresh_token).not.toBe(body.refresh_token);
  });

  it('keeps a stable subject across refreshes so logs can correlate', async () => {
    const body = await getTokenPair();
    const first = jwt.verify(body.access_token, 'test-secret-for-vitest') as Record<string, string>;
    const res = await request(app).post('/oauth/token').send({
      grant_type: 'refresh_token',
      refresh_token: body.refresh_token,
    });
    const second = jwt.verify(res.body.access_token, 'test-secret-for-vitest') as Record<string, string>;
    expect(second.sub).toBe(first.sub);
    expect(first.sub).toMatch(/^[0-9a-f]{12}$/);
  });

  it('never leaks a credential into the subject', async () => {
    const body = await getTokenPair({ apiKey: 'mb_super_secret' } as any);
    const decoded = jwt.verify(body.access_token, 'test-secret-for-vitest') as Record<string, string>;
    expect(decoded.sub).not.toContain('mb_super_secret');
  });

  it('refuses an access token used as a refresh token', async () => {
    const body = await getTokenPair();
    const res = await request(app).post('/oauth/token').send({
      grant_type: 'refresh_token',
      refresh_token: body.access_token,
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_grant');
    expect(res.body.error_description).toBe('Not a refresh token');
  });

  it('rejects a missing refresh_token', async () => {
    const res = await request(app).post('/oauth/token').send({ grant_type: 'refresh_token' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_request');
  });

  it('rejects a malformed refresh token', async () => {
    const res = await request(app).post('/oauth/token').send({
      grant_type: 'refresh_token',
      refresh_token: 'not.a.jwt',
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_grant');
  });

  it('rejects a refresh token signed with the wrong secret', async () => {
    const forged = jwt.sign(
      { metabase_url: 'https://metabase.example.com', typ: 'refresh' },
      'attacker-secret',
      { expiresIn: '30d' },
    );
    const res = await request(app).post('/oauth/token').send({
      grant_type: 'refresh_token',
      refresh_token: forged,
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_grant');
  });

  it('rejects an expired refresh token', async () => {
    const expired = jwt.sign(
      { metabase_url: 'https://metabase.example.com', typ: 'refresh' },
      'test-secret-for-vitest',
      { expiresIn: '-1s' },
    );
    const res = await request(app).post('/oauth/token').send({
      grant_type: 'refresh_token',
      refresh_token: expired,
    });
    expect(res.status).toBe(400);
    expect(res.body.error_description).toBe('Refresh token expired');
  });
});

// ── Discovery advertises the refresh grant ───────────────────────────────────

describe('refresh grant advertisement', () => {
  it('lists refresh_token in authorization server metadata', async () => {
    const res = await request(app).get('/.well-known/oauth-authorization-server');
    expect(res.body.grant_types_supported).toContain('refresh_token');
  });

  it('lists refresh_token in openid configuration', async () => {
    const res = await request(app).get('/.well-known/openid-configuration');
    expect(res.body.grant_types_supported).toContain('refresh_token');
  });

  it('lists refresh_token on client registration', async () => {
    const res = await request(app).post('/oauth/register').send({
      redirect_uris: ['https://client.example.com/callback'],
    });
    expect(res.body.grant_types).toContain('refresh_token');
  });
});

// ── PKCE ─────────────────────────────────────────────────────────────────────

describe('PKCE (S256)', () => {
  // Precomputed: verifier = 'test-verifier-string', challenge = SHA256(verifier) base64url
  const verifier  = 'test-verifier-string';
  // echo -n 'test-verifier-string' | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '='
  const challenge = 'LHKy4-q59ocwlltGr-0vD9UbiHBsIU09drZuupn1ghs';

  it('issues token when PKCE verifier is correct', async () => {
    const code = await getAuthCode({ apiKey: 'mb_pkce', codeChallenge: challenge });
    const res = await request(app).post('/oauth/token').send({
      grant_type: 'authorization_code',
      code,
      code_verifier: verifier,
    });
    expect(res.status).toBe(200);
    expect(res.body.access_token).toBeTruthy();
  });

  it('rejects token when PKCE verifier is wrong', async () => {
    const code = await getAuthCode({ apiKey: 'mb_pkce', codeChallenge: challenge });
    const res = await request(app).post('/oauth/token').send({
      grant_type: 'authorization_code',
      code,
      code_verifier: 'wrong-verifier',
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_grant');
  });

  it('rejects token when PKCE verifier is missing', async () => {
    const code = await getAuthCode({ apiKey: 'mb_pkce', codeChallenge: challenge });
    const res = await request(app).post('/oauth/token').send({
      grant_type: 'authorization_code',
      code,
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_grant');
  });
});

// ── MCP proxy auth ────────────────────────────────────────────────────────────

describe('POST /mcp - authentication', () => {
  it('returns 401 when no Authorization header', async () => {
    const res = await request(app).post('/mcp').send({ jsonrpc: '2.0', method: 'tools/list', id: 1 });
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('Bearer token required');
  });

  it('returns 401 when token is invalid', async () => {
    const res = await request(app)
      .post('/mcp')
      .set('Authorization', 'Bearer invalid.jwt.token')
      .send({ jsonrpc: '2.0', method: 'tools/list', id: 1 });
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('invalid_token');
  });

  it('returns 401 for non-Bearer auth scheme', async () => {
    const res = await request(app)
      .post('/mcp')
      .set('Authorization', 'Basic dXNlcjpwYXNz')
      .send({ jsonrpc: '2.0', method: 'tools/list', id: 1 });
    expect(res.status).toBe(401);
  });

  it('distinguishes an expired token from an invalid one', async () => {
    const expired = jwt.sign(
      { metabase_url: 'https://metabase.example.com', typ: 'access' },
      'test-secret-for-vitest',
      { expiresIn: '-1s' },
    );
    const res = await request(app)
      .post('/mcp')
      .set('Authorization', `Bearer ${expired}`)
      .send({ jsonrpc: '2.0', method: 'tools/list', id: 1 });
    expect(res.status).toBe(401);
    expect(res.body.error_description).toBe('Token expired');

    const bad = await request(app)
      .post('/mcp')
      .set('Authorization', 'Bearer not.a.jwt')
      .send({ jsonrpc: '2.0', method: 'tools/list', id: 1 });
    expect(bad.body.error_description).toBe('Token invalid');
  });

  it('refuses a refresh token used as a bearer credential', async () => {
    const code = await getAuthCode({ apiKey: 'mb_key' });
    const { body } = await request(app).post('/oauth/token').send({ grant_type: 'authorization_code', code });
    const res = await request(app)
      .post('/mcp')
      .set('Authorization', `Bearer ${body.refresh_token}`)
      .send({ jsonrpc: '2.0', method: 'tools/list', id: 1 });
    expect(res.status).toBe(401);
    expect(res.body.error_description).toBe('Not an access token');
  });

  it('sends a WWW-Authenticate challenge so the client knows to renew', async () => {
    const expired = jwt.sign(
      { metabase_url: 'https://metabase.example.com', typ: 'access' },
      'test-secret-for-vitest',
      { expiresIn: '-1s' },
    );
    const res = await request(app)
      .post('/mcp')
      .set('Authorization', `Bearer ${expired}`)
      .send({ jsonrpc: '2.0', method: 'tools/list', id: 1 });
    expect(res.headers['www-authenticate']).toContain('error="invalid_token"');

    const none = await request(app).post('/mcp').send({ jsonrpc: '2.0', method: 'tools/list', id: 1 });
    expect(none.headers['www-authenticate']).toContain('Bearer realm=');
  });
});

// ── Health ────────────────────────────────────────────────────────────────────

describe('GET /health', () => {
  it('returns ok', async () => {
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
  });
});
