import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { createAuthenticateHandler, createClientResolver } from '../src/auth.js';
import { MetabaseClient } from '../src/client/metabase-client.js';

// ── createClientResolver ────────────────────────────────────────────────────

describe('createClientResolver', () => {
  it('returns the session client when ctx.session.metabaseClient exists', () => {
    const sessionClient = { id: 'session' } as unknown as MetabaseClient;
    const getClient = createClientResolver(null);
    const result = getClient({ session: { metabaseClient: sessionClient } });
    expect(result).toBe(sessionClient);
  });

  it('returns the defaultClient when no session client is present', () => {
    const defaultClient = new MetabaseClient({
      url: 'http://metabase.test',
      apiKey: 'key-default',
    });
    const getClient = createClientResolver(defaultClient);
    expect(getClient({})).toBe(defaultClient);
    expect(getClient(undefined)).toBe(defaultClient);
  });

  it('prefers the session client over the defaultClient', () => {
    const sessionClient = { id: 'session' } as unknown as MetabaseClient;
    const defaultClient = new MetabaseClient({
      url: 'http://metabase.test',
      apiKey: 'key-default',
    });
    const getClient = createClientResolver(defaultClient);
    expect(getClient({ session: { metabaseClient: sessionClient } })).toBe(sessionClient);
  });

  it('throws when both defaultClient is null and no session client', () => {
    const getClient = createClientResolver(null);
    expect(() => getClient()).toThrow('No MetabaseClient available');
    expect(() => getClient({})).toThrow('No MetabaseClient available');
  });
});

// ── createAuthenticateHandler ───────────────────────────────────────────────

describe('createAuthenticateHandler', () => {
  const authenticate = createAuthenticateHandler();

  afterEach(() => {
    delete process.env.METABASE_URL;
  });

  it('returns a MetabaseClient when x-metabase-url + x-metabase-api-key are provided', () => {
    const result = authenticate({
      headers: {
        'x-metabase-url': 'http://metabase.test',
        'x-metabase-api-key': 'mb_testapikey123',
      },
    });
    expect(result.metabaseClient).toBeInstanceOf(MetabaseClient);
  });

  it('returns a MetabaseClient when x-metabase-url + username/password are provided', () => {
    const result = authenticate({
      headers: {
        'x-metabase-url': 'http://metabase.test',
        'x-metabase-username': 'admin@test.com',
        'x-metabase-password': 'secret',
      },
    });
    expect(result.metabaseClient).toBeInstanceOf(MetabaseClient);
  });

  it('falls back to METABASE_URL env var when x-metabase-url header is absent', () => {
    process.env.METABASE_URL = 'http://env-metabase.test';
    const result = authenticate({
      headers: { 'x-metabase-api-key': 'mb_testapikey123' },
    });
    expect(result.metabaseClient).toBeInstanceOf(MetabaseClient);
  });

  it('throws a 401 Response when URL is missing and METABASE_URL is not set', () => {
    expect(() =>
      authenticate({ headers: { 'x-metabase-api-key': 'mb_key12345678' } })
    ).toThrow(Response);

    try {
      authenticate({ headers: { 'x-metabase-api-key': 'mb_key12345678' } });
    } catch (e) {
      expect((e as Response).status).toBe(401);
      expect((e as Response).statusText).toMatch(/Missing Metabase URL/);
    }
  });

  it('throws a 401 Response when credentials are missing', () => {
    try {
      authenticate({ headers: { 'x-metabase-url': 'http://metabase.test' } });
    } catch (e) {
      expect((e as Response).status).toBe(401);
      expect((e as Response).statusText).toMatch(/Missing credentials/);
    }
  });

  it('throws a 401 Response when only username is provided (no password)', () => {
    try {
      authenticate({
        headers: {
          'x-metabase-url': 'http://metabase.test',
          'x-metabase-username': 'admin@test.com',
        },
      });
    } catch (e) {
      expect((e as Response).status).toBe(401);
    }
  });

  it('returns a MetabaseClient when x-metabase-session-token is provided (Google SSO)', () => {
    const result = authenticate({
      headers: {
        'x-metabase-url': 'http://metabase.test',
        'x-metabase-session-token': 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx',
      },
    });
    expect(result.metabaseClient).toBeInstanceOf(MetabaseClient);
  });

  it('throws a 401 Response when only username is provided without session token either', () => {
    try {
      authenticate({
        headers: {
          'x-metabase-url': 'http://metabase.test',
          'x-metabase-username': 'admin@test.com',
          // no password, no session token
        },
      });
    } catch (e) {
      expect((e as Response).status).toBe(401);
    }
  });

  it('ignores a malformed API key and uses the session token instead', () => {
    // A password manager fills the OAuth form's first type=password field, so a
    // request can carry a saved password where an API key belongs. The key
    // outranks everything else, so honouring it would waste a good session.
    const handler = createAuthenticateHandler();
    const { metabaseClient } = handler({
      headers: {
        'x-metabase-url': 'https://metabase.example.com',
        'x-metabase-api-key': 'my-saved-google-password',
        'x-metabase-session-token': 'a-real-session-uuid',
      },
    });
    expect((metabaseClient as any).authMode).toBe('session_token');
  });

  it('still honours a well-formed API key', () => {
    const handler = createAuthenticateHandler();
    const { metabaseClient } = handler({
      headers: {
        'x-metabase-url': 'https://metabase.example.com',
        'x-metabase-api-key': 'mb_realkey12345',
        'x-metabase-session-token': 'a-real-session-uuid',
      },
    });
    expect((metabaseClient as any).authMode).toBe('api_key');
  });

  it('throws a 401 when the malformed key was the only credential', () => {
    const handler = createAuthenticateHandler();
    expect(() => handler({
      headers: {
        'x-metabase-url': 'https://metabase.example.com',
        'x-metabase-api-key': 'not-a-key',
      },
    })).toThrow();
  });

  it('each call creates an independent MetabaseClient (session isolation)', () => {
    const r1 = authenticate({
      headers: {
        'x-metabase-url': 'http://metabase-a.test',
        'x-metabase-api-key': 'mb_key_a12345',
      },
    });
    const r2 = authenticate({
      headers: {
        'x-metabase-url': 'http://metabase-b.test',
        'x-metabase-api-key': 'mb_key_b12345',
      },
    });
    expect(r1.metabaseClient).not.toBe(r2.metabaseClient);
  });
});
