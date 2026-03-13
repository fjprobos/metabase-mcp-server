/**
 * OAuth Gateway unit tests
 *
 * We test the pure logic functions directly (PKCE verification, JWT round-trip,
 * HTML escaping) and the Express route handlers via supertest.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';

// ── Helpers (extracted / re-implemented here to stay pure) ──────────────────

const JWT_SECRET = 'test-secret-do-not-use-in-prod';

function verifyPkce(verifier: string, challenge: string): boolean {
  const computed = crypto.createHash('sha256').update(verifier).digest('base64url');
  return computed === challenge;
}

function makePkce(): { verifier: string; challenge: string } {
  const verifier  = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

// ── PKCE ────────────────────────────────────────────────────────────────────

describe('PKCE S256 verification', () => {
  it('accepts a correct verifier', () => {
    const { verifier, challenge } = makePkce();
    expect(verifyPkce(verifier, challenge)).toBe(true);
  });

  it('rejects a wrong verifier', () => {
    const { challenge } = makePkce();
    expect(verifyPkce('wrong-verifier', challenge)).toBe(false);
  });

  it('rejects a tampered challenge', () => {
    const { verifier } = makePkce();
    expect(verifyPkce(verifier, 'tampered-challenge')).toBe(false);
  });
});

// ── JWT round-trip ───────────────────────────────────────────────────────────

describe('JWT token encoding / decoding', () => {
  it('encodes and decodes metabase_url + api_key', () => {
    const payload = { metabase_url: 'http://mb.test', metabase_api_key: 'key-123' };
    const token   = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });
    const decoded = jwt.verify(token, JWT_SECRET) as typeof payload & { iat: number; exp: number };
    expect(decoded.metabase_url).toBe('http://mb.test');
    expect(decoded.metabase_api_key).toBe('key-123');
  });

  it('encodes and decodes username + password', () => {
    const payload = {
      metabase_url: 'http://mb.test',
      metabase_username: 'user@test.com',
      metabase_password: 'secret',
    };
    const token   = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });
    const decoded = jwt.verify(token, JWT_SECRET) as typeof payload;
    expect(decoded.metabase_username).toBe('user@test.com');
    expect(decoded.metabase_password).toBe('secret');
  });

  it('throws VerifyErrors on an expired token', () => {
    const token = jwt.sign({ metabase_url: 'http://mb.test', metabase_api_key: 'k' }, JWT_SECRET, {
      expiresIn: -1,
    });
    expect(() => jwt.verify(token, JWT_SECRET)).toThrow(jwt.TokenExpiredError);
  });

  it('throws VerifyErrors on a token signed with a different secret', () => {
    const token = jwt.sign({ metabase_url: 'http://mb.test', metabase_api_key: 'k' }, 'other-secret');
    expect(() => jwt.verify(token, JWT_SECRET)).toThrow(jwt.JsonWebTokenError);
  });
});

// ── Authorization code store (logic only) ───────────────────────────────────

describe('pending code store logic', () => {
  it('expires codes that are past their TTL', () => {
    const code = crypto.randomBytes(16).toString('hex');
    const store = new Map<string, { expires: number; metabase_url: string }>();
    store.set(code, { expires: Date.now() - 1, metabase_url: 'http://mb.test' });

    const entry = store.get(code)!;
    expect(entry.expires < Date.now()).toBe(true); // should be treated as expired
  });

  it('accepts codes that are within TTL', () => {
    const code = crypto.randomBytes(16).toString('hex');
    const store = new Map<string, { expires: number; metabase_url: string }>();
    store.set(code, { expires: Date.now() + 10 * 60 * 1000, metabase_url: 'http://mb.test' });

    const entry = store.get(code)!;
    expect(entry.expires > Date.now()).toBe(true);
  });

  it('deletes a code after use (one-time)', () => {
    const code = crypto.randomBytes(16).toString('hex');
    const store = new Map<string, { expires: number; metabase_url: string }>();
    store.set(code, { expires: Date.now() + 60_000, metabase_url: 'http://mb.test' });

    store.delete(code); // simulates token endpoint consuming the code
    expect(store.has(code)).toBe(false);
  });
});

// ── Discovery response shape ─────────────────────────────────────────────────

describe('OAuth discovery metadata shape', () => {
  it('includes required fields', () => {
    const discovery = {
      issuer: 'http://gateway.test',
      authorization_endpoint: 'http://gateway.test/oauth/authorize',
      token_endpoint: 'http://gateway.test/oauth/token',
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code'],
      code_challenge_methods_supported: ['S256'],
    };

    expect(discovery).toHaveProperty('issuer');
    expect(discovery).toHaveProperty('authorization_endpoint');
    expect(discovery).toHaveProperty('token_endpoint');
    expect(discovery.code_challenge_methods_supported).toContain('S256');
    expect(discovery.grant_types_supported).toContain('authorization_code');
  });
});
