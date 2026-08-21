import { describe, it, expect, beforeEach, vi } from 'vitest';

const send = vi.fn();

vi.mock('@aws-sdk/client-secrets-manager', () => ({
  SecretsManagerClient: class {
    send = send;
  },
  GetSecretValueCommand: class {
    constructor(public input: { SecretId: string }) {}
  },
}));

const {
  hydrateEnvFromVault,
  loadSecrets,
  vaultName,
  SecretUnavailableError,
  _resetCache,
} = await import('../src/utils/secrets.js');

const ENV_KEYS = ['APP_ENV', 'CLAY_TEAM', 'AWS_REGION', 'METABASE_API_KEY', 'JWT_SECRET'];

/** Answers GetSecretValue from a {vaultName: contents} map; anything else 404s. */
function vaultsRespond(vaults: Record<string, Record<string, string>>) {
  send.mockImplementation((cmd: { input: { SecretId: string } }) => {
    const contents = vaults[cmd.input.SecretId];
    if (!contents) {
      const err = new Error('not found');
      err.name = 'ResourceNotFoundException';
      return Promise.reject(err);
    }
    return Promise.resolve({ SecretString: JSON.stringify(contents) });
  });
}

beforeEach(() => {
  for (const key of ENV_KEYS) delete process.env[key];
  send.mockReset();
  _resetCache();
});

describe('vaultName', () => {
  it('builds the team vault from CLAY_TEAM and APP_ENV', () => {
    process.env.CLAY_TEAM = 'data';
    process.env.APP_ENV = 'production';
    expect(vaultName()).toBe('clay-data-secrets-production');
  });

  it('defaults to the data team in development', () => {
    expect(vaultName()).toBe('clay-data-secrets-development');
  });

  it('is case-insensitive for CLAY_TEAM and APP_ENV', () => {
    process.env.CLAY_TEAM = 'Data';
    process.env.APP_ENV = 'PRODUCTION';
    expect(vaultName()).toBe('clay-data-secrets-production');
  });

  it('points team clay at the common vault', () => {
    process.env.CLAY_TEAM = 'clay';
    expect(vaultName()).toBe('clay-common-secrets-development');
  });

  it('rejects an environment outside development/production', () => {
    process.env.APP_ENV = 'staging';
    expect(() => vaultName()).toThrow(SecretUnavailableError);
    expect(() => vaultName()).toThrow('staging');
  });
});

describe('loadSecrets', () => {
  it('layers the team vault on top of the common one', async () => {
    vaultsRespond({
      'clay-common-secrets-development': { SHARED: 'common', OVERRIDDEN: 'from-common' },
      'clay-data-secrets-development': { OWN: 'team', OVERRIDDEN: 'from-team' },
    });

    await expect(loadSecrets()).resolves.toEqual({
      SHARED: 'common',
      OWN: 'team',
      OVERRIDDEN: 'from-team',
    });
  });

  it('reads only the common vault for team clay', async () => {
    process.env.CLAY_TEAM = 'clay';
    vaultsRespond({ 'clay-common-secrets-development': { SHARED: 'common' } });

    await expect(loadSecrets()).resolves.toEqual({ SHARED: 'common' });
    expect(send).toHaveBeenCalledTimes(1);
  });

  it('tolerates a missing common vault', async () => {
    vaultsRespond({ 'clay-data-secrets-development': { OWN: 'team' } });

    await expect(loadSecrets()).resolves.toEqual({ OWN: 'team' });
  });

  it('fails when the team vault is unreachable, reporting the AWS code', async () => {
    const denied = new Error('nope');
    denied.name = 'AccessDeniedException';
    send.mockRejectedValue(denied);

    await expect(loadSecrets()).rejects.toThrow(SecretUnavailableError);
    await expect(loadSecrets()).rejects.toThrow(
      'could not read clay-data-secrets-development: AccessDeniedException: nope'
    );
  });

  it('includes the underlying message so failures stay diagnosable', async () => {
    // A malformed session token used to surface as a bare "TypeError".
    send.mockRejectedValue(new TypeError('Invalid character in header content'));

    await expect(loadSecrets()).rejects.toThrow(
      'could not read clay-data-secrets-development: ' +
        'TypeError: Invalid character in header content'
    );
  });

  it('rejects a vault that is not a flat JSON object', async () => {
    send.mockResolvedValue({ SecretString: '["not", "an", "object"]' });

    await expect(loadSecrets()).rejects.toThrow('is not a flat JSON object');
  });

  it('fetches each vault once across repeated calls', async () => {
    vaultsRespond({ 'clay-data-secrets-development': { OWN: 'team' } });

    await loadSecrets();
    await loadSecrets();

    // one call per vault (common + team), not per invocation
    expect(send).toHaveBeenCalledTimes(2);
  });

  it('does not cache a failure, so the next call retries', async () => {
    const transient = new Error('boom');
    transient.name = 'ThrottlingException';
    send.mockRejectedValueOnce(transient).mockRejectedValueOnce(transient);

    await expect(loadSecrets()).rejects.toThrow(SecretUnavailableError);

    vaultsRespond({ 'clay-data-secrets-development': { OWN: 'team' } });
    await expect(loadSecrets()).resolves.toEqual({ OWN: 'team' });
  });
});

describe('hydrateEnvFromVault', () => {
  it('resolves a variable from the team vault', async () => {
    vaultsRespond({ 'clay-data-secrets-development': { METABASE_MCP_KEY: 'mb_from_vault' } });

    const origin = await hydrateEnvFromVault({ METABASE_API_KEY: 'METABASE_MCP_KEY' });

    expect(process.env.METABASE_API_KEY).toBe('mb_from_vault');
    expect(origin.METABASE_API_KEY).toBe(
      'Secrets Manager · clay-data-secrets-development · METABASE_MCP_KEY'
    );
  });

  it('keeps an env var that is already set and skips AWS entirely', async () => {
    process.env.METABASE_API_KEY = 'mb_from_env';

    const origin = await hydrateEnvFromVault({ METABASE_API_KEY: 'METABASE_MCP_KEY' });

    expect(process.env.METABASE_API_KEY).toBe('mb_from_env');
    expect(origin.METABASE_API_KEY).toBe('METABASE_API_KEY environment variable');
    expect(send).not.toHaveBeenCalled();
  });

  it('leaves a variable undefined when its key is absent from the vault', async () => {
    vaultsRespond({ 'clay-data-secrets-development': { SOMETHING_ELSE: 'x' } });

    const origin = await hydrateEnvFromVault({ JWT_SECRET: 'METABASE_MCP_GATEWAY_SECRET' });

    expect(process.env.JWT_SECRET).toBeUndefined();
    expect(origin).not.toHaveProperty('JWT_SECRET');
  });

  it('queries AWS once for several variables', async () => {
    vaultsRespond({
      'clay-data-secrets-development': {
        METABASE_MCP_KEY: 'mb',
        METABASE_MCP_GATEWAY_SECRET: 'jwt',
      },
    });

    await hydrateEnvFromVault({
      METABASE_API_KEY: 'METABASE_MCP_KEY',
      JWT_SECRET: 'METABASE_MCP_GATEWAY_SECRET',
    });

    expect(process.env.METABASE_API_KEY).toBe('mb');
    expect(process.env.JWT_SECRET).toBe('jwt');
    expect(send).toHaveBeenCalledTimes(2); // common + team, once each
  });

  it('keeps vault contents out of the error when the payload is malformed', async () => {
    // Truncated JSON: the raw SyntaxError would quote the vault's own contents.
    send.mockResolvedValue({
      SecretString: '{"METABASE_MCP_GATEWAY_SECRET": "must-not-leak"',
    });

    const err = await hydrateEnvFromVault({
      JWT_SECRET: 'METABASE_MCP_GATEWAY_SECRET',
    }).catch((e) => e as Error);

    expect(err.message).toBe(
      'could not read clay-data-secrets-development: is not valid JSON'
    );
    expect(err.message).not.toContain('must-not-leak');
  });
});
