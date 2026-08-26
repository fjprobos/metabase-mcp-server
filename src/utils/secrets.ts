/**
 * Credential loading from AWS Secrets Manager (Clay POL-SEC-001).
 *
 * Clay's vault model:
 *   clay-common-secrets-{env}   values shared across teams
 *   clay-{team}-secrets-{env}   values owned by a single team
 *
 * The common vault is read first, then the team vault, which takes precedence.
 * The environment comes from APP_ENV and the team from CLAY_TEAM. Values live
 * in memory only: they are never written to disk nor logged.
 *
 * An env var that is already set wins over the vault, so local development
 * keeps working without AWS credentials.
 */

import {
  SecretsManagerClient,
  GetSecretValueCommand,
} from "@aws-sdk/client-secrets-manager";

const ENVIRONMENTS = ["development", "production"] as const;

/** Failure to obtain a secret. Never carries the secret's value. */
export class SecretUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SecretUnavailableError";
  }
}

function environment(): string {
  const env = (process.env.APP_ENV || "development").toLowerCase();
  if (!(ENVIRONMENTS as readonly string[]).includes(env)) {
    throw new SecretUnavailableError(
      `APP_ENV="${env}" is not valid; use one of ${ENVIRONMENTS.join(", ")}`
    );
  }
  return env;
}

function team(): string {
  return (process.env.CLAY_TEAM || "data").toLowerCase();
}

/** The team's vault (or the common one for team `clay`), for messages and logs. */
export function vaultName(): string {
  const t = team();
  return t === "clay"
    ? `clay-common-secrets-${environment()}`
    : `clay-${t}-secrets-${environment()}`;
}

let client: SecretsManagerClient | null = null;

function getClient(): SecretsManagerClient {
  if (!client) {
    client = new SecretsManagerClient({
      region:
        process.env.AWS_REGION || process.env.AWS_DEFAULT_REGION || "us-east-1",
    });
  }
  return client;
}

type Vault = Record<string, string>;

/** A vault whose payload is missing or not a flat JSON object. */
class VaultShapeError extends Error {}

/**
 * A diagnosable one-liner for a failure to read a vault.
 *
 * Vault contents never reach it: shape problems carry our own wording, and SDK
 * or runtime errors describe transport and authorization, not the payload.
 */
function describeFailure(e: unknown): string {
  if (e instanceof VaultShapeError) return e.message;
  if (e instanceof Error) return e.message ? `${e.name}: ${e.message}` : e.name;
  return "unknown error";
}

/**
 * A vault's contents. When not required, a missing vault yields {}.
 * Errors describe the kind of failure, never the secret's contents.
 */
async function readVault(name: string, required: boolean): Promise<Vault> {
  try {
    const res = await getClient().send(
      new GetSecretValueCommand({ SecretId: name })
    );
    if (!res.SecretString) {
      throw new VaultShapeError("has no SecretString");
    }
    let contents: unknown;
    try {
      contents = JSON.parse(res.SecretString);
    } catch {
      // A SyntaxError quotes the text it could not parse — which is the vault's
      // contents — so it is dropped rather than folded into the message.
      throw new VaultShapeError("is not valid JSON");
    }
    if (
      contents === null ||
      typeof contents !== "object" ||
      Array.isArray(contents)
    ) {
      throw new VaultShapeError("is not a flat JSON object");
    }
    return contents as Vault;
  } catch (e) {
    if (!required) return {};
    throw new SecretUnavailableError(
      `could not read ${name}: ${describeFailure(e)}`
    );
  }
}

let cache: Promise<Vault> | null = null;

/**
 * The merged contents of the common and team vaults.
 *
 * Team `clay` only gets the common vault; every other team layers its own vault
 * on top of the common one. A failure is not cached, so a transient network or
 * credential error can be retried.
 */
export function loadSecrets(): Promise<Vault> {
  if (!cache) {
    const env = environment();
    const t = team();
    cache = (async () => {
      if (t === "clay") {
        return readVault(`clay-common-secrets-${env}`, true);
      }
      const [common, own] = await Promise.all([
        readVault(`clay-common-secrets-${env}`, false),
        readVault(`clay-${t}-secrets-${env}`, true),
      ]);
      return { ...common, ...own };
    })().catch((e) => {
      cache = null;
      throw e;
    });
  }
  return cache;
}

/**
 * Fills process.env from the vault given a {ENV_VAR: VAULT_KEY} mapping.
 *
 * An env var that is already set is left alone, and if all of them are set AWS
 * is never called — that is what keeps local development credential-free. Keys
 * missing from the vault are left undefined: deciding what is mandatory belongs
 * to the caller, which knows which combination of credentials it can work with.
 *
 * Returns, per resolved variable, where its value came from. Safe to log: it
 * describes the origin, never the value.
 */
export async function hydrateEnvFromVault(
  mapping: Record<string, string>
): Promise<Record<string, string>> {
  const origin: Record<string, string> = {};
  const missing: string[] = [];

  for (const variable of Object.keys(mapping)) {
    if (process.env[variable]) {
      origin[variable] = `${variable} environment variable`;
    } else {
      missing.push(variable);
    }
  }

  if (missing.length === 0) return origin;

  const secrets = await loadSecrets();
  const vault = vaultName();

  for (const variable of missing) {
    const key = mapping[variable];
    const value = secrets[key];
    if (value === undefined) continue;
    process.env[variable] = value;
    origin[variable] = `Secrets Manager · ${vault} · ${key}`;
  }

  return origin;
}

/** Test-only: drops the memoized client and secrets. */
export function _resetCache(): void {
  cache = null;
  client = null;
}
