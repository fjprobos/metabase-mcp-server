import { MetabaseClient } from "./client/metabase-client.js";

/**
 * Creates a per-request authenticate handler for HTTP Stream transport.
 * Extracts Metabase credentials from request headers and returns a
 * session-scoped MetabaseClient.
 */
export function createAuthenticateHandler() {
  return (request: any): { metabaseClient: MetabaseClient } => {
    const url = (request.headers['x-metabase-url'] as string) || process.env.METABASE_URL;
    const username = request.headers['x-metabase-username'] as string;
    const password = request.headers['x-metabase-password'] as string;
    const sessionToken = request.headers['x-metabase-session-token'] as string;

    // A Metabase API key always starts with `mb_`. An API key outranks every
    // other credential below, so accepting a value that cannot be one means
    // discarding a good session token in favour of something Metabase will
    // refuse — the caller then gets a 401 with no hint that it carried a
    // working credential all along. Callers do send such values: a browser
    // password manager fills the OAuth form's first type=password field, and
    // tokens minted before that was fixed still carry the result.
    const rawApiKey = request.headers['x-metabase-api-key'] as string;
    const apiKey = rawApiKey && !rawApiKey.startsWith('mb_') ? undefined : rawApiKey;
    if (rawApiKey && !apiKey) {
      console.error(JSON.stringify({
        timestamp: new Date().toISOString(),
        level: 'warn',
        message: 'Ignoring a malformed Metabase API key (must start with mb_)',
        has_session_token: Boolean(sessionToken),
      }));
    }

    if (!url) {
      throw new Response(null, {
        status: 401,
        statusText: 'Missing Metabase URL: provide x-metabase-url header or METABASE_URL env var',
      });
    }
    if (!apiKey && (!username || !password) && !sessionToken) {
      throw new Response(null, {
        status: 401,
        statusText: 'Missing credentials: provide x-metabase-api-key, x-metabase-username + x-metabase-password, or x-metabase-session-token headers',
      });
    }

    const metabaseClient = new MetabaseClient({ url, apiKey, username, password, sessionToken });
    return { metabaseClient };
  };
}

/**
 * Creates a client resolver that returns the appropriate MetabaseClient
 * for the current request context.
 * - HTTP mode: returns the per-session client from ctx.session.metabaseClient
 * - stdio mode: returns the shared defaultClient
 */
export function createClientResolver(defaultClient: MetabaseClient | null) {
  return (ctx?: any): MetabaseClient => {
    const sessionClient = ctx?.session?.metabaseClient;
    if (sessionClient) return sessionClient;
    if (defaultClient) return defaultClient;
    throw new Error('No MetabaseClient available — provide credentials via headers');
  };
}
