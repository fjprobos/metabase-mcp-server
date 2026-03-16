# Spec: Google SSO Authentication Support

## Context

The OAuth gateway (`src/oauth-gateway.ts`) currently supports two auth methods for Metabase:
- API Key (`x-metabase-api-key`)
- Username + Password (`x-metabase-username` + `x-metabase-password`)

When a Metabase instance enforces Google SSO, neither method is available. The only
programmatic workaround is to extract the `metabase.SESSION` cookie value from the browser
after a successful Google SSO login and use it directly as an `X-Metabase-Session` header
on Metabase API calls.

The per-request auth mechanism is implemented in `feat/http-stream-transport-with-per-request-auth`
in `src/auth.ts`. That branch reads `x-metabase-*` headers per request and creates a
`MetabaseClient` per session — but does not yet handle `x-metabase-session-token`.

---

## Goal

Allow users who authenticate in Metabase via Google SSO to connect to the MCP server
by providing their `metabase.SESSION` cookie value in the OAuth authorization form.

---

## How Metabase Session Tokens Work

- After any login (including Google SSO), Metabase sets a `metabase.SESSION` cookie.
- This cookie value is a UUID session token.
- It can be used directly as the `X-Metabase-Session` request header on all Metabase API calls,
  bypassing the need for username/password or an API key.
- The session expires based on the instance's JWT settings (typically a few hours to days).
- There is no programmatic API to obtain this token via Google SSO — the user must
  extract it manually from browser dev tools.

---

## Scope

Changes are scoped to 4 files, all within `feat/http-stream-transport-with-per-request-auth`
(see open question below about target branch):

| File | Change |
|------|--------|
| `src/types/metabase.ts` | Add `sessionToken?: string` to `MetabaseConfig` |
| `src/client/metabase-client.ts` | Support pre-existing session token in constructor |
| `src/auth.ts` | Read `x-metabase-session-token` header per request |
| `src/oauth-gateway.ts` | Add session token field to form + flow through JWT + proxy |

---

## Detailed Changes

### 1. `src/types/metabase.ts`

Add optional field to `MetabaseConfig`:

```ts
export interface MetabaseConfig {
  url: string;
  username?: string;
  password?: string;
  apiKey?: string;
  sessionToken?: string;   // ← new: pre-existing Metabase session (e.g. from Google SSO)
}
```

---

### 2. `src/client/metabase-client.ts`

In the constructor, add a third valid auth path alongside API key and username/password:

```
if config.sessionToken:
  set X-Metabase-Session header directly on axiosInstance
  set this.sessionToken = config.sessionToken   (skips getSessionToken() call)
  skip the "credentials not provided" error
```

The `ensureAuthenticated()` check already short-circuits if `this.sessionToken` is set,
so no other changes are needed in the client.

**Validation change:** the constructor currently throws if neither `apiKey` nor
`username+password` is provided. Add `sessionToken` as a third accepted option.

---

### 3. `src/auth.ts`

In `createAuthenticateHandler`, add reading of `x-metabase-session-token`:

```ts
const sessionToken = request.headers['x-metabase-session-token'] as string;
```

Update the credentials check:
```ts
// before: !apiKey && (!username || !password)
// after:
if (!apiKey && (!username || !password) && !sessionToken) {
  throw 401 response
}
```

Pass `sessionToken` to `MetabaseClient`:
```ts
const metabaseClient = new MetabaseClient({ url, apiKey, username, password, sessionToken });
```

---

### 4. `src/oauth-gateway.ts`

**`PendingCode` interface:** add `metabase_session_token?: string`

**HTML form:** add a third auth option after the "o usa usuario y contraseña" divider:

```
[ existing: API Key field ]
--- o usa usuario y contraseña ---
[ existing: Username + Password fields ]
--- o usa un token de sesión (Google SSO) ---
[ new: Session Token field (password input) ]
[ new: small helper text explaining where to find it ]
```

The helper text should say (roughly):
> Si tu Metabase usa Google SSO, inicia sesión en el browser, abre DevTools →
> Application → Cookies y copia el valor de `metabase.SESSION`.
> Este token expira según la configuración de tu instancia.

**Form JS validation:** extend to accept session token as a valid third option:
```js
if (!key && !(user && pass) && !sessionToken) { show error }
```

**POST /oauth/authorize handler:**
- Read `metabase_session_token` from body
- Update validation: accept key OR (user+pass) OR session_token
- Store in `PendingCode`

**POST /oauth/token handler:** include `metabase_session_token` in JWT payload

**MCP proxy:** inject header if present:
```ts
if (payload.metabase_session_token)
  proxyHeaders['x-metabase-session-token'] = payload.metabase_session_token;
```

---

## Token Expiry Warning

The session token from Metabase expires. Two options:

**Option A:** Show a static warning in the form (simple, no extra logic).
**Option B:** Check token validity against Metabase's `/api/user/current` before issuing
the JWT, and return a user-friendly error if it's already expired.

Option B gives better UX but adds an outbound HTTP call at authorize time. Recommendation:
start with Option A for simplicity.

---

## Open Questions

### Q1: Target branch
The per-request auth mechanism (`src/auth.ts`, modified `src/server.ts`, modified tools)
lives in `feat/http-stream-transport-with-per-request-auth`, which has NOT been merged
to `main`.

**Option A:** Implement Google SSO directly on `feat/http-stream-transport-with-per-request-auth`.
**Option B:** Merge `feat/http-stream-transport-with-per-request-auth` into `main` first,
then implement Google SSO on `main`.

The two branches diverged at commit `1c15ff3` and have non-overlapping changes, so a
merge should be clean. Recommended: Option B — it avoids accumulating divergence and
results in a single coherent `main`.

### Q2: Token expiry UX
Do you want Option A (static warning in the form) or Option B (validate token against
Metabase before issuing JWT)?

### Q3: Tests
The `feat/http-stream-transport-with-per-request-auth` branch has `tests/auth.test.ts`
covering the current `createAuthenticateHandler`. Should we add test cases for the
session token path in that same file?

---

## What is NOT in scope

- Implementing a real OAuth 2.0 flow with Google (that would require Google Cloud
  credentials and a callback URL — it's a much larger change and requires Metabase Pro/Enterprise).
- Any server-side session refresh / re-authentication when the token expires.
- Env var `METABASE_SESSION_TOKEN` for standalone mode (not related to this flow).
