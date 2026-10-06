<!--
SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>

SPDX-License-Identifier: MIT
-->

# Client credentials

`client_credentials` issues an access token that represents the **OAuth
client itself** — not a user who clicked “Allow”. Use it when another
service (a worker, a partner backend, an internal tool) needs scoped API
access and there is no interactive login to run.

That is a different trust model from the authorization-code path covered
elsewhere: there is no consent screen, no refresh token, and
`ClientBearerPlug` loads the **client** Ash record as the actor instead of
a user.

## Enabling the grant

The grant is on out of the box. `:verify_client_secret` defaults to
`{AshAuthentication.Oauth2Server.ClientSecret, :verify, []}`, which
constant-time-compares a SHA-256 digest on the client’s
`client_secret_hash` attribute (added by the installer).

You can disable it by setting the `verify_client_secret` to `nil`:

```elixir
defmodule MyApp.Oauth2Server do
  use AshAuthentication.Oauth2Server,
    # ...required options...
    scopes: ["my-scope"]
    # Disable the client_secret grant.
    # verify_client_secret: nil
    # Or overwrite the verification function with your own.
    # verify_client_secret: {MyApp.Accounts, :verify_oauth_client_secret, []}
    # extra_access_token_claims: {MyApp.Accounts, :oauth_extra_claims, []}
end
```

The `extra_access_token_claims` allows you to set additional fields on the JWT
claims. Reserved JWT claims (`iss`, `sub`, `aud`, ...) are not overwritable.

## Creating a client

Confidential clients are ordinary Ash rows. Add a create action to your client
resource that accepts the secret hash:

```elixir
create :register_client_credentials do
  accept [
    :client_name,
    :redirect_uris,
    :grant_types,
    :response_types,
    :token_endpoint_auth_method,
    :scope,
    :client_secret_hash
  ]
end
```

```elixir
{plain, hash} = AshAuthentication.Oauth2Server.ClientSecret.generate()

client =
  MyApp.Accounts.OauthClient
  |> Ash.Changeset.for_create(:register_client_credentials, %{
    client_name: "Billing integration",
    redirect_uris: [],
    grant_types: ["client_credentials"],
    response_types: [],
    token_endpoint_auth_method: "client_secret_post",
    scope: "my-scope",
    client_secret_hash: hash
  })
  |> Ash.create!()

# Pass the client.id and plain variables to the user once. Never log them.
```

Prefer `client_secret_basic` or `client_secret_post` on the client row —
both mean “confidential client with a secret”. Callers may authenticate
with **either** HTTP Basic **or** form-body credentials regardless of
which of those two values is stored. Use `none` only for public clients;
those cannot use this grant.

A client with any method other than `none` is confidential on **every**
grant, not only this one: if you also give it `authorization_code` /
`refresh_token`, it must present its secret on those token requests too
(RFC 6749 §4.1.3 / §6), otherwise the request fails with
`invalid_client`. The check runs before the code is consumed or the
refresh token rotated, so a failed attempt doesn't burn either. The same
applies to `/oauth/revoke`. Public clients (`none`) must not send a secret
at all; they get `invalid_client` if they do.

`grant_types` is enforced on every grant. A client that lists only
`client_credentials` cannot start `/oauth/authorize` or redeem a code
(`unauthorized_client`), so a machine client can't be used to obtain
user-delegated tokens. A client must list `refresh_token` to get a refresh
token or to use the refresh grant. A `nil` `grant_types` means the RFC 7591
default, `["authorization_code"]`.

## Protecting resource-server routes

Wire a pipeline that uses `ClientBearerPlug`. Do **not** reuse the user
`BearerPlug`: tokens from this grant carry a reserved
`"gty" => "client_credentials"` claim (and set both `sub` and `client_id`
to the client’s id). `BearerPlug` rejects any token with a `gty` claim,
and `ClientBearerPlug` requires it, so machine and user tokens cannot
stand in for each other even if a client id and a user id collide.
`:extra_access_token_claims` cannot set `gty`. If you verify tokens
yourself with `AshAuthentication.Oauth2Server.Jwt.verify/2`, check `gty`
the same way before treating `sub` as a user id.

```elixir
pipeline :api do
  plug AshAuthentication.Phoenix.Oauth2Server.ClientBearerPlug,
    oauth2_server: MyApp.Oauth2Server

  plug AshAuthentication.Phoenix.Oauth2Server.RequireScopePlug,
    oauth2_server: MyApp.Oauth2Server,
    scope: "my-scope"
end
```

If the server protects more than one resource (the `:resources` option),
name the resource each pipeline guards with `resource: :name` on both
plugs. The plug then accepts only tokens issued for that resource, and the
`WWW-Authenticate` challenge points at that resource's metadata. The option
is required when there is more than one resource, and plug initialisation
raises without it.

On each request the plug re-loads the client and checks that
`client_credentials` is still allowed and that the token’s scopes remain
inside the client’s current allow-list — so stripping a grant or narrowing
`scope` on the row takes effect before the JWT’s `exp`.

## Calling `/oauth/token`

Body credentials (`client_secret_post` style):

```bash
curl -sS -X POST 'https://auth.example.com/oauth/token' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=client_credentials' \
  -d 'client_id=CLIENT_ID' \
  -d 'client_secret=CLIENT_SECRET' \
  -d 'scope=my-scope'
```

The request must be `application/x-www-form-urlencoded` (RFC 6749 §4.4.2);
a JSON body is rejected with `invalid_request`.

HTTP Basic (`client_secret_basic` style) — same client row works either
way:

```bash
curl -sS -X POST 'https://auth.example.com/oauth/token' \
  -u 'CLIENT_ID:CLIENT_SECRET' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=client_credentials' \
  -d 'scope=my-scope'
```

Credentials belong in the body **or** in HTTP Basic — never both, and never
in the query string (RFC 6749 §5.2 / §2.3.1). The registered
`token_endpoint_auth_method` (`client_secret_basic` or
`client_secret_post`) is metadata for clients/tooling; this server does
not reject a valid secret presented via the other channel.

A successful response looks like:

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "my-scope"
}
```

There is no refresh token; when it expires the client authenticates again.
At least one scope is required (request or the client’s default
allow-list). Scopes must be offered by the resource the token is for.

### Choosing the resource

A token is bound to one resource (RFC 8707). Send `resource` with the
resource's URL, an absolute URI without a fragment:

```bash
  -d 'resource=https://api.example.com/mcp'
```

- With a single configured resource, `resource` is optional and defaults to
  it.
- With several, `resource` is required. Without it the request is
  ambiguous and fails with `invalid_target`.
- A value that matches no configured resource, or several different
  resources in one request, is `invalid_target`. The same resource repeated
  is accepted.
- The token's `aud` is the resource's URL. Scopes are checked against that
  resource's scopes (its `:scopes` entry, or the server's `:scopes` when it
  has none), so a scope the resource does not offer is `invalid_scope`.
  When you omit `scope`, the client's whole allow-list is the default, so
  it must be a subset of that resource's scopes. Otherwise name the
  scopes you want.

Nothing yet restricts which resources a client may ask for. Any client
with the grant can request a token for any configured resource, limited
only by its `scope` allow-list.

### Errors

`invalid_client` is a `400`, or a `401` with a `WWW-Authenticate: Basic`
challenge when the client authenticated with the `Authorization` header
(OAuth 2.1 §3.2.4).

## Security notes (RFC 9700 / RFC 6819)

Aligned with OAuth security BCPs for this grant:

- **Confidential clients only** — public / `auth_method: none` clients are
  rejected; DCR cannot register `client_credentials` secrets
  (RFC 6819 §5.2.3.1).
- **No credentials in the URI** — `client_id` / `client_secret` (and
  assertion params) in the query string are rejected; only the request body
  or `Authorization` header may carry them (RFC 6749 §2.3.1 /
  RFC 6819 §4.3.3).
- **Uniform `invalid_client`** — unknown clients, ineligible grant, and bad
  secrets all map to the same error, with a timing pad on early rejects so
  client-id enumeration is harder (RFC 6819 / RFC 9700).
- **Audience-bound tokens** — every access token carries `aud` = the URL of
  the one resource it was issued for; resource plugs reject other audiences,
  so a token for one resource cannot be replayed at another
  (RFC 9700 §2.3 / RFC 6819 §5.1.5.5).
- **Least privilege** — scopes are enforced against the resource's scopes and
  the client allow-list; bearer plugs re-check both on each request
  (RFC 9700 §2.3).
- **Header-only bearer tokens** — protected-resource metadata advertises
  `bearer_methods_supported: ["header"]`; query/form bearer tokens are not
  accepted (RFC 6750 / RFC 9700).
- **Short-lived access tokens** — default lifetime is one hour; tune
  `:access_token_lifetime` down for higher-risk APIs (no refresh token on
  this grant — clients re-authenticate) (RFC 6819 §5.1.5.3).
- **Secret handling** — default storage is a SHA-256 digest of a
  high-entropy secret (`ClientSecret`). Prefer hashing/cloaking at rest;
  never log plaintext. RFC 9700 §2.5 recommends asymmetric client
  authentication (`private_key_jwt` / mTLS) when you can — symmetric
  secrets remain supported but are the weaker option. Sender-constrained
  access tokens (DPoP / certificate-bound) are not implemented yet; rely
  on short lifetimes, audience binding, and TLS.
- **Rate-limit** `/oauth/token` and `/oauth/register` at the edge (Hammer,
  PlugAttack, reverse proxy) against online secret guessing
  (RFC 6819 §5.1.4.2). The library does not ship a rate limiter.
- **Do not** put open CORS credentials on the token endpoint for browser
  clients that are not supposed to hold machine secrets.
- **Password / implicit grants** are not offered — consistent with
  RFC 9700 §2.1.2 / §2.4.
