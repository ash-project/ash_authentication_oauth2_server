<!--
SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>

SPDX-License-Identifier: MIT
-->

# Client credentials

The `client_credentials` grant
([RFC 6749 section 4.4](https://www.rfc-editor.org/rfc/rfc6749#section-4.4))
issues an access token that represents the OAuth client itself. Use it when
another service (a worker, a partner backend, an internal tool) needs scoped
API access without an interactive login.

The client sends its id and secret to `/oauth/token` and gets an access token
back. There is no consent screen and no refresh token: when the token expires,
the client requests a new one the same way. On your API, `BearerPlug` verifies
the token and sets the client's Ash record as the actor, so your policies
authorize the client.

## Enabling the grant

The grant is off by default. Add it to `:supported_grants`:

```elixir
defmodule MyApp.Oauth2Server do
  use AshAuthentication.Oauth2Server,
    # ...required options...
    scopes: ["my-scope"],
    supported_grants: [:authorization_code, :refresh_token, :client_credentials]
end
```

The metadata document then lists `client_credentials` in
`grant_types_supported`. A server can also support this grant alone; see the
grants section of `AshAuthentication.Oauth2Server` for what each entry
switches on.

Two further options apply:

* `:verify_client_secret` checks the secret a client presents. The default,
  `AshAuthentication.Oauth2Server.ClientSecret`, compares a SHA-256 digest
  with the `client_secret_hash` attribute of the client. Override it to
  verify against a KMS or another store.
* `:extra_access_token_claims` adds claims to every access token. For this
  grant the callback receives the client record, which is useful for tenancy
  claims. Reserved claims (`iss`, `sub`, `aud`, `client_id`, `scope`, `iat`,
  `nbf`, `exp`, `jti`, `tenant`, `gty`) cannot be overridden.

## Creating a client

Dynamic client registration and Client ID Metadata Documents register public
clients only, so a client for this grant is created by your application. The
installer adds the `client_secret_hash` and `allowed_resources` attributes to
the client resource; add a create action that accepts them:

```elixir
create :register_client_credentials do
  accept [
    :client_name,
    :redirect_uris,
    :grant_types,
    :response_types,
    :token_endpoint_auth_method,
    :scope,
    :client_secret_hash,
    :allowed_resources
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
    token_endpoint_auth_method: "client_secret_basic",
    scope: "my-scope",
    client_secret_hash: hash
  })
  |> Ash.create!()

# Show `client.id` and `plain` to the operator once. Never log them.
```

The client metadata follows
[RFC 7591 section 2](https://www.rfc-editor.org/rfc/rfc7591#section-2):

* `grant_types` lists the grants the client may use. A client that lists only
  `client_credentials` cannot start `/oauth/authorize` or redeem a code
  (`unauthorized_client`), so a machine client cannot obtain user tokens. A
  client without the attribute has the default, `["authorization_code"]`.
* `token_endpoint_auth_method` is `client_secret_basic` (HTTP Basic) or
  `client_secret_post` (`client_id` and `client_secret` in the body). The
  server accepts the registered method only. A client with `none` is public
  and cannot use this grant.
* `scope` is the client's allow-list. A request may ask for a subset of it.
  When the request omits `scope`, the whole list is granted.
* `allowed_resources`, when set, names the resources the client may request
  tokens for. Without it, the client may use every configured resource.

A confidential client authenticates on every grant it uses, not only this
one. If it also lists `authorization_code` or `refresh_token`, it presents
its secret on those token requests and on `/oauth/revoke` too
([RFC 6749 section 3.2.1](https://www.rfc-editor.org/rfc/rfc6749#section-3.2.1)).

## Requesting a token

With `client_secret_basic`:

```bash
curl -sS -X POST 'https://auth.example.com/oauth/token' \
  -u 'CLIENT_ID:CLIENT_SECRET' \
  -d 'grant_type=client_credentials' \
  -d 'scope=my-scope'
```

With `client_secret_post`:

```bash
curl -sS -X POST 'https://auth.example.com/oauth/token' \
  -d 'grant_type=client_credentials' \
  -d 'client_id=CLIENT_ID' \
  -d 'client_secret=CLIENT_SECRET' \
  -d 'scope=my-scope'
```

The response is an access token without a refresh token:

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "my-scope"
}
```

A token is bound to one resource
([RFC 8707](https://www.rfc-editor.org/rfc/rfc8707)). With one configured
resource, `resource` is optional. With several, send the resource's URL as
`resource`; scopes are checked against that resource's scopes.

Errors follow
[RFC 6749 section 5.2](https://www.rfc-editor.org/rfc/rfc6749#section-5.2):

| Error | When |
|---|---|
| `invalid_request` | Credentials in both the header and the body, in the query string, or a malformed parameter. |
| `invalid_client` | Unknown client, wrong secret, no credentials, a public client, or a method other than the registered one. With an `Authorization` header the status is 401 with a `WWW-Authenticate: Basic` challenge. |
| `unauthorized_client` | The client authenticated but does not list `client_credentials`. |
| `unsupported_grant_type` | The server does not list `client_credentials` in `:supported_grants`. |
| `invalid_scope` | A scope outside the client's allow-list or the resource's scopes, or no scope at all. |
| `invalid_target` | An unknown, ambiguous, or disallowed `resource`. |

## Protecting resource-server routes

`AshAuthentication.Phoenix.Oauth2Server.BearerPlug` accepts tokens from this
grant as soon as the server supports it. The actor it sets is the client
record, where a user token sets a user record, so policies on a route that
takes both must handle both:

```elixir
pipeline :api do
  plug AshAuthentication.Phoenix.Oauth2Server.BearerPlug,
    oauth2_server: MyApp.Oauth2Server

  plug AshAuthentication.Phoenix.Oauth2Server.RequireScopePlug,
    oauth2_server: MyApp.Oauth2Server,
    scope: "my-scope"
end
```

Access tokens from this grant carry `"gty": "client_credentials"`, and their
`sub` is the client id
([RFC 9068 section 2.2](https://www.rfc-editor.org/rfc/rfc9068#section-2.2)).
User tokens never carry `gty`, and `:extra_access_token_claims` cannot set
it. If you verify tokens yourself with
`AshAuthentication.Oauth2Server.Jwt.verify/2`, check `gty` before treating
`sub` as a user id.

On each request the plug reloads the client and checks that it still lists
`client_credentials`, may still use the resource, and that the token's
scopes are still within its allow-list. Removing the grant, a resource, or a
scope from the client row takes effect before the token expires.

## Dynamic client registration and metadata documents

Dynamic client registration ([RFC 7591](https://www.rfc-editor.org/rfc/rfc7591))
and [Client ID Metadata Documents](client-id-metadata-documents.md) register
public clients for the `authorization_code` grant, with `refresh_token` when
the server supports it. They cannot register a client for
`client_credentials` or set a secret, so `:supported_grants` narrows what
they may request, and both require `:authorization_code` in the list.

## Security notes

* The grant is limited to confidential clients
  ([RFC 6749 section 4.4](https://www.rfc-editor.org/rfc/rfc6749#section-4.4)).
* Credentials are accepted in the `Authorization` header or the request
  body, never in the query string
  ([RFC 6749 section 2.3.1](https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1)).
* Access tokens are bound to one resource and are short-lived; tune
  `:access_token_lifetime` for your APIs
  ([RFC 9700 section 2.3](https://www.rfc-editor.org/rfc/rfc9700#section-2.3)).
* Secrets are stored as a digest. RFC 9700 recommends asymmetric client
  authentication (`private_key_jwt`, mTLS), which this library does not
  implement yet.
* Rate-limit `/oauth/token` against online secret guessing. The library
  does not ship a rate limiter; see `AshAuthentication.Oauth2Server`.
