<!--
SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>

SPDX-License-Identifier: MIT
-->

# Client ID Metadata Documents

Client ID Metadata Documents (CIMD,
[draft-ietf-oauth-client-id-metadata-document](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-00))
let an OAuth client use an HTTPS URL as its `client_id`. The URL points
at a JSON document the client hosts:

```json
{
  "client_id": "https://app.example.com/oauth/client-metadata.json",
  "client_name": "Example MCP Client",
  "redirect_uris": ["http://localhost:3000/callback"],
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none"
}
```

When such a `client_id` arrives at `/oauth/authorize`, this server
fetches the document, validates it, and treats the result as the
client's registration — no `/oauth/register` call needed. This is the
client registration mechanism the MCP spec (2026-07-28) recommends;
Dynamic Client Registration is deprecated there and kept for backwards
compatibility.

## Enabling it

```elixir
use AshAuthentication.Oauth2Server,
  # ...
  cimd_enabled?: true
```

Two prerequisites:

1. **The `req` dependency** (for the default fetcher):

   ```elixir
   {:req, "~> 0.5"}
   ```

2. **CIMD support on your client resource.** New installs get this from
   the installer; existing apps add:

   ```elixir
   attribute :cimd_url, :string, public?: true

   identity :by_cimd_url, [:cimd_url]

   create :register_cimd do
     upsert? true
     upsert_identity :by_cimd_url

     accept [:cimd_url, :client_name, :redirect_uris, :grant_types,
             :response_types, :token_endpoint_auth_method, :scope]
   end
   ```

   then `mix ash.codegen add_cimd_to_oauth_clients` + migrate.

With CIMD on, the RFC 8414 metadata document advertises
`client_id_metadata_document_supported: true`, which is how clients
discover they can skip registration.

## How it works

* **Authorize** — a URL-shaped `client_id` triggers a fetch (through an
  in-memory cache that honours the document's HTTP cache headers, capped
  at one hour). The document is validated — its `client_id` must match
  the URL exactly, `client_name` and valid `redirect_uris` are required,
  and the grant/response/auth-method fields must be within what this
  server supports (public clients only) — then upserted into your client
  resource keyed by `cimd_url`. From there the flow is identical to any
  other client: exact-match redirect URI checks, consent (persisted per
  user + client), audience-bound codes.
* **Token / revocation** — the client presents the same URL as its
  `client_id`; it's resolved against the database only (never fetched).
  Access tokens minted for CIMD clients carry the URL in their
  `client_id` claim.
* **Cache** — `AshAuthentication.Oauth2Server.Supervisor` runs the
  document cache. Without it everything still works; each authorize
  request just re-fetches.

## SSRF and the fetcher

Fetching an attacker-suppliable URL from inside your infrastructure is
the risky part of CIMD. The default fetcher
(`AshAuthentication.Oauth2Server.CIMD.ReqFetcher`) enforces an outbound
policy: HTTPS on port 443 only, a required path component, DNS
resolution up front with **every** resolved address required to be
publicly routable (loopback, RFC 1918, link-local/cloud-metadata, CGNAT,
NAT64/6to4/v4-mapped embeddings, and friends are rejected), a connect
pinned to the validated IP (closing the DNS-rebinding window) with TLS
verification kept on the hostname, no redirects, and a 64 KiB / 5s
response cap.

If you need a different policy — an egress proxy, a host allowlist, or a
stub in tests — implement `AshAuthentication.Oauth2Server.CIMD.Fetcher`
and set `:cimd_fetcher`. The fetcher options (`:cimd_fetch_options`) are
passed through to `fetch/2`.

Because a fetch can be triggered by an unauthenticated `GET
/oauth/authorize`, rate-limit that endpoint the same way you rate-limit
the other protocol endpoints (see the "Rate limiting" section in
`AshAuthentication.Oauth2Server`).

## Relationship to DCR

CIMD and Dynamic Client Registration coexist; enable either or both.
Clients following the MCP 2026-07-28 spec prefer CIMD when
`client_id_metadata_document_supported` is advertised and fall back to
DCR via `registration_endpoint`. If you serve older MCP clients, keep
`dcr_enabled?: true` alongside `cimd_enabled?: true` during the
transition window.
