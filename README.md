<!--
SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>

SPDX-License-Identifier: MIT
-->

# AshAuthentication.Oauth2Server

An OAuth 2.1 authorization server for Ash Framework apps. Pairs with
[`ash_authentication`](https://hexdocs.pm/ash_authentication) for the
user-login side and runs on Phoenix.

## What this gives you

* OAuth 2.1 `/authorize` + `/token` flow with PKCE-only (RFC 9700)
* Client ID Metadata Documents (CIMD) — opt-in URL-based client
  identity, the registration mechanism the MCP 2026-07-28 spec
  recommends, with an SSRF-hardened document fetcher
* Dynamic Client Registration (RFC 7591) — opt-in, with optional
  initial-access-token gating
* Audience-bound access tokens (RFC 8707)
* Issuer identification on authorization responses (RFC 9207)
* Refresh-token rotation with reuse detection
* Discovery metadata (RFC 8414 + RFC 9728) + `/.well-known/openid-configuration`
* User-driven consent screen with override-friendly UI
* Bearer plug for protected resource endpoints, plus a scope-gate plug
  that emits step-up-friendly `insufficient_scope` challenges (RFC 6750)
* Designed to host Model Context Protocol (MCP) servers, ChatGPT Apps
  SDK connectors, Claude.ai integrations, etc.

## Installation

```bash
mix igniter.install ash_authentication_oauth2_server
```

This scaffolds the four resources (`OAuthClient`,
`OAuthAuthorizationCode`, `OAuthRefreshToken`, `OAuthConsent`), wires
them into your `Accounts` domain, generates an `Oauth2Server` config
module, and adds the secret-resolution clauses on your `Secrets`
module.

## Usage

See `AshAuthentication.Oauth2Server` for full configuration, and the
post-install notice for the steps to wire the routes into your
Phoenix router and mount `AshAuthentication.Phoenix.Oauth2Server.BearerPlug`
on your protected endpoints.
