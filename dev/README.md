<!--
SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>

SPDX-License-Identifier: MIT
-->

# Dev app

A small Ash app to try the authorization server by hand. It stores all data
in ETS, so a restart clears it. The mock sign-in signs you in as
`dev@example.com` without a password.

## Run

```bash
mix dev
```

Then open http://localhost:4000.

## Protected resources

One authorization server protects two resources. Each resource accepts only
tokens for its own audience and scope.

| Resource | URL | Scope | Exposes |
|---|---|---|---|
| `:mcp` | http://localhost:4000/mcp | `mcp` | The `greet` tool (ash_ai) |
| `:gql` | http://localhost:4000/gql | `gql` | The `me` query (ash_graphql) |

## Add the MCP server to Claude Code

```bash
claude mcp add --transport http ash-dev http://localhost:4000/mcp
```

In Claude Code, run `/mcp`, select `ash-dev`, and authenticate. Your browser
opens the sign-in page. Sign in and approve the consent screen. Then ask
Claude to call the `greet` tool.
