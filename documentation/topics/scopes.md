<!--
SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/team-alembic/ash_authentication_oauth2_server/graphs/contributors>

SPDX-License-Identifier: MIT
-->

# Reading scopes from an access token

The OAuth 2.1 access token issued by this server is a signed JWT carrying
the scopes the user approved (or the client requested, if you've turned
off scope enforcement). This guide shows how to read those scopes inside
a Phoenix resource server protected by
`AshAuthentication.Phoenix.Oauth2Server.BearerPlug`.

## The shape of what's on the conn

After `BearerPlug` validates an `Authorization: Bearer <jwt>` header,
two things end up on the conn:

| Where | What | Use for |
|---|---|---|
| `Ash.PlugHelpers.get_actor(conn)` | The user record (loaded by `sub`) | "Who is this" — policies, ownership, tenancy |
| `conn.assigns.oauth_claims` | The verified JWT claims map | "What is this bearer allowed to do" — scopes, client identity, audience |

`oauth_claims` is a plain map of string keys. The interesting ones:

  * `"scope"` — space-separated list of granted scopes (RFC 6749 §3.3)
  * `"client_id"` — which OAuth client minted this token
  * `"aud"` — the resource URL the token was bound to (RFC 8707)
  * `"sub"` — the user's primary key
  * `"jti"` — unique token id

Pull scopes as a list:

```elixir
scopes =
  conn.assigns.oauth_claims["scope"]
  |> String.split(" ", trim: true)
```

## Scopes are conn-scoped, not actor-scoped

The same user authenticating from two different OAuth clients (e.g. a
mobile app and a CLI) gets two tokens with potentially different scope
sets. The actor on the conn is the user in both cases; the scopes
differ. This is the right OAuth semantic — an access token represents a
**delegated grant from user → client**, distinct from the user's own
permissions inside your app.

That means: don't pre-compute scope-derived permissions onto the user
record. Read scopes from the conn (or context) at the point of action.

## Pattern 1: a `RequireScope` plug

Cheapest gating — return 403 in the pipeline before the request reaches
the controller:

```elixir
defmodule MyAppWeb.RequireScope do
  @behaviour Plug
  import Plug.Conn

  @impl true
  def init(scope) when is_binary(scope), do: scope

  @impl true
  def call(conn, scope) do
    scopes =
      conn.assigns
      |> Map.get(:oauth_claims, %{})
      |> Map.get("scope", "")
      |> String.split(" ", trim: true)

    if scope in scopes do
      conn
    else
      conn |> send_resp(403, "") |> halt()
    end
  end
end
```

Mount it in your pipeline after `BearerPlug`:

```elixir
pipeline :mcp_read do
  plug AshAuthentication.Phoenix.Oauth2Server.BearerPlug,
    oauth2_server: MyApp.Oauth2Server
  plug MyAppWeb.RequireScope, "mcp.read"
end

pipeline :mcp_write do
  plug AshAuthentication.Phoenix.Oauth2Server.BearerPlug,
    oauth2_server: MyApp.Oauth2Server
  plug MyAppWeb.RequireScope, "mcp.write"
end
```

Good when scope-to-route mapping is fixed.

## Pattern 2: Scopes in Ash policies

When you want scopes to flow into resource-level authorization (so
they apply uniformly across HTTP, internal calls, GraphQL, etc.),
copy the scope list into the Ash context after `BearerPlug` runs.

A small plug:

```elixir
defmodule MyAppWeb.PutOAuthContext do
  @behaviour Plug

  @impl true
  def init(opts), do: opts

  @impl true
  def call(conn, _opts) do
    case conn.assigns[:oauth_claims] do
      nil ->
        conn

      claims ->
        Ash.PlugHelpers.update_context(conn, fn ctx ->
          Map.merge(ctx || %{}, %{
            oauth_scopes: String.split(claims["scope"] || "", " ", trim: true),
            oauth_client_id: claims["client_id"]
          })
        end)
    end
  end
end
```

Wired into the same pipeline:

```elixir
pipeline :mcp do
  plug AshAuthentication.Phoenix.Oauth2Server.BearerPlug,
    oauth2_server: MyApp.Oauth2Server
  plug MyAppWeb.PutOAuthContext
end
```

Then read it in a policy:

```elixir
defmodule MyApp.Mcp.Resource do
  use Ash.Resource, authorizers: [Ash.Policy.Authorizer]

  policies do
    policy action_type(:read) do
      authorize_if expr(^context(:oauth_scopes) |> contains("mcp.read"))
    end

    policy action_type([:create, :update]) do
      authorize_if expr(^context(:oauth_scopes) |> contains("mcp.write"))
    end
  end
end
```

This style is the most ergonomic for apps that already lean on Ash
policies — the scope becomes just another input to the policy check
alongside the actor.

## Pattern 3: Direct inspection in a controller

When the scope check is one-off or non-trivial, just read the assign:

```elixir
def show(conn, %{"id" => id}) do
  scopes =
    conn.assigns.oauth_claims["scope"] |> String.split(" ", trim: true)

  cond do
    "mcp.admin" in scopes ->
      # full visibility
      render(conn, "show.json", thing: MyApp.Things.get_with_internals!(id))

    "mcp.read" in scopes ->
      # public-only fields
      render(conn, "show.json", thing: MyApp.Things.get_public!(id))

    true ->
      send_resp(conn, 403, "")
  end
end
```

## A note on enforcement

The scope catalogue your server advertises (in the `:scopes` option on
your `Oauth2Server` module) is enforced at `/authorize`: when
`:enforce_scopes?` is `true` (the default), a client requesting a
scope outside that catalogue is rejected before the user ever sees
the consent screen. So by the time a token reaches `BearerPlug`, its
scope claim is already known to be drawn from the configured set —
the resource server only has to compare against scope names it
already knows.
