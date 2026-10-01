# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Phoenix.Oauth2Server.BearerPlug do
  @moduledoc """
  Resource-server side bearer token validation.

  Validates an `Authorization: Bearer <jwt>` header against the configured
  authorization server. On success, loads the user via `Ash.get/3` on the
  configured `user_resource` and sets it as the conn's actor.

  ## Usage

      pipeline :mcp_protected do
        plug AshAuthentication.Phoenix.Oauth2Server.BearerPlug,
          oauth2_server: MyApp.Oauth2Server
      end

  ## Options

    * `:oauth2_server` (required) — your `Oauth2Server` config module
    * `:required?` (default `true`) — when `false`, missing/invalid tokens
      pass through unchanged instead of returning 401. Useful for routes
      that should serve unauthenticated users with a different (e.g.
      session-based) signal.
    * `:scope` — a scope string (or list of scope strings) advertised in
      the 401 challenge as `scope="…"`. The MCP spec recommends this so
      clients know which scopes to request during initial authorization
      instead of asking for everything in `scopes_supported`. This is
      advisory — it does not enforce anything; pair with
      `AshAuthentication.Phoenix.Oauth2Server.RequireScopePlug` for
      enforcement.

  ## Failure behavior

  Per RFC 6750 §3, a missing or invalid token results in `401` with a
  `WWW-Authenticate: Bearer resource_metadata="..."` header pointing at
  the protected-resource metadata endpoint (plus `scope="…"` when the
  `:scope` option is set), so MCP-style clients can auto-discover the
  authorization server and the scopes they should request.

  ## What ends up on the conn

  On success two things are set, and downstream code reads from each
  for different purposes:

    * **`Ash.PlugHelpers.get_actor(conn)`** — the user record loaded
      via `Ash.get/3` on the configured `user_resource` using the
      token's `sub` claim. Use this for "who is this" (Ash policies,
      tenant resolution, ownership checks).
    * **`conn.assigns.oauth_claims`** — the verified JWT claims map.
      Use this for "what is this bearer allowed to do" — most
      importantly the scope claim:

          scopes =
            conn.assigns.oauth_claims["scope"]
            |> String.split(" ", trim: true)

      Other useful claims: `client_id` (which OAuth client minted
      this), `aud` (which resource), `jti` (unique token id).

  Note that scopes are **conn-scoped, not actor-scoped**. The same
  user with two access tokens minted for two different clients ends
  up with the same actor but different `oauth_claims["scope"]`. This
  is the right OAuth semantic — the access token is a delegated grant
  from user → client, distinct from the user's own permissions.

  ## Person tokens only

  Machine (`client_credentials`) tokens carry a reserved
  `"gty" => "client_credentials"` claim; person-delegated tokens never
  carry `gty`. This plug rejects any token with a `gty` claim, so a
  machine token cannot authenticate as a user even if a client id and a
  user id collide. As defense in depth it also rejects tokens where
  `sub == client_id` (the machine-token shape). Use `ClientBearerPlug`
  for machine routes.

  ### Gating an action on a scope

  Use `AshAuthentication.Phoenix.Oauth2Server.RequireScopePlug` after
  this plug — it 403s with the RFC 6750 `insufficient_scope` challenge
  shape that step-up-capable clients understand:

      pipeline :mcp_read do
        plug AshAuthentication.Phoenix.Oauth2Server.BearerPlug,
          oauth2_server: MyApp.Oauth2Server,
          scope: "mcp.read"

        plug AshAuthentication.Phoenix.Oauth2Server.RequireScopePlug,
          oauth2_server: MyApp.Oauth2Server,
          scope: "mcp.read"
      end

  ### Reading scopes inside an Ash policy

  If you'd rather gate at the resource layer, copy `oauth_claims` into
  the actor's metadata or the action context before invoking the
  action. For example, a tiny plug between `BearerPlug` and your
  controller:

      plug fn conn, _ ->
        Ash.PlugHelpers.update_context(conn, fn ctx ->
          Map.put(ctx || %{}, :oauth_scopes,
            conn.assigns.oauth_claims["scope"]
            |> String.split(" ", trim: true))
        end)
      end

  then in your resource:

      policies do
        policy action(:read) do
          authorize_if expr(^context(:oauth_scopes) |> contains("mcp.read"))
        end
      end
  """

  @behaviour Plug

  alias AshAuthentication.Oauth2Server.Jwt
  alias AshAuthentication.Phoenix.Oauth2Server.Bearer

  @impl Plug
  def init(opts), do: Bearer.init_opts(opts)

  @impl Plug
  def call(conn, opts), do: Bearer.call(conn, opts, &verify_and_load/2)

  defp verify_and_load(server, token) do
    with {:ok, claims} <- Jwt.verify(server, token),
         :ok <- ensure_person_token(claims),
         {:ok, user} <- load_user(server, claims) do
      {:ok, user, claims}
    end
  end

  # Person tokens never carry `gty` (only machine tokens do), and never
  # have sub == client_id (the machine-token shape).
  defp ensure_person_token(%{"sub" => sub, "client_id" => client_id} = claims)
       when is_binary(sub) and sub != "" and is_binary(client_id) and client_id != "" and
              sub != client_id and not is_map_key(claims, "gty") do
    :ok
  end

  defp ensure_person_token(_), do: {:error, :not_person_token}

  defp load_user(server, %{"sub" => sub} = claims) when is_binary(sub) and sub != "" do
    opts =
      [context: %{private: %{ash_authentication?: true}}]
      |> Bearer.maybe_put_tenant_opt(claims)

    case Ash.get(server.user_resource(), sub, opts) do
      {:ok, user} -> {:ok, user}
      _ -> {:error, :user_not_found}
    end
  end

  defp load_user(_, _), do: {:error, :missing_subject}
end
