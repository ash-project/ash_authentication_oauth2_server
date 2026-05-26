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

  ## Failure behavior

  Per RFC 6750 §3, a missing or invalid token results in `401` with a
  `WWW-Authenticate: Bearer resource_metadata="..."` header pointing at
  the protected-resource metadata endpoint, so MCP-style clients can
  auto-discover the authorization server.

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

  ### Gating an action on a scope

  The minimum useful pattern is a plug that 403s when a required
  scope isn't present. Drop one of these into your pipeline after
  this plug, or write it inline in your controller:

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

      pipeline :mcp_read do
        plug AshAuthentication.Phoenix.Oauth2Server.BearerPlug,
          oauth2_server: MyApp.Oauth2Server
        plug MyAppWeb.RequireScope, "mcp.read"
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
  import Plug.Conn

  alias AshAuthentication.Oauth2Server.Jwt

  @impl Plug
  def init(opts) do
    %{
      server: Keyword.fetch!(opts, :oauth2_server),
      required?: Keyword.get(opts, :required?, true)
    }
  end

  @impl Plug
  def call(conn, %{server: server, required?: required?}) do
    case extract_token(conn) do
      :no_token when required? ->
        challenge(conn, server, nil)

      :no_token ->
        conn

      {:ok, token} ->
        case verify_and_load(server, token) do
          {:ok, user, claims} ->
            conn
            |> maybe_set_tenant(claims)
            |> Ash.PlugHelpers.set_actor(user)
            |> assign(:oauth_claims, claims)

          {:error, reason} when required? ->
            challenge(conn, server, reason)

          {:error, _} ->
            conn
        end
    end
  end

  # Restore the Ash tenant that the AS baked into the token at mint
  # time. Single-tenant deployments mint tokens without a "tenant"
  # claim — this is a no-op for them. The string form here is what
  # `Ash.ToTenant.to_tenant/2` produced at mint time.
  defp maybe_set_tenant(conn, %{"tenant" => tenant}) when is_binary(tenant) and tenant != "" do
    Ash.PlugHelpers.set_tenant(conn, tenant)
  end

  defp maybe_set_tenant(conn, _), do: conn

  defp extract_token(conn) do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> token | _] when token != "" -> {:ok, token}
      ["bearer " <> token | _] when token != "" -> {:ok, token}
      _ -> :no_token
    end
  end

  defp verify_and_load(server, token) do
    with {:ok, claims} <- Jwt.verify(server, token),
         {:ok, user} <- load_user(server, claims) do
      {:ok, user, claims}
    end
  end

  defp load_user(server, %{"sub" => sub} = claims) when is_binary(sub) and sub != "" do
    opts =
      [context: %{private: %{ash_authentication?: true}}]
      |> maybe_put_tenant_opt(claims)

    case Ash.get(server.user_resource(), sub, opts) do
      {:ok, user} -> {:ok, user}
      _ -> {:error, :user_not_found}
    end
  end

  defp load_user(_, _), do: {:error, :missing_subject}

  defp maybe_put_tenant_opt(opts, %{"tenant" => tenant}) when is_binary(tenant) and tenant != "",
    do: Keyword.put(opts, :tenant, tenant)

  defp maybe_put_tenant_opt(opts, _), do: opts

  defp challenge(conn, server, reason) do
    # PRM lives at the host root per RFC 9728, not under the resource's
    # path. Strip path/query from the resource URL so the metadata URL
    # points at <scheme>://<host>/.well-known/oauth-protected-resource.
    metadata_url =
      server.resource_url()
      |> URI.parse()
      |> Map.merge(%{path: "/.well-known/oauth-protected-resource", query: nil, fragment: nil})
      |> URI.to_string()

    error_param =
      case reason do
        nil -> ""
        :invalid_audience -> ~s|, error="invalid_token", error_description="audience mismatch"|
        :invalid_issuer -> ~s|, error="invalid_token", error_description="issuer mismatch"|
        :expired -> ~s|, error="invalid_token", error_description="token expired"|
        _ -> ~s|, error="invalid_token"|
      end

    conn
    |> put_resp_header(
      "www-authenticate",
      ~s|Bearer resource_metadata="#{metadata_url}"#{error_param}|
    )
    |> send_resp(401, "")
    |> halt()
  end
end
