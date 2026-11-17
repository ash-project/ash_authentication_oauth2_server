# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Phoenix.Oauth2Server.BearerPlug do
  @moduledoc """
  Resource-server side bearer token validation.

  Validates an `Authorization: Bearer <jwt>` header against the configured
  authorization server. On success, loads the token's subject and sets it
  as the conn's actor: the user for a token from the `authorization_code`
  or `refresh_token` grant, and the OAuth client for a token from the
  `client_credentials` grant.

  ## Usage

      pipeline :mcp_protected do
        plug AshAuthentication.Phoenix.Oauth2Server.BearerPlug,
          oauth2_server: MyApp.Oauth2Server
      end

  ## Options

    * `:oauth2_server` (required) — your `Oauth2Server` config module
    * `:resource` — the name of the protected resource that this plug
      guards. The plug accepts only tokens whose `aud` names this resource,
      and its challenges point at this resource's metadata. Required when the
      server configures more than one resource.
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

    * **`Ash.PlugHelpers.get_actor(conn)`** — the record loaded via
      `Ash.get/3` using the token's `sub` claim: a record of the
      configured `user_resource` for a user token, or of the configured
      `client_resource` for a client credentials token. Use this for "who
      is this" (Ash policies, tenant resolution, ownership checks).
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

  ## Client credentials tokens

  A token from the `client_credentials` grant represents the client
  itself (RFC 9068 §2.2: `sub` is the client identifier). The server marks
  such tokens with a `gty` claim of `"client_credentials"`, which user
  tokens never carry and `:extra_access_token_claims` cannot set. The plug
  loads the client record as the actor, so policies must be written for
  both kinds of actor when a route accepts both. Check the actor's struct,
  or the `gty` claim, to tell them apart.

  Client tokens are accepted only while the server lists
  `:client_credentials` in `:supported_grants`. On every request the plug
  also reloads the client and checks that it still has the grant, may
  still use the resource, and that the token's scopes are still inside
  the client's allow-list, so revoking a client's access takes effect
  before its tokens expire.

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
  import Plug.Conn

  alias AshAuthentication.Oauth2Server.{Jwt, Token}
  alias AshAuthentication.Phoenix.Oauth2Server.Errors

  @ash_context %{private: %{ash_authentication?: true}}

  @impl Plug
  def init(opts) do
    server = Keyword.fetch!(opts, :oauth2_server)
    resource = Keyword.get(opts, :resource)
    AshAuthentication.Oauth2Server.__check_resource_option__!(server, resource)

    %{
      server: server,
      resource: resource,
      required?: Keyword.get(opts, :required?, true),
      scope: opts |> Keyword.get(:scope) |> normalize_scope()
    }
  end

  defp normalize_scope(nil), do: nil
  defp normalize_scope(scope), do: scope |> List.wrap() |> Enum.join(" ")

  @impl Plug
  def call(conn, %{server: server, resource: resource, required?: required?, scope: scope}) do
    case extract_token(conn) do
      :no_token when required? ->
        challenge(conn, server, resource, nil, scope)

      :no_token ->
        conn

      :malformed when required? ->
        challenge(conn, server, resource, :malformed, scope)

      :malformed ->
        conn

      {:ok, token} ->
        case verify_and_load(server, resource, token) do
          {:ok, actor, claims} ->
            conn
            |> maybe_set_tenant(claims)
            |> Ash.PlugHelpers.set_actor(actor)
            |> assign(:oauth_claims, claims)

          {:error, reason} when required? ->
            challenge(conn, server, resource, reason, scope)

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

  defp extract_token(conn), do: __parse_bearer__(conn)

  @doc false
  # RFC 7235 §2.1: the auth-scheme is case-insensitive. RFC 6750 §2.1: one
  # or more spaces separate it from the token. A Bearer header without a
  # token is a malformed request (RFC 6750 §3.1). Another scheme is no
  # Bearer authentication at all.
  @spec __parse_bearer__(Plug.Conn.t()) :: {:ok, String.t()} | :no_token | :malformed
  def __parse_bearer__(conn) do
    with [header | _] <- get_req_header(conn, "authorization"),
         [scheme | rest] <- String.split(header, " ", parts: 2),
         "bearer" <- String.downcase(scheme) do
      case rest |> List.first("") |> String.trim_leading(" ") do
        "" -> :malformed
        token -> {:ok, token}
      end
    else
      _ -> :no_token
    end
  end

  defp verify_and_load(server, resource, token) do
    with {:ok, claims} <- Jwt.verify(server, token, resource: resource) do
      case claims do
        %{"gty" => "client_credentials"} -> load_client(server, resource, claims)
        %{"gty" => _} -> {:error, :invalid_token}
        _ -> load_user(server, claims)
      end
    end
  end

  defp load_user(server, %{"sub" => sub} = claims) when is_binary(sub) and sub != "" do
    case Ash.get(server.user_resource(), sub, ash_opts(claims)) do
      {:ok, user} -> {:ok, user, claims}
      _ -> {:error, :user_not_found}
    end
  end

  defp load_user(_, _), do: {:error, :missing_subject}

  # A client credentials token names the client in both `sub` and
  # `client_id` (RFC 9068 §2.2). The client is reloaded and re-checked so
  # that removing the grant, the resource, or scopes from the client row
  # takes effect before the token expires.
  defp load_client(server, resource, %{"sub" => sub, "client_id" => sub} = claims)
       when is_binary(sub) and sub != "" do
    with :ok <- check_grant_supported(server),
         {:ok, client} <- get_client(server, sub, claims),
         :ok <- check_still_eligible(client),
         :ok <- check_resource_still_allowed(server, resource, client),
         :ok <- check_scopes_still_allowed(server, resource, client, claims) do
      {:ok, client, claims}
    end
  end

  defp load_client(_, _, _), do: {:error, :invalid_token}

  defp check_grant_supported(server) do
    if server.grant_supported?(:client_credentials),
      do: :ok,
      else: {:error, :client_not_eligible}
  end

  defp get_client(server, client_id, claims) do
    case Ash.get(server.client_resource(), client_id, ash_opts(claims)) do
      {:ok, client} -> {:ok, client}
      _ -> {:error, :client_not_found}
    end
  end

  defp check_still_eligible(client) do
    if Token.client_credentials_allowed?(client),
      do: :ok,
      else: {:error, :client_not_eligible}
  end

  # Without `:resource` the plug guards the only configured resource.
  defp check_resource_still_allowed(server, resource, client) do
    name = resource || server.resources() |> List.first()

    if Token.client_resource_allowed?(client, name),
      do: :ok,
      else: {:error, :resource_not_allowed}
  end

  defp check_scopes_still_allowed(server, resource, client, %{"scope" => scope}) do
    if Token.machine_scopes_allowed?(server, resource, client, scope),
      do: :ok,
      else: {:error, :scopes_no_longer_allowed}
  end

  defp check_scopes_still_allowed(_, _, _, _), do: {:error, :scopes_no_longer_allowed}

  defp ash_opts(%{"tenant" => tenant}) when is_binary(tenant) and tenant != "",
    do: [context: @ash_context, tenant: tenant]

  defp ash_opts(_), do: [context: @ash_context]

  defp challenge(conn, server, resource, reason, scope) do
    status = if reason == :malformed, do: 400, else: 401

    metadata_url =
      Errors.resource_metadata_url(server, Ash.PlugHelpers.get_tenant(conn), resource)

    {error, error_description} = error_params(reason)

    challenge =
      Errors.bearer_challenge([
        {"resource_metadata", metadata_url},
        {"scope", scope},
        {"error", error},
        {"error_description", error_description}
      ])

    conn
    |> put_resp_header("www-authenticate", challenge)
    |> send_resp(status, "")
    |> halt()
  end

  defp error_params(reason) do
    case reason do
      nil -> {nil, nil}
      :malformed -> {"invalid_request", "Bearer credentials without a token"}
      :invalid_audience -> {"invalid_token", "audience mismatch"}
      :invalid_issuer -> {"invalid_token", "issuer mismatch"}
      :expired -> {"invalid_token", "token expired"}
      :client_not_found -> {"invalid_token", "client not found"}
      :client_not_eligible -> {"invalid_token", "client credentials no longer allowed"}
      :resource_not_allowed -> {"invalid_token", "client no longer allowed this resource"}
      :scopes_no_longer_allowed -> {"invalid_token", "token scopes no longer allowed"}
      _ -> {"invalid_token", nil}
    end
  end
end
