# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Phoenix.Oauth2Server.ProtocolRouter do
  @moduledoc """
  Plug router for the client-facing OAuth 2.1 protocol endpoints — anything
  called by an external OAuth client without a browser session.

  Endpoints handled:

    * `GET /oauth-authorization-server` — RFC 8414 metadata
    * `GET /oauth-protected-resource[/<path>]` — RFC 9728 metadata, one
      document for each configured resource
    * `GET /openid-configuration`       — alias for OIDC-conformant tooling
    * `POST /register`                  — RFC 7591 Dynamic Client Registration
    * `POST /token`                     — authorization_code, refresh_token,
                                         and client_credentials grants
    * `POST /revoke`                    — RFC 7009 token revocation

  Mount this behind your API pipeline (no CSRF, no session needed). For the
  human-driven consent step (`/authorize`), see
  `AshAuthentication.Phoenix.Oauth2Server.ConsentRouter`.

  ## Options

    * `:oauth2_server` (required) — the user's `Oauth2Server` config module
  """

  use Plug.Router, copy_opts_to_assign: :oauth2_server_router_opts

  alias AshAuthentication.Oauth2Server.{ClientAuth, Metadata, Register, Token}
  alias AshAuthentication.Phoenix.Oauth2Server.{BearerPlug, Errors}

  plug Plug.Parsers,
    parsers: [:urlencoded, :json],
    pass: ["*/*"],
    json_decoder: Jason

  plug :match
  plug :restrict_well_known_mount
  plug :dispatch

  # The metadata discovery documents — the only routes allowed to answer under
  # the `/.well-known` mount (see the `well_known?` forward in the Router).
  @well_known_paths [
    ["oauth-authorization-server"],
    ["openid-configuration"]
  ]

  # This router is forwarded at both `/oauth` (full route table) and
  # `/.well-known` (`well_known?: true`). Because Phoenix strips the matched
  # prefix before dispatch, both mounts otherwise see the same route table — so
  # under `/.well-known` we serve only the metadata GETs and 404 everything else
  # (notably the state-changing /register, /token, /revoke).
  defp restrict_well_known_mount(conn, _opts) do
    well_known? = Keyword.get(conn.assigns.oauth2_server_router_opts, :well_known?, false)

    if well_known? and not (conn.method == "GET" and well_known_path?(conn.path_info)) do
      conn |> send_resp(404, "") |> halt()
    else
      conn
    end
  end

  defp well_known_path?(["oauth-protected-resource" | _]), do: true
  defp well_known_path?(path_info), do: path_info in @well_known_paths

  # ── metadata ───────────────────────────────────────────────────────────────

  get("/oauth-authorization-server", do: serve_authorization_server_metadata(conn))
  get("/openid-configuration", do: serve_authorization_server_metadata(conn))

  # RFC 9728 §3.1 puts the document for `https://host/mcp` at
  # `/.well-known/oauth-protected-resource/mcp`.
  # sobelow_skip ["XSS.SendResp"]
  get "/oauth-protected-resource/*resource_path" do
    server = server!(conn.assigns.oauth2_server_router_opts)
    context = secret_context(conn)

    case resource_for_path(server, context, conn, resource_path) do
      {:ok, resource} ->
        conn
        |> put_resp_header("content-type", "application/json")
        |> put_resp_header("cache-control", metadata_cache_control(conn))
        |> send_resp(200, Jason.encode!(Metadata.protected_resource(server, context, resource)))
        |> halt()

      :error ->
        conn |> send_resp(404, "") |> halt()
    end
  end

  # A server with one resource also answers at the host root, whatever the
  # resource path. MCP clients fall back to the root when the path-suffixed
  # URL fails.
  defp resource_for_path(server, context, conn, resource_path) do
    case {server.resources(), resource_path} do
      {[resource], []} ->
        {:ok, resource}

      {resources, _} ->
        Enum.find_value(resources, :error, fn resource ->
          %URI{path: path, query: query} = URI.parse(server.resource_url(resource, context))

          if String.split(path || "", "/", trim: true) == resource_path and
               conn.query_string == (query || ""),
             do: {:ok, resource}
        end)
    end
  end

  # ── DCR ────────────────────────────────────────────────────────────────────

  post "/register" do
    server = server!(conn.assigns.oauth2_server_router_opts)
    opts = [initial_access_token: extract_bearer(conn)] ++ tenant_opts(conn)

    case Register.register(server, conn.params, opts) do
      {:ok, _client, body} ->
        conn
        |> put_resp_header("content-type", "application/json")
        |> put_resp_header("cache-control", "no-store")
        |> send_resp(201, Jason.encode!(body))
        |> halt()

      {:error, :dcr_disabled} ->
        # DCR is off on this server. Treat the route as not present —
        # consistent with the metadata document not advertising it.
        conn |> send_resp(404, "") |> halt()

      {:error, :missing_initial_access_token} ->
        # RFC 6750 §3.1 — a request without authentication gets a challenge
        # without an error code.
        conn
        |> put_resp_header("cache-control", "no-store")
        |> put_resp_header("www-authenticate", Errors.bearer_challenge([]))
        |> send_resp(401, "")
        |> halt()

      {:error, :invalid_initial_access_token} ->
        # RFC 7591 §3.2.2 — Bearer-auth failure, not a metadata error.
        Errors.send_bearer_error(
          conn,
          401,
          "invalid_token",
          "registration requires a valid initial access token"
        )

      {:error, code, desc} ->
        Errors.send_dcr_error(conn, code, desc)
    end
  end

  # ── token ──────────────────────────────────────────────────────────────────

  post "/token" do
    conn = fetch_query_params(conn)
    server = server!(conn.assigns.oauth2_server_router_opts)
    params = conn.params || %{}
    opts = client_request_opts(conn)

    result =
      with :ok <- reject_credentials_in_query(conn) do
        case Map.get(params, "grant_type") do
          "authorization_code" -> Token.exchange_authorization_code(server, params, opts)
          "refresh_token" -> Token.exchange_refresh_token(server, params, opts)
          "client_credentials" -> client_credentials(server, conn, params, opts)
          type when type in [nil, ""] -> {:error, :invalid_request}
          _ -> {:error, :unsupported_grant_type}
        end
      end

    case result do
      {:ok, response} ->
        conn
        |> put_resp_header("content-type", "application/json")
        # RFC 6749 §5.1 — MUST send Cache-Control: no-store and Pragma: no-cache.
        |> put_resp_header("cache-control", "no-store")
        |> put_resp_header("pragma", "no-cache")
        |> send_resp(200, Jason.encode!(token_response_json(response)))
        |> halt()

      {:error, :unsupported_grant_type} ->
        Errors.send_oauth_error(conn, 400, "unsupported_grant_type", nil)

      {:error, reason} ->
        send_token_error(conn, server, reason)
    end
  end

  # RFC 6749 §2.3.1: client credentials MUST NOT be sent in the request URI.
  # Reject them in the query even when a body is also present.
  @token_credential_query_params ~w(
    client_id client_secret client_assertion client_assertion_type
  )

  defp reject_credentials_in_query(conn) do
    qp = conn.query_params || %{}

    if Enum.any?(@token_credential_query_params, &Map.has_key?(qp, &1)),
      do: {:error, :invalid_request},
      else: :ok
  end

  # Disabled when the server has no `verify_client_secret` configured. The
  # credentials come from HTTP Basic or the body; confidential clients may use
  # either (see `Token.exchange_client_credentials/3`).
  defp client_credentials(server, conn, params, opts) do
    if server.client_credentials_enabled?() do
      with {:ok, client_id, client_secret, _via} <- ClientAuth.credentials(conn, params) do
        params = Map.merge(params, %{"client_id" => client_id, "client_secret" => client_secret})
        Token.exchange_client_credentials(server, params, opts)
      end
    else
      {:error, :unsupported_grant_type}
    end
  end

  # ── revocation (RFC 7009) ──────────────────────────────────────────────────

  # RFC 7009 §2.2: an invalid token is a 200, like a revoked one. Only a bad
  # request, a token of another client, or a token type the server cannot
  # revoke is an error.
  post "/revoke" do
    server = server!(conn.assigns.oauth2_server_router_opts)

    case Token.revoke(server, conn.params || %{}, client_request_opts(conn)) do
      :ok ->
        conn
        |> put_resp_header("cache-control", "no-store")
        |> send_resp(200, "")
        |> halt()

      {:error, :unsupported_token_type} ->
        Errors.send_oauth_error(
          conn,
          400,
          "unsupported_token_type",
          "access tokens cannot be revoked"
        )

      # RFC 7009 §2.2.1: on a 503 the client must assume that the token
      # still exists, and may retry.
      {:error, :server_error} ->
        conn |> put_resp_header("cache-control", "no-store") |> send_resp(503, "") |> halt()

      {:error, reason} ->
        send_token_error(conn, server, reason)
    end
  end

  # ── default ────────────────────────────────────────────────────────────────

  match _ do
    conn |> send_resp(404, "") |> halt()
  end

  # ── helpers ───────────────────────────────────────────────────────────────

  defp server!(opts), do: Keyword.fetch!(opts, :oauth2_server)

  # Read the Ash tenant set upstream (browser plug, header parser, etc.)
  # and forward it to the protocol-core functions. Returns `[]` for
  # single-tenant deployments so the caller can splice without an `if`.
  defp tenant_opts(conn) do
    case Ash.PlugHelpers.get_tenant(conn) do
      nil -> []
      tenant -> [tenant: tenant]
    end
  end

  defp client_request_opts(conn) do
    [authorization_scheme: authorization_scheme(conn)] ++ tenant_opts(conn)
  end

  defp authorization_scheme(conn) do
    case Plug.Conn.get_req_header(conn, "authorization") do
      [header | _] -> header |> String.split(" ", parts: 2) |> hd() |> String.downcase()
      [] -> nil
    end
  end

  # OAuth 2.1 §3.2.4: when a client attempted authentication with the
  # Authorization header, `invalid_client` MUST be a 401 with a challenge
  # for the scheme the client used. RFC 7617 §2 requires `realm` in a Basic
  # challenge.
  defp send_token_error(conn, server, reason) do
    case {Errors.describe_token_error(reason), authorization_scheme(conn)} do
      {{_status, "invalid_client" = code, desc}, "basic"} ->
        realm = server.issuer_url(secret_context(conn))

        conn
        |> put_resp_header("www-authenticate", ~s|Basic realm="#{realm}"|)
        |> Errors.send_oauth_error(401, code, desc)

      {{status, code, desc}, _scheme} ->
        Errors.send_oauth_error(conn, status, code, desc)
    end
  end

  # Pull the bearer token out of `Authorization: Bearer <token>` if
  # present. Used by `/register` to forward an RFC 7591 initial access
  # token into the protocol core.
  defp extract_bearer(conn) do
    case BearerPlug.__parse_bearer__(conn) do
      {:ok, token} -> token
      _ -> nil
    end
  end

  # sobelow_skip ["XSS.SendResp"]
  defp serve_authorization_server_metadata(conn) do
    server = server!(conn.assigns.oauth2_server_router_opts)

    conn
    |> put_resp_header("content-type", "application/json")
    |> put_resp_header("cache-control", metadata_cache_control(conn))
    |> send_resp(
      200,
      Jason.encode!(Metadata.authorization_server(server, secret_context(conn)))
    )
    |> halt()
  end

  defp secret_context(conn) do
    case Ash.PlugHelpers.get_tenant(conn) do
      nil -> %{}
      tenant -> %{tenant: tenant}
    end
  end

  # Metadata (issuer, token_endpoint, jwks_uri, …) is tenant-specific when a
  # tenant is set on the conn. The tenant is often derived from outside the URL
  # (a request header or the host), so a shared cache keyed on the URL alone
  # would hand one tenant's endpoints to another. We can't emit a correct `Vary`
  # (the selector is app-specific), so tenant-specific responses are marked
  # `private` — never stored by shared caches. Tenant-independent responses stay
  # publicly cacheable.
  defp metadata_cache_control(conn) do
    case Ash.PlugHelpers.get_tenant(conn) do
      nil -> "public, max-age=3600"
      _ -> "private, max-age=3600"
    end
  end

  defp token_response_json(%{} = response) do
    base = %{
      "access_token" => response.access_token,
      "token_type" => response.token_type,
      "expires_in" => response.expires_in,
      "scope" => response.scope
    }

    case Map.get(response, :refresh_token) do
      nil -> base
      token -> Map.put(base, "refresh_token", token)
    end
  end
end
