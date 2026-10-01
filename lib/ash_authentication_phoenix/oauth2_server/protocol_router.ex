# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Phoenix.Oauth2Server.ProtocolRouter do
  @moduledoc """
  Plug router for the client-facing OAuth 2.1 protocol endpoints — anything
  called by an external OAuth client without a browser session.

  Endpoints handled:

    * `GET /oauth-authorization-server` — RFC 8414 metadata
    * `GET /oauth-protected-resource`   — RFC 9728 metadata
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
  alias AshAuthentication.Phoenix.Oauth2Server.{Bearer, Errors}

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
    ["openid-configuration"],
    ["oauth-protected-resource"]
  ]

  # This router is forwarded at both `/oauth` (full route table) and
  # `/.well-known` (`well_known?: true`). Because Phoenix strips the matched
  # prefix before dispatch, both mounts otherwise see the same route table — so
  # under `/.well-known` we serve only the metadata GETs and 404 everything else
  # (notably the state-changing /register, /token, /revoke).
  defp restrict_well_known_mount(conn, _opts) do
    well_known? = Keyword.get(conn.assigns.oauth2_server_router_opts, :well_known?, false)

    if well_known? and not (conn.method == "GET" and conn.path_info in @well_known_paths) do
      conn |> send_resp(404, "") |> halt()
    else
      conn
    end
  end

  # ── metadata ───────────────────────────────────────────────────────────────

  get("/oauth-authorization-server", do: serve_authorization_server_metadata(conn))
  get("/openid-configuration", do: serve_authorization_server_metadata(conn))

  # sobelow_skip ["XSS.SendResp"]
  get "/oauth-protected-resource" do
    server = server!(conn.assigns.oauth2_server_router_opts)

    conn
    |> put_resp_header("content-type", "application/json")
    |> put_resp_header("cache-control", metadata_cache_control(conn))
    |> send_resp(200, Jason.encode!(Metadata.protected_resource(server, secret_context(conn))))
    |> halt()
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
    # RFC 6749 §4.4.2 / OAuth 2.1 §3.2.2 — token requests use
    # application/x-www-form-urlencoded (JSON is not a defined encoding).
    if form_urlencoded?(conn) do
      handle_token(conn)
    else
      Errors.send_oauth_error(
        conn,
        400,
        "invalid_request",
        "token requests must use application/x-www-form-urlencoded"
      )
    end
  end

  # Client credentials MUST NOT appear in the request URI (RFC 6749 §2.3.1 /
  # RFC 6819 transmission disclosure). Reject them in the query even when a
  # body is also present.
  @token_credential_query_params ~w(
    client_id client_secret client_assertion client_assertion_type
  )

  defp handle_token(conn) do
    conn = fetch_query_params(conn)

    result =
      with :ok <- reject_credentials_in_query(conn) do
        server = server!(conn.assigns.oauth2_server_router_opts)
        # Body only — Plug.Parsers merges query into `conn.params`, which would
        # otherwise let URI credentials masquerade as form fields.
        params = token_body_params(conn)
        opts = tenant_opts(conn)
        exchange_token(server, conn, params, opts)
      end

    case result do
      {:ok, response} ->
        conn
        |> put_resp_header("content-type", "application/json; charset=UTF-8")
        # RFC 6749 §5.1 — MUST send Cache-Control: no-store and Pragma: no-cache.
        |> put_resp_header("cache-control", "no-store")
        |> put_resp_header("pragma", "no-cache")
        |> send_resp(200, Jason.encode!(token_response_json(response)))
        |> halt()

      {:error, :unsupported_grant_type} ->
        Errors.send_oauth_error(conn, 400, "unsupported_grant_type", nil)

      {:error, :invalid_client} ->
        # RFC 6749 §5.2 — when the client used Authorization, MUST be 401
        # with WWW-Authenticate matching that scheme.
        conn
        |> maybe_invalid_client_authenticate_header()
        |> then(fn c ->
          {status, code, desc} = Errors.describe_token_error(:invalid_client)
          Errors.send_oauth_error(c, status, code, desc)
        end)

      {:error, reason} ->
        {status, code, desc} = Errors.describe_token_error(reason)
        Errors.send_oauth_error(conn, status, code, desc)
    end
  end

  defp exchange_token(server, conn, params, opts) do
    case Map.get(params, "grant_type") do
      "authorization_code" ->
        with {:ok, params} <- merge_client_auth(conn, params) do
          Token.exchange_authorization_code(server, params, opts)
        end

      "refresh_token" ->
        with {:ok, params} <- merge_client_auth(conn, params) do
          Token.exchange_refresh_token(server, params, opts)
        end

      "client_credentials" ->
        if server.client_credentials_enabled?() do
          case ClientAuth.credentials(conn, params) do
            {:ok, client_id, client_secret, _via} ->
              # `_via` is discarded: confidential clients may use Basic or
              # body interchangeably (see Token.exchange_client_credentials/3).
              Token.exchange_client_credentials(
                server,
                Map.merge(params, %{
                  "client_id" => client_id,
                  "client_secret" => client_secret
                }),
                opts
              )

            {:error, reason} ->
              {:error, reason}
          end
        else
          {:error, :unsupported_grant_type}
        end

      grant when is_binary(grant) ->
        {:error, :unsupported_grant_type}

      grant when is_list(grant) ->
        # Repeated grant_type parameter (RFC 6749 §5.2 invalid_request).
        {:error, :invalid_request}

      _ ->
        {:error, :unsupported_grant_type}
    end
  end

  # Public clients send only a body `client_id`; confidential clients also
  # present a secret via Basic or the body. Normalize either presentation
  # into `client_id` + `client_secret` params so `Token` can authenticate
  # confidential clients (RFC 6749 §4.1.3 / §6).
  defp merge_client_auth(conn, params) do
    case ClientAuth.optional_credentials(conn, params) do
      :none ->
        {:ok, params}

      {:ok, client_id, client_secret, _via} ->
        {:ok, Map.merge(params, %{"client_id" => client_id, "client_secret" => client_secret})}

      {:error, _} = error ->
        error
    end
  end

  defp reject_credentials_in_query(conn) do
    qp = conn.query_params || %{}

    if Enum.any?(@token_credential_query_params, &Map.has_key?(qp, &1)) do
      {:error, :invalid_request}
    else
      :ok
    end
  end

  defp token_body_params(%{body_params: body}) when is_map(body), do: body
  defp token_body_params(conn), do: conn.params || %{}

  defp form_urlencoded?(conn) do
    case Plug.Conn.get_req_header(conn, "content-type") do
      [value | _] ->
        value
        |> String.downcase()
        |> String.starts_with?("application/x-www-form-urlencoded")

      _ ->
        false
    end
  end

  # ── revocation (RFC 7009) ──────────────────────────────────────────────────

  # Always 200, regardless of whether the token existed or matched the client
  # — RFC 7009 §2.2 requires the endpoint not to leak token state.
  post "/revoke" do
    server = server!(conn.assigns.oauth2_server_router_opts)
    :ok = Token.revoke(server, conn.params || %{}, tenant_opts(conn))

    conn
    |> put_resp_header("cache-control", "no-store")
    |> send_resp(200, "")
    |> halt()
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

  # Pull the bearer token out of `Authorization: Bearer <token>` if
  # present. Used by `/register` to forward an RFC 7591 initial access
  # token into the protocol core.
  defp extract_bearer(conn) do
    case Bearer.extract_token(conn) do
      {:ok, token} -> token
      :no_token -> nil
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

  defp maybe_invalid_client_authenticate_header(conn) do
    case get_req_header(conn, "authorization") do
      [value | _] when is_binary(value) and value != "" ->
        put_resp_header(conn, "www-authenticate", ~s|Basic realm="oauth"|)

      _ ->
        conn
    end
  end
end
