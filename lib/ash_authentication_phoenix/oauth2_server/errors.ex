# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Phoenix.Oauth2Server.Errors do
  @moduledoc """
  HTTP error response helpers for OAuth 2.1 / RFC 7591.
  """

  import Plug.Conn

  @doc """
  Send a JSON error per OAuth 2.0 / RFC 6749 §5.2.

  Codes: `"invalid_request"`, `"invalid_client"`, `"invalid_grant"`,
  `"unsupported_grant_type"`, `"invalid_scope"`, etc.
  """
  # sobelow_skip ["XSS.SendResp"]
  @spec send_oauth_error(Plug.Conn.t(), pos_integer(), String.t(), String.t() | nil) ::
          Plug.Conn.t()
  def send_oauth_error(conn, status, code, description \\ nil) do
    body = %{"error" => code} |> maybe_put("error_description", description)

    conn
    |> put_resp_header("content-type", "application/json")
    |> put_resp_header("cache-control", "no-store")
    |> send_resp(status, Jason.encode!(body))
    |> halt()
  end

  @doc """
  Send a 400 with an RFC 7591 DCR-shaped error.

  Codes: `"invalid_redirect_uri"`, `"invalid_client_metadata"`.
  """
  def send_dcr_error(conn, code, description \\ nil) do
    send_oauth_error(conn, 400, code, description)
  end

  @doc """
  Send a Bearer-auth error per RFC 6750 §3 — JSON body + a
  `WWW-Authenticate: Bearer error="…", error_description="…"` header.

  Used for failures of Bearer-authenticated endpoints (e.g. RFC 7591
  initial-access-token failures on `/oauth/register`).
  """
  # sobelow_skip ["XSS.SendResp"]
  @spec send_bearer_error(Plug.Conn.t(), pos_integer(), String.t(), String.t() | nil) ::
          Plug.Conn.t()
  def send_bearer_error(conn, status, code, description \\ nil) do
    challenge = bearer_challenge([{"error", code}, {"error_description", description}])
    body = %{"error" => code} |> maybe_put("error_description", description)

    conn
    |> put_resp_header("content-type", "application/json")
    |> put_resp_header("cache-control", "no-store")
    |> put_resp_header("www-authenticate", challenge)
    |> send_resp(status, Jason.encode!(body))
    |> halt()
  end

  @doc false
  # Build a `WWW-Authenticate: Bearer …` header value from ordered
  # `{key, value}` auth-params. `nil` values are dropped and every value is
  # escaped as an RFC 7235 quoted-string, so a value derived from request data
  # (e.g. a tenant-bearing `resource_metadata` URL) can't break out of its
  # quotes and inject additional auth-params.
  @spec bearer_challenge([{String.t(), String.t() | nil}]) :: String.t()
  def bearer_challenge(params) do
    challenge =
      params
      |> Enum.reject(fn {_, v} -> is_nil(v) end)
      |> Enum.map_join(", ", fn {k, v} -> ~s|#{k}="#{escape_quoted(v)}"| end)

    String.trim_trailing("Bearer " <> challenge)
  end

  # WWW-Authenticate quoted-string values: backslash-escape `"` and `\`.
  defp escape_quoted(value) do
    value
    |> String.replace("\\", "\\\\")
    |> String.replace("\"", "\\\"")
  end

  @doc """
  Send an RFC 6750 §3.1 `insufficient_scope` challenge — a 403 with a
  `WWW-Authenticate` header carrying the scopes the current operation
  needs and a pointer at the protected-resource metadata document, so
  MCP-style clients can drive a step-up authorization flow.

  `required_scopes` should be **all** scopes the operation needs, in one
  challenge — challenging incrementally forces the client through one
  authorization round-trip per scope.

  Options:

    * `:description` — human-readable `error_description`
    * `:tenant` — forwarded to the server's `resource_url/2` resolution
    * `:resource` — the name of the protected resource. Defaults to the only
      configured resource.
  """
  # sobelow_skip ["XSS.SendResp"]
  @spec send_insufficient_scope(Plug.Conn.t(), module(), [String.t()] | String.t(), keyword()) ::
          Plug.Conn.t()
  def send_insufficient_scope(conn, server, required_scopes, opts \\ []) do
    scope = required_scopes |> List.wrap() |> Enum.join(" ")
    description = Keyword.get(opts, :description)

    challenge =
      bearer_challenge([
        {"error", "insufficient_scope"},
        {"scope", scope},
        {"resource_metadata",
         resource_metadata_url(server, Keyword.get(opts, :tenant), Keyword.get(opts, :resource))},
        {"error_description", description}
      ])

    body =
      %{"error" => "insufficient_scope", "scope" => scope}
      |> maybe_put("error_description", description)

    conn
    |> put_resp_header("content-type", "application/json")
    |> put_resp_header("cache-control", "no-store")
    |> put_resp_header("www-authenticate", challenge)
    |> send_resp(403, Jason.encode!(body))
    |> halt()
  end

  @doc """
  The URL of the protected-resource metadata document (RFC 9728) for a
  protected resource — the value of the `resource_metadata` parameter in
  `WWW-Authenticate` challenges. Per RFC 9728 §3.1 the well-known suffix goes
  between the host and the path of the resource identifier, so
  `https://host/mcp` maps to `https://host/.well-known/oauth-protected-resource/mcp`.

  `resource` is the name of a configured resource, and defaults to the only
  configured resource.
  """
  @spec resource_metadata_url(module(), any(), atom() | nil) :: String.t()
  def resource_metadata_url(server, tenant \\ nil, resource \\ nil) do
    context = if tenant, do: %{tenant: tenant}, else: %{}
    uri = URI.parse(server.resource_url(resource, context))

    %{uri | path: "/.well-known/oauth-protected-resource" <> resource_path(uri), fragment: nil}
    |> URI.to_string()
  end

  defp resource_path(%URI{path: path}) when path in [nil, "/"], do: ""
  defp resource_path(%URI{path: path}), do: path

  @doc """
  Translate a `:reason` atom returned from a core module into an
  `{http_status, error_code, description}` triple suitable for an OAuth
  error response.

  A reason that is not listed here is a server fault, not a malformed
  request, so it maps to `500`.
  """
  @spec describe_token_error(atom()) :: {pos_integer(), String.t(), String.t()}
  def describe_token_error(reason) do
    case reason do
      :reuse -> {400, "invalid_grant", "code or refresh token already used"}
      :expired -> {400, "invalid_grant", "expired"}
      :pkce -> {400, "invalid_grant", "PKCE verification failed"}
      :resource_mismatch -> {400, "invalid_grant", "grant resource is not configured"}
      :invalid_target -> {400, "invalid_target", "requested resource is not acceptable"}
      :redirect_mismatch -> {400, "invalid_grant", "redirect_uri mismatch"}
      :invalid_code -> {400, "invalid_grant", "code not found or invalid"}
      :invalid_refresh -> {400, "invalid_grant", "refresh token invalid"}
      :revoked -> {400, "invalid_grant", "refresh token revoked"}
      :client_mismatch -> {400, "invalid_grant", "client mismatch"}
      :invalid_client -> {400, "invalid_client", "unknown client"}
      :unsupported_client_authentication -> {400, "invalid_client", "public client"}
      :unauthorized_client -> {400, "unauthorized_client", "grant type not registered"}
      :invalid_scope -> {400, "invalid_scope", "requested scope exceeds the grant"}
      :invalid_request -> {400, "invalid_request", "missing required parameters"}
      :refresh_create_failed -> {500, "server_error", "could not issue refresh token"}
      _ -> {500, "server_error", "request could not be processed"}
    end
  end

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)
end
