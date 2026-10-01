# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.Metadata do
  @moduledoc """
  Builders for the discovery metadata endpoints.

    * `protected_resource/1` (RFC 9728) — for the resource server, served at
      `/.well-known/oauth-protected-resource`.
    * `authorization_server/1` (RFC 8414) — for the authorization server,
      served at `/.well-known/oauth-authorization-server`.

  Both return plain maps; controllers JSON-encode them.
  """

  @doc """
  Build the OAuth Protected Resource Metadata document (RFC 9728).

  `context` is forwarded to the server's `resource_url/1` and `issuer_url/1`
  callbacks so per-request (e.g. per-tenant) resolution works. Single-tenant
  callers can pass `%{}`.
  """
  @spec protected_resource(server :: module(), context :: map()) :: map()
  def protected_resource(server, context \\ %{}) do
    %{
      "resource" => server.resource_url(context),
      "authorization_servers" => [server.issuer_url(context)],
      "scopes_supported" => server.scopes(),
      # RFC 6750 / RFC 9700 — only the Authorization header method; query
      # and form body bearer tokens are not accepted by the resource plugs.
      "bearer_methods_supported" => ["header"]
    }
  end

  @doc """
  Build the OAuth Authorization Server Metadata document (RFC 8414).

  Endpoint paths are derived from the `issuer_url` so that mounting under a
  custom prefix works without configuration. `context` is forwarded to
  `issuer_url/1` so per-tenant deployments can resolve the issuer from the
  current request.
  """
  @spec authorization_server(server :: module(), context :: map()) :: map()
  def authorization_server(server, context \\ %{}) do
    issuer = server.issuer_url(context)
    client_credentials? = server.client_credentials_enabled?()

    base = %{
      "issuer" => issuer,
      "authorization_endpoint" => issuer <> "/oauth/authorize",
      "token_endpoint" => issuer <> "/oauth/token",
      "revocation_endpoint" => issuer <> "/oauth/revoke",
      "response_types_supported" => ["code"],
      # Only advertise `client_credentials` when `:verify_client_secret` is
      # set (library default: `ClientSecret.verify/2`). Pass `nil` to disable.
      "grant_types_supported" => grant_types_supported(client_credentials?),
      "code_challenge_methods_supported" => ["S256"],
      "token_endpoint_auth_methods_supported" =>
        token_endpoint_auth_methods_supported(client_credentials?),
      "scopes_supported" => server.scopes(),
      # RFC 9207 — we include `iss` in every authorization response, and
      # advertising that is a MUST once we do (RFC 9207 §2.3).
      "authorization_response_iss_parameter_supported" => true
    }

    base
    # Only advertise the DCR endpoint when it's actually enabled.
    # Clients use this field to decide whether to attempt registration.
    |> put_if(server.dcr_enabled?(), "registration_endpoint", issuer <> "/oauth/register")
    # Clients check this before using a URL as their client_id (and fall
    # back to DCR / pre-registration when it's absent).
    |> put_if(server.cimd_enabled?(), "client_id_metadata_document_supported", true)
  end

  defp grant_types_supported(true),
    do: ["authorization_code", "refresh_token", "client_credentials"]

  defp grant_types_supported(false),
    do: ["authorization_code", "refresh_token"]

  # Secret-based token-endpoint auth is only meaningful once confidential
  # clients (client_credentials) are configured on this server.
  defp token_endpoint_auth_methods_supported(true),
    do: ["none", "client_secret_basic", "client_secret_post"]

  defp token_endpoint_auth_methods_supported(false),
    do: ["none"]

  defp put_if(map, true, key, value), do: Map.put(map, key, value)
  defp put_if(map, false, _key, _value), do: map
end
