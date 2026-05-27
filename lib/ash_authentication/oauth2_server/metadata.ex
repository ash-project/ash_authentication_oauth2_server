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

    base = %{
      "issuer" => issuer,
      "authorization_endpoint" => issuer <> "/oauth/authorize",
      "token_endpoint" => issuer <> "/oauth/token",
      "revocation_endpoint" => issuer <> "/oauth/revoke",
      "response_types_supported" => ["code"],
      "grant_types_supported" => ["authorization_code", "refresh_token"],
      "code_challenge_methods_supported" => ["S256"],
      "token_endpoint_auth_methods_supported" => ["none"],
      "scopes_supported" => server.scopes()
    }

    # Only advertise the DCR endpoint when it's actually enabled.
    # Clients use this field to decide whether to attempt registration.
    if server.dcr_enabled?(),
      do: Map.put(base, "registration_endpoint", issuer <> "/oauth/register"),
      else: base
  end
end
