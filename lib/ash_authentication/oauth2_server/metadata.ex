# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.Metadata do
  @moduledoc """
  Builders for the discovery metadata endpoints.

    * `protected_resource/3` (RFC 9728) — for a protected resource, served at
      `/.well-known/oauth-protected-resource` followed by the path of the
      resource identifier.
    * `authorization_server/1` (RFC 8414) — for the authorization server,
      served at `/.well-known/oauth-authorization-server`.

  Both return plain maps; controllers JSON-encode them.
  """

  @doc """
  Build the OAuth Protected Resource Metadata document (RFC 9728).

  `context` is forwarded to the server's `resource_url/2` and `issuer_url/1`
  callbacks so per-request (e.g. per-tenant) resolution works. Single-tenant
  callers can pass `%{}`. `resource` is the name of a configured resource,
  and defaults to the only configured resource.
  """
  @spec protected_resource(server :: module(), context :: map(), resource :: atom() | nil) ::
          map()
  def protected_resource(server, context \\ %{}, resource \\ nil) do
    %{
      "resource" => server.resource_url(resource, context),
      "authorization_servers" => [server.issuer_url(context)],
      "scopes_supported" => server.resource_scopes(resource),
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
    grants = server.supported_grants()
    authorization_code? = :authorization_code in grants

    base = %{
      "issuer" => issuer,
      "token_endpoint" => issuer <> "/oauth/token",
      "revocation_endpoint" => issuer <> "/oauth/revoke",
      # RFC 8414 §2: `response_types_supported` is required. Without the
      # authorization code grant there is no authorization endpoint and no
      # response type.
      "response_types_supported" => if(authorization_code?, do: ["code"], else: []),
      "grant_types_supported" => Enum.map(grants, &Atom.to_string/1),
      # Confidential clients authenticate with a secret on every grant
      # (RFC 6749 §2.3.1), public clients with `client_id` only.
      "token_endpoint_auth_methods_supported" => [
        "none",
        "client_secret_basic",
        "client_secret_post"
      ],
      "scopes_supported" => server.scopes()
    }

    base
    |> put_if(authorization_code?, "authorization_endpoint", issuer <> "/oauth/authorize")
    |> put_if(authorization_code?, "code_challenge_methods_supported", ["S256"])
    # RFC 9207 — we include `iss` in every authorization response, and
    # advertising that is a MUST once we do (RFC 9207 §2.3).
    |> put_if(authorization_code?, "authorization_response_iss_parameter_supported", true)
    # Only advertise the DCR endpoint when it's actually enabled.
    # Clients use this field to decide whether to attempt registration.
    |> put_if(server.dcr_enabled?(), "registration_endpoint", issuer <> "/oauth/register")
    # Clients check this before using a URL as their client_id (and fall
    # back to DCR / pre-registration when it's absent).
    |> put_if(server.cimd_enabled?(), "client_id_metadata_document_supported", true)
  end

  defp put_if(map, true, key, value), do: Map.put(map, key, value)
  defp put_if(map, false, _key, _value), do: map
end
