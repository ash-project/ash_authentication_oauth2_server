# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.Register do
  @moduledoc """
  Protocol-pure logic for `/oauth/register` (RFC 7591 Dynamic Client
  Registration).

  v1 supports public clients only (PKCE, `token_endpoint_auth_method: "none"`).
  Confidential clients (`client_secret_basic`) are deferred.

  Registration is open by default — the standard RFC 7591 mode. To gate
  it, set `:initial_access_token` on your `Oauth2Server` module and pass
  the request's bearer token via `opts[:initial_access_token]` when
  calling `register/3` (RFC 7591 §3).

  All Ash calls run through the `AshAuthentication.Checks.AshAuthenticationInteraction`
  bypass (set by the installer) rather than `authorize?: false`.
  """

  alias AshAuthentication.Oauth2Server.ClientMetadata

  @ash_context %{private: %{ash_authentication?: true}}

  @doc """
  Register a new OAuth client from RFC 7591-shaped parameters.

  `opts` may include:

    * `:initial_access_token` — the bearer token the request presented
      (or `nil`). When the server has `:initial_access_token` configured,
      this MUST match (constant-time) or registration is rejected.
    * `:tenant` — Ash tenant for the create call. Forwarded as-is so
      multi-tenant client resources scope correctly.

  Returns:

    * `{:ok, client_record, response_body}` on success.
    * `{:error, :dcr_disabled}` when the server has `dcr_enabled?: false`
      (the library default). Controllers should treat this as a 404 —
      the endpoint is not exposed.
    * `{:error, :invalid_initial_access_token}` when the bearer was
      missing or didn't match. Per RFC 7591 §3.2.2 this is a Bearer-auth
      failure — controllers should emit `401` with
      `WWW-Authenticate: Bearer error="invalid_token"`, not 400.
    * `{:error, code, description}` for any other validation failure —
      a 400 DCR error response per RFC 7591 §3.2.2.
  """
  @spec register(server :: module(), params :: map(), opts :: keyword()) ::
          {:ok, Ash.Resource.record(), map()}
          | {:error, :dcr_disabled}
          | {:error, :invalid_initial_access_token}
          | {:error, String.t(), String.t()}
  def register(server, params, opts \\ []) do
    with :ok <- check_dcr_enabled(server),
         :ok <- check_initial_access_token(server, opts),
         :ok <- ClientMetadata.validate_redirect_uris(params),
         :ok <- validate_client_name(params),
         :ok <- ClientMetadata.validate_grant_types(params),
         :ok <- ClientMetadata.validate_response_types(params),
         :ok <- ClientMetadata.validate_auth_method(params),
         {:ok, client} <- create_client(server, params, opts) do
      {:ok, client, response_body(server, client)}
    else
      {:error, :dcr_disabled} = err -> err
      {:error, :invalid_initial_access_token} = err -> err
      {:error, code, desc} -> {:error, code, desc}
      {:error, _other} -> {:error, "invalid_client_metadata", "client could not be registered"}
    end
  end

  defp check_dcr_enabled(server) do
    if server.dcr_enabled?(), do: :ok, else: {:error, :dcr_disabled}
  end

  defp check_initial_access_token(server, opts) do
    case server.initial_access_token() do
      nil ->
        :ok

      expected when is_binary(expected) ->
        presented = Keyword.get(opts, :initial_access_token)

        if is_binary(presented) and Plug.Crypto.secure_compare(expected, presented),
          do: :ok,
          else: {:error, :invalid_initial_access_token}
    end
  end

  # `client_name` is optional in RFC 7591. When present, must be a string;
  # we don't impose length limits but reject obviously bogus shapes so they
  # turn into a clean DCR error rather than a 500 in the changeset.
  defp validate_client_name(%{"client_name" => name}) when is_binary(name), do: :ok

  defp validate_client_name(%{"client_name" => _}),
    do: {:error, "invalid_client_metadata", "client_name must be a string"}

  defp validate_client_name(_), do: :ok

  defp create_client(server, params, opts) do
    attrs = %{
      client_name: Map.get(params, "client_name", "Unnamed Client"),
      redirect_uris: Map.fetch!(params, "redirect_uris"),
      grant_types: ClientMetadata.narrow_grant_types(params),
      response_types: Map.get(params, "response_types", ["code"]),
      token_endpoint_auth_method: Map.get(params, "token_endpoint_auth_method", "none"),
      scope: Enum.join(server.scopes(), " ")
    }

    server.client_resource()
    |> Ash.Changeset.for_create(:register, attrs)
    |> Ash.create(ash_opts(opts))
  end

  defp ash_opts(opts) do
    base = [context: @ash_context]

    case Keyword.get(opts, :tenant) do
      nil -> base
      tenant -> Keyword.put(base, :tenant, tenant)
    end
  end

  defp response_body(server, client) do
    base = %{
      "client_id" => client.id,
      "client_id_issued_at" => DateTime.to_unix(client.inserted_at),
      "client_name" => client.client_name,
      "redirect_uris" => client.redirect_uris,
      "grant_types" => client.grant_types,
      "response_types" => client.response_types,
      "token_endpoint_auth_method" => client.token_endpoint_auth_method,
      "scope" => client.scope
    }

    if server.dcr_always_return_client_secret?() and
         client.token_endpoint_auth_method == "none" do
      Map.put(base, "client_secret", "")
    else
      base
    end
  end
end
