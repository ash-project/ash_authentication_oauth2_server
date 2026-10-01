# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Phoenix.Oauth2Server.Bearer do
  @moduledoc """
  Shared helpers for RFC 6750 Bearer plugs (`BearerPlug`, `ClientBearerPlug`).
  """

  import Plug.Conn

  alias AshAuthentication.Phoenix.Oauth2Server.Errors

  @type plug_opts :: %{
          server: module(),
          required?: boolean(),
          scope: String.t() | nil
        }

  @type verify_fun :: (module(), String.t() ->
                         {:ok, Ash.Resource.record(), map()} | {:error, atom()})

  @doc """
  Normalize plug options shared by the bearer plugs.
  """
  @spec init_opts(keyword()) :: plug_opts()
  def init_opts(opts) do
    %{
      server: Keyword.fetch!(opts, :oauth2_server),
      required?: Keyword.get(opts, :required?, true),
      scope: opts |> Keyword.get(:scope) |> normalize_scope()
    }
  end

  @doc """
  Extract the access token from `Authorization: Bearer …`.

  Scheme matching is case-insensitive per OAuth 2.1 / RFC 6750.
  Returns `{:ok, token}` or `:no_token`.
  """
  @spec extract_token(Plug.Conn.t()) :: {:ok, String.t()} | :no_token
  def extract_token(conn) do
    case get_req_header(conn, "authorization") do
      [value | _] when is_binary(value) ->
        case String.split(value, " ", parts: 2) do
          [scheme, token] ->
            if String.downcase(scheme) == "bearer" and token != "" do
              {:ok, token}
            else
              :no_token
            end

          _ ->
            :no_token
        end

      _ ->
        :no_token
    end
  end

  @doc """
  Shared bearer-plug `call/2` flow.

  `verify_fun` receives `(server, token)` and must return
  `{:ok, actor, claims}` or `{:error, reason}`.
  """
  @spec call(Plug.Conn.t(), plug_opts(), verify_fun()) :: Plug.Conn.t()
  def call(conn, %{server: server, required?: required?, scope: scope}, verify_fun) do
    case extract_token(conn) do
      :no_token when required? ->
        send_challenge(conn, server, nil, scope)

      :no_token ->
        conn

      {:ok, token} ->
        case verify_fun.(server, token) do
          {:ok, actor, claims} ->
            conn
            |> maybe_set_tenant(claims)
            |> Ash.PlugHelpers.set_actor(actor)
            |> assign(:oauth_claims, claims)

          {:error, reason} when required? ->
            send_challenge(conn, server, reason, scope)

          {:error, _} ->
            conn
        end
    end
  end

  @doc """
  Add `:tenant` to Ash opts when the token carries a tenant claim.
  """
  @spec maybe_put_tenant_opt(keyword(), map()) :: keyword()
  def maybe_put_tenant_opt(opts, %{"tenant" => tenant}) when is_binary(tenant) and tenant != "",
    do: Keyword.put(opts, :tenant, tenant)

  def maybe_put_tenant_opt(opts, _), do: opts

  # Restore the Ash tenant that the AS baked into the token at mint
  # time. Single-tenant deployments mint tokens without a "tenant"
  # claim — this is a no-op for them. The string form here is what
  # `Ash.ToTenant.to_tenant/2` produced at mint time.
  defp maybe_set_tenant(conn, %{"tenant" => tenant}) when is_binary(tenant) and tenant != "" do
    Ash.PlugHelpers.set_tenant(conn, tenant)
  end

  defp maybe_set_tenant(conn, _), do: conn

  defp send_challenge(conn, server, reason, scope) do
    metadata_url = Errors.resource_metadata_url(server, Ash.PlugHelpers.get_tenant(conn))
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
    |> send_resp(401, "")
    |> halt()
  end

  defp normalize_scope(nil), do: nil
  defp normalize_scope(scope), do: scope |> List.wrap() |> Enum.join(" ")

  defp error_params(reason) do
    case reason do
      nil -> {nil, nil}
      :invalid_audience -> {"invalid_token", "audience mismatch"}
      :invalid_issuer -> {"invalid_token", "issuer mismatch"}
      :expired -> {"invalid_token", "token expired"}
      :not_person_token -> {"invalid_token", "not a user access token"}
      :client_not_found -> {"invalid_token", "client not found"}
      :client_not_eligible -> {"invalid_token", "client credentials no longer allowed"}
      :scopes_no_longer_allowed -> {"invalid_token", "token scopes no longer allowed"}
      :not_machine_token -> {"invalid_token", "not a client credentials token"}
      _ -> {"invalid_token", nil}
    end
  end
end
