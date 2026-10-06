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
          resource: atom() | nil,
          required?: boolean(),
          scope: String.t() | nil
        }

  @type verify_fun :: (module(), atom() | nil, String.t() ->
                         {:ok, Ash.Resource.record(), map()} | {:error, atom()})

  @doc """
  Normalize plug options shared by the bearer plugs.
  """
  @spec init_opts(keyword()) :: plug_opts()
  def init_opts(opts) do
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

  @doc """
  Extract the access token from `Authorization: Bearer …`.

  RFC 7235 §2.1: the auth-scheme is case-insensitive. RFC 6750 §2.1: one or
  more spaces separate it from the token. A Bearer header without a token is
  a malformed request (RFC 6750 §3.1). Another scheme is no Bearer
  authentication at all.
  """
  @spec extract_token(Plug.Conn.t()) :: {:ok, String.t()} | :no_token | :malformed
  def extract_token(conn) do
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

  @doc """
  Shared bearer-plug `call/2` flow.

  `verify_fun` receives `(server, resource, token)` and must return
  `{:ok, actor, claims}` or `{:error, reason}`.
  """
  @spec call(Plug.Conn.t(), plug_opts(), verify_fun()) :: Plug.Conn.t()
  def call(
        conn,
        %{server: server, resource: resource, required?: required?, scope: scope},
        verify_fun
      ) do
    case extract_token(conn) do
      :no_token when required? ->
        send_challenge(conn, server, resource, nil, scope)

      :no_token ->
        conn

      :malformed when required? ->
        send_challenge(conn, server, resource, :malformed, scope)

      :malformed ->
        conn

      {:ok, token} ->
        case verify_fun.(server, resource, token) do
          {:ok, actor, claims} ->
            conn
            |> maybe_set_tenant(claims)
            |> Ash.PlugHelpers.set_actor(actor)
            |> assign(:oauth_claims, claims)

          {:error, reason} when required? ->
            send_challenge(conn, server, resource, reason, scope)

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

  defp send_challenge(conn, server, resource, reason, scope) do
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

  defp normalize_scope(nil), do: nil
  defp normalize_scope(scope), do: scope |> List.wrap() |> Enum.join(" ")

  defp error_params(reason) do
    case reason do
      nil -> {nil, nil}
      :malformed -> {"invalid_request", "Bearer credentials without a token"}
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
