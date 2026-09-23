# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Phoenix.Oauth2Server.ClientBearerPlug do
  @moduledoc """
  Resource-server bearer validation for **machine** (client credentials) tokens.

  Validates the JWT and loads the **OAuth client** as the Ash actor. Does
  **not** replace `AshAuthentication.Phoenix.Oauth2Server.BearerPlug`, which
  loads a **user**.

  ## Usage

      pipeline :integration_api do
        plug AshAuthentication.Phoenix.Oauth2Server.ClientBearerPlug,
          oauth2_server: MyApp.Oauth2Server

        plug AshAuthentication.Phoenix.Oauth2Server.RequireScopePlug,
          oauth2_server: MyApp.Oauth2Server,
          scope: "my-scope"
      end

  ## Options

  Same as `BearerPlug`: `:oauth2_server` (required), `:required?` (default
  `true`), `:scope` (advisory on 401 challenges).

  ## What ends up on the conn

    * **`Ash.PlugHelpers.get_actor(conn)`** — the client resource record
    * **`conn.assigns.oauth_claims`** — verified JWT claims (including `scope`)

  ## Machine-token fingerprint

  Client-credentials tokens mint `sub` and `client_id` to the same client
  id. Person-delegated tokens mint `sub` as the user id and `client_id` as
  the OAuth client. This plug requires `sub == client_id` so a user access
  token cannot authenticate as a machine client even if ids collide across
  resources.

  On every request the plug also reloads the client and confirms it still
  lists `client_credentials` with a confidential auth method, and that
  the token's scopes remain within the client's current allow-list and
  the server catalogue — so revoking machine access or narrowing scopes
  takes effect before the JWT expires.
  """

  @behaviour Plug
  import Plug.Conn

  alias AshAuthentication.Oauth2Server.{Jwt, Token}
  alias AshAuthentication.Phoenix.Oauth2Server.Errors

  @impl Plug
  def init(opts) do
    %{
      server: Keyword.fetch!(opts, :oauth2_server),
      required?: Keyword.get(opts, :required?, true),
      scope: opts |> Keyword.get(:scope) |> normalize_scope()
    }
  end

  defp normalize_scope(nil), do: nil
  defp normalize_scope(scope), do: scope |> List.wrap() |> Enum.join(" ")

  @impl Plug
  def call(conn, %{server: server, required?: required?, scope: scope}) do
    case extract_token(conn) do
      :no_token when required? ->
        challenge(conn, server, nil, scope)

      :no_token ->
        conn

      {:ok, token} ->
        case verify_and_load(server, token) do
          {:ok, client, claims} ->
            conn
            |> maybe_set_tenant(claims)
            |> Ash.PlugHelpers.set_actor(client)
            |> assign(:oauth_claims, claims)

          {:error, reason} when required? ->
            challenge(conn, server, reason, scope)

          {:error, _} ->
            conn
        end
    end
  end

  defp maybe_set_tenant(conn, %{"tenant" => tenant}) when is_binary(tenant) and tenant != "" do
    Ash.PlugHelpers.set_tenant(conn, tenant)
  end

  defp maybe_set_tenant(conn, _), do: conn

  defp extract_token(conn) do
    case get_req_header(conn, "authorization") do
      [value | _] when is_binary(value) ->
        case String.split(value, " ", parts: 2) do
          [scheme, token] ->
            # OAuth 2.1 / RFC 6750 — "Bearer" is case-insensitive.
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

  defp verify_and_load(server, token) do
    with {:ok, claims} <- Jwt.verify(server, token),
         :ok <- ensure_machine_token(claims),
         {:ok, client} <- load_client(server, claims),
         :ok <- ensure_still_eligible(client),
         :ok <- ensure_scopes_still_allowed(server, client, claims) do
      {:ok, client, claims}
    end
  end

  # Machine tokens set both claims to the client id; user tokens differ.
  defp ensure_machine_token(%{"sub" => sub, "client_id" => client_id})
       when is_binary(sub) and sub != "" and is_binary(client_id) and client_id != "" and
              sub == client_id do
    :ok
  end

  defp ensure_machine_token(_), do: {:error, :not_machine_token}

  # Re-check grant eligibility so revoking machine access on the client
  # row takes effect before the JWT expires.
  defp ensure_still_eligible(client) do
    if Token.client_credentials_allowed?(client) do
      :ok
    else
      {:error, :client_not_eligible}
    end
  end

  defp ensure_scopes_still_allowed(server, client, %{"scope" => scope}) do
    if Token.machine_scopes_allowed?(server, client, scope) do
      :ok
    else
      {:error, :scopes_no_longer_allowed}
    end
  end

  defp ensure_scopes_still_allowed(_, _, _), do: {:error, :scopes_no_longer_allowed}

  defp load_client(server, %{"sub" => client_id} = claims)
       when is_binary(client_id) and client_id != "" do
    opts =
      [context: %{private: %{ash_authentication?: true}}]
      |> maybe_put_tenant_opt(claims)

    case Ash.get(server.client_resource(), client_id, opts) do
      {:ok, client} -> {:ok, client}
      _ -> {:error, :client_not_found}
    end
  end

  defp load_client(_, _), do: {:error, :missing_subject}

  defp maybe_put_tenant_opt(opts, %{"tenant" => tenant}) when is_binary(tenant) and tenant != "",
    do: Keyword.put(opts, :tenant, tenant)

  defp maybe_put_tenant_opt(opts, _), do: opts

  defp challenge(conn, server, reason, scope) do
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

  defp error_params(reason) do
    case reason do
      nil -> {nil, nil}
      :invalid_audience -> {"invalid_token", "audience mismatch"}
      :invalid_issuer -> {"invalid_token", "issuer mismatch"}
      :expired -> {"invalid_token", "token expired"}
      :client_not_found -> {"invalid_token", "client not found"}
      :client_not_eligible -> {"invalid_token", "client credentials no longer allowed"}
      :scopes_no_longer_allowed -> {"invalid_token", "token scopes no longer allowed"}
      :not_machine_token -> {"invalid_token", "not a client credentials token"}
      _ -> {"invalid_token", nil}
    end
  end
end
