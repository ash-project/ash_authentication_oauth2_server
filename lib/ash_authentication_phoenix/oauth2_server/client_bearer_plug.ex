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

  ## Machine tokens only

  Client-credentials tokens carry a reserved
  `"gty" => "client_credentials"` claim, which person-delegated tokens
  never carry and `:extra_access_token_claims` cannot set. This plug
  requires that claim, and additionally that `sub == client_id` (both are
  minted from the client row's id), so a user access token cannot
  authenticate as a machine client even if a user id and a client id
  collide.

  On every request the plug also reloads the client and confirms it still
  lists `client_credentials` with a confidential auth method, and that
  the token's scopes remain within the client's current allow-list and
  the server catalogue — so revoking machine access or narrowing scopes
  takes effect before the JWT expires.
  """

  @behaviour Plug

  alias AshAuthentication.Oauth2Server.{Jwt, Token}
  alias AshAuthentication.Phoenix.Oauth2Server.Bearer

  @impl Plug
  def init(opts), do: Bearer.init_opts(opts)

  @impl Plug
  def call(conn, opts), do: Bearer.call(conn, opts, &verify_and_load/2)

  defp verify_and_load(server, token) do
    with {:ok, claims} <- Jwt.verify(server, token),
         :ok <- ensure_machine_token(claims),
         {:ok, client} <- load_client(server, claims),
         :ok <- ensure_still_eligible(client),
         :ok <- ensure_scopes_still_allowed(server, client, claims) do
      {:ok, client, claims}
    end
  end

  # Machine tokens carry gty=client_credentials and set both claims to
  # the client id; user tokens have neither property.
  defp ensure_machine_token(%{
         "gty" => "client_credentials",
         "sub" => sub,
         "client_id" => client_id
       })
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
      |> Bearer.maybe_put_tenant_opt(claims)

    case Ash.get(server.client_resource(), client_id, opts) do
      {:ok, client} -> {:ok, client}
      _ -> {:error, :client_not_found}
    end
  end

  defp load_client(_, _), do: {:error, :missing_subject}
end
