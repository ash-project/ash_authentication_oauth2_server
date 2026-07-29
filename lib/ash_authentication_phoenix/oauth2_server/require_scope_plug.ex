# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Phoenix.Oauth2Server.RequireScopePlug do
  @moduledoc """
  Gate a pipeline on OAuth scopes, with spec-shaped errors.

  Mount after `AshAuthentication.Phoenix.Oauth2Server.BearerPlug` — it
  reads the verified claims that plug put in `conn.assigns.oauth_claims`:

      pipeline :mcp_write do
        plug AshAuthentication.Phoenix.Oauth2Server.BearerPlug,
          oauth2_server: MyApp.Oauth2Server

        plug AshAuthentication.Phoenix.Oauth2Server.RequireScopePlug,
          oauth2_server: MyApp.Oauth2Server,
          scope: "mcp.write"
      end

  When the bearer token lacks a required scope, the response is the
  RFC 6750 §3.1 shape — `403` with `WWW-Authenticate: Bearer
  error="insufficient_scope", scope="…", resource_metadata="…"` — which
  is what step-up-capable clients (including MCP clients following the
  2026-07-28 spec) use to re-authorize with the scopes they're missing.
  All missing-or-required scopes are emitted in a single challenge, per
  the spec's guidance against incremental challenges.

  When there are no verified claims at all (the plug ran without
  `BearerPlug`, or with `required?: false` and no token), it responds
  `401` like `BearerPlug` would — authorization is required before scope
  can be evaluated.

  ## Options

    * `:oauth2_server` (required) — your `Oauth2Server` config module
    * `:scope` (required) — a scope string or list of scope strings; the
      token must carry **all** of them
    * `:description` — optional `error_description` for the challenge

  ## Scope hierarchies

  Matching is exact set membership. If your scope catalogue is
  hierarchical (`mcp.admin` implies `mcp.write`), expand the hierarchy
  into the token's scope at consent/mint time, or write your own plug —
  the spec requires the *server* to account for hierarchies, and only
  you know yours.
  """

  @behaviour Plug
  import Plug.Conn

  alias AshAuthentication.Phoenix.Oauth2Server.Errors

  @impl Plug
  def init(opts) do
    %{
      server: Keyword.fetch!(opts, :oauth2_server),
      scopes: opts |> Keyword.fetch!(:scope) |> List.wrap(),
      description: Keyword.get(opts, :description)
    }
  end

  @impl Plug
  def call(conn, %{server: server, scopes: required, description: description}) do
    case conn.assigns[:oauth_claims] do
      %{} = claims ->
        granted =
          claims
          |> Map.get("scope", "")
          |> String.split(" ", trim: true)
          |> MapSet.new()

        if Enum.all?(required, &MapSet.member?(granted, &1)) do
          conn
        else
          Errors.send_insufficient_scope(conn, server, required,
            description: description,
            tenant: Ash.PlugHelpers.get_tenant(conn)
          )
        end

      _ ->
        unauthorized(conn, server)
    end
  end

  defp unauthorized(conn, server) do
    metadata_url = Errors.resource_metadata_url(server, Ash.PlugHelpers.get_tenant(conn))

    conn
    |> put_resp_header("www-authenticate", ~s|Bearer resource_metadata="#{metadata_url}"|)
    |> send_resp(401, "")
    |> halt()
  end
end
