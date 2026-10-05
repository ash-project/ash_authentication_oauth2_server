# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule Dev.Router do
  @moduledoc false
  use Phoenix.Router
  use AshAuthentication.Phoenix.Oauth2Server.Router

  import Dev.AuthPlug, only: [load_from_session: 2, set_actor: 2]

  alias AshAuthentication.Phoenix.Oauth2Server.{BearerPlug, RequireScopePlug}

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :protect_from_forgery
    plug :load_from_session
    plug :set_actor, :user
  end

  pipeline :api do
    plug :accepts, ["json"]
  end

  pipeline :mcp do
    plug BearerPlug, oauth2_server: Dev.Oauth2Server, resource: :mcp, scope: "mcp"
    plug RequireScopePlug, oauth2_server: Dev.Oauth2Server, resource: :mcp, scope: "mcp"
  end

  pipeline :gql do
    plug BearerPlug, oauth2_server: Dev.Oauth2Server, resource: :gql, scope: "gql"
    plug RequireScopePlug, oauth2_server: Dev.Oauth2Server, resource: :gql, scope: "gql"
    plug AshGraphql.Plug
  end

  scope "/" do
    pipe_through :browser

    get "/", Dev.PageController, :home
    get "/sign-in", Dev.PageController, :sign_in
    forward "/auth", Dev.AuthPlug
    oauth2_server_consent_routes(oauth2_server: Dev.Oauth2Server)
  end

  scope "/" do
    pipe_through :api
    oauth2_server_protocol_routes(oauth2_server: Dev.Oauth2Server)
  end

  scope "/" do
    pipe_through :mcp

    forward "/mcp", AshAi.Mcp.Router,
      tools: [:greet],
      otp_app: :ash_authentication_oauth2_server
  end

  scope "/" do
    pipe_through :gql
    forward "/gql", Absinthe.Plug, schema: Dev.Schema
  end
end
