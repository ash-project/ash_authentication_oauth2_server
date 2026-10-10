# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Phoenix.Oauth2Server.Router do
  @moduledoc """
  Phoenix router macros for mounting the OAuth 2.1 authorization server.

  `use` this module inside your router to gain access to
  `oauth2_server_consent_routes/1` (browser-facing, user consent) and
  `oauth2_server_protocol_routes/1` (client-facing protocol endpoints).

  ## Example

      defmodule MyAppWeb.Router do
        use Phoenix.Router
        use AshAuthentication.Phoenix.Oauth2Server.Router

        scope "/" do
          pipe_through :browser
          oauth2_server_consent_routes oauth2_server: MyApp.Oauth2Server
        end

        scope "/" do
          pipe_through :api
          oauth2_server_protocol_routes oauth2_server: MyApp.Oauth2Server
        end
      end

  The two macros forward to:

    * `AshAuthentication.Phoenix.Oauth2Server.ConsentRouter` — handles
      `/oauth/authorize` (the user-driven consent step), unless replaced
      with the `:consent_router` option.
    * `AshAuthentication.Phoenix.Oauth2Server.ProtocolRouter` — handles
      `/oauth/register`, `/oauth/token`, `/oauth/revoke`, and the three
      metadata documents under `/.well-known`.
  """

  defmacro __using__(_opts) do
    quote do
      import AshAuthentication.Phoenix.Oauth2Server.Router,
        only: [
          oauth2_server_consent_routes: 0,
          oauth2_server_consent_routes: 1,
          oauth2_server_protocol_routes: 0,
          oauth2_server_protocol_routes: 1
        ]
    end
  end

  @doc """
  Generate the routes for the user-driven consent step of an OAuth 2.1
  authorization-server flow.

  Mount this inside a scope that pipes through your **browser** pipeline
  (with `:protect_from_forgery` and session loading) — both the consent
  GET and POST need a logged-in user and CSRF protection.

  ## Example

      scope "/" do
        pipe_through :browser
        oauth2_server_consent_routes oauth2_server: MyApp.Oauth2Server
      end

  ## Options

    * `:oauth2_server` (required) — your `Oauth2Server` config module.
    * `:path` — base path. Defaults to `/oauth/authorize`.
    * `:consent_router` — a module implementing the standard `Plug` behaviour.
      Defaults to `AshAuthentication.Phoenix.Oauth2Server.ConsentRouter`.
      See [Custom consent flows](custom-consent-flows.md) for a worked router example.
    * `:consent_view` — module exposing `render(:consent, assigns)`.
      Defaults to `AshAuthentication.Phoenix.Oauth2Server.ConsentView`.

  Set `:consent_router` when your application needs to own the complete consent
  flow, including GET and POST handling:

      scope "/" do
        pipe_through :browser

        oauth2_server_consent_routes(
          oauth2_server: MyApp.Oauth2Server,
          consent_router: MyAppWeb.ConsentRouter
        )
      end

  A replacement router receives `:oauth2_server` and `:consent_view` through
  `init/1`. Phoenix strips the mounted path prefix, so the default GET and POST
  handlers match `/`. Custom router failures propagate. They do not fall back
  to the default.

  A custom router can reuse protocol handling through
  `AshAuthentication.Phoenix.Oauth2Server.Consent.prepare/2` and
  `AshAuthentication.Phoenix.Oauth2Server.Consent.complete/4`.
  Preparation validates the request and browser context without deciding or
  granting consent. Completion accepts `:consent_view` in its separate options
  for rendering or finishes the application's decision with session renewal
  and OAuth responses.

  Application authorization and atomic persistence of application grants plus
  OAuth consent remain application-owned. Keep session loading and CSRF
  protection in the outer browser pipeline. See the worked guide and each
  operation's documentation for the hand-back contract.
  """
  defmacro oauth2_server_consent_routes(opts \\ []) when is_list(opts) do
    quote location: :keep do
      opts = unquote(opts)
      server = Keyword.fetch!(opts, :oauth2_server)
      path = Keyword.get(opts, :path, "/oauth/authorize")

      consent_view =
        Keyword.get(opts, :consent_view, AshAuthentication.Phoenix.Oauth2Server.ConsentView)

      consent_router =
        Keyword.get(opts, :consent_router, AshAuthentication.Phoenix.Oauth2Server.ConsentRouter)

      scope "/", alias: false do
        forward path, consent_router,
          oauth2_server: server,
          consent_view: consent_view
      end
    end
  end

  @doc """
  Generate the routes for the client-facing OAuth 2.1 protocol endpoints —
  discovery, dynamic client registration, token, and revocation.

  Mount this inside a scope that pipes through your **API** pipeline. These
  endpoints are called by external OAuth clients without a browser session,
  so CSRF must NOT apply.

  ## Example

      scope "/" do
        pipe_through :api
        oauth2_server_protocol_routes oauth2_server: MyApp.Oauth2Server
      end

  ## Options

    * `:oauth2_server` (required) — your `Oauth2Server` config module.
    * `:oauth_path` — prefix for `/token`, `/register`, etc. Defaults to `/oauth`.
    * `:well_known_path` — prefix for `/oauth-authorization-server`,
      `/oauth-protected-resource`, `/openid-configuration`.
      Defaults to `/.well-known`.
  """
  defmacro oauth2_server_protocol_routes(opts \\ []) when is_list(opts) do
    quote location: :keep do
      opts = unquote(opts)
      server = Keyword.fetch!(opts, :oauth2_server)
      oauth_path = Keyword.get(opts, :oauth_path, "/oauth")
      well_known_path = Keyword.get(opts, :well_known_path, "/.well-known")

      scope "/", alias: false do
        forward oauth_path, AshAuthentication.Phoenix.Oauth2Server.ProtocolRouter,
          oauth2_server: server

        # The same plug is forwarded here, but `well_known?: true` restricts it
        # to the metadata discovery documents. Phoenix's forward strips the
        # prefix before dispatch, so without that flag the state-changing
        # /register, /token, and /revoke routes would answer under /.well-known
        # too, bypassing edge controls scoped to the oauth path.
        forward well_known_path, AshAuthentication.Phoenix.Oauth2Server.ProtocolRouter,
          oauth2_server: server,
          well_known?: true
      end
    end
  end
end
