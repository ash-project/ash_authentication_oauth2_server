# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Phoenix.Oauth2Server.ConsentRouter do
  @moduledoc """
  Plug router for the human-driven consent step of the OAuth 2.1 flow.

  Handles `GET /authorize` (renders the consent screen) and
  `POST /authorize` (records the consent decision and redirects with a code).
  Both require a logged-in browser session — mount this behind your
  browser/session pipeline, not your API pipeline.

  See `AshAuthentication.Phoenix.Oauth2Server.ProtocolRouter` for the
  client-facing protocol endpoints (token, register, metadata). Custom consent
  routers can reuse `AshAuthentication.Phoenix.Oauth2Server.Consent` for
  protocol handling while owning their UI, application authorization and
  consent transaction.

  ## Options

    * `:oauth2_server` (required) — the user's `Oauth2Server` config module
    * `:consent_view` — module exposing `render(:consent, assigns)`
      (default: `AshAuthentication.Phoenix.Oauth2Server.ConsentView`)
  """

  use Plug.Router, copy_opts_to_assign: :oauth2_server_router_opts

  alias AshAuthentication.Oauth2Server.Authorize
  alias AshAuthentication.Phoenix.Oauth2Server.Consent

  plug Plug.Parsers,
    parsers: [:urlencoded],
    pass: ["*/*"]

  plug :match
  plug :dispatch

  get "/" do
    opts = conn.assigns.oauth2_server_router_opts

    case Consent.prepare(conn, opts) do
      {:ok, conn, request} ->
        if Authorize.consented?(
             request.server,
             request.user,
             request.validated.client,
             request.validated.scope,
             request.tenant_opts
           ) do
          Consent.complete(conn, request, :approved)
        else
          Consent.complete(conn, request, {:render, %{}}, opts)
        end

      {:halt, conn} ->
        conn
    end
  end

  post "/" do
    case Consent.prepare(conn, conn.assigns.oauth2_server_router_opts) do
      {:ok, conn, %{action: "approve"} = request} ->
        Authorize.grant_consent!(
          request.server,
          request.user,
          request.validated.client,
          request.validated.scope,
          request.tenant_opts
        )

        Consent.complete(conn, request, :approved)

      {:ok, conn, request} ->
        Consent.complete(conn, request, :denied)

      {:halt, conn} ->
        conn
    end
  end

  match _ do
    conn |> send_resp(404, "") |> halt()
  end
end
