<!--
SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>

SPDX-License-Identifier: MIT
-->

# Custom consent flows

Use `:consent_view` when you only need different consent markup. Use
`:consent_router` when your application must own the decisions and persistence
behind the browser flow, such as saving application access grants together with
OAuth consent.

A replacement is a standard Plug. The mounting macro forwards `:oauth2_server`
and `:consent_view` through `init/1`, with the mounted prefix stripped before
matching. It can reuse
`AshAuthentication.Phoenix.Oauth2Server.Consent` for request preparation and
response handling without implementing the individual protocol steps itself.

```elixir
scope "/" do
  # Load the session, actor and tenant, and enforce CSRF in the browser pipeline.
  pipe_through :browser

  oauth2_server_consent_routes(
    oauth2_server: MyApp.Oauth2Server,
    consent_router: MyAppWeb.ConsentRouter,
    consent_view: MyAppWeb.ConsentView
  )
end
```

## Application-owned persistence

The example assumes an application function named
`MyApp.Accounts.grant_oauth_access/5`. **This is not a library API.** Implement it
in your own domain before using the router:

- Arguments are the server config module, authenticated user, freshly validated
  OAuth request, untrusted application selection, and tenant options.
- Validate the selection's shape, load the selected records in the current
  tenant, and authorize the user for every requested grant.
- Persist those grants and OAuth consent in one transaction on their shared
  transactional data layer. Call
  `AshAuthentication.Oauth2Server.Authorize.grant_consent!/5` inside that
  transaction with the same user, validated client/scope, and tenant options.
  The library's authentication bypass context does not authorize application
  grants.
- Return `:ok` only after committing. Return `{:error, :forbidden}` for denied
  access or `{:error, :failed}` after rolling back a persistence failure. Neither
  error may leave partial grants or consent behind.

Your `MyAppWeb.ConsentView.render/2` receives the usual consent assigns plus
`:user` and `:tenant`. Render a POST form to `:action_path` with `_csrf_token`,
`consent_request`, and an `action` button valued `approve` or `deny`. Add your
application-specific `selection` field. Escape untrusted values and paginate
any growing selection lists in your application.

## Example

```elixir
defmodule MyAppWeb.ConsentRouter do
  use Plug.Router, copy_opts_to_assign: :consent_opts

  alias AshAuthentication.Phoenix.Oauth2Server.Consent

  plug :match
  plug :dispatch

  get "/" do
    case Consent.prepare(conn, conn.assigns.consent_opts) do
      {:ok, conn, request} ->
        # The default renderer supplies sealed OAuth fields and the CSRF token.
        Consent.complete(conn, request, {:render, %{}}, conn.assigns.consent_opts)

      {:halt, conn} ->
        conn
    end
  end

  post "/" do
    # Preparation verifies the sealed request and validates it with this tenant.
    case Consent.prepare(conn, conn.assigns.consent_opts) do
      {:ok, conn, %{action: "approve"} = request} ->
        approve(conn, request)

      {:ok, conn, request} ->
        Consent.complete(conn, request, :denied)

      {:halt, conn} ->
        conn
    end
  end

  match _ do
    conn |> send_resp(404, "") |> halt()
  end

  defp approve(conn, request) do
    # The application authorizes the selection and commits both kinds of grants.
    case MyApp.Accounts.grant_oauth_access(
           request.server,
           request.user,
           request.validated,
           conn.params["selection"],
           request.tenant_opts
         ) do
      :ok ->
        # Completion renews the session and issues a code without rewriting consent.
        # Code issuance failures do not roll back the committed grants.
        Consent.complete(conn, request, :approved)

      {:error, :forbidden} ->
        Consent.complete(conn, request, {:error, "access_denied", "Access not permitted"})

      {:error, :failed} ->
        Consent.complete(
          conn,
          request,
          {:error, "server_error", "Consent could not be saved"}
        )
    end
  end
end
```

Extra view assigns can be passed with `{:render, assigns}`, including on a
prepared POST when the application needs to show a selection error. The default
renderer owns the protocol fields, signed token and browser-context assigns.
Extra assigns cannot override them.
