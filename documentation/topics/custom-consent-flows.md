<!--
SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>

SPDX-License-Identifier: MIT
-->

# Custom consent flows

In some cases, your application needs more than the default OAuth consent flow.
For example, you may need to:

- Let users choose which workspaces or projects a client can access.
- Apply organization-specific approval policies before granting access.
- Save application access grants and OAuth consent in a single transaction.

The example below uses workspace selection. Your resource server must enforce
those workspace grants alongside the token's OAuth scopes.

Use `:consent_view` when you only need different markup for the default flow.
Use `:consent_router` when your application needs to authorize and persist an
application-specific selection. The default router can skip the screen when
OAuth consent already exists, so changing the view alone does not ensure a
workspace-selection step runs.

## Contract

Custom routers can reuse
`AshAuthentication.Phoenix.Oauth2Server.Consent.prepare/2` and
`AshAuthentication.Phoenix.Oauth2Server.Consent.complete/4`:

1. **Prepare the request.** `prepare/2` validates the OAuth request in the
   current Ash tenant and requires an authenticated actor. On POST it verifies
   the sealed protocol fields and validates them again. It returns
   `{:ok, conn, request}` without checking prior consent or writing grants, or
   `{:halt, conn}` after handling a protocol or authentication failure.
   Keep `request` unchanged.
2. **Do the application work.** On GET, load workspace choices the user may see.
   On approval, validate the submitted workspace IDs, load them in the current
   tenant, and authorize the user for every client-workspace grant. Persist
   these grants and OAuth consent in one transaction on their shared
   transactional data layer. The library's authentication bypass context does
   not authorize workspace access.
3. **Complete the response.** Render with `{:render, assigns}` and separate
   view options, or pass `:approved` only after the transaction commits.
   `complete/4` renews an approved POST session and issues a code without
   rewriting consent. Use `:denied` or an OAuth error for unsuccessful decisions.
   Code-creation failures do not roll back previously committed grants.

Inside the application transaction, call
`AshAuthentication.Oauth2Server.Authorize.grant_consent!/5` with the prepared user,
validated client and scope, and tenant options:

```elixir
AshAuthentication.Oauth2Server.Authorize.grant_consent!(
  server,
  user,
  validated.client,
  validated.scope,
  tenant_opts
)
```

A replacement is a standard Plug. Its `call/2` must return a `Plug.Conn`, not a
decision or an application result tuple. The example below translates application
results into decisions passed to `complete/4`, which returns a halted connection.

## Workspace-selection router

Mount the router behind a browser pipeline that loads the session, actor and
tenant, and enforces CSRF protection. The mounting macro forwards `:oauth2_server`
and `:consent_view` through `init/1` and strips the mounted prefix before matching:

```elixir
scope "/" do
  pipe_through :browser

  oauth2_server_consent_routes(
    oauth2_server: MyApp.Oauth2Server,
    consent_router: MyAppWeb.ConsentRouter,
    consent_view: MyAppWeb.ConsentView
  )
end
```

The router calls two **application-owned functions, not library APIs**:

- `MyApp.Accounts.list_oauth_workspaces/2` loads a bounded or paginated set of
  workspace choices for the user and tenant options.
- `MyApp.Accounts.grant_oauth_access/5` accepts the server, authenticated user,
  validated OAuth request, untrusted workspace IDs and tenant options. Implement
  the authorization and transaction described above. Return `:ok` only after
  committing, `{:error, :forbidden}` for denied access, or `{:error, :failed}`
  after rolling back a persistence failure. Errors must leave no partial grants
  or consent behind.

Implement `MyAppWeb.ConsentView.render(:consent, assigns)` to display `:workspaces`
and the usual consent fields, including `:user` and `:tenant`. Render a POST form
at `:action_path` with `_csrf_token`, `consent_request`, and an `action` button
valued `approve` or `deny`. Workspace checkboxes named `workspace_ids[]` submit
an untrusted list of IDs. Escape untrusted labels. Extra assigns cannot override
the helper's protocol or browser-context fields.

```elixir
defmodule MyAppWeb.ConsentRouter do
  use Plug.Router, copy_opts_to_assign: :consent_opts

  alias AshAuthentication.Phoenix.Oauth2Server.Consent

  plug :match
  plug :dispatch

  get "/" do
    opts = conn.assigns.consent_opts

    case Consent.prepare(conn, opts) do
      {:ok, conn, request} ->
        workspaces = MyApp.Accounts.list_oauth_workspaces(request.user, request.tenant_opts)
        Consent.complete(conn, request, {:render, %{workspaces: workspaces}}, opts)

      {:halt, conn} ->
        conn
    end
  end

  post "/" do
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
    # Authorize the workspace IDs and commit both kinds of grants together.
    case MyApp.Accounts.grant_oauth_access(
           request.server,
           request.user,
           request.validated,
           conn.params["workspace_ids"],
           request.tenant_opts
         ) do
      :ok ->
        # Issue the code only after the application transaction commits.
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
