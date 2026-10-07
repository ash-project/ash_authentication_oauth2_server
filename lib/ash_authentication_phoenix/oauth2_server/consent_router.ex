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
  routers can reuse `prepare/2` and `complete/3` for protocol handling while
  owning their UI, application authorization and consent transaction.

  ## Options

    * `:oauth2_server` (required) — the user's `Oauth2Server` config module
    * `:consent_view` — module exposing `render(:consent, assigns)`
      (default: `AshAuthentication.Phoenix.Oauth2Server.ConsentView`)
  """

  use Plug.Router, copy_opts_to_assign: :oauth2_server_router_opts

  alias AshAuthentication.Oauth2Server.Authorize
  alias AshAuthentication.Phoenix.Oauth2Server.{ConsentView, Errors}

  @max_state_bytes 2048
  @consent_request_salt "ash_authentication_phoenix oauth2_server consent_request v1"
  @consent_request_max_age 600
  @parser_opts Plug.Parsers.init(parsers: [:urlencoded], pass: ["*/*"])

  @typedoc """
  Validated request and browser context returned by `prepare/2`.

  Application grant operations use `server`, `user`, `validated` and
  `tenant_opts`. Keep this request unchanged when passing it to `complete/3`.
  `action` is the validated POST button value, or nil for GET.
  """
  @type request :: %{
          server: module(),
          user: Ash.Resource.Record.t(),
          validated: Authorize.validated(),
          tenant: term(),
          tenant_opts: Authorize.opts(),
          method: String.t(),
          action: String.t() | nil,
          consent_view: module()
        }

  @typedoc """
  Application decision passed to `complete/3` after preparation.

  Approval means consent and any application grants have already committed.
  Rendering accepts extra view assigns, but cannot override protocol fields.
  """
  @type decision ::
          :approved
          | :denied
          | {:error, String.t(), String.t() | nil}
          | {:render, map()}

  plug Plug.Parsers,
    parsers: [:urlencoded],
    pass: ["*/*"]

  plug :match
  plug :dispatch

  get "/" do
    case prepare(conn, conn.assigns.oauth2_server_router_opts) do
      {:ok, conn, request} ->
        if Authorize.consented?(
             request.server,
             request.user,
             request.validated.client,
             request.validated.scope,
             request.tenant_opts
           ) do
          complete(conn, request, :approved)
        else
          complete(conn, request, {:render, %{}})
        end

      {:halt, conn} ->
        conn
    end
  end

  post "/" do
    case prepare(conn, conn.assigns.oauth2_server_router_opts) do
      {:ok, conn, %{action: "approve"} = request} ->
        Authorize.grant_consent!(
          request.server,
          request.user,
          request.validated.client,
          request.validated.scope,
          request.tenant_opts
        )

        complete(conn, request, :approved)

      {:ok, conn, request} ->
        complete(conn, request, :denied)

      {:halt, conn} ->
        conn
    end
  end

  match _ do
    conn |> send_resp(404, "") |> halt()
  end

  @doc """
  Prepare a GET or POST consent request for application-owned handling.

  `opts` accepts the same `:oauth2_server` and `:consent_view` options as this
  router. Parses URL-encoded requests with the default parser limits, checks
  GET state size, verifies and reconstructs sealed POST protocol fields, and
  validates the request with the browser connection's current Ash tenant.
  Requires its authenticated actor and an approve or deny action on POST.
  Session loading and CSRF protection remain in the outer browser pipeline.

  Returns `{:ok, conn, request}` without rendering, checking prior consent,
  persisting grants or issuing a code. Returns `{:halt, conn}` after responding
  to invalid requests or redirecting an unauthenticated browser to sign-in.
  Unsupported methods return a halted 404. Parser and configuration failures
  propagate as they do in the default router.
  """
  @spec prepare(Plug.Conn.t(), keyword()) ::
          {:ok, Plug.Conn.t(), request()} | {:halt, Plug.Conn.t()}
  def prepare(%Plug.Conn{method: method} = conn, opts) when method in ["GET", "POST"] do
    conn = Plug.Parsers.call(conn, @parser_opts)
    server = server!(opts)

    case request_params(conn, server) do
      {:ok, params} ->
        prepare_request(conn, server, params, opts)

      {:error, :state_too_large} ->
        {:halt, bad_state_html(conn)}

      {:error, :invalid} ->
        {:halt,
         Errors.send_oauth_error(
           conn,
           400,
           "invalid_request",
           "consent request token missing, invalid, or expired"
         )}
    end
  end

  def prepare(conn, _opts), do: {:halt, conn |> send_resp(404, "") |> halt()}

  @doc """
  Hand a prepared consent decision back to the default response handling.

  Pass the connection and unchanged `request` returned by `prepare/2`, plus:

    * `{:render, assigns}` to render the configured consent view. Adds signed
      request and CSRF fields, frame protections, actor and tenant assigns.
      Protocol and browser-context assigns take precedence over extra assigns.
    * `:approved` after consent and required application grants have committed.
      Renews the session for an approved POST and issues a code. GET approval
      reuses existing grants and does not renew the session.
    * `:denied` to redirect with `access_denied` without granting or renewing.
    * `{:error, code, description}` to return an application OAuth error.
      The description is omitted when nil or empty.

  Returns a halted connection. This function does not persist consent or
  application grants. Code-creation failures propagate and do not roll back
  previously committed grants. Invalid decisions, including approving a denied
  POST, raise `ArgumentError`. This is opt-in reuse, not a sandbox for custom
  Plug code or a replacement for application authorization.
  """
  @spec complete(Plug.Conn.t(), request(), decision()) :: Plug.Conn.t()
  def complete(conn, request, {:render, assigns}) when is_map(assigns) do
    render_consent(conn, request, assigns)
  end

  def complete(conn, %{method: "POST", action: "approve"} = request, :approved) do
    conn |> rotate_session() |> issue_code_redirect(request)
  end

  def complete(conn, %{method: "GET"} = request, :approved) do
    issue_code_redirect(conn, request)
  end

  def complete(conn, request, :denied) do
    complete(conn, request, {:error, "access_denied", nil})
  end

  def complete(conn, request, {:error, code, description})
      when is_binary(code) and (is_binary(description) or is_nil(description)) do
    conn = Ash.PlugHelpers.set_tenant(conn, request.tenant)

    redirect_with_oauth_error(
      conn,
      request.server,
      request.validated.redirect_uri,
      request.validated.state,
      code,
      description
    )
  end

  def complete(_conn, _request, _decision) do
    raise ArgumentError, "invalid consent completion decision"
  end

  defp request_params(%Plug.Conn{method: "GET", query_params: params}, _server) do
    with :ok <- check_state_size(params), do: {:ok, params}
  end

  defp request_params(conn, server) do
    verify_consent_request(server, Map.get(conn.params, "consent_request"))
  end

  defp prepare_request(conn, server, params, opts) do
    tenant_opts = tenant_opts(conn)

    with {:ok, validated} <- Authorize.validate_request(server, params, tenant_opts),
         {:ok, user} <- require_user(conn),
         :ok <- check_action(conn) do
      {:ok, conn,
       %{
         server: server,
         user: user,
         validated: validated,
         tenant: Ash.PlugHelpers.get_tenant(conn),
         tenant_opts: tenant_opts,
         method: conn.method,
         action: if(conn.method == "POST", do: Map.get(conn.params, "action")),
         consent_view: consent_view!(opts)
       }}
    else
      {:error, :no_user} ->
        {:halt, sign_in_redirect(conn, server)}

      {:error, :bad_client, code, desc} ->
        {:halt, Errors.send_oauth_error(conn, 400, code, desc)}

      {:error, :bad_redirect_uri} ->
        {:halt, bad_redirect_html(conn)}

      {:error, :invalid_action} ->
        {:halt, Errors.send_oauth_error(conn, 400, "invalid_request", "missing action")}

      {:error, code, desc} ->
        {:halt, redirect_authorize_error(conn, server, params, code, desc)}
    end
  end

  defp check_action(%Plug.Conn{method: "GET"}), do: :ok

  defp check_action(%Plug.Conn{params: %{"action" => action}}) when action in ["approve", "deny"],
    do: :ok

  defp check_action(_conn), do: {:error, :invalid_action}

  # ── shared helpers ────────────────────────────────────────────────────────

  defp server!(opts), do: Keyword.fetch!(opts, :oauth2_server)
  defp consent_view!(opts), do: Keyword.get(opts, :consent_view, ConsentView)

  defp require_user(conn) do
    case Ash.PlugHelpers.get_actor(conn) do
      nil -> {:error, :no_user}
      user -> {:ok, user}
    end
  end

  defp issue_code_redirect(conn, request) do
    validated = request.validated
    code = Authorize.issue_code!(request.server, request.user, validated, request.tenant_opts)

    location =
      append_query(
        validated.redirect_uri,
        %{
          "code" => code.id,
          # RFC 9207 — identify the issuer in the authorization response
          # so the client can detect authorization-server mix-up attacks.
          "iss" => issuer_url(request.server, request.tenant)
        }
        |> maybe_put_param("state", validated.state)
      )

    conn
    |> put_resp_header("location", location)
    |> send_resp(302, "")
    |> halt()
  end

  # RFC 6749 §4.1.2.1: once the client and redirect_uri are validated,
  # error responses MUST go back via 302 with `error`, `error_description`,
  # and `state` so the client can surface the failure to the end user.
  # `Authorize.error_redirect_uri/3` applies the same exact match as a
  # successful request. Without a valid target the error goes to the user
  # agent directly (OAuth 2.1 §4.1.2.1).
  defp redirect_authorize_error(conn, server, params, code, desc) do
    case Authorize.error_redirect_uri(server, params, tenant_opts(conn)) do
      {:ok, redirect_uri} ->
        redirect_with_oauth_error(
          conn,
          server,
          redirect_uri,
          Map.get(params, "state"),
          code,
          desc
        )

      :error ->
        Errors.send_oauth_error(conn, 400, code, desc)
    end
  end

  # RFC 9207 §2 requires `iss` on error responses too.
  defp redirect_with_oauth_error(conn, server, redirect_uri, state, code, desc) do
    query =
      %{"error" => code, "iss" => issuer(conn, server)}
      |> maybe_put_param("error_description", desc)
      |> maybe_put_param("state", state)

    conn
    |> put_resp_header("location", append_query(redirect_uri, query))
    |> send_resp(302, "")
    |> halt()
  end

  # OAuth 2.1 §2.3: a query in the redirect URI MUST be retained when
  # adding parameters. The URI is extended as a string, because re-encoding
  # it with URI.to_string/1 can change the registered form (a default port,
  # for example). Registered redirect URIs carry no fragment.
  defp append_query(redirect_uri, params) do
    separator =
      case URI.parse(redirect_uri).query do
        nil -> "?"
        "" -> ""
        _query -> "&"
      end

    redirect_uri <> separator <> URI.encode_query(params)
  end

  defp issuer(conn, server), do: issuer_url(server, Ash.PlugHelpers.get_tenant(conn))
  defp issuer_url(server, nil), do: server.issuer_url()
  defp issuer_url(server, tenant), do: server.issuer_url(%{tenant: tenant})

  defp maybe_put_param(map, key, value) when is_binary(value) and value != "",
    do: Map.put(map, key, value)

  defp maybe_put_param(map, _key, _value), do: map

  defp tenant_opts(conn) do
    case Ash.PlugHelpers.get_tenant(conn) do
      nil -> []
      tenant -> [tenant: tenant]
    end
  end

  defp check_state_size(%{"state" => state}) when is_binary(state) do
    if byte_size(state) > @max_state_bytes, do: {:error, :state_too_large}, else: :ok
  end

  defp check_state_size(_), do: :ok

  # Re-key the session on the anon→consented transition so a fixated
  # pre-login session id can't carry into the consented context.
  defp rotate_session(conn), do: Plug.Conn.configure_session(conn, renew: true)

  # sobelow_skip ["XSS.SendResp"]
  defp render_consent(conn, request, extra_assigns) do
    validated = request.validated

    assigns =
      Map.merge(extra_assigns, %{
        client_name: validated.client.client_name,
        client_id: validated.client.id,
        redirect_uri: validated.redirect_uri,
        code_challenge: validated.code_challenge,
        scope: validated.scope,
        state: validated.state,
        resource: validated.resource,
        action_path: conn.request_path,
        csrf_token: get_csrf_token(),
        consent_request: mint_consent_request(request.server, validated),
        user: request.user,
        tenant: request.tenant
      })

    body = request.consent_view.render(:consent, assigns) |> IO.iodata_to_binary()

    conn
    |> put_resp_header("content-type", "text/html; charset=utf-8")
    |> put_resp_header("x-frame-options", "DENY")
    |> put_resp_header("content-security-policy", "frame-ancestors 'none'")
    |> send_resp(200, body)
    |> halt()
  end

  defp sign_in_redirect(conn, server) do
    case server.sign_in_path() do
      path when is_binary(path) ->
        return_to =
          conn.request_path <>
            if conn.query_string != "", do: "?" <> conn.query_string, else: ""

        # AshAuthentication.Phoenix sign-in handlers read `:return_to` from
        # session, not from the query string. Put it in both so any
        # convention works.
        conn
        |> Plug.Conn.put_session(:return_to, return_to)
        |> put_resp_header(
          "location",
          path <> "?" <> URI.encode_query(%{"return_to" => return_to})
        )
        |> send_resp(302, "")
        |> halt()

      _ ->
        conn |> send_resp(401, "authentication required") |> halt()
    end
  end

  # sobelow_skip ["XSS.SendResp"]
  defp bad_redirect_html(conn) do
    body = """
    <!DOCTYPE html>
    <html lang="en"><head><meta charset="UTF-8"><title>Invalid redirect URI</title>
    <style>body{font-family:system-ui,sans-serif;max-width:480px;margin:4rem auto;padding:0 1rem}</style>
    </head><body><h1>Invalid redirect URI</h1>
    <p>The <code>redirect_uri</code> does not match any registered redirect URI for this client.</p>
    <p>For security reasons, we cannot redirect you back. Please contact the application that sent you here.</p>
    </body></html>
    """

    conn
    |> put_resp_header("content-type", "text/html; charset=utf-8")
    |> send_resp(400, body)
    |> halt()
  end

  # sobelow_skip ["XSS.SendResp"]
  defp bad_state_html(conn) do
    body = """
    <!DOCTYPE html>
    <html lang="en"><head><meta charset="UTF-8"><title>Request too large</title>
    <style>body{font-family:system-ui,sans-serif;max-width:480px;margin:4rem auto;padding:0 1rem}</style>
    </head><body><h1>Request too large</h1>
    <p>The <code>state</code> parameter exceeds the maximum permitted size.</p>
    </body></html>
    """

    conn
    |> put_resp_header("content-type", "text/html; charset=utf-8")
    |> send_resp(400, body)
    |> halt()
  end

  defp get_csrf_token do
    Plug.CSRFProtection.get_csrf_token()
  rescue
    _ -> ""
  end

  # Bind the user-visible consent UI to the values that drove the code
  # issuance. The token captures everything an attacker might want to
  # silently swap (scope, code_challenge, redirect_uri, state, resource,
  # client_id) and is verified before the POST is honoured.
  defp mint_consent_request(server, validated) do
    payload = %{
      "client_id" => validated.client.id,
      "redirect_uri" => validated.redirect_uri,
      "code_challenge" => validated.code_challenge,
      "scope" => validated.scope,
      "state" => validated.state,
      "resource" => validated.resource
    }

    Plug.Crypto.sign(server.signing_secret(), @consent_request_salt, payload)
  end

  defp verify_consent_request(server, token) when is_binary(token) and token != "" do
    case Plug.Crypto.verify(server.signing_secret(), @consent_request_salt, token,
           max_age: @consent_request_max_age
         ) do
      {:ok, payload} when is_map(payload) -> {:ok, sealed_params(payload)}
      _ -> {:error, :invalid}
    end
  end

  defp verify_consent_request(_server, _token), do: {:error, :invalid}

  # Rebuild the protocol params from the sealed payload so `validate_request`
  # operates on trusted server-side values, not the form's hidden inputs.
  defp sealed_params(sealed) do
    %{
      "response_type" => "code",
      "code_challenge_method" => "S256",
      "client_id" => Map.get(sealed, "client_id"),
      "redirect_uri" => Map.get(sealed, "redirect_uri"),
      "code_challenge" => Map.get(sealed, "code_challenge"),
      "scope" => Map.get(sealed, "scope"),
      "state" => Map.get(sealed, "state"),
      "resource" => Map.get(sealed, "resource")
    }
  end
end
