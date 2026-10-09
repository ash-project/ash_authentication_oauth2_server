# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Phoenix.Oauth2Server.ConsentRouterTest do
  @moduledoc """
  Exercises preparation and completion of application-owned consent flows.
  Covers parsing, sealed requests, validation and authentication failures,
  rendering, committed-consent hand-back, session renewal and tenant isolation.
  Uses the library's ETS fixtures and never makes network requests.
  """
  use ExUnit.Case, async: false

  import Plug.Conn
  import Plug.Test

  alias AshAuthentication.Oauth2Server.{Authorize, PKCE}
  alias AshAuthentication.Phoenix.Oauth2Server.ConsentRouter
  alias Oauth2ServerTest.{OAuthAuthorizationCode, OAuthClient, OAuthConsent, Server, User}

  alias Oauth2ServerTest.{
    TenantedOAuthAuthorizationCode,
    TenantedOAuthClient,
    TenantedOAuthConsent,
    TenantedServer,
    TenantedUser
  }

  @request_salt "ash_authentication_phoenix oauth2_server consent_request v1"
  @redirect_uri "https://chat.example.com/cb"

  defmodule RecordingView do
    def render(:consent, assigns) do
      send(self(), {:consent_assigns, assigns})
      "<form method=\"post\"></form>"
    end
  end

  defmodule RaisingView do
    def render(:consent, _assigns), do: raise("custom consent view failed")
  end

  defmodule TenantIssuerServer do
    defdelegate authorization_code_resource(), to: TenantedServer
    defdelegate authorization_code_lifetime(), to: TenantedServer
    defdelegate client_resource(), to: TenantedServer
    defdelegate consent_resource(), to: TenantedServer
    defdelegate issuer_url(), to: TenantedServer
    defdelegate resources(), to: TenantedServer
    defdelegate resource_scopes(resource), to: TenantedServer
    defdelegate resource_url(resource, context), to: TenantedServer
    defdelegate signing_secret(), to: TenantedServer
    defdelegate scopes(), to: TenantedServer
    defdelegate enforce_scopes?(), to: TenantedServer
    defdelegate cimd_enabled?(), to: TenantedServer
    defdelegate sign_in_path(), to: TenantedServer

    def issuer_url(%{tenant: tenant}), do: "https://#{tenant}.example.com"
  end

  defmodule SignInServer do
    defdelegate client_resource(), to: Server
    defdelegate resources(), to: Server
    defdelegate resource_scopes(resource), to: Server
    defdelegate resource_url(resource, context), to: Server
    defdelegate signing_secret(), to: Server
    defdelegate scopes(), to: Server
    defdelegate enforce_scopes?(), to: Server
    defdelegate cimd_enabled?(), to: Server

    def sign_in_path, do: "/sign-in"
  end

  defmodule RecordingConsentServer do
    defdelegate client_resource(), to: Server
    defdelegate resources(), to: Server
    defdelegate resource_scopes(resource), to: Server
    defdelegate resource_url(resource, context), to: Server
    defdelegate signing_secret(), to: Server
    defdelegate scopes(), to: Server
    defdelegate enforce_scopes?(), to: Server
    defdelegate cimd_enabled?(), to: Server
    defdelegate sign_in_path(), to: Server
    defdelegate authorization_code_resource(), to: Server
    defdelegate authorization_code_lifetime(), to: Server
    defdelegate issuer_url(), to: Server

    def consent_resource do
      send(self(), :consent_resource_requested)
      Server.consent_resource()
    end
  end

  defmodule RecordingCimdFetcher do
    @behaviour AshAuthentication.Oauth2Server.CIMD.Fetcher

    @impl true
    def fetch(url, opts) do
      send(self(), {:metadata_fetched, url})
      Oauth2ServerTest.StubFetcher.fetch(url, opts)
    end
  end

  defmodule RecordingCimdServer do
    defdelegate client_resource(), to: Server
    defdelegate resources(), to: Server
    defdelegate resource_scopes(resource), to: Server
    defdelegate resource_url(resource, context), to: Server
    defdelegate signing_secret(), to: Server
    defdelegate scopes(), to: Server
    defdelegate enforce_scopes?(), to: Server
    defdelegate issuer_url(), to: Server

    defdelegate cimd_fetch_options(), to: Server
    def cimd_enabled?, do: true
    def cimd_fetcher, do: RecordingCimdFetcher
  end

  defmodule VanishingClientServer do
    defdelegate client_resource(), to: Server
    defdelegate cimd_enabled?(), to: Server
    defdelegate enforce_scopes?(), to: Server

    def scopes do
      Ash.bulk_destroy!(OAuthClient, :destroy, %{}, return_errors?: true)
      Server.scopes()
    end
  end

  setup do
    Oauth2ServerTest.StubFetcher.clear()
    on_exit(fn -> Oauth2ServerTest.StubFetcher.clear() end)

    for resource <- [
          OAuthAuthorizationCode,
          OAuthClient,
          OAuthConsent,
          User,
          TenantedOAuthAuthorizationCode,
          TenantedOAuthClient,
          TenantedOAuthConsent,
          TenantedUser
        ] do
      Ash.bulk_destroy!(resource, :destroy, %{}, return_errors?: true)
    end

    user =
      User |> Ash.Changeset.for_create(:create, %{email: "alice@example.com"}) |> Ash.create!()

    client =
      OAuthClient
      |> Ash.Changeset.for_create(:register, %{
        client_name: "Consent preparation test",
        redirect_uris: [@redirect_uri]
      })
      |> Ash.create!()

    {:ok, user: user, client: client, params: authorize_params(client.id)}
  end

  describe "prepare/2" do
    test "returns validated GET context without rendering, granting or issuing", context do
      {:ok, conn, request} = prepare_get(context)
      assert conn.state == :unset
      refute conn.halted
      assert request.server == Server
      assert request.user.id == context.user.id
      assert request.tenant == nil
      assert request.tenant_opts == []
      assert request.method == "GET"
      assert request.action == nil
      assert request.validated.client.id == context.client.id
      assert request.validated.state == context.params["state"]
      assert request.validated.scope == "mcp"
      assert_no_writes()
    end

    test "keeps rendering options out of GET and POST requests", context do
      for conn <- [
            conn(:get, "/oauth/authorize?" <> URI.encode_query(context.params)),
            conn(:post, "/oauth/authorize", %{
              "consent_request" => sign(context.params),
              "action" => "approve"
            })
          ] do
        assert {:ok, _conn, request} =
                 ConsentRouter.prepare(browser(conn, context.user),
                   oauth2_server: Server,
                   consent_view: RecordingView
                 )

        refute Map.has_key?(request, :consent_view)
        assert_no_writes()
      end
    end

    test "does not short-circuit application checks when OAuth consent exists", context do
      Authorize.grant_consent!(Server, context.user, context.client, "mcp")
      {:ok, conn, _request} = prepare_get(context)
      assert conn.state == :unset
      assert {:ok, []} = Ash.read(OAuthAuthorizationCode)
    end

    test "parses POST bodies and ignores unsealed protocol fields", context do
      form = %{
        "consent_request" => sign(context.params),
        "action" => "approve",
        "selection" => "workspace-a",
        "client_id" => "other-client",
        "redirect_uri" => "https://other.example.com/cb",
        "scope" => "unapproved-scope",
        "code_challenge" => "unapproved-challenge"
      }

      conn =
        conn(:post, "/oauth/authorize", URI.encode_query(form))
        |> put_req_header("content-type", "application/x-www-form-urlencoded")
        |> browser(context.user)

      assert {:ok, conn, request} = ConsentRouter.prepare(conn, oauth2_server: Server)
      assert conn.params["selection"] == "workspace-a"
      assert request.method == "POST"
      assert request.action == "approve"
      assert request.validated.client.id == context.client.id
      assert request.validated.redirect_uri == @redirect_uri
      assert request.validated.scope == "mcp"
      assert request.validated.code_challenge == context.params["code_challenge"]
      assert_no_writes()
    end

    test "reconstructs only the supported code and PKCE fields", context do
      payload =
        Map.merge(context.params, %{
          "response_type" => "token",
          "code_challenge_method" => "plain",
          "workspace_id" => "not-an-oauth-parameter"
        })

      {:ok, _conn, request} = prepare_post(context, sign(payload))
      assert request.validated.code_challenge == context.params["code_challenge"]
      refute Map.has_key?(request.validated, :workspace_id)
    end

    test "validates again after token verification", context do
      token = sign(context.params)
      Ash.destroy!(context.client)
      {:halt, conn} = prepare_post(context, token)
      assert conn.status == 400
      assert Jason.decode!(conn.resp_body)["error"] == "invalid_client"
      assert get_resp_header(conn, "location") == []
      assert_no_writes()
    end

    test "rejects missing, empty, malformed, non-string and modified tokens", context do
      for token <- [nil, "", "tampered", 123, %{}, [], sign(context.params) <> "tampered"] do
        {:halt, conn} = prepare_post(context, token)
        assert conn.status == 400
        assert conn.halted
        assert get_resp_header(conn, "location") == []
        assert Jason.decode!(conn.resp_body)["error"] == "invalid_request"
        assert_no_writes()
      end
    end

    test "rejects expired, wrong-secret and signed non-map tokens", context do
      for token <- [
            Plug.Crypto.sign(Server.signing_secret(), @request_salt, context.params,
              signed_at: System.os_time(:second) - 601
            ),
            Plug.Crypto.sign("different-test-signing-secret", @request_salt, context.params),
            sign(["not a request"])
          ] do
        {:halt, conn} = prepare_post(context, token)
        assert conn.status == 400
        assert get_resp_header(conn, "location") == []
        assert_no_writes()
      end
    end

    test "requires an authenticated actor on GET and POST", context do
      for conn <- [
            conn(:get, "/oauth/authorize?" <> URI.encode_query(context.params)),
            conn(:post, "/oauth/authorize", %{
              "consent_request" => sign(context.params),
              "action" => "approve"
            })
          ] do
        assert {:halt, conn} =
                 ConsentRouter.prepare(init_test_session(conn, %{}), oauth2_server: Server)

        assert conn.status == 401
        assert conn.halted
        assert get_resp_header(conn, "location") == []
        assert_no_writes()
      end
    end

    test "stores full sign-in return paths without losing session data", context do
      for path <- ["/oauth/authorize", "/oauth/authorize?hint=example"] do
        conn =
          conn(:get, path)
          |> Map.put(:query_params, context.params)
          |> init_test_session(%{preserved: "value"})

        assert {:halt, conn} = ConsentRouter.prepare(conn, oauth2_server: SignInServer)
        assert conn.status == 302
        assert conn.halted
        assert get_session(conn, :return_to) == path
        assert get_session(conn, :preserved) == "value"
        [location] = get_resp_header(conn, "location")
        assert URI.parse(location).path == "/sign-in"
        assert redirect_query(conn) == %{"return_to" => path}
      end
    end

    test "rejects oversized state before protocol work", context do
      params = Map.put(context.params, "state", String.duplicate("s", 2049))
      {:halt, conn} = prepare_get(%{context | params: params})
      assert conn.status == 400
      assert get_resp_header(conn, "location") == []
      assert get_resp_header(conn, "content-type") == ["text/html; charset=utf-8"]
      assert_no_writes()
    end

    test "accepts state at the existing size boundary", context do
      params = Map.put(context.params, "state", String.duplicate("s", 2048))
      assert {:ok, _, _} = prepare_get(%{context | params: params})
    end

    test "rejects missing and invalid POST decisions after request validation", context do
      for action <- [nil, "", "other", 123] do
        {:halt, conn} = prepare_post(context, sign(context.params), action)
        assert conn.status == 400
        assert Jason.decode!(conn.resp_body)["error"] == "invalid_request"
        assert get_resp_header(conn, "location") == []
        assert_no_writes()
      end
    end

    test "returns a halted 404 for unsupported methods", context do
      for method <- [:put, :delete] do
        conn = conn(method, "/oauth/authorize") |> browser(context.user)
        assert {:halt, conn} = ConsentRouter.prepare(conn, oauth2_server: Server)
        assert conn.status == 404
        assert conn.halted
        assert_no_writes()
      end
    end

    test "propagates malformed URL-encoded body errors", context do
      conn =
        conn(:post, "/oauth/authorize", "selection=%FF")
        |> put_req_header("content-type", "application/x-www-form-urlencoded")
        |> browser(context.user)

      assert_raise Plug.Parsers.BadEncodingError, fn ->
        ConsentRouter.prepare(conn, oauth2_server: Server)
      end

      assert_no_writes()
    end

    test "propagates missing required configuration", context do
      conn = conn(:get, "/oauth/authorize") |> browser(context.user)
      assert_raise KeyError, fn -> ConsentRouter.prepare(conn, []) end
      assert_no_writes()
    end

    test "retains parser passthrough and rejects a missing consent token", context do
      conn =
        conn(:post, "/oauth/authorize", "raw body")
        |> put_req_header("content-type", "application/octet-stream")
        |> browser(context.user)

      {:halt, conn} = ConsentRouter.prepare(conn, oauth2_server: Server)
      assert conn.status == 400
      assert_no_writes()
    end

    test "redirects protocol errors only to a registered callback", context do
      params = Map.put(context.params, "scope", "not-advertised")
      {:halt, conn} = prepare_get(%{context | params: params})
      assert conn.status == 302

      assert redirect_query(conn) == %{
               "error" => "invalid_scope",
               "error_description" => "scope not-advertised is not allowed",
               "state" => context.params["state"],
               "iss" => Server.issuer_url()
             }

      assert_no_writes()
    end

    test "responds directly for unknown clients and unsafe or incomplete redirects", context do
      for params <- [
            Map.put(context.params, "client_id", Ash.UUIDv7.generate()),
            Map.put(context.params, "redirect_uri", "https://other.example.com/cb"),
            Map.put(context.params, "client_id", ""),
            Map.put(context.params, "redirect_uri", %{"nested" => "value"}),
            Map.put(context.params, "client_id", 123),
            %{}
          ] do
        {:halt, conn} = prepare_get(%{context | params: params})
        assert conn.status == 400
        assert conn.halted
        assert get_resp_header(conn, "location") == []
        assert_no_writes()
      end
    end

    test "does not resolve URL clients when CIMD is disabled", context do
      params = Map.put(context.params, "client_id", "https://client.example.com/metadata.json")
      {:halt, conn} = prepare_get(%{context | params: params})
      assert conn.status == 400
      assert get_resp_header(conn, "location") == []
    end

    test "resolves CIMD during validation but never refetches for the error redirect", context do
      start_supervised!({AshAuthentication.Oauth2Server.CIMD.Cache, []})
      url = "https://client.example.com/metadata.json"
      params = Map.merge(context.params, %{"client_id" => url, "response_type" => "token"})
      Oauth2ServerTest.StubFetcher.stub(url, {:error, :not_found})
      {:halt, conn} = prepare_get(%{context | params: params}, RecordingCimdServer)
      assert conn.status == 400
      assert get_resp_header(conn, "location") == []
      assert_received {:metadata_fetched, ^url}
      refute_received {:metadata_fetched, _}

      Oauth2ServerTest.StubFetcher.stub(url, %{
        document: %{
          "client_id" => url,
          "client_name" => "Resolved client",
          "redirect_uris" => [@redirect_uri]
        },
        cache_ttl: 0
      })

      {:halt, conn} = prepare_get(%{context | params: params}, RecordingCimdServer)
      assert conn.status == 302
      assert redirect_query(conn)["error"] == "unsupported_response_type"
      assert redirect_query(conn)["iss"] == Server.issuer_url()
      assert_received {:metadata_fetched, ^url}
      refute_received {:metadata_fetched, _}
      assert_no_writes()
    end

    test "responds directly to every current client-validation error on GET and POST", context do
      for {params, get_error, post_error} <- [
            {Map.delete(context.params, "client_id"), "invalid_request", "invalid_request"},
            {Map.put(context.params, "client_id", %{"nested" => "value"}), "invalid_request",
             "invalid_request"},
            {Map.put(context.params, "client_id", 123), "invalid_client", "invalid_request"},
            {Map.put(context.params, "client_id", ""), "invalid_request", "invalid_request"},
            {Map.put(context.params, "client_id", Ash.UUIDv7.generate()), "invalid_client",
             "invalid_client"}
          ] do
        for {result, error} <- [
              {prepare_get(%{context | params: params}), get_error},
              {prepare_post(context, sign(params)), post_error}
            ] do
          assert {:halt, conn} = result
          assert conn.status == 400
          assert conn.halted
          assert get_resp_header(conn, "location") == []
          assert Jason.decode!(conn.resp_body)["error"] == error
          assert_no_writes()
        end
      end
    end

    test "defaults an omitted or empty callback to the only registered URI", context do
      for params <- [
            Map.delete(context.params, "redirect_uri"),
            Map.put(context.params, "redirect_uri", "")
          ] do
        assert {:ok, _, request} = prepare_get(%{context | params: params})
        assert request.validated.redirect_uri == @redirect_uri

        {:halt, conn} = prepare_get(%{context | params: Map.put(params, "scope", "unknown")})
        assert conn.status == 302
        assert URI.parse(hd(get_resp_header(conn, "location"))).path == "/cb"
        assert redirect_query(conn)["error"] == "invalid_scope"
        assert_no_writes()
      end
    end

    test "does not default the callback when several URIs are registered", context do
      client =
        OAuthClient
        |> Ash.Changeset.for_create(:register, %{
          client_name: "Multiple callbacks",
          redirect_uris: [@redirect_uri, "https://chat.example.com/other"]
        })
        |> Ash.create!()

      params = context.params |> Map.put("client_id", client.id) |> Map.delete("redirect_uri")
      {:halt, conn} = prepare_get(%{context | params: params})
      assert conn.status == 400
      assert get_resp_header(conn, "location") == []
      assert_no_writes()
    end

    test "responds directly if the validated client disappears before an error redirect",
         context do
      params = Map.put(context.params, "scope", "unknown")
      {:halt, conn} = prepare_get(%{context | params: params}, VanishingClientServer)
      assert conn.status == 400
      assert Jason.decode!(conn.resp_body)["error"] == "invalid_scope"
      assert get_resp_header(conn, "location") == []
      assert_no_writes()
    end

    test "keeps exact callback matching and omits malformed state from protocol errors",
         context do
      {:halt, conn} =
        prepare_get(%{
          context
          | params: Map.put(context.params, "redirect_uri", "HTTPS://CHAT.EXAMPLE.COM/cb")
        })

      assert conn.status == 400
      assert get_resp_header(conn, "location") == []

      conn =
        conn(
          :get,
          "/oauth/authorize?" <>
            URI.encode_query(Map.delete(context.params, "state")) <> "&state[x]=y"
        )
        |> browser(context.user)

      {:halt, conn} = ConsentRouter.prepare(conn, oauth2_server: Server)
      assert conn.status == 302
      assert redirect_query(conn)["error"] == "invalid_request"
      refute Map.has_key?(redirect_query(conn), "state")
      assert_no_writes()
    end
  end

  describe "complete/4" do
    test "uses the default consent view when rendering options are omitted", context do
      {:ok, conn, request} = prepare_get(context)
      conn = ConsentRouter.complete(conn, request, {:render, %{}})
      assert conn.status == 200
      assert conn.halted
      assert conn.resp_body =~ "<form method=\"POST\" action=\"/oauth/authorize\">"
      assert conn.resp_body =~ "name=\"consent_request\""
      assert conn.resp_body =~ context.client.client_name
      refute_received {:consent_assigns, _}
      assert_no_writes()
    end

    test "renders signed form fields and keeps protocol assigns authoritative", context do
      {:ok, conn, request} = prepare_get(context)

      conn =
        ConsentRouter.complete(
          conn,
          request,
          {:render,
           %{
             selection: "workspace-a",
             scope: "fake",
             client_id: "fake",
             user: nil,
             tenant: "other",
             action_path: "/other",
             csrf_token: "fake",
             consent_request: "fake"
           }},
          consent_view: RecordingView
        )

      assert conn.status == 200
      assert conn.halted
      assert get_resp_header(conn, "content-type") == ["text/html; charset=utf-8"]
      assert get_resp_header(conn, "x-frame-options") == ["DENY"]
      assert get_resp_header(conn, "content-security-policy") == ["frame-ancestors 'none'"]
      assert_received {:consent_assigns, assigns}
      assert assigns.scope == "mcp"
      assert assigns.user.id == context.user.id
      assert assigns.tenant == nil
      assert assigns.selection == "workspace-a"
      assert assigns.action_path == "/oauth/authorize"
      assert assigns.client_id == context.client.id
      assert is_binary(assigns.csrf_token)
      refute assigns.csrf_token == "fake"
      assert is_binary(assigns.consent_request)
      refute assigns.consent_request == "fake"
      {:ok, _conn, post_request} = prepare_post(context, assigns.consent_request)
      assert post_request.validated == request.validated
      assert_no_writes()
    end

    test "rerenders a prepared POST without granting, issuing or renewing", context do
      {:ok, conn, request} = prepare_post(context, sign(context.params))

      conn =
        ConsentRouter.complete(conn, request, {:render, %{validation_error: "Choose access"}},
          consent_view: RecordingView
        )

      assert conn.status == 200
      refute Map.get(conn.private, :plug_session_info) == :renew
      assert_received {:consent_assigns, %{validation_error: "Choose access"}}
      assert_no_writes()
    end

    test "propagates custom view failures without consent or code writes", context do
      {:ok, conn, request} = prepare_get(context)

      assert_raise RuntimeError, "custom consent view failed", fn ->
        ConsentRouter.complete(conn, request, {:render, %{}}, consent_view: RaisingView)
      end

      assert_no_writes()
    end

    test "retains the default CSRF-token error fallback", context do
      {:ok, conn, request} = prepare_get(context)
      Plug.CSRFProtection.delete_csrf_token()
      Plug.CSRFProtection.load_state(conn.secret_key_base, "")

      try do
        conn = ConsentRouter.complete(conn, request, {:render, %{}}, consent_view: RecordingView)
        assert conn.status == 200
        assert_received {:consent_assigns, %{csrf_token: ""}}
        assert_no_writes()
      after
        Plug.CSRFProtection.delete_csrf_token()
      end
    end

    test "completes committed approval without creating or refreshing consent", context do
      {:ok, conn, request} =
        prepare_post(context, sign(context.params), "approve", RecordingConsentServer)

      consent = Authorize.grant_consent!(Server, context.user, context.client, "mcp")
      conn = ConsentRouter.complete(conn, request, :approved, consent_view: RaisingView)
      assert conn.status == 302
      assert conn.halted
      assert conn.private.plug_session_info == :renew
      refute_received :consent_resource_requested
      assert_unchanged_consent(consent)
      assert {:ok, [code]} = Ash.read(OAuthAuthorizationCode)
      assert code.user_id == context.user.id
      assert code.client_id == context.client.id
      assert code.code_challenge == context.params["code_challenge"]
      assert code.scope == "mcp"

      assert redirect_query(conn) == %{
               "code" => code.id,
               "state" => context.params["state"],
               "iss" => Server.issuer_url()
             }
    end

    test "finishes reused GET consent without renewing or writing consent", context do
      consent = Authorize.grant_consent!(Server, context.user, context.client, "mcp")
      {:ok, conn, request} = prepare_get(context)
      conn = ConsentRouter.complete(conn, request, :approved, consent_view: RaisingView)
      assert conn.status == 302
      refute Map.get(conn.private, :plug_session_info) == :renew
      assert_unchanged_consent(consent)
      assert {:ok, [_]} = Ash.read(OAuthAuthorizationCode)
    end

    test "does not record consent on the application's behalf", context do
      {:ok, conn, request} = prepare_post(context, sign(context.params))
      conn = ConsentRouter.complete(conn, request, :approved)
      assert conn.status == 302
      assert {:ok, []} = Ash.read(OAuthConsent)
      assert {:ok, [_]} = Ash.read(OAuthAuthorizationCode)
    end

    test "propagates issuance failures without rolling back committed consent", context do
      {:ok, conn, request} = prepare_post(context, sign(context.params))
      consent = Authorize.grant_consent!(Server, context.user, context.client, "mcp")
      request = %{request | user: %{id: "invalid"}}
      assert_raise Ash.Error.Invalid, fn -> ConsentRouter.complete(conn, request, :approved) end
      assert {:ok, []} = Ash.read(OAuthAuthorizationCode)
      assert_unchanged_consent(consent)
    end

    test "denies without granting, issuing or renewing", context do
      {:ok, conn, request} = prepare_post(context, sign(context.params), "deny")
      conn = ConsentRouter.complete(conn, request, :denied, consent_view: RaisingView)
      assert conn.status == 302
      assert conn.halted
      refute Map.get(conn.private, :plug_session_info) == :renew

      assert redirect_query(conn) == %{
               "error" => "access_denied",
               "state" => context.params["state"],
               "iss" => Server.issuer_url()
             }

      assert_no_writes()
    end

    test "returns application errors and omits empty descriptions", context do
      for description <- [nil, "", "Consent could not be saved"] do
        {:ok, conn, request} = prepare_post(context, sign(context.params))

        conn =
          ConsentRouter.complete(conn, request, {:error, "server_error", description},
            consent_view: RaisingView
          )

        assert conn.status == 302
        assert conn.halted
        assert redirect_query(conn)["error"] == "server_error"
        assert redirect_query(conn)["iss"] == Server.issuer_url()
        refute Map.get(conn.private, :plug_session_info) == :renew

        if description in [nil, ""] do
          refute Map.has_key?(redirect_query(conn), "error_description")
        else
          assert redirect_query(conn)["error_description"] == description
        end

        assert_no_writes()
      end
    end

    test "rejects approving a denied submission and unsupported completion results", context do
      {:ok, conn, request} = prepare_post(context, sign(context.params), "deny")
      assert_raise ArgumentError, fn -> ConsentRouter.complete(conn, request, :approved) end

      for decision <- [
            :unknown,
            {:render, nil},
            {:error, 123, nil},
            {:error, "server_error", %{}}
          ] do
        assert_raise ArgumentError, fn -> ConsentRouter.complete(conn, request, decision) end
      end

      assert_no_writes()
    end

    test "keeps the low-level helpers private" do
      Code.ensure_loaded!(ConsentRouter)

      for {function, arity} <- [
            mint_consent_request: 2,
            verify_consent_request: 2,
            issue_code_redirect: 2,
            redirect_authorize_error: 5,
            redirect_with_oauth_error: 6,
            sign_in_redirect: 2
          ] do
        refute function_exported?(ConsentRouter, function, arity)
      end
    end
  end

  describe "current OAuth response behavior" do
    test "preserves existing callback queries for approval, denial and application errors",
         context do
      for {registered, prefix} <- [
            {"https://chat.example.com/cb?app=1", "https://chat.example.com/cb?app=1&"},
            {"https://chat.example.com/cb?", "https://chat.example.com/cb?"},
            {"https://chat.example.com:443/cb?app=1", "https://chat.example.com:443/cb?app=1&"}
          ] do
        client =
          OAuthClient
          |> Ash.Changeset.for_create(:register, %{
            client_name: "Callback query",
            redirect_uris: [registered]
          })
          |> Ash.create!()

        params =
          context.params |> Map.put("client_id", client.id) |> Map.put("redirect_uri", registered)

        context = %{context | client: client, params: params}
        consent = Authorize.grant_consent!(Server, context.user, client, "mcp")

        for decision <- [:approved, :denied, {:error, "server_error", "Could not save consent"}] do
          {:ok, conn, request} = prepare_post(context, sign(params))
          conn = ConsentRouter.complete(conn, request, decision)
          assert conn.status == 302
          [location] = get_resp_header(conn, "location")
          assert String.starts_with?(location, prefix)

          assert redirect_query(conn)["app"] ==
                   if(URI.parse(registered).query == "app=1", do: "1", else: nil)

          assert redirect_query(conn)["state"] == params["state"]
          assert redirect_query(conn)["iss"] == Server.issuer_url()
          assert {:ok, stored} = Ash.get(OAuthConsent, consent.id)
          assert stored.granted_at == consent.granted_at
        end
      end
    end

    test "omits absent or empty state from GET and sealed POST responses", context do
      for params <- [Map.delete(context.params, "state"), Map.put(context.params, "state", "")] do
        context = %{context | params: params}
        Authorize.grant_consent!(Server, context.user, context.client, "mcp")
        {:ok, conn, request} = prepare_get(context)
        assert request.validated.state == nil
        conn = ConsentRouter.complete(conn, request, {:render, %{}}, consent_view: RecordingView)
        assert conn.status == 200
        assert_received {:consent_assigns, %{consent_request: token}}

        for decision <- [:approved, :denied, {:error, "server_error", nil}],
            method <- [:get, :post] do
          {:ok, conn, request} =
            if method == :get,
              do: prepare_get(context),
              else: prepare_post(context, token)

          conn = ConsentRouter.complete(conn, request, decision)
          assert conn.status == 302
          refute Map.has_key?(redirect_query(conn), "state")
          assert redirect_query(conn)["iss"] == Server.issuer_url()
        end
      end
    end

    test "keeps multiple-resource selection in the prepared context and authorization code",
         context do
      for resource <- [:mcp, :gql] do
        params =
          context.params
          |> Map.put("scope", Atom.to_string(resource))
          |> Map.put("resource", Oauth2ServerTest.MultiResourceServer.resource_url(resource))

        {:ok, conn, request} =
          prepare_get(%{context | params: params}, Oauth2ServerTest.MultiResourceServer)

        Authorize.grant_consent!(
          request.server,
          request.user,
          request.validated.client,
          request.validated.scope
        )

        conn = ConsentRouter.complete(conn, request, :approved)
        assert conn.status == 302
        assert {:ok, code} = Ash.get(OAuthAuthorizationCode, redirect_query(conn)["code"])
        assert code.resource_uri == params["resource"]
        assert code.scope == Atom.to_string(resource)
      end
    end
  end

  describe "tenant context" do
    test "uses one tenant for validation, grants, issuance and issuer resolution" do
      context = tenant_context("tenant-a")
      {:ok, conn, request} = prepare_get(context, TenantIssuerServer)
      assert request.tenant == "tenant-a"
      assert request.tenant_opts == [tenant: "tenant-a"]

      conn = ConsentRouter.complete(conn, request, {:render, %{}}, consent_view: RecordingView)
      assert conn.status == 200
      assert_received {:consent_assigns, %{tenant: "tenant-a", consent_request: token}}
      {:ok, conn, request} = prepare_post(context, token, "approve", TenantIssuerServer)

      Authorize.grant_consent!(
        request.server,
        request.user,
        request.validated.client,
        request.validated.scope,
        request.tenant_opts
      )

      conn = ConsentRouter.complete(conn, request, :approved)
      assert redirect_query(conn)["iss"] == "https://tenant-a.example.com"
      assert {:ok, [code]} = Ash.read(TenantedOAuthAuthorizationCode, tenant: "tenant-a")
      assert code.org_id == "tenant-a"
      assert {:ok, []} = Ash.read(TenantedOAuthAuthorizationCode, tenant: "tenant-b")
      assert {:ok, [_]} = Ash.read(TenantedOAuthConsent, tenant: "tenant-a")
      assert {:ok, []} = Ash.read(TenantedOAuthConsent, tenant: "tenant-b")
    end

    test "requires registered clients to belong to the current tenant" do
      context = tenant_context("tenant-a")

      for {tenant, expected_status} <- [{"tenant-a", 302}, {"tenant-b", 400}] do
        context = %{context | tenant: tenant, params: Map.put(context.params, "scope", "unknown")}
        {:halt, conn} = prepare_get(context, TenantIssuerServer)
        assert conn.status == expected_status

        if tenant == "tenant-b" do
          assert get_resp_header(conn, "location") == []
        else
          assert redirect_query(conn)["iss"] == "https://tenant-a.example.com"
        end
      end
    end

    test "uses distinct issuers for denied requests in each tenant and without a tenant",
         context do
      for {context, server, issuer} <- [
            {context, Server, "https://app.example.com"},
            {tenant_context("tenant-a"), TenantIssuerServer, "https://tenant-a.example.com"},
            {tenant_context("tenant-b"), TenantIssuerServer, "https://tenant-b.example.com"}
          ] do
        {:ok, conn, request} = prepare_post(context, sign(context.params), "deny", server)
        conn = ConsentRouter.complete(conn, request, :denied)
        assert redirect_query(conn)["iss"] == issuer
      end
    end
  end

  defp prepare_get(context, server \\ Server) do
    conn =
      conn(:get, "/oauth/authorize?" <> Plug.Conn.Query.encode(context.params))
      |> browser(context.user)
      |> Ash.PlugHelpers.set_tenant(Map.get(context, :tenant))

    ConsentRouter.prepare(conn, oauth2_server: server)
  end

  defp prepare_post(context, token, action \\ "approve", server \\ Server) do
    conn =
      conn(:post, "/oauth/authorize", %{"consent_request" => token, "action" => action})
      |> browser(context.user)
      |> Ash.PlugHelpers.set_tenant(Map.get(context, :tenant))

    ConsentRouter.prepare(conn, oauth2_server: server)
  end

  defp browser(conn, user), do: conn |> init_test_session(%{}) |> Ash.PlugHelpers.set_actor(user)
  defp sign(payload), do: Plug.Crypto.sign(Server.signing_secret(), @request_salt, payload)

  defp authorize_params(client_id) do
    %{
      "response_type" => "code",
      "client_id" => client_id,
      "redirect_uri" => @redirect_uri,
      "code_challenge" => PKCE.challenge("test-verifier-test-verifier-test-verifier-1234"),
      "code_challenge_method" => "S256",
      "scope" => "mcp",
      "state" => "state",
      "resource" => Server.resource_url()
    }
  end

  defp tenant_context(tenant) do
    user =
      TenantedUser
      |> Ash.Changeset.for_create(:create, %{email: "#{tenant}@example.com", org_id: tenant})
      |> Ash.create!(tenant: tenant)

    client =
      TenantedOAuthClient
      |> Ash.Changeset.for_create(
        :register,
        %{client_name: "Tenant client", redirect_uris: [@redirect_uri]},
        tenant: tenant
      )
      |> Ash.create!(tenant: tenant)

    %{user: user, client: client, params: authorize_params(client.id), tenant: tenant}
  end

  defp assert_unchanged_consent(consent) do
    assert {:ok, [stored]} = Ash.read(OAuthConsent)
    fields = [:id, :user_id, :client_id, :scope, :granted_at]
    assert Map.take(stored, fields) == Map.take(consent, fields)
  end

  defp assert_no_writes do
    assert {:ok, []} = Ash.read(OAuthAuthorizationCode)
    assert {:ok, []} = Ash.read(OAuthConsent)
  end

  defp redirect_query(conn) do
    [location] = get_resp_header(conn, "location")
    location |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
  end
end
