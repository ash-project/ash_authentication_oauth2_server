# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Phoenix.Oauth2Server.RouterTest do
  @moduledoc """
  HTTP-level test for the Oauth2Server routers, driven through Plug.Test.

  Protocol-level correctness (PKCE, JWT claims, code consume, etc.) is
  covered in the `ash_authentication` core tests. This file only validates
  the HTTP surface — status codes, headers, JSON shapes, redirects, route
  splitting between ConsentRouter and ProtocolRouter.
  """
  use ExUnit.Case, async: false

  import Plug.Test
  import Plug.Conn

  require Ash.Query

  alias AshAuthentication.Oauth2Server.{Authorize, Jwt, PKCE, Token}

  alias AshAuthentication.Phoenix.Oauth2Server.{ConsentRouter, Errors, ProtocolRouter}
  alias Oauth2ServerTest.Server

  alias Oauth2ServerTest.{
    OAuthAuthorizationCode,
    OAuthClient,
    OAuthConsent,
    OAuthRefreshToken,
    User
  }

  @consent_opts ConsentRouter.init(oauth2_server: Server)
  @protocol_opts ProtocolRouter.init(oauth2_server: Server)

  # A real Phoenix router wired through the public macro, so the `/oauth` and
  # `/.well-known` mounts exercise Phoenix's prefix-stripping `forward` exactly
  # as an application would.
  defmodule PhoenixRouterFixture do
    use Phoenix.Router
    use AshAuthentication.Phoenix.Oauth2Server.Router

    oauth2_server_protocol_routes(oauth2_server: Oauth2ServerTest.Server)
  end

  defp call_router(conn), do: PhoenixRouterFixture.call(conn, PhoenixRouterFixture.init([]))

  setup do
    for resource <- [OAuthClient, OAuthAuthorizationCode, OAuthRefreshToken, OAuthConsent, User] do
      Ash.bulk_destroy!(resource, :destroy, %{}, return_errors?: true)
    end

    user =
      User
      |> Ash.Changeset.for_create(:create, %{email: "alice@example.com"})
      |> Ash.create!()

    {:ok, user: user}
  end

  defp call_consent(conn) do
    conn
    |> Plug.Test.init_test_session(%{})
    |> ConsentRouter.call(@consent_opts)
  end

  defp call_protocol(conn), do: ProtocolRouter.call(conn, @protocol_opts)

  defp register_client(redirect_uri \\ "https://chat.example.com/cb") do
    conn(
      :post,
      "/register",
      Jason.encode!(%{
        "client_name" => "Test",
        "redirect_uris" => [redirect_uri]
      })
    )
    |> put_req_header("content-type", "application/json")
    |> call_protocol()
  end

  defp pkce do
    verifier = Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)
    {verifier, PKCE.challenge(verifier)}
  end

  describe "ProtocolRouter: GET /oauth-authorization-server" do
    test "returns RFC 8414 metadata as JSON" do
      conn = call_protocol(conn(:get, "/oauth-authorization-server"))

      assert conn.status == 200
      assert ["application/json"] = get_resp_header(conn, "content-type")
      body = Jason.decode!(conn.resp_body)
      assert body["issuer"] == Server.issuer_url()
      assert body["token_endpoint"] =~ "/oauth/token"
      assert "S256" in body["code_challenge_methods_supported"]
    end
  end

  describe "ProtocolRouter: GET /openid-configuration (alias)" do
    test "returns the same body as oauth-authorization-server" do
      a = call_protocol(conn(:get, "/oauth-authorization-server")) |> Map.get(:resp_body)
      b = call_protocol(conn(:get, "/openid-configuration")) |> Map.get(:resp_body)
      assert a == b
    end
  end

  describe "ProtocolRouter: GET /oauth-protected-resource" do
    test "returns RFC 9728 metadata as JSON" do
      conn = call_protocol(conn(:get, "/oauth-protected-resource"))

      assert conn.status == 200
      body = Jason.decode!(conn.resp_body)
      assert body["resource"] == Server.resource_url()
      assert body["authorization_servers"] == [Server.issuer_url()]
    end
  end

  describe "Router: /.well-known serves only metadata, not protocol endpoints" do
    test "the metadata documents answer under /.well-known" do
      for path <- [
            "/.well-known/oauth-authorization-server",
            "/.well-known/openid-configuration",
            "/.well-known/oauth-protected-resource"
          ] do
        conn = call_router(conn(:get, path))
        assert conn.status == 200, "expected 200 for #{path}, got #{conn.status}"
      end
    end

    test "state-changing endpoints are NOT aliased under /.well-known" do
      for path <- ["/.well-known/register", "/.well-known/token", "/.well-known/revoke"] do
        conn = call_router(conn(:post, path, %{}))
        assert conn.status == 404, "expected 404 for #{path}, got #{conn.status}"
      end
    end

    test "the same endpoints remain reachable under /oauth" do
      # Not 404 — reachable (exact status depends on DCR/token validation).
      refute call_router(conn(:post, "/oauth/register", %{})).status == 404
      assert call_router(conn(:get, "/oauth/oauth-authorization-server")).status == 200
    end
  end

  describe "ProtocolRouter: metadata cache-control is tenant-aware" do
    for path <- ["/oauth-authorization-server", "/oauth-protected-resource"] do
      test "#{path} is publicly cacheable without a tenant" do
        conn = call_protocol(conn(:get, unquote(path)))
        assert get_resp_header(conn, "cache-control") == ["public, max-age=3600"]
      end

      test "#{path} is private (not shared-cacheable) when a tenant is set" do
        # A tenant-specific response must never be stored by a shared cache,
        # which would otherwise serve one tenant's endpoints to another.
        conn =
          conn(:get, unquote(path))
          |> Ash.PlugHelpers.set_tenant("tenant-a")
          |> call_protocol()

        assert get_resp_header(conn, "cache-control") == ["private, max-age=3600"]
      end
    end
  end

  describe "ProtocolRouter: POST /register" do
    test "registers a client and returns 201 + RFC 7591 body" do
      conn = register_client()

      assert conn.status == 201
      body = Jason.decode!(conn.resp_body)
      assert is_binary(body["client_id"])
      assert body["redirect_uris"] == ["https://chat.example.com/cb"]
      assert body["scope"] == "mcp"
    end

    test "rejects bogus redirect_uris with 400 + invalid_redirect_uri" do
      conn =
        conn(
          :post,
          "/register",
          Jason.encode!(%{"redirect_uris" => ["http://evil.example.com/cb"]})
        )
        |> put_req_header("content-type", "application/json")
        |> call_protocol()

      assert conn.status == 400
      body = Jason.decode!(conn.resp_body)
      assert body["error"] == "invalid_redirect_uri"
    end

    test "404s when DCR is disabled on the server" do
      opts =
        ProtocolRouter.init(oauth2_server: Oauth2ServerTest.DcrDisabledServer)

      conn =
        conn(
          :post,
          "/register",
          Jason.encode!(%{
            "client_name" => "X",
            "redirect_uris" => ["https://app.example.com/cb"]
          })
        )
        |> put_req_header("content-type", "application/json")
        |> ProtocolRouter.call(opts)

      assert conn.status == 404
    end

    test "401 + WWW-Authenticate when initial access token is wrong (RFC 7591 §3.2.2)" do
      opts =
        ProtocolRouter.init(oauth2_server: Oauth2ServerTest.GatedServer)

      conn =
        conn(
          :post,
          "/register",
          Jason.encode!(%{
            "client_name" => "X",
            "redirect_uris" => ["https://app.example.com/cb"]
          })
        )
        |> put_req_header("content-type", "application/json")
        |> put_req_header("authorization", "Bearer wrong-token")
        |> ProtocolRouter.call(opts)

      assert conn.status == 401
      [www_auth] = get_resp_header(conn, "www-authenticate")
      assert www_auth =~ ~s|Bearer error="invalid_token"|
      body = Jason.decode!(conn.resp_body)
      assert body["error"] == "invalid_token"
    end

    test "accepts a registration with the correct initial access token" do
      opts =
        ProtocolRouter.init(oauth2_server: Oauth2ServerTest.GatedServer)

      conn =
        conn(
          :post,
          "/register",
          Jason.encode!(%{
            "client_name" => "Trusted",
            "redirect_uris" => ["https://app.example.com/cb"]
          })
        )
        |> put_req_header("content-type", "application/json")
        |> put_req_header("authorization", "Bearer test-initial-access-token-shhh")
        |> ProtocolRouter.call(opts)

      assert conn.status == 201
    end
  end

  describe "ConsentRouter: GET /authorize" do
    test "401s when no actor is present and no sign_in_path is configured" do
      {client_id, redirect_uri} = create_client_for_authorize()
      {_v, challenge} = pkce()

      conn =
        conn(:get, "/?" <> URI.encode_query(authorize_query(client_id, redirect_uri, challenge)))
        |> call_consent()

      assert conn.status == 401
    end

    test "302s with code when consent already exists", %{user: user} do
      {client_id, redirect_uri} = create_client_for_authorize()
      {_v, challenge} = pkce()

      OAuthConsent
      |> Ash.Changeset.for_create(:grant, %{user_id: user.id, client_id: client_id, scope: "mcp"})
      |> Ash.create!()

      conn =
        conn(:get, "/?" <> URI.encode_query(authorize_query(client_id, redirect_uri, challenge)))
        |> Ash.PlugHelpers.set_actor(user)
        |> call_consent()

      assert conn.status == 302
      [location] = get_resp_header(conn, "location")
      assert String.starts_with?(location, redirect_uri <> "?")
      query = location |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
      assert is_binary(query["code"])
      assert query["state"] == "csrf-state"
    end

    test "renders consent HTML when no prior consent and user is logged in", %{user: user} do
      {client_id, redirect_uri} = create_client_for_authorize()
      {_v, challenge} = pkce()

      conn =
        conn(:get, "/?" <> URI.encode_query(authorize_query(client_id, redirect_uri, challenge)))
        |> Ash.PlugHelpers.set_actor(user)
        |> call_consent()

      assert conn.status == 200
      assert ["text/html; charset=utf-8"] = get_resp_header(conn, "content-type")
      assert conn.resp_body =~ "Authorize"
      assert conn.resp_body =~ "Approve"
    end
  end

  describe "ConsentRouter: authorize errors" do
    test "redirects an error only to the exact registered redirect_uri", %{user: user} do
      {client_id, redirect_uri} = create_client_for_authorize()
      {_v, challenge} = pkce()

      query =
        client_id
        |> authorize_query(redirect_uri, challenge)
        |> Map.put("response_type", "token")

      conn =
        conn(:get, "/?" <> URI.encode_query(query))
        |> Ash.PlugHelpers.set_actor(user)
        |> call_consent()

      assert conn.status == 302
      [location] = get_resp_header(conn, "location")
      assert String.starts_with?(location, redirect_uri <> "?")
      params = location |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
      assert params["error"] == "unsupported_response_type"

      # Equivalent after normalization, but not the registered string.
      conn =
        conn(
          :get,
          "/?" <> URI.encode_query(%{query | "redirect_uri" => "HTTPS://CHAT.EXAMPLE.COM/cb"})
        )
        |> Ash.PlugHelpers.set_actor(user)
        |> call_consent()

      assert conn.status == 400
      assert get_resp_header(conn, "location") == []
    end

    test "accepts a request without state and omits state from the redirect (OAuth 2.1 §4.1.1)",
         %{user: user} do
      {client_id, redirect_uri} = create_client_for_authorize()
      {_v, challenge} = pkce()

      OAuthConsent
      |> Ash.Changeset.for_create(:grant, %{user_id: user.id, client_id: client_id, scope: "mcp"})
      |> Ash.create!()

      query = client_id |> authorize_query(redirect_uri, challenge) |> Map.delete("state")

      conn =
        conn(:get, "/?" <> URI.encode_query(query))
        |> Ash.PlugHelpers.set_actor(user)
        |> call_consent()

      assert conn.status == 302
      [location] = get_resp_header(conn, "location")
      params = location |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
      assert is_binary(params["code"])
      refute Map.has_key?(params, "state")
    end

    test "redirects an error to the only registered redirect_uri when it is omitted",
         %{user: user} do
      {client_id, redirect_uri} = create_client_for_authorize()
      {_v, challenge} = pkce()

      query =
        client_id
        |> authorize_query(redirect_uri, challenge)
        |> Map.delete("redirect_uri")
        |> Map.put("response_type", "token")

      conn =
        conn(:get, "/?" <> URI.encode_query(query))
        |> Ash.PlugHelpers.set_actor(user)
        |> call_consent()

      assert conn.status == 302
      [location] = get_resp_header(conn, "location")
      assert String.starts_with?(location, redirect_uri <> "?")
    end

    test "keeps the redirect_uri as registered when adding parameters (OAuth 2.1 §2.3)",
         %{user: user} do
      for {registered, prefix} <- [
            {"https://chat.example.com/cb?app=1", "https://chat.example.com/cb?app=1&"},
            {"https://chat.example.com/cb?", "https://chat.example.com/cb?"},
            {"https://chat.example.com:443/cb?app=1", "https://chat.example.com:443/cb?app=1&"}
          ] do
        {client_id, redirect_uri} = create_client_for_authorize(registered)
        {_v, challenge} = pkce()

        OAuthConsent
        |> Ash.Changeset.for_create(:grant, %{
          user_id: user.id,
          client_id: client_id,
          scope: "mcp"
        })
        |> Ash.create!()

        conn =
          conn(
            :get,
            "/?" <> URI.encode_query(authorize_query(client_id, redirect_uri, challenge))
          )
          |> Ash.PlugHelpers.set_actor(user)
          |> call_consent()

        [code] =
          OAuthAuthorizationCode
          |> Ash.Query.filter(client_id == ^client_id)
          |> Ash.read!(context: %{private: %{ash_authentication?: true}})

        assert conn.status == 302

        assert get_resp_header(conn, "location") == [
                 prefix <>
                   URI.encode_query(%{
                     "code" => code.id,
                     "iss" => Server.issuer_url(),
                     "state" => "csrf-state"
                   })
               ]
      end
    end

    test "never redirects an unknown client", %{user: user} do
      {_v, challenge} = pkce()

      query =
        authorize_query(Ash.UUIDv7.generate(), "https://chat.example.com/cb", challenge)

      conn =
        conn(:get, "/?" <> URI.encode_query(query))
        |> Ash.PlugHelpers.set_actor(user)
        |> call_consent()

      assert conn.status == 400
      assert get_resp_header(conn, "location") == []
      assert Jason.decode!(conn.resp_body)["error"] == "invalid_client"
    end
  end

  describe "ConsentRouter: POST /authorize" do
    test "approves and 302s with code, recording consent", %{user: user} do
      {client_id, redirect_uri} = create_client_for_authorize()
      {_v, challenge} = pkce()

      consent_request = obtain_consent_request(user, client_id, redirect_uri, challenge)

      conn =
        conn(:post, "/", %{"consent_request" => consent_request, "action" => "approve"})
        |> put_req_header("content-type", "application/x-www-form-urlencoded")
        |> Ash.PlugHelpers.set_actor(user)
        |> call_consent()

      assert conn.status == 302
      [location] = get_resp_header(conn, "location")
      assert String.starts_with?(location, redirect_uri <> "?")

      assert {:ok, [_]} = Ash.read(OAuthConsent)
    end

    test "deny redirects with error=access_denied", %{user: user} do
      {client_id, redirect_uri} = create_client_for_authorize()
      {_v, challenge} = pkce()

      consent_request = obtain_consent_request(user, client_id, redirect_uri, challenge)

      conn =
        conn(:post, "/", %{"consent_request" => consent_request, "action" => "deny"})
        |> put_req_header("content-type", "application/x-www-form-urlencoded")
        |> Ash.PlugHelpers.set_actor(user)
        |> call_consent()

      assert conn.status == 302
      [location] = get_resp_header(conn, "location")
      query = location |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
      assert query["error"] == "access_denied"
    end

    test "rejects POST without consent_request token", %{user: user} do
      conn =
        conn(:post, "/", %{"action" => "approve"})
        |> put_req_header("content-type", "application/x-www-form-urlencoded")
        |> Ash.PlugHelpers.set_actor(user)
        |> call_consent()

      assert conn.status == 400
      assert Jason.decode!(conn.resp_body)["error"] == "invalid_request"
    end

    test "rejects POST with tampered consent_request token", %{user: user} do
      conn =
        conn(:post, "/", %{"consent_request" => "not-a-valid-token", "action" => "approve"})
        |> put_req_header("content-type", "application/x-www-form-urlencoded")
        |> Ash.PlugHelpers.set_actor(user)
        |> call_consent()

      assert conn.status == 400
      assert Jason.decode!(conn.resp_body)["error"] == "invalid_request"
    end
  end

  describe "ProtocolRouter: POST /token (authorization_code grant)" do
    test "exchanges code for tokens with valid PKCE", %{user: user} do
      {client_id, redirect_uri} = create_client_for_authorize()
      {verifier, challenge} = pkce()

      consent_request = obtain_consent_request(user, client_id, redirect_uri, challenge)

      authorize_conn =
        conn(:post, "/", %{"consent_request" => consent_request, "action" => "approve"})
        |> put_req_header("content-type", "application/x-www-form-urlencoded")
        |> Ash.PlugHelpers.set_actor(user)
        |> call_consent()

      [location] = get_resp_header(authorize_conn, "location")
      query = location |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
      code = query["code"]

      token_conn =
        conn(:post, "/token", %{
          "grant_type" => "authorization_code",
          "code" => code,
          "redirect_uri" => redirect_uri,
          "code_verifier" => verifier,
          "client_id" => client_id,
          "resource" => Server.resource_url()
        })
        |> put_req_header("content-type", "application/x-www-form-urlencoded")
        |> call_protocol()

      assert token_conn.status == 200
      body = Jason.decode!(token_conn.resp_body)
      assert body["token_type"] == "Bearer"
      assert is_binary(body["access_token"])
      assert is_binary(body["refresh_token"])
      assert body["scope"] == "mcp"
      assert body["expires_in"] == Server.access_token_lifetime()

      assert {:ok, claims} =
               Jwt.verify(Server, body["access_token"])

      assert claims["sub"] == user.id
    end

    test "an unacceptable resource returns 400 + invalid_target (RFC 8707 §2)", %{user: user} do
      {client_id, redirect_uri} = create_client_for_authorize()
      {verifier, challenge} = pkce()

      consent_request = obtain_consent_request(user, client_id, redirect_uri, challenge)

      authorize_conn =
        conn(:post, "/", %{"consent_request" => consent_request, "action" => "approve"})
        |> put_req_header("content-type", "application/x-www-form-urlencoded")
        |> Ash.PlugHelpers.set_actor(user)
        |> call_consent()

      [location] = get_resp_header(authorize_conn, "location")
      query = location |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()

      token_conn =
        conn(:post, "/token", %{
          "grant_type" => "authorization_code",
          "code" => query["code"],
          "redirect_uri" => redirect_uri,
          "code_verifier" => verifier,
          "client_id" => client_id,
          "resource" => "https://other.example.com/api"
        })
        |> put_req_header("content-type", "application/x-www-form-urlencoded")
        |> call_protocol()

      assert token_conn.status == 400
      assert Jason.decode!(token_conn.resp_body)["error"] == "invalid_target"
    end

    test "a missing grant_type returns 400 + invalid_request" do
      conn =
        conn(:post, "/token", %{"client_id" => "x"})
        |> put_req_header("content-type", "application/x-www-form-urlencoded")
        |> call_protocol()

      assert conn.status == 400
      assert Jason.decode!(conn.resp_body)["error"] == "invalid_request"
    end

    test "unsupported grant_type returns 400 + RFC code" do
      conn =
        conn(:post, "/token", %{"grant_type" => "password"})
        |> put_req_header("content-type", "application/x-www-form-urlencoded")
        |> call_protocol()

      assert conn.status == 400
      body = Jason.decode!(conn.resp_body)
      assert body["error"] == "unsupported_grant_type"
    end
  end

  describe "ProtocolRouter: POST /revoke (RFC 7009)" do
    defp issue_tokens(user, client_id) do
      {verifier, challenge} = pkce()

      {:ok, validated} =
        Authorize.validate_request(
          Server,
          authorize_query(client_id, "https://chat.example.com/cb", challenge)
        )

      code = Authorize.issue_code!(Server, user, validated)

      {:ok, tokens} =
        Token.exchange_authorization_code(Server, %{
          "grant_type" => "authorization_code",
          "code" => code.id,
          "code_verifier" => verifier,
          "client_id" => client_id
        })

      tokens
    end

    defp revoke(params) do
      conn(:post, "/revoke", params)
      |> put_req_header("content-type", "application/x-www-form-urlencoded")
      |> call_protocol()
    end

    defp error_of(conn), do: Jason.decode!(conn.resp_body)["error"]

    test "revokes the client's own refresh token", %{user: user} do
      {client_id, _} = create_client_for_authorize()
      tokens = issue_tokens(user, client_id)

      assert revoke(%{"token" => tokens.refresh_token, "client_id" => client_id}).status == 200

      assert {:error, :revoked} =
               Token.exchange_refresh_token(Server, %{
                 "refresh_token" => tokens.refresh_token,
                 "client_id" => client_id
               })
    end

    test "answers 200 for a token that is not valid (§2.2)" do
      {client_id, _} = create_client_for_authorize()
      assert revoke(%{"token" => "not-a-token", "client_id" => client_id}).status == 200
    end

    test "rejects a request without token or client_id with invalid_request" do
      {client_id, _} = create_client_for_authorize()

      for params <- [%{"client_id" => client_id}, %{"token" => "x"}] do
        conn = revoke(params)
        assert conn.status == 400
        assert error_of(conn) == "invalid_request"
      end
    end

    test "rejects an unknown client with invalid_client" do
      conn = revoke(%{"token" => "x", "client_id" => Ash.UUIDv7.generate()})
      assert conn.status == 400
      assert error_of(conn) == "invalid_client"
    end

    test "refuses a refresh token of another client (§2.1)", %{user: user} do
      {client_id, _} = create_client_for_authorize()
      {other_client_id, _} = create_client_for_authorize()
      tokens = issue_tokens(user, client_id)

      conn = revoke(%{"token" => tokens.refresh_token, "client_id" => other_client_id})
      assert conn.status == 400
      assert error_of(conn) == "invalid_grant"

      assert {:ok, _} =
               Token.exchange_refresh_token(Server, %{
                 "refresh_token" => tokens.refresh_token,
                 "client_id" => client_id
               })
    end

    test "answers unsupported_token_type for an access token (§2.2.1)", %{user: user} do
      {client_id, _} = create_client_for_authorize()
      tokens = issue_tokens(user, client_id)

      conn = revoke(%{"token" => tokens.access_token, "client_id" => client_id})
      assert conn.status == 400
      assert error_of(conn) == "unsupported_token_type"
    end
  end

  describe "Errors.describe_token_error/1" do
    test "maps a reason it does not know to a server error, not a client error" do
      assert {500, "server_error", _} = Errors.describe_token_error(:server_error)
      assert {500, "server_error", _} = Errors.describe_token_error(%RuntimeError{})
      assert {400, "invalid_request", _} = Errors.describe_token_error(:invalid_request)
    end
  end

  describe "router scoping" do
    test "ConsentRouter only handles / (the /oauth/authorize prefix is stripped)" do
      assert call_consent(conn(:post, "/token")).status == 404
      assert call_consent(conn(:get, "/oauth-authorization-server")).status == 404
    end

    test "ProtocolRouter doesn't accidentally handle / (consent's path)" do
      assert call_protocol(conn(:get, "/")).status == 404
    end
  end

  # ── helpers ────────────────────────────────────────────────────────────────

  defp create_client_for_authorize(redirect_uri \\ "https://chat.example.com/cb") do
    conn = register_client(redirect_uri)
    body = Jason.decode!(conn.resp_body)
    {body["client_id"], redirect_uri}
  end

  defp authorize_query(client_id, redirect_uri, challenge) do
    %{
      "response_type" => "code",
      "client_id" => client_id,
      "redirect_uri" => redirect_uri,
      "code_challenge" => challenge,
      "code_challenge_method" => "S256",
      "scope" => "mcp",
      "state" => "csrf-state",
      "resource" => Server.resource_url()
    }
  end

  # Walks the GET /authorize → consent screen → extracts the sealed
  # consent_request token. POSTs to /authorize must use this token rather
  # than re-submitting the raw protocol params.
  defp obtain_consent_request(user, client_id, redirect_uri, challenge) do
    conn =
      conn(:get, "/?" <> URI.encode_query(authorize_query(client_id, redirect_uri, challenge)))
      |> Ash.PlugHelpers.set_actor(user)
      |> call_consent()

    [_, token] = Regex.run(~r/name="consent_request" value="([^"]+)"/, conn.resp_body)
    token
  end
end
