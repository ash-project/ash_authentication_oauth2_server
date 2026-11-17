# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.SupportedGrantsTest do
  @moduledoc """
  The `:supported_grants` option: what each grant switches on, and the
  compile-time checks between the options.
  """
  use ExUnit.Case, async: true

  import Plug.Test
  import Plug.Conn

  alias AshAuthentication.Oauth2Server.{Authorize, PKCE, Register, Token}
  alias AshAuthentication.Phoenix.Oauth2Server.{ConsentRouter, ProtocolRouter}
  alias Oauth2ServerTest.{ClientCredentialsOnlyServer, Domain, NoRefreshServer, OAuthClient, User}

  @redirect_uri "https://app.example.com/cb"

  defp create_user do
    User
    |> Ash.Changeset.for_create(:create, %{
      email: "grants-#{System.unique_integer([:positive])}@example.com"
    })
    |> Ash.create!(domain: Domain)
  end

  defp create_public_client(grant_types) do
    OAuthClient
    |> Ash.Changeset.for_create(:register, %{
      client_name: "Public",
      redirect_uris: [@redirect_uri],
      grant_types: grant_types,
      token_endpoint_auth_method: "none",
      scope: "mcp"
    })
    |> Ash.create!(domain: Domain, context: %{private: %{ash_authentication?: true}})
  end

  defp issue_code(server, client, user) do
    verifier = Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)

    code =
      Authorize.issue_code!(server, user, %{
        client: client,
        redirect_uri: @redirect_uri,
        code_challenge: PKCE.challenge(verifier),
        scope: "mcp",
        resource: server.resource_url()
      })

    {code.id, verifier}
  end

  describe "defaults and accessors" do
    test "the default is authorization_code and refresh_token" do
      assert Oauth2ServerTest.Server.supported_grants() == [:authorization_code, :refresh_token]
      assert Oauth2ServerTest.Server.grant_supported?(:refresh_token)
      assert Oauth2ServerTest.Server.grant_supported?("refresh_token")
      refute Oauth2ServerTest.Server.grant_supported?(:client_credentials)
      refute Oauth2ServerTest.Server.grant_supported?("client_credentials")
    end
  end

  describe "without refresh_token" do
    test "the authorization code exchange issues no refresh token" do
      client = create_public_client(["authorization_code", "refresh_token"])
      {code, verifier} = issue_code(NoRefreshServer, client, create_user())

      assert {:ok, response} =
               Token.exchange_authorization_code(NoRefreshServer, %{
                 "grant_type" => "authorization_code",
                 "client_id" => client.id,
                 "code" => code,
                 "code_verifier" => verifier,
                 "redirect_uri" => @redirect_uri
               })

      assert is_nil(response.refresh_token)
    end

    test "the refresh_token grant is unsupported" do
      client = create_public_client(["authorization_code", "refresh_token"])

      assert {:error, :unsupported_grant_type} =
               Token.exchange_refresh_token(NoRefreshServer, %{
                 "client_id" => client.id,
                 "refresh_token" => "anything"
               })

      conn =
        conn(:post, "/token", %{
          "grant_type" => "refresh_token",
          "client_id" => client.id,
          "refresh_token" => "anything"
        })
        |> put_req_header("content-type", "application/x-www-form-urlencoded")
        |> ProtocolRouter.call(ProtocolRouter.init(oauth2_server: NoRefreshServer))

      assert conn.status == 400
      assert Jason.decode!(conn.resp_body)["error"] == "unsupported_grant_type"
    end

    test "dynamic client registration narrows grant_types to the supported ones" do
      assert {:ok, client, body} =
               Register.register(NoRefreshServer, %{
                 "redirect_uris" => [@redirect_uri],
                 "grant_types" => ["authorization_code", "refresh_token", "client_credentials"]
               })

      assert client.grant_types == ["authorization_code"]
      assert body["grant_types"] == ["authorization_code"]
    end
  end

  describe "without authorization_code" do
    test "the consent router answers 404" do
      opts = ConsentRouter.init(oauth2_server: ClientCredentialsOnlyServer)

      for method <- [:get, :post] do
        conn = conn(method, "/", %{"client_id" => "x"}) |> ConsentRouter.call(opts)
        assert conn.status == 404
        assert conn.halted
      end
    end

    test "the authorization_code grant is unsupported" do
      assert {:error, :unsupported_grant_type} =
               Token.exchange_authorization_code(ClientCredentialsOnlyServer, %{
                 "client_id" => "x",
                 "code" => "c",
                 "code_verifier" => "v"
               })
    end

    test "the token endpoint still serves client_credentials" do
      {plain, hash} = AshAuthentication.Oauth2Server.ClientSecret.generate()

      client =
        OAuthClient
        |> Ash.Changeset.for_create(:register_client_credentials, %{
          client_name: "Machine",
          redirect_uris: [],
          grant_types: ["client_credentials"],
          response_types: [],
          token_endpoint_auth_method: "client_secret_basic",
          scope: "my-scope",
          client_secret_hash: hash
        })
        |> Ash.create!(domain: Domain, context: %{private: %{ash_authentication?: true}})

      conn =
        conn(:post, "/token", %{"grant_type" => "client_credentials"})
        |> put_req_header("content-type", "application/x-www-form-urlencoded")
        |> put_req_header("authorization", "Basic " <> Base.encode64("#{client.id}:#{plain}"))
        |> ProtocolRouter.call(ProtocolRouter.init(oauth2_server: ClientCredentialsOnlyServer))

      assert conn.status == 200
      assert Jason.decode!(conn.resp_body)["scope"] == "my-scope"
    end
  end

  describe "option validation" do
    defp define_server(extra) do
      name = Module.concat(__MODULE__, "Server#{System.unique_integer([:positive])}")

      quoted =
        quote do
          defmodule unquote(name) do
            use AshAuthentication.Oauth2Server,
                [
                  otp_app: :ash_authentication_oauth2_server,
                  user_resource: Oauth2ServerTest.User,
                  issuer_url: "https://issuer.example.com",
                  resource_url: "https://issuer.example.com/mcp",
                  signing_secret: "a-signing-secret-that-is-long-enough",
                  client_resource: Oauth2ServerTest.OAuthClient,
                  authorization_code_resource: Oauth2ServerTest.OAuthAuthorizationCode,
                  refresh_token_resource: Oauth2ServerTest.OAuthRefreshToken,
                  consent_resource: Oauth2ServerTest.OAuthConsent,
                  scopes: ["mcp"]
                ] ++ unquote(extra)
          end
        end

      Code.eval_quoted(quoted)
    end

    test "rejects an empty or unknown grant list" do
      assert_raise CompileError, ~r/supported_grants/, fn ->
        define_server(supported_grants: [])
      end

      assert_raise CompileError, ~r/supported_grants/, fn ->
        define_server(supported_grants: [:password])
      end
    end

    test "refresh_token requires authorization_code" do
      assert_raise CompileError, ~r/refresh_token/, fn ->
        define_server(supported_grants: [:refresh_token, :client_credentials])
      end
    end

    test "DCR and CIMD require authorization_code" do
      assert_raise CompileError, ~r/dcr_enabled\?/, fn ->
        define_server(supported_grants: [:client_credentials], dcr_enabled?: true)
      end

      assert_raise CompileError, ~r/cimd_enabled\?/, fn ->
        define_server(supported_grants: [:client_credentials], cimd_enabled?: true)
      end
    end

    test "verify_client_secret must be a function or an MFA" do
      assert_raise CompileError, ~r/verify_client_secret/, fn ->
        define_server(verify_client_secret: nil)
      end
    end
  end
end
