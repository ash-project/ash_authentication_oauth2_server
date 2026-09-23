# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.ClientCredentialsTest do
  use ExUnit.Case, async: true

  alias AshAuthentication.Oauth2Server.{ClientAuth, Jwt, Token}
  alias AshAuthentication.Phoenix.Oauth2Server.ClientBearerPlug
  alias Oauth2ServerTest.{ClientSecrets, Domain, MachineServer, OAuthClient, User}

  @secret "super-secret-machine-credential"

  setup do
    client =
      OAuthClient
      |> Ash.Changeset.for_create(:register_client_credentials, %{
        client_name: "Machine",
        redirect_uris: [],
        grant_types: ["client_credentials"],
        response_types: [],
        token_endpoint_auth_method: "client_secret_post",
        scope: "my-scope",
        client_secret_hash: ClientSecrets.hash(@secret)
      })
      |> Ash.create!(domain: Domain, context: %{private: %{ash_authentication?: true}})

    %{client: client}
  end

  describe "ClientAuth.credentials/2" do
    test "reads body client_id + client_secret" do
      assert {:ok, "cid", "sec", :post} =
               ClientAuth.credentials(%{}, %{"client_id" => "cid", "client_secret" => "sec"})
    end

    test "prefers HTTP Basic when body has no credentials" do
      encoded = Base.encode64("cid:sec")

      conn =
        Plug.Test.conn(:post, "/")
        |> Map.put(:req_headers, [{"authorization", "Basic #{encoded}"}])

      assert {:ok, "cid", "sec", :basic} = ClientAuth.credentials(conn, %{})
    end

    test "rejects Basic combined with body credentials (RFC 6749 §5.2)" do
      encoded = Base.encode64("cid:sec")

      conn =
        Plug.Test.conn(:post, "/")
        |> Map.put(:req_headers, [{"authorization", "Basic #{encoded}"}])

      assert {:error, :invalid_request} =
               ClientAuth.credentials(conn, %{"client_id" => "cid", "client_secret" => "sec"})

      assert {:error, :invalid_request} =
               ClientAuth.credentials(conn, %{"client_id" => "other", "client_secret" => "sec"})
    end

    test "rejects missing client_secret" do
      assert {:error, :invalid_request} =
               ClientAuth.credentials(%{}, %{"client_id" => "cid"})
    end

    test "percent-decodes Basic user-id and password (RFC 7617)" do
      encoded = Base.encode64("client%3Aid:sec%2Fret")

      conn =
        Plug.Test.conn(:post, "/")
        |> Map.put(:req_headers, [{"authorization", "Basic #{encoded}"}])

      assert {:ok, "client:id", "sec/ret", :basic} = ClientAuth.credentials(conn, %{})
    end

    test "rejects oversized client_secret" do
      huge = String.duplicate("a", 5_000)

      assert {:error, :invalid_request} =
               ClientAuth.credentials(%{}, %{"client_id" => "cid", "client_secret" => huge})
    end

    test "rejects malformed Basic without falling back to body" do
      conn =
        Plug.Test.conn(:post, "/")
        |> Map.put(:req_headers, [{"authorization", "Basic not-base64!!!"}])

      assert {:error, :invalid_client} =
               ClientAuth.credentials(conn, %{
                 "client_id" => "cid",
                 "client_secret" => "sec"
               })
    end

    test "rejects non-string credential params" do
      assert {:error, :invalid_request} =
               ClientAuth.credentials(%{}, %{
                 "client_id" => ["array"],
                 "client_secret" => "sec"
               })
    end
  end

  describe "Token.exchange_client_credentials/3" do
    test "mints an access token without a refresh token", %{client: client} do
      assert {:ok, response} =
               Token.exchange_client_credentials(MachineServer, %{
                 "client_id" => client.id,
                 "client_secret" => @secret,
                 "scope" => "my-scope"
               })

      assert response.token_type == "Bearer"
      assert response.scope == "my-scope"
      assert response.expires_in == MachineServer.access_token_lifetime()
      refute Map.has_key?(response, :refresh_token)

      assert {:ok, claims} = Jwt.verify(MachineServer, response.access_token)
      assert claims["sub"] == client.id
      assert claims["client_id"] == client.id
      assert claims["scope"] == "my-scope"
    end

    test "defaults scope to the client's scope when omitted", %{client: client} do
      assert {:ok, response} =
               Token.exchange_client_credentials(MachineServer, %{
                 "client_id" => client.id,
                 "client_secret" => @secret
               })

      assert response.scope == "my-scope"
    end

    test "rejects a bad secret", %{client: client} do
      assert {:error, :invalid_client} =
               Token.exchange_client_credentials(MachineServer, %{
                 "client_id" => client.id,
                 "client_secret" => "wrong"
               })
    end

    test "rejects an unknown client_id" do
      assert {:error, :invalid_client} =
               Token.exchange_client_credentials(MachineServer, %{
                 "client_id" => Ash.UUIDv7.generate(),
                 "client_secret" => @secret
               })
    end

    test "rejects a public client without enumerating the grant" do
      public =
        OAuthClient
        |> Ash.Changeset.for_create(:register, %{
          client_name: "Public",
          redirect_uris: ["https://app.example.com/cb"],
          grant_types: ["authorization_code"],
          token_endpoint_auth_method: "none",
          scope: "mcp"
        })
        |> Ash.create!(domain: Domain, context: %{private: %{ash_authentication?: true}})

      assert {:error, :invalid_client} =
               Token.exchange_client_credentials(MachineServer, %{
                 "client_id" => public.id,
                 "client_secret" => @secret
               })
    end

    test "rejects confidential client missing client_credentials grant_types", %{client: _client} do
      confidential =
        OAuthClient
        |> Ash.Changeset.for_create(:register_client_credentials, %{
          client_name: "Auth code only",
          redirect_uris: ["https://app.example.com/cb"],
          grant_types: ["authorization_code"],
          response_types: ["code"],
          token_endpoint_auth_method: "client_secret_post",
          scope: "my-scope",
          client_secret_hash: ClientSecrets.hash(@secret)
        })
        |> Ash.create!(domain: Domain, context: %{private: %{ash_authentication?: true}})

      assert {:error, :invalid_client} =
               Token.exchange_client_credentials(MachineServer, %{
                 "client_id" => confidential.id,
                 "client_secret" => @secret
               })
    end

    test "rejects scopes outside the client allow-list", %{client: client} do
      assert {:error, :invalid_scope} =
               Token.exchange_client_credentials(MachineServer, %{
                 "client_id" => client.id,
                 "client_secret" => @secret,
                 "scope" => "mcp"
               })
    end

    test "rejects scopes outside the server catalogue", %{client: client} do
      assert {:error, :invalid_scope} =
               Token.exchange_client_credentials(MachineServer, %{
                 "client_id" => client.id,
                 "client_secret" => @secret,
                 "scope" => "not-a-real-scope"
               })
    end

    test "rejects resource mismatch", %{client: client} do
      assert {:error, :invalid_target} =
               Token.exchange_client_credentials(MachineServer, %{
                 "client_id" => client.id,
                 "client_secret" => @secret,
                 "resource" => "https://other.example.com/api"
               })
    end

    test "rejects resource URI with a fragment (RFC 8707)", %{client: client} do
      assert {:error, :invalid_target} =
               Token.exchange_client_credentials(MachineServer, %{
                 "client_id" => client.id,
                 "client_secret" => @secret,
                 "resource" => "https://app.example.com/mcp#frag"
               })
    end

    test "accepts a matching resource parameter", %{client: client} do
      assert {:ok, _} =
               Token.exchange_client_credentials(MachineServer, %{
                 "client_id" => client.id,
                 "client_secret" => @secret,
                 "resource" => "https://app.example.com/mcp"
               })
    end

    test "rejects missing credentials" do
      assert {:error, :invalid_request} =
               Token.exchange_client_credentials(MachineServer, %{"scope" => "my-scope"})
    end

    test "rejects non-string scope param", %{client: client} do
      assert {:error, :invalid_request} =
               Token.exchange_client_credentials(MachineServer, %{
                 "client_id" => client.id,
                 "client_secret" => @secret,
                 "scope" => ["my-scope"]
               })
    end

    test "rejects malformed scope tokens (RFC 6749 §3.3 charset)", %{client: client} do
      assert {:error, :invalid_scope} =
               Token.exchange_client_credentials(MachineServer, %{
                 "client_id" => client.id,
                 "client_secret" => @secret,
                 "scope" => "bad\"scope"
               })
    end

    test "rejects non-string resource param", %{client: client} do
      # Repeated `resource` that includes a non-audience value → invalid_target
      assert {:error, :invalid_target} =
               Token.exchange_client_credentials(MachineServer, %{
                 "client_id" => client.id,
                 "client_secret" => @secret,
                 "resource" => ["https://evil.example", "https://app.example.com/mcp"]
               })
    end

    test "errors when verify_client_secret is not configured", %{client: client} do
      assert {:error, :verify_client_secret_not_configured} =
               Token.exchange_client_credentials(Oauth2ServerTest.Server, %{
                 "client_id" => client.id,
                 "client_secret" => @secret
               })
    end

    test "empty client scope allows any catalogue scope" do
      open =
        OAuthClient
        |> Ash.Changeset.for_create(:register_client_credentials, %{
          client_name: "Open scopes",
          redirect_uris: [],
          grant_types: ["client_credentials"],
          response_types: [],
          token_endpoint_auth_method: "client_secret_post",
          scope: "",
          client_secret_hash: ClientSecrets.hash(@secret)
        })
        |> Ash.create!(domain: Domain, context: %{private: %{ash_authentication?: true}})

      assert {:ok, response} =
               Token.exchange_client_credentials(MachineServer, %{
                 "client_id" => open.id,
                 "client_secret" => @secret,
                 "scope" => "mcp my-scope"
               })

      assert response.scope == "mcp my-scope"
    end

    test "rejects empty resolved scope" do
      open =
        OAuthClient
        |> Ash.Changeset.for_create(:register_client_credentials, %{
          client_name: "No scopes",
          redirect_uris: [],
          grant_types: ["client_credentials"],
          response_types: [],
          token_endpoint_auth_method: "client_secret_post",
          scope: "",
          client_secret_hash: ClientSecrets.hash(@secret)
        })
        |> Ash.create!(domain: Domain, context: %{private: %{ash_authentication?: true}})

      assert {:error, :invalid_scope} =
               Token.exchange_client_credentials(MachineServer, %{
                 "client_id" => open.id,
                 "client_secret" => @secret
               })
    end

    test "ignores leftover _client_auth_via tags (presentation is not bound)", %{client: client} do
      # Router no longer forwards via; if a caller still sets it, it must
      # not reject a valid confidential secret.
      assert {:ok, _} =
               Token.exchange_client_credentials(MachineServer, %{
                 "client_id" => client.id,
                 "client_secret" => @secret,
                 "_client_auth_via" => :basic
               })
    end

    test "merges extra_access_token_claims into the JWT", %{client: client} do
      assert {:ok, response} =
               Token.exchange_client_credentials(Oauth2ServerTest.MachineServerWithExtras, %{
                 "client_id" => client.id,
                 "client_secret" => @secret,
                 "scope" => "my-scope"
               })

      assert {:ok, claims} =
               Jwt.verify(Oauth2ServerTest.MachineServerWithExtras, response.access_token)

      assert claims["org_id"] == "org-from-extras"
      assert claims["client_name"] == "Machine"
    end
  end

  describe "ClientBearerPlug" do
    test "sets the client as actor", %{client: client} do
      {:ok, %{access_token: token}} =
        Token.exchange_client_credentials(MachineServer, %{
          "client_id" => client.id,
          "client_secret" => @secret
        })

      conn =
        Plug.Test.conn(:get, "/")
        |> Plug.Conn.put_req_header("authorization", "Bearer #{token}")
        |> ClientBearerPlug.call(ClientBearerPlug.init(oauth2_server: MachineServer))

      refute conn.halted
      actor = Ash.PlugHelpers.get_actor(conn)
      assert actor.id == client.id
      assert conn.assigns.oauth_claims["scope"] == "my-scope"
    end

    test "401 when the subject is not a client" do
      {:ok, token, _claims} =
        Jwt.mint(MachineServer,
          sub: Ash.UUIDv7.generate(),
          client_id: "x",
          scope: "my-scope"
        )

      conn =
        Plug.Test.conn(:get, "/")
        |> Plug.Conn.put_req_header("authorization", "Bearer #{token}")
        |> ClientBearerPlug.call(ClientBearerPlug.init(oauth2_server: MachineServer))

      assert conn.status == 401
      assert conn.halted
    end

    test "401 for a person-delegated user access token", %{client: client} do
      user =
        User
        |> Ash.Changeset.for_create(:create, %{email: "machine-reject@example.com"})
        |> Ash.create!(domain: Domain)

      {:ok, token, claims} =
        Jwt.mint(MachineServer,
          sub: user.id,
          client_id: client.id,
          scope: "my-scope"
        )

      # Person token fingerprint: sub (user) != client_id
      refute claims["sub"] == claims["client_id"]

      conn =
        Plug.Test.conn(:get, "/")
        |> Plug.Conn.put_req_header("authorization", "Bearer #{token}")
        |> ClientBearerPlug.call(ClientBearerPlug.init(oauth2_server: MachineServer))

      assert conn.status == 401
      assert conn.halted
      assert Ash.PlugHelpers.get_actor(conn) == nil
    end

    test "401 when machine grant is revoked on the client row", %{client: client} do
      {:ok, %{access_token: token}} =
        Token.exchange_client_credentials(MachineServer, %{
          "client_id" => client.id,
          "client_secret" => @secret
        })

      client
      |> Ash.Changeset.for_update(:update, %{grant_types: ["authorization_code"]})
      |> Ash.update!(domain: Domain, context: %{private: %{ash_authentication?: true}})

      conn =
        Plug.Test.conn(:get, "/")
        |> Plug.Conn.put_req_header("authorization", "Bearer #{token}")
        |> ClientBearerPlug.call(ClientBearerPlug.init(oauth2_server: MachineServer))

      assert conn.status == 401
      assert conn.halted
      assert Ash.PlugHelpers.get_actor(conn) == nil
    end

    test "401 when client scope allow-list is narrowed after mint", %{client: client} do
      {:ok, %{access_token: token}} =
        Token.exchange_client_credentials(MachineServer, %{
          "client_id" => client.id,
          "client_secret" => @secret,
          "scope" => "my-scope"
        })

      client
      |> Ash.Changeset.for_update(:update, %{scope: "mcp"})
      |> Ash.update!(domain: Domain, context: %{private: %{ash_authentication?: true}})

      conn =
        Plug.Test.conn(:get, "/")
        |> Plug.Conn.put_req_header("authorization", "Bearer #{token}")
        |> ClientBearerPlug.call(ClientBearerPlug.init(oauth2_server: MachineServer))

      assert conn.status == 401
      assert conn.halted
    end

    test "RequireScopePlug enforces scopes after ClientBearerPlug", %{client: client} do
      alias AshAuthentication.Phoenix.Oauth2Server.RequireScopePlug

      {:ok, %{access_token: token}} =
        Token.exchange_client_credentials(MachineServer, %{
          "client_id" => client.id,
          "client_secret" => @secret,
          "scope" => "my-scope"
        })

      ok =
        Plug.Test.conn(:get, "/")
        |> Plug.Conn.put_req_header("authorization", "Bearer #{token}")
        |> ClientBearerPlug.call(ClientBearerPlug.init(oauth2_server: MachineServer))
        |> RequireScopePlug.call(
          RequireScopePlug.init(oauth2_server: MachineServer, scope: "my-scope")
        )

      refute ok.halted

      denied =
        Plug.Test.conn(:get, "/")
        |> Plug.Conn.put_req_header("authorization", "Bearer #{token}")
        |> ClientBearerPlug.call(ClientBearerPlug.init(oauth2_server: MachineServer))
        |> RequireScopePlug.call(
          RequireScopePlug.init(oauth2_server: MachineServer, scope: "mcp")
        )

      assert denied.status == 403
      assert denied.halted
    end
  end

  describe "BearerPlug vs machine tokens" do
    test "user BearerPlug rejects a client_credentials token", %{client: client} do
      alias AshAuthentication.Phoenix.Oauth2Server.BearerPlug

      {:ok, %{access_token: token}} =
        Token.exchange_client_credentials(MachineServer, %{
          "client_id" => client.id,
          "client_secret" => @secret
        })

      conn =
        Plug.Test.conn(:get, "/")
        |> Plug.Conn.put_req_header("authorization", "Bearer #{token}")
        |> BearerPlug.call(BearerPlug.init(oauth2_server: MachineServer))

      assert conn.status == 401
      assert conn.halted
      assert Ash.PlugHelpers.get_actor(conn) == nil
    end
  end
end
