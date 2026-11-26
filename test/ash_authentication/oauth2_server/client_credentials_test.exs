# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.ClientCredentialsTest do
  use ExUnit.Case, async: true

  alias AshAuthentication.Oauth2Server.{ClientAuth, Jwt, Token}
  alias AshAuthentication.Phoenix.Oauth2Server.BearerPlug
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

  describe "ClientAuth.parse/2" do
    defp basic_conn(user_id, password) do
      Plug.Test.conn(:post, "/")
      |> Plug.Conn.put_req_header(
        "authorization",
        "Basic " <> Base.encode64("#{user_id}:#{password}")
      )
    end

    test "reads body client_id + client_secret as client_secret_post" do
      assert {:ok,
              %ClientAuth{client_id: "cid", client_secret: "sec", method: :client_secret_post}} =
               ClientAuth.parse(%{}, %{"client_id" => "cid", "client_secret" => "sec"})
    end

    test "reads HTTP Basic as client_secret_basic" do
      assert {:ok,
              %ClientAuth{client_id: "cid", client_secret: "sec", method: :client_secret_basic}} =
               ClientAuth.parse(basic_conn("cid", "sec"), %{})
    end

    test "a body client_id alone identifies a public client" do
      assert {:ok, %ClientAuth{client_id: "cid", client_secret: nil, method: :none}} =
               ClientAuth.parse(%{}, %{"client_id" => "cid"})

      assert {:ok, %ClientAuth{client_id: "cid", client_secret: nil, method: :none}} =
               ClientAuth.parse(%{}, %{"client_id" => "cid", "client_secret" => ""})
    end

    test "no credentials at all" do
      assert {:ok, %ClientAuth{client_id: nil, client_secret: nil, method: :none}} =
               ClientAuth.parse(%{}, %{})
    end

    test "accepts a body client_id that names the Basic client (RFC 6749 §3.2.1)" do
      assert {:ok, %ClientAuth{client_id: "cid", method: :client_secret_basic}} =
               ClientAuth.parse(basic_conn("cid", "sec"), %{"client_id" => "cid"})
    end

    test "rejects a body client_id that names another client" do
      assert {:error, :invalid_request} =
               ClientAuth.parse(basic_conn("cid", "sec"), %{"client_id" => "other"})
    end

    test "rejects Basic combined with a body client_secret (RFC 6749 §5.2)" do
      assert {:error, :invalid_request} =
               ClientAuth.parse(basic_conn("cid", "sec"), %{
                 "client_id" => "cid",
                 "client_secret" => "sec"
               })
    end

    test "rejects a client_secret without a client_id" do
      assert {:error, :invalid_request} = ClientAuth.parse(%{}, %{"client_secret" => "sec"})
    end

    test "reports a client assertion as an unsupported method" do
      assert {:ok, %ClientAuth{client_id: "cid", method: :unsupported}} =
               ClientAuth.parse(%{}, %{
                 "client_id" => "cid",
                 "client_assertion_type" =>
                   "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                 "client_assertion" => "eyJ..."
               })

      assert {:error, :invalid_request} =
               ClientAuth.parse(basic_conn("cid", "sec"), %{"client_assertion" => "eyJ..."})
    end

    test "reports another Authorization scheme as an unsupported method" do
      conn =
        Plug.Test.conn(:post, "/")
        |> Plug.Conn.put_req_header("authorization", "Bearer token")

      assert {:ok, %ClientAuth{client_id: "cid", method: :unsupported}} =
               ClientAuth.parse(conn, %{"client_id" => "cid"})
    end

    test "percent-decodes Basic user-id and password (RFC 6749 §2.3.1)" do
      assert {:ok, %ClientAuth{client_id: "client:id", client_secret: "sec/ret"}} =
               ClientAuth.parse(basic_conn("client%3Aid", "sec%2Fret"), %{})
    end

    test "rejects oversized client_secret" do
      huge = String.duplicate("a", 5_000)

      assert {:error, :invalid_request} =
               ClientAuth.parse(%{}, %{"client_id" => "cid", "client_secret" => huge})
    end

    test "rejects malformed Basic without falling back to the body" do
      conn =
        Plug.Test.conn(:post, "/")
        |> Plug.Conn.put_req_header("authorization", "Basic not-base64!!!")

      assert {:error, :invalid_client} =
               ClientAuth.parse(conn, %{"client_id" => "cid", "client_secret" => "sec"})

      assert {:error, :invalid_client} =
               ClientAuth.parse(basic_conn("", "sec"), %{})
    end

    test "rejects non-string credential params" do
      assert {:error, :invalid_request} =
               ClientAuth.parse(%{}, %{"client_id" => ["array"], "client_secret" => "sec"})
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

    test "rejects a public client (RFC 6749 §4.4: confidential clients only)" do
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

      assert {:error, :invalid_client} =
               Token.exchange_client_credentials(MachineServer, %{"client_id" => public.id})
    end

    test "unauthorized_client for an authenticated client without the grant" do
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

      assert {:error, :unauthorized_client} =
               Token.exchange_client_credentials(MachineServer, %{
                 "client_id" => confidential.id,
                 "client_secret" => @secret
               })

      # A wrong secret is still invalid_client: the grant check needs an
      # authenticated client.
      assert {:error, :invalid_client} =
               Token.exchange_client_credentials(MachineServer, %{
                 "client_id" => confidential.id,
                 "client_secret" => "wrong"
               })
    end

    test "authenticates with the registered method only (RFC 7591 §2)", %{client: client} do
      # The client registered client_secret_post.
      basic = %ClientAuth{
        client_id: client.id,
        client_secret: @secret,
        method: :client_secret_basic
      }

      assert {:error, :invalid_client} =
               Token.exchange_client_credentials(MachineServer, %{}, client_auth: basic)

      assert {:ok, _} =
               Token.exchange_client_credentials(MachineServer, %{},
                 client_auth: %{basic | method: :client_secret_post}
               )

      assert {:error, :invalid_client} =
               Token.exchange_client_credentials(MachineServer, %{},
                 client_auth: %{basic | method: :unsupported}
               )
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

    test "invalid_client without client authentication (RFC 6749 §4.4.2)" do
      assert {:error, :invalid_client} =
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

    test "unsupported_grant_type on a server without the grant", %{client: client} do
      assert {:error, :unsupported_grant_type} =
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

  describe "BearerPlug with client credentials tokens" do
    defp call_plug(token, server \\ MachineServer) do
      Plug.Test.conn(:get, "/")
      |> Plug.Conn.put_req_header("authorization", "Bearer #{token}")
      |> BearerPlug.call(BearerPlug.init(oauth2_server: server))
    end

    test "sets the client as actor", %{client: client} do
      {:ok, %{access_token: token}} =
        Token.exchange_client_credentials(MachineServer, %{
          "client_id" => client.id,
          "client_secret" => @secret
        })

      conn = call_plug(token)

      refute conn.halted
      actor = Ash.PlugHelpers.get_actor(conn)
      assert %OAuthClient{} = actor
      assert actor.id == client.id
      assert conn.assigns.oauth_claims["scope"] == "my-scope"
    end

    test "sets the user as actor for a user token", %{client: client} do
      user =
        User
        |> Ash.Changeset.for_create(:create, %{email: "machine-user@example.com"})
        |> Ash.create!(domain: Domain)

      {:ok, token, claims} =
        Jwt.mint(MachineServer, sub: user.id, client_id: client.id, scope: "my-scope")

      refute Map.has_key?(claims, "gty")

      conn = call_plug(token)

      refute conn.halted
      assert %User{id: id} = Ash.PlugHelpers.get_actor(conn)
      assert id == user.id
    end

    test "401 when the subject of a user token is unknown" do
      {:ok, token, _claims} =
        Jwt.mint(MachineServer, sub: Ash.UUIDv7.generate(), client_id: "x", scope: "my-scope")

      conn = call_plug(token)

      assert conn.status == 401
      assert conn.halted
    end

    test "401 for a client token on a server without the grant", %{client: client} do
      {:ok, %{access_token: token}} =
        Token.exchange_client_credentials(MachineServer, %{
          "client_id" => client.id,
          "client_secret" => @secret
        })

      # Same issuer and signing secret, but `client_credentials` is not in
      # its `:supported_grants`.
      conn = call_plug(token, Oauth2ServerTest.Server)

      assert conn.status == 401
      assert conn.halted
      assert Ash.PlugHelpers.get_actor(conn) == nil
      [challenge] = Plug.Conn.get_resp_header(conn, "www-authenticate")
      assert challenge =~ "no longer allowed"
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

      conn = call_plug(token)

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

      conn = call_plug(token)

      assert conn.status == 401
      assert conn.halted
    end

    test "RequireScopePlug enforces scopes after BearerPlug", %{client: client} do
      alias AshAuthentication.Phoenix.Oauth2Server.RequireScopePlug

      {:ok, %{access_token: token}} =
        Token.exchange_client_credentials(MachineServer, %{
          "client_id" => client.id,
          "client_secret" => @secret,
          "scope" => "my-scope"
        })

      ok =
        call_plug(token)
        |> RequireScopePlug.call(
          RequireScopePlug.init(oauth2_server: MachineServer, scope: "my-scope")
        )

      refute ok.halted

      denied =
        call_plug(token)
        |> RequireScopePlug.call(
          RequireScopePlug.init(oauth2_server: MachineServer, scope: "mcp")
        )

      assert denied.status == 403
      assert denied.halted
    end
  end
end
