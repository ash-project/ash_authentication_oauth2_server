# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.ConfidentialClientTest do
  @moduledoc """
  Confidential clients (any `token_endpoint_auth_method` other than
  `none`) must authenticate on the `authorization_code` and
  `refresh_token` grants too (RFC 6749 §4.1.3 / §6), and a failed
  authentication must not burn the code or rotate the refresh token.

  Also covers `grant_types` enforcement on the user-delegated flow and
  the machine-vs-person token distinction (`gty` claim).
  """
  use ExUnit.Case, async: true

  import Plug.Test
  import Plug.Conn

  alias AshAuthentication.Oauth2Server.{Authorize, Jwt, PKCE, Token}
  alias AshAuthentication.Phoenix.Oauth2Server.{BearerPlug, ClientBearerPlug, ProtocolRouter}
  alias Oauth2ServerTest.{ClientSecrets, Domain, MachineServer, OAuthClient, User}

  @secret "super-secret-confidential-credential"
  @redirect_uri "https://app.example.com/cb"
  @protocol_opts ProtocolRouter.init(oauth2_server: MachineServer)

  setup do
    user =
      User
      |> Ash.Changeset.for_create(:create, %{
        email: "confidential-#{System.unique_integer([:positive])}@example.com"
      })
      |> Ash.create!(domain: Domain)

    %{user: user, client: create_client("client_secret_basic")}
  end

  defp create_client(auth_method, grant_types \\ ["authorization_code", "refresh_token"]) do
    OAuthClient
    |> Ash.Changeset.for_create(:register_client_credentials, %{
      client_name: "Confidential",
      redirect_uris: [@redirect_uri],
      grant_types: grant_types,
      response_types: ["code"],
      token_endpoint_auth_method: auth_method,
      scope: "mcp my-scope",
      client_secret_hash: ClientSecrets.hash(@secret)
    })
    |> Ash.create!(domain: Domain, context: %{private: %{ash_authentication?: true}})
  end

  defp issue_code(client, user) do
    verifier = Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)

    {:ok, validated} =
      Authorize.validate_request(MachineServer, %{
        "response_type" => "code",
        "client_id" => client.id,
        "redirect_uri" => @redirect_uri,
        "code_challenge" => PKCE.challenge(verifier),
        "code_challenge_method" => "S256",
        "scope" => "mcp",
        "state" => "s",
        "resource" => MachineServer.resource_url()
      })

    {Authorize.issue_code!(MachineServer, user, validated).id, verifier}
  end

  defp code_params(client, code, verifier, extra \\ %{}) do
    Map.merge(
      %{
        "grant_type" => "authorization_code",
        "code" => code,
        "redirect_uri" => @redirect_uri,
        "code_verifier" => verifier,
        "client_id" => client.id
      },
      extra
    )
  end

  defp refresh_params(client, refresh, extra \\ %{}) do
    Map.merge(
      %{"grant_type" => "refresh_token", "refresh_token" => refresh, "client_id" => client.id},
      extra
    )
  end

  describe "authorization_code grant" do
    test "confidential client without a secret is rejected and the code is not burned",
         %{client: client, user: user} do
      {code, verifier} = issue_code(client, user)

      assert {:error, :invalid_client} =
               Token.exchange_authorization_code(
                 MachineServer,
                 code_params(client, code, verifier)
               )

      # The failed attempt must not have consumed the code.
      assert {:ok, %{refresh_token: _}} =
               Token.exchange_authorization_code(
                 MachineServer,
                 code_params(client, code, verifier, %{"client_secret" => @secret})
               )
    end

    test "confidential client with a wrong secret is rejected", %{client: client, user: user} do
      {code, verifier} = issue_code(client, user)

      assert {:error, :invalid_client} =
               Token.exchange_authorization_code(
                 MachineServer,
                 code_params(client, code, verifier, %{"client_secret" => "wrong"})
               )
    end

    test "unimplemented auth methods fail closed", %{user: user} do
      client = create_client("private_key_jwt")
      {code, verifier} = issue_code(client, user)

      assert {:error, :invalid_client} =
               Token.exchange_authorization_code(
                 MachineServer,
                 code_params(client, code, verifier)
               )
    end

    test "public clients still need no secret, and a stray one is ignored", %{user: user} do
      client = create_client("none")
      {code, verifier} = issue_code(client, user)

      assert {:ok, _} =
               Token.exchange_authorization_code(
                 MachineServer,
                 code_params(client, code, verifier, %{"client_secret" => "ignored"})
               )
    end

    test "person tokens carry no gty claim", %{client: client, user: user} do
      {code, verifier} = issue_code(client, user)

      {:ok, %{access_token: at}} =
        Token.exchange_authorization_code(
          MachineServer,
          code_params(client, code, verifier, %{"client_secret" => @secret})
        )

      assert {:ok, claims} = Jwt.verify(MachineServer, at)
      refute Map.has_key?(claims, "gty")
    end
  end

  describe "refresh_token grant" do
    setup %{client: client, user: user} do
      {code, verifier} = issue_code(client, user)

      {:ok, %{refresh_token: refresh}} =
        Token.exchange_authorization_code(
          MachineServer,
          code_params(client, code, verifier, %{"client_secret" => @secret})
        )

      %{refresh: refresh}
    end

    test "confidential client without a secret is rejected and the token is not rotated",
         %{client: client, refresh: refresh} do
      assert {:error, :invalid_client} =
               Token.exchange_refresh_token(MachineServer, refresh_params(client, refresh))

      assert {:error, :invalid_client} =
               Token.exchange_refresh_token(
                 MachineServer,
                 refresh_params(client, refresh, %{"client_secret" => "wrong"})
               )

      # Neither failure rotated the token (which would make this a reuse).
      assert {:ok, %{refresh_token: _}} =
               Token.exchange_refresh_token(
                 MachineServer,
                 refresh_params(client, refresh, %{"client_secret" => @secret})
               )
    end
  end

  describe "grant_types enforcement" do
    defp authorize_params(client) do
      %{
        "response_type" => "code",
        "client_id" => client.id,
        "redirect_uri" => @redirect_uri,
        "code_challenge" => PKCE.challenge("verifier"),
        "code_challenge_method" => "S256",
        "scope" => "mcp",
        "state" => "s",
        "resource" => MachineServer.resource_url()
      }
    end

    # Bypass `validate_request/2` so the token-endpoint check is tested on
    # its own, as if the grant had been removed after the code was issued.
    defp issue_code_unchecked(client, user) do
      verifier = Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)

      code =
        Authorize.issue_code!(MachineServer, user, %{
          client: client,
          redirect_uri: @redirect_uri,
          code_challenge: PKCE.challenge(verifier),
          scope: "mcp",
          resource: MachineServer.resource_url()
        })

      {code.id, verifier}
    end

    defp set_grant_types(client, grant_types) do
      client
      |> Ash.Changeset.for_update(:update, %{grant_types: grant_types})
      |> Ash.update!(domain: Domain, context: %{private: %{ash_authentication?: true}})
    end

    test "authorize rejects a client not registered for authorization_code" do
      client = create_client("client_secret_post", ["client_credentials"])

      assert {:error, "unauthorized_client", _} =
               Authorize.validate_request(MachineServer, authorize_params(client))
    end

    test "authorize rejects a client with an explicitly empty grant list" do
      client = create_client("none", [])

      assert {:error, "unauthorized_client", _} =
               Authorize.validate_request(MachineServer, authorize_params(client))
    end

    test "authorize treats nil grant_types as the RFC 7591 default" do
      client = create_client("none", nil)

      assert {:ok, _} = Authorize.validate_request(MachineServer, authorize_params(client))
    end

    test "code exchange rejects a client not registered for authorization_code, without burning the code",
         %{client: client, user: user} do
      {code, verifier} = issue_code_unchecked(client, user)
      params = code_params(client, code, verifier, %{"client_secret" => @secret})

      set_grant_types(client, ["client_credentials"])

      assert {:error, :unauthorized_client} =
               Token.exchange_authorization_code(MachineServer, params)

      set_grant_types(client, ["authorization_code"])
      assert {:ok, _} = Token.exchange_authorization_code(MachineServer, params)
    end

    test "a failed secret is reported before grant eligibility", %{client: client, user: user} do
      {code, verifier} = issue_code_unchecked(client, user)
      set_grant_types(client, ["client_credentials"])

      assert {:error, :invalid_client} =
               Token.exchange_authorization_code(
                 MachineServer,
                 code_params(client, code, verifier, %{"client_secret" => "wrong"})
               )
    end

    test "refresh is allowed with only authorization_code (the RFC 7591 default)",
         %{user: user} do
      client = create_client("client_secret_post", ["authorization_code"])
      {code, verifier} = issue_code(client, user)

      {:ok, %{refresh_token: refresh}} =
        Token.exchange_authorization_code(
          MachineServer,
          code_params(client, code, verifier, %{"client_secret" => @secret})
        )

      assert {:ok, _} =
               Token.exchange_refresh_token(
                 MachineServer,
                 refresh_params(client, refresh, %{"client_secret" => @secret})
               )
    end

    test "refresh is rejected once the client loses both user-flow grants",
         %{client: client, user: user} do
      {code, verifier} = issue_code(client, user)

      {:ok, %{refresh_token: refresh}} =
        Token.exchange_authorization_code(
          MachineServer,
          code_params(client, code, verifier, %{"client_secret" => @secret})
        )

      set_grant_types(client, ["client_credentials"])

      assert {:error, :unauthorized_client} =
               Token.exchange_refresh_token(
                 MachineServer,
                 refresh_params(client, refresh, %{"client_secret" => @secret})
               )
    end
  end

  describe "POST /token client authentication" do
    defp post_token(params, headers \\ []) do
      conn = conn(:post, "/token", params)

      headers
      |> Enum.reduce(conn, fn {k, v}, c -> put_req_header(c, k, v) end)
      |> put_req_header("content-type", "application/x-www-form-urlencoded")
      |> ProtocolRouter.call(@protocol_opts)
    end

    test "accepts HTTP Basic on the authorization_code grant", %{client: client, user: user} do
      {code, verifier} = issue_code(client, user)
      basic = Base.encode64("#{client.id}:#{@secret}")

      conn =
        code_params(client, code, verifier)
        |> Map.delete("client_id")
        |> post_token([{"authorization", "Basic #{basic}"}])

      assert conn.status == 200
      assert is_binary(Jason.decode!(conn.resp_body)["refresh_token"])
    end

    test "401 invalid_client without a secret", %{client: client, user: user} do
      {code, verifier} = issue_code(client, user)

      conn = post_token(code_params(client, code, verifier))

      assert conn.status == 401
      assert Jason.decode!(conn.resp_body)["error"] == "invalid_client"
    end

    test "Basic combined with body credentials is invalid_request",
         %{client: client, user: user} do
      {code, verifier} = issue_code(client, user)
      basic = Base.encode64("#{client.id}:#{@secret}")

      conn =
        code_params(client, code, verifier, %{"client_secret" => @secret})
        |> post_token([{"authorization", "Basic #{basic}"}])

      assert conn.status == 400
      assert Jason.decode!(conn.resp_body)["error"] == "invalid_request"
    end
  end

  describe "machine vs person tokens" do
    setup do
      %{machine: create_client("client_secret_post", ["client_credentials"])}
    end

    test "machine tokens mint sub and client_id from the stored id, with gty",
         %{machine: machine} do
      # A non-canonical spelling of the id that the data layer still
      # resolves must not leak into the token.
      assert {:ok, %{access_token: at}} =
               Token.exchange_client_credentials(MachineServer, %{
                 "client_id" => String.upcase(machine.id),
                 "client_secret" => @secret,
                 "scope" => "my-scope"
               })

      assert {:ok, claims} = Jwt.verify(MachineServer, at)
      assert claims["sub"] == machine.id
      assert claims["client_id"] == machine.id
      assert claims["gty"] == "client_credentials"
    end

    test "extra claims cannot set gty" do
      {:ok, _token, claims} =
        Jwt.mint(MachineServer,
          sub: "user",
          client_id: "client",
          scope: "mcp",
          extra_claims: %{"gty" => "client_credentials", gty: "client_credentials"}
        )

      refute Map.has_key?(claims, "gty")
    end

    test "BearerPlug rejects any token carrying gty, even when sub != client_id",
         %{user: user, machine: machine} do
      {:ok, token, _} =
        Jwt.mint(MachineServer,
          sub: user.id,
          client_id: machine.id,
          scope: "my-scope",
          grant_type: "client_credentials"
        )

      conn =
        conn(:get, "/")
        |> put_req_header("authorization", "Bearer #{token}")
        |> BearerPlug.call(BearerPlug.init(oauth2_server: MachineServer))

      assert conn.status == 401
      assert Ash.PlugHelpers.get_actor(conn) == nil
    end

    test "ClientBearerPlug rejects sub == client_id without gty", %{machine: machine} do
      {:ok, token, _} =
        Jwt.mint(MachineServer, sub: machine.id, client_id: machine.id, scope: "my-scope")

      conn =
        conn(:get, "/")
        |> put_req_header("authorization", "Bearer #{token}")
        |> ClientBearerPlug.call(ClientBearerPlug.init(oauth2_server: MachineServer))

      assert conn.status == 401
      assert Ash.PlugHelpers.get_actor(conn) == nil
    end

    test "ClientBearerPlug accepts a real machine token", %{machine: machine} do
      {:ok, %{access_token: at}} =
        Token.exchange_client_credentials(MachineServer, %{
          "client_id" => machine.id,
          "client_secret" => @secret
        })

      conn =
        conn(:get, "/")
        |> put_req_header("authorization", "Bearer #{at}")
        |> ClientBearerPlug.call(ClientBearerPlug.init(oauth2_server: MachineServer))

      refute conn.halted
      assert Ash.PlugHelpers.get_actor(conn).id == machine.id
    end
  end
end
