# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Phoenix.Oauth2Server.MultiResourceTest do
  @moduledoc """
  HTTP surface for a server that protects `/mcp` and `/gql`: one RFC 9728
  document for each resource, and bearer checks that accept only tokens
  for their own resource.
  """
  use ExUnit.Case, async: false

  import Plug.Test
  import Plug.Conn

  alias AshAuthentication.Oauth2Server.Jwt
  alias AshAuthentication.Phoenix.Oauth2Server.{BearerPlug, ProtocolRouter, RequireScopePlug}
  alias Oauth2ServerTest.{MultiResourceServer, User}

  @protocol_opts ProtocolRouter.init(oauth2_server: MultiResourceServer)

  setup do
    Ash.bulk_destroy!(User, :destroy, %{}, return_errors?: true)

    user =
      User
      |> Ash.Changeset.for_create(:create, %{email: "alice@example.com"})
      |> Ash.create!()

    {:ok, user: user}
  end

  defp get_metadata(path), do: ProtocolRouter.call(conn(:get, path), @protocol_opts)

  defp bearer_conn(token) do
    conn(:get, "/") |> put_req_header("authorization", "Bearer " <> token)
  end

  defp call_bearer(conn, resource) do
    BearerPlug.call(conn, BearerPlug.init(oauth2_server: MultiResourceServer, resource: resource))
  end

  defp mint(user, resource) do
    {:ok, token, _claims} =
      Jwt.mint(MultiResourceServer,
        sub: user.id,
        client_id: "client",
        scope: "mcp",
        resource: MultiResourceServer.resource_url(resource)
      )

    token
  end

  describe "end to end: authorize for /mcp, then try /gql" do
    alias AshAuthentication.Oauth2Server.PKCE
    alias AshAuthentication.Phoenix.Oauth2Server.ConsentRouter

    @consent_opts ConsentRouter.init(oauth2_server: MultiResourceServer)
    @mcp "https://app.example.com/mcp"
    @gql "https://app.example.com/gql"

    defp post_form(path, params) do
      conn(:post, path, params)
      |> put_req_header("content-type", "application/x-www-form-urlencoded")
      |> ProtocolRouter.call(@protocol_opts)
    end

    test "the grant and its tokens stay bound to /mcp", %{user: user} do
      register =
        conn(
          :post,
          "/register",
          Jason.encode!(%{
            "client_name" => "Claude",
            "redirect_uris" => ["http://localhost:33418/callback"],
            "grant_types" => ["authorization_code", "refresh_token"]
          })
        )
        |> put_req_header("content-type", "application/json")
        |> ProtocolRouter.call(@protocol_opts)

      client_id = Jason.decode!(register.resp_body)["client_id"]

      Oauth2ServerTest.OAuthConsent
      |> Ash.Changeset.for_create(:grant, %{user_id: user.id, client_id: client_id, scope: "mcp"})
      |> Ash.create!()

      verifier = Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)

      query = %{
        "response_type" => "code",
        "client_id" => client_id,
        "redirect_uri" => "http://localhost:33418/callback",
        "code_challenge" => PKCE.challenge(verifier),
        "code_challenge_method" => "S256",
        "scope" => "mcp",
        "resource" => @mcp
      }

      authorize =
        conn(:get, "/?" <> URI.encode_query(query))
        |> Plug.Test.init_test_session(%{})
        |> Ash.PlugHelpers.set_actor(user)
        |> ConsentRouter.call(@consent_opts)

      assert authorize.status == 302
      [location] = get_resp_header(authorize, "location")
      code = URI.decode_query(URI.parse(location).query)["code"]

      tokens =
        post_form("/token", %{
          "grant_type" => "authorization_code",
          "code" => code,
          "code_verifier" => verifier,
          "client_id" => client_id,
          "resource" => @mcp
        })

      assert tokens.status == 200
      %{"access_token" => access, "refresh_token" => refresh} = Jason.decode!(tokens.resp_body)

      switch =
        post_form("/token", %{
          "grant_type" => "refresh_token",
          "refresh_token" => refresh,
          "client_id" => client_id,
          "resource" => @gql
        })

      assert switch.status == 400
      assert Jason.decode!(switch.resp_body)["error"] == "invalid_target"

      refute access |> bearer_conn() |> call_bearer(:mcp) |> Map.get(:halted)
      assert (access |> bearer_conn() |> call_bearer(:gql)).status == 401

      refreshed =
        post_form("/token", %{
          "grant_type" => "refresh_token",
          "refresh_token" => refresh,
          "client_id" => client_id,
          "resource" => @mcp
        })

      assert refreshed.status == 200
    end
  end

  describe "protected resource metadata" do
    test "serves each resource at the path of its identifier (RFC 9728 §3.1)" do
      for {path, resource, scopes} <- [
            {"/oauth-protected-resource/mcp", "https://app.example.com/mcp", ["mcp"]},
            {"/oauth-protected-resource/gql", "https://app.example.com/gql", ["gql"]}
          ] do
        conn = get_metadata(path)

        assert conn.status == 200
        body = Jason.decode!(conn.resp_body)
        assert body["resource"] == resource
        assert body["scopes_supported"] == scopes
      end
    end

    test "404s at the host root and at paths of no resource" do
      assert get_metadata("/oauth-protected-resource").status == 404
      assert get_metadata("/oauth-protected-resource/other").status == 404
    end
  end

  describe "BearerPlug :resource option" do
    test "accepts a token for its own resource", %{user: user} do
      conn = user |> mint(:mcp) |> bearer_conn() |> call_bearer(:mcp)

      refute conn.halted
      assert conn.assigns.oauth_claims["aud"] == "https://app.example.com/mcp"
    end

    test "rejects a token for another resource and points at its own metadata",
         %{user: user} do
      conn = user |> mint(:mcp) |> bearer_conn() |> call_bearer(:gql)

      assert conn.status == 401
      [challenge] = get_resp_header(conn, "www-authenticate")

      assert challenge =~
               ~s|resource_metadata="https://app.example.com/.well-known/oauth-protected-resource/gql"|

      assert challenge =~ ~s|error="invalid_token"|
    end
  end

  test "revocation recognises an access token for any resource (RFC 7009 §2.2.1)",
       %{user: user} do
    {:ok, client, _} =
      AshAuthentication.Oauth2Server.Register.register(MultiResourceServer, %{
        "client_name" => "Test",
        "redirect_uris" => ["https://chat.example.com/cb"]
      })

    conn =
      conn(:post, "/revoke", %{"token" => mint(user, :gql), "client_id" => client.id})
      |> put_req_header("content-type", "application/x-www-form-urlencoded")
      |> ProtocolRouter.call(@protocol_opts)

    assert conn.status == 400
    assert Jason.decode!(conn.resp_body)["error"] == "unsupported_token_type"
  end

  test "the plugs reject a missing or unknown resource at init" do
    for plug <- [BearerPlug, RequireScopePlug], resource <- [nil, :other] do
      assert_raise ArgumentError, fn ->
        plug.init(oauth2_server: MultiResourceServer, resource: resource, scope: "mcp")
      end
    end
  end

  test "RequireScopePlug points its challenge at the metadata of its resource" do
    conn =
      conn(:get, "/")
      |> assign(:oauth_claims, %{"scope" => "gql"})
      |> RequireScopePlug.call(
        RequireScopePlug.init(
          oauth2_server: MultiResourceServer,
          resource: :gql,
          scope: "gql.write"
        )
      )

    assert conn.status == 403
    [challenge] = get_resp_header(conn, "www-authenticate")

    assert challenge =~
             ~s|resource_metadata="https://app.example.com/.well-known/oauth-protected-resource/gql"|
  end
end
