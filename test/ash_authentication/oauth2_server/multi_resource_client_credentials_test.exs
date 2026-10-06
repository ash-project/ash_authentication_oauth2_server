# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.MultiResourceClientCredentialsTest do
  @moduledoc """
  The `client_credentials` grant on a server that protects two resources,
  `/mcp` and `/gql`. A machine token is bound to one resource (RFC 8707) and
  is valid only there.
  """
  use ExUnit.Case, async: false

  alias AshAuthentication.Oauth2Server.{Jwt, Token}
  alias AshAuthentication.Phoenix.Oauth2Server.ClientBearerPlug
  alias Oauth2ServerTest.MultiResourceServer, as: Server
  alias Oauth2ServerTest.{ClientSecrets, Domain, OAuthClient}

  @mcp "https://app.example.com/mcp"
  @gql "https://app.example.com/gql"
  @secret "super-secret-machine-credential"

  setup do
    Ash.bulk_destroy!(OAuthClient, :destroy, %{}, return_errors?: true)

    client =
      OAuthClient
      |> Ash.Changeset.for_create(:register_client_credentials, %{
        client_name: "Machine",
        redirect_uris: [],
        grant_types: ["client_credentials"],
        response_types: [],
        token_endpoint_auth_method: "client_secret_post",
        scope: "mcp gql",
        client_secret_hash: ClientSecrets.hash(@secret)
      })
      |> Ash.create!(domain: Domain, context: %{private: %{ash_authentication?: true}})

    {:ok, client: client}
  end

  defp params(client, extra) do
    Map.merge(%{"client_id" => client.id, "client_secret" => @secret}, extra)
  end

  defp issue(client, extra) do
    Token.exchange_client_credentials(Server, params(client, extra))
  end

  defp call_plug(token, resource) do
    Plug.Test.conn(:get, "/")
    |> Plug.Conn.put_req_header("authorization", "Bearer #{token}")
    |> ClientBearerPlug.call(ClientBearerPlug.init(oauth2_server: Server, resource: resource))
  end

  describe "resource selection" do
    test "binds the token to the requested resource", %{client: client} do
      assert {:ok, %{access_token: token, scope: "mcp"}} =
               issue(client, %{"resource" => @mcp, "scope" => "mcp"})

      assert {:ok, %{"aud" => @mcp}} = Jwt.verify(Server, token, resource: :mcp)
    end

    test "binds to another resource when asked", %{client: client} do
      assert {:ok, %{access_token: token}} =
               issue(client, %{"resource" => @gql, "scope" => "gql"})

      assert {:ok, %{"aud" => @gql}} = Jwt.verify(Server, token, resource: :gql)
    end

    test "is invalid_target without a resource, since it is ambiguous", %{client: client} do
      assert {:error, :invalid_target} = issue(client, %{"scope" => "mcp"})
    end

    test "is invalid_target for an unknown resource", %{client: client} do
      assert {:error, :invalid_target} =
               issue(client, %{"resource" => "https://app.example.com/other", "scope" => "mcp"})
    end

    test "is invalid_target for a resource with a fragment", %{client: client} do
      assert {:error, :invalid_target} =
               issue(client, %{"resource" => @mcp <> "#frag", "scope" => "mcp"})
    end

    test "accepts the same resource repeated", %{client: client} do
      assert {:ok, _} = issue(client, %{"resource" => [@mcp, @mcp], "scope" => "mcp"})
    end

    test "is invalid_target for different resources in one request", %{client: client} do
      assert {:error, :invalid_target} =
               issue(client, %{"resource" => [@mcp, @gql], "scope" => "mcp"})
    end
  end

  describe "per-resource scopes" do
    test "rejects a scope that the resource does not offer", %{client: client} do
      assert {:error, :invalid_scope} =
               issue(client, %{"resource" => @mcp, "scope" => "gql"})

      assert {:error, :invalid_scope} =
               issue(client, %{"resource" => @gql, "scope" => "mcp gql"})
    end

    test "defaults to the client's scopes, which the resource must offer", %{client: client} do
      # The client allows `mcp gql`, but `/mcp` offers only `mcp`.
      assert {:error, :invalid_scope} = issue(client, %{"resource" => @mcp})
    end
  end

  describe "allowed_resources" do
    defp restrict(client, resources) do
      client
      |> Ash.Changeset.for_update(:update, %{allowed_resources: resources},
        domain: Domain,
        context: %{private: %{ash_authentication?: true}}
      )
      |> Ash.update!()
    end

    test "is unrestricted without a list", %{client: client} do
      assert Token.client_resource_allowed?(client, :mcp)
      assert Token.client_resource_allowed?(client, :gql)
      assert Token.client_resource_allowed?(restrict(client, []), :gql)
    end

    test "limits the client to the listed resources", %{client: client} do
      restrict(client, ["mcp"])

      assert {:ok, _} = issue(client, %{"resource" => @mcp, "scope" => "mcp"})

      assert {:error, :invalid_target} =
               issue(client, %{"resource" => @gql, "scope" => "gql"})
    end

    test "the plug rejects a token once the resource is no longer allowed", %{client: client} do
      {:ok, %{access_token: token}} = issue(client, %{"resource" => @gql, "scope" => "gql"})
      refute call_plug(token, :gql).halted

      restrict(client, ["mcp"])

      conn = call_plug(token, :gql)
      assert conn.halted
      assert conn.status == 401
      [challenge] = Plug.Conn.get_resp_header(conn, "www-authenticate")
      assert challenge =~ "no longer allowed this resource"
    end
  end

  describe "ClientBearerPlug" do
    setup %{client: client} do
      {:ok, %{access_token: mcp_token}} =
        issue(client, %{"resource" => @mcp, "scope" => "mcp"})

      {:ok, %{access_token: gql_token}} =
        issue(client, %{"resource" => @gql, "scope" => "gql"})

      {:ok, mcp_token: mcp_token, gql_token: gql_token}
    end

    test "accepts a token at its own resource", %{client: client, mcp_token: mcp, gql_token: gql} do
      conn = call_plug(mcp, :mcp)
      refute conn.halted
      assert Ash.PlugHelpers.get_actor(conn).id == client.id

      conn = call_plug(gql, :gql)
      refute conn.halted
      assert conn.assigns.oauth_claims["scope"] == "gql"
    end

    test "rejects a token at the other resource", %{mcp_token: mcp, gql_token: gql} do
      for {token, resource} <- [{mcp, :gql}, {gql, :mcp}] do
        conn = call_plug(token, resource)
        assert conn.halted
        assert conn.status == 401
        [challenge] = Plug.Conn.get_resp_header(conn, "www-authenticate")
        assert challenge =~ "audience mismatch"
      end
    end

    test "points the challenge at the resource's metadata", %{mcp_token: mcp} do
      conn = call_plug(mcp, :gql)
      [challenge] = Plug.Conn.get_resp_header(conn, "www-authenticate")
      assert challenge =~ "/.well-known/oauth-protected-resource/gql"
    end

    test "requires :resource at plug init" do
      assert_raise ArgumentError, ~r/more than one resource/, fn ->
        ClientBearerPlug.init(oauth2_server: Server)
      end
    end

    test "re-checks scopes against the resource when the client is narrowed",
         %{client: client, mcp_token: mcp} do
      client
      |> Ash.Changeset.for_update(:update, %{scope: "gql"},
        domain: Domain,
        context: %{private: %{ash_authentication?: true}}
      )
      |> Ash.update!()

      conn = call_plug(mcp, :mcp)
      assert conn.halted
      assert conn.status == 401
    end
  end

  describe "Token.machine_scopes_allowed?/4" do
    test "checks the scope against the named resource", %{client: client} do
      assert Token.machine_scopes_allowed?(Server, :mcp, client, "mcp")
      refute Token.machine_scopes_allowed?(Server, :mcp, client, "gql")
      assert Token.machine_scopes_allowed?(Server, :gql, client, "gql")
    end
  end
end
