# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Phoenix.Oauth2Server.RequireScopePlugTest do
  @moduledoc """
  Scope-challenge surface: `RequireScopePlug`'s RFC 6750 §3.1
  `insufficient_scope` 403s and `BearerPlug`'s advisory `scope` on 401
  challenges.
  """
  use ExUnit.Case, async: false

  import Plug.Test
  import Plug.Conn

  alias AshAuthentication.Oauth2Server.Jwt
  alias AshAuthentication.Phoenix.Oauth2Server.{BearerPlug, RequireScopePlug}
  alias Oauth2ServerTest.{Server, User}

  setup do
    Ash.bulk_destroy!(User, :destroy, %{}, return_errors?: true)

    user =
      User
      |> Ash.Changeset.for_create(:create, %{email: "alice@example.com"})
      |> Ash.create!()

    {:ok, user: user}
  end

  defp claims_conn(scope) do
    conn(:get, "/") |> assign(:oauth_claims, %{"scope" => scope})
  end

  defp call_require(conn, opts) do
    RequireScopePlug.call(conn, RequireScopePlug.init([oauth2_server: Server] ++ opts))
  end

  defp www_authenticate(conn) do
    [value] = get_resp_header(conn, "www-authenticate")
    value
  end

  describe "RequireScopePlug" do
    test "passes through when the token has the scope" do
      conn = claims_conn("mcp.read mcp.write") |> call_require(scope: "mcp.read")
      refute conn.halted
    end

    test "requires all scopes when given a list" do
      conn = claims_conn("mcp.read mcp.write") |> call_require(scope: ["mcp.read", "mcp.write"])
      refute conn.halted
    end

    test "403s with an RFC 6750 insufficient_scope challenge" do
      conn = claims_conn("mcp.read") |> call_require(scope: ["mcp.read", "mcp.write"])

      assert conn.halted
      assert conn.status == 403

      challenge = www_authenticate(conn)
      assert challenge =~ ~s|error="insufficient_scope"|
      # All required scopes in a single challenge, per the MCP spec.
      assert challenge =~ ~s|scope="mcp.read mcp.write"|

      assert challenge =~
               ~s|resource_metadata="https://app.example.com/.well-known/oauth-protected-resource"|

      body = Jason.decode!(conn.resp_body)
      assert body["error"] == "insufficient_scope"
      assert body["scope"] == "mcp.read mcp.write"
    end

    test "401s when there are no verified claims at all" do
      conn = conn(:get, "/") |> call_require(scope: "mcp.read")

      assert conn.halted
      assert conn.status == 401
      assert www_authenticate(conn) =~ ~s|resource_metadata=|
    end
  end

  describe "BearerPlug :scope option" do
    test "401 challenge advertises the scope hint", %{user: _user} do
      conn =
        conn(:get, "/")
        |> BearerPlug.call(
          BearerPlug.init(oauth2_server: Server, scope: ["mcp.read", "mcp.write"])
        )

      assert conn.status == 401
      assert www_authenticate(conn) =~ ~s|scope="mcp.read mcp.write"|
    end

    test "valid tokens still pass with :scope set", %{user: user} do
      {:ok, token, _} = Jwt.mint(Server, sub: user.id, client_id: "test", scope: "mcp")

      conn =
        conn(:get, "/")
        |> put_req_header("authorization", "Bearer " <> token)
        |> BearerPlug.call(BearerPlug.init(oauth2_server: Server, scope: "mcp"))

      refute conn.halted
      assert conn.assigns.oauth_claims["scope"] == "mcp"
    end
  end
end
