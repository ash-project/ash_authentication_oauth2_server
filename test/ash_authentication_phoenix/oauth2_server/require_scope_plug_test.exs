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
  alias AshAuthentication.Phoenix.Oauth2Server.{BearerPlug, Errors, RequireScopePlug}
  alias Oauth2ServerTest.{Server, User}

  # An attacker-controlled tenant value that tries to close the quoted
  # resource_metadata value and smuggle a second auth-param.
  @injection ~s|victim", scope="admin", filler="x|

  # A server whose resource_url bakes in the (request-derived) tenant, like a
  # typical multi-tenant app. The challenge paths only call resource_url/1, so
  # this stand-in is enough to drive the tenant into the emitted header.
  defmodule InjectionServer do
    @moduledoc false
    def resource_url(%{tenant: tenant}) when is_binary(tenant),
      do: "https://#{tenant}.app.example.com/mcp"

    def resource_url(_), do: "https://app.example.com/mcp"
  end

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

  describe "challenge header injection via the tenant" do
    test "BearerPlug escapes a tenant that tries to smuggle auth-params" do
      conn =
        conn(:get, "/")
        |> Ash.PlugHelpers.set_tenant(@injection)
        |> BearerPlug.call(BearerPlug.init(oauth2_server: InjectionServer))

      assert conn.status == 401
      challenge = www_authenticate(conn)

      # The `"` from the tenant is neutralised, so `scope="admin"` never
      # appears as a real auth-param — only inside the escaped metadata value.
      refute challenge =~ ~s|scope="admin"|
      assert challenge =~ ~S|scope=\"admin\"|
    end

    test "RequireScopePlug (401, no claims) escapes the tenant" do
      conn =
        conn(:get, "/")
        |> Ash.PlugHelpers.set_tenant(@injection)
        |> RequireScopePlug.call(
          RequireScopePlug.init(oauth2_server: InjectionServer, scope: "mcp.read")
        )

      assert conn.status == 401
      challenge = www_authenticate(conn)
      refute challenge =~ ~s|scope="admin"|
      assert challenge =~ ~S|scope=\"admin\"|
    end

    test "RequireScopePlug (403, insufficient_scope) escapes the tenant" do
      conn =
        claims_conn("mcp.read")
        |> Ash.PlugHelpers.set_tenant(@injection)
        |> RequireScopePlug.call(
          RequireScopePlug.init(oauth2_server: InjectionServer, scope: ["mcp.read", "mcp.write"])
        )

      assert conn.status == 403
      challenge = www_authenticate(conn)
      # The legitimate required-scope param is present…
      assert challenge =~ ~s|scope="mcp.read mcp.write"|
      # …but the injected admin scope is not a real param.
      refute challenge =~ ~s|scope="admin"|
    end
  end

  describe "Errors.bearer_challenge/1" do
    test "drops nils and escapes quoted-string values" do
      challenge =
        Errors.bearer_challenge([
          {"resource_metadata", ~s|https://victim", scope="admin"|},
          {"scope", nil},
          {"error", "invalid_token"}
        ])

      assert challenge == ~S|Bearer resource_metadata="https://victim\", scope=\"admin\"", error="invalid_token"|
      refute challenge =~ ~s|scope="admin"|
    end
  end
end
