# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Phoenix.Oauth2Server.BearerPlugTest do
  @moduledoc """
  Parsing of the `Authorization` header (RFC 6750 §2.1, RFC 7235 §2.1) and
  the matching error responses (RFC 6750 §3.1).
  """
  use ExUnit.Case, async: false

  import Plug.Test
  import Plug.Conn

  alias AshAuthentication.Oauth2Server.Jwt
  alias AshAuthentication.Phoenix.Oauth2Server.BearerPlug
  alias Oauth2ServerTest.{Server, User}

  setup do
    Ash.bulk_destroy!(User, :destroy, %{}, return_errors?: true)

    user =
      User
      |> Ash.Changeset.for_create(:create, %{email: "alice@example.com"})
      |> Ash.create!()

    {:ok, token, _claims} = Jwt.mint(Server, sub: user.id, client_id: "client", scope: "mcp")
    {:ok, token: token}
  end

  defp call(header) do
    conn(:get, "/")
    |> then(&if header, do: put_req_header(&1, "authorization", header), else: &1)
    |> BearerPlug.call(BearerPlug.init(oauth2_server: Server))
  end

  defp challenge(conn) do
    [value] = get_resp_header(conn, "www-authenticate")
    value
  end

  test "accepts the scheme in any case and with several spaces", %{token: token} do
    for header <- ["Bearer " <> token, "BEARER " <> token, "bearer   " <> token] do
      conn = call(header)
      refute conn.halted, "expected #{inspect(header)} to authenticate"
    end
  end

  test "a request without authentication gets a challenge without an error code" do
    for header <- [nil, "Basic dXNlcjpwYXNz"] do
      conn = call(header)
      assert conn.status == 401
      refute challenge(conn) =~ "error="
    end
  end

  test "a Bearer header without a token is invalid_request with 400" do
    for header <- ["Bearer", "Bearer ", "bearer    "] do
      conn = call(header)
      assert conn.status == 400
      assert challenge(conn) =~ ~s|error="invalid_request"|
    end
  end

  test "a malformed token is invalid_token with 401" do
    conn = call("Bearer not a token")
    assert conn.status == 401
    assert challenge(conn) =~ ~s|error="invalid_token"|
  end
end
