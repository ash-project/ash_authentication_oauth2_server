# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule Dev.PageController do
  @moduledoc false
  use Phoenix.Controller, formats: [:html]

  def home(conn, _params) do
    user =
      case conn.assigns[:current_user] do
        nil -> ~s|Not signed in. <a href="/sign-in">Sign in</a>|
        user -> "Signed in as #{Plug.HTML.html_escape(to_string(user.email))}"
      end

    html(conn, """
    <!DOCTYPE html>
    <html lang="en"><head><meta charset="UTF-8"><title>Dev app</title></head><body>
    <h1>ash_authentication_oauth2_server dev app</h1>
    <p>#{user}</p>
    <ul>
      <li>MCP: <code>http://localhost:4000/mcp</code> (scope <code>mcp</code>)</li>
      <li>GraphQL: <code>http://localhost:4000/gql</code> (scope <code>gql</code>)</li>
      <li><a href="/.well-known/oauth-authorization-server">Authorization server metadata</a></li>
    </ul>
    </body></html>
    """)
  end

  def sign_in(conn, _params) do
    html(conn, """
    <!DOCTYPE html>
    <html lang="en"><head><meta charset="UTF-8"><title>Sign in</title></head><body>
    <h1>Sign in</h1>
    <p><a href="/auth/user/mock">Sign in as dev@example.com</a></p>
    </body></html>
    """)
  end
end
