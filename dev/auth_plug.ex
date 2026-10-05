# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule Dev.AuthPlug do
  @moduledoc false
  use AshAuthentication.Plug, otp_app: :ash_authentication_oauth2_server

  @impl AshAuthentication.Plug
  def handle_success(conn, _activity, user, _token) do
    return_to = get_session(conn, :return_to) || "/"

    conn
    |> delete_session(:return_to)
    |> store_in_session(user)
    |> Phoenix.Controller.redirect(to: return_to)
  end

  @impl AshAuthentication.Plug
  def handle_failure(conn, _activity, _reason) do
    send_resp(conn, 401, "Sign-in failed")
  end
end
