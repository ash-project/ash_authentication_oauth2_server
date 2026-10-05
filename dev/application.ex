# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule Dev.Application do
  @moduledoc """
  A small Phoenix app to try the authorization server by hand.

  Start it with `mix dev` (or `iex -S mix dev`), then open
  http://localhost:4000.
  """

  use Application

  @impl Application
  def start(_type, _args) do
    Supervisor.start_link(
      [
        {AshAuthentication.Oauth2Server.Supervisor, otp_app: :ash_authentication_oauth2_server},
        Dev.Endpoint
      ],
      strategy: :one_for_one,
      name: Dev.Supervisor
    )
  end
end
