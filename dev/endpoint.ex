# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule Dev.Endpoint do
  @moduledoc false
  use Phoenix.Endpoint, otp_app: :ash_authentication_oauth2_server

  plug Plug.Logger

  plug Plug.Parsers,
    parsers: [:urlencoded, :json, Absinthe.Plug.Parser],
    pass: ["*/*"],
    json_decoder: Jason

  plug Plug.Session,
    store: :cookie,
    key: "_dev_key",
    signing_salt: "dev-signing-salt",
    same_site: "Lax"

  plug Dev.Router
end
