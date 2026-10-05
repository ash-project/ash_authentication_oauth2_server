# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

import Config

config :ash_authentication_oauth2_server, ash_domains: [Dev.Accounts]
config :ash, default_string_length_count: :codepoints

config :ash_authentication_oauth2_server, Dev.Endpoint,
  adapter: Bandit.PhoenixAdapter,
  http: [ip: {127, 0, 0, 1}, port: 4000],
  url: [host: "localhost", port: 4000],
  render_errors: [formats: [html: Dev.ErrorHTML], layout: false],
  secret_key_base: String.duplicate("dev-secret-key-base-", 4)

config :phoenix, :json_library, Jason
