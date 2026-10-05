# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule Dev.Accounts do
  @moduledoc false
  use Ash.Domain,
    otp_app: :ash_authentication_oauth2_server,
    extensions: [AshAi, AshGraphql.Domain]

  tools do
    tool :greet, Dev.Accounts.User, :greet
  end

  resources do
    resource Dev.Accounts.User
    resource Dev.Accounts.OAuthClient
    resource Dev.Accounts.OAuthAuthorizationCode
    resource Dev.Accounts.OAuthRefreshToken
    resource Dev.Accounts.OAuthConsent
  end
end
