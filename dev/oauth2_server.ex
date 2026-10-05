# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule Dev.Oauth2Server do
  @moduledoc false
  use AshAuthentication.Oauth2Server,
    otp_app: :ash_authentication_oauth2_server,
    user_resource: Dev.Accounts.User,
    issuer_url: "http://localhost:4000",
    resources: [
      mcp: [url: "http://localhost:4000/mcp", scopes: ["mcp"]],
      gql: [url: "http://localhost:4000/gql", scopes: ["gql"]]
    ],
    signing_secret: "dev-signing-secret-dev-signing-secret",
    client_resource: Dev.Accounts.OAuthClient,
    authorization_code_resource: Dev.Accounts.OAuthAuthorizationCode,
    refresh_token_resource: Dev.Accounts.OAuthRefreshToken,
    consent_resource: Dev.Accounts.OAuthConsent,
    scopes: ["mcp", "gql"],
    dcr_enabled?: true,
    sign_in_path: "/sign-in"
end
