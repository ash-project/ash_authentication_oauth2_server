# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/team-alembic/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

import Config

if Mix.env() == :test do
  import_config "test.exs"
end

if Mix.env() == :dev do
  config :git_ops,
    mix_project: AshAuthentication.Oauth2Server.MixProject,
    github_handle_lookup?: true,
    changelog_file: "CHANGELOG.md",
    repository_url: "https://github.com/team-alembic/ash_authentication_oauth2_server",
    # Manage the version in `mix.exs`
    manage_mix_version?: true,
    # Manage the version in `README.md` (and any other doc that calls it out)
    manage_readme_version: "README.md",
    version_tag_prefix: "v"
end
