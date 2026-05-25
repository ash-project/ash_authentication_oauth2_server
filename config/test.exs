# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/team-alembic/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

import Config

config :ash_authentication_oauth2_server,
  ash_domains: [Oauth2ServerTest.Domain]

config :ash, :validate_domain_config_inclusion?, false
config :ash, :validate_domain_resource_inclusion?, false
