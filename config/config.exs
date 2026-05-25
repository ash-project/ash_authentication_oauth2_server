# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/team-alembic/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

import Config

if Mix.env() == :test do
  import_config "test.exs"
end
