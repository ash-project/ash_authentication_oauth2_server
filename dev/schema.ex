# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule Dev.Schema do
  @moduledoc false
  use Absinthe.Schema
  use AshGraphql, domains: [Dev.Accounts]

  query do
  end
end
