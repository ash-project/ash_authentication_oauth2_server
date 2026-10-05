# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule Dev.ErrorHTML do
  @moduledoc false

  def render(template, _assigns), do: Phoenix.Controller.status_message_from_template(template)
end
