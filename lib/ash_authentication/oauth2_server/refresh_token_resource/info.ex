# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.RefreshTokenResource.Info do
  @moduledoc """
  Introspection helpers for the
  `AshAuthentication.Oauth2Server.RefreshTokenResource` extension.
  """

  use Spark.InfoGenerator,
    extension: AshAuthentication.Oauth2Server.RefreshTokenResource,
    sections: [:oauth2_server]
end
