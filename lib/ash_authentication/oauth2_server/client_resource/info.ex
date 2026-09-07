# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.ClientResource.Info do
  @moduledoc """
  Introspection helpers for the
  `AshAuthentication.Oauth2Server.ClientResource` extension.
  """

  use Spark.InfoGenerator,
    extension: AshAuthentication.Oauth2Server.ClientResource,
    sections: [:oauth2_server]
end
