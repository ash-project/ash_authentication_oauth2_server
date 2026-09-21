# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Phoenix.Oauth2Server.ConsentHandler.Default do
  @moduledoc """
  Default consent handler preserving the authorization server's scope-only flow.

  It delegates prior-consent checks and grant persistence to the public
  `AshAuthentication.Oauth2Server.Authorize` API and adds no presentation data.
  Applications opt into additional requirements by configuring another module
  that implements `AshAuthentication.Phoenix.Oauth2Server.ConsentHandler`.
  """

  @behaviour AshAuthentication.Phoenix.Oauth2Server.ConsentHandler

  alias AshAuthentication.Oauth2Server.Authorize

  @impl true
  @doc "Checks whether the persisted OAuth scope consent covers the validated request."
  def consented?(server, user, validated, opts) do
    Authorize.consented?(server, user, validated.client, validated.scope, opts)
  end

  @impl true
  @doc "Returns no application-specific consent view assigns."
  def prepare(_server, _user, _validated, _params, _opts), do: {:ok, %{}}

  @impl true
  @doc "Persists the validated OAuth scope grant through the public authorization API."
  def grant(server, user, validated, _params, opts) do
    {:ok, Authorize.grant_consent!(server, user, validated.client, validated.scope, opts)}
  end
end
