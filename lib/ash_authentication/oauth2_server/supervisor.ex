# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.Supervisor do
  @moduledoc """
  Supervises the background processes for an OAuth2 server.

  Add this to your application's supervision tree, passing your OTP
  app name:

  ```elixir
  defmodule MyApp.Application do
    use Application

    def start(_type, _args) do
      children = [
        # ...
        {AshAuthentication.Oauth2Server.Supervisor, otp_app: :my_app}
      ]

      Supervisor.start_link(children, strategy: :one_for_one)
    end
  end
  ```

  ## Options

    * `:otp_app` (required) — your application's OTP app name.
    * `:list_tenants` — for apps using `strategy :context` multitenancy
      on the OAuth2 resources. Accepts a static list of tenant
      identifiers, a 0-arity function, or an `{module, function, args}`
      tuple. The expunger will run once per tenant per resource per
      interval. Defaults to `[nil]` (single tenant-less pass — correct
      for apps with no multitenancy or `global? true` attribute
      multitenancy).

  Currently this supervisor starts:

    * `AshAuthentication.Oauth2Server.Expunger` — periodically removes
      expired authorization codes and refresh tokens from any resource
      extended with `AshAuthentication.Oauth2Server.AuthorizationCodeResource`
      or `AshAuthentication.Oauth2Server.RefreshTokenResource`.
  """

  use Supervisor

  alias AshAuthentication.Oauth2Server.Expunger

  @doc false
  @spec start_link(keyword) :: Supervisor.on_start()
  def start_link(opts) do
    Supervisor.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(opts) do
    otp_app = Keyword.fetch!(opts, :otp_app)
    expunger_opts = Keyword.take(opts, [:list_tenants]) |> Keyword.put(:otp_app, otp_app)

    children = [
      {Expunger, expunger_opts}
    ]

    Supervisor.init(children, strategy: :one_for_one)
  end
end
