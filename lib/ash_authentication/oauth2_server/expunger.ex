# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.Expunger do
  @moduledoc """
  A `GenServer` which periodically removes expired OAuth2 authorization
  codes and refresh tokens.

  Scans all resources extended with either
  `AshAuthentication.Oauth2Server.AuthorizationCodeResource` or
  `AshAuthentication.Oauth2Server.RefreshTokenResource` and, on each
  resource's configured `expunge_interval` (hours), runs that
  resource's `:expunge_expired` destroy action.

  ## Multitenancy

  For resources using `strategy :context` multitenancy (and not
  `global? true`), Ash refuses tenant-less destroys, and a single
  tenant-less call could not reach rows that live in separate tenant
  schemas anyway. Pass `:list_tenants` (via the `Supervisor`) so the
  expunger fans out one destroy per tenant per resource:

      {AshAuthentication.Oauth2Server.Supervisor,
        otp_app: :my_app,
        list_tenants: {MyApp.Repo, :all_tenants, []}}

  `list_tenants` accepts a static list, a 0-arity function, or an
  `{module, function, args}` tuple. Default: `[nil]` — a single
  tenant-less pass, which is correct for apps with no multitenancy or
  with `strategy :attribute, global? true`.

  Started for you by `AshAuthentication.Oauth2Server.Supervisor` —
  you should not need to start this yourself.
  """

  use GenServer

  alias AshAuthentication.Oauth2Server.AuthorizationCodeResource
  alias AshAuthentication.Oauth2Server.RefreshTokenResource

  require Logger

  @doc false
  @spec start_link(keyword) :: GenServer.on_start()
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts)

  @impl true
  def init(opts) do
    otp_app = Keyword.fetch!(opts, :otp_app)
    list_tenants = Keyword.get(opts, :list_tenants, [nil])

    resource_states =
      otp_app
      |> Spark.sparks(Ash.Resource)
      |> Stream.flat_map(&extension_for/1)
      |> Enum.reduce(%{}, fn {resource, extension}, acc ->
        state = schedule_timer(%{interval: nil, timer: nil}, resource, extension)
        Map.put(acc, resource, {extension, state})
      end)

    {:ok, %{otp_app: otp_app, resources: resource_states, list_tenants: list_tenants}}
  end

  @impl true
  def handle_info({:expunge, resource}, state) do
    {extension, resource_state} = Map.fetch!(state.resources, resource)

    for tenant <- resolve_tenants(state.list_tenants) do
      case extension.expunge_expired(resource, tenant: tenant) do
        :ok ->
          :ok

        {:error, reason} ->
          Logger.warning(
            "Oauth2Server.Expunger: failed to expunge #{inspect(resource)} " <>
              "(tenant=#{inspect(tenant)}): #{inspect(reason)}"
          )
      end
    end

    resource_state = schedule_timer(resource_state, resource, extension)

    {:noreply,
     %{state | resources: Map.put(state.resources, resource, {extension, resource_state})}}
  end

  def handle_info(_, state), do: {:noreply, state}

  defp resolve_tenants(list) when is_list(list), do: list
  defp resolve_tenants(fun) when is_function(fun, 0), do: fun.()
  defp resolve_tenants({mod, fun, args}), do: apply(mod, fun, args)

  # A resource may carry only one of the two extensions; produce the
  # matching tuple so we know which `expunge_expired/1` helper to call.
  defp extension_for(resource) do
    extensions = Spark.extensions(resource)

    cond do
      AuthorizationCodeResource in extensions ->
        [{resource, AuthorizationCodeResource}]

      RefreshTokenResource in extensions ->
        [{resource, RefreshTokenResource}]

      true ->
        []
    end
  end

  defp schedule_timer(state, resource, extension) do
    new_interval = interval_for(resource, extension)

    cond do
      state.interval == new_interval and not is_nil(state.timer) ->
        state

      is_nil(state.timer) ->
        {:ok, timer} = :timer.send_interval(new_interval, {:expunge, resource})
        %{state | interval: new_interval, timer: timer}

      true ->
        :timer.cancel(state.timer)
        {:ok, timer} = :timer.send_interval(new_interval, {:expunge, resource})
        %{state | interval: new_interval, timer: timer}
    end
  end

  # Interval is configured in hours; convert to milliseconds.
  defp interval_for(resource, extension) do
    info_module = Module.concat(extension, Info)
    info_module.oauth2_server_expunge_interval!(resource) * 60 * 60 * 1000
  end
end
