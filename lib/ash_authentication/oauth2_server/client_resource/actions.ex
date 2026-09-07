# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.ClientResource.Actions do
  @moduledoc """
  Action helpers for resources extended with
  `AshAuthentication.Oauth2Server.ClientResource`.
  """

  alias Ash.Query
  alias AshAuthentication.Oauth2Server.ClientResource.Info

  require Logger

  @ash_context %{private: %{ash_authentication?: true}}

  @doc """
  Bulk-destroy CIMD client rows (those with a `cimd_url`) whose
  `last_used_at` is older than the configured `cimd_client_ttl`.

  ## Options

    * `:tenant` — required for resources using `strategy :context`
      multitenancy without `global? true`. Defaults to `nil`.
    * `:domain` — overrides the resource's compile-time domain.
  """
  @spec expunge_expired(Ash.Resource.t(), keyword) :: :ok | {:error, any}
  def expunge_expired(resource, opts \\ []) do
    action_name = Info.oauth2_server_expunge_expired_action_name!(resource)
    domain = opts[:domain] || Ash.Resource.Info.domain(resource)
    tenant = opts[:tenant]

    resource
    |> Query.new()
    |> Query.set_context(@ash_context)
    |> Query.set_tenant(tenant)
    |> Ash.bulk_destroy(action_name, %{},
      domain: domain,
      tenant: tenant,
      strategy: [:atomic, :atomic_batches, :stream],
      context: @ash_context,
      return_errors?: true,
      notify?: false,
      return_records?: false
    )
    |> case do
      %{status: :success} -> :ok
      %{errors: errors} -> {:error, Ash.Error.to_class(errors)}
    end
  end

  @doc """
  Refresh `last_used_at` on a single client record so an actively-used CIMD
  client is not collected. Best-effort: failures are logged, never raised,
  so a bookkeeping write can never fail a token exchange.
  """
  @spec touch_last_used(Ash.Resource.record(), keyword) :: :ok
  def touch_last_used(client, opts \\ []) do
    resource = client.__struct__
    action_name = Info.oauth2_server_touch_last_used_action_name!(resource)
    domain = opts[:domain] || Ash.Resource.Info.domain(resource)
    tenant = opts[:tenant]

    client
    |> Ash.Changeset.for_update(action_name, %{}, tenant: tenant, context: @ash_context)
    |> Ash.update(domain: domain, tenant: tenant)
    |> case do
      {:ok, _} ->
        :ok

      {:error, error} ->
        Logger.warning(
          "Oauth2Server.ClientResource: failed to touch last_used_at on " <>
            "#{inspect(resource)}: #{inspect(error)}"
        )

        :ok
    end
  end
end
