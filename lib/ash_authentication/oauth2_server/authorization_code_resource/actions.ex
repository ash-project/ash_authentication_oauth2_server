# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.AuthorizationCodeResource.Actions do
  @moduledoc """
  Action helpers for resources extended with
  `AshAuthentication.Oauth2Server.AuthorizationCodeResource`.
  """

  alias Ash.Query
  alias AshAuthentication.Oauth2Server.AuthorizationCodeResource.Info

  @ash_context %{private: %{ash_authentication?: true}}

  @doc """
  Bulk-destroy authorization-code rows that have expired or whose
  `consumed_at` is older than the configured grace.

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
end
