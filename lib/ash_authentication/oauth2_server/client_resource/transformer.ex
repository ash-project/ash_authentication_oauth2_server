# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.ClientResource.Transformer do
  @moduledoc false

  use Spark.Dsl.Transformer

  alias Ash.Resource
  alias AshAuthentication.Oauth2Server.ClientResource.Info
  alias Spark.Dsl.Transformer

  require Ash.Expr

  @impl true
  def after?(_), do: false

  @impl true
  def before?(_), do: false

  @impl true
  def transform(dsl_state) do
    expunge_name = Info.oauth2_server_expunge_expired_action_name!(dsl_state)
    touch_name = Info.oauth2_server_touch_last_used_action_name!(dsl_state)
    ttl = Info.oauth2_server_cimd_client_ttl!(dsl_state)

    with {:ok, dsl_state} <- maybe_add_expunge(dsl_state, expunge_name, ttl) do
      maybe_add_touch(dsl_state, touch_name)
    end
  end

  defp maybe_add_expunge(dsl_state, name, ttl) do
    if action_exists?(dsl_state, name) do
      {:ok, dsl_state}
    else
      # Only CIMD rows (those with a cimd_url) that have not been used within
      # the TTL are removed; registered clients (cimd_url is nil) are untouched.
      filter =
        Transformer.build_entity!(Resource.Dsl, [:actions, :destroy], :change,
          change:
            {Ash.Resource.Change.Filter,
             filter:
               Ash.Expr.expr(
                 not is_nil(cimd_url) and not is_nil(last_used_at) and
                   last_used_at < ago(^ttl, :second)
               )}
        )

      with {:ok, action} <-
             Transformer.build_entity(Resource.Dsl, [:actions], :destroy,
               name: name,
               accept: [],
               changes: [filter]
             ) do
        {:ok, Transformer.add_entity(dsl_state, [:actions], action)}
      end
    end
  end

  defp maybe_add_touch(dsl_state, name) do
    if action_exists?(dsl_state, name) do
      {:ok, dsl_state}
    else
      # Mirrors the installer scaffold: `change atomic_update(:last_used_at, expr(now()))`.
      change =
        Transformer.build_entity!(Resource.Dsl, [:actions, :update], :change,
          change:
            {Ash.Resource.Change.Atomic,
             attribute: :last_used_at, expr: Ash.Expr.expr(now()), cast_atomic?: true}
        )

      # require_atomic? false so the bump still lands on resources whose
      # changesets carry before_action hooks (e.g. an identity with
      # `pre_check_with`); Ash still runs it atomically where it can.
      with {:ok, action} <-
             Transformer.build_entity(Resource.Dsl, [:actions], :update,
               name: name,
               accept: [],
               require_atomic?: false,
               changes: [change]
             ) do
        {:ok, Transformer.add_entity(dsl_state, [:actions], action)}
      end
    end
  end

  defp action_exists?(dsl_state, name) do
    dsl_state
    |> Transformer.get_entities([:actions])
    |> Enum.any?(&(&1.name == name))
  end
end
