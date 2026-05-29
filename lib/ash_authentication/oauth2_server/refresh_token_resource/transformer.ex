# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.RefreshTokenResource.Transformer do
  @moduledoc false

  use Spark.Dsl.Transformer

  alias Ash.Resource
  alias AshAuthentication.Oauth2Server.RefreshTokenResource.Info
  alias Spark.Dsl.Transformer

  require Ash.Expr

  @impl true
  def after?(_), do: false

  @impl true
  def before?(_), do: false

  @impl true
  def transform(dsl_state) do
    action_name = Info.oauth2_server_expunge_expired_action_name!(dsl_state)
    revoked_grace = Info.oauth2_server_revoked_grace!(dsl_state)
    rotated_grace = Info.oauth2_server_rotated_grace!(dsl_state)

    case Transformer.get_entities(dsl_state, [:actions])
         |> Enum.find(&(&1.name == action_name)) do
      nil ->
        with {:ok, action} <- build_action(action_name, revoked_grace, rotated_grace) do
          {:ok, Transformer.add_entity(dsl_state, [:actions], action)}
        end

      _existing ->
        {:ok, dsl_state}
    end
  end

  defp build_action(name, revoked_grace, rotated_grace) do
    filter =
      Transformer.build_entity!(Resource.Dsl, [:actions, :destroy], :change,
        change:
          {Ash.Resource.Change.Filter,
           filter:
             Ash.Expr.expr(
               expires_at < now() or
                 (not is_nil(revoked_at) and revoked_at < ago(^revoked_grace, :second)) or
                 (not is_nil(rotated_at) and rotated_at < ago(^rotated_grace, :second))
             )}
      )

    Transformer.build_entity(Resource.Dsl, [:actions], :destroy,
      name: name,
      accept: [],
      changes: [filter]
    )
  end
end
