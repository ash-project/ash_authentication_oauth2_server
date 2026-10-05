# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule Dev.MockStrategy do
  @moduledoc """
  An authentication strategy that signs in a fixed user without any
  credentials. Never use it outside the dev app.
  """

  defstruct name: :mock, resource: nil, __spark_metadata__: nil

  use AshAuthentication.Strategy.Custom,
    entity: %Spark.Dsl.Entity{
      name: :mock,
      describe: "Signs in `dev@example.com` without credentials.",
      target: __MODULE__,
      args: [{:optional, :name, :mock}],
      schema: [name: [type: :atom, required: true]]
    }
end

defimpl AshAuthentication.Strategy, for: Dev.MockStrategy do
  import AshAuthentication.Plug.Helpers, only: [store_authentication_result: 2]

  def name(strategy), do: strategy.name
  def phases(_strategy), do: [:sign_in]
  def actions(_strategy), do: [:sign_in]

  def routes(strategy) do
    subject_name = AshAuthentication.Info.authentication_subject_name!(strategy.resource)
    [{"/#{subject_name}/#{strategy.name}", :sign_in}]
  end

  def method_for_phase(_strategy, :sign_in), do: :get

  def plug(strategy, :sign_in, conn) do
    store_authentication_result(conn, action(strategy, :sign_in, %{}, []))
  end

  def action(strategy, :sign_in, _params, options) do
    strategy.resource
    |> Ash.Changeset.for_create(:sign_in_with_mock, %{},
      context: %{private: %{ash_authentication?: true}}
    )
    |> Ash.create(options)
  end

  def tokens_required?(_strategy), do: false
end
