# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.AuthorizationCodeResource.Verifier do
  @moduledoc """
  Verifies that an OAuth2 authorization-code resource declares every
  attribute the `Authorize` and `Token` cores read or write.

  Raises a compile-time DSL error if any required attribute is
  missing or has the wrong type / nullability.
  """

  use Spark.Dsl.Verifier

  alias Spark.{Dsl.Verifier, Error.DslError}

  # Required by the Authorize/Token cores. `user_id` is checked
  # separately because its type matches the host app's `User.id`.
  @required_attributes [
    {:client_id, [Ash.Type.UUIDv7, :uuid_v7], allow_nil?: false},
    {:redirect_uri, [Ash.Type.String, :string], allow_nil?: false},
    {:code_challenge, [Ash.Type.String, :string], allow_nil?: false},
    {:scope, [Ash.Type.String, :string], allow_nil?: false},
    {:resource_uri, [Ash.Type.String, :string], allow_nil?: false},
    {:expires_at, [Ash.Type.UtcDatetimeUsec, :utc_datetime_usec], allow_nil?: false},
    {:consumed_at, [Ash.Type.UtcDatetimeUsec, :utc_datetime_usec], allow_nil?: true}
  ]

  @impl true
  def verify(dsl_state) do
    with :ok <- verify_required_attributes(dsl_state) do
      verify_user_id_attribute(dsl_state)
    end
  end

  defp verify_required_attributes(dsl_state) do
    Enum.reduce_while(@required_attributes, :ok, fn {name, types, opts}, :ok ->
      case verify_attribute(dsl_state, name, types, opts) do
        :ok -> {:cont, :ok}
        {:error, _} = err -> {:halt, err}
      end
    end)
  end

  defp verify_user_id_attribute(dsl_state) do
    case attribute(dsl_state, :user_id) do
      nil ->
        {:error, missing_attribute_error(dsl_state, :user_id, "matching your User's id type")}

      %{allow_nil?: true} ->
        {:error, allow_nil_error(dsl_state, :user_id, false)}

      _ ->
        :ok
    end
  end

  defp verify_attribute(dsl_state, name, types, opts) do
    case attribute(dsl_state, name) do
      nil ->
        {:error, missing_attribute_error(dsl_state, name, type_hint(types))}

      attr ->
        with :ok <- check_type(attr, types) do
          check_allow_nil(dsl_state, attr, opts[:allow_nil?])
        end
    end
  end

  defp check_type(attr, types) do
    if attr.type in types do
      :ok
    else
      {:error,
       DslError.exception(
         path: [:attributes, attr.name],
         message:
           "The `:#{attr.name}` attribute must have type `#{type_hint(types)}` " <>
             "(got `#{inspect(attr.type)}`)."
       )}
    end
  end

  defp check_allow_nil(dsl_state, attr, expected) do
    if attr.allow_nil? == expected do
      :ok
    else
      {:error, allow_nil_error(dsl_state, attr.name, expected)}
    end
  end

  defp missing_attribute_error(dsl_state, name, type_hint) do
    DslError.exception(
      module: Verifier.get_persisted(dsl_state, :module),
      path: [:attributes, name],
      message:
        "The OAuth2 authorization-code resource must declare an attribute " <>
          "`:#{name}` (#{type_hint})."
    )
  end

  defp allow_nil_error(dsl_state, name, expected) do
    DslError.exception(
      module: Verifier.get_persisted(dsl_state, :module),
      path: [:attributes, name],
      message: "The `:#{name}` attribute must have `allow_nil?: #{expected}`."
    )
  end

  defp type_hint([_canonical, shorthand | _]), do: ":#{shorthand}"
  defp type_hint([type | _]), do: inspect(type)

  defp attribute(dsl_state, name) do
    dsl_state
    |> Verifier.get_entities([:attributes])
    |> Enum.find(&(&1.name == name))
  end
end
