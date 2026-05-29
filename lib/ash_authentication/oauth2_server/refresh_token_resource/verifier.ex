# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.RefreshTokenResource.Verifier do
  @moduledoc """
  Verifies the refresh-token resource has the shape the Token core
  depends on:

    * `:id` attribute is writable (the library pre-allocates the new
      refresh row's id so a rotation is one filtered UPDATE).
    * Every attribute the `Token` core reads/writes exists with the
      expected type — `token_hash`, `client_id`, `user_id`, `scope`,
      `resource_uri`, `expires_at`, `rotated_to_id`, `rotated_at`,
      `revoked_at`.
    * `:rotate` action exists and carries
      `AshAuthentication.Oauth2Server.Changes.RotateRefreshToken`,
      which attaches the atomic filter (filters already-rotated /
      already-revoked rows out of the underlying UPDATE; race-safety
      lives entirely here).

  Violations raise at resource-compile time with a fix-it message.
  """

  use Spark.Dsl.Verifier

  alias Spark.{Dsl.Verifier, Error.DslError}

  # Attributes the Token core reads or writes. Type lists permit either
  # the canonical Ash type module or the shorthand atom the DSL accepts.
  @required_attributes [
    {:token_hash, [Ash.Type.String, :string], allow_nil?: false},
    {:client_id, [Ash.Type.UUIDv7, :uuid_v7], allow_nil?: false},
    {:scope, [Ash.Type.String, :string], allow_nil?: false},
    {:resource_uri, [Ash.Type.String, :string], allow_nil?: false},
    {:expires_at, [Ash.Type.UtcDatetimeUsec, :utc_datetime_usec], allow_nil?: false},
    {:chain_id, [Ash.Type.UUIDv7, :uuid_v7], allow_nil?: false},
    {:generation, [Ash.Type.Integer, :integer], allow_nil?: false},
    {:rotated_to_id, [Ash.Type.UUIDv7, :uuid_v7], allow_nil?: true},
    {:rotated_at, [Ash.Type.UtcDatetimeUsec, :utc_datetime_usec], allow_nil?: true},
    {:revoked_at, [Ash.Type.UtcDatetimeUsec, :utc_datetime_usec], allow_nil?: true}
  ]

  @rotate_change AshAuthentication.Oauth2Server.Changes.RotateRefreshToken

  @impl true
  def verify(dsl_state) do
    with :ok <- verify_id_writable(dsl_state),
         :ok <- verify_required_attributes(dsl_state),
         :ok <- verify_user_id_attribute(dsl_state) do
      verify_rotate_action(dsl_state)
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

  # `user_id` type depends on the host app's `User.id`. We check only
  # that the attribute is declared and non-nullable.
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
        "The OAuth2 refresh-token resource must declare an attribute " <>
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

  defp verify_id_writable(dsl_state) do
    case attribute(dsl_state, :id) do
      %{writable?: true} ->
        :ok

      %{writable?: false} ->
        {:error,
         DslError.exception(
           module: Verifier.get_persisted(dsl_state, :module),
           path: [:attributes, :id],
           message: """
           The OAuth2 refresh-token resource needs a writable `:id` attribute.

           The Token core pre-allocates the new refresh row's id so the
           rotation can be a single filtered UPDATE; with a non-writable
           `:id` it can't be set explicitly.

           Fix: declare `:id` like this (instead of `uuid_v7_primary_key :id`):

               attribute :id, :uuid_v7 do
                 primary_key? true
                 allow_nil? false
                 default &Ash.UUIDv7.generate/0
                 writable? true
                 public? true
               end
           """
         )}

      nil ->
        {:error,
         DslError.exception(
           module: Verifier.get_persisted(dsl_state, :module),
           path: [:attributes],
           message: "The OAuth2 refresh-token resource must declare a writable `:id` primary key."
         )}
    end
  end

  defp verify_rotate_action(dsl_state) do
    case action(dsl_state, :rotate) do
      nil ->
        {:error,
         DslError.exception(
           module: Verifier.get_persisted(dsl_state, :module),
           path: [:actions],
           message:
             "The OAuth2 refresh-token resource must declare a `:rotate` update action. " <>
               "Re-run `mix ash_authentication.add_oauth2_server` or copy the action from the installer's scaffold."
         )}

      %{type: :update} = action ->
        if has_rotate_change?(action) do
          :ok
        else
          {:error, rotate_missing_change_error(dsl_state)}
        end

      other ->
        {:error,
         DslError.exception(
           module: Verifier.get_persisted(dsl_state, :module),
           path: [:actions, :rotate],
           message:
             "The `:rotate` action must be an `update` action (got #{inspect(other.type)})."
         )}
    end
  end

  # The change module attaches the atomic filter AND sets the
  # rotated_to_id attribute. Presence of the change is the contract.
  defp has_rotate_change?(%{changes: changes}) when is_list(changes) do
    Enum.any?(changes, fn
      %{change: {mod, _opts}} -> mod == @rotate_change
      %{change: mod} when is_atom(mod) -> mod == @rotate_change
      _ -> false
    end)
  end

  defp has_rotate_change?(_), do: false

  defp rotate_missing_change_error(dsl_state) do
    DslError.exception(
      module: Verifier.get_persisted(dsl_state, :module),
      path: [:actions, :rotate],
      message: """
      The `:rotate` action must include the
      `#{inspect(@rotate_change)}` change.

      That change attaches the atomic filter and sets the
      `:rotated_to_id` attribute together — without it, two concurrent
      refresh-token requests can both succeed and issue two new tokens
      for the same refresh, defeating reuse detection.

      Fix:

          update :rotate do
            argument :rotated_to_id, :uuid_v7, allow_nil?: false
            accept []

            change #{inspect(@rotate_change)}
          end
      """
    )
  end

  defp attribute(dsl_state, name) do
    dsl_state
    |> Verifier.get_entities([:attributes])
    |> Enum.find(&(&1.name == name))
  end

  defp action(dsl_state, name) do
    dsl_state
    |> Verifier.get_entities([:actions])
    |> Enum.find(&(&1.name == name))
  end
end
