# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.AuthorizationCodeResource do
  @default_expunge_interval_hrs 1
  @default_consumed_grace_seconds 86_400

  @dsl [
    %Spark.Dsl.Section{
      name: :oauth2_server,
      describe: "Configuration for an OAuth2 authorization-code resource",
      schema: [
        expunge_expired_action_name: [
          type: :atom,
          doc:
            "The name of the auto-generated destroy action that removes expired/consumed rows.",
          default: :expunge_expired
        ],
        expunge_interval: [
          type: :pos_integer,
          doc:
            "How often (in hours) to scan this resource for rows that have expired and can be removed.",
          default: @default_expunge_interval_hrs
        ],
        consumed_grace: [
          type: :pos_integer,
          doc:
            "How long (in seconds) to keep consumed authorization-code rows before expunging them.",
          default: @default_consumed_grace_seconds
        ]
      ]
    }
  ]

  @moduledoc """
  Resource extension for OAuth 2.1 authorization-code rows.

  Adds an auto-generated `:expunge_expired` destroy action and exposes
  configuration for the `AshAuthentication.Oauth2Server.Expunger`
  GenServer, which periodically removes:

    * rows whose `expires_at` has passed
    * rows whose `consumed_at` is older than `consumed_grace`

  ## Usage

      use Ash.Resource,
        extensions: [AshAuthentication.Oauth2Server.AuthorizationCodeResource],
        ...

      oauth2_server do
        expunge_interval 1
        consumed_grace 86_400
      end

  ## Removing expired records

  Add `AshAuthentication.Oauth2Server.Supervisor` to your application
  supervision tree; it starts the expunger which scans on each
  resource's configured interval.
  """

  alias AshAuthentication.Oauth2Server.AuthorizationCodeResource

  use Spark.Dsl.Extension,
    sections: @dsl,
    transformers: [AuthorizationCodeResource.Transformer],
    verifiers: [AuthorizationCodeResource.Verifier]

  @doc """
  Bulk-destroy authorization-code rows that have expired or whose
  `consumed_at` is older than the configured `consumed_grace`.
  """
  @spec expunge_expired(Ash.Resource.t(), keyword) :: :ok | {:error, any}
  defdelegate expunge_expired(resource, opts \\ []), to: AuthorizationCodeResource.Actions
end
