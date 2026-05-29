# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.RefreshTokenResource do
  @default_expunge_interval_hrs 12
  @default_grace_seconds 86_400

  @dsl [
    %Spark.Dsl.Section{
      name: :oauth2_server,
      describe: "Configuration for an OAuth2 refresh-token resource",
      schema: [
        expunge_expired_action_name: [
          type: :atom,
          doc:
            "The name of the auto-generated destroy action that removes expired/rotated/revoked rows.",
          default: :expunge_expired
        ],
        expunge_interval: [
          type: :pos_integer,
          doc:
            "How often (in hours) to scan this resource for rows that have expired and can be removed.",
          default: @default_expunge_interval_hrs
        ],
        revoked_grace: [
          type: :pos_integer,
          doc: "How long (in seconds) to keep revoked refresh-token rows before expunging them.",
          default: @default_grace_seconds
        ],
        rotated_grace: [
          type: :pos_integer,
          doc: "How long (in seconds) to keep rotated refresh-token rows before expunging them.",
          default: @default_grace_seconds
        ]
      ]
    }
  ]

  @moduledoc """
  Resource extension for OAuth 2.1 refresh-token rows.

  Verifies, at compile time, that the resource conforms to the
  contract the `Token` core depends on for race-safe rotation
  (writable `:id`, required attributes, a `:rotate` action carrying
  `AshAuthentication.Oauth2Server.Changes.RotateRefreshToken`).

  Adds an auto-generated `:expunge_expired` destroy action and
  exposes configuration for the
  `AshAuthentication.Oauth2Server.Expunger` GenServer, which
  periodically removes:

    * rows whose `expires_at` has passed
    * rows whose `revoked_at` is older than `revoked_grace`
    * rows whose `rotated_at` is older than `rotated_grace`

  ## Usage

      use Ash.Resource,
        extensions: [AshAuthentication.Oauth2Server.RefreshTokenResource],
        ...

      oauth2_server do
        expunge_interval 12
        revoked_grace 86_400
        rotated_grace 86_400
      end

  ## Removing expired records

  Add `AshAuthentication.Oauth2Server.Supervisor` to your application
  supervision tree; it starts the expunger which scans on each
  resource's configured interval.
  """

  alias AshAuthentication.Oauth2Server.RefreshTokenResource

  use Spark.Dsl.Extension,
    sections: @dsl,
    transformers: [RefreshTokenResource.Transformer],
    verifiers: [RefreshTokenResource.Verifier]

  @doc """
  Bulk-destroy refresh-token rows that have expired, or whose
  `revoked_at` / `rotated_at` is older than the configured grace.
  """
  @spec expunge_expired(Ash.Resource.t(), keyword) :: :ok | {:error, any}
  defdelegate expunge_expired(resource, opts \\ []), to: RefreshTokenResource.Actions
end
