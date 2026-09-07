# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.ClientResource do
  @default_expunge_interval_hrs 24
  # 30 days
  @default_cimd_client_ttl_seconds 2_592_000

  @dsl [
    %Spark.Dsl.Section{
      name: :oauth2_server,
      describe: "Configuration for an OAuth2 client resource.",
      schema: [
        expunge_expired_action_name: [
          type: :atom,
          doc:
            "The name of the auto-generated destroy action that removes stale CIMD client rows.",
          default: :expunge_expired
        ],
        touch_last_used_action_name: [
          type: :atom,
          doc:
            "The name of the update action that refreshes a CIMD client's `last_used_at`. " <>
              "Reused if it already exists on the resource; auto-generated otherwise.",
          default: :touch
        ],
        expunge_interval: [
          type: :pos_integer,
          doc: "How often (in hours) to scan this resource for stale CIMD client rows to remove.",
          default: @default_expunge_interval_hrs
        ],
        cimd_client_ttl: [
          type: :pos_integer,
          doc:
            "How long (in seconds) a CIMD client (a row with a `cimd_url`) may go unused before it is expunged.",
          default: @default_cimd_client_ttl_seconds
        ]
      ]
    }
  ]

  @moduledoc """
  Resource extension for an OAuth2 client resource.

  Its purpose is garbage-collecting Client ID Metadata Document (CIMD)
  clients. A CIMD client is resolved and upserted (keyed by `cimd_url`)
  whenever an unfamiliar URL `client_id` reaches `/authorize`, so without
  a bound the client table grows one row per distinct URL ever seen. This
  extension adds an auto-generated `:expunge_expired` destroy action that
  removes CIMD client rows whose `last_used_at` is older than
  `cimd_client_ttl`, and reuses (or auto-generates) a `:touch` update
  action the token and authorize paths call to keep active clients from
  being collected.

  Only rows with a non-nil `cimd_url` are ever removed; ordinary
  (registered) clients are untouched.

  ## Usage

      use Ash.Resource,
        extensions: [AshAuthentication.Oauth2Server.ClientResource],
        ...

      oauth2_server do
        expunge_interval 24
        cimd_client_ttl 2_592_000
      end

  The resource must have `cimd_url` and `last_used_at` attributes (the
  installer scaffolds both). Removal is driven by
  `AshAuthentication.Oauth2Server.Expunger`, started by
  `AshAuthentication.Oauth2Server.Supervisor`.
  """

  alias AshAuthentication.Oauth2Server.ClientResource

  use Spark.Dsl.Extension,
    sections: @dsl,
    transformers: [ClientResource.Transformer]

  @doc """
  Bulk-destroy CIMD client rows (those with a `cimd_url`) whose
  `last_used_at` is older than the configured `cimd_client_ttl`.
  """
  @spec expunge_expired(Ash.Resource.t(), keyword) :: :ok | {:error, any}
  defdelegate expunge_expired(resource, opts \\ []), to: ClientResource.Actions

  @doc """
  Refresh a CIMD client's `last_used_at` to now, so that an actively-used
  client is not collected by `expunge_expired/2`. Best-effort; a failure
  is logged, never raised.
  """
  @spec touch_last_used(Ash.Resource.record(), keyword) :: :ok
  defdelegate touch_last_used(client, opts \\ []), to: ClientResource.Actions
end
