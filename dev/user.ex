# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule Dev.Accounts.User do
  @moduledoc false
  use Ash.Resource,
    domain: Dev.Accounts,
    data_layer: Ash.DataLayer.Ets,
    authorizers: [Ash.Policy.Authorizer],
    extensions: [AshAuthentication, Dev.MockStrategy, AshGraphql.Resource]

  authentication do
    strategies do
      mock(:mock)
    end
  end

  graphql do
    type :user

    queries do
      read_one :me, :me
    end
  end

  attributes do
    uuid_v7_primary_key :id
    attribute :email, :ci_string, public?: true, allow_nil?: false
  end

  actions do
    defaults [:read]

    read :me do
      filter expr(id == ^actor(:id))
    end

    create :sign_in_with_mock do
      accept []
      upsert? true
      upsert_identity :unique_email
      change set_attribute(:email, "dev@example.com")
    end

    action :greet, :string do
      description "Returns a static greeting."

      run fn _input, _context ->
        {:ok, "Hello from the ash_authentication_oauth2_server dev app!"}
      end
    end
  end

  policies do
    bypass AshAuthentication.Checks.AshAuthenticationInteraction do
      authorize_if always()
    end

    policy action_type(:read) do
      authorize_if expr(id == ^actor(:id))
    end

    policy action(:greet) do
      authorize_if actor_present()
    end
  end

  identities do
    identity :unique_email, [:email], pre_check_with: Dev.Accounts
  end
end
