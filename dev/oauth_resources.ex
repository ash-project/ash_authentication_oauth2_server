# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule Dev.Accounts.OAuthClient do
  @moduledoc false
  use Ash.Resource,
    domain: Dev.Accounts,
    data_layer: Ash.DataLayer.Ets,
    extensions: [AshAuthentication.Oauth2Server.ClientResource]

  attributes do
    uuid_v7_primary_key :id
    attribute :client_name, :string, public?: true, allow_nil?: false
    attribute :redirect_uris, {:array, :string}, public?: true, allow_nil?: false, default: []
    attribute :grant_types, {:array, :string}, public?: true, default: ["authorization_code"]
    attribute :response_types, {:array, :string}, public?: true, default: ["code"]
    attribute :token_endpoint_auth_method, :string, public?: true, default: "none"
    attribute :scope, :string, public?: true, default: "mcp"
    attribute :cimd_url, :string, public?: true
    attribute :last_used_at, :utc_datetime_usec, public?: true
    create_timestamp :inserted_at
    update_timestamp :updated_at
  end

  actions do
    defaults [:read, :destroy]

    create :register do
      accept [
        :client_name,
        :redirect_uris,
        :grant_types,
        :response_types,
        :token_endpoint_auth_method,
        :scope
      ]
    end

    create :register_cimd do
      upsert? true
      upsert_identity :by_cimd_url

      accept [
        :cimd_url,
        :client_name,
        :redirect_uris,
        :grant_types,
        :response_types,
        :token_endpoint_auth_method,
        :scope
      ]
    end
  end

  identities do
    identity :by_cimd_url, [:cimd_url], pre_check_with: Dev.Accounts
  end
end

defmodule Dev.Accounts.OAuthAuthorizationCode do
  @moduledoc false
  use Ash.Resource,
    domain: Dev.Accounts,
    data_layer: Ash.DataLayer.Ets,
    extensions: [AshAuthentication.Oauth2Server.AuthorizationCodeResource]

  attributes do
    uuid_v7_primary_key :id
    attribute :client_id, :uuid_v7, allow_nil?: false, public?: true
    attribute :user_id, :uuid_v7, allow_nil?: false, public?: true
    attribute :redirect_uri, :string, allow_nil?: false, public?: true
    attribute :code_challenge, :string, allow_nil?: false, public?: true
    attribute :scope, :string, allow_nil?: false, public?: true
    attribute :resource_uri, :string, allow_nil?: false, public?: true
    attribute :expires_at, :utc_datetime_usec, allow_nil?: false, public?: true
    attribute :consumed_at, :utc_datetime_usec, public?: true
  end

  actions do
    defaults [:read, :destroy]

    create :create do
      accept [
        :client_id,
        :user_id,
        :redirect_uri,
        :code_challenge,
        :scope,
        :resource_uri,
        :expires_at
      ]
    end

    update :consume do
      accept []

      validate absent(:consumed_at) do
        message "code already used"
      end

      change atomic_update(:consumed_at, expr(now()))
    end
  end
end

defmodule Dev.Accounts.OAuthRefreshToken do
  @moduledoc false
  use Ash.Resource,
    domain: Dev.Accounts,
    data_layer: Ash.DataLayer.Ets,
    extensions: [AshAuthentication.Oauth2Server.RefreshTokenResource]

  attributes do
    # The token core sets the id of the next token when it rotates.
    uuid_v7_primary_key :id, writable?: true
    attribute :token_hash, :string, allow_nil?: false, public?: true
    attribute :client_id, :uuid_v7, allow_nil?: false, public?: true
    attribute :user_id, :uuid_v7, allow_nil?: false, public?: true
    attribute :scope, :string, allow_nil?: false, public?: true
    attribute :resource_uri, :string, allow_nil?: false, public?: true
    attribute :expires_at, :utc_datetime_usec, allow_nil?: false, public?: true
    attribute :chain_id, :uuid_v7, allow_nil?: false, public?: true
    attribute :generation, :integer, allow_nil?: false, default: 0, public?: true
    attribute :rotated_to_id, :uuid_v7, public?: true
    attribute :rotated_at, :utc_datetime_usec, public?: true
    attribute :revoked_at, :utc_datetime_usec, public?: true
  end

  actions do
    defaults [:read, :destroy]

    create :issue do
      accept [
        :id,
        :chain_id,
        :generation,
        :token_hash,
        :client_id,
        :user_id,
        :scope,
        :resource_uri,
        :expires_at
      ]
    end

    # ETS identities use `pre_check_with:`, which adds a hook that cannot run
    # atomically.
    update :rotate do
      argument :rotated_to_id, :uuid_v7, allow_nil?: false
      accept []
      require_atomic? false

      change AshAuthentication.Oauth2Server.Changes.RotateRefreshToken
    end

    update :revoke do
      accept []
      require_atomic? false
      change set_attribute(:revoked_at, &DateTime.utc_now/0)
    end
  end

  identities do
    identity :by_token_hash, [:token_hash], pre_check_with: Dev.Accounts
  end
end

defmodule Dev.Accounts.OAuthConsent do
  @moduledoc false
  use Ash.Resource,
    domain: Dev.Accounts,
    data_layer: Ash.DataLayer.Ets

  attributes do
    uuid_v7_primary_key :id
    attribute :user_id, :uuid_v7, allow_nil?: false, public?: true
    attribute :client_id, :uuid_v7, allow_nil?: false, public?: true
    attribute :scope, :string, allow_nil?: false, public?: true

    attribute :granted_at, :utc_datetime_usec,
      allow_nil?: false,
      public?: true,
      default: &DateTime.utc_now/0
  end

  actions do
    defaults [:read, :destroy]

    create :grant do
      upsert? true
      upsert_identity :by_user_client
      accept [:user_id, :client_id, :scope]
    end
  end

  identities do
    identity :by_user_client, [:user_id, :client_id], pre_check_with: Dev.Accounts
  end
end
