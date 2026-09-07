# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.ExpungerTest do
  @moduledoc """
  Tests for the auto-generated `:expunge_expired` destroy actions and
  the helpers that wrap them on each marker extension.
  """
  use ExUnit.Case, async: false

  alias AshAuthentication.Oauth2Server.{
    AuthorizationCodeResource,
    ClientResource,
    RefreshTokenResource
  }

  # Matches ClientResource's default cimd_client_ttl (30 days).
  @client_ttl 2_592_000

  alias Oauth2ServerTest.{
    OAuthAuthorizationCode,
    OAuthClient,
    OAuthRefreshToken,
    TenantedOAuthRefreshToken
  }

  @ash_context %{private: %{ash_authentication?: true}}

  setup do
    on_exit(fn ->
      for resource <- [OAuthAuthorizationCode, OAuthRefreshToken, OAuthClient] do
        resource
        |> Ash.Query.new()
        |> Ash.read!(context: @ash_context)
        |> Enum.each(&Ash.destroy!(&1, context: @ash_context))
      end
    end)

    :ok
  end

  describe "AuthorizationCodeResource.expunge_expired/1" do
    test "removes rows whose expires_at has passed" do
      past = DateTime.add(DateTime.utc_now(), -3600, :second)
      future = DateTime.add(DateTime.utc_now(), 600, :second)

      expired = create_code!(expires_at: past)
      valid = create_code!(expires_at: future)

      assert :ok = AuthorizationCodeResource.expunge_expired(OAuthAuthorizationCode)

      refute exists?(OAuthAuthorizationCode, expired.id)
      assert exists?(OAuthAuthorizationCode, valid.id)
    end

    test "removes rows whose consumed_at is older than the grace window" do
      future = DateTime.add(DateTime.utc_now(), 600, :second)
      stale_consumed = DateTime.add(DateTime.utc_now(), -86_400 - 60, :second)
      fresh_consumed = DateTime.add(DateTime.utc_now(), -60, :second)

      stale = create_code!(expires_at: future, consumed_at: stale_consumed)
      fresh = create_code!(expires_at: future, consumed_at: fresh_consumed)
      unconsumed = create_code!(expires_at: future)

      assert :ok = AuthorizationCodeResource.expunge_expired(OAuthAuthorizationCode)

      refute exists?(OAuthAuthorizationCode, stale.id)
      assert exists?(OAuthAuthorizationCode, fresh.id)
      assert exists?(OAuthAuthorizationCode, unconsumed.id)
    end
  end

  describe "RefreshTokenResource.expunge_expired/1" do
    test "removes rows whose expires_at has passed" do
      past = DateTime.add(DateTime.utc_now(), -3600, :second)
      future = DateTime.add(DateTime.utc_now(), 600, :second)

      expired = create_refresh!(expires_at: past)
      valid = create_refresh!(expires_at: future)

      assert :ok = RefreshTokenResource.expunge_expired(OAuthRefreshToken)

      refute exists?(OAuthRefreshToken, expired.id)
      assert exists?(OAuthRefreshToken, valid.id)
    end

    test "removes rows whose revoked_at is older than the grace window" do
      future = DateTime.add(DateTime.utc_now(), 600, :second)
      stale_revoked = DateTime.add(DateTime.utc_now(), -86_400 - 60, :second)
      fresh_revoked = DateTime.add(DateTime.utc_now(), -60, :second)

      stale = create_refresh!(expires_at: future, revoked_at: stale_revoked)
      fresh = create_refresh!(expires_at: future, revoked_at: fresh_revoked)
      live = create_refresh!(expires_at: future)

      assert :ok = RefreshTokenResource.expunge_expired(OAuthRefreshToken)

      refute exists?(OAuthRefreshToken, stale.id)
      assert exists?(OAuthRefreshToken, fresh.id)
      assert exists?(OAuthRefreshToken, live.id)
    end

    test "removes rows whose rotated_at is older than the grace window" do
      future = DateTime.add(DateTime.utc_now(), 600, :second)
      stale_rotated = DateTime.add(DateTime.utc_now(), -86_400 - 60, :second)
      fresh_rotated = DateTime.add(DateTime.utc_now(), -60, :second)
      successor_id = Ash.UUIDv7.generate()

      stale =
        create_refresh!(
          expires_at: future,
          rotated_to_id: successor_id,
          rotated_at: stale_rotated
        )

      fresh =
        create_refresh!(
          expires_at: future,
          rotated_to_id: successor_id,
          rotated_at: fresh_rotated
        )

      assert :ok = RefreshTokenResource.expunge_expired(OAuthRefreshToken)

      refute exists?(OAuthRefreshToken, stale.id)
      assert exists?(OAuthRefreshToken, fresh.id)
    end
  end

  describe "ClientResource.expunge_expired/1" do
    test "removes only CIMD rows unused for longer than the TTL" do
      now = DateTime.utc_now()
      stale = DateTime.add(now, -@client_ttl - 60, :second)
      fresh = DateTime.add(now, -60, :second)

      stale_cimd =
        create_client!(cimd_url: "https://stale.example.com/client", last_used_at: stale)

      fresh_cimd =
        create_client!(cimd_url: "https://fresh.example.com/client", last_used_at: fresh)

      assert :ok = ClientResource.expunge_expired(OAuthClient)

      refute exists?(OAuthClient, stale_cimd.id)
      assert exists?(OAuthClient, fresh_cimd.id)
    end

    test "never removes registered (non-CIMD) clients, however old" do
      stale = DateTime.add(DateTime.utc_now(), -@client_ttl * 10, :second)

      # cimd_url nil => registered client; must survive regardless of last_used_at.
      registered = create_client!(cimd_url: nil, last_used_at: stale)
      # A CIMD row that has never recorded a last_used_at is also left alone
      # (the filter requires a non-nil last_used_at to compare against).
      never_used = create_client!(cimd_url: "https://nulltime.example.com/client")

      assert :ok = ClientResource.expunge_expired(OAuthClient)

      assert exists?(OAuthClient, registered.id)
      assert exists?(OAuthClient, never_used.id)
    end
  end

  describe "tenant scoping" do
    test "passes :tenant through to the underlying bulk_destroy" do
      past = DateTime.add(DateTime.utc_now(), -3600, :second)

      tenant_a_id = Ash.UUIDv7.generate()
      tenant_b_id = Ash.UUIDv7.generate()

      Ash.Seed.seed!(TenantedOAuthRefreshToken, %{
        id: tenant_a_id,
        chain_id: tenant_a_id,
        org_id: "tenant_a",
        token_hash: random_hash(),
        client_id: Ash.UUIDv7.generate(),
        user_id: Ash.UUIDv7.generate(),
        scope: "mcp",
        resource_uri: "https://app.example.com/mcp",
        expires_at: past
      })

      Ash.Seed.seed!(TenantedOAuthRefreshToken, %{
        id: tenant_b_id,
        chain_id: tenant_b_id,
        org_id: "tenant_b",
        token_hash: random_hash(),
        client_id: Ash.UUIDv7.generate(),
        user_id: Ash.UUIDv7.generate(),
        scope: "mcp",
        resource_uri: "https://app.example.com/mcp",
        expires_at: past
      })

      assert :ok =
               RefreshTokenResource.expunge_expired(TenantedOAuthRefreshToken,
                 tenant: "tenant_a"
               )

      refute exists?(TenantedOAuthRefreshToken, tenant_a_id, tenant: "tenant_a")
      assert exists?(TenantedOAuthRefreshToken, tenant_b_id, tenant: "tenant_b")

      # Clean up the survivor
      Ash.destroy!(
        Ash.get!(TenantedOAuthRefreshToken, tenant_b_id,
          tenant: "tenant_b",
          context: @ash_context
        ),
        context: @ash_context
      )
    end
  end

  defp exists?(resource, id, opts \\ []) do
    case Ash.get(resource, id, Keyword.put_new(opts, :context, @ash_context)) do
      {:ok, _} -> true
      {:error, _} -> false
    end
  end

  defp random_hash, do: :crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower)

  # Use Ash.Seed.seed! to bypass action constraints — these tests need
  # to write `consumed_at`/`revoked_at`/`rotated_at` to specific past
  # times, which the real actions intentionally don't allow.

  defp create_code!(overrides) do
    defaults = %{
      id: Ash.UUIDv7.generate(),
      client_id: Ash.UUIDv7.generate(),
      user_id: Ash.UUIDv7.generate(),
      redirect_uri: "https://x.example.com/cb",
      code_challenge: "challenge",
      scope: "mcp",
      resource_uri: "https://app.example.com/mcp",
      expires_at: DateTime.add(DateTime.utc_now(), 600, :second)
    }

    Ash.Seed.seed!(OAuthAuthorizationCode, Map.merge(defaults, Map.new(overrides)))
  end

  defp create_client!(overrides) do
    defaults = %{
      id: Ash.UUIDv7.generate(),
      client_name: "Test Client",
      redirect_uris: ["https://x.example.com/cb"],
      scope: "mcp"
    }

    Ash.Seed.seed!(OAuthClient, Map.merge(defaults, Map.new(overrides)))
  end

  defp create_refresh!(overrides) do
    id = Ash.UUIDv7.generate()

    defaults = %{
      id: id,
      chain_id: id,
      token_hash: :crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower),
      client_id: Ash.UUIDv7.generate(),
      user_id: Ash.UUIDv7.generate(),
      scope: "mcp",
      resource_uri: "https://app.example.com/mcp",
      expires_at: DateTime.add(DateTime.utc_now(), 600, :second)
    }

    Ash.Seed.seed!(OAuthRefreshToken, Map.merge(defaults, Map.new(overrides)))
  end
end
