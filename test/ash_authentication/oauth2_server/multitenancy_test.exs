# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/team-alembic/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.MultitenancyTest do
  @moduledoc """
  Exercises the tenant-threading contract:

    * `:tenant` opt → forwarded to every Ash action so multi-tenant
      resources scope correctly.
    * Tenant baked into the JWT's `"tenant"` claim at mint time.
    * `Jwt.verify/2` surfaces the claim verbatim.
    * Cross-tenant operations are isolated (a tenant-A row is invisible
      under tenant B).

  Backed by the `Oauth2ServerTest.Tenanted*` resources, which opt into
  attribute-based multitenancy on `:org_id`.
  """
  use ExUnit.Case, async: false

  alias AshAuthentication.Oauth2Server.{Authorize, Jwt, PKCE, Register, Token}
  alias Oauth2ServerTest.TenantedServer

  alias Oauth2ServerTest.{
    TenantedOAuthAuthorizationCode,
    TenantedOAuthClient,
    TenantedOAuthConsent,
    TenantedOAuthRefreshToken,
    TenantedUser
  }

  @tenant_a "org-alpha"
  @tenant_b "org-beta"

  setup do
    for resource <- [
          TenantedOAuthClient,
          TenantedOAuthAuthorizationCode,
          TenantedOAuthRefreshToken,
          TenantedOAuthConsent,
          TenantedUser
        ] do
      Ash.bulk_destroy!(resource, :destroy, %{}, return_errors?: true)
    end

    user_a = create_user(@tenant_a, "alice@example.com")
    user_b = create_user(@tenant_b, "bob@example.com")
    {:ok, user_a: user_a, user_b: user_b}
  end

  defp create_user(tenant, email) do
    TenantedUser
    |> Ash.Changeset.for_create(:create, %{org_id: tenant, email: email})
    |> Ash.create!(tenant: tenant)
  end

  defp register_client(tenant, redirect_uri \\ "https://chat.example.com/cb") do
    {:ok, client, _body} =
      Register.register(
        TenantedServer,
        %{
          "client_name" => "Test #{tenant}",
          "redirect_uris" => [redirect_uri]
        },
        tenant: tenant
      )

    client
  end

  defp pkce_pair do
    verifier = Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)
    {verifier, PKCE.challenge(verifier)}
  end

  defp authorize_params(client, code_challenge, redirect_uri) do
    %{
      "response_type" => "code",
      "client_id" => client.id,
      "redirect_uri" => redirect_uri,
      "code_challenge" => code_challenge,
      "code_challenge_method" => "S256",
      "scope" => "mcp",
      "state" => "csrf-state",
      "resource" => TenantedServer.resource_url()
    }
  end

  describe "Register.register/3" do
    test "scopes new clients to the requested tenant" do
      client_a = register_client(@tenant_a)
      client_b = register_client(@tenant_b)

      # Each tenant sees only their own client
      {:ok, [seen_a]} = Ash.read(TenantedOAuthClient, tenant: @tenant_a, action: :read)
      assert seen_a.id == client_a.id

      {:ok, [seen_b]} = Ash.read(TenantedOAuthClient, tenant: @tenant_b, action: :read)
      assert seen_b.id == client_b.id

      # The tenant-A client is invisible under tenant B
      assert {:error, _} = Ash.get(TenantedOAuthClient, client_a.id, tenant: @tenant_b)
    end
  end

  describe "Authorize + Token" do
    test "issue_code/exchange round-trip is tenant-scoped end-to-end", %{user_a: user_a} do
      client = register_client(@tenant_a)
      redirect_uri = "https://chat.example.com/cb"
      {verifier, challenge} = pkce_pair()

      {:ok, validated} =
        Authorize.validate_request(
          TenantedServer,
          authorize_params(client, challenge, redirect_uri),
          tenant: @tenant_a
        )

      code = Authorize.issue_code!(TenantedServer, user_a, validated, tenant: @tenant_a)
      assert code.org_id == @tenant_a

      # Exchange the code in the same tenant — happy path.
      assert {:ok, response} =
               Token.exchange_authorization_code(
                 TenantedServer,
                 %{
                   "code" => code.id,
                   "client_id" => client.id,
                   "redirect_uri" => redirect_uri,
                   "code_verifier" => verifier
                 },
                 tenant: @tenant_a
               )

      assert is_binary(response.access_token)
      assert is_binary(response.refresh_token)

      # The access token carries the tenant claim.
      assert {:ok, claims} = Jwt.verify(TenantedServer, response.access_token)
      assert claims["tenant"] == @tenant_a
      assert claims["sub"] == user_a.id
    end

    test "exchange under a different tenant cannot consume another tenant's code",
         %{user_a: user_a} do
      client = register_client(@tenant_a)
      redirect_uri = "https://chat.example.com/cb"
      {verifier, challenge} = pkce_pair()

      {:ok, validated} =
        Authorize.validate_request(
          TenantedServer,
          authorize_params(client, challenge, redirect_uri),
          tenant: @tenant_a
        )

      code = Authorize.issue_code!(TenantedServer, user_a, validated, tenant: @tenant_a)

      # Try to redeem under the wrong tenant — should be unreachable.
      assert {:error, :invalid_code} =
               Token.exchange_authorization_code(
                 TenantedServer,
                 %{
                   "code" => code.id,
                   "client_id" => client.id,
                   "redirect_uri" => redirect_uri,
                   "code_verifier" => verifier
                 },
                 tenant: @tenant_b
               )

      # Code is still consumable under the right tenant
      assert {:ok, _response} =
               Token.exchange_authorization_code(
                 TenantedServer,
                 %{
                   "code" => code.id,
                   "client_id" => client.id,
                   "redirect_uri" => redirect_uri,
                   "code_verifier" => verifier
                 },
                 tenant: @tenant_a
               )
    end

    test "refresh-token rotation honors tenant", %{user_a: user_a} do
      client = register_client(@tenant_a)
      redirect_uri = "https://chat.example.com/cb"
      {verifier, challenge} = pkce_pair()

      {:ok, validated} =
        Authorize.validate_request(
          TenantedServer,
          authorize_params(client, challenge, redirect_uri),
          tenant: @tenant_a
        )

      code = Authorize.issue_code!(TenantedServer, user_a, validated, tenant: @tenant_a)

      {:ok, %{refresh_token: refresh_a}} =
        Token.exchange_authorization_code(
          TenantedServer,
          %{
            "code" => code.id,
            "client_id" => client.id,
            "redirect_uri" => redirect_uri,
            "code_verifier" => verifier
          },
          tenant: @tenant_a
        )

      # Wrong tenant on refresh → invalid_refresh (filter doesn't see the row)
      assert {:error, :invalid_refresh} =
               Token.exchange_refresh_token(
                 TenantedServer,
                 %{
                   "refresh_token" => refresh_a,
                   "client_id" => client.id,
                   "resource" => TenantedServer.resource_url()
                 },
                 tenant: @tenant_b
               )

      # Right tenant: rotation succeeds, new JWT still carries the tenant claim
      assert {:ok, %{access_token: at, refresh_token: refresh_a2}} =
               Token.exchange_refresh_token(
                 TenantedServer,
                 %{
                   "refresh_token" => refresh_a,
                   "client_id" => client.id,
                   "resource" => TenantedServer.resource_url()
                 },
                 tenant: @tenant_a
               )

      assert refresh_a2 != refresh_a
      assert {:ok, claims} = Jwt.verify(TenantedServer, at)
      assert claims["tenant"] == @tenant_a
    end
  end

  describe "Jwt.mint/2" do
    test "omits the tenant claim when no tenant is passed" do
      {:ok, _token, claims} =
        Jwt.mint(TenantedServer,
          sub: "user-1",
          client_id: "client-1",
          scope: "mcp"
        )

      refute Map.has_key?(claims, "tenant")
    end

    test "stores the tenant claim under the normalized string form" do
      {:ok, _token, claims} =
        Jwt.mint(TenantedServer,
          sub: "user-1",
          client_id: "client-1",
          scope: "mcp",
          tenant: @tenant_a
        )

      assert claims["tenant"] == @tenant_a
    end
  end

  describe "Authorize.consented?/5" do
    test "consent in one tenant doesn't apply in another", %{user_a: user_a} do
      client = register_client(@tenant_a)

      Authorize.grant_consent!(TenantedServer, user_a, client, "mcp", tenant: @tenant_a)

      assert Authorize.consented?(TenantedServer, user_a, client, "mcp", tenant: @tenant_a)
      refute Authorize.consented?(TenantedServer, user_a, client, "mcp", tenant: @tenant_b)
    end
  end
end
