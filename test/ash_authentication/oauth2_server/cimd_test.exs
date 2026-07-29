# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.CIMDTest do
  @moduledoc """
  Client ID Metadata Documents (CIMD): resolution, validation, the full
  authorization-code + refresh flow with a URL client_id, metadata
  advertisement, the document cache, and the default fetcher's URL/IP
  policy (no network involved anywhere — documents come from
  `Oauth2ServerTest.StubFetcher`).
  """
  use ExUnit.Case, async: false

  alias AshAuthentication.Oauth2Server.{Authorize, CIMD, Jwt, Metadata, Token}
  alias AshAuthentication.Oauth2Server.CIMD.{Cache, ReqFetcher}
  alias Oauth2ServerTest.{CimdServer, Server, StubFetcher}

  alias Oauth2ServerTest.{
    OAuthAuthorizationCode,
    OAuthClient,
    OAuthConsent,
    OAuthRefreshToken,
    User
  }

  @client_id "https://app.example.net/oauth/client-metadata.json"
  @redirect_uri "https://app.example.net/callback"

  setup do
    for resource <- [OAuthClient, OAuthAuthorizationCode, OAuthRefreshToken, OAuthConsent, User] do
      Ash.bulk_destroy!(resource, :destroy, %{}, return_errors?: true)
    end

    StubFetcher.clear()
    on_exit(&StubFetcher.clear/0)

    user =
      User
      |> Ash.Changeset.for_create(:create, %{email: "alice@example.com"})
      |> Ash.create!()

    {:ok, user: user}
  end

  defp document(overrides \\ %{}) do
    Map.merge(
      %{
        "client_id" => @client_id,
        "client_name" => "CIMD Test Client",
        "redirect_uris" => [@redirect_uri],
        "grant_types" => ["authorization_code", "refresh_token"],
        "response_types" => ["code"],
        "token_endpoint_auth_method" => "none"
      },
      overrides
    )
  end

  defp pkce_pair do
    verifier = Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)
    {verifier, AshAuthentication.Oauth2Server.PKCE.challenge(verifier)}
  end

  defp authorize_params(code_challenge) do
    %{
      "response_type" => "code",
      "client_id" => @client_id,
      "redirect_uri" => @redirect_uri,
      "code_challenge" => code_challenge,
      "code_challenge_method" => "S256",
      "scope" => "mcp",
      "state" => "csrf-state",
      "resource" => CimdServer.resource_url()
    }
  end

  describe "metadata advertisement" do
    test "advertises client_id_metadata_document_supported when enabled" do
      assert Metadata.authorization_server(CimdServer)[
               "client_id_metadata_document_supported"
             ] == true
    end

    test "omits client_id_metadata_document_supported when disabled" do
      refute Map.has_key?(
               Metadata.authorization_server(Server),
               "client_id_metadata_document_supported"
             )
    end

    test "advertises authorization_response_iss_parameter_supported (RFC 9207)" do
      assert Metadata.authorization_server(Server)[
               "authorization_response_iss_parameter_supported"
             ] == true
    end
  end

  describe "resolve_client/3" do
    test "fetches, validates, and upserts a client from the document" do
      StubFetcher.stub(@client_id, document())

      assert {:ok, client} = CIMD.resolve_client(CimdServer, @client_id)
      assert client.cimd_url == @client_id
      assert client.client_name == "CIMD Test Client"
      assert client.redirect_uris == [@redirect_uri]
      assert client.token_endpoint_auth_method == "none"
      # The client's allowed scope is the server catalogue, like DCR.
      assert client.scope == "mcp"
    end

    test "re-resolving updates the stored client in place (upsert)" do
      StubFetcher.stub(@client_id, document())
      assert {:ok, client} = CIMD.resolve_client(CimdServer, @client_id)

      StubFetcher.stub(@client_id, document(%{"client_name" => "Renamed"}))
      assert {:ok, updated} = CIMD.resolve_client(CimdServer, @client_id)

      assert updated.id == client.id
      assert updated.client_name == "Renamed"
      assert Ash.count!(OAuthClient) == 1
    end

    test "narrows unsupported grant_types instead of rejecting the document" do
      # A CIMD document is shared across every server the client talks to,
      # so it may list grants (e.g. device_code) aimed at other servers.
      StubFetcher.stub(
        @client_id,
        document(%{
          "grant_types" => [
            "authorization_code",
            "refresh_token",
            "urn:ietf:params:oauth:grant-type:device_code"
          ]
        })
      )

      assert {:ok, client} = CIMD.resolve_client(CimdServer, @client_id)
      assert client.grant_types == ["authorization_code", "refresh_token"]
    end

    test "rejects a document whose grant_types omit authorization_code" do
      StubFetcher.stub(@client_id, document(%{"grant_types" => ["client_credentials"]}))

      assert {:error, description} = CIMD.resolve_client(CimdServer, @client_id)
      assert description =~ "authorization_code"
    end

    test "rejects a document whose client_id does not exactly match the URL" do
      StubFetcher.stub(@client_id, document(%{"client_id" => @client_id <> "?other"}))

      assert {:error, description} = CIMD.resolve_client(CimdServer, @client_id)
      assert description =~ "does not exactly match"
    end

    test "rejects a document without client_name" do
      StubFetcher.stub(@client_id, Map.delete(document(), "client_name"))
      assert {:error, "client_name is required"} = CIMD.resolve_client(CimdServer, @client_id)
    end

    test "rejects a document with invalid redirect_uris" do
      StubFetcher.stub(
        @client_id,
        document(%{"redirect_uris" => ["http://attacker.example.com/cb"]})
      )

      assert {:error, description} = CIMD.resolve_client(CimdServer, @client_id)
      assert description =~ "redirect URIs"
    end

    test "rejects a document asking for an unsupported auth method" do
      StubFetcher.stub(@client_id, document(%{"token_endpoint_auth_method" => "private_key_jwt"}))

      assert {:error, description} = CIMD.resolve_client(CimdServer, @client_id)
      assert description =~ "token_endpoint_auth_method"
    end

    test "returns a generic error when the fetch fails" do
      StubFetcher.stub(@client_id, {:error, :nxdomain})

      assert {:error, "could not fetch client metadata document"} =
               CIMD.resolve_client(CimdServer, @client_id)
    end
  end

  describe "authorize with a URL client_id" do
    test "validate_request resolves the CIMD client" do
      StubFetcher.stub(@client_id, document())
      {_verifier, challenge} = pkce_pair()

      assert {:ok, validated} =
               Authorize.validate_request(CimdServer, authorize_params(challenge))

      assert validated.client.cimd_url == @client_id
      assert validated.redirect_uri == @redirect_uri
    end

    test "redirect_uri must match the document exactly" do
      StubFetcher.stub(@client_id, document())
      {_verifier, challenge} = pkce_pair()

      params = Map.put(authorize_params(challenge), "redirect_uri", "https://evil.example.com/cb")
      assert {:error, :bad_redirect_uri} = Authorize.validate_request(CimdServer, params)
    end

    test "URL client_ids are rejected when CIMD is disabled" do
      StubFetcher.stub(@client_id, document())
      {_verifier, challenge} = pkce_pair()

      params = Map.put(authorize_params(challenge), "resource", Server.resource_url())
      assert {:error, "invalid_client", description} = Authorize.validate_request(Server, params)
      assert description =~ "not supported"
    end
  end

  describe "full flow with a URL client_id" do
    test "authorize → token → refresh → revoke", %{user: user} do
      StubFetcher.stub(@client_id, document())
      {verifier, challenge} = pkce_pair()

      {:ok, validated} = Authorize.validate_request(CimdServer, authorize_params(challenge))
      code = Authorize.issue_code!(CimdServer, user, validated)

      # The token endpoint identifies the client by its URL — resolved
      # from the database, no fetch.
      assert {:ok, token_response} =
               Token.exchange_authorization_code(CimdServer, %{
                 "grant_type" => "authorization_code",
                 "code" => code.id,
                 "client_id" => @client_id,
                 "redirect_uri" => @redirect_uri,
                 "code_verifier" => verifier
               })

      # The access token's client_id claim is the client's public
      # identifier — the CIMD URL, not our internal row id.
      assert {:ok, claims} = Jwt.verify(CimdServer, token_response.access_token)
      assert claims["client_id"] == @client_id
      assert claims["sub"] == user.id

      # Refresh rotation with the URL client_id.
      assert {:ok, refreshed} =
               Token.exchange_refresh_token(CimdServer, %{
                 "grant_type" => "refresh_token",
                 "refresh_token" => token_response.refresh_token,
                 "client_id" => @client_id
               })

      assert {:ok, refreshed_claims} = Jwt.verify(CimdServer, refreshed.access_token)
      assert refreshed_claims["client_id"] == @client_id

      # Revocation with the URL client_id kills the chain.
      assert :ok =
               Token.revoke(CimdServer, %{
                 "token" => refreshed.refresh_token,
                 "client_id" => @client_id
               })

      assert {:error, :revoked} =
               Token.exchange_refresh_token(CimdServer, %{
                 "grant_type" => "refresh_token",
                 "refresh_token" => refreshed.refresh_token,
                 "client_id" => @client_id
               })
    end

    test "a URL client_id unknown to the database fails the token exchange", %{user: user} do
      StubFetcher.stub(@client_id, document())
      {verifier, challenge} = pkce_pair()

      {:ok, validated} = Authorize.validate_request(CimdServer, authorize_params(challenge))
      code = Authorize.issue_code!(CimdServer, user, validated)

      assert {:error, :client_mismatch} =
               Token.exchange_authorization_code(CimdServer, %{
                 "grant_type" => "authorization_code",
                 "code" => code.id,
                 "client_id" => "https://other.example.net/client.json",
                 "redirect_uri" => @redirect_uri,
                 "code_verifier" => verifier
               })
    end
  end

  describe "Cache" do
    setup do
      pid = start_supervised!({Cache, []})
      {:ok, cache: pid}
    end

    test "stores and expires documents" do
      assert :miss = Cache.get("https://x.example.com/c.json")

      Cache.put("https://x.example.com/c.json", %{"client_id" => "x"}, 60)
      assert {:ok, %{"client_id" => "x"}} = Cache.get("https://x.example.com/c.json")
    end

    test "a ttl of 0 is not cached" do
      Cache.put("https://y.example.com/c.json", %{"client_id" => "y"}, 0)
      assert :miss = Cache.get("https://y.example.com/c.json")
    end
  end

  describe "Cache when not started" do
    test "get and put degrade to no-ops" do
      assert :miss = Cache.get("https://nostart.example.com/c.json")
      assert :ok = Cache.put("https://nostart.example.com/c.json", %{}, 60)
    end
  end

  describe "ReqFetcher.validate_url/2" do
    test "accepts a well-formed CIMD URL" do
      assert {:ok, %URI{}} = ReqFetcher.validate_url("https://app.example.com/client.json")
    end

    test "rejects http, missing path, root path, fragments, userinfo, and odd ports" do
      assert {:error, :invalid_url} = ReqFetcher.validate_url("http://app.example.com/c.json")
      assert {:error, :missing_path} = ReqFetcher.validate_url("https://app.example.com")
      assert {:error, :missing_path} = ReqFetcher.validate_url("https://app.example.com/")
      assert {:error, :invalid_url} = ReqFetcher.validate_url("https://app.example.com/c.json#f")

      assert {:error, :invalid_url} =
               ReqFetcher.validate_url("https://u:p@app.example.com/c.json")

      assert {:error, :port_not_allowed} =
               ReqFetcher.validate_url("https://app.example.com:8443/c.json")
    end

    test "allows extra ports when configured" do
      assert {:ok, %URI{port: 8443}} =
               ReqFetcher.validate_url("https://app.example.com:8443/c.json",
                 allowed_ports: [443, 8443]
               )
    end
  end

  describe "ReqFetcher.public_ip?/1 (SSRF policy)" do
    test "rejects loopback, private, link-local, CGNAT, and reserved IPv4" do
      for ip <- [
            {127, 0, 0, 1},
            {10, 1, 2, 3},
            {172, 16, 0, 1},
            {172, 31, 255, 255},
            {192, 168, 1, 1},
            # cloud metadata endpoint
            {169, 254, 169, 254},
            {100, 64, 0, 1},
            {0, 0, 0, 0},
            {198, 18, 0, 1},
            {224, 0, 0, 1},
            {240, 0, 0, 1},
            {255, 255, 255, 255}
          ] do
        refute ReqFetcher.public_ip?(ip), "expected #{inspect(ip)} to be rejected"
      end
    end

    test "accepts public IPv4" do
      for ip <- [{1, 1, 1, 1}, {8, 8, 8, 8}, {93, 184, 216, 34}, {172, 15, 0, 1}, {172, 32, 0, 1}] do
        assert ReqFetcher.public_ip?(ip), "expected #{inspect(ip)} to be accepted"
      end
    end

    test "rejects non-public IPv6, including embedded-IPv4 forms" do
      for ip <- [
            # ::1
            {0, 0, 0, 0, 0, 0, 0, 1},
            # fc00::/7 unique-local
            {0xFC00, 0, 0, 0, 0, 0, 0, 1},
            {0xFD12, 0x3456, 0, 0, 0, 0, 0, 1},
            # fe80::/10 link-local
            {0xFE80, 0, 0, 0, 0, 0, 0, 1},
            # ff02:: multicast
            {0xFF02, 0, 0, 0, 0, 0, 0, 1},
            # ::ffff:127.0.0.1 (v4-mapped loopback)
            {0, 0, 0, 0, 0, 0xFFFF, 0x7F00, 0x0001},
            # ::ffff:10.0.0.1 (v4-mapped private)
            {0, 0, 0, 0, 0, 0xFFFF, 0x0A00, 0x0001},
            # 64:ff9b::10.0.0.1 (NAT64 private)
            {0x64, 0xFF9B, 0, 0, 0, 0, 0x0A00, 0x0001},
            # 2002:0a00:0001:: (6to4 embedding 10.0.0.1)
            {0x2002, 0x0A00, 0x0001, 0, 0, 0, 0, 0},
            # 2001:db8:: documentation
            {0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}
          ] do
        refute ReqFetcher.public_ip?(ip), "expected #{inspect(ip)} to be rejected"
      end
    end

    test "accepts public IPv6, including public embedded-IPv4 forms" do
      for ip <- [
            # 2606:4700:4700::1111 (Cloudflare)
            {0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111},
            # ::ffff:1.1.1.1 (v4-mapped public)
            {0, 0, 0, 0, 0, 0xFFFF, 0x0101, 0x0101}
          ] do
        assert ReqFetcher.public_ip?(ip), "expected #{inspect(ip)} to be accepted"
      end
    end
  end
end
