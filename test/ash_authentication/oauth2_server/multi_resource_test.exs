# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.MultiResourceTest do
  @moduledoc """
  One authorization server that protects two resources, `/mcp` and `/gql`.
  Each grant is bound to one resource (RFC 8707), and each token is valid
  only at that resource.
  """
  use ExUnit.Case, async: false

  alias AshAuthentication.Oauth2Server
  alias AshAuthentication.Oauth2Server.{Authorize, Jwt, Metadata, PKCE, Register, Token}
  alias Oauth2ServerTest.MultiResourceServer, as: Server

  alias Oauth2ServerTest.{
    OAuthAuthorizationCode,
    OAuthClient,
    OAuthConsent,
    OAuthRefreshToken,
    User
  }

  @mcp "https://app.example.com/mcp"
  @gql "https://app.example.com/gql"
  @redirect_uri "https://chat.example.com/cb"

  setup do
    for resource <- [OAuthClient, OAuthAuthorizationCode, OAuthRefreshToken, OAuthConsent, User] do
      Ash.bulk_destroy!(resource, :destroy, %{}, return_errors?: true)
    end

    user =
      User
      |> Ash.Changeset.for_create(:create, %{email: "alice@example.com"})
      |> Ash.create!()

    {:ok, client, _body} =
      Register.register(Server, %{
        "client_name" => "Test",
        "redirect_uris" => [@redirect_uri],
        "grant_types" => ["authorization_code", "refresh_token"]
      })

    {:ok, user: user, client: client}
  end

  defp authorize_params(client, challenge, overrides) do
    Map.merge(
      %{
        "response_type" => "code",
        "client_id" => client.id,
        "redirect_uri" => @redirect_uri,
        "code_challenge" => challenge,
        "code_challenge_method" => "S256",
        "scope" => "mcp",
        "state" => "csrf-state",
        "resource" => @mcp
      },
      overrides
    )
  end

  defp pkce_pair do
    verifier = Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)
    {verifier, PKCE.challenge(verifier)}
  end

  defp issue_code(user, client, overrides) do
    {verifier, challenge} = pkce_pair()

    {:ok, validated} =
      Authorize.validate_request(Server, authorize_params(client, challenge, overrides))

    {Authorize.issue_code!(Server, user, validated), verifier}
  end

  defp exchange(client, code, verifier, resource) do
    Token.exchange_authorization_code(Server, %{
      "grant_type" => "authorization_code",
      "code" => code.id,
      "redirect_uri" => @redirect_uri,
      "code_verifier" => verifier,
      "client_id" => client.id,
      "resource" => resource
    })
  end

  defp refresh(client, refresh_token, resource) do
    Token.exchange_refresh_token(
      Server,
      %{
        "grant_type" => "refresh_token",
        "refresh_token" => refresh_token,
        "client_id" => client.id
      }
      |> then(&if resource, do: Map.put(&1, "resource", resource), else: &1)
    )
  end

  describe "configuration" do
    test "exposes each resource by name" do
      assert Server.resources() == [:mcp, :gql]
      assert Server.resource_url(:mcp) == @mcp
      assert Server.resource_url(:gql, %{}) == @gql
      assert Server.resource_scopes(:gql) == ["gql"]
    end

    test "requires a resource name when more than one resource is configured" do
      assert_raise ArgumentError, ~r/more than one resource/, fn -> Server.resource_url() end
    end

    test "rejects an unknown resource name" do
      assert_raise ArgumentError, ~r/no resource named :other/, fn ->
        Server.resource_url(:other)
      end
    end

    test "finds a resource by its identifier after URL normalization" do
      assert {:ok, :gql, @gql} =
               Oauth2Server.__find_resource__(Server, "HTTPS://App.Example.com:443/gql")

      assert :error = Oauth2Server.__find_resource__(Server, "https://app.example.com")
    end

    test "requires exactly one of :resource_url and :resources" do
      base = [
        otp_app: :x,
        user_resource: X,
        issuer_url: "i",
        signing_secret: "s",
        client_resource: X,
        authorization_code_resource: X,
        refresh_token_resource: X,
        consent_resource: X
      ]

      assert :ok = Oauth2Server.__validate_opts__!(M, base ++ [resource_url: "r"])
      assert :ok = Oauth2Server.__validate_opts__!(M, base ++ [resources: [a: [url: "r"]]])

      for bad <- [
            [],
            [resources: []],
            [resource_url: "r", resources: [a: [url: "r"]]],
            [resources: [a: [scopes: ["x"]]]],
            [resources: [a: [url: "r"], a: [url: "q"]]]
          ] do
        assert_raise CompileError, fn -> Oauth2Server.__validate_opts__!(M, base ++ bad) end
      end
    end
  end

  describe "scopes of several resources (RFC 9068 §5)" do
    @base [
      otp_app: :x,
      user_resource: X,
      issuer_url: "i",
      signing_secret: "s",
      client_resource: X,
      authorization_code_resource: X,
      refresh_token_resource: X,
      consent_resource: X,
      scopes: ["a", "b"]
    ]

    test "accepts disjoint scopes from the catalogue" do
      assert :ok =
               Oauth2Server.__validate_opts__!(
                 M,
                 @base ++
                   [resources: [m: [url: "r", scopes: ["a"]], g: [url: "q", scopes: ["b"]]]]
               )
    end

    test "rejects a resource without scopes, a shared scope, and a scope outside the catalogue" do
      for resources <- [
            [m: [url: "r", scopes: ["a"]], g: [url: "q"]],
            [m: [url: "r", scopes: ["a"]], g: [url: "q", scopes: ["a", "b"]]],
            [m: [url: "r", scopes: ["a"]], g: [url: "q", scopes: ["c"]]]
          ] do
        assert_raise CompileError, fn ->
          Oauth2Server.__validate_opts__!(M, @base ++ [resources: resources])
        end
      end
    end

    test "rejects shared scopes that a function computes" do
      assert_raise ArgumentError, ~r/scope "a" belongs to more than one resource/, fn ->
        Oauth2Server.__check_disjoint_scopes__!(M, m: ["a"], g: ["a", "b"])
      end
    end
  end

  describe "authorize" do
    test "binds the code to the requested resource", %{user: user, client: client} do
      {code, _verifier} = issue_code(user, client, %{"resource" => @gql, "scope" => "gql"})
      assert code.resource_uri == @gql
    end

    test "selects the resource from the scope when resource is absent", %{client: client} do
      {_verifier, challenge} = pkce_pair()

      params =
        client |> authorize_params(challenge, %{"scope" => "gql"}) |> Map.delete("resource")

      assert {:ok, %{resource: @gql}} = Authorize.validate_request(Server, params)
    end

    test "requires resource when the scopes select more than one resource", %{client: client} do
      {_verifier, challenge} = pkce_pair()

      params =
        client |> authorize_params(challenge, %{"scope" => "mcp gql"}) |> Map.delete("resource")

      assert {:error, "invalid_target", _} = Authorize.validate_request(Server, params)
    end

    test "rejects a scope that the resource does not accept", %{client: client} do
      {_verifier, challenge} = pkce_pair()
      params = authorize_params(client, challenge, %{"resource" => @mcp, "scope" => "gql"})

      assert {:error, "invalid_target", desc} = Authorize.validate_request(Server, params)
      assert desc =~ "gql"
    end

    test "rejects a resource that is not configured", %{client: client} do
      {_verifier, challenge} = pkce_pair()
      params = authorize_params(client, challenge, %{"resource" => "https://app.example.com"})

      assert {:error, "invalid_target", desc} = Authorize.validate_request(Server, params)
      assert desc =~ @mcp
      assert desc =~ @gql
    end

    test "consent to a second resource keeps the consent to the first",
         %{user: user, client: client} do
      Authorize.grant_consent!(Server, user, client, "mcp")
      Authorize.grant_consent!(Server, user, client, "gql")

      assert Authorize.consented?(Server, user, client, "mcp")
      assert Authorize.consented?(Server, user, client, "gql")
    end
  end

  describe "token" do
    test "the access token is valid only at the resource of the grant",
         %{user: user, client: client} do
      {code, verifier} = issue_code(user, client, %{})
      assert {:ok, tokens} = exchange(client, code, verifier, @mcp)

      assert {:ok, %{"aud" => @mcp}} = Jwt.verify(Server, tokens.access_token, resource: :mcp)

      assert {:error, :invalid_audience} =
               Jwt.verify(Server, tokens.access_token, resource: :gql)
    end

    test "a code for one resource cannot be exchanged for another",
         %{user: user, client: client} do
      {code, verifier} = issue_code(user, client, %{})
      assert {:error, :invalid_target} = exchange(client, code, verifier, @gql)
    end

    test "a refresh stays bound to the resource of the grant", %{user: user, client: client} do
      {code, verifier} = issue_code(user, client, %{})
      {:ok, first} = exchange(client, code, verifier, @mcp)

      assert {:error, :invalid_target} = refresh(client, first.refresh_token, @gql)

      assert {:ok, second} = refresh(client, first.refresh_token, @mcp)
      assert {:ok, %{"aud" => @mcp}} = Jwt.verify(Server, second.access_token, resource: :mcp)

      assert {:ok, third} = refresh(client, second.refresh_token, nil)
      assert {:ok, %{"aud" => @mcp}} = Jwt.verify(Server, third.access_token, resource: :mcp)
    end

    test "a refresh with an unknown resource is invalid_target", %{user: user, client: client} do
      {code, verifier} = issue_code(user, client, %{})
      {:ok, first} = exchange(client, code, verifier, @mcp)

      assert {:error, :invalid_target} =
               refresh(client, first.refresh_token, "https://app.example.com")
    end
  end

  describe "metadata" do
    test "describes each resource with its own identifier and scopes" do
      assert %{"resource" => @mcp, "scopes_supported" => ["mcp"]} =
               Metadata.protected_resource(Server, %{}, :mcp)

      assert %{"resource" => @gql, "scopes_supported" => ["gql"]} =
               Metadata.protected_resource(Server, %{}, :gql)
    end
  end
end
