# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.AuthorizationCodeResourceTest do
  @moduledoc false
  use ExUnit.Case, async: false

  alias AshAuthentication.Oauth2Server.{Authorize, Token}
  alias Oauth2ServerTest.{OAuthAuthorizationCode, Server, User}

  describe "AuthorizationCodeResource.Verifier" do
    test "verifies valid authorization code resource successfully" do
      dsl_state = OAuthAuthorizationCode.spark_dsl_config()

      assert :ok =
               AshAuthentication.Oauth2Server.AuthorizationCodeResource.Verifier.verify(dsl_state)
    end

    test "returns error when code_hash attribute is missing" do
      dsl_state = OAuthAuthorizationCode.spark_dsl_config()

      entities =
        Spark.Dsl.Verifier.get_entities(dsl_state, [:attributes])
        |> Enum.reject(&(&1.name == :code_hash))

      modified_dsl =
        put_in(dsl_state, [[:attributes], :entities], entities)

      assert {:error, %Spark.Error.DslError{message: message}} =
               AshAuthentication.Oauth2Server.AuthorizationCodeResource.Verifier.verify(
                 modified_dsl
               )

      assert message =~ "must declare an attribute `:code_hash`"
    end
  end

  describe "authorization code hashing and lookup" do
    test "Authorize.hash_code/1 produces consistent sha256 hex digest" do
      raw = "test-code-12345"
      expected = :crypto.hash(:sha256, raw) |> Base.encode16(case: :lower)
      assert Authorize.hash_code(raw) == expected
    end

    test "issue_code! returns raw code only in metadata while persisting code_hash" do
      user =
        Ash.create!(Ash.Changeset.for_create(User, :create, %{email: "verifier@example.com"}))

      {:ok, client, _} =
        AshAuthentication.Oauth2Server.Register.register(Server, %{
          "client_name" => "Verifier Test",
          "redirect_uris" => ["https://chat.example.com/cb"]
        })

      verifier = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
      challenge = AshAuthentication.Oauth2Server.PKCE.challenge(verifier)

      {:ok, validated} =
        Authorize.validate_request(Server, %{
          "client_id" => client.id,
          "redirect_uri" => "https://chat.example.com/cb",
          "response_type" => "code",
          "scope" => "mcp",
          "code_challenge" => challenge,
          "code_challenge_method" => "S256"
        })

      code_record = Authorize.issue_code!(Server, user, validated)
      raw_code = Authorize.get_raw_code(code_record)

      assert is_binary(raw_code)
      assert byte_size(raw_code) >= 32
      assert code_record.id != raw_code
      assert code_record.code_hash == Authorize.hash_code(raw_code)

      # Persisted row only has code_hash
      db_record = Ash.get!(OAuthAuthorizationCode, code_record.id)
      assert db_record.code_hash == Authorize.hash_code(raw_code)
      refute Map.has_key?(db_record, :code)

      # Presenting the row ID fails
      assert {:error, :invalid_code} =
               Token.exchange_authorization_code(Server, %{
                 "grant_type" => "authorization_code",
                 "code" => code_record.id,
                 "redirect_uri" => "https://chat.example.com/cb",
                 "code_verifier" => verifier,
                 "client_id" => client.id,
                 "resource" => Server.resource_url()
               })

      # Presenting the raw code succeeds
      assert {:ok, response} =
               Token.exchange_authorization_code(Server, %{
                 "grant_type" => "authorization_code",
                 "code" => raw_code,
                 "redirect_uri" => "https://chat.example.com/cb",
                 "code_verifier" => verifier,
                 "client_id" => client.id,
                 "resource" => Server.resource_url()
               })

      assert is_binary(response.access_token)
    end
  end
end
