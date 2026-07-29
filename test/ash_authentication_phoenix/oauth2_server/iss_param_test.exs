# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Phoenix.Oauth2Server.IssParamTest do
  @moduledoc """
  RFC 9207 — the `iss` parameter must appear in every authorization
  response, success and error alike, and be advertised in metadata.
  """
  use ExUnit.Case, async: false

  import Plug.Test
  import Plug.Conn

  alias AshAuthentication.Oauth2Server.PKCE
  alias AshAuthentication.Phoenix.Oauth2Server.{ConsentRouter, ProtocolRouter}
  alias Oauth2ServerTest.Server

  alias Oauth2ServerTest.{
    OAuthAuthorizationCode,
    OAuthClient,
    OAuthConsent,
    OAuthRefreshToken,
    User
  }

  @consent_opts ConsentRouter.init(oauth2_server: Server)
  @protocol_opts ProtocolRouter.init(oauth2_server: Server)

  setup do
    for resource <- [OAuthClient, OAuthAuthorizationCode, OAuthRefreshToken, OAuthConsent, User] do
      Ash.bulk_destroy!(resource, :destroy, %{}, return_errors?: true)
    end

    user =
      User
      |> Ash.Changeset.for_create(:create, %{email: "alice@example.com"})
      |> Ash.create!()

    client =
      OAuthClient
      |> Ash.Changeset.for_create(:register, %{
        client_name: "Iss Test",
        redirect_uris: ["https://chat.example.com/cb"]
      })
      |> Ash.create!()

    {:ok, user: user, client: client}
  end

  defp call_consent(conn) do
    conn
    |> Plug.Test.init_test_session(%{})
    |> ConsentRouter.call(@consent_opts)
  end

  defp authorize_query(client, challenge) do
    %{
      "response_type" => "code",
      "client_id" => client.id,
      "redirect_uri" => "https://chat.example.com/cb",
      "code_challenge" => challenge,
      "code_challenge_method" => "S256",
      "scope" => "mcp",
      "state" => "csrf-state",
      "resource" => Server.resource_url()
    }
  end

  defp redirect_query(conn) do
    [location] = get_resp_header(conn, "location")
    location |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
  end

  test "success redirects carry iss", %{user: user, client: client} do
    {_verifier, challenge} = {nil, PKCE.challenge("verifier-verifier-verifier-verifier-1234")}

    OAuthConsent
    |> Ash.Changeset.for_create(:grant, %{user_id: user.id, client_id: client.id, scope: "mcp"})
    |> Ash.create!()

    conn =
      conn(:get, "/?" <> URI.encode_query(authorize_query(client, challenge)))
      |> Ash.PlugHelpers.set_actor(user)
      |> call_consent()

    assert conn.status == 302
    query = redirect_query(conn)
    assert is_binary(query["code"])
    assert query["iss"] == Server.issuer_url()
  end

  test "error redirects carry iss too", %{user: user, client: client} do
    challenge = PKCE.challenge("verifier-verifier-verifier-verifier-1234")

    # Unknown scope → redirectable invalid_scope error (client + redirect_uri
    # are valid, so the error goes back via 302 per RFC 6749 §4.1.2.1).
    query_params =
      client
      |> authorize_query(challenge)
      |> Map.put("scope", "not-a-real-scope")

    conn =
      conn(:get, "/?" <> URI.encode_query(query_params))
      |> Ash.PlugHelpers.set_actor(user)
      |> call_consent()

    assert conn.status == 302
    query = redirect_query(conn)
    assert query["error"] == "invalid_scope"
    assert query["iss"] == Server.issuer_url()
  end

  test "metadata advertises authorization_response_iss_parameter_supported" do
    conn = conn(:get, "/oauth-authorization-server") |> ProtocolRouter.call(@protocol_opts)

    assert conn.status == 200
    assert Jason.decode!(conn.resp_body)["authorization_response_iss_parameter_supported"] == true
  end
end
