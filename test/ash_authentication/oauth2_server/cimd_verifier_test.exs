# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.CimdVerifierTest do
  @moduledoc """
  The compile-time guard (`@after_verify`) that refuses to let a server
  enable CIMD without the client-resource garbage-collection extension.

  `__verify_cimd_support__!/1` is exercised directly: the real hook runs
  inside the parallel checker, where a raise surfaces as a process EXIT
  rather than a catchable error.
  """
  use ExUnit.Case, async: true

  alias AshAuthentication.Oauth2Server

  # OAuthClient carries the ClientResource extension; TenantedOAuthClient does not.
  defmodule ExtendedServer do
    def cimd_enabled?, do: true
    def client_resource, do: Oauth2ServerTest.OAuthClient
  end

  defmodule UnextendedServer do
    def cimd_enabled?, do: true
    def client_resource, do: Oauth2ServerTest.TenantedOAuthClient
  end

  defmodule DisabledServer do
    def cimd_enabled?, do: false
    def client_resource, do: Oauth2ServerTest.TenantedOAuthClient
  end

  test "raises when CIMD is enabled but the client resource lacks the extension" do
    assert_raise CompileError, ~r/missing the.*ClientResource.*extension/s, fn ->
      Oauth2Server.__verify_cimd_support__!(UnextendedServer)
    end
  end

  test "passes when the client resource carries the extension" do
    assert :ok = Oauth2Server.__verify_cimd_support__!(ExtendedServer)
  end

  test "passes when CIMD is disabled, regardless of the client resource" do
    assert :ok = Oauth2Server.__verify_cimd_support__!(DisabledServer)
  end
end
