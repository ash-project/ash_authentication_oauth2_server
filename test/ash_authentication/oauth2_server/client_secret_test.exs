# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.ClientSecretTest do
  use ExUnit.Case, async: true

  alias AshAuthentication.Oauth2Server.ClientSecret

  test "generate/0 returns a high-entropy secret and matching hash" do
    {plain, hash} = ClientSecret.generate()

    assert is_binary(plain) and byte_size(plain) >= 32
    assert hash == ClientSecret.hash(plain)
    assert ClientSecret.verify(%{client_secret_hash: hash}, plain)
    refute ClientSecret.verify(%{client_secret_hash: hash}, plain <> "x")
  end

  test "verify/2 returns false without a usable hash" do
    refute ClientSecret.verify(%{client_secret_hash: nil}, "anything")
    refute ClientSecret.verify(%{}, "anything")
  end

  test "hash_attribute/0 is :client_secret_hash" do
    assert ClientSecret.hash_attribute() == :client_secret_hash
  end
end
