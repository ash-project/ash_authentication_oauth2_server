# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.ClientSecret do
  @moduledoc """
  Default hashing and verification for confidential-client secrets.

  OAuth client secrets are high-entropy random strings (RFC 6819 §5.1.4.2).
  They are stored as a SHA-256 hex digest on the client row's
  `client_secret_hash` attribute — the same approach this library uses for
  refresh-token hashes. Verification is constant-time via
  `Plug.Crypto.secure_compare/2`.

  ## Typical flow

      {plain, hash} = AshAuthentication.Oauth2Server.ClientSecret.generate()
      # persist `hash` on the client; show `plain` **once** to the operator

  `:verify_client_secret` on `AshAuthentication.Oauth2Server` defaults to
  `{AshAuthentication.Oauth2Server.ClientSecret, :verify, []}`. Override
  with a custom MFA/fun for KMS, etc., or set
  `verify_client_secret: nil` to disable the `client_credentials` grant.
  """

  @hash_attribute :client_secret_hash
  @secret_bytes 32

  @doc "Attribute name expected on the client resource (`:client_secret_hash`)."
  @spec hash_attribute() :: :client_secret_hash
  def hash_attribute, do: @hash_attribute

  @doc """
  Generate a high-entropy plaintext secret and its storage hash.

  Returns `{plaintext, hash}`. Persist only the hash; return the plaintext
  to the client operator exactly once.
  """
  @spec generate() :: {plaintext :: String.t(), hash :: String.t()}
  def generate do
    plain = :crypto.strong_rand_bytes(@secret_bytes) |> Base.url_encode64(padding: false)
    {plain, hash(plain)}
  end

  @doc "SHA-256 hex digest of a plaintext secret (lowercase)."
  @spec hash(String.t()) :: String.t()
  def hash(secret) when is_binary(secret) do
    :crypto.hash(:sha256, secret) |> Base.encode16(case: :lower)
  end

  @doc """
  Verify a presented secret against `client.client_secret_hash`.

  Suitable as the `:verify_client_secret` MFA. Returns `false` when the
  client has no usable hash (after a constant-time dummy compare so missing
  hashes are not obviously faster than wrong secrets).
  """
  @spec verify(map(), String.t()) :: boolean()
  def verify(client, secret) when is_map(client) and is_binary(secret) do
    case stored_hash(client) do
      hash when is_binary(hash) and hash != "" ->
        Plug.Crypto.secure_compare(hash, hash(secret))

      _ ->
        dummy = hash("ash-authentication-oauth2-server-missing-client-secret-hash")
        _ = Plug.Crypto.secure_compare(dummy, hash(secret))
        false
    end
  end

  def verify(_, _), do: false

  defp stored_hash(%{__struct__: _} = client) do
    Map.get(client, @hash_attribute)
  end

  defp stored_hash(client) when is_map(client) do
    Map.get(client, @hash_attribute) || Map.get(client, Atom.to_string(@hash_attribute))
  end
end
