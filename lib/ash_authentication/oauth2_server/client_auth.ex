# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.ClientAuth do
  @moduledoc """
  Extract confidential-client credentials from a token request.

  Tries HTTP Basic first, then form body `client_id` + `client_secret`.
  Per RFC 6749 §5.2, using **both** mechanisms in one request is
  `invalid_request` (multiple authentication mechanisms).

  This module only extracts credentials; which presentation is allowed
  for a given client is decided by the token grant (confidential secret
  methods accept either channel).
  """

  @type auth_via :: :basic | :post

  # Bound sizes so crafted form/Basic values cannot force unbounded work
  # in app `verify_client_secret` callbacks (e.g. slow hashes).
  @max_client_id_bytes 2_048
  @max_client_secret_bytes 4_096

  @doc """
  Return `{client_id, client_secret, via}` from Basic auth **or** body params.

  Exactly one presentation:

  1. `Authorization: Basic …` (`via: :basic`), with no body `client_id` /
     `client_secret`
  2. else body `client_id` + `client_secret` (`via: :post`)

  A present but undecodable `Authorization: Basic …` header is
  `{:error, :invalid_client}`.

  User-id and password in Basic are percent-decoded per RFC 7617 /
  OAuth 2.1 client-password encoding.
  """
  @spec credentials(Plug.Conn.t() | map(), map()) ::
          {:ok, client_id :: String.t(), client_secret :: String.t(), auth_via()}
          | {:error, :invalid_client | :invalid_request}
  def credentials(conn_or_headers, params) when is_map(params) do
    with :ok <- ensure_scalar_strings(params) do
      resolve(basic_credentials(conn_or_headers), params)
    end
  end

  @doc """
  Like `credentials/2`, but for grants where client authentication is
  only required for confidential clients (`authorization_code`,
  `refresh_token`).

  Returns `:none` when the request presents no client secret at all —
  no `Authorization: Basic …` header and no (non-blank) body
  `client_secret` — which is the public-client case. Otherwise behaves
  exactly like `credentials/2`, including rejecting Basic combined with
  body credentials.
  """
  @spec optional_credentials(Plug.Conn.t() | map(), map()) ::
          :none
          | {:ok, client_id :: String.t(), client_secret :: String.t(), auth_via()}
          | {:error, :invalid_client | :invalid_request}
  def optional_credentials(conn_or_headers, params) when is_map(params) do
    with :ok <- ensure_scalar_strings(params) do
      case basic_credentials(conn_or_headers) do
        :absent ->
          if is_nil(blank_to_nil(params["client_secret"])),
            do: :none,
            else: resolve(:absent, params)

        basic ->
          resolve(basic, params)
      end
    end
  end

  defp resolve({:ok, basic_id, basic_secret}, params) do
    # RFC 6749 §5.2 invalid_request — "utilizes more than one mechanism
    # for authenticating the client" / "includes multiple credentials".
    if body_credential_present?(params) do
      {:error, :invalid_request}
    else
      finish(basic_id, basic_secret, :basic)
    end
  end

  defp resolve(:malformed_basic, _params), do: {:error, :invalid_client}

  defp resolve(:absent, params) do
    id = blank_to_nil(params["client_id"])
    secret = blank_to_nil(params["client_secret"])

    cond do
      is_binary(id) and is_binary(secret) ->
        finish(id, secret, :post)

      is_binary(id) ->
        {:error, :invalid_request}

      true ->
        {:error, :invalid_request}
    end
  end

  defp body_credential_present?(params) do
    not is_nil(blank_to_nil(params["client_id"])) or
      not is_nil(blank_to_nil(params["client_secret"]))
  end

  defp finish(id, secret, via) do
    cond do
      byte_size(id) > @max_client_id_bytes ->
        {:error, :invalid_request}

      byte_size(secret) > @max_client_secret_bytes ->
        {:error, :invalid_request}

      true ->
        {:ok, id, secret, via}
    end
  end

  # Non-string / nested credential params (e.g. arrays from crafted
  # form bodies / repeated parameters) are invalid_request, not coerced.
  defp ensure_scalar_strings(params) do
    id = Map.get(params, "client_id")
    secret = Map.get(params, "client_secret")

    cond do
      not is_nil(id) and not is_binary(id) ->
        {:error, :invalid_request}

      not is_nil(secret) and not is_binary(secret) ->
        {:error, :invalid_request}

      true ->
        :ok
    end
  end

  defp basic_credentials(%Plug.Conn{} = conn) do
    case Plug.Conn.get_req_header(conn, "authorization") do
      [value | _] when is_binary(value) -> parse_authorization(value)
      _ -> :absent
    end
  end

  defp basic_credentials(%{"authorization" => value}) when is_binary(value),
    do: parse_authorization(value)

  defp basic_credentials(_), do: :absent

  # Scheme matching is case-insensitive (RFC 9110).
  defp parse_authorization(value) do
    case String.split(value, " ", parts: 2) do
      [scheme, encoded] ->
        if String.downcase(scheme) == "basic" do
          decode_basic(encoded)
        else
          :absent
        end

      _ ->
        :absent
    end
  end

  defp decode_basic(encoded) do
    case Base.decode64(String.trim(encoded)) do
      {:ok, decoded} ->
        case String.split(decoded, ":", parts: 2) do
          [id, secret] when id != "" and secret != "" ->
            case {percent_decode(id), percent_decode(secret)} do
              {{:ok, id}, {:ok, secret}} when id != "" and secret != "" ->
                {:ok, id, secret}

              _ ->
                :malformed_basic
            end

          _ ->
            :malformed_basic
        end

      :error ->
        :malformed_basic
    end
  end

  defp percent_decode(value) do
    {:ok, URI.decode(value)}
  rescue
    ArgumentError -> :error
  end

  defp blank_to_nil(nil), do: nil
  defp blank_to_nil(""), do: nil
  defp blank_to_nil(value) when is_binary(value), do: value
end
