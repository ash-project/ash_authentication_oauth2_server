# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.ClientAuth do
  @moduledoc """
  The client authentication of a token endpoint request.

  A client identifies itself with `client_id`, and a confidential client
  authenticates with a secret, either as HTTP Basic credentials or as the
  `client_secret` body parameter (RFC 6749 §2.3.1). `parse/2` reads both
  and reports which method the request used, so the grant can compare it
  with the method the client registered (RFC 7591 §2
  `token_endpoint_auth_method`).

  A request fails with `invalid_request` when it uses more than one
  authentication method, names two different clients, or carries malformed
  parameters (RFC 6749 §5.2). A Basic header that cannot be decoded fails
  with `invalid_client`.
  """

  @type method :: :none | :client_secret_basic | :client_secret_post | :unsupported

  @type t :: %__MODULE__{
          client_id: String.t() | nil,
          client_secret: String.t() | nil,
          method: method()
        }

  defstruct client_id: nil, client_secret: nil, method: :none

  # Bound sizes so crafted values cannot force unbounded work in the
  # configured `:verify_client_secret`.
  @max_client_id_bytes 2_048
  @max_client_secret_bytes 4_096

  @assertion_params ~w(client_assertion client_assertion_type)

  @doc """
  Parse the client authentication of a request.

  Takes the `Plug.Conn` (or a map of lowercase request headers) and the
  decoded body parameters. Returns the client id, the secret when one was
  presented, and the method:

    * `:none` when the request carries no client credentials. `client_id`
      is the body parameter, or `nil`.
    * `:client_secret_basic` for `Authorization: Basic`. A body `client_id`
      is accepted when it names the same client.
    * `:client_secret_post` for `client_id` and `client_secret` body
      parameters.
    * `:unsupported` for a method this server does not implement, such as
      a `client_assertion` or another `Authorization` scheme.

  An empty `client_secret` counts as absent (OAuth 2.1 §3.2).
  """
  @spec parse(Plug.Conn.t() | map(), map()) ::
          {:ok, t()} | {:error, :invalid_request | :invalid_client}
  def parse(conn_or_headers, params) when is_map(params) do
    with :ok <- check_param_shapes(params),
         {:ok, header} <- parse_authorization(conn_or_headers) do
      body_id = blank_to_nil(params["client_id"])
      body_secret = blank_to_nil(params["client_secret"])
      assertion? = Enum.any?(@assertion_params, &Map.has_key?(params, &1))

      mechanisms = Enum.count([header != :absent, body_secret != nil, assertion?], & &1)

      cond do
        # RFC 6749 §5.2: more than one mechanism is a malformed request.
        mechanisms > 1 ->
          {:error, :invalid_request}

        match?({:basic, _, _}, header) ->
          {:basic, id, secret} = header

          if is_nil(body_id) or body_id == id,
            do: finish(id, secret, :client_secret_basic),
            else: {:error, :invalid_request}

        header == :unsupported or assertion? ->
          {:ok, %__MODULE__{client_id: body_id, method: :unsupported}}

        is_binary(body_secret) and is_binary(body_id) ->
          finish(body_id, body_secret, :client_secret_post)

        is_binary(body_secret) ->
          # A secret without a client id cannot be checked against anything.
          {:error, :invalid_request}

        true ->
          finish(body_id, nil, :none)
      end
    end
  end

  defp finish(id, secret, method) do
    cond do
      is_binary(id) and byte_size(id) > @max_client_id_bytes ->
        {:error, :invalid_request}

      is_binary(secret) and byte_size(secret) > @max_client_secret_bytes ->
        {:error, :invalid_request}

      true ->
        {:ok, %__MODULE__{client_id: id, client_secret: secret, method: method}}
    end
  end

  # A repeated parameter decodes to a list, and `client_id[x]=y` to a map.
  # Both are malformed (RFC 6749 §5.2).
  defp check_param_shapes(params) do
    if Enum.all?(["client_id", "client_secret" | @assertion_params], fn key ->
         is_nil(params[key]) or is_binary(params[key])
       end),
       do: :ok,
       else: {:error, :invalid_request}
  end

  defp parse_authorization(%Plug.Conn{} = conn) do
    case Plug.Conn.get_req_header(conn, "authorization") do
      [value | _] -> parse_authorization_value(value)
      [] -> {:ok, :absent}
    end
  end

  defp parse_authorization(%{"authorization" => value}) when is_binary(value),
    do: parse_authorization_value(value)

  defp parse_authorization(_), do: {:ok, :absent}

  # The scheme is case-insensitive (RFC 9110 §11.1).
  defp parse_authorization_value(value) do
    case String.split(value, " ", parts: 2) do
      [scheme, encoded] ->
        if String.downcase(scheme) == "basic",
          do: decode_basic(encoded),
          else: {:ok, :unsupported}

      _ ->
        {:ok, :unsupported}
    end
  end

  # RFC 6749 §2.3.1: user-id and password are form-urlencoded before they
  # are joined, so both are percent-decoded here.
  defp decode_basic(encoded) do
    with {:ok, decoded} <- Base.decode64(String.trim(encoded)),
         [id, secret] <- String.split(decoded, ":", parts: 2),
         {:ok, id} <- percent_decode(id),
         {:ok, secret} <- percent_decode(secret),
         true <- id != "" and secret != "" do
      {:ok, {:basic, id, secret}}
    else
      _ -> {:error, :invalid_client}
    end
  end

  defp percent_decode(value) do
    {:ok, URI.decode(value)}
  rescue
    ArgumentError -> :error
  end

  defp blank_to_nil(""), do: nil
  defp blank_to_nil(value), do: value
end
