# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.ClientMetadata do
  @moduledoc """
  Shared validation for OAuth client metadata, whichever way it arrives —
  a Dynamic Client Registration request body (RFC 7591) or a fetched
  Client ID Metadata Document. Both are JSON objects with the same
  field vocabulary, and this server accepts the same subset from each:
  public clients only (`token_endpoint_auth_method: "none"`), the
  `authorization_code` + `refresh_token` grants, and `code` responses.

  All functions take the decoded metadata map (string keys) and return
  `:ok` or `{:error, error_code, description}` in RFC 7591's error
  vocabulary.
  """

  @valid_grant_types ~w(authorization_code refresh_token)
  @valid_response_types ~w(code)
  @valid_auth_methods ~w(none)

  @doc """
  Validate `redirect_uris`: required, non-empty, and every entry must be
  `https` (or `http` on a loopback host), have a host, and carry no
  fragment.
  """
  @spec validate_redirect_uris(map()) :: :ok | {:error, String.t(), String.t()}
  def validate_redirect_uris(%{"redirect_uris" => uris}) when is_list(uris) and uris != [] do
    Enum.reduce_while(uris, :ok, fn uri, _ ->
      case URI.new(uri) do
        {:ok, %URI{scheme: "https", host: host, fragment: nil}}
        when is_binary(host) and host != "" ->
          {:cont, :ok}

        {:ok, %URI{scheme: "http", host: host, fragment: nil}}
        when host in ["localhost", "127.0.0.1", "::1"] ->
          {:cont, :ok}

        _ ->
          {:halt,
           {:error, "invalid_redirect_uri",
            "redirect URIs must use https (or http localhost), have a host, and no fragment"}}
      end
    end)
  end

  def validate_redirect_uris(_),
    do: {:error, "invalid_client_metadata", "redirect_uris is required"}

  @doc """
  Validate `grant_types` when present.

  The client must list `authorization_code` — it is the only way to obtain
  a token from this server. Grants beyond what this server supports are
  tolerated rather than rejected: RFC 7591 §2 lets the server "reject or
  replace" requested metadata, and a client's metadata (particularly a
  CIMD document, which is shared across every server the client talks to)
  routinely describes capabilities aimed at other authorization servers.
  The stored registration is narrowed to the supported subset via
  `narrow_grant_types/1`.
  """
  @spec validate_grant_types(map()) :: :ok | {:error, String.t(), String.t()}
  def validate_grant_types(%{"grant_types" => grants}) when is_list(grants) do
    if "authorization_code" in grants,
      do: :ok,
      else: {:error, "invalid_client_metadata", "grant_types must include authorization_code"}
  end

  def validate_grant_types(_), do: :ok

  @doc """
  The subset of the client's requested `grant_types` this server supports —
  what actually gets registered. Defaults to `["authorization_code"]` when
  the field is absent.
  """
  @spec narrow_grant_types(map()) :: [String.t()]
  def narrow_grant_types(params) do
    params
    |> Map.get("grant_types", ["authorization_code"])
    |> Enum.filter(&(&1 in @valid_grant_types))
  end

  @doc """
  Validate `response_types` when present — `code` only.
  """
  @spec validate_response_types(map()) :: :ok | {:error, String.t(), String.t()}
  def validate_response_types(%{"response_types" => types}) when is_list(types) do
    if Enum.all?(types, &(&1 in @valid_response_types)),
      do: :ok,
      else: {:error, "invalid_client_metadata", "unsupported response_type"}
  end

  def validate_response_types(_), do: :ok

  @doc """
  Validate `token_endpoint_auth_method` when present — public clients
  (`"none"`) only.
  """
  @spec validate_auth_method(map()) :: :ok | {:error, String.t(), String.t()}
  def validate_auth_method(%{"token_endpoint_auth_method" => m}) when m in @valid_auth_methods,
    do: :ok

  def validate_auth_method(%{"token_endpoint_auth_method" => _}),
    do: {:error, "invalid_client_metadata", "unsupported token_endpoint_auth_method"}

  def validate_auth_method(_), do: :ok
end
