# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.CIMD do
  @moduledoc """
  OAuth Client ID Metadata Documents
  ([draft-ietf-oauth-client-id-metadata-document](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-00)).

  A CIMD client uses an HTTPS URL as its `client_id`; the URL points at a
  JSON document describing the client (`client_name`, `redirect_uris`, …).
  This lets clients and servers with no prior relationship interoperate
  without a registration endpoint — the mechanism the MCP spec (2026-07-28)
  now recommends over Dynamic Client Registration.

  Enable it with `cimd_enabled?: true` on your `Oauth2Server` module. When
  enabled, the RFC 8414 metadata document advertises
  `client_id_metadata_document_supported: true` and the `/oauth/authorize`
  endpoint accepts URL-shaped `client_id`s.

  ## How resolved clients are stored

  A validated metadata document is upserted into your regular client
  resource, keyed by a `cimd_url` attribute — so authorization codes,
  refresh tokens, and consent records keep referencing clients by their
  UUID primary key exactly as they do for registered clients. The
  document is re-fetched (subject to HTTP caching, honoured via
  `AshAuthentication.Oauth2Server.CIMD.Cache`) on each authorization
  request, so renamed clients and rotated redirect URIs are picked up;
  the token, revocation, and error-redirect paths resolve the URL from
  the database only and never trigger a fetch.

  ## Client resource requirements

  Your client resource needs (the installer scaffolds these for new apps):

      attribute :cimd_url, :string, public?: true

      identity :by_cimd_url, [:cimd_url]

      create :register_cimd do
        upsert? true
        upsert_identity :by_cimd_url
        accept [:cimd_url, :client_name, :redirect_uris, :grant_types,
                :response_types, :token_endpoint_auth_method, :scope]
      end

  ## Fetching and SSRF

  The fetch of an attacker-suppliable URL is the risky part; it goes
  through the `:cimd_fetcher` module (default:
  `AshAuthentication.Oauth2Server.CIMD.ReqFetcher`, which requires the
  optional `req` dependency and applies a strict outbound policy — see
  its docs). The authorize endpoint is the only place a fetch can be
  triggered, and it is unauthenticated by protocol design — rate-limit it
  like the other protocol endpoints (see the "Rate limiting" section in
  `AshAuthentication.Oauth2Server`).
  """

  require Ash.Query
  require Logger

  alias AshAuthentication.Oauth2Server.CIMD.Cache
  alias AshAuthentication.Oauth2Server.ClientMetadata

  @ash_context %{private: %{ash_authentication?: true}}

  # Applied when the document's response carried no cache directives, and
  # as the upper bound when it did — a stolen/compromised client identity
  # shouldn't be pinned in cache for longer than an hour regardless of
  # what its Cache-Control says.
  @default_cache_ttl 300
  @max_cache_ttl 3600

  @doc """
  Is this `client_id` value a CIMD-style URL?

  Per the draft, a CIMD `client_id` must be an `https` URL — anything
  else is treated as an ordinary (opaque) client identifier.
  """
  @spec url_client_id?(term()) :: boolean()
  def url_client_id?(client_id),
    do: is_binary(client_id) and String.starts_with?(client_id, "https://")

  @doc """
  Resolve a URL `client_id` to a client record: fetch the metadata
  document (through the cache), validate it, and upsert it into the
  client resource.

  Returns `{:ok, client}` or `{:error, description}` — the description is
  safe to include in an OAuth `invalid_client` error response; fetch and
  data-layer details are logged, not returned.
  """
  @spec resolve_client(server :: module(), url :: String.t(), opts :: keyword()) ::
          {:ok, Ash.Resource.record()} | {:error, String.t()}
  def resolve_client(server, url, opts \\ []) do
    ensure_client_resource_support!(server)

    with {:ok, document} <- get_document(server, url),
         :ok <- validate_document(document, url) do
      upsert_client(server, url, document, opts)
    end
  end

  @doc """
  Look up an already-resolved CIMD client by its URL — database only, no
  fetch. Used by the token, revocation, and error-redirect paths, where
  the client must have been resolved during authorization already.
  """
  @spec find_client(server :: module(), url :: String.t(), opts :: keyword()) ::
          {:ok, Ash.Resource.record()} | :error
  def find_client(server, url, opts \\ []) do
    server.client_resource()
    |> Ash.Query.filter(cimd_url == ^url)
    |> Ash.read_one(ash_opts(opts))
    |> case do
      {:ok, client} when not is_nil(client) -> {:ok, client}
      _ -> :error
    end
  end

  # ── document retrieval ─────────────────────────────────────────────────────

  defp get_document(server, url) do
    case Cache.get(url) do
      {:ok, document} ->
        {:ok, document}

      :miss ->
        fetch_document(server, url)
    end
  end

  defp fetch_document(server, url) do
    case server.cimd_fetcher().fetch(url, server.cimd_fetch_options()) do
      {:ok, %{document: document, cache_ttl: ttl}} ->
        Cache.put(url, document, clamp_ttl(ttl))
        {:ok, document}

      {:error, reason} ->
        Logger.warning(
          "Oauth2Server: failed to fetch client ID metadata document from " <>
            "#{inspect(url)}: #{inspect(reason)}"
        )

        {:error, "could not fetch client metadata document"}
    end
  end

  defp clamp_ttl(nil), do: @default_cache_ttl
  defp clamp_ttl(ttl) when is_integer(ttl) and ttl >= 0, do: min(ttl, @max_cache_ttl)
  defp clamp_ttl(_), do: 0

  # ── document validation ────────────────────────────────────────────────────

  @doc """
  Validate a fetched metadata document against the CIMD draft and this
  server's supported client shape.

  Checks, in order: the document's `client_id` matches the URL it was
  fetched from **exactly** (no normalization — per the draft), a
  `client_name` is present (required by the MCP spec; it's what the
  consent screen shows the user), and the `redirect_uris` /
  `grant_types` / `response_types` / `token_endpoint_auth_method`
  fields pass the same validation Dynamic Client Registration applies.
  """
  @spec validate_document(document :: map(), url :: String.t()) ::
          :ok | {:error, String.t()}
  def validate_document(document, url) when is_map(document) do
    with :ok <- check_client_id(document, url),
         :ok <- check_client_name(document),
         :ok <- flatten(ClientMetadata.validate_redirect_uris(document)),
         :ok <- flatten(ClientMetadata.validate_grant_types(document)),
         :ok <- flatten(ClientMetadata.validate_response_types(document)) do
      flatten(ClientMetadata.validate_auth_method(document))
    end
  end

  def validate_document(_, _), do: {:error, "metadata document must be a JSON object"}

  defp check_client_id(%{"client_id" => client_id}, url) when client_id == url, do: :ok

  defp check_client_id(_, _),
    do: {:error, "client_id in metadata document does not exactly match the document URL"}

  defp check_client_name(%{"client_name" => name}) when is_binary(name) and name != "", do: :ok
  defp check_client_name(_), do: {:error, "client_name is required"}

  defp flatten(:ok), do: :ok
  defp flatten({:error, _code, description}), do: {:error, description}

  # ── persistence ────────────────────────────────────────────────────────────

  defp upsert_client(server, url, document, opts) do
    attrs = %{
      cimd_url: url,
      client_name: Map.fetch!(document, "client_name"),
      redirect_uris: Map.fetch!(document, "redirect_uris"),
      grant_types: ClientMetadata.narrow_grant_types(document),
      response_types: Map.get(document, "response_types", ["code"]),
      token_endpoint_auth_method: Map.get(document, "token_endpoint_auth_method", "none"),
      scope: Enum.join(server.scopes(), " ")
    }

    server.client_resource()
    |> Ash.Changeset.for_create(:register_cimd, attrs)
    |> Ash.create(ash_opts(opts))
    |> case do
      {:ok, client} ->
        {:ok, client}

      {:error, error} ->
        Logger.error(
          "Oauth2Server: failed to upsert CIMD client for #{inspect(url)}: #{inspect(error)}"
        )

        {:error, "could not register client from metadata document"}
    end
  end

  defp ensure_client_resource_support!(server) do
    resource = server.client_resource()

    unless Ash.Resource.Info.attribute(resource, :cimd_url) &&
             Ash.Resource.Info.action(resource, :register_cimd) do
      raise """
      #{inspect(server)} has `cimd_enabled?: true`, but its client resource
      (#{inspect(resource)}) is missing CIMD support. Add:

          attribute :cimd_url, :string, public?: true

          identity :by_cimd_url, [:cimd_url]

          create :register_cimd do
            upsert? true
            upsert_identity :by_cimd_url
            accept [:cimd_url, :client_name, :redirect_uris, :grant_types,
                    :response_types, :token_endpoint_auth_method, :scope]
          end

      (and a migration for the new attribute + unique index).
      """
    end
  end

  defp ash_opts(opts) do
    base = [context: @ash_context]

    case Keyword.get(opts, :tenant) do
      nil -> base
      tenant -> Keyword.put(base, :tenant, tenant)
    end
  end
end
