# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.CIMD.Fetcher do
  @moduledoc """
  Behaviour for fetching OAuth Client ID Metadata Documents.

  A Client ID Metadata Document (CIMD) client identifies itself with an
  HTTPS URL as its `client_id`; the authorization server fetches the JSON
  metadata document from that URL. This behaviour is the extension point
  for *how* that fetch happens — the default implementation is
  `AshAuthentication.Oauth2Server.CIMD.ReqFetcher`, which applies an
  SSRF-safe outbound policy.

  Swap in your own module via the `:cimd_fetcher` option on your
  `Oauth2Server` module when you need a different outbound policy (an
  egress proxy, an allowlist of client hosts, a stub for tests, etc.).
  """

  @typedoc """
  A successful fetch.

    * `:document` — the decoded JSON object (a map with string keys).
      Validation of its *contents* happens in
      `AshAuthentication.Oauth2Server.CIMD` — the fetcher only guarantees
      it retrieved and decoded a JSON object.
    * `:cache_ttl` — seconds the document may be cached for, derived from
      the response's `Cache-Control` header. `nil` means the response
      carried no caching directives (the caller applies its default);
      `0` means the response asked not to be cached.
  """
  @type result :: %{
          document: map(),
          cache_ttl: non_neg_integer() | nil
        }

  @doc """
  Fetch and JSON-decode the metadata document at `url`.

  `opts` is the server's `:cimd_fetch_options` config, passed through
  verbatim — implementations define their own option set.
  """
  @callback fetch(url :: String.t(), opts :: keyword()) ::
              {:ok, result()} | {:error, term()}
end
