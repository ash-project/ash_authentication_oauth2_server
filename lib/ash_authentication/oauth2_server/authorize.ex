# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.Authorize do
  @moduledoc """
  Protocol-pure logic for the `/oauth/authorize` endpoint.

  Controllers in `ash_authentication_phoenix` are thin wrappers around
  `validate_request/3`, `consented?/5`, `grant_consent!/5`, and
  `issue_code!/4`. None of these functions touch `Plug.Conn`.

  ## Authorization & tenancy

  All Ash calls run through the `AshAuthentication.Checks.AshAuthenticationInteraction`
  bypass (set by the installer) rather than `authorize?: false`. Every public
  function accepts an `opts` keyword that may include `:tenant`; when set, it's
  threaded to every action so multi-tenant resources scope correctly.
  """

  require Ash.Query

  alias AshAuthentication.Oauth2Server
  alias AshAuthentication.Oauth2Server.{CIMD, ClientMetadata}

  @ash_context %{private: %{ash_authentication?: true}}

  @typedoc """
  The validated authorize-request payload. The struct is intentionally small —
  enough to render a consent screen and ultimately mint an authorization code.
  """
  @type validated :: %{
          client: Ash.Resource.Record.t(),
          redirect_uri: String.t(),
          code_challenge: String.t(),
          scope: String.t(),
          state: String.t() | nil,
          resource: String.t()
        }

  @typedoc "Options shared across this module's public functions."
  @type opts :: [tenant: any()]

  @doc """
  Validate an inbound authorize request.

  Returns:

    * `{:ok, validated}` — request is structurally sound and the client +
      redirect_uri are known.
    * `{:error, :bad_client, error_code, description}` — `client_id` is
      missing or unknown. Per OAuth 2.1 §4.1.2.1 the controller MUST NOT
      redirect.
    * `{:error, :bad_redirect_uri}` — redirect_uri is missing or doesn't
      match a registered URI; per RFC 6749 §4.1.2.1 the controller MUST NOT
      redirect.
    * `{:error, error_code, description}` — any other validation error.
      The client and the redirect URI are validated before any of these,
      so controllers redirect these errors to `error_redirect_uri/3`.

  ## A note on the `state` parameter

  `state` is optional (OAuth 2.1 §4.1.1). This server requires PKCE, which
  already protects the flow against CSRF (RFC 9700 §4.7). A client that
  sends `state` MUST set it to a cryptographically random, unguessable
  value. The server echoes it back via the redirect so the client can
  correlate the response with its pending request.

  This means **clients should NOT use `state` as a stash for
  application-level data** like a "return-to" URL or routing hints. That
  pattern is unsafe — the value travels through the user-agent and
  query string and is reflected back by the server, so any data put in
  it can be observed, replayed, or tampered with. Stash that data
  server-side (keyed by a fresh `state`), or encode it in a signed
  cookie.

  We don't enforce a shape or entropy minimum here, but anything other
  than a random per-request value defeats the purpose of `state`.
  """
  @spec validate_request(server :: module(), params :: map(), opts()) ::
          {:ok, validated()}
          | {:error, :bad_client, String.t(), String.t()}
          | {:error, :bad_redirect_uri}
          | {:error, String.t(), String.t()}
  def validate_request(server, params, opts \\ []) do
    secret_context = secret_context(Keyword.get(opts, :tenant))

    # OAuth 2.1 §4.1.2.1: client and redirect URI first, because only
    # errors after them may be redirected. Then malformed-request errors,
    # then the values the server does not accept.
    with {:ok, client} <- load_client(server, params, opts),
         {:ok, redirect_uri} <- resolve_redirect_uri(params, client),
         :ok <- check_grant_type(client),
         {:ok, _response_type} <- require_present(params, "response_type"),
         {:ok, code_challenge} <- require_present(params, "code_challenge"),
         :ok <- check_string_params(params, ["resource", "scope", "state"]),
         :ok <- require_eq(params, "code_challenge_method", "S256", "invalid_request"),
         :ok <- require_eq(params, "response_type", "code", "unsupported_response_type"),
         {:ok, scope} <- require_scope(params),
         :ok <- check_scopes(server, scope),
         {:ok, resource} <- resolve_resource(server, params, scope, secret_context) do
      {:ok,
       %{
         client: client,
         redirect_uri: redirect_uri,
         code_challenge: code_challenge,
         scope: scope,
         state: optional(params, "state"),
         resource: resource
       }}
    end
  end

  @doc """
  The redirect URI for an error that `validate_request/3` returned as
  `{:error, error_code, description}`: the request's `redirect_uri`, or the
  client's only registered redirect URI when the request omits it.

  Applies the same match as `validate_request/3`, so it returns `:error`
  for any URI that `validate_request/3` would not redirect to. Reads the
  client from the database only. It never fetches a Client ID Metadata
  Document, because `validate_request/3` already stored it.
  """
  @spec error_redirect_uri(server :: module(), params :: map(), opts()) ::
          {:ok, String.t()} | :error
  def error_redirect_uri(server, params, opts \\ []) do
    with {:ok, client} <- find_client(server, params["client_id"], opts),
         {:ok, redirect_uri} <- resolve_redirect_uri(params, client) do
      {:ok, redirect_uri}
    else
      _ -> :error
    end
  end

  defp find_client(server, "https://" <> _ = url, opts), do: CIMD.find_client(server, url, opts)

  defp find_client(server, client_id, opts) when is_binary(client_id) and client_id != "",
    do: Ash.get(server.client_resource(), client_id, ash_opts(opts))

  defp find_client(_server, _client_id, _opts), do: :error

  @doc """
  Has the user already consented to this client at a scope that covers the
  currently-requested scope?

  Returns true ONLY when prior consent exists AND its scope is a superset of
  `requested_scope`. This prevents silent privilege expansion when a client
  later asks for more scopes than the user originally agreed to.
  """
  @spec consented?(
          server :: module(),
          user :: Ash.Resource.Record.t(),
          client :: Ash.Resource.Record.t(),
          requested_scope :: String.t(),
          opts()
        ) :: boolean()
  def consented?(server, user, client, requested_scope, opts \\ []) do
    case stored_scope(server, user, client, opts) do
      {:ok, stored} -> scope_covers?(stored, requested_scope)
      :error -> false
    end
  end

  @doc """
  Add `scope` to the consent of `user` for `client`.
  """
  @spec grant_consent!(
          server :: module(),
          user :: Ash.Resource.Record.t(),
          client :: Ash.Resource.Record.t(),
          scope :: String.t(),
          opts()
        ) :: Ash.Resource.Record.t()
  def grant_consent!(server, user, client, scope, opts \\ []) do
    resource = server.consent_resource()

    resource
    |> Ash.transact(
      fn ->
        scope =
          case stored_scope(server, user, client, opts, true) do
            {:ok, stored} -> merge_scopes(stored, scope)
            :error -> scope
          end

        resource
        |> Ash.Changeset.for_create(:grant, %{
          user_id: user.id,
          client_id: client.id,
          scope: scope
        })
        |> Ash.create!(ash_opts(opts))
      end,
      Keyword.take(opts, [:tenant])
    )
    |> case do
      {:ok, consent} -> consent
      {:error, error} -> raise Ash.Error.to_error_class(error)
    end
  end

  defp stored_scope(server, user, client, opts, lock? \\ false) do
    server.consent_resource()
    |> Ash.Query.filter(user_id == ^user.id and client_id == ^client.id)
    |> maybe_lock(lock?)
    |> Ash.read_one(ash_opts(opts))
    |> case do
      {:ok, %{scope: stored}} when is_binary(stored) -> {:ok, stored}
      _ -> :error
    end
  end

  defp maybe_lock(query, true) do
    if Ash.DataLayer.data_layer_can?(query.resource, {:lock, :for_update}),
      do: Ash.Query.lock(query, :for_update),
      else: query
  end

  defp maybe_lock(query, false), do: query

  defp merge_scopes(stored, requested) do
    (String.split(stored, " ", trim: true) ++ String.split(requested, " ", trim: true))
    |> Enum.uniq()
    |> Enum.join(" ")
  end

  @doc """
  Mint a new short-lived authorization code bound to the user, client, scope,
  PKCE challenge, and resource URI.
  """
  @spec issue_code!(
          server :: module(),
          user :: Ash.Resource.Record.t(),
          validated :: validated(),
          opts()
        ) :: Ash.Resource.Record.t()
  def issue_code!(server, user, validated, opts \\ []) do
    expires_at =
      DateTime.add(DateTime.utc_now(), server.authorization_code_lifetime(), :second)

    server.authorization_code_resource()
    |> Ash.Changeset.for_create(:create, %{
      client_id: validated.client.id,
      user_id: user.id,
      redirect_uri: validated.redirect_uri,
      code_challenge: validated.code_challenge,
      scope: validated.scope,
      resource_uri: validated.resource,
      expires_at: expires_at
    })
    |> Ash.create!(ash_opts(opts))
  end

  # ── helpers ──────────────────────────────────────────────────────────────

  # Builds the standard Ash opts: bypass context + tenant if provided.
  defp ash_opts(opts) do
    base = [context: @ash_context]

    case Keyword.get(opts, :tenant) do
      nil -> base
      tenant -> Keyword.put(base, :tenant, tenant)
    end
  end

  defp require_eq(params, key, expected, error_code) do
    case Map.get(params, key) do
      ^expected -> :ok
      _ -> {:error, error_code, "expected #{key}=#{expected}"}
    end
  end

  # A query like `resource[x]=y` decodes to a map. That is a malformed
  # parameter, `invalid_request`, not an omitted one (OAuth 2.1 §4.1.2.1).
  defp check_string_params(params, keys) do
    case Enum.find(keys, &(not (is_nil(params[&1]) or is_binary(params[&1])))) do
      nil -> :ok
      key -> {:error, "invalid_request", "#{key} must be a string"}
    end
  end

  # OAuth 2.1 §3.1: a parameter sent without a value counts as omitted.
  defp optional(params, key) do
    case Map.get(params, key) do
      "" -> nil
      value when is_binary(value) -> value
      _ -> nil
    end
  end

  # OAuth 2.1 §1.4.1: without a default scope, a request that omits
  # `scope` fails as `invalid_scope`.
  defp require_scope(params) do
    case require_present(params, "scope") do
      {:ok, scope} -> {:ok, scope}
      {:error, _code, _desc} -> {:error, "invalid_scope", "scope is required"}
    end
  end

  defp require_present(params, key) do
    case Map.get(params, key) do
      v when is_binary(v) and v != "" -> {:ok, v}
      _ -> {:error, "invalid_request", "#{key} is required"}
    end
  end

  # A URL-shaped client_id is a Client ID Metadata Document reference —
  # resolve it (fetch + validate + upsert) when CIMD is enabled.
  defp load_client(server, %{"client_id" => "https://" <> _ = url}, opts) do
    if server.cimd_enabled?() do
      case CIMD.resolve_client(server, url, opts) do
        {:ok, client} -> {:ok, client}
        {:error, description} -> {:error, :bad_client, "invalid_client", description}
      end
    else
      {:error, :bad_client, "invalid_client", "URL client_ids are not supported by this server"}
    end
  end

  defp load_client(server, %{"client_id" => id}, opts) when is_binary(id) and id != "" do
    case Ash.get(server.client_resource(), id, ash_opts(opts)) do
      {:ok, client} -> {:ok, client}
      _ -> {:error, :bad_client, "invalid_client", "unknown client_id"}
    end
  end

  defp load_client(_server, params, _opts) do
    case Map.fetch(params, "client_id") do
      {:ok, id} when id not in [nil, ""] ->
        {:error, :bad_client, "invalid_request", "client_id must be a string"}

      _ ->
        {:error, :bad_client, "invalid_request", "client_id required"}
    end
  end

  # RFC 6749 §4.1.2.1 — a client not registered for the authorization_code
  # grant (e.g. a client_credentials-only machine client) must not start a
  # user-delegated flow. Checked after the redirect URI so the error can be
  # returned to the client's (validated) redirect URI.
  defp check_grant_type(client) do
    if "authorization_code" in ClientMetadata.allowed_grant_types(client),
      do: :ok,
      else:
        {:error, "unauthorized_client",
         "client is not allowed to use the authorization_code grant"}
  end

  # RFC 9700 §4.1 — exact byte-equal match. No normalization, no
  # default-port elision, no trailing-slash equivalence. The client MUST
  # use the same redirect URI string it registered with — with the one
  # exception RFC 9700 inherits from RFC 8252 §7.3: for loopback
  # redirects, the port MUST be allowed to vary, because native and CLI
  # clients bind an ephemeral port at authorization time and
  # (particularly with CIMD) cannot register it in advance.
  #
  # RFC 8252 §7.3 phrases the exception in terms of "http://127.0.0.1"
  # (and by extension "::1"), and a strict reading excludes the
  # `localhost` hostname since its resolution isn't guaranteed to stay
  # loopback. In practice several real-world native/CLI OAuth clients
  # (Claude Code among them) always redirect to `localhost` and never
  # fall back to the IP literal, even when their own client metadata
  # advertises support for both — so excluding it breaks interop with
  # them entirely. We include `localhost` here too, accepting the same
  # theoretical, local-machine-only risk the IP-literal exception
  # already accepts.
  # OAuth 2.1 §2.3.2: `redirect_uri` is optional when the client has
  # exactly one registered redirect URI.
  # A `redirect_uri` that is not a string is malformed, not omitted.
  defp resolve_redirect_uri(%{"redirect_uri" => uri}, _client)
       when not is_nil(uri) and not is_binary(uri),
       do: {:error, :bad_redirect_uri}

  defp resolve_redirect_uri(params, %{redirect_uris: uris}) when is_list(uris) do
    case {optional(params, "redirect_uri"), uris} do
      {nil, [only]} ->
        {:ok, only}

      {nil, _} ->
        {:error, :bad_redirect_uri}

      {uri, uris} ->
        if Enum.any?(uris, &redirect_uri_match?(uri, &1)),
          do: {:ok, uri},
          else: {:error, :bad_redirect_uri}
    end
  end

  defp resolve_redirect_uri(_, _), do: {:error, :bad_redirect_uri}

  @loopback_hosts ["127.0.0.1", "::1", "localhost"]

  defp redirect_uri_match?(uri, uri), do: true

  defp redirect_uri_match?(presented, registered) do
    presented = URI.parse(presented)
    registered = URI.parse(registered)

    presented.host in @loopback_hosts and
      registered.host == presented.host and
      registered.scheme == presented.scheme and
      registered.path == presented.path and
      registered.query == presented.query
  end

  # When `enforce_scopes?` is true (the default), every requested scope
  # must be in the server's advertised catalogue. When false, scopes are
  # passed through unchecked — for apps with a dynamic catalogue that
  # validate scopes downstream.
  defp check_scopes(server, scope) when is_binary(scope) do
    if server.enforce_scopes?() do
      allowed = MapSet.new(server.scopes())
      requested = scope |> String.split(" ", trim: true) |> MapSet.new()

      case MapSet.difference(requested, allowed) |> MapSet.to_list() do
        [] -> :ok
        [unknown | _] -> {:error, "invalid_scope", scope_error_description(unknown)}
      end
    else
      :ok
    end
  end

  # OAuth 2.1 §4.1.2.1 limits `error_description` to %x20-21 / %x23-5B /
  # %x5D-7E. A valid scope token (RFC 6749 §3.3) uses only those characters,
  # so it is safe to echo. Any other value is left out.
  defp scope_error_description(scope) do
    if scope =~ ~r/\A[\x21\x23-\x5B\x5D-\x7E]+\z/,
      do: "scope #{scope} is not allowed",
      else: "requested scope is not allowed"
  end

  # `resource` is optional per RFC 8707 §2. When present, it MUST name a
  # configured resource. When absent, the requested scopes select the
  # resource (RFC 9068 §3). Error descriptions echo the configured
  # identifiers (server-controlled), never the user-supplied value, so they
  # don't create a "reflect user input" surface.
  defp resolve_resource(server, params, scope, secret_context) do
    requested = scope |> String.split(" ", trim: true) |> MapSet.new()
    check_disjoint_scopes!(server)

    with {:ok, name} <- select_resource(server, params, requested, secret_context),
         :ok <- check_resource_scopes(server, name, requested) do
      {:ok, server.resource_url(name, secret_context)}
    end
  end

  defp select_resource(server, %{"resource" => res}, _requested, secret_context)
       when is_binary(res) and res != "" do
    case Oauth2Server.__find_resource__(server, res, secret_context) do
      {:ok, name, _url} ->
        {:ok, name}

      :error ->
        expected =
          Enum.map_join(server.resources(), ", ", &server.resource_url(&1, secret_context))

        {:error, "invalid_target",
         "resource parameter does not match a resource of this authorization server " <>
           "(expected one of: #{expected})"}
    end
  end

  defp select_resource(server, _params, requested, _secret_context) do
    case server.resources() do
      [name] ->
        {:ok, name}

      names ->
        names
        |> Enum.filter(&MapSet.subset?(requested, MapSet.new(server.resource_scopes(&1))))
        |> case do
          [name] ->
            {:ok, name}

          _ ->
            {:error, "invalid_target",
             "resource parameter is required, because the requested scopes do not " <>
               "select exactly one resource"}
        end
    end
  end

  # Static scope lists are checked at compile time. This catches scope
  # lists that functions compute.
  defp check_disjoint_scopes!(server) do
    case server.resources() do
      [_single] ->
        :ok

      names ->
        Oauth2Server.__check_disjoint_scopes__!(
          server,
          Enum.map(names, &{&1, server.resource_scopes(&1)})
        )
    end
  end

  # RFC 8707 §2 — `invalid_target` also reports a scope that the selected
  # resource does not accept.
  defp check_resource_scopes(server, name, requested) do
    if server.enforce_scopes?() do
      allowed = MapSet.new(server.resource_scopes(name))

      case requested |> MapSet.difference(allowed) |> MapSet.to_list() do
        [] ->
          :ok

        [unknown | _] ->
          {:error, "invalid_target", scope_error_description(unknown) <> " for this resource"}
      end
    else
      :ok
    end
  end

  defp secret_context(nil), do: %{}
  defp secret_context(tenant), do: %{tenant: tenant}

  defp scope_covers?(stored, requested) when is_binary(stored) and is_binary(requested) do
    stored_set = stored |> String.split(" ", trim: true) |> MapSet.new()
    requested_set = requested |> String.split(" ", trim: true) |> MapSet.new()
    MapSet.subset?(requested_set, stored_set)
  end

  defp scope_covers?(_, _), do: false
end
