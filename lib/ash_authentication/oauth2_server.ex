# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server do
  @moduledoc """
  An OAuth 2.1 authorization server, configured per app via a single module.

  The authorization server is a singleton — one per app, not one per user
  resource — so its config lives on its own module rather than on a strategy
  block of a user resource.

  ## Usage

  ```elixir
  defmodule MyApp.Oauth2Server do
    use AshAuthentication.Oauth2Server,
      otp_app: :my_app,
      user_resource: MyApp.Accounts.User,
      issuer_url: {MyApp.Secrets, []},
      resource_url: {MyApp.Secrets, []},
      signing_secret: {MyApp.Secrets, []},
      client_resource: MyApp.Accounts.OAuthClient,
      authorization_code_resource: MyApp.Accounts.OAuthAuthorizationCode,
      refresh_token_resource: MyApp.Accounts.OAuthRefreshToken,
      consent_resource: MyApp.Accounts.OAuthConsent,
      scopes: ["mcp"]
  end
  ```

  Required keys: `:otp_app`, `:user_resource`, `:issuer_url`, `:signing_secret`,
  `:client_resource`, `:authorization_code_resource`, `:refresh_token_resource`,
  `:consent_resource`, and exactly one of `:resource_url` or `:resources`.

  Optional keys (with defaults):

  | Key | Default | Notes |
  |---|---|---|
  | `:scopes` | `[]` | Scope catalogue advertised in metadata and accepted at `/authorize`. Can be a static list (`["read", "write"]`), a 0-arity function (`fn -> [...] end`), or an MFA tuple (`{Module, :function, [args]}`) — use the function/MFA forms for dynamically-computed catalogues. The library default is empty, which combined with `:enforce_scopes?` (also default) means *no scope works out of the box* — the installer scaffolds a placeholder you're meant to replace. |
  | `:enforce_scopes?` | `true` | When `true`, requested scopes at `/authorize` MUST be a subset of `:scopes`. Set to `false` only if you have a dynamic / runtime-generated scope catalogue and intend to validate downstream. |
  | `:access_token_lifetime` | `{1, :hour}` | `{integer, unit}` where unit is `:second`, `:minute`, `:hour`, or `:day` |
  | `:refresh_token_lifetime` | `{30, :days}` | |
  | `:authorization_code_lifetime` | `{10, :minutes}` | |
  | `:clock_skew_seconds` | `30` | Tolerance applied to `exp` and `nbf` JWT claim checks. Allows for small clock differences between the AS and resource server. RFC 7519 §4.1.4 — "MAY provide for some small leeway, usually no more than a few minutes." |
  | `:dcr_enabled?` | `false` | Enable dynamic client registration (RFC 7591) at `POST /oauth/register`. Off by default — the safer posture for first-party-only apps. Turn on if you're hosting clients that self-register (MCP, ChatGPT Apps SDK, Claude.ai connectors). When off, the route 404s and the metadata document omits `registration_endpoint`. |
  | `:dcr_always_return_client_secret?` | `false` | Workaround for clients that misbehave when `client_secret` is absent for `auth_method: none`. The registration response then carries an empty `client_secret`. The token endpoint accepts that empty value in the request body, but answers `invalid_client` to any other client credentials, including an `Authorization: Basic` header (OAuth 2.1 §3.2.2). See https://community.openai.com/t/1366118 |
  | `:cimd_enabled?` | `false` | Accept HTTPS URLs as `client_id`s per the OAuth Client ID Metadata Documents draft — the registration mechanism the MCP spec (2026-07-28) recommends over DCR. Requires CIMD support on your client resource and (for the default fetcher) the optional `req` dependency. See `AshAuthentication.Oauth2Server.CIMD`. When on, the metadata document advertises `client_id_metadata_document_supported: true`. |
  | `:cimd_fetcher` | `AshAuthentication.Oauth2Server.CIMD.ReqFetcher` | Module implementing `AshAuthentication.Oauth2Server.CIMD.Fetcher` used to retrieve client metadata documents. Swap for a custom outbound policy or a test stub. |
  | `:cimd_fetch_options` | `[]` | Keyword options passed to the fetcher's `fetch/2` — see `AshAuthentication.Oauth2Server.CIMD.ReqFetcher` for the default fetcher's options. |
  | `:sign_in_path` | `nil` | Path to redirect unauthenticated `/oauth/authorize` requests to. When `nil`, returns 401. |
  | `:initial_access_token` | `nil` | When set, `POST /oauth/register` requires the request to present a matching `Authorization: Bearer …` token (RFC 7591 §3). When `nil` (default), dynamic client registration is open — see the trust-model note below. |
  | `:verify_client_secret` | `{AshAuthentication.Oauth2Server.ClientSecret, :verify, []}` | MFA `{Mod, :fun, args}` or 2-arity fun `(client, secret) -> boolean` used by the `client_credentials` grant to check a confidential client's secret. The default verifies a SHA-256 digest on `client_secret_hash` — see `AshAuthentication.Oauth2Server.ClientSecret`. Override for KMS / etc., or set to `nil` to disable `client_credentials` (metadata omits the grant). |
  | `:extra_access_token_claims` | `nil` | Optional MFA `{Mod, :fun, args}` or 3-arity fun `(client_or_nil, claims, opts) -> map` merged into minted access-token claims (string keys). Use for app tenancy claims on machine tokens. |

  ## Protected resources

  A protected resource is an API that accepts the access tokens this server
  issues. Its identifier is a URL (RFC 8707 §2, RFC 9728 §1.2), and every
  access token names exactly one resource in its `aud` claim.

  For a single resource, set `:resource_url`. To protect more than one
  resource, set `:resources` instead, with one entry for each resource:

  ```elixir
  scopes: ["mcp", "gql"],
  resources: [
    mcp: [url: {MyApp.Secrets, []}, scopes: ["mcp"]],
    gql: [url: {MyApp.Secrets, []}, scopes: ["gql"]]
  ]
  ```

    * `:url` (required) — the resource identifier, for example
      `https://app.example.com/mcp`. It accepts the same values as the other
      secrets below. The secret path is `[:resources, name]`.
    * `:scopes` — the scopes that this resource accepts. It accepts the same
      values as the server's `:scopes`. Required when you configure more
      than one resource. With a single resource it defaults to all of the
      server's scopes.

  With more than one resource, each scope must belong to exactly one
  resource, and the server's `:scopes` must list all of them. A scope then
  always identifies its resource (RFC 9068 §5). This matters for consent,
  which is stored per client and scope: consent to a scope cannot cover a
  resource that the user did not see on the consent screen. Static scope
  lists are checked at compile time. Scope lists that functions compute are
  checked when an authorization request uses them.

  Each grant is bound to one resource. A client selects it with the
  `resource` parameter (RFC 8707). If a client does not send `resource`, the
  server selects the resource that the requested scopes belong to (RFC 9068
  §3). If the scopes belong to more than one resource, the request fails
  with `invalid_target`.

  A refresh stays bound to the resource of the original grant. A `resource`
  parameter that names another resource fails with `invalid_target`.

  On the resource side, give the resource name to
  `AshAuthentication.Phoenix.Oauth2Server.BearerPlug` and
  `AshAuthentication.Phoenix.Oauth2Server.RequireScopePlug`. Each plug then
  accepts only tokens for its resource. With more than one resource the
  option is required, and the plugs raise at init without it:

  ```elixir
  pipeline :mcp do
    plug AshAuthentication.Phoenix.Oauth2Server.BearerPlug,
      oauth2_server: MyApp.Oauth2Server,
      resource: :mcp
  end

  pipeline :gql do
    plug AshAuthentication.Phoenix.Oauth2Server.BearerPlug,
      oauth2_server: MyApp.Oauth2Server,
      resource: :gql
  end
  ```

  The protocol router serves the RFC 9728 metadata of each resource at
  `/.well-known/oauth-protected-resource` followed by the path of the
  resource identifier, for example `/.well-known/oauth-protected-resource/mcp`.

  ## Dynamic client registration

  RFC 7591's `POST /oauth/register` endpoint is **off by default** —
  the safer posture for first-party-only apps, where you have a fixed
  set of clients and don't want a registration surface.

  Turn it on (`dcr_enabled?: true`) when you're hosting an OAuth server
  for clients that self-register: MCP servers (ChatGPT Apps SDK,
  Claude.ai connectors, Claude Code, etc.) literally cannot work
  without it — they fetch your discovery document, see the
  `registration_endpoint`, and POST themselves into existence before
  the user-facing flow can start. User-facing protection in that mode
  lives further down in the consent screen and audience-bound tokens.

  Even with DCR on, you can gate *who* can register by setting
  `:initial_access_token` (RFC 7591 §3) and requiring the matching
  `Authorization: Bearer …` header — useful when DCR exists for known
  infrastructure rather than arbitrary internet clients.

  ## Rate limiting

  The protocol endpoints — `/oauth/register`, `/oauth/token`,
  `/oauth/revoke` — are unauthenticated by design (clients haven't
  finished authenticating yet) and so are reasonable DoS targets. RFC
  7591 §5 explicitly notes that `/register` "MAY be rate-limited or
  otherwise limited to prevent a denial-of-service attack on the
  client registration endpoint."

  We recommend implementing this at the router level rather than in
  the library — the right tool depends on your deployment (in-process
  per-node, Redis-backed across nodes, CDN/edge), and any plug you
  already use for the rest of your app will work here too. Some
  options:

    * [`Hammer`](https://hex.pm/packages/hammer) — flexible counter
      backends (ETS, Redis, Mnesia).
    * [`PlugAttack`](https://hex.pm/packages/plug_attack) — composable
      throttling/blocking rules as a plug pipeline.
    * Edge/CDN-level limits (Cloudflare, Fastly, fly.io) — cheapest
      and stops bad traffic before it reaches your app.

  If your app sits behind a reverse proxy or CDN, `conn.remote_ip`
  defaults to the proxy's IP. Set up
  [`remote_ip`](https://hexdocs.pm/remote_ip) (or your own
  `X-Forwarded-For` plug) so Phoenix sees the real client before any
  IP-based limiter runs. For deployments where DCR doesn't need to be
  open, you can turn the registration endpoint off entirely with
  `dcr_enabled?: false` (the library default), or gate it behind a
  shared secret with `:initial_access_token`.

  ## Secret values

  `:issuer_url`, `:resource_url`, the `:url` of each entry in `:resources`,
  `:signing_secret`, and `:initial_access_token` accept any of:

    * a literal string — resolved at compile time
    * a `{Module, opts}` tuple where `Module` implements
      `AshAuthentication.Secret` — resolved at call time
    * a 2-arity anonymous function — resolved at call time
    * an MFA tuple `{Module, :function, [extra_args]}` — resolved at call time

  See `AshAuthentication.Secret` for details.

  ## Reading the config

  Each option is exposed as a function on the module:

      iex> MyApp.Oauth2Server.user_resource()
      MyApp.Accounts.User
      iex> MyApp.Oauth2Server.issuer_url()
      "https://app.example.com"
      iex> MyApp.Oauth2Server.access_token_lifetime()
      3600
  """

  alias AshAuthentication.Oauth2Server

  @required_keys [
    :otp_app,
    :user_resource,
    :issuer_url,
    :signing_secret,
    :client_resource,
    :authorization_code_resource,
    :refresh_token_resource,
    :consent_resource
  ]

  @doc false
  def __default_opts__ do
    [
      scopes: [],
      enforce_scopes?: true,
      access_token_lifetime: {1, :hour},
      refresh_token_lifetime: {30, :days},
      authorization_code_lifetime: {10, :minutes},
      clock_skew_seconds: 30,
      dcr_enabled?: false,
      dcr_always_return_client_secret?: false,
      cimd_enabled?: false,
      cimd_fetcher: AshAuthentication.Oauth2Server.CIMD.ReqFetcher,
      cimd_fetch_options: [],
      sign_in_path: nil,
      initial_access_token: nil,
      verify_client_secret: {AshAuthentication.Oauth2Server.ClientSecret, :verify, []},
      extra_access_token_claims: nil
    ]
  end

  @doc false
  defmacro __using__(opts) do
    quote bind_quoted: [opts: opts] do
      Oauth2Server.__validate_opts__!(__MODULE__, opts)

      # Fail closed at compile time if CIMD is enabled without the client-resource
      # garbage-collection extension — see __verify_cimd_support__!/1. Deferred to
      # @after_verify so the client resource is fully compiled before we introspect it.
      @after_verify {Oauth2Server, :__verify_cimd_support__!}

      @oauth2_server_opts Keyword.merge(Oauth2Server.__default_opts__(), opts)

      def otp_app, do: Keyword.fetch!(@oauth2_server_opts, :otp_app)
      def user_resource, do: Keyword.fetch!(@oauth2_server_opts, :user_resource)
      def client_resource, do: Keyword.fetch!(@oauth2_server_opts, :client_resource)

      def authorization_code_resource,
        do: Keyword.fetch!(@oauth2_server_opts, :authorization_code_resource)

      def refresh_token_resource,
        do: Keyword.fetch!(@oauth2_server_opts, :refresh_token_resource)

      def consent_resource, do: Keyword.fetch!(@oauth2_server_opts, :consent_resource)

      def scopes do
        @oauth2_server_opts
        |> Keyword.fetch!(:scopes)
        |> Oauth2Server.__resolve_scopes__!(__MODULE__)
      end

      def enforce_scopes?, do: Keyword.fetch!(@oauth2_server_opts, :enforce_scopes?)
      def clock_skew_seconds, do: Keyword.fetch!(@oauth2_server_opts, :clock_skew_seconds)
      def sign_in_path, do: Keyword.fetch!(@oauth2_server_opts, :sign_in_path)

      def dcr_enabled?, do: Keyword.fetch!(@oauth2_server_opts, :dcr_enabled?)

      def dcr_always_return_client_secret?,
        do: Keyword.fetch!(@oauth2_server_opts, :dcr_always_return_client_secret?)

      def cimd_enabled?, do: Keyword.fetch!(@oauth2_server_opts, :cimd_enabled?)
      def cimd_fetcher, do: Keyword.fetch!(@oauth2_server_opts, :cimd_fetcher)
      def cimd_fetch_options, do: Keyword.fetch!(@oauth2_server_opts, :cimd_fetch_options)

      def access_token_lifetime,
        do: Oauth2Server.__lifetime_seconds__(@oauth2_server_opts[:access_token_lifetime])

      def refresh_token_lifetime,
        do: Oauth2Server.__lifetime_seconds__(@oauth2_server_opts[:refresh_token_lifetime])

      def authorization_code_lifetime,
        do: Oauth2Server.__lifetime_seconds__(@oauth2_server_opts[:authorization_code_lifetime])

      def issuer_url(context \\ %{}) do
        @oauth2_server_opts
        |> Keyword.fetch!(:issuer_url)
        |> Oauth2Server.__resolve_secret__!(__MODULE__, [:issuer_url], context)
        |> Oauth2Server.__normalize_url__()
      end

      @doc """
      The names of the configured protected resources. A server configured
      with `:resource_url` has one resource, named `:default`.
      """
      def resources do
        @oauth2_server_opts
        |> Oauth2Server.__resources__()
        |> Enum.map(&elem(&1, 0))
      end

      @doc """
      The identifier of a protected resource.

      Takes a resource name, a secret context, or both. A `nil` name selects
      the only configured resource, and raises if there is more than one.
      """
      def resource_url(name_or_context \\ %{})
      def resource_url(context) when is_map(context), do: resource_url(nil, context)
      def resource_url(name) when is_atom(name), do: resource_url(name, %{})

      def resource_url(name, context) do
        {_name, spec, path, _scopes} =
          Oauth2Server.__fetch_resource__!(__MODULE__, @oauth2_server_opts, name)

        spec
        |> Oauth2Server.__resolve_secret__!(__MODULE__, path, context)
        |> Oauth2Server.__normalize_url__()
      end

      @doc """
      The scopes that a protected resource accepts. A `nil` name selects the
      only configured resource.
      """
      def resource_scopes(name \\ nil) do
        case Oauth2Server.__fetch_resource__!(__MODULE__, @oauth2_server_opts, name) do
          {_name, _spec, _path, nil} -> scopes()
          {_name, _spec, _path, spec} -> Oauth2Server.__resolve_scopes__!(spec, __MODULE__)
        end
      end

      def signing_secret(context \\ %{}) do
        @oauth2_server_opts
        |> Keyword.fetch!(:signing_secret)
        |> Oauth2Server.__resolve_secret__!(__MODULE__, [:signing_secret], context)
      end

      @doc """
      The configured initial access token, or `nil` if dynamic client
      registration is open.

      When non-nil, `POST /oauth/register` requires the request to present
      the matching token in `Authorization: Bearer …`. See RFC 7591 §3.
      """
      def initial_access_token do
        case @oauth2_server_opts[:initial_access_token] do
          nil ->
            nil

          spec ->
            Oauth2Server.__resolve_secret__!(spec, __MODULE__, [:initial_access_token])
        end
      end

      @doc """
      Verify a confidential client's presented secret.

      Returns `true` / `false`, or `{:error, :verify_client_secret_not_configured}`
      when `:verify_client_secret` was explicitly set to `nil` (grant disabled).
      The library default is `AshAuthentication.Oauth2Server.ClientSecret.verify/2`.
      """
      def verify_client_secret(client, secret)
          when is_binary(secret) do
        case @oauth2_server_opts[:verify_client_secret] do
          nil ->
            {:error, :verify_client_secret_not_configured}

          fun when is_function(fun, 2) ->
            fun.(client, secret) == true

          {mod, fun, args} when is_atom(mod) and is_atom(fun) and is_list(args) ->
            apply(mod, fun, [client, secret | args]) == true

          other ->
            raise ArgumentError,
                  "invalid :verify_client_secret on #{inspect(__MODULE__)}: #{inspect(other)}"
        end
      end

      @doc """
      Whether the `client_credentials` grant is usable on this server.

      True when `:verify_client_secret` is set (the library default uses
      `AshAuthentication.Oauth2Server.ClientSecret`). Discovery metadata only
      advertises the grant when this returns true. Pass
      `verify_client_secret: nil` to disable.
      """
      def client_credentials_enabled? do
        @oauth2_server_opts[:verify_client_secret] != nil
      end

      @doc """
      Optional extra JWT claims for an access token.

      `principal` is the user id (person grants) or the client record
      (`client_credentials`). Returns a map of string keys to merge into
      the token claims. Reserved protocol claims (`iss`, `sub`, `aud`,
      `client_id`, `scope`, `iat`, `nbf`, `exp`, `jti`, `tenant`) are
      ignored if returned — only app-specific keys are kept.
      """
      def extra_access_token_claims(principal, claims, opts \\ []) do
        case @oauth2_server_opts[:extra_access_token_claims] do
          nil ->
            %{}

          fun when is_function(fun, 3) ->
            fun.(principal, claims, opts) || %{}

          {mod, fun, args} when is_atom(mod) and is_atom(fun) and is_list(args) ->
            apply(mod, fun, [principal, claims, opts | args]) || %{}

          other ->
            raise ArgumentError,
                  "invalid :extra_access_token_claims on #{inspect(__MODULE__)}: #{inspect(other)}"
        end
      end

      def __oauth2_server__, do: true
    end
  end

  @doc false
  def __validate_opts__!(module, opts) do
    missing = @required_keys -- Keyword.keys(opts)

    if missing != [] do
      raise CompileError,
        description:
          "#{inspect(module)} is missing required `use AshAuthentication.Oauth2Server` options: " <>
            inspect(missing)
    end

    validate_resources!(module, opts)

    case Keyword.fetch!(opts, :otp_app) do
      atom when is_atom(atom) ->
        :ok

      other ->
        raise CompileError,
          description: "expected `:otp_app` to be an atom, got: #{inspect(other)}"
    end

    Enum.each(
      [
        :user_resource,
        :client_resource,
        :authorization_code_resource,
        :refresh_token_resource,
        :consent_resource
      ],
      fn key ->
        case Keyword.fetch!(opts, key) do
          atom when is_atom(atom) and not is_nil(atom) ->
            :ok

          other ->
            raise CompileError,
              description: "expected `#{inspect(key)}` to be a module, got: #{inspect(other)}"
        end
      end
    )

    :ok
  end

  defp validate_resources!(module, opts) do
    case {Keyword.has_key?(opts, :resource_url), Keyword.fetch(opts, :resources)} do
      {true, :error} ->
        :ok

      {false, {:ok, [_ | _] = resources}} ->
        Enum.each(resources, &validate_resource!(module, &1))

        if length(Enum.uniq_by(resources, &elem(&1, 0))) != length(resources) do
          raise CompileError,
            description:
              "#{inspect(module)} configures a resource name in `:resources` more than once"
        end

        validate_resource_scopes!(module, resources, Keyword.get(opts, :scopes, []))

      {true, {:ok, _}} ->
        raise CompileError,
          description:
            "#{inspect(module)} sets both `:resource_url` and `:resources`. Set only one of them."

      _ ->
        raise CompileError,
          description:
            "#{inspect(module)} must set `:resource_url` or a non-empty `:resources` keyword list"
    end
  end

  defp validate_resource!(module, {name, config}) when is_atom(name) and is_list(config) do
    unless Keyword.has_key?(config, :url) do
      raise CompileError,
        description: "#{inspect(module)}: resource #{inspect(name)} in `:resources` has no `:url`"
    end
  end

  defp validate_resource!(module, other) do
    raise CompileError,
      description:
        "#{inspect(module)}: expected each entry in `:resources` to be `name: [url: ...]`, " <>
          "got: #{inspect(other)}"
  end

  # With more than one resource, every scope must belong to exactly one of
  # them (RFC 9068 §5). Consent is stored per client and scope, so a shared
  # scope would let consent for one resource cover another. Scope lists
  # given as functions are checked when they are resolved.
  defp validate_resource_scopes!(_module, [_single], _server_scopes), do: :ok

  defp validate_resource_scopes!(module, resources, server_scopes) do
    Enum.each(resources, fn {name, config} ->
      unless Keyword.has_key?(config, :scopes) do
        raise CompileError,
          description:
            "#{inspect(module)}: resource #{inspect(name)} has no `:scopes`. " <>
              "Each of several resources must declare its own scopes."
      end
    end)

    lists = Enum.map(resources, fn {name, config} -> {name, config[:scopes]} end)

    if Enum.all?(lists, fn {_name, scopes} -> is_list(scopes) end) do
      __check_disjoint_scopes__!(module, lists, CompileError)

      if is_list(server_scopes) do
        case Enum.flat_map(lists, &elem(&1, 1)) -- server_scopes do
          [] ->
            :ok

          [scope | _] ->
            raise CompileError,
              description:
                "#{inspect(module)}: resource scope #{inspect(scope)} is not in `:scopes`"
        end
      end
    end

    :ok
  end

  @doc false
  def __check_disjoint_scopes__!(module, lists, exception \\ ArgumentError) do
    lists
    |> Enum.flat_map(fn {name, scopes} -> Enum.map(scopes, &{&1, name}) end)
    |> Enum.group_by(&elem(&1, 0), &elem(&1, 1))
    |> Enum.find(fn {_scope, names} -> length(names) > 1 end)
    |> case do
      nil ->
        :ok

      {scope, names} ->
        message =
          "#{inspect(module)}: scope #{inspect(scope)} belongs to more than one resource " <>
            "(#{Enum.map_join(names, ", ", &inspect/1)}). Each scope must belong to one resource."

        if exception == CompileError,
          do: raise(CompileError, description: message),
          else: raise(ArgumentError, message)
    end
  end

  @doc false
  # Each resource as `{name, url_spec, secret_path, scopes_spec}`. A server
  # configured with `:resource_url` keeps `[:resource_url]` as the secret path,
  # so existing `AshAuthentication.Secret` implementations keep working.
  def __resources__(opts) do
    case Keyword.fetch(opts, :resources) do
      {:ok, resources} ->
        Enum.map(resources, fn {name, config} ->
          {name, Keyword.fetch!(config, :url), [:resources, name], config[:scopes]}
        end)

      :error ->
        [{:default, Keyword.fetch!(opts, :resource_url), [:resource_url], nil}]
    end
  end

  @doc false
  def __fetch_resource__!(module, opts, nil) do
    case __resources__(opts) do
      [resource] ->
        resource

      resources ->
        raise ArgumentError,
              "#{inspect(module)} configures more than one resource. " <>
                "Give the name of a resource: #{inspect(Enum.map(resources, &elem(&1, 0)))}"
    end
  end

  def __fetch_resource__!(module, opts, name) do
    resources = __resources__(opts)

    List.keyfind(resources, name, 0) ||
      raise ArgumentError,
            "#{inspect(module)} has no resource named #{inspect(name)}. " <>
              "Configured resources: #{inspect(Enum.map(resources, &elem(&1, 0)))}"
  end

  @doc false
  # Plug option check: a plug on a server with several resources must name
  # one, and the name must be configured. Raises at plug init, which Phoenix
  # runs when the router compiles.
  def __check_resource_option__!(server, resource) do
    case {server.resources(), resource} do
      {[_single], nil} ->
        :ok

      {resources, nil} ->
        raise ArgumentError,
              "#{inspect(server)} configures more than one resource. " <>
                "Set the `:resource` option to one of #{inspect(resources)}."

      {resources, name} ->
        if name in resources,
          do: :ok,
          else:
            raise(
              ArgumentError,
              "#{inspect(server)} has no resource named #{inspect(name)}. " <>
                "Configured resources: #{inspect(resources)}"
            )
    end
  end

  @doc false
  # Find the configured resource whose identifier equals `url` after URL
  # normalization. Returns `{:ok, name, canonical_url}` or `:error`.
  def __find_resource__(server, url, context \\ %{})

  def __find_resource__(server, url, context) when is_binary(url) do
    normalized = __normalize_url__(url)

    Enum.find_value(server.resources(), :error, fn name ->
      if server.resource_url(name, context) == normalized, do: {:ok, name, normalized}
    end)
  end

  def __find_resource__(_server, _url, _context), do: :error

  @doc false
  # Runs via @after_verify on every `use AshAuthentication.Oauth2Server` module.
  # When CIMD is enabled the client resource MUST carry the ClientResource
  # extension; otherwise a row accumulates for every distinct URL client_id ever
  # resolved at /authorize with nothing to prune it (unbounded-growth DoS). We
  # fail the build rather than silently leak.
  def __verify_cimd_support__!(module) do
    if module.cimd_enabled?() do
      client_resource = module.client_resource()
      Code.ensure_compiled!(client_resource)

      unless Oauth2Server.ClientResource in Spark.extensions(client_resource) do
        raise CompileError,
          description: """
          #{inspect(module)} has `cimd_enabled?: true`, but its client resource \
          (#{inspect(client_resource)}) is missing the \
          `AshAuthentication.Oauth2Server.ClientResource` extension.

          Without it, a client row is stored for every distinct URL `client_id` \
          ever resolved at `/authorize`, and nothing prunes them — an \
          unbounded-growth denial-of-service vector. Add the extension to your \
          client resource (no migration is required):

              use Ash.Resource,
                extensions: [AshAuthentication.Oauth2Server.ClientResource],
                ...

          See `AshAuthentication.Oauth2Server.ClientResource`.
          """
      end
    end

    :ok
  end

  @doc false
  @lifetime_units %{
    second: 1,
    seconds: 1,
    minute: 60,
    minutes: 60,
    hour: 3_600,
    hours: 3_600,
    day: 86_400,
    days: 86_400
  }
  def __lifetime_seconds__(seconds) when is_integer(seconds) and seconds > 0, do: seconds

  def __lifetime_seconds__({n, unit}) when is_integer(n) and n > 0 do
    multiplier = Map.fetch!(@lifetime_units, unit)
    n * multiplier
  end

  def __lifetime_seconds__(other),
    do: raise(ArgumentError, "invalid lifetime: #{inspect(other)}")

  @doc false
  def __resolve_secret__!(value, module, path, context \\ %{}) do
    case resolve_secret(value, module, path, context) do
      {:ok, resolved} ->
        resolved

      :error ->
        raise "Oauth2Server: failed to resolve secret at #{inspect(path)} on #{inspect(module)}"

      {:error, reason} ->
        raise "Oauth2Server: failed to resolve secret at #{inspect(path)}: #{inspect(reason)}"
    end
  end

  defp resolve_secret(value, _module, _path, _context) when is_binary(value), do: {:ok, value}

  defp resolve_secret({mod, opts}, module, path, context)
       when is_atom(mod) and is_list(opts) do
    Code.ensure_loaded(mod)

    if function_exported?(mod, :__secret_for_arity__, 0) do
      AshAuthentication.Secret.secret_for(mod, path, module, opts, context)
    else
      {:error, {:not_a_secret_module, mod}}
    end
  end

  defp resolve_secret({mod, fun, args}, module, path, _context)
       when is_atom(mod) and is_atom(fun) and is_list(args) do
    mod |> apply(fun, [path, module | args]) |> normalize_resolved_secret()
  end

  defp resolve_secret(fun, module, path, _context) when is_function(fun, 2) do
    fun.(path, module) |> normalize_resolved_secret()
  end

  defp resolve_secret(other, _module, _path, _context),
    do: {:error, {:invalid_secret, other}}

  # A resolved secret must be a non-empty binary. Treat nil, false, "",
  # {:error, _}, {:ok, nil} and any non-binary as a resolution failure so that
  # __resolve_secret__!/4 raises rather than silently accepting it: a
  # configured-but-failing :initial_access_token provider must not drop the DCR
  # bearer-token gate, and signing_secret must never resolve to an empty key.
  defp normalize_resolved_secret({:ok, value}) when is_binary(value) and value != "",
    do: {:ok, value}

  defp normalize_resolved_secret(value) when is_binary(value) and value != "", do: {:ok, value}
  defp normalize_resolved_secret(_), do: :error

  @doc false
  # Resolve the `:scopes` option, which may be a static list, a 0-arity
  # function, or an MFA tuple. Returns the list of scope strings.
  def __resolve_scopes__!(list, _module) when is_list(list), do: list

  def __resolve_scopes__!(fun, _module) when is_function(fun, 0),
    do: ensure_scopes_list!(fun.(), fun)

  def __resolve_scopes__!({mod, fun, args} = mfa, _module)
      when is_atom(mod) and is_atom(fun) and is_list(args),
      do: ensure_scopes_list!(apply(mod, fun, args), mfa)

  def __resolve_scopes__!(other, module) do
    raise """
    Invalid `:scopes` value on #{inspect(module)}: #{inspect(other)}.

    Expected one of:

      * a list of scope strings — `["read", "write"]`
      * a 0-arity function — `fn -> ["read", "write"] end`
      * an MFA tuple — `{Module, :function, [args]}`
    """
  end

  defp ensure_scopes_list!(list, _source) when is_list(list), do: list

  defp ensure_scopes_list!(other, source),
    do: raise("#{inspect(source)} returned #{inspect(other)}, expected a list of scopes")

  @doc """
  Canonicalize a URL for redirect_uri / resource / issuer comparison.

  Per RFC 8252 §7.3 and RFC 3986 §6 — lowercase scheme + host, elide
  default ports (80 for http, 443 for https), strip trailing slash off
  an empty path, drop the fragment. Two URLs that compare equal after
  this canonicalization are considered equivalent.
  """
  def __normalize_url__(url) when is_binary(url) do
    uri = URI.parse(url)
    scheme = uri.scheme && String.downcase(uri.scheme)

    %{
      uri
      | scheme: scheme,
        host: uri.host && String.downcase(uri.host),
        port: normalize_port(scheme, uri.port),
        path: normalize_path(uri.path),
        fragment: nil
    }
    |> URI.to_string()
    |> String.trim_trailing("/")
  end

  defp normalize_path(nil), do: nil
  defp normalize_path("/"), do: nil
  defp normalize_path(path), do: path

  defp normalize_port("http", 80), do: nil
  defp normalize_port("https", 443), do: nil
  defp normalize_port(_, port), do: port
end
