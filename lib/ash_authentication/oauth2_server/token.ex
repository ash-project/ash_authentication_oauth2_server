# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.Token do
  @moduledoc """
  Protocol-pure logic for the `/oauth/token` endpoint.

  Supports three grant types:

    * `authorization_code` — with PKCE verification, redirect/resource
      binding checks, and one-shot consumption of the code.
    * `refresh_token` — with rotation and reuse detection per OAuth 2.1
      §4.3.1. A second use of an already-rotated refresh token revokes the
      entire descendant chain.
    * `client_credentials` — machine-to-machine; confidential client
      authenticates with a secret; access token only (no refresh token).

  All functions return tagged tuples; controllers translate them to HTTP.

  ## Authorization & tenancy

  All Ash calls run through the `AshAuthentication.Checks.AshAuthenticationInteraction`
  bypass (set by the installer) rather than `authorize?: false`. Every public
  function accepts an `opts` keyword that may include `:tenant`; when set, it's
  threaded to every action and baked into the minted token as a `"tenant"`
  claim so the resource server can restore it on subsequent requests.
  """

  require Ash.Query
  require Logger

  alias AshAuthentication.Oauth2Server.{CIMD, ClientMetadata, Jwt, PKCE}

  @ash_context %{private: %{ash_authentication?: true}}

  @typedoc "Result of a successful grant — the bundle returned to the client."
  @type token_response :: %{
          :access_token => String.t(),
          :token_type => String.t(),
          :expires_in => pos_integer(),
          :scope => String.t(),
          optional(:refresh_token) => String.t() | nil
        }

  @typedoc """
  Options shared across this module's public functions.

    * `:tenant` — the Ash tenant.
    * `:authorization_scheme` — the scheme of the request's `Authorization`
      header, downcased (for example `"basic"`), or `nil` without one. The
      server supports public clients only, so any client credentials make
      the request fail (OAuth 2.1 §3.2.2).
  """
  @type opts :: [tenant: any(), authorization_scheme: String.t() | nil]

  # ── client_credentials grant ───────────────────────────────────────────────

  @doc """
  Issue an access token for a confidential client (no user, no refresh token).

  `params` must include credentials either as body fields or already merged
  from HTTP Basic (`client_id` + `client_secret`). Prefer calling via the
  protocol router, which uses `ClientAuth.credentials/2`.

  Requires the server to configure `:verify_client_secret`. The client row
  must list `client_credentials` in `grant_types` and must not use
  `token_endpoint_auth_method: "none"`. Ineligible clients and bad secrets
  both return `{:error, :invalid_client}` so callers cannot distinguish
  grant eligibility from secret failure.

  `token_endpoint_auth_method` of `client_secret_basic` or
  `client_secret_post` both mean “confidential client with a secret”.
  Either HTTP Basic **or** body credentials are accepted for those rows.
  Dual Basic+body in one request remains `invalid_request` via
  `ClientAuth`. The registered method is kept for metadata/interop but
  is not bound to presentation on the wire.
  """
  @spec exchange_client_credentials(server :: module(), params :: map(), opts()) ::
          {:ok, token_response()} | {:error, atom()}
  def exchange_client_credentials(server, params, opts \\ [])

  def exchange_client_credentials(server, params, opts) when is_map(params) do
    tenant = Keyword.get(opts, :tenant)
    secret_context = secret_context(tenant)

    with {:ok, client_id, client_secret} <- client_credentials_from_params(params),
         {:ok, client} <- get_client(server, client_id, client_secret, opts),
         :ok <- ensure_client_credentials_allowed(client, client_secret),
         :ok <- verify_secret(server, client, client_secret),
         {:ok, resource, audience} <- resolve_resource(server, params, secret_context),
         {:ok, scope} <- resolve_client_credentials_scope(server, resource, client, params),
         extra <- server.extra_access_token_claims(client, %{"scope" => scope}, opts),
         {:ok, access_token, _claims} <-
           Jwt.mint(server,
             # Both from the stored row, never the presented value: the
             # data layer may accept a non-canonical spelling of the id
             # (e.g. an upper-case UUID) that would otherwise leak into
             # the token and make `sub` and `client_id` disagree.
             sub: client.id,
             client_id: client.id,
             scope: scope,
             audience: audience,
             tenant: tenant,
             grant_type: "client_credentials",
             extra_claims: extra
           ) do
      touch_client(client, opts)

      {:ok,
       %{
         access_token: access_token,
         token_type: "Bearer",
         expires_in: server.access_token_lifetime(),
         scope: scope
       }}
    end
  end

  @doc """
  Whether a client row is currently allowed to use `client_credentials`.

  Used at token issue and again by `ClientBearerPlug` so removing the grant
  (or switching the client to a public auth method) invalidates machine
  access without waiting for JWT expiry.
  """
  @spec client_credentials_allowed?(Ash.Resource.record()) :: boolean()
  def client_credentials_allowed?(client) do
    ensure_client_credentials_allowed(client, nil) == :ok
  end

  @doc """
  Whether a minted access-token scope string is still allowed for `client`
  against the server's current catalogue and the client's allow-list.

  Used by `ClientBearerPlug` so narrowing a client's scopes (or the
  server catalogue) takes effect before JWT expiry.
  """
  @spec machine_scopes_allowed?(module(), atom() | nil, Ash.Resource.record(), String.t()) ::
          boolean()
  def machine_scopes_allowed?(server, resource, client, scope) when is_binary(scope) do
    token_scopes = scope |> String.split(" ", trim: true) |> MapSet.new()
    client_scopes = client_scope_set(client)

    match?(
      :ok,
      with :ok <- reject_empty_scope(token_scopes),
           :ok <- check_requested_against_catalogue(server, resource, token_scopes),
           :ok <- check_requested_against_client(token_scopes, client_scopes) do
        :ok
      end
    )
  end

  def machine_scopes_allowed?(_, _, _, _), do: false

  defp client_credentials_from_params(%{"client_id" => id, "client_secret" => secret})
       when is_binary(id) and id != "" and is_binary(secret) and secret != "" do
    {:ok, id, secret}
  end

  defp client_credentials_from_params(_), do: {:error, :invalid_request}

  defp get_client(server, client_id, secret, opts) do
    case Ash.get(server.client_resource(), client_id, ash_opts(opts)) do
      {:ok, client} ->
        {:ok, client}

      _ ->
        # RFC 6819 / RFC 9700 — unknown clients should not fail faster than
        # a failed secret check (client-id enumeration via timing).
        burn_client_auth_time(secret)
        {:error, :invalid_client}
    end
  end

  # Collapse grant / public-client failures to `invalid_client` so callers
  # cannot distinguish "unknown client", "wrong secret", and "not allowed
  # this grant".
  defp ensure_client_credentials_allowed(client, secret) do
    grants = ClientMetadata.allowed_grant_types(client)

    cond do
      "client_credentials" not in grants ->
        burn_client_auth_time(secret)
        {:error, :invalid_client}

      public_client?(client) ->
        burn_client_auth_time(secret)
        {:error, :invalid_client}

      true ->
        :ok
    end
  end

  # Approximate a failed constant-time secret compare so early rejects
  # (unknown / ineligible client) are not obviously faster.
  defp burn_client_auth_time(secret) when is_binary(secret) do
    dummy = :crypto.hash(:sha256, "ash-authentication-oauth2-server-dummy")
    presented = :crypto.hash(:sha256, secret)
    _ = Plug.Crypto.secure_compare(dummy, presented)
    :ok
  end

  defp burn_client_auth_time(_), do: burn_client_auth_time("")

  # Presentation (Basic vs body) is intentionally *not* bound to
  # `token_endpoint_auth_method`: any confidential secret method accepts
  # either channel. See `exchange_client_credentials/3` moduledoc.
  # Dual mechanisms in one request are rejected earlier by ClientAuth.

  defp verify_secret(server, client, secret) do
    case server.verify_client_secret(client, secret) do
      true ->
        :ok

      false ->
        {:error, :invalid_client}

      {:error, :verify_client_secret_not_configured} ->
        {:error, :verify_client_secret_not_configured}

      other ->
        raise ArgumentError,
              "verify_client_secret must return a boolean, got: #{inspect(other)}"
    end
  end

  # RFC 8707 — `resource` may appear once or repeatedly; each value MUST be
  # an absolute URI without a fragment and must identify a configured
  # resource. A token is bound to one resource, so every value must name the
  # same one. Without `resource`, a server with a single resource uses it; with
  # several the request is ambiguous. Failures use `invalid_target` (not
  # `invalid_grant`). Returns `{:ok, resource_name, resource_url}`.
  defp resolve_resource(server, params, secret_context) do
    case Map.fetch(params, "resource") do
      :error ->
        case server.resources() do
          [name] -> {:ok, name, server.resource_url(name, secret_context)}
          _ -> {:error, :invalid_target}
        end

      {:ok, value} ->
        value
        |> List.wrap()
        |> Enum.reduce_while({:ok, nil}, fn res, {:ok, found} ->
          with :ok <- validate_resource_uri(res),
               {:ok, name, url} <-
                 AshAuthentication.Oauth2Server.__find_resource__(server, res, secret_context),
               true <- is_nil(found) or found == {name, url} do
            {:cont, {:ok, {name, url}}}
          else
            _ -> {:halt, {:error, :invalid_target}}
          end
        end)
        |> case do
          {:ok, {name, url}} -> {:ok, name, url}
          {:ok, nil} -> {:error, :invalid_target}
          {:error, _} = err -> err
        end
    end
  end

  defp validate_resource_uri(res) when is_binary(res) and res != "" do
    uri = URI.parse(res)

    cond do
      # Absolute URI required (RFC 8707 §2).
      uri.scheme not in ["https", "http"] or is_nil(uri.host) or uri.host == "" ->
        {:error, :invalid_target}

      # Fragment MUST NOT be included.
      not is_nil(uri.fragment) ->
        {:error, :invalid_target}

      true ->
        :ok
    end
  end

  defp validate_resource_uri(_), do: {:error, :invalid_target}

  defp resolve_client_credentials_scope(server, resource, client, params) do
    client_scopes = client_scope_set(client)

    with {:ok, requested} <- requested_scope_set(params, client_scopes),
         :ok <- reject_empty_scope(requested),
         :ok <- validate_scope_tokens(requested),
         :ok <- check_requested_against_catalogue(server, resource, requested),
         :ok <- check_requested_against_client(requested, client_scopes) do
      {:ok, requested |> MapSet.to_list() |> Enum.sort() |> Enum.join(" ")}
    end
  end

  defp requested_scope_set(params, client_scopes) do
    case Map.fetch(params, "scope") do
      :error ->
        {:ok, client_scopes}

      {:ok, scope} when is_binary(scope) and scope != "" ->
        {:ok, scope |> String.split(" ", trim: true) |> MapSet.new()}

      {:ok, scope} when is_binary(scope) ->
        {:ok, client_scopes}

      {:ok, _} ->
        # Repeated / non-string scope (RFC 6749 §5.2 invalid_request —
        # "repeats a parameter" often surfaces as a list in parsers).
        {:error, :invalid_request}
    end
  end

  defp client_scope_set(client) do
    client
    |> Map.get(:scope)
    |> List.wrap()
    |> Enum.flat_map(fn
      s when is_binary(s) -> String.split(s, " ", trim: true)
      _ -> []
    end)
    |> MapSet.new()
  end

  defp reject_empty_scope(requested) do
    if MapSet.size(requested) == 0, do: {:error, :invalid_scope}, else: :ok
  end

  # RFC 6749 §3.3 / OAuth 2.1 §1.4.1 — scope-token charset.
  # scope-token = 1*( %x21 / %x23-5B / %x5D-7E )
  defp validate_scope_tokens(requested) do
    if Enum.all?(requested, &valid_scope_token?/1) do
      :ok
    else
      {:error, :invalid_scope}
    end
  end

  defp valid_scope_token?(token) when is_binary(token) and token != "" do
    token
    |> String.to_charlist()
    |> Enum.all?(fn
      c when c == 0x21 or (c >= 0x23 and c <= 0x5B) or (c >= 0x5D and c <= 0x7E) -> true
      _ -> false
    end)
  end

  defp valid_scope_token?(_), do: false

  defp check_requested_against_catalogue(server, resource, requested) do
    if server.enforce_scopes?() do
      allowed = MapSet.new(server.resource_scopes(resource))

      case MapSet.difference(requested, allowed) |> MapSet.to_list() do
        [] -> :ok
        _ -> {:error, :invalid_scope}
      end
    else
      :ok
    end
  end

  defp check_requested_against_client(requested, client_scopes) do
    # Empty client scope means "no restriction beyond the server catalogue"
    # — same idea as an unset client scope allow-list.
    if MapSet.size(client_scopes) == 0 or MapSet.subset?(requested, client_scopes) do
      :ok
    else
      {:error, :invalid_scope}
    end
  end

  # ── authorization_code grant ───────────────────────────────────────────────

  @doc """
  Exchange an authorization code (with PKCE verifier) for an access + refresh
  token pair. Consumes the code atomically once every check has passed; a
  second call with the same code returns `{:error, :reuse}`.
  """
  @spec exchange_authorization_code(server :: module(), params :: map(), opts()) ::
          {:ok, token_response()}
          | {:error, atom()}
  def exchange_authorization_code(server, params, opts \\ []) do
    tenant = Keyword.get(opts, :tenant)
    secret_context = secret_context(tenant)

    with :ok <- require_params(params, ["client_id", "code", "code_verifier"]),
         {:ok, presented_client_id, client} <- resolve_client_id(server, params, opts),
         :ok <- authenticate_client(server, client, params, opts),
         :ok <- check_grant_type(client, "authorization_code"),
         {:ok, code} <- load_code(server, params, client.id, opts),
         :ok <- verify_pkce(code, params),
         :ok <- check_redirect_match(params, code),
         :ok <- check_resource_match(server, params, code, secret_context),
         {:ok, code} <- consume_code(code, opts),
         extra <-
           server.extra_access_token_claims(code.user_id, %{"scope" => code.scope}, opts),
         {:ok, access_token, _claims} <-
           Jwt.mint(server,
             # The claim carries the identifier the client authenticates
             # as — for CIMD clients that's their URL, not our row id.
             sub: code.user_id,
             client_id: presented_client_id,
             scope: code.scope,
             audience: code.resource_uri,
             tenant: tenant,
             extra_claims: extra
           ),
         {:ok, refresh_token} <- maybe_issue_refresh_token(server, client, code, opts) do
      touch_client(client, opts)

      {:ok,
       %{
         access_token: access_token,
         token_type: "Bearer",
         expires_in: server.access_token_lifetime(),
         refresh_token: refresh_token,
         scope: code.scope
       }}
    end
  end

  defp secret_context(nil), do: %{}
  defp secret_context(tenant), do: %{tenant: tenant}

  # OAuth 2.1 §3.2: a parameter sent without a value counts as omitted. A
  # missing required parameter is `invalid_request` (§3.2.4), checked before
  # the client or the grant is looked up.
  defp require_params(params, keys) do
    if Enum.all?(keys, &present?(params[&1])), do: :ok, else: {:error, :invalid_request}
  end

  defp present?(value), do: is_binary(value) and value != ""

  # A form body like `scope[x]=y`, or a JSON object, decodes to a map. That
  # is a malformed parameter, `invalid_request` (OAuth 2.1 §3.2.4).
  defp check_optional_string(params, key) do
    if is_nil(params[key]) or is_binary(params[key]),
      do: :ok,
      else: {:error, :invalid_request}
  end

  # RFC 6749 §4.1.3 / §6: a confidential client MUST authenticate on every
  # token request. Runs before the code is consumed or the refresh token
  # rotated, so a caller without the secret cannot burn a legitimate
  # client's grant.
  defp authenticate_client(server, client, params, opts) do
    if public_client?(client),
      do: check_no_client_credentials(params, opts),
      else: authenticate_confidential_client(server, client, params["client_secret"])
  end

  # Any method other than `none` (including ones this server doesn't
  # implement, e.g. `private_key_jwt`) requires a verified secret — fail
  # closed rather than treating unknown methods as public.
  defp authenticate_confidential_client(server, client, secret)
       when is_binary(secret) and secret != "" do
    case server.verify_client_secret(client, secret) do
      true ->
        :ok

      {:error, :verify_client_secret_not_configured} ->
        Logger.warning(
          "Oauth2Server: confidential client #{inspect(client.id)} cannot authenticate " <>
            "because :verify_client_secret is nil"
        )

        {:error, :invalid_client}

      _ ->
        {:error, :invalid_client}
    end
  end

  defp authenticate_confidential_client(_server, _client, _secret), do: {:error, :invalid_client}

  defp public_client?(client),
    do: Map.get(client, :token_endpoint_auth_method) in [nil, "none"]

  # OAuth 2.1 §3.2.2: the server MUST authenticate a client that includes
  # client authentication. A public client
  # (`token_endpoint_auth_method: "none"`) has nothing to check
  # the credentials against, and any credentials are `invalid_client`. More
  # than one mechanism is `invalid_request` (§3.2.4). An empty
  # `client_secret` counts as omitted (§3.2), which keeps the
  # `dcr_always_return_client_secret?` workaround working.
  defp check_no_client_credentials(params, opts) do
    mechanisms =
      Enum.count(
        [
          Keyword.get(opts, :authorization_scheme) == "basic",
          present?(params["client_secret"]),
          present?(params["client_assertion"])
        ],
        & &1
      )

    case mechanisms do
      0 -> :ok
      1 -> {:error, :unsupported_client_authentication}
      _ -> {:error, :invalid_request}
    end
  end

  # Map the presented `client_id` param to the id stored on codes /
  # refresh rows. Ordinary client_ids pass through unchanged; URL-shaped
  # ones (Client ID Metadata Documents) resolve to the client row that was
  # upserted at authorize time — a database lookup only, never a fetch.
  # An unknown client is `invalid_client` (OAuth 2.1 §3.2.4), checked
  # before the grant. Returns `{:ok, presented, client}`.
  defp resolve_client_id(server, %{"client_id" => "https://" <> _ = url}, opts) do
    with true <- server.cimd_enabled?(),
         {:ok, client} <- CIMD.find_client(server, url, opts) do
      {:ok, url, client}
    else
      _ -> {:error, :invalid_client}
    end
  end

  defp resolve_client_id(server, %{"client_id" => client_id}, opts)
       when is_binary(client_id) and client_id != "" do
    case Ash.get(server.client_resource(), client_id, ash_opts(opts)) do
      {:ok, client} -> {:ok, client_id, client}
      _ -> {:error, :invalid_client}
    end
  end

  defp resolve_client_id(_server, _params, _opts), do: {:error, :invalid_request}

  # OAuth 2.1 §3.2.4: a client may use only the grant types it registered.
  # A client without registered grant types has the RFC 7591 §2 default,
  # `authorization_code` alone.
  defp check_grant_type(client, grant_type) do
    if grant_type in client_grant_types(client), do: :ok, else: {:error, :unauthorized_client}
  end

  defp client_grant_types(%{grant_types: [_ | _] = grant_types}), do: grant_types
  defp client_grant_types(_client), do: ["authorization_code"]

  # A client that cannot use the refresh_token grant gets no refresh token.
  defp maybe_issue_refresh_token(server, client, code, opts) do
    if "refresh_token" in client_grant_types(client),
      do: issue_refresh_token(server, client.id, code, opts),
      else: {:ok, nil}
  end

  # A request that fails any check leaves the code unconsumed, so a client
  # that sent a bad verifier or resource can retry with the same code.
  defp load_code(server, %{"code" => code_id}, client_id, opts) do
    with {:ok, code} <-
           code_or_error(Ash.get(server.authorization_code_resource(), code_id, ash_opts(opts))),
         :ok <- check_client_match(code, client_id),
         :ok <- check_not_consumed(code),
         :ok <- check_not_expired(code) do
      {:ok, code}
    end
  end

  # `:consume` validates `consumed_at` atomically, so a concurrent request
  # that consumed the code first makes this one fail.
  defp consume_code(code, opts) do
    code
    |> Ash.Changeset.for_update(:consume, %{})
    |> Ash.update(ash_opts(opts))
    |> code_or_error()
  end

  defp code_or_error({:ok, _} = ok), do: ok
  defp code_or_error({:error, _}), do: {:error, :invalid_code}

  defp check_client_match(%{client_id: code_client_id}, client_id) do
    if code_client_id == client_id, do: :ok, else: {:error, :client_mismatch}
  end

  defp check_not_consumed(%{consumed_at: nil}), do: :ok
  defp check_not_consumed(_), do: {:error, :reuse}

  defp check_not_expired(%{expires_at: expires_at}) do
    if DateTime.compare(DateTime.utc_now(), expires_at) == :gt,
      do: {:error, :expired},
      else: :ok
  end

  defp verify_pkce(code, %{"code_verifier" => verifier}) when is_binary(verifier) do
    case PKCE.verify(verifier, code.code_challenge) do
      :ok -> :ok
      :error -> {:error, :pkce}
    end
  end

  defp verify_pkce(_, _), do: {:error, :pkce}

  # `resource` is optional per RFC 8707 §2. A code bound to a resource that
  # is no longer configured is a bad grant. A requested value other than the
  # code's resource is `invalid_target`, which RFC 8707 §2 defines for this
  # case.
  defp check_resource_match(server, params, code, secret_context) do
    cond do
      code.resource_uri not in resource_urls(server, secret_context) ->
        {:error, :resource_mismatch}

      not requested_resource_ok?(params["resource"], code.resource_uri) ->
        {:error, :invalid_target}

      true ->
        :ok
    end
  end

  # OAuth 2.1 §4.1.3 drops `redirect_uri` from the token request, because
  # PKCE prevents code injection. §10.2 still requires an OAuth 2.0 client's
  # value to match the one bound to the code, exactly (RFC 9700 §4.1).
  defp check_redirect_match(%{"redirect_uri" => uri}, %{redirect_uri: uri}), do: :ok
  defp check_redirect_match(%{"redirect_uri" => nil}, _), do: :ok
  defp check_redirect_match(%{"redirect_uri" => ""}, _), do: :ok
  defp check_redirect_match(%{"redirect_uri" => _}, _), do: {:error, :redirect_mismatch}
  defp check_redirect_match(_, _), do: :ok

  # ── refresh_token grant ───────────────────────────────────────────────────

  @doc """
  Exchange a refresh token for a new access + refresh pair. Implements
  rotation + reuse detection (OAuth 2.1 §4.3.1): a second use of an
  already-rotated refresh token returns `{:error, :reuse}` and revokes the
  descendant chain.

  The rotation is atomic at the data-layer level — every "is this
  refresh usable" check lives in the `:rotate` action's filter, so
  validate + rotate is one query in the happy path. On a 0-row result
  (race lost, invalid token, expired, etc.) we do a follow-up read to
  distinguish `:reuse` from the other failure modes.
  """
  @spec exchange_refresh_token(server :: module(), params :: map(), opts()) ::
          {:ok, token_response()} | {:error, atom()}
  def exchange_refresh_token(server, params, opts \\ [])

  def exchange_refresh_token(server, params, opts) do
    with :ok <- require_params(params, ["client_id", "refresh_token"]),
         :ok <- check_optional_string(params, "scope"),
         {:ok, presented_client_id, client} <- resolve_client_id(server, params, opts),
         :ok <- authenticate_client(server, client, params, opts),
         :ok <- check_grant_type(client, "refresh_token") do
      raw = params["refresh_token"]
      do_exchange_refresh_token(server, params, raw, presented_client_id, client.id, opts)
    end
  end

  defp do_exchange_refresh_token(server, params, raw, presented_client_id, client_id, opts) do
    hash = hash_refresh(raw)
    resource = Map.get(params, "resource")
    resource_urls = resource_urls(server, secret_context(Keyword.get(opts, :tenant)))

    # Allocate the new refresh row's identifiers upfront so the rotate
    # can atomically set `rotated_to_id = ^new_id` without a separate
    # round-trip.
    {new_raw, new_hash} = generate_refresh()
    new_id = Ash.UUIDv7.generate()

    with {:ok, scope} <-
           requested_scope(server, hash, params, client_id, resource_urls, resource, opts) do
      new_refresh = {new_id, new_hash, new_raw}

      case atomic_rotate(server, hash, client_id, resource, resource_urls, new_id, opts) do
        {:ok, old_row} ->
          complete_rotation(server, old_row, scope, presented_client_id, new_refresh, opts)

        :no_match ->
          case disambiguate_failure(server, hash, client_id, resource_urls, resource, opts) do
            :reuse ->
              revoke_chain_by_hash(server, hash, opts)
              {:error, :reuse}

            other ->
              {:error, other}
          end

        {:bulk_error, errors} ->
          # The bulk update itself failed for a real reason (validation,
          # constraint, DB connectivity, etc.). Log it for ops visibility,
          # don't leak details to the caller, and skip the disambiguation
          # read — we already know the operation didn't complete. The
          # refresh token may still be valid, so this is not `invalid_grant`.
          Logger.error("Oauth2Server: refresh-token bulk_update failed: " <> inspect(errors))

          {:error, :server_error}
      end
    end
  end

  # The bulk update's filter holds every "is this refresh usable" check
  # in one place — client/resource/expiry/rotation/revocation — so the
  # whole "validate + rotate" step is one atomic operation. Returns:
  #
  #   * `{:ok, old_row}` — happy path; old row data is used to issue
  #     the new refresh + mint the access token.
  #   * `:no_match` — the filter matched zero rows. The caller does a
  #     follow-up read to distinguish `:reuse` (chain-revoke) from
  #     other invalid-grant cases.
  #   * `{:bulk_error, errors}` — the bulk update itself failed for a
  #     real reason (validation, constraint, etc.). The caller logs
  #     and returns a server error without disambiguating.
  defp atomic_rotate(server, hash, client_id, resource, resource_urls, new_id, opts) do
    case Enum.filter(resource_urls, &requested_resource_ok?(resource, &1)) do
      [] -> :no_match
      allowed -> do_atomic_rotate(server, hash, client_id, allowed, new_id, opts)
    end
  end

  defp do_atomic_rotate(server, hash, client_id, allowed_resources, new_id, opts) do
    now = DateTime.utc_now()

    bulk_opts =
      [return_records?: true, return_errors?: true]
      |> Keyword.merge(ash_opts(opts))

    server.refresh_token_resource()
    |> Ash.Query.filter(
      token_hash == ^hash and
        client_id == ^client_id and
        resource_uri in ^allowed_resources and
        expires_at > ^now and
        is_nil(rotated_to_id) and
        is_nil(revoked_at)
    )
    |> Ash.bulk_update(:rotate, %{rotated_to_id: new_id}, bulk_opts)
    |> case do
      %Ash.BulkResult{status: :success, records: [old_row | _]} -> {:ok, old_row}
      %Ash.BulkResult{status: :success} -> :no_match
      %Ash.BulkResult{status: :error, errors: errors} -> {:bulk_error, errors}
    end
  end

  # OAuth 2.1 §4.3.1: an omitted scope means the scope of the grant. The
  # access token gets the requested scope, and the new refresh token keeps
  # the scope of the grant (RFC 6749 §6).
  defp complete_rotation(server, old_row, scope, presented_client_id, new_refresh, opts) do
    {new_id, new_hash, new_raw} = new_refresh
    tenant = Keyword.get(opts, :tenant)
    access_scope = scope || old_row.scope

    new_expires_at =
      DateTime.add(DateTime.utc_now(), server.refresh_token_lifetime(), :second)

    with {:ok, _new_row} <-
           server.refresh_token_resource()
           |> Ash.Changeset.for_create(:issue, %{
             id: new_id,
             # Inherit the parent's chain_id so the whole rotation
             # lineage shares one id — enables single-UPDATE chain
             # revocation on reuse detection.
             chain_id: old_row.chain_id,
             generation: old_row.generation + 1,
             token_hash: new_hash,
             client_id: old_row.client_id,
             user_id: old_row.user_id,
             scope: old_row.scope,
             resource_uri: old_row.resource_uri,
             expires_at: new_expires_at
           })
           |> Ash.create(ash_opts(opts)),
         {:ok, access_token, _claims} <-
           Jwt.mint(server,
             sub: old_row.user_id,
             client_id: presented_client_id,
             scope: access_scope,
             audience: old_row.resource_uri,
             tenant: tenant,
             extra_claims:
               server.extra_access_token_claims(old_row.user_id, %{"scope" => access_scope}, opts)
           ) do
      touch_client_by_id(server, old_row.client_id, opts)

      {:ok,
       %{
         access_token: access_token,
         token_type: "Bearer",
         expires_in: server.access_token_lifetime(),
         refresh_token: new_raw,
         scope: access_scope
       }}
    end
  end

  # Re-read by hash on a 0-row update to figure out *why* the filter
  # didn't match. The atom returned drives both the public error and
  # the chain-revoke decision (only `:reuse` triggers revocation).
  # We could do this with errors on the bulk_update's filter instead
  # but not all data layers support that
  defp disambiguate_failure(server, hash, client_id, resource_urls, resource, opts) do
    case find_refresh(server, hash, opts) do
      {:ok, row} -> classify_row(row, client_id, resource_urls, resource) || :invalid_refresh
      {:error, _} -> :invalid_refresh
    end
  end

  # A requested scope beyond the grant is `invalid_scope` (OAuth 2.1
  # §4.3.1). The rotate filter cannot compare scopes, so a request with a
  # scope reads the row first. Only a token that passes every other check
  # gets the scope error. A failing token takes the rotate path, which
  # reports its own error and detects reuse.
  defp requested_scope(server, hash, params, client_id, resource_urls, resource, opts) do
    requested = String.split(params["scope"] || "", " ", trim: true)

    with [_ | _] <- requested,
         {:ok, row} <- find_refresh(server, hash, opts),
         nil <- classify_row(row, client_id, resource_urls, resource) do
      granted = String.split(row.scope, " ", trim: true)

      if Enum.all?(requested, &(&1 in granted)),
        do: {:ok, Enum.join(requested, " ")},
        else: {:error, :invalid_scope}
    else
      _ -> {:ok, nil}
    end
  end

  # The token's own state comes first. A rotated token is a replay no matter
  # which client or resource the request names, so it must reach `:reuse`
  # and revoke the chain (OAuth 2.1 §4.3.1). A dead token is `invalid_grant`
  # even when the requested resource is also wrong.
  defp classify_row(row, client_id, resource_urls, resource) do
    cond do
      row.revoked_at -> :revoked
      row.rotated_to_id -> :reuse
      DateTime.compare(DateTime.utc_now(), row.expires_at) == :gt -> :expired
      row.client_id != client_id -> :client_mismatch
      row.resource_uri not in resource_urls -> :resource_mismatch
      not requested_resource_ok?(resource, row.resource_uri) -> :invalid_target
      true -> nil
    end
  end

  @doc """
  Revoke a token per RFC 7009.

  Only refresh tokens are revocable here: access tokens are stateless JWTs.
  When a refresh token is revoked, the entire descendant chain (rotated-to
  successors) is also revoked, so a refresh that has been rotated through
  cannot resurrect the session.

  The `params` map mirrors what RFC 7009 §2.1 sends to the endpoint:

    * `"token"` (required) — the raw token string the client wishes to revoke.
    * `"client_id"` (required) — the public client identifier.
    * `"token_type_hint"` (optional) — ignored, because the server detects
      the token type itself (RFC 7009 §2.1).

  Returns:

    * `:ok` — the token is revoked, or it is not a valid token (RFC 7009
      §2.2).
    * `{:error, :invalid_request}` — `token` or `client_id` is missing.
    * `{:error, :invalid_client}` — the client is unknown.
    * `{:error, :client_mismatch}` — the refresh token was issued to another
      client. RFC 7009 §2.1 refuses the request.
    * `{:error, :unsupported_token_type}` — the token is a valid access
      token, which this server cannot revoke (RFC 7009 §2.2.1).
    * `{:error, :server_error}` — the revocation did not complete. The
      client must assume that the token is still valid (RFC 7009 §2.2.1).
  """
  @spec revoke(server :: module(), params :: map(), opts()) :: :ok | {:error, atom()}
  def revoke(server, params, opts \\ []) do
    with :ok <- require_params(params, ["client_id", "token"]),
         {:ok, _presented, %{id: client_id} = client} <- resolve_client_id(server, params, opts),
         :ok <- authenticate_client(server, client, params, opts) do
      token = params["token"]

      server.refresh_token_resource()
      |> Ash.Query.filter(token_hash == ^hash_refresh(token))
      |> Ash.read_one(ash_opts(opts))
      |> case do
        {:ok, %{client_id: ^client_id} = row} -> revoke_chain_by_id(server, row.chain_id, opts)
        {:ok, nil} -> revoke_access_token(server, token)
        {:ok, _row} -> {:error, :client_mismatch}
        {:error, _} -> {:error, :server_error}
      end
    end
  end

  defp revoke_access_token(server, token) do
    if match?({:ok, _}, Jwt.verify(server, token, resource: server.resources())),
      do: {:error, :unsupported_token_type},
      else: :ok
  end

  defp find_refresh(server, hash, opts) do
    server.refresh_token_resource()
    |> Ash.Query.filter(token_hash == ^hash)
    |> Ash.read_one(ash_opts(opts))
    |> case do
      {:ok, nil} -> {:error, :invalid_refresh}
      {:ok, row} -> {:ok, row}
      _ -> {:error, :invalid_refresh}
    end
  end

  # `resource` is optional per RFC 8707 §2 — when absent (`nil` or empty
  # string) we don't enforce, otherwise it must canonicalize to the
  # resource the grant is bound to.
  defp requested_resource_ok?(nil, _expected), do: true
  defp requested_resource_ok?("", _expected), do: true

  defp requested_resource_ok?(bin, expected) when is_binary(bin) do
    AshAuthentication.Oauth2Server.__normalize_url__(bin) == expected
  end

  defp requested_resource_ok?(_, _), do: false

  defp resource_urls(server, secret_context),
    do: Enum.map(server.resources(), &server.resource_url(&1, secret_context))

  # On reuse detection, revoke every refresh token in the chain in a
  # single filtered UPDATE. RFC 6749 §4.3.1. Every row in a rotation
  # lineage carries the same `chain_id` (set at initial issuance,
  # inherited on rotation), so one filtered UPDATE clears them all.
  defp revoke_chain_by_hash(server, hash, opts) do
    case find_refresh(server, hash, opts) do
      {:ok, row} ->
        revoke_chain_by_id(server, row.chain_id, opts)

      _ ->
        Logger.warning(
          "Oauth2Server: refresh-token reuse detected but couldn't load row for chain revocation"
        )

        :ok
    end
  end

  defp revoke_chain_by_id(server, chain_id, opts) do
    bulk_opts =
      [return_records?: false, return_errors?: true, notify?: false]
      |> Keyword.merge(ash_opts(opts))

    server.refresh_token_resource()
    |> Ash.Query.filter(chain_id == ^chain_id and is_nil(revoked_at))
    |> Ash.bulk_update(:revoke, %{}, bulk_opts)
    |> case do
      %Ash.BulkResult{status: :success} ->
        :ok

      %Ash.BulkResult{status: status, errors: errors} ->
        Logger.warning(
          "Oauth2Server: chain revocation for chain_id=#{inspect(chain_id)} " <>
            "ended with status #{inspect(status)}: #{inspect(errors)}"
        )

        {:error, :server_error}
    end
  end

  # ── refresh issuance helpers ───────────────────────────────────────────────

  defp issue_refresh_token(server, client_id, code, opts) do
    {raw, hash} = generate_refresh()
    expires_at = DateTime.add(DateTime.utc_now(), server.refresh_token_lifetime(), :second)
    id = Ash.UUIDv7.generate()

    server.refresh_token_resource()
    |> Ash.Changeset.for_create(:issue, %{
      id: id,
      # Root of a fresh chain — chain_id points at this row's own id so
      # every later rotation in the chain shares the same chain_id and
      # reuse-detection can revoke the whole chain in one UPDATE.
      chain_id: id,
      token_hash: hash,
      client_id: client_id,
      user_id: code.user_id,
      scope: code.scope,
      resource_uri: code.resource_uri,
      expires_at: expires_at
    })
    |> Ash.create(ash_opts(opts))
    |> case do
      {:ok, _} -> {:ok, raw}
      {:error, _} -> {:error, :refresh_create_failed}
    end
  end

  defp generate_refresh do
    raw = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
    hash = hash_refresh(raw)
    {raw, hash}
  end

  defp hash_refresh(raw),
    do: :crypto.hash(:sha256, raw) |> Base.encode16(case: :lower)

  # ── client touch (best-effort) ────────────────────────────────────────────

  defp touch_client(client, opts) do
    client
    |> Ash.Changeset.for_update(:touch, %{})
    |> Ash.update(ash_opts(opts))
  rescue
    _ -> :ok
  end

  defp touch_client_by_id(server, client_id, opts) do
    case Ash.get(server.client_resource(), client_id, ash_opts(opts)) do
      {:ok, client} -> touch_client(client, opts)
      _ -> :ok
    end
  end

  # ── opts helper ───────────────────────────────────────────────────────────

  # Bypass context + tenant (when provided). Used for every Ash call in
  # this module.
  defp ash_opts(opts) do
    base = [context: @ash_context]

    case Keyword.get(opts, :tenant) do
      nil -> base
      tenant -> Keyword.put(base, :tenant, tenant)
    end
  end
end
