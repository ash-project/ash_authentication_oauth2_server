# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.CIMD.ReqFetcher do
  @moduledoc """
  The default Client ID Metadata Document fetcher, built on `Req`.

  A CIMD `client_id` is an attacker-suppliable URL that this server
  fetches — the textbook SSRF setup — so every request goes through an
  outbound policy before any bytes leave the box:

    * **URL shape** — `https` scheme, a real host, a non-root path
      component (per the CIMD draft), no fragment, no userinfo, and
      port 443 unless `:allowed_ports` says otherwise.
    * **Address validation** — the host is resolved up front and *every*
      returned address must be publicly routable. Loopback, RFC 1918,
      link-local (including the cloud metadata range `169.254.0.0/16`),
      CGNAT, multicast, reserved ranges, and their IPv6 equivalents
      (including v4-mapped/NAT64/6to4 forms, whose embedded IPv4 is
      re-checked) are all rejected.
    * **Pinned connect** — the request connects to the *validated IP*
      while keeping TLS verification, SNI, and the `Host` header on the
      original hostname (Mint's `:hostname` option). This closes the
      DNS-rebinding window between "resolve and check" and "connect".
    * **No redirects** — a redirect response is an error. A compliant
      CIMD document is served directly at its `client_id` URL.
    * **Bounded response** — the body is capped at `:max_body_bytes`
      (default 64 KiB) and the request at `:receive_timeout` /
      `:connect_timeout` (default 5s each).

  Requires the optional `:req` dependency:

      {:req, "~> 0.5"}

  ## Options (via `:cimd_fetch_options` on your server module)

    * `:max_body_bytes` — response size cap (default `65_536`)
    * `:connect_timeout` — TCP/TLS connect timeout in ms (default `5_000`)
    * `:receive_timeout` — response receive timeout in ms (default `5_000`)
    * `:allowed_ports` — permitted URL ports (default `[443]`)
    * `:allow_non_public_ips?` — skip the address validation entirely
      (default `false`). **Never enable this in production** — it exists
      for development against local stub servers only.
  """

  @behaviour AshAuthentication.Oauth2Server.CIMD.Fetcher

  @default_max_body_bytes 65_536
  @default_timeout 5_000
  @default_allowed_ports [443]

  @impl true
  def fetch(url, opts \\ []) do
    with :ok <- ensure_req!(),
         {:ok, uri} <- validate_url(url, opts),
         {:ok, ip} <- resolve_and_validate(uri.host, opts) do
      do_fetch(uri, ip, opts)
    end
  end

  # ── URL shape ──────────────────────────────────────────────────────────────

  @doc false
  # Public for tests. Validates the URL shape per the CIMD draft plus this
  # module's outbound policy. Returns `{:ok, %URI{}}` or `{:error, reason}`.
  def validate_url(url, opts \\ []) when is_binary(url) do
    allowed_ports = Keyword.get(opts, :allowed_ports, @default_allowed_ports)

    case URI.new(url) do
      {:ok, %URI{scheme: "https", host: host, userinfo: nil, fragment: nil} = uri}
      when is_binary(host) and host != "" ->
        cond do
          uri.path in [nil, "", "/"] ->
            {:error, :missing_path}

          uri.port not in allowed_ports ->
            {:error, :port_not_allowed}

          true ->
            {:ok, uri}
        end

      _ ->
        {:error, :invalid_url}
    end
  end

  # ── address validation ─────────────────────────────────────────────────────

  defp resolve_and_validate(host, opts) do
    if Keyword.get(opts, :allow_non_public_ips?, false) do
      resolve_first(host)
    else
      with {:ok, ips} <- resolve_all(host) do
        # Reject the host outright if ANY of its addresses is non-public.
        # A host that mixes public and private records is exactly the
        # shape a rebinding/multi-record attack takes.
        if Enum.all?(ips, &public_ip?/1),
          do: {:ok, hd(ips)},
          else: {:error, :non_public_address}
      end
    end
  end

  defp resolve_first(host) do
    with {:ok, [ip | _]} <- resolve_all(host), do: {:ok, ip}
  end

  defp resolve_all(host) do
    charlist = String.to_charlist(host)

    case :inet.parse_address(charlist) do
      {:ok, ip} ->
        {:ok, [ip]}

      {:error, _} ->
        v4 = getaddrs(charlist, :inet)
        # Prefer IPv4 for the pinned connect; fall back to IPv6-only hosts.
        case v4 ++ getaddrs(charlist, :inet6) do
          [] -> {:error, :nxdomain}
          ips -> {:ok, Enum.uniq(ips)}
        end
    end
  end

  defp getaddrs(charlist, family) do
    case :inet.getaddrs(charlist, family) do
      {:ok, ips} -> ips
      {:error, _} -> []
    end
  end

  @doc false
  # Public for tests. True when the address is publicly routable — i.e.
  # safe to make an outbound request to under this module's SSRF policy.
  def public_ip?({a, b, c, d}) do
    not (a == 0 or
           a == 10 or
           a == 127 or
           (a == 100 and b >= 64 and b <= 127) or
           (a == 169 and b == 254) or
           (a == 172 and b >= 16 and b <= 31) or
           (a == 192 and b == 0 and c == 0) or
           (a == 192 and b == 0 and c == 2) or
           (a == 192 and b == 88 and c == 99) or
           (a == 192 and b == 168) or
           (a == 198 and (b == 18 or b == 19)) or
           (a == 198 and b == 51 and c == 100) or
           (a == 203 and b == 0 and c == 113) or
           a >= 224 or
           (a == 255 and b == 255 and c == 255 and d == 255))
  end

  def public_ip?({w1, w2, w3, w4, w5, w6, w7, w8} = ip) do
    cond do
      # :: and ::1
      ip in [{0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0, 0, 1}] ->
        false

      # ::ffff:a.b.c.d — IPv4-mapped; re-check the embedded IPv4
      {w1, w2, w3, w4, w5} == {0, 0, 0, 0, 0} and w6 == 0xFFFF ->
        public_ip?(embedded_v4(w7, w8))

      # 64:ff9b::/96 — NAT64; re-check the embedded IPv4
      {w1, w2, w3, w4, w5, w6} == {0x64, 0xFF9B, 0, 0, 0, 0} ->
        public_ip?(embedded_v4(w7, w8))

      # 2002::/16 — 6to4; the embedded IPv4 is in words 2-3
      w1 == 0x2002 ->
        public_ip?(embedded_v4(w2, w3))

      # 100::/64 discard, 2001:db8::/32 documentation
      {w1, w2, w3, w4} == {0x100, 0, 0, 0} or {w1, w2} == {0x2001, 0xDB8} ->
        false

      # fc00::/7 unique-local, fe80::/10 link-local, ff00::/8 multicast
      Bitwise.band(w1, 0xFE00) == 0xFC00 or
        Bitwise.band(w1, 0xFFC0) == 0xFE80 or
          Bitwise.band(w1, 0xFF00) == 0xFF00 ->
        false

      true ->
        true
    end
  end

  defp embedded_v4(hi, lo) do
    {Bitwise.bsr(hi, 8), Bitwise.band(hi, 0xFF), Bitwise.bsr(lo, 8), Bitwise.band(lo, 0xFF)}
  end

  # ── the request itself ─────────────────────────────────────────────────────

  defp do_fetch(uri, ip, opts) do
    max_body = Keyword.get(opts, :max_body_bytes, @default_max_body_bytes)

    request =
      Req.new(
        url: pinned_url(uri, ip),
        headers: [{"accept", "application/json"}],
        connect_options: [
          # Connect to the validated IP, but keep TLS verification, SNI,
          # and the Host header on the original hostname.
          hostname: uri.host,
          timeout: Keyword.get(opts, :connect_timeout, @default_timeout)
        ],
        receive_timeout: Keyword.get(opts, :receive_timeout, @default_timeout),
        redirect: false,
        retry: false,
        # Raw body collection with a size cap — decoding happens below so
        # an oversized response never accumulates in memory.
        into: body_limiter(max_body)
      )

    case Req.request(request) do
      {:ok, %{status: 200} = response} ->
        decode_response(response)

      {:ok, %{status: status}} when status in 300..399 ->
        {:error, :redirect_not_allowed}

      {:ok, %{status: status}} ->
        {:error, {:http_status, status}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp pinned_url(uri, ip) do
    ip_string = ip |> :inet.ntoa() |> to_string()
    host = if tuple_size(ip) == 8, do: "[" <> ip_string <> "]", else: ip_string
    port = if uri.port == 443, do: "", else: ":#{uri.port}"
    query = if uri.query, do: "?" <> uri.query, else: ""

    "https://#{host}#{port}#{uri.path}#{query}"
  end

  defp body_limiter(max_body) do
    fn {:data, chunk}, {req, resp} ->
      body = (Req.Response.get_private(resp, :cimd_body) || <<>>) <> chunk

      if byte_size(body) > max_body do
        {:halt, {req, Req.Response.put_private(resp, :cimd_too_large, true)}}
      else
        {:cont, {req, Req.Response.put_private(resp, :cimd_body, body)}}
      end
    end
  end

  defp decode_response(response) do
    if Req.Response.get_private(response, :cimd_too_large, false) do
      {:error, :document_too_large}
    else
      body = Req.Response.get_private(response, :cimd_body) || ""

      case Jason.decode(body) do
        {:ok, document} when is_map(document) ->
          {:ok, %{document: document, cache_ttl: cache_ttl(response)}}

        {:ok, _} ->
          {:error, :not_a_json_object}

        {:error, _} ->
          {:error, :invalid_json}
      end
    end
  end

  # Derive a cache TTL from Cache-Control. `nil` means "no directive —
  # caller decides"; `0` means "the response asked not to be cached".
  defp cache_ttl(response) do
    case Req.Response.get_header(response, "cache-control") do
      [value | _] ->
        directives =
          value
          |> String.downcase()
          |> String.split(",", trim: true)
          |> Enum.map(&String.trim/1)

        cond do
          Enum.any?(directives, &(&1 in ["no-store", "no-cache", "private"])) ->
            0

          max_age = Enum.find_value(directives, &parse_max_age/1) ->
            max_age

          true ->
            nil
        end

      [] ->
        nil
    end
  end

  defp parse_max_age("max-age=" <> value) do
    case Integer.parse(value) do
      {seconds, _} when seconds >= 0 -> seconds
      _ -> nil
    end
  end

  defp parse_max_age(_), do: nil

  defp ensure_req! do
    if Code.ensure_loaded?(Req) do
      :ok
    else
      raise """
      #{inspect(__MODULE__)} requires the optional `req` dependency.

      Add it to your deps:

          {:req, "~> 0.5"}

      or configure a custom fetcher via the `:cimd_fetcher` option on your
      Oauth2Server module.
      """
    end
  end
end
