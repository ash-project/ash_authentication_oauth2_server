# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.CIMD.Cache do
  @moduledoc """
  ETS cache for fetched Client ID Metadata Documents.

  Started by `AshAuthentication.Oauth2Server.Supervisor`. The cache is a
  pure optimization — every read/write degrades to a no-op when the
  supervisor (and therefore the table) isn't running, so CIMD keeps
  working without it, just with a fetch per authorize request.

  Entries are keyed by the exact `client_id` URL and honour the TTL the
  fetcher derived from the document's HTTP cache headers. The table is
  bounded (`@max_entries`) so a flood of one-off client URLs can't grow
  it without limit, and expired entries are swept periodically.
  """

  use GenServer

  @table __MODULE__
  @max_entries 10_000
  @sweep_interval :timer.minutes(10)

  @doc false
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Look up a cached document. Returns `{:ok, document}` or `:miss`.
  """
  @spec get(String.t()) :: {:ok, map()} | :miss
  def get(url) do
    case :ets.lookup(@table, url) do
      [{^url, document, expires_at}] ->
        if System.monotonic_time(:second) < expires_at, do: {:ok, document}, else: :miss

      [] ->
        :miss
    end
  rescue
    # Table not started — the supervisor isn't running. Treat as a miss.
    ArgumentError -> :miss
  end

  @doc """
  Cache a document for `ttl` seconds. A `ttl` of `0` (or the table being
  absent or full) is a no-op.
  """
  @spec put(String.t(), map(), non_neg_integer()) :: :ok
  def put(_url, _document, 0), do: :ok

  def put(url, document, ttl) when is_integer(ttl) and ttl > 0 do
    if :ets.info(@table, :size) < @max_entries do
      :ets.insert(@table, {url, document, System.monotonic_time(:second) + ttl})
    end

    :ok
  rescue
    ArgumentError -> :ok
  end

  @impl true
  def init(_opts) do
    :ets.new(@table, [:named_table, :set, :public, read_concurrency: true])
    schedule_sweep()
    {:ok, %{}}
  end

  @impl true
  def handle_info(:sweep, state) do
    now = System.monotonic_time(:second)
    :ets.select_delete(@table, [{{:_, :_, :"$1"}, [{:<, :"$1", now}], [true]}])
    schedule_sweep()
    {:noreply, state}
  end

  defp schedule_sweep do
    Process.send_after(self(), :sweep, @sweep_interval)
  end
end
