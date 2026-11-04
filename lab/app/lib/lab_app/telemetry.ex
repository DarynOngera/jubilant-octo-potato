defmodule LabApp.Telemetry do
  @moduledoc """
  Attaches to Bandit's :telemetry events and emits one JSON line per event
  to stdout, which `docker compose logs -f` (and the Python harness, via
  `docker logs --since`) can capture as a structured timeline. This is the
  "application-level telemetry" layer referenced in the detection pack --
  it cannot see frames Bandit rejects before they reach a handler, which is
  why probes/common.py's MemorySampler polls /admin/stats directly during
  each run.
  """
  use GenServer

  @events [
    [:bandit, :request, :start],
    [:bandit, :request, :stop],
    [:bandit, :request, :exception]
  ]

  def start_link(_opts), do: GenServer.start_link(__MODULE__, :ok, name: __MODULE__)

  @impl true
  def init(:ok) do
    :telemetry.attach_many("lab-app-telemetry", @events, &__MODULE__.handle_event/4, nil)
    {:ok, %{}}
  end

  def handle_event(event, measurements, metadata, _config) do
    line =
      Jason.encode!(%{
        ts_ms: System.system_time(:millisecond),
        event: Enum.join(event, "."),
        measurements: safe_map(measurements),
        metadata: safe_metadata(metadata)
      })

    IO.puts(line)
  end

  defp safe_map(m) when is_map(m), do: m
  defp safe_map(_), do: %{}

  defp safe_metadata(m) when is_map(m) do
    %{
      method: Map.get(m, :method),
      status: Map.get(m, :status),
      path: get_in(m, [:conn, Access.key(:request_path)])
    }
  rescue
    _ -> %{}
  end

  defp safe_metadata(_), do: %{}
end
