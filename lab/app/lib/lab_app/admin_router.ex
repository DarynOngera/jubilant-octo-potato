defmodule LabApp.AdminRouter do
  @moduledoc """
  Telemetry/metrics endpoint, served on a separate listener (see
  LabApp.Application) so it stays reachable while the app listener is under
  a resource-exhaustion PoC.
  """
  use Plug.Router

  plug :match
  plug :dispatch

  get "/stats" do
    send_resp(conn, 200, Jason.encode!(snapshot()))
  end

  # Force a full-BEAM garbage collection before a probe baseline. Without
  # this, a previous attack run can leave enough residual memory to inflate
  # the control baseline and make the patched target look noisy. This endpoint
  # is lab-only: it is intentionally absent from LabApp.Router.
  post "/gc" do
    gc_all()
    send_resp(conn, 200, Jason.encode!(%{status: "ok"}))
  end

  match _ do
    send_resp(conn, 404, "not found")
  end

  defp gc_all do
    Process.list()
    |> Enum.each(fn pid ->
      if Process.alive?(pid) do
        :erlang.garbage_collect(pid)
      end
    end)
  end

  def snapshot do
    mem = :erlang.memory() |> Map.new()

    %{
      timestamp_ms: System.system_time(:millisecond),
      erlang_memory: mem,
      process_count: :erlang.system_info(:process_count),
      run_queue: :erlang.statistics(:run_queue),
      port_count: :erlang.system_info(:port_count),
      bandit_version: Application.spec(:bandit, :vsn) |> to_string(),
      top_processes: top_processes(10)
    }
  end

  # Surfaces the heaviest BEAM processes by memory -- during an amplification
  # PoC these will be the stream/connection processes handling the attack
  # connection, confirming *where* the growth is, not just that it happened.
  defp top_processes(n) do
    Process.list()
    |> Enum.map(fn pid ->
      case Process.info(pid, [:memory, :message_queue_len, :reductions, :registered_name]) do
        nil -> nil
        info -> Map.new(info) |> Map.put(:pid, inspect(pid))
      end
    end)
    |> Enum.reject(&is_nil/1)
    |> Enum.sort_by(& &1.memory, :desc)
    |> Enum.take(n)
  end
end
