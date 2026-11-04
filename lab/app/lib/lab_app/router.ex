defmodule LabApp.Router do
  @moduledoc """
  The vulnerable/patched target surface. Deliberately simple: realistic
  Plug apps call Plug.Conn.read_body/2 with a configured length cap, and
  that is exactly the code path several of the advisories (e.g.
  CVE-2026-39803, CVE-2026-111101) exercise -- so the test harness talks to
  a plain, idiomatic Plug app rather than anything bandit-internal.
  """
  use Plug.Router

  plug :match
  plug :dispatch

  get "/healthz" do
    send_resp(conn, 200, "ok")
  end

  # Consumes the full request body under an explicit length cap, exactly as
  # a typical controller action would via Plug.Parsers. This is the
  # endpoint PoCs point at: if Bandit buffers/allocates beyond what the cap
  # and read_timeout imply, it shows up as RSS growth here regardless of
  # what this handler does with the bytes.
  post "/echo" do
    max_body_length = max_body_length()
    opts = [length: max_body_length, read_timeout: read_timeout_ms()]

    case read_full_body(conn, opts, 0, max_body_length) do
      {:ok, total_bytes, conn} ->
        send_resp(conn, 200, Jason.encode!(%{received_bytes: total_bytes}))

      {:error, reason, conn} ->
        send_resp(conn, 413, Jason.encode!(%{error: inspect(reason)}))
    end
  end

  get "/ws/echo" do
    conn
    |> WebSockAdapter.upgrade(LabApp.WsEcho, [], timeout: 60_000)
  end

  match _ do
    send_resp(conn, 404, "not found")
  end

  # NOTE: Plug.Conn.read_body/2's :length option caps each individual read,
  # not the total body. A recursive reader must enforce the total itself,
  # otherwise MAX_BODY_LENGTH is only a read-chunk size and the endpoint
  # happily buffers an unbounded body. This is the behaviour several
  # advisories (notably CVE-2026-39803) are actually about.
  defp read_full_body(conn, opts, acc, max_body_length) do
    case Plug.Conn.read_body(conn, opts) do
      {:ok, body, conn} ->
        finish_body(acc + byte_size(body), max_body_length, conn)

      {:more, body, conn} ->
        total = acc + byte_size(body)

        if total > max_body_length do
          {:error, :body_too_large, conn}
        else
          read_full_body(conn, opts, total, max_body_length)
        end

      {:error, reason} ->
        {:error, reason, conn}
    end
  end

  defp finish_body(total, max_body_length, conn) do
    if total > max_body_length do
      {:error, :body_too_large, conn}
    else
      {:ok, total, conn}
    end
  end

  # Read these at request time, not compile time, so the container's runtime
  # environment actually controls the limit.
  defp max_body_length do
    String.to_integer(System.get_env("MAX_BODY_LENGTH", "1000000"))
  end

  defp read_timeout_ms do
    String.to_integer(System.get_env("READ_TIMEOUT_MS", "15000"))
  end
end

defmodule LabApp.WsEcho do
  @behaviour WebSock

  @impl true
  def init(_opts), do: {:ok, %{}}

  @impl true
  def handle_in({data, opcode: :text}, state), do: {:push, {:text, data}, state}
  def handle_in({data, opcode: :binary}, state), do: {:push, {:binary, data}, state}

  @impl true
  def handle_info(_msg, state), do: {:ok, state}
end
