defmodule LabApp.Application do
  @moduledoc """
  Minimal Plug/Bandit target app used across every PoC and lab experiment.

  Two HTTP listeners are started:
    * :app_port  (default 4000) - the Bandit instance under test. All PoC
      traffic goes here. HTTP/1 and HTTP/2 (h2c, cleartext) are both enabled
      so the same image covers both protocol families.
    * :admin_port (default 4001) - a second, independent Bandit instance
      serving only LabApp.AdminRouter (memory/process telemetry). Kept on a
      separate listener/port so an attack saturating the app listener's
      acceptor pool or scheduler doesn't also block our ability to read
      metrics out of the same BEAM instance.

  Set BANDIT_HTTP2 =false to force HTTP/1.1-only experiments.
  """
  use Application

  @impl true
  def start(_type, _args) do
    app_port = env_int("APP_PORT", 4000)
    admin_port = env_int("ADMIN_PORT", 4001)
    http2 = System.get_env("BANDIT_HTTP2", "true") == "true"

    children = [
      LabApp.Telemetry,
      {Bandit,
       plug: LabApp.Router,
       scheme: :http,
       port: app_port,
       # Bandit >= 1.13 configures each protocol stack separately; there is
       # no top-level :protocol_options key. HTTP/2 (h2c, prior knowledge)
       # is enabled by default, so only disable it when asked.
       http_1_options: [enabled: true],
       http_2_options: [enabled: http2]},
      {Bandit,
       plug: LabApp.AdminRouter,
       scheme: :http,
       port: admin_port}
    ]

    opts = [strategy: :one_for_one, name: LabApp.Supervisor]
    Supervisor.start_link(children, opts)
  end

  defp env_int(name, default) do
    case System.get_env(name) do
      nil -> default
      val -> String.to_integer(val)
    end
  end
end
