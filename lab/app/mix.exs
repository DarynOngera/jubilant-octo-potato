defmodule LabApp.MixProject do
  use Mix.Project

  # The version under test is injected at build time via --build-arg
  # BANDIT_VERSION, which Docker exports as the BANDIT_VERSION env var before
  # `mix deps.get` runs. This lets one app image serve as both the
  # "vulnerable" and "patched" target just by pinning a different tag.
  @bandit_version System.get_env("BANDIT_VERSION", "1.14.1")

  def project do
    [
      app: :lab_app,
      version: "0.1.0",
      elixir: "~> 1.15",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  def application do
    [
      mod: {LabApp.Application, []},
      extra_applications: [:logger, :telemetry]
    ]
  end

  defp deps do
    [
      {:bandit, @bandit_version},
      {:plug, "~> 1.16"},
      {:websock_adapter, "~> 0.5"},
      {:telemetry, "~> 1.2"},
      {:telemetry_metrics, "~> 1.0"},
      {:jason, "~> 1.4"}
    ]
  end
end
