defmodule Flow.MixProject do
  use Mix.Project

  def project do
    [
      app: :flow,
      version: "0.1.0",
      elixir: "~> 1.14",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger],
      mod: {Flow.Application, []}
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:ranch, "~> 2.1"},
      {:varint, "~> 1.3.0"},
      {:jason, "~> 1.4.0"},
      {:elixir_uuid, "~> 1.2"},
      # {:rsa_ex, "~> 0.4"}
      {:x509, "~> 0.8.5"},
      {:httpoison, "~> 2.0"},
      {:libcluster, "~> 3.3"},
      # {:nbt, git: "https://github.com/asaaki/NBT.git"}
      # {:erl_nbt, "~>1.0.0"}
      {:rustler, "~> 0.27.0"}
      # {:dep_from_hexpm, "~> 0.3.0"},
      # {:dep_from_git, git: "https://github.com/elixir-lang/my_dep.git", tag: "0.1.0"}
    ]
  end
end
