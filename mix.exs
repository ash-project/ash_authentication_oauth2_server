# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.MixProject do
  use Mix.Project

  @version "0.1.0"

  @description """
  An OAuth 2.1 authorization server for Ash Framework apps — RFC 7591 dynamic
  client registration, PKCE, audience-bound JWTs, refresh-token rotation, and
  a built-in consent flow on top of ash_authentication + Phoenix.
  """

  def project do
    [
      app: :ash_authentication_oauth2_server,
      version: @version,
      elixir: "~> 1.16",
      start_permanent: Mix.env() == :prod,
      preferred_cli_env: [ci: :test],
      elixirc_paths: elixirc_paths(Mix.env()),
      package: package(),
      deps: deps(),
      aliases: aliases(),
      docs: &docs/0,
      description: @description,
      source_url: "https://github.com/ash-project/ash_authentication_oauth2_server",
      homepage_url: "https://github.com/ash-project/ash_authentication_oauth2_server",
      dialyzer: [
        plt_add_apps: [:mix, :ex_unit]
      ],
      consolidate_protocols: Mix.env() != :test
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp package do
    [
      maintainers: [
        "James Harton <james.harton@alembic.com.au>",
        "Zach Daniel <zach@zachdaniel.dev>"
      ],
      licenses: ["MIT"],
      files: ~w(lib .formatter.exs mix.exs README* documentation LICENSES),
      links: %{
        "Source" => "https://github.com/ash-project/ash_authentication_oauth2_server",
        "GitHub" => "https://github.com/ash-project/ash_authentication_oauth2_server",
        "Discord" => "https://discord.gg/HTHRaaVPUc",
        "Website" => "https://ash-hq.org",
        "REUSE Compliance" =>
          "https://api.reuse.software/info/github.com/ash-project/ash_authentication_oauth2_server"
      }
    ]
  end

  defp docs do
    [
      main: "readme",
      source_ref: "v#{@version}",
      extra_section: "GUIDES",
      extras: [
        {"README.md", title: "Home"},
        "documentation/topics/scopes.md"
      ],
      groups_for_extras: [
        Topics: ~r'documentation/topics'
      ],
      before_closing_head_tag: fn type ->
        if type == :html do
          """
          <script>
            if (location.hostname === "hexdocs.pm") {
              var script = document.createElement("script");
              script.src = "https://plausible.io/js/script.js";
              script.setAttribute("defer", "defer")
              script.setAttribute("data-domain", "ashhexdocs")
              document.head.appendChild(script);
            }
          </script>
          """
        end
      end
    ]
  end

  defp deps do
    [
      {:ash, "~> 3.0"},
      {:ash_authentication, "~> 5.0-rc"},
      {:phoenix, "~> 1.6"},
      {:plug, "~> 1.14"},
      {:jason, "~> 1.0"},
      {:joken, "~> 2.0"},
      # Dev / test
      {:ash_phoenix, "~> 2.3 and >= 2.3.11", only: [:dev, :test]},
      {:credo, "~> 1.6", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.2", only: [:dev, :test], runtime: false},
      {:doctor, "~> 0.18", only: [:dev, :test]},
      {:ex_check, "~> 0.15", only: [:dev, :test]},
      {:ex_doc, "~> 0.37-rc", only: [:dev, :test], runtime: false},
      {:git_ops, "~> 2.4", only: [:dev, :test], runtime: false},
      {:igniter, "~> 0.5 and >= 0.5.25", optional: true},
      {:makeup_html, ">= 0.0.0", only: :dev, runtime: false},
      {:mimic, "~> 2.1", only: [:dev, :test]},
      {:mix_audit, "~> 2.1", only: [:dev, :test]},
      {:plug_cowboy, "~> 2.5", only: [:dev, :test]},
      {:sobelow, "~> 0.13", only: [:dev, :test]}
    ]
  end

  defp aliases do
    [
      ci: [
        "format --check-formatted",
        "doctor --full --raise",
        "credo --strict",
        "dialyzer",
        "hex.audit",
        "test"
      ],
      credo: "credo --strict",
      sobelow: "sobelow --skip",
      "deps.audit": ["deps.audit --ignore-package-names cowlib"]
    ]
  end
end
