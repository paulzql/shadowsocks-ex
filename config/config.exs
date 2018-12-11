# This file is responsible for configuring your application
# and its dependencies with the aid of the Mix.Config module.
use Mix.Config

# This configuration is loaded before any dependency and is restricted
# to this project. If another project depends on this project, this
# file won't be loaded nor affect the parent project. For this reason,
# if you want to provide default values for your application for
# 3rd-party users, it should be done in your "mix.exs" file.

# You can configure for your application as:
#
#     config :shadowsocks, key: :value
#
# And access this configuration in your application as:
#
#     Application.get_env(:shadowsocks, :key)
#
# Or configure a 3rd-party app:
#
#     config :logger, level: :info
#
config :logger,
  handle_sasl_reports: true

config :shadowsocks, :report,
  port_min_flow: 5 * 1024 * 1024,
  port_min_time: 60 * 1000,
  conn_min_flow: 5 * 1024 * 1024

config :shadowsocks, :protocol,
  recv_timeout: 180000,
  anti_max_time: 10000,
  anti_max_bytes: 500,
  anti_detect: true

# dynamic block attack ip
config :shadowsocks, :dynamic_blocklist,
  enable: true,
  attack_times: 30, # block ip when attack times more than attack_times in collect_duration
  collect_duration: 3600 * 1000, # collect attack times every collect_duration
  block_expire: 7 * 3600 * 1000 # how long to block ip

config :shadowsocks,:skip_localhost, true
# It is also possible to import configuration files, relative to this
# directory. For example, you can emulate configuration per environment
# by uncommenting the line below and defining dev.exs, test.exs and such.
# Configuration from the imported file will override the ones defined
# here (which is why it is important to import them last).
#
import_config "#{Mix.env}.exs"
