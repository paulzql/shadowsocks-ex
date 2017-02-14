use Mix.Config

config :shadowsocks, :listeners,
  [
    [
      type: :server,
      method: "aes-256-cfb",
      password: "pass",
      port: 8888,
      ota: false,
      ip: {127, 0, 0, 1}
    ],
  ]
