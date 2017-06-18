use Mix.Config

config :shadowsocks, :listeners,
  [
    [
      type: :server,
      method: "rc4-md5",
      password: "pass",
      port: 8888,
      ota: false,
      ip: {127, 0, 0, 1}
    ],
  ]
