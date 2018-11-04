use Mix.Config

config :shadowsocks, :listeners,
  [
    [
      # type: Shadowsocks.Conn.Http302,
      type: :server, #Shadowsocks.Conn.ObfsServer,
      method: "rc4-md5",
      password: "pass",
      port: 8888,
      ota: false,
      udp: true,
      failover: "http://ionet.cc"
    ],
    [
      type: :client,
      method: "rc4-md5",
      password: "pass",
      server: {"localhost", 8888},
      port: 1081,
      ota: true,
      ip: {127, 0, 0, 1}
    ],
    # [
    #   type: :client,
    #   method: "aes-128-cfb",
    #   password: "PS5X21dh51",
    #   server: {"tw1.ionet.cc", 6003},
    #   port: 1080,
    #   ota: false,
    #   ip: {127, 0, 0, 1}
    # ],
  ]

  config :shadowsocks, :protocol,
    recv_timeout: 5000,
    anti_max_time: 1000,
    anti_max_bytes: 1,
    anti_detect: true

# dynamic block attack ip
config :shadowsocks, :dynamic_blocklist,
  enable: false