# Shadowsocks-ex

shadowsocks-ex is a elixir port of [shadowsocks](https://github.com/shadowsocks/shadowsocks)

A fast tunnel proxy that helps you bypass firewalls.

Features:
- TCP  support
- UDP  support [TODO]
- Client support
- Server support
- OTA    support
- Mulit user support


Encryption methods
- rc4-md5
- aes-128-cfb
- aes-192-cfb
- aes-256-cfb
- aes-128-ctr
- aes-192-ctr
- aes-256-ctr

## Useage
### start a listener

    Shadowsocks.start(args)

the `args` is a keyword list, fields:

    * `type` required `atom` - the connection type, `:client` or `:server` or custom module name
    * `port` required `integer` - listen port
    * `ip`   optional `tuple` - listen ip, example: `{127,0,0,1}`
    * `method` optional `string` - encode method, default: `"rc4-md5"`
    * `password` required `string` - encode password
    * `ota` optional `bool` - is force open one time auth, default: `false`
    * `server` optional `tuple` - required if `type` is `:client`, example: `{"la.ss.org", 8388}`

### stop a listener

      Shadowsocks.stop(port)

  stop listener by listen port, always return `:ok`

### update listener args

      Shadowsocks.update(port, args)

  the `args` is a keyword list, *see `Shadowsocks.start(args)` method*


## Configuration

**startup listeners example:**

```elixir
config :shadowsocks, :listeners,
  [
    [
      type: :server,
      method: "aes-192-cfb",
      password: "pass",
      port: 8888,
      ota: true,
      ip: {127, 0, 0, 1}
    ],
    [
      type: Shadowsocks.Conn.Http302,
      method: "rc4-md5",
      password: "pass",
      port: 8889,
      ota: false,
      ip: {0, 0, 0, 0},
      redirect_url: "http://ionet.cc"
    ],
    [
      type: :client,
      method: "aes-192-cfb",
      password: "pass",
      server: {"localhost", 8888},
      port: 1080,
      ota: true,
      ip: {127, 0, 0, 1}
    ],
  ]

```

## Connection Events

Event name: `Shadowsocks.Event`

events:

```elixir
{:port, :open, port}                       # when start listener on port
{:conn, :open, {port, pid, {addr, port}}}  # when received connection request
{:conn, :close, {port, pid, reason, flow}} # when connection process exited
{:conn, :connect, {port, pid, {ret, addr, port}}} # connect to remote addr result
{:port, :flow, {port, down, up}}           # flow report on the port
```

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed
by adding `shadowsocks` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [{:shadowsocks, "~> 0.1.0"}]
end
```

Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). Once published, the docs can
be found at [https://hexdocs.pm/shadowsocks](https://hexdocs.pm/shadowsocks).

