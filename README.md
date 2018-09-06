# Shadowsocks-ex

shadowsocks-ex is a elixir port of [shadowsocks](https://github.com/shadowsocks/shadowsocks)

A fast tunnel proxy that helps you bypass firewalls.

Features:
- TCP  support
- UDP  support (only server)
- Client support (socks5 and http proxy)
- Server support
- OTA    support
- Mulit user support
- Transparent Proxy Client support
- Anti protocol detection

Encryption methods
- rc4-md5
- aes-128-cfb
- aes-192-cfb
- aes-256-cfb
- aes-128-ctr
- aes-192-ctr
- aes-256-ctr
- aes-128-gcm
- aes-192-gcm
- aes-256-gcm

## Installation

The package can be installed
by adding `shadowsocks` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [{:shadowsocks, "~> 0.4"}]
end
```

## Documentation
The online docs can
be found at [https://hexdocs.pm/shadowsocks](https://hexdocs.pm/shadowsocks).

## Usage
### start a listener

```elixir
Shadowsocks.start(args)
```

the `args` is a keyword list, fields:

 * `type` required `atom` - the connection type, `:client` or `:server` or custom module name

    There are currently four built-in `type`:

    1. `Shadowsocks.Conn.Client` - general client, alias is `:client`
    2. `Shadowsocks.Conn.Server` - general server, alias is `:server`
    3. `Shadowsocks.Conn.TransparentClient` - transparent client, use iptables forward to this port instead socks5 client
    4. `Shadowsocks.Conn.HTTP302` - redirect any http get request to `:redirect_url`, otherwise drop connections
    5. `Shadowsocks.Conn.ObfsServer` - simple http obfs server (Compatible with raw protocol, It means that can both accept http obfs client and original shadowsocks client. see: [https://github.com/shadowsocks/simple-obfs](https://github.com/shadowsocks/simple-obfs))

 * `port` required `integer` - listen port
 * `ip`   optional `tuple` - listen ip, example: `{127,0,0,1}`
 * `method` optional `string` - encode method, default: `"rc4-md5"`
 * `password` required `string` - encode password
 * `ota` optional `bool` - is force open one time auth, default: `false`
 * `server` optional `tuple` - required if `type` is `:client`, example: `{"la.ss.org", 8388}`
 * `udp`   optional `bool` - enable udp relay (only support server side)

### stop a listener

```elixir
Shadowsocks.stop(port)
```

  stop listener by listen port, always return `:ok`

### update listener args

```elixir
Shadowsocks.update(port, args)
```

  the `args` is a keyword list, *see `Shadowsocks.start/1` method*


## Configuration

### startup listeners example:

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
      redirect_url: "https://google.com"
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


### compile time configs

```elixir
config :shadowsocks, :report,
    port_min_flow: 5 * 1024 * 1024, # report flow when cached flow exceed :port_min_flow
    port_min_time: 60 * 1000,       # report flow when cached flow after :port_min_time
    conn_min_flow: 5 * 1024 * 1024  # send flow to listener when cached flow exceed :conn_min_flow

config :shadowsocks, :protocol,
  recv_timeout: 180000,             # timeout for receive header
  anti_max_time: 10000,             # anti max delay time (ms), random sleep time before close connection
  anti_max_bytes: 500,              # anti max reply bytes, random bytes send to client
  anti_detect: true                 # on / off anti protocol detection
```

## Connection Events

Event name: `Shadowsocks.Event`

events:

```elixir
{:port, :open, port}                       # when start listener on port
{:conn, :open, {port, pid, addr}}  # when received connection request
{:conn, :close, {port, pid, reason, flow}} # when connection process exited
{:conn, :connect, {port, pid, {ret, addr, port}}} # connect to remote addr result
{:port, :flow, {port, down, up}}           # flow report on the port
```
