defmodule Shadowsocks do
  @moduledoc """
  The Shadowsocks.

  This module defines common apis to start,update,stop shadowsocks listeners.

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

  the `args` is a keyword list, *see `Shadowsocks.start/1` method*

  """

  @doc """
  start a listener

  the `args` is a keyword list, fields:

    * `type` required `atom` - the connection type, `:client` or `:server` or custom module name

      There are currently four built-in `type`:

      1. `Shadowsocks.Conn.Client` - general client, alias is `:client`
      2. `Shadowsocks.Conn.Server` - general server, alias is `:server`
      3. `Shadowsocks.Conn.TransparentClient` - transparent client, perfect with iptables
      4. `Shadowsocks.Conn.HTTP302` - redirect any http get request to `:redirect_url`, otherwise drop connections

    * `port` required `integer` - listen port
    * `ip`   optional `tuple` - listen ip, example: `{127,0,0,1}`
    * `method` optional `string` - encode method, default: `"aes-256-cfb"`
    * `password` required `string` - encode password
    * `ota` optional `bool` - is force open one time auth, default: `false`
    * `server` optional `tuple` - required if `type` is `:client`, example: `{"la.ss.org", 8388}`
  """
  def start(args) do
    Supervisor.start_child(Shadowsocks.ListenerSup, [args])
  end

  @doc """
  update listener args

  the `args` is a keyword list, *see `Shadowsocks.start/1` method*
  """
  def update(port, args) do
    case find_listener(port) do
      [pid] ->
        Shadowsocks.Listener.update(pid, args)
      _ ->
        {:error, :not_running}
    end
  end

  @doc """
  stop a listener

  stop listener by listen port, always return `:ok`
  """
  def stop(port) do
    find_listener(port)
    |> Enum.each(fn(p)-> Supervisor.terminate_child(Shadowsocks.ListenerSup, p) end)
    :ok
  end

  @doc """
  check port is running
  """
  def running?(port) do
    case find_listener(port) do
      [] -> false
      _ -> true
    end
  end

  @doc """
  get listener `pid`
  """
  def get(port) do
    case find_listener(port) do
      [pid|_] -> pid
      _ -> nil
    end
  end

  defp find_listener(port) do
    children = Supervisor.which_children(Shadowsocks.ListenerSup)
    for {_,p,_,_} <- children, Shadowsocks.Listener.port(p) == port, do: p
  end

end
