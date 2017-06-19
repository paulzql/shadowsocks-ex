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
    * `method` optional `string` - encode method, default: `"aes-256-cfb"`
    * `password` required `string` - encode password
    * `ota` optional `bool` - is force open one time auth, default: `false`
    * `server` optional `tuple` - required if `type` is `:client`, example: `{"la.ss.org", 8388}`

  ### stop a listener

      Shadowsocks.stop(port)

  stop listener by listen port, always return `:ok`

  ### update listener args

      Shadowsocks.update(port, args)

  the `args` is a keyword list, fields:
    * `method` optional `string` - encode method
    * `password` optional `string` - encode password

  """

  @doc """
  start a listener

  the `args` is a keyword list, fields:

    * `type` required `atom` - the connection type, `:client` or `:server` or custom module name
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

  the `args` is a keyword list, fields:
    * **see `start(args)` method
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
