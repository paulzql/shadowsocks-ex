defmodule Shadowsocks.Event do
  require Logger

  defmacro start_listener(port) do
    quote do
      GenEvent.notify(Shadowsocks.Event, {:port, :open, unquote(port)})
    end
  end

  defmacro open_conn(port, pid, sock) do
    quote do
      {:ok, {addr, _}} = :inet.peername(unquote(sock))
      GenEvent.notify(Shadowsocks.Event, {:conn, :open, {unquote(port), unquote(pid), addr}})
    end
  end

  defmacro close_conn(port, pid, reason, flow) do
    quote do
      GenEvent.notify(Shadowsocks.Event, {:conn, :close, {unquote(port), unquote(pid), unquote(reason), unquote(flow)}})
    end
  end

  defmacro connect(port, info) do
    quote do
      Logger.debug "#{inspect unquote(info)}"
      GenEvent.notify(Shadowsocks.Event, {:conn, :connect, {unquote(port), unquote(self()), unquote(info)}})
    end
  end

  defmacro flow(port, down, up) do
    quote do
      GenEvent.notify(Shadowsocks.Event, {:port, :flow, {unquote(port),unquote(down), unquote(up)}})
    end
  end

end
