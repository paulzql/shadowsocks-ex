defmodule Shadowsocks.Event do
  require Logger

  defmacro start_listener(port) do
    quote do
      :gen_event.notify(Shadowsocks.Event, {:port, :open, unquote(port)})
    end
  end

  defmacro open_conn(port, pid, sock) do
    quote do
      {:ok, {addr, _}} = :inet.peername(unquote(sock))
      :gen_event.notify(Shadowsocks.Event, {:conn, :open, {unquote(port), unquote(pid), addr}})
    end
  end

  defmacro close_conn(port, pid, reason, flow) do
    quote do
      :gen_event.notify(Shadowsocks.Event, {:conn, :close, {unquote(port), unquote(pid), unquote(reason), unquote(flow)}})
    end
  end

  defmacro connect(port, info) do
    quote do
      Logger.debug "#{inspect unquote(info)}"
      :gen_event.notify(Shadowsocks.Event, {:conn, :connect, {unquote(port), unquote(self()), unquote(info)}})
    end
  end

  defmacro flow(port, down, up) do
    quote do
      :gen_event.notify(Shadowsocks.Event, {:port, :flow, {unquote(port),unquote(down), unquote(up)}})
    end
  end
  defmacro sync_flow(port, down, up) do
    quote do
      :gen_event.sync_notify(Shadowsocks.Event, {:port, :flow, {unquote(port),unquote(down), unquote(up)}})
    end
  end

end
