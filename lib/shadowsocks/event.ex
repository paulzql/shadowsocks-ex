defmodule Shadowsocks.Event do
  defmacro start_listener(port) do
    quote do
      GenEvent.notify(Shadowsocks.Event, {:listener, :start, unquote(port)})
    end
  end

  defmacro accept(port, addr) do
    quote do
      GenEvent.notify(Shadowsocks.Event, {:listener, :accept, {unquote(port), unquote(addr)}})
    end
  end

  defmacro flow(port, down, up) do
    quote do
      GenEvent.notify(Shadowsocks.Event, {:conn, :report_flow, {unquote(port),unquote(down), unquote(up)}})
    end
  end

  defmacro connect(arg) do
    quote do
      GenEvent.notify(Shadowsocks.Event, {:conn, :connect, unquote(arg)})
    end
  end
end
