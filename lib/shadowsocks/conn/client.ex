defmodule Shadowsocks.Conn.Client do
  alias Shadowsocks.Stream

  def init(socket, encoder, parent, args) do
    {atyp, data} = Shadowsocks.Protocol.recv_socks5(socket)

    ssock = Shadowsocks.Conn.connect!(args[:server], args)
    stream =
      %Stream{sock: ssock, encoder: encoder}
      |> Shadowsocks.Protocol.send_target({atyp, data})

    spawn(fn ->
      Shadowsocks.Conn.proxy_stream(socket, stream, parent, 0, :up)
    end)

    %Stream{stream | ota: false}
    |> Shadowsocks.Protocol.recv_iv!()
    |> Shadowsocks.Conn.proxy_stream(socket, parent, 0, :down)
  end

end
