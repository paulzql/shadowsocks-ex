defmodule Shadowsocks.Conn.Server do
  alias Shadowsocks.Stream

  def init(socket, encoder, parent, args) do
    # recv target and check ota
    {stream, addr} =
      Shadowsocks.Protocol.init_stream(socket, encoder)
      |> Shadowsocks.Protocol.recv_target()

    ssock = Shadowsocks.Conn.connect!(addr, args)

    spawn(fn ->
      stream
      |> Shadowsocks.Protocol.send_iv!()
      |> Shadowsocks.Conn.proxy_stream(ssock, parent, 0, :up)
    end)

    Shadowsocks.Conn.proxy_stream(ssock, %Stream{stream | ota: false}, parent, 0, :down)
  end

end
