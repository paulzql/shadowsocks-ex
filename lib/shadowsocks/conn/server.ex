defmodule Shadowsocks.Conn.Server do
  alias Shadowsocks.Stream
  @behaviour  Shadowsocks.Conn
  
  def init(socket, encoder, parent, args) do
    # recv target and check ota
    {stream, addr} =
      Shadowsocks.Protocol.init_stream!(socket, encoder)
      |> Shadowsocks.Protocol.recv_target()

    ssock = Shadowsocks.Conn.connect!(addr, args)

    conn_pid = self()
    pid = spawn(fn ->
      stream
      |> Shadowsocks.Protocol.send_iv!()
      |> Shadowsocks.Conn.proxy_stream(ssock, parent, 0, :up, conn_pid)
    end)

    Shadowsocks.Conn.proxy_stream(ssock, %Stream{stream | ota: false}, parent, 0, :down, conn_pid)
    ref = Process.monitor(pid)
    receive do
      {:DOWN, ^ref, _, _, _} ->
        :ok
    after 1000 ->
        :ok
    end
  end

end
