defmodule Shadowsocks.Conn.TransparentClient do
  alias Shadowsocks.Stream
  @behaviour  Shadowsocks.Conn

  @so_original_dst [{:raw, 0, 80, 16}]
  @ipv6_so_original_dst [{:raw, 41, 80, 16}]

  @atyp_v4 0x01
  @atyp_v6 0x04

  def init(socket, encoder, parent, args) do
    {atyp, data} = get_addr!(socket)

    ssock = Shadowsocks.Conn.connect!(args[:server], args)

    stream =
      %Stream{sock: ssock, encoder: encoder, ota_iv: encoder.enc_iv}
      |> Shadowsocks.Protocol.send_iv!()
      |> Shadowsocks.Protocol.send_target({atyp, data})

    spawn(fn ->
      Shadowsocks.Conn.proxy_stream(socket, stream, parent, 0, :up)
    end)

    stream
    |> struct(ota: false)
    |> Shadowsocks.Protocol.recv_iv!()
    |> Shadowsocks.Conn.proxy_stream(socket, parent, 0, :down)
  end

  defp get_addr!(sock) do
    with {:error, _} <- :inet.getopts(sock, @so_original_dst),
         {:error, _} <- :inet.getopts(sock, @ipv6_so_original_dst) do
      exit(:invalid_original_dst)
    else
      {:ok, [{:raw, 0, 80, <<_::16, port::16, ip::32, _::binary>>}]} ->
        {@atyp_v4, <<ip::32, port::16>>}
      {:ok, [{:raw, 41, 80, <<_::16, port::16, _::32, ip::binary-size(16), _::binary>>}]} ->
        {@atyp_v6, <<ip::binary, port::16>>}
    end
  end
end
