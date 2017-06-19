defmodule Shadowsocks.Conn.Http302 do
  alias Shadowsocks.Stream

  def init(socket, encoder, _parent, %{redirect_url: url}) do
    {stream, _} =
      Shadowsocks.Protocol.init_stream(socket, encoder)
      |> Shadowsocks.Protocol.recv_target()

    case Stream.recv(stream, 8, 10000) do
      {:ok, stream, "GET http"} ->
        write_302(stream, url)
      {:ok, stream, "GET /"<>_} ->
        write_302(stream, url)
      _ -> :ignore
    end
  end
  def init(_,_,_,_), do: :argument_error

  def write_302(stream, url) do
    str = ~s<HTTP/1.1 302 Found\r\nLocation: #{url}\r\n\r\n>
    stream
    |> Shadowsocks.Protocol.send_iv!()
    |> Stream.send!(str)
  end
end
