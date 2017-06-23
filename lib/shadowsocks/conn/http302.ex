defmodule Shadowsocks.Conn.Http302 do
  alias Shadowsocks.Stream

  @timeout 10000
  @re_path ~r|([^ ]*) HTTP/1.1\r\n|
  @re_host ~r|\r\nHost: ([^\r\n]*)\r\n|

  def init(socket, encoder, _parent, %{redirect_url: url}) do
    {stream, _} =
      Shadowsocks.Protocol.init_stream(socket, encoder)
      |> Shadowsocks.Protocol.recv_target()

    case Stream.recv(stream, 4, @timeout) do
      {:ok, stream, "GET "} ->
        case get_url(stream) do
          {_stream, ^url} ->
            :ignore
          {stream, _url2} ->
            write_302(stream, url)
        end
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

  defp get_url(stream, rest \\ <<>>)
  defp get_url(_stream, rest) when byte_size(rest) > 1024 do
    exit(:normal)
  end
  defp get_url(stream, rest) do
    {:ok, stream, data} = Stream.recv(stream, 0, @timeout)
    case rest <> data do
      "http://" <> _ = rest2 ->
        case Regex.run(@re_path, rest2) do
          [_, url] -> {stream, String.trim(url) |> URI.parse |> to_string}
          _ ->
            get_url(stream, rest2)
        end
      "/" <> _ = rest2 ->
        with [_, host] <- Regex.run(@re_host, rest2),
             [_, path] <- Regex.run(@re_path, rest2) do
          {stream, URI.parse("http://#{String.trim(host)}#{String.trim(path)}") |> to_string}
        else
          _ ->
            get_url(stream, rest2)
        end
    end
  end
end
