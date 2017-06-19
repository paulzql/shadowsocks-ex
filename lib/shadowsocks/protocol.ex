defmodule Shadowsocks.Protocol do
  alias Shadowsocks.Stream
  use Bitwise
  alias Shadowsocks.Encoder

  @recv_timeout 180000

  @atyp_v4 0x01
  @atyp_v6 0x04
  @atyp_dom 0x03
  @hmac_len 10
  @ota_flag 0x10

  ## ----------------------------------------------------------------------------------------------------
  ## server side  function for init protocol
  ## ----------------------------------------------------------------------------------------------------
  @doc """
  init encoder socket stream
  """
  def init_stream(sock, encoder) do
    {sock, ivdata} = Stream.recv!(sock, byte_size(encoder.enc_iv))
    %Stream{sock: sock, encoder: Encoder.init_decode(encoder, ivdata), ota_iv: ivdata}
  end

  def send_iv!(stream) do
    Stream.send!(stream.sock, stream.encoder.enc_iv)
    stream
  end

  def recv_iv!(stream) do
    {_, iv} = Stream.recv!(stream.sock, byte_size(stream.encoder.enc_iv))
    %Stream{stream | encoder: Encoder.init_decode(stream.encoder, iv), ota_iv: iv}
  end

  @doc """
  receive the client request
  """
  def recv_target(stream) do
    {stream, <<addr_type::8>>} = Stream.recv!(stream, 1)
    {stream, ipport_bin} = recv_addr(addr_type &&& 0x0F, stream)

    ipport = parse_addr(addr_type &&& 0x0F, ipport_bin)
    if (addr_type &&& @ota_flag) == @ota_flag do
      {stream, <<hmac::binary-size(@hmac_len)>>} = Stream.recv!(stream, @hmac_len)
      ^hmac = :crypto.hmac(:sha, [stream.ota_iv, stream.encoder.key], [addr_type,ipport_bin], @hmac_len)
      {%Stream{stream | ota: true}, ipport}
    else
      {stream, ipport}
    end
  end

  ## ----------------------------------------------------------------------------------------------------
  ## client side  function for init protocol
  ## ----------------------------------------------------------------------------------------------------

  # recv socks5 request
  def recv_socks5(sock) do
    # ------ handshark --------------------------
    # exactly socks5 version otherwise boom!!!
    <<0x05::8, methods::8>> = exactly_recv(sock, 2)
    # don't care methods
    _ = exactly_recv(sock, methods)
    # response ok
    :ok = :gen_tcp.send(sock, <<0x05::8, 0>>)

    # ------ socks5 req -------------------------
    # only support socks5 connect
    <<0x05::8, 0x01::8, 0, atyp::8>> = exactly_recv(sock, 4)
    ret =
      case atyp do
        @atyp_v4 -> exactly_recv(sock, 6)
        @atyp_v6 -> exactly_recv(sock, 18)
        @atyp_dom ->
          <<domlen::8>> = exactly_recv(sock, 1)
          [domlen, exactly_recv(sock, domlen+2)]
      end
    :ok = :gen_tcp.send(sock, <<0x05, 0x00, 0, 0x01, 0::32, 0::16>>)
    {atyp, ret}
  end

  def send_target(%Stream{encoder: encoder, ota: ota}=stream, {atyp, ipport}) do
    if ota do
      ota_atyp = atyp ||| @ota_flag
      hmac = :crypto.hmac(:sha, [encoder.enc_iv, encoder.key], [ota_atyp, ipport], @hmac_len)
      %Stream{stream | ota: false}
      |> Stream.send!(<<ota_atyp::8, ipport::binary, hmac::binary>>)
      |> struct(ota: true)
    else
      Stream.send!(stream, <<atyp::8, ipport::binary>>)
    end
  end

  defp exactly_recv(sock, size) do
    {:ok, ret} = :gen_tcp.recv(sock, size, @recv_timeout)
    ret
  end

  defp recv_addr(@atyp_v4, sock), do: Stream.recv!(sock, 6)
  defp recv_addr(@atyp_v6, sock), do: Stream.recv!(sock, 18)
  defp recv_addr(@atyp_dom, sock) do
    {sock, <<domlen::8>>} = Stream.recv!(sock, 1)
    {sock, ipport} = Stream.recv!(sock, domlen + 2)
    {sock, <<domlen, ipport::binary>>}
  end

  defp parse_addr(@atyp_v4, <<ip1::8,ip2::8,ip3::8,ip4::8,port::16>>), do: {{ip1,ip2,ip3,ip4}, port}
  defp parse_addr(@atyp_v6, <<ip::binary-size(16), port::16>>), do: {for(<<x::16 <- ip>>, do: x) |> List.to_tuple(), port}
  defp parse_addr(@atyp_dom, <<len::8, ip::binary-size(len), port::16>>), do: {String.to_charlist(ip), port}
end
