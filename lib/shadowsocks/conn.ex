defmodule Shadowsocks.Conn do
  use GenServer
  use Bitwise
  require Shadowsocks.Event
  require Logger
  import Record
  alias Shadowsocks.Encoder

  defrecordp :state, csock: nil, ssock: nil, ota: nil, port: nil, encoder: nil, down: 0, up: 0, sending: 0, ota_data: <<>>, ota_len: 2, ota_id: 0, ota_iv: <<>>, type: :server, server: nil, c2s_handler: nil, s2c_handler: nil

  @recv_timeout 180000
  @tcp_opts [:binary, {:packet, :raw}, {:active, :once}, {:nodelay, true}]

  @atyp_v4 0x01
  @atyp_v6 0x04
  @atyp_dom 0x03
  @hmac_len 10
  @ota_flag 0x10

  def start_link(socket, args) do
    :proc_lib.start_link(__MODULE__, :init, [socket, args])
  end

  def init(socket, %{method: method, password: pass}=args) do
    :proc_lib.init_ack({:ok, self()})
    wait_socket(socket)

    state(csock: socket)
    |> state(ota: args[:ota], port: args[:port], type: args[:type], server: args[:server])
    |> state(encoder: Encoder.init(method, pass))
    |> init_proto
  end

  defp wait_socket(sock) do
    receive do
      {:shoot, ^sock} ->
        :ok
      _ ->
        wait_socket(sock)
    end
  end

  ## ----------------------------------------------------------------------------------------------------
  ## gen server
  ## ----------------------------------------------------------------------------------------------------
  def init([]), do: :pass

  def handle_info({:tcp, csock, data}, state(csock: csock, c2s_handler: handler)=conn) do
    :inet.setopts(csock, active: :once)
    handler.(data, conn)
  end
  def handle_info({:tcp, ssock, data}, state(ssock: ssock, s2c_handler: handler)=conn) do
    :inet.setopts(ssock, active: :once)
    handler.(data, conn)
  end

  # socket send reply
  def handle_info({:inet_reply, _, _}, state(csock: nil, sending: 1)=conn) do
    {:stop, :normal, conn}
  end
  def handle_info({:inet_reply, _, _}, state(ssock: nil, sending: 1)=conn) do
    {:stop, :normal, conn}
  end

  # socket closed
  def handle_info({:tcp_closed, _}, state(sending: 0)=conn) do
    {:stop, :normal, conn}
  end
  def handle_info({:tcp_closed, csock}, state(csock: csock)=conn) do
    {:stop, :normal, state(conn, csock: nil)}
  end
  def handle_info({:tcp_closed, ssock}, state(csock: ssock)=conn) do
    {:stop, :normal, state(conn, csock: nil)}
  end

  # first send
  def handle_info({:send, data}, state(ota: false, ssock: ssock, up: up, sending: s)=conn) do
    s = s + try_send(ssock, data)
    {:noreply, state(conn, sending: s, up: up+byte_size(data))}
  end
  def handle_info({:send, data}, state(ota_data: rest)=conn) do
    handle_ota(state(conn, ota_data: <<rest::binary, data::binary>>))
  end

  def handle_info(_, conn) do
    {:noreply, conn}
  end

  def terminate(_, state(up: up, down: down, port: port)) do
    Shadowsocks.Event.flow(port, down, up)
  end

  ## ----------------------------------------------------------------------------------------------------
  ## protocol init
  ## ----------------------------------------------------------------------------------------------------

  defp init_proto(state(type: :server, csock: csock)=conn) do
    {{addr, port}, data, conn} = recv_ivec(conn) |> recv_target
    case :gen_tcp.connect(addr, port, @tcp_opts) do
      {:ok, ssock} ->
        send self(), {:send, data}
        :inet.setopts(csock, active: :once)
        Shadowsocks.Event.connect({:ok, addr, port})
        Logger.debug "addr: #{addr}:#{port}"
        :gen_server.enter_loop(__MODULE__, [], init_handler(state(conn, ssock: ssock, server: {addr,port})))
      error ->
        Shadowsocks.Event.connect({error, addr, port})
    end
  end

  defp init_proto(state(type: :client, csock: csock, server: {ip,port})=conn) do
    {atyp, data} = recv_socks5(csock)
    case :gen_tcp.connect(ip, port, @tcp_opts) do
      {:ok, ssock} ->
        {encoder, data} =
        if conn.ota do
          hmac = :crypto.hmac(:sha, [conn.encoder.enc_iv,conn.encoder.key], [atyp ||| @ota_flag, data], @hmac_len)
          Encoder.encode(conn.encoder, [atyp ||| @ota_flag, data, hmac])
        else
          Encoder.encode(conn.encoder, [atyp, data])
        end
        :ok = :gen_tcp.send(ssock, data)
        :inet.setopts(csock, active: :once)
        :gen_server.enter_loop(__MODULE__, [], init_handler(state(conn, ssock: ssock, encoder: encoder, ota_iv: encoder.enc_iv)))
      error ->
        error
    end
  end

  defp init_handler(state(type: :client, ota: true)=conn), do: state(conn, c2s_handler: &client_ota_c2s/2, s2c_handler: &client_s2c/2)
  defp init_handler(state(type: :client, ota: false)=conn), do: state(conn, c2s_handler: &client_c2s/2, s2c_handler: &client_s2c/2)
  defp init_handler(state(type: :server, ota: true)=conn), do: state(conn, c2s_handler: &server_ota_c2s/2, s2c_handler: &server_s2c/2)
  defp init_handler(state(type: :server, ota: false)=conn), do: state(conn, c2s_handler: &server_c2s/2, s2c_handler: &server_s2c/2)

  ## ----------------------------------------------------------------------------------------------------
  ## Data encoding / decoding
  ## ----------------------------------------------------------------------------------------------------
  defp client_c2s(data, state(ssock: ssock, up: up, sending: s)=conn) do
    {encoder, data} = Encoder.encode(state(conn, :encoder), data)
    s = s + try_send(ssock, data)
    {:noreply, state(conn, encoder: encoder, up: up+byte_size(data), sending: s)}
  end
  defp client_ota_c2s(data, state(ssock: ssock, up: up, sending: s, ota_id: id)=conn) do
    hmac = :crypto.hmac(:sha, [conn.ota_iv, <<id::32>>], data, @hmac_len)
    {encoder, data} = Encoder.encode(state(conn, :encoder), [<<byte_size(data)::16>>, hmac, data])
    s = s + try_send(ssock, data)
    {:noreply, state(conn, encoder: encoder, up: up+byte_size(data), sending: s, ota_id: id+1)}
  end

  defp client_s2c(data, state(csock: csock, down: down, sending: s)=conn) do
    {encoder, data} = Encoder.decode(state(conn, :encoder), data)
    s = s + try_send(csock, data)
    {:noreply, state(conn, encoder: encoder, down: down+byte_size(data), sending: s)}
  end


  defp server_c2s(data, state(ssock: ssock, up: up, sending: s)=conn) do
    {encoder, data} = Encoder.decode(state(conn, :encoder), data)
    s = s + try_send(ssock, data)
    {:noreply, state(conn, encoder: encoder, up: up+byte_size(data), sending: s)}
  end

  defp server_ota_c2s(data, state(ota_data: rest)=conn) do
    {encoder, data} = Encoder.decode(state(conn, :encoder), data)
    handle_ota(state(conn, ota_data: <<rest::binary, data::binary>>, encoder: encoder))
  end

  defp server_s2c(data, state(csock: csock, down: down, sending: s)=conn) do
    {encoder, data} = Encoder.encode(state(conn,:encoder), data)
    s = s + try_send(csock, data)
    {:noreply, state(conn, encoder: encoder, down: down+byte_size(data), sending: s)}
  end

  # handle ota frame
  defp handle_ota(state(ota_data: data, ota_len: 2)=conn) when byte_size(data) >= 2 do
    <<len::16, _::binary>> = data
    handle_ota(state(conn, ota_len: len+@hmac_len+2))
  end
  defp handle_ota(state(ssock: ssock, ota_iv: iv, ota_data: data, ota_len: len, ota_id: id, up: up, sending: s)=conn) do
    len = len - @hmac_len - 2
    <<_::16, hmac::binary-size(@hmac_len), data::binary-size(len), rest::binary>> = data
    ^hmac = :crypto.hmac(:sha, [iv, <<id::32>>], data, @hmac_len)
    s = s + try_send(ssock,  data)
    handle_ota(state(conn, up: up+byte_size(data), sending: s, ota_data: rest, ota_len: 2, ota_id: id+1))
  end
  defp handle_ota(conn), do: {:noreply, conn}

  defp try_send(sock, data) do
    try do
      :erlang.port_command(sock, data)
      1
    catch
      _ ->
        0
    rescue
      _ ->
        0
    end
  end

  ## ----------------------------------------------------------------------------------------------------
  ## server side internal function for init protocol
  ## ----------------------------------------------------------------------------------------------------
  defp recv_ivec(state(csock: sock, encoder: encoder)=conn) do
    {:ok, ivdata} = :gen_tcp.recv(sock, byte_size(encoder.enc_iv), @recv_timeout)
    state(conn, ota_iv: ivdata, encoder: Encoder.init_decode(encoder, ivdata))
  end

  defp recv_target(conn) do
    {<<addr_type::8, data::binary>>, conn} = recv_decode(1, <<>>, conn)
    {ipport_bin, rest, conn} = recv_addr(addr_type &&& 0x0F, data, conn)

    ipport = parse_addr(addr_type &&& 0x0F, ipport_bin)
    if (addr_type &&& @ota_flag) == @ota_flag do
      {rest, conn} = check_ota([addr_type,ipport_bin], rest, conn)
      {ipport, rest, conn}
    else
      {ipport, rest, conn}
    end
  end

   # recv and decode data until got intput length
  defp recv_decode(len, data, conn) when byte_size(data) >= len do
    {data, conn}
  end
  defp recv_decode(len, rest, state(csock: sock, encoder: encoder)=conn) do
    {:ok, data} = :gen_tcp.recv(sock, 0, @recv_timeout)
    {encoder, data} = Encoder.decode(encoder, data)
    recv_decode(len, <<rest::binary, data::binary>>, state(conn, encoder: encoder))
  end

  defp recv_addr(@atyp_v4, data, conn) do
    {<<ipport::binary-size(6), rest::binary>>, conn} = recv_decode(6, data, conn)
    {ipport, rest, conn}
  end
  defp recv_addr(@atyp_v6, data, conn) do
    {<<ipport::binary-size(18), rest::binary>>, conn} = recv_decode(18, data, conn)
    {ipport, rest, conn}
  end
  defp recv_addr(@atyp_dom, data, conn) do
    {<<domlen::8, rest::binary>>, conn} = recv_decode(1, data, conn)
    len = domlen + 2
    {<<ipport::binary-size(len), rest::binary>>, conn} = recv_decode(len, rest, conn)
    {<<domlen, ipport::binary>>, rest, conn}
  end

  defp parse_addr(@atyp_v4, <<ip1::8,ip2::8,ip3::8,ip4::8,port::16>>), do: {{ip1,ip2,ip3,ip4}, port}
  defp parse_addr(@atyp_v6, <<ip::binary-size(16), port::16>>), do: {for(<<x::16 <- ip>>, do: x) |> List.to_tuple(), port}
  defp parse_addr(@atyp_dom, <<len::8, ip::binary-size(len), port::16>>), do: {String.to_charlist(ip), port}

  defp check_ota(check_data, rest, state(ota_iv: ota_iv, encoder: encoder)=conn) do
    {<<hmac::binary-size(@hmac_len), rest::binary>>, conn} = recv_decode(@hmac_len, rest, conn)
    ^hmac = :crypto.hmac(:sha, [ota_iv, encoder.key], check_data, @hmac_len)
    {rest, state(conn, ota: true)}
  end

  ## ----------------------------------------------------------------------------------------------------
  ## client side internal function for init protocol
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

  defp exactly_recv(sock, size) do
    {:ok, ret} = :gen_tcp.recv(sock, size, @recv_timeout)
    ret
  end
end

