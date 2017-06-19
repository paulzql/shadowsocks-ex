defmodule Shadowsocks.Conn do
  use GenServer
  use Bitwise
  require Shadowsocks.Event
  require Logger
  import Record
  alias Shadowsocks.Encoder

  defrecordp :state, csock: nil, ssock: nil, ota: nil, port: nil, encoder: nil, down: 0, up: 0, sending: 0, ota_data: <<>>, ota_len: 0, ota_id: 0, ota_iv: <<>>, type: :server, server: nil, c2s_handler: nil, s2c_handler: nil, parent: nil

  @tcp_opts [:binary, {:packet, :raw}, {:active, :false}, {:nodelay, true}, {:buffer, 16384}]
  @flow_report_limit 5 * 1024 * 1024

  def start_link(socket, args) do
    :proc_lib.start_link(__MODULE__, :init, [self(), socket, args])
  end

  def init(parent, socket, %{method: method, password: pass}=args) do
    :proc_lib.init_ack({:ok, self()})
    wait_socket(socket)

    Shadowsocks.Event.open_conn(args[:port], self(), socket)

    args[:type]
    |> apply(:init, [socket, Encoder.init(method, pass), parent, args])
  end

  @doc """
  connect to {addr, port}
  *args* conn config options
  """
  @spec connect!({charlist | tuple}, map) :: port
  def connect!({addr, port}, args) do
    case :gen_tcp.connect(addr, port, @tcp_opts) do
      {:ok, ssock} ->
        Shadowsocks.Event.connect(args[:port],{:ok, addr, port})
        ssock
      error ->
        Shadowsocks.Event.connect(args[:port],{error, addr, port})
        exit(error)
    end
  end

  @doc """
  make a proxy from `is` to `os`

  `is` input stream
  `os` output stream
  `size` init data size (`size` will report to flow event)
  `type` `:up` or `:down`, use to report flow event
  """
  @spec proxy_stream(port | struct, port | struct, pid, integer, :up | :down) :: any
  def proxy_stream(is, os, pid, size, type) when size >= @flow_report_limit do
    if type == :up do
      send pid, {:flow, self(), 0, size}
    else
      send pid, {:flow, self(), size, 0}
    end
    proxy_stream(is, os, pid, 0, type)
  end
  def proxy_stream(is, os, pid, size, type) do
    with {:ok, is, data} <- Shadowsocks.Stream.recv(is, 0),
         os <- Shadowsocks.Stream.async_send(os, data) do
      proxy_stream(is, os, pid, size+byte_size(data), type)
    else
      _e ->
      if type == :up do
        send pid, {:flow, self(), 0, size}
      else
        send pid, {:flow, self(), size, 0}
      end

      Shadowsocks.Conn.close(is)
      Shadowsocks.Conn.close(os)
    end
  end

  def close(sock) when is_port(sock) do
    :gen_tcp.close(sock)
  end
  def close(%{sock: sock}) do
    :gen_tcp.close(sock)
  end

  defp wait_socket(sock) do
    receive do
      {:shoot, ^sock} ->
        :ok
      _ ->
        wait_socket(sock)
    end
  end

end
