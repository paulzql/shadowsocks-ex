defmodule Shadowsocks.UDPRelay do

  alias Shadowsocks.Encoder

  @timeout 15 * 60 * 1000
  @flow_report_limit 1024 * 1024

  def start_link(args) do
    :proc_lib.start_link(__MODULE__, :init, [self(), args])
  end

  def init(parent, %{method: method, password: pass, port: port}) do
    {:ok, socket} = :gen_udp.open(port, [:binary, {:active, :once}])

    :proc_lib.init_ack({:ok, self()})

    loop(socket, Encoder.init(method, pass), parent)
  end

  defp loop(lsock, encoder, parent) do
    receive do
      {:udp, ^lsock, caddr, cport, data} ->
        pid =
          case Process.get({caddr, cport}) do
            nil ->
              p = spawn(fn -> init_conn(lsock, encoder, parent) end)
              Process.put({caddr, cport}, p)
              p
            pid ->
              pid
          end
        send pid, {:client, data}

        :inet.setopts(lsock, active: :once)
        loop(lsock, encoder, parent)
      :stop ->
        :stop
      _ ->
        loop(lsock, encoder, parent)
    end
  end

  defp init_conn(lsock, encoder, parent) do
    conn_loop(lsock, encoder, %{parent: parent, down: 0, up: 0})
  end

  defp conn_loop(lsock, encoder, %{parent: pid, down: down, up: up})
              when down > @flow_report_limit or up > @flow_report_limit do
    send pid, {:flow, down, up}
    conn_loop(lsock, encoder, %{parent: pid, down: 0, up: 0})
  end
  defp conn_loop(lsock, encoder, arg) do
    receive do
      {:client, data} ->
        {addr, port, data} =
          encoder
          |> Encoder.decode_once(data)
          |> Shadowsocks.Protocol.unpack

        socket =
          case Process.get({addr, port}) do
            nil ->
              {:ok, socket} = :gen_udp.open(0, [:binary, {:active, :once}])
              Process.put({addr, port}, socket)
              socket
            socket ->
              socket
          end

        :gen_udp.send(socket, addr, port, data)
        conn_loop(lsock, encoder, arg)

      {:udp, sock, addr, port, data} ->
        data = Shadowsocks.Protocol.pack(addr, port, data)
        :gen_udp.send(lsock, addr, port, Encoder.encode_once(encoder, data))
        :inet.setopts(sock, active: :once)
        conn_loop(lsock, encoder, arg)

    after
      @timeout ->
        send arg.parent, {:flow, arg.down, arg.up}
        exit(:timeout)
    end
  end


end
