defmodule Shadowsocks.UDPRelay do
  alias Shadowsocks.Encoder
  require Shadowsocks.Protocol

  @timeout 15 * 60 * 1000
  @flow_report_limit 1024 * 1024

  def start_link(args) do
    :proc_lib.start_link(__MODULE__, :init, [self(), args])
  end

  def init(parent, %{method: method, password: pass, port: port}=args) do
    opts = case args do
             %{ip: ip} when is_tuple(ip) and tuple_size(ip) == 4 ->
               [:binary, {:active, :once}, {:ip, ip}]
             %{ip: ip} when is_tuple(ip) and tuple_size(ip) == 8 ->
               [:binary, {:active, :once}, {:ip, ip}, :inet6]
             _ ->
               [:binary, {:active, :once}, :inet6]
           end
    {:ok, socket} = :gen_udp.open(port, opts)

    :proc_lib.init_ack({:ok, self()})

    loop(socket, Encoder.init(method, pass), parent)
  end

  defp loop(lsock, encoder, parent) do
    receive do
      {:udp, ^lsock, caddr, cport, data} ->
        case Shadowsocks.BlackList.blocked?(caddr) do
          true ->
            :ignore
          _ ->
            client = {caddr, cport}
            pid =
              case Process.get(client) do
                nil ->
                  {p,_} = spawn_monitor(fn -> init_conn(lsock, encoder, parent, client) end)
                  Process.put(client, p)
                  Process.put(p, client)
                  p
                pid ->
                  pid
              end
            send pid, {:client, data}
        end

        :inet.setopts(lsock, active: :once)
        loop(lsock, encoder, parent)
      :stop ->
        :stop
      {:update, method, password} ->
        loop(lsock, Encoder.init(method, password), parent)
      {:DOWN, _, :process, pid, _} ->
        with {addr, port} <- Process.get(pid) do
          Process.delete(pid)
          Process.delete({addr, port})
        end
        loop(lsock, encoder, parent)
      _ ->
        loop(lsock, encoder, parent)
    end
  end

  defp init_conn(lsock, encoder, parent, {addr, port}) do
    {:ok, socket} = :gen_udp.open(0, [:binary, {:active, :once}])
    conn_loop(lsock, encoder, %{parent: parent, down: 0, up: 0, socket: socket, addr: addr, port: port})
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
        Shadowsocks.Protocol.skip_localhost(addr)
        :gen_udp.send(arg.socket, addr, port, data)
        conn_loop(lsock, encoder, arg)

      {:udp, sock, addr, port, data} ->
        data = Shadowsocks.Protocol.pack(addr, port, data)
        :gen_udp.send(lsock, arg.addr, arg.port, Encoder.encode_once(encoder, data))
        :inet.setopts(sock, active: :once)
        conn_loop(lsock, encoder, arg)

    after
      @timeout ->
        send arg.parent, {:flow, arg.down, arg.up}
        exit(:timeout)
    end
  end


end
