defmodule Shadowsocks.Listener do
  use GenServer
  require Shadowsocks.Event
  import Record

  defrecordp :state, lsock: nil, args: nil, port: nil,
                     up: 0, down: 0, flow_time: 0, udp: nil

  @opts [:binary, {:backlog, 20},{:nodelay, true},
         {:active, false}, {:packet, :raw},{:reuseaddr, true},
         {:send_timeout_close, true}, {:buffer, 16384}]

  @default_arg %{ota: false, method: "rc4-md5", udp: false, type: :server}

  @min_flow Application.get_env(:shadowsocks, :report, [])
            |> Keyword.get(:port_min_flow, 5 * 1024 * 1024)
  @min_time Application.get_env(:shadowsocks, :report, [])
            |> Keyword.get(:port_min_time, 60 * 1000)

  def update(pid, args) when is_list(args) do
    map_arg = for {k, v} <- args, do: {k,v}, into: %{}
    update(pid, map_arg)
  end
  def update(pid, args) do
    GenServer.call pid, {:update, args}
  end

  def port(pid) do
    GenServer.call pid, :get_port
  end

  def start_link(args) when is_list(args) do
    map_arg = for {k, v} <- args, do: {k,v}, into: %{}
    start_link(map_arg)
  end
  def start_link(args) when is_map(args) do
    GenServer.start_link(__MODULE__, args)
  end

  def init(args) do
    args = merge_args(@default_arg, args)
    Process.flag(:trap_exit, true)

    opts = case args do
             %{ip: ip} when is_tuple(ip) and tuple_size(ip) == 4 ->
               [{:ip, ip}|@opts]
             %{ip: ip} when is_tuple(ip) and tuple_size(ip) == 8 ->
               [{:ip, ip}, :inet6 | @opts]
             _->
               [:inet6 | @opts]
           end

    with {:ok, lsock} <- :gen_tcp.listen(args.port, opts),
         {:ok, _} <- :prim_inet.async_accept(lsock, -1),
         {:ok, udp_pid} <- start_udprelay(args) do
      Shadowsocks.Event.start_listener(args.port)
      {:ok, state(lsock: lsock, args: args, port: args.port, udp: udp_pid)}
    else
      error ->
        {:stop, error}
    end
  end

  def handle_call({:update, args}, _from, state(args: old_args)=state) do
    try do
      args = merge_args(old_args, args)
      # update udp
      case {state(state, :udp), args} do
        {nil, %{udp: true}} ->
          {:ok, pid} = start_udprelay(args)
          {:reply, :ok, state(state, args: args, udp: pid)}
        {nil, %{udp: false}} ->
          {:reply, :ok, state(state, args: args)}
        {pid, %{udp: true}} when is_pid(pid) ->
          send pid, {:update, args[:method], args[:password]}
          {:reply, :ok, state(state, args: args)}
        {pid, %{udp: false}} when is_pid(pid) ->
          send pid, :stop
          {:reply, :ok, state(state, args: args, udp: nil)}
      end
    rescue
      e in ArgumentError ->
        {:reply, {:error, e}, state}
    end
  end

  def handle_call(:get_port, _, state(port: port)=state) do
    {:reply, port, state}
  end

  def handle_info({:inet_async, _, _, {:ok, csock}}, state) do
    true = :inet_db.register_socket(csock, :inet_tcp)
    {:ok, pid} = Shadowsocks.Conn.start_link(csock, state(state, :args))
    Process.put(pid, {0, 0})
    case :gen_tcp.controlling_process(csock, pid) do
      :ok ->
        send pid, {:shoot, csock}
      {:error, _} ->
        Process.exit(pid, :kill)
        :gen_tcp.close(csock)
    end
    case :prim_inet.async_accept(state(state,:lsock), -1) do
      {:ok, _} ->
        {:noreply, state}
      {:error, ref} ->
        {:stop, {:async_accept, :inet.format_error(ref)}, state}
    end

  end

  def handle_info({:inet_async, _lsock, _ref, error}, state) do
    {:stop, error, state}
  end
  # UDP
  def handle_info({:flow, down, up}, state) do
    {:noreply, save_flow(down, up, state)}
  end
  # TCP
  def handle_info({:flow, pid, down, up}, state) do
    with {old_down, old_up} <- Process.get(pid) do
      Process.put(pid, {old_down+down, old_up+up})
    end
    {:noreply, save_flow(down, up, state)}
  end

  def handle_info({:EXIT, pid, reason}, state(port: port)=state) do
    with {down, up} <- Process.get(pid) do
      Shadowsocks.Event.close_conn(port, pid, reason, {down, up})
      Process.delete(pid)
    end
    {:noreply, state}
  end
  def handle_info(msg, state) do
    IO.puts "bad message: #{inspect msg}"
    {:noreply, state}
  end

  def terminate(_, state(port: port, up: up, down: down)) when up > 0 and down > 0 do
    Shadowsocks.Event.sync_flow(port, down, up)
  end
  def terminate(_, state) do
    state
  end

  defp save_flow(down, up, state(up: pup, down: pdown, flow_time: ft)=s) do
    tick = System.system_time(:milliseconds)
    case {pup+up, pdown+down} do
      {u, d} when u > @min_flow or d > @min_flow or tick - ft > @min_time ->
        Shadowsocks.Event.flow(state(s, :port), d, u)
        state(s, up: 0, down: 0, flow_time: tick)
      {u,d} ->
        state(s, up: u, down: d)
    end
  end

  defp start_udprelay(%{udp: true}=args) do
    Shadowsocks.UDPRelay.start_link(args)
  end
  defp start_udprelay(_) do
    {:ok, nil}
  end

  defp merge_args(old_args, args) do
    Map.merge(old_args, args)
    |> validate_arg(:port, :required)
    |> validate_arg(:port, &is_integer/1)
    |> validate_arg(:method, :required)
    |> downcase(:method)
    |> validate_arg(:method, Shadowsocks.Encoder.methods())
    |> validate_arg(:password, :required)
    |> validate_arg(:password, &is_binary/1)
    |> validate_arg(:type, &is_atom/1)
    |> validate_arg(:ota, [true, false])
    |> case do
         %{type: :client}=m ->
           m
           |> validate_arg(:server, :required)
           |> validate_arg(:server, &is_tuple/1)
         m -> m
       end
    |> case do
         %{type: :client}=m -> %{m | type: Shadowsocks.Conn.Client}
         %{type: :server}=m -> %{m | type: Shadowsocks.Conn.Server}
         %{type: mod}=m when is_atom(mod) ->
           unless Code.ensure_compiled?(mod) do
             raise ArgumentError, message: "bad arg type, need :client / :server / module"
           end
           m
         _ -> raise ArgumentError, message: "bad arg type, need :client / :server / module"
       end
    |> case do
         %{server: {domain, port}}=m when is_binary(domain) ->
           %{m | server: {String.to_charlist(domain), port}}
         m -> m
       end
  end

  defp validate_arg(arg, key, :required) do
    unless Map.has_key?(arg, key) do
      raise ArgumentError, message: "required #{key}"
    end
    arg
  end
  defp validate_arg(arg, key, fun) when is_function(fun) do
    unless fun.(arg[key]) do
      raise ArgumentError, message: "bad arg #{key} : #{arg[key]}"
    end
    arg
  end
  defp validate_arg(arg, key, values) when is_list(values) do
    unless Enum.any?(values, &(&1 == arg[key])) do
      raise ArgumentError, message: "bad arg #{key} : #{arg[key]}, accept values: #{inspect values}"
    end
    arg
  end
  defp downcase(arg, key), do: Map.put(arg, key, String.downcase(arg[key]))
end
