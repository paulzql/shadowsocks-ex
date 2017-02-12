defmodule Shadowsocks.Listener do
  use GenServer
  require Shadowsocks.Event
  import Record

  defrecordp :state, lsock: nil, args: nil, port: nil

  @opts [:binary, {:backlog, 20},{:nodelay, true}, {:active, false}, {:packet, :raw},{:reuseaddr, true},{:send_timeout_close, true}]

  def update(pid, args) do
    GenServer.call pid, {:update, args}
  end

  def start_link(args) when is_list(args) do
    Enum.into(args, %{}) |> start_link
  end
  def start_link(args) do
    GenServer.start_link(__MODULE__, args)
  end

  def init(args) do
    Process.flag(:trap_exit, true)

    args = if Map.has_key?(args, :method) do args else Map.put(args, :method, "aes-256-cfb") end
    opts = case args do
             %{ip: ip} ->
               [{:ip, ip}|@opts]
             _->
               @opts
           end
    case :gen_tcp.listen(args.port, opts) do
      {:ok, lsock} ->
        case :prim_inet.async_accept(lsock, -1) do
          {:ok, _} ->
            Shadowsocks.Event.start_listener(args.port)
            {:ok, state(lsock: lsock, args: args, port: args.port)}
          {:error, error} ->
            {:stop, error}
        end
      error ->
        {:stop, error}
    end
  end

  def handle_call({:update, args}, _from, state(args: old_args)=state) do
    args = Enum.filter(args, fn(k)-> :method==k or :password==k end)
    state(state, args: Enum.into(args, old_args))
  end

  def handle_info({:inet_async, _, _, {:ok, csock}}, state) do
    true = :inet_db.register_socket(csock, :inet_tcp)
    {:ok, {addr, _}} = :inet.peername(csock)
    Shadowsocks.Event.accept(state.port, addr)
    {:ok, pid} = Shadowsocks.Conn.start_link(csock, state.args)
    case :gen_tcp.controlling_process(csock, pid) do
      :ok ->
        send pid, {:shoot, csock}
      {:error, _} ->
        Process.exit(pid, :kill)
        :gen_tcp.close(csock)
    end
    case :prim_inet.async_accept(state.lsock, -1) do
      {:ok, _} ->
        {:noreply, state}
      {:error, ref} ->
        {:stop, {:async_accept, :inet.format_error(ref)}, state}
    end

  end

  def handle_info({:inet_async, _lsock, _ref, error}, state) do
    {:stop, error, state}
  end

  def handle_info({:EXIT, _pid, _reason}, state) do
    {:noreply, state}
  end

end
