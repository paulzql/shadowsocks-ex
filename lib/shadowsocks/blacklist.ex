defmodule Shadowsocks.BlackList do
    use GenServer
    require Shadowsocks.Event

    @tab :ss_blacklist
    @cache_tab :ss_failed_ips
    @check_block_time 600 * 1000

    defmodule EventHandler do
        @behaviour :gen_event
    
        def init([pid]), do: {:ok, pid}
    
        def handle_event({:bad_request, _, saddr}, pid) do
          send pid, {:bad_request, saddr}
          {:ok, pid}
        end
        def handle_event(_event, pid) do
            {:ok, pid}
        end
        def handle_call(_, state), do: {:ok, :ok, state}
        def handle_info(_, state), do: {:ok, state}
        def terminate(_,_), do: :ok
        def code_change(_old_vsn, state, _extra), do: {:ok, state}
    end    
    @doc """
    check ip in blacklist?
    """
    @spec blocked?(tuple) :: boolean
    def blocked?(addr) do
        :ets.member(@tab, addr)
    end  
    @doc """
    add ip to blacklist's static rule
    """
    @spec add(tuple) :: boolean
    def add(addr) do
        add(addr, :static)
    end
    @doc """
    remove ip to blacklist
    """
    @spec del(tuple) :: boolean
    def del({a,b,c,d}) do
        # translate ipv4 to ipv6
        <<a1::16, a2::16>> = <<a::8, b::8, c::8, d::8>>
        :ets.delete(@tab, {0,0,0,0,0,0xFFFF, a1, a2})
        :ets.delete(@tab, {a,b,c,d})
    end
    def del(addr) do
        :ets.delete(@tab, addr)
    end
    @doc """
    clear blacklist
    """
    @spec clear(:static | :dynamic | :all) :: boolean
    def clear(:all) do
        :ets.delete(@tab)
    end
    def clear(:static) do
        :ets.match_delete(@tab, {:_, :static, :_})
    end
    def clear(:dynamic) do
        :ets.match_delete(@tab, {:_, :dynamic, :_})
    end
    def clear(_), do: false
    @doc """
    list block rules
    """
    @spec list() :: [{tuple, :static | :dynamic, integer}]
    def list() do
        :ets.tab2list(@tab)
    end

    def start_link, do: GenServer.start_link(__MODULE__, [], name: __MODULE__)
    def init([]) do
        @tab = :ets.new(@tab, [:set, 
                              :named_table, 
                              :public, 
                              {:read_concurrency, true}])
        :ets.new(@cache_tab, [:set, :protected, :named_table])
        with args <- Application.get_env(:shadowsocks, :dynamic_blocklist),
             true <- Keyword.keyword?(args),
             true <- Keyword.get(args, :enable, false),
             attack_times <- Keyword.get(args, :attack_times, 50),
             attack_time <- Keyword.get(args, :collect_duration, 3600*1000),
             block_time <- Keyword.get(args, :block_expire, 7 * 24 * 3600 * 1000) do
             block_expire = min(block_time, @check_block_time)
            :gen_event.add_handler(Shadowsocks.Event, EventHandler, [self()])
            Process.send_after self(), :attack_check, attack_time
            Process.send_after self(), :expire_check, block_expire
            {:ok, %{block_time: block_time, 
                    attack_time: attack_time, 
                    attack_times: attack_times, 
                    block_expire: block_expire}}
        else
            _ ->
                {:ok, %{}}
        end
    end

    def handle_info({:bad_request, addr}, %{attack_times: attack_times}=state) do
        case :ets.lookup(@cache_tab, addr) do
            [{_, times}] when times >= attack_times ->
                add(addr, :dynamic)
                Shadowsocks.Event.dynamic_blocked(addr)
                :ets.delete(@cache_tab, addr)
            [{_, times}] ->
                :ets.insert(@cache_tab, {addr, times+1})
            [] ->
                :ets.insert(@cache_tab, {addr, 1})
        end
        {:noreply, state}
    end
    def handle_info(:attack_check, %{attack_time: attack_time}=state) do
        :ets.delete(@cache_tab)
        Process.send_after self(), :attack_check, attack_time
        {:noreply, state}
    end
    def handle_info(:expire_check, %{block_time: block_time, block_expire: check_time}=state) do
        time = System.system_time(:milliseconds) - block_time
        :ets.select_delete(@tab, [{{:_, :dynamic, :"$1"}, [{:"<", :"$1", time}], [true]}])
        Process.send_after self(), :expire_check, check_time
        {:noreply, state}
    end
    def handle_info(_, state) do
        {:noreply, state}
    end

    def terminate(_, _) do
        :gen_event.delete_handler(Shadowsocks.Event, EventHandler, [self()])
    end

    defp add({a,b,c,d}, type) do
        # translate ipv4 to ipv6
        <<a1::16, a2::16>> = <<a::8, b::8, c::8, d::8>>
        :ets.insert(@tab, {{0,0,0,0,0,0xFFFF, a1, a2}, type, System.system_time(:milliseconds)})
        :ets.insert(@tab, {{a,b,c,d}, type, System.system_time(:milliseconds)})        
    end
    defp add(addr, type) do
        :ets.insert(@tab, {addr, type, System.system_time(:milliseconds)})
    end
end