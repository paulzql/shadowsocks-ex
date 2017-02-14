defmodule Shadowsocks.ListenerSup do
  use Supervisor

  def start_link() do
    Supervisor.start_link(__MODULE__, [], name: Shadowsocks.ListenerSup)
  end

  def init([]) do
    children = [
      worker(Shadowsocks.Listener, [], restart: :transient, shutdown: 500)
    ]

    supervise(children, strategy: :simple_one_for_one)
  end
end
