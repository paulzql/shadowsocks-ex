defmodule Shadowsocks.Application do
  # See http://elixir-lang.org/docs/stable/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  def start(_type, _args) do
    import Supervisor.Spec, warn: false

    # Define workers and child supervisors to be supervised
    children = [
      # Starts a worker by calling: Shadowsocks.Worker.start_link(arg1, arg2, arg3)
      # worker(Shadowsocks.Worker, [arg1, arg2, arg3]),
      worker(:gen_event, [{:local, Shadowsocks.Event}], modules: :dynamic),
      worker(Shadowsocks.BlackList, []),
      supervisor(Shadowsocks.ListenerSup, [])
    ]

    # See http://elixir-lang.org/docs/stable/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: Shadowsocks.Supervisor]

    with {:ok, pid} <- Supervisor.start_link(children, opts) do
      # start listeners from application env
      Application.get_env(:shadowsocks, :listeners, [])
      |> Enum.reduce_while({:ok, pid}, fn(args, acc)->
        case Shadowsocks.start(args) do
          {:ok, _} -> {:cont, acc}
          error -> {:halt, error}
        end
      end) # end reduce
    end # end with

  end
end
