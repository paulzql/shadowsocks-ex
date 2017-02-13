defmodule Shadowsocks do
  @moduledoc """
  Documentation for Shadowsocks.
  """

  @doc """
  Hello world.

  ## Examples

      iex> Shadowsocks.hello
      :world

  """
  def hello do
    :world
  end

  def start(opts) do
    :todo
  end

  def start_server(port, pass, opts) do
    :todo
  end

  def start_client(port, pass, server, opts) do
    :todo
  end

  def test() do
    Shadowsocks.Listener.start_link(type: :server, port: 8889, method: "aes-128-cfb", password: "pass1", ota: true)
  end

end
