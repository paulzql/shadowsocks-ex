defmodule Shadowsocks.Stream do
  defstruct sock: nil, encoder: nil, ota_iv: nil, ota_id: -1, ota: false

  @recv_timeout 180000

  def send(%{sock: sock, encoder: encoder}=stream, data) do
    {encoder, data} = Shadowsocks.Encoder.encode(encoder, data)
    stream = %Shadowsocks.Stream{stream | encoder: encoder}
    case :gen_tcp.send(sock, data) do
      :ok ->
        {:ok, stream}
      {:error, _err} ->
        {:error, stream}
    end
  end
  def send(sock, data) do
    case :gen_tcp.send(sock, data) do
      :ok ->
        {:ok, sock}
      {:error, _err} ->
        {:error, sock}
    end
  end

  def async_send(%{sock: sock, encoder: encoder}=stream, data) do
    {encoder, data} = Shadowsocks.Encoder.encode(encoder, data)
    async_send(sock, data)
    %Shadowsocks.Stream{stream | encoder: encoder}
  end
  def async_send(sock, data) do
    try do
      :erlang.port_command(sock, data, [])
    catch
      _ ->
        Kernel.send self(), {:error, sock}
    end
    sock
  end

  def recv(%{sock: sock, encoder: encoder}=stream, size, timeout) do
    with {:ok, data} <- wait_data(sock, size, timeout),
         {encoder, data} <- Shadowsocks.Encoder.decode(encoder, data) do
      {:ok, %Shadowsocks.Stream{stream | encoder: encoder}, data}
    else
      {:error, err} ->
        {:error, stream, err}
    end
  end
  def recv(sock, size, timeout) do
    {ret, data} = wait_data(sock, size, timeout)
    {ret, sock, data}
  end

  def recv(self, size) do
    Shadowsocks.Stream.recv(self, size, -1)
  end

  defp wait_data(sock, size, timeout) do
    case :prim_inet.async_recv(sock, size, timeout) do
      {:ok, ref} ->
	    receive do
	      {:inet_async, ^sock, ^ref, info} -> info;
	      {:"EXIT", ^sock, _Reason} ->
	        {:error, :closed}
          {:inet_reply, _, _} ->
            wait_data(sock, size, timeout)
          err ->
            err
        end
      err ->
        err
    end
  end

  def recv!(self, size) do
    {:ok, stream, data} = Shadowsocks.Stream.recv(self, size, @recv_timeout)
    {stream, data}
  end

  def send!(self, data) do
    {:ok, stream} = Shadowsocks.Stream.send(self, data)
    stream
  end
end
