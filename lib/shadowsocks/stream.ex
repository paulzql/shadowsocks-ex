defmodule Shadowsocks.Stream do
  defstruct sock: nil, encoder: nil, recv_rest: {<<>>, 0}, ota_iv: nil, ota_id: 0, ota: false

  @recv_timeout 180000
  @hmac_len 10

  @moduledoc """
  process stream transport and decode / encode
  """

  @doc """
  wirte data to stream, **bolcked**
  """
  def send(%{sock: sock}=stream, data) do
    {stream, data} = encode_ota(stream, data)
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

  @doc """
  wirte data to stream by async
  *note:* this method is copy data to socket driver.

  The sender process will received message: `{:inet_reply, socket, status}` when send has completed.

  The `recv` method receive and ignore `{:inet_reply, socket, status}` message. So, you should not care this message after you called `recv`, otherwise you must receive this message.
  """
  def async_send(%{sock: sock}=stream, data) do
    {stream, data} = encode_ota(stream, data)
    async_send(sock, data)
    stream
  end
  def async_send(sock, data) do
    try do
      :erlang.port_command(sock, data, [])
    rescue
      _e in ArgumentError ->
        Kernel.send self(), {:error, sock}
    catch
      _ ->
        Kernel.send self(), {:error, sock}
    end
    sock
  end

  @doc """
  receive and decode data
  *note* the size only can be 0 when OTA stream
  """
  def recv(%{ota: true, ota_id: id, ota_iv: iv, sock: sock, encoder: encoder}=stream, 0, timeout) do
    %Shadowsocks.Stream{recv_rest: {_, 0}} = stream
    with {:ok, data1} <- wait_data(sock, 2, timeout),
         {encoder, <<len::16>>} <- Shadowsocks.Encoder.decode(encoder, data1),
         {:ok, data2} <- wait_data(sock, @hmac_len+len, timeout),
         {encoder, <<hmac::binary-size(@hmac_len), data::binary>>} <- Shadowsocks.Encoder.decode(encoder, data2),
           ^hmac <- :crypto.hmac(:sha, [iv, <<id::32>>], data, @hmac_len) do
      {:ok, %Shadowsocks.Stream{stream | encoder: encoder, ota_id: id+1}, data}
    else
      {:error, err} ->
        {:error, stream, err}
      _ ->
        {:error, stream, :hmac}
    end
  end
  def recv(%{sock: _sock, encoder: _encoder, recv_rest: {acc, acc_size}}=stream, size, _timeout)
  when acc_size > 0 and acc_size >= size do
    {data, acc} =
      cond do
        size > 0 ->
          <<data::binary-size(size), acc::binary>> = IO.iodata_to_binary(acc)
          {data, acc}
        true -> {IO.iodata_to_binary(acc), <<>>}
      end
    {:ok, %Shadowsocks.Stream{stream | recv_rest: {acc, byte_size(acc)}}, data}
  end
  def recv(%{sock: sock, encoder: encoder, recv_rest: {acc, acc_size}}=stream, size, timeout) do
    with {:ok, data} <- wait_data(sock, size - acc_size, timeout),
         {encoder, data} <- Shadowsocks.Encoder.decode(encoder, data) do
      recv(%Shadowsocks.Stream{stream | encoder: encoder, recv_rest: {[acc, data], acc_size + byte_size(data)}}, size)
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

  def recv!(self, size) do
    {:ok, stream, data} = Shadowsocks.Stream.recv(self, size, @recv_timeout)
    {stream, data}
  end

  def send!(self, data) do
    {:ok, stream} = Shadowsocks.Stream.send(self, data)
    stream
  end

  defp wait_data(sock, size, timeout) do
    case :prim_inet.async_recv(sock, size, timeout) do
      {:ok, ref} ->
	    receive_data(sock, ref)
      err ->
        err
    end
  end

  defp receive_data(sock, ref) do
	receive do
	  {:inet_async, ^sock, ^ref, info} ->
        info;
	  {:"EXIT", ^sock, _Reason} ->
	    {:error, :closed}
      {:error, reason} -> {:error, reason}
      # {:inet_reply, _, _} ->
      _ ->
        receive_data(sock, ref)
    end
  end

  defp encode_ota(%{ota: true, ota_id: id, ota_iv: iv, encoder: encoder}=stream, data) do
    hmac = :crypto.hmac(:sha, [iv, <<id::32>>], data, @hmac_len)
    {encoder, data} = Shadowsocks.Encoder.encode(encoder, [<<byte_size(data)::16>>, hmac, data])
    {%Shadowsocks.Stream{stream | ota_id: id+1, encoder: encoder}, data}
  end
  defp encode_ota(%{encoder: encoder}=stream, data) do
    {encoder, data} = Shadowsocks.Encoder.encode(encoder, data)
    {%Shadowsocks.Stream{stream | encoder: encoder}, data}
  end
  defp encode_ota(s, data), do: {s, data}

end
