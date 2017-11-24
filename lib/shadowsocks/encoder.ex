defmodule Shadowsocks.Encoder do
  import Bitwise
  alias Shadowsocks.Encoder
  defstruct method: nil,key: nil, enc_iv: nil, dec_iv: nil, enc_stream: nil, dec_stream: nil, enc_rest: <<>>, dec_rest: {<<>>, 0}, type: :stream

  @type t :: %Shadowsocks.Encoder{}

  # {method, {key_len, iv_len}, crypto_type}
  @methods %{
    "rc4-md5" => {:rc4_md5, {16, 16}, :stream},
    "aes-128-ctr" => {:aes_128_ctr, {16, 16}, :stream},
    "aes-192-ctr" => {:aes_192_ctr, {24, 16}, :stream},
    "aes-256-ctr" => {:aes_256_ctr, {32, 16}, :stream},
    "aes-128-cfb" => {:aes_128_cfb, {16, 16}, :block},
    "aes-192-cfb" => {:aes_192_cfb, {24, 16}, :block},
    "aes-256-cfb" => {:aes_256_cfb, {32, 16}, :block},
    "aead-aes-128-gcm" => {:aead_aes_128_gcm, {16, 16}, :aead},
    "aead-aes-192-gcm" => {:aead_aes_192_gcm, {24, 24}, :aead},
    "aead-aes-256-gcm" => {:aead_aes_256_gcm, {32, 32}, :aead}
  }

  @aead_tag_len   16
  @aead_nonce_len 12

  defmodule AEADState do
    @enforce_keys [:method, :key, :chunk]
    defstruct method: nil, key: nil, ctr: 0, chunk: nil
    @type t :: %AEADState{
      method: :aes_gcm,
      key:    binary,
      ctr:    non_neg_integer,
      chunk:  {:frame_len | :frame_data, non_neg_integer}
    }
  end

  @doc """
  get all supported method name
  """
  def methods(), do: Map.keys(@methods)

  @doc """
  init encoder by method and password
  """
  def init(method, pass) do
    {method, kv_len, type} = @methods[method]

    {key, iv} = gen_key_iv(kv_len, pass)

    %Shadowsocks.Encoder{method: method,
                         type: type,
                         key: key,
                         enc_iv: iv,
                         enc_stream: init_stream(method, key, iv)}
  end

  @doc """
  init decode meta info base on encoder
  """
  def init_decode(%Encoder{method: method, key: key}=encoder, iv) do
    %Encoder{encoder | dec_iv: iv, dec_stream: init_stream(method, key, iv)}
  end

  @doc """
  encode for stream package
  """
  def encode(%Encoder{type: :stream, enc_stream: stream}=encoder, data) do
    {stream, enc_data} = :crypto.stream_encrypt(stream, data)
    {%Encoder{encoder | enc_stream: stream}, enc_data}
  end
  def encode(%Encoder{type: :aead, enc_stream: aead_state}=encoder, data) do
    {aead_state, enc_data} = encode_aead(aead_state, data, IO.iodata_length(data), [])
    {%Encoder{encoder | enc_stream: aead_state}, enc_data}
  end
  def encode(%Encoder{type: :block, method: method, key: key, enc_iv: iv, enc_rest: rest}=encoder, data)
  when method in [:aes_128_cfb, :aes_192_cfb, :aes_256_cfb] do
    data = IO.iodata_to_binary(data)
    dsize = byte_size(data)
    rsize = byte_size(rest)
    len = div((dsize+rsize), 16) * 16
    <<data::binary-size(len), rest::binary>> = <<rest::binary, data::binary>>

    enc_data = :crypto.block_encrypt(:aes_cfb128, key, iv, data)
    iv = :binary.part(<<iv::binary, enc_data::binary>>, byte_size(enc_data)+16, -16)
    enc_rest = :crypto.block_encrypt(:aes_cfb128, key, iv, rest)
    ret = :binary.part(<<enc_data::binary, enc_rest::binary>>, rsize, dsize)
    {%Encoder{encoder | enc_iv: iv, enc_rest: rest}, ret}
  end

  defp encode_aead(state, _data, 0,   res_data_acc) do
    {state, Enum.reverse(res_data_acc)}
  end
  defp encode_aead(state,  data, len, res_data_acc) do
    {chunk_data, chunk_len, rest_data} = cond do
      len > 0x4000 ->
        << long_chunk_data::binary-size(0x3FFF), long_rest_data::binary >> = IO.iodata_to_binary(data)
        {long_chunk_data, 0x3FFF, long_rest_data}
      true ->
        {data, len, nil}
    end
    %AEADState{method: method, key: key, ctr: ctr} = state
    chunk_len_bin = <<0::2, chunk_len::14>>
    {enc_len,  enc_len_tag}  = :crypto.block_encrypt(method, key, aead_nonce(ctr+0), {<<>>, chunk_len_bin, @aead_tag_len})
    {enc_data, enc_data_tag} = :crypto.block_encrypt(method, key, aead_nonce(ctr+1), {<<>>, chunk_data,    @aead_tag_len})
    res_data_acc = [[enc_len, enc_len_tag, enc_data, enc_data_tag] | res_data_acc]
    encode_aead(%AEADState{state | ctr: ctr + 2}, rest_data, len - chunk_len, res_data_acc)
  end

  @doc """
  decode for stream package
  """
  def decode(%Encoder{type: :stream, dec_stream: stream}=encoder, data) do
    {stream, dec_data} = :crypto.stream_decrypt(stream, data)
    {%Encoder{encoder | dec_stream: stream}, dec_data}
  end
  def decode(%Encoder{type: :aead, dec_stream: aead_state, dec_rest: {rest, rsize}}=encoder, data) do
    data_size = IO.iodata_length(data)
    new_data = case {rsize, data_size} do
                 {0, 0} -> []
                 {0, _} -> data
                 {_, 0} -> rest
                 {_, _} -> [rest, data]
               end
    {aead_state, {new_rest, new_rsize}, dec_data} = decode_aead(aead_state, new_data, rsize + data_size, [])
    {%Encoder{encoder | dec_stream: aead_state, dec_rest: {new_rest, new_rsize}}, IO.iodata_to_binary(dec_data)}
  end
  def decode(%Encoder{type: :block, method: method, key: key, dec_iv: iv, dec_rest: {rest, rsize}}=encoder, data)
  when method in [:aes_128_cfb, :aes_192_cfb, :aes_256_cfb] do
    dsize = byte_size(data)
    len = div((dsize+rsize), 16) * 16
    <<data::binary-size(len), rest::binary>> = <<IO.iodata_to_binary(rest)::binary, data::binary>>

    dec_data = :crypto.block_decrypt(:aes_cfb128, key, iv, data)
    iv = :binary.part(<<iv::binary, data::binary>>, byte_size(data)+16, -16)
    dec_rest = :crypto.block_decrypt(:aes_cfb128, key, iv, rest)
    ret = :binary.part(<<dec_data::binary, dec_rest::binary>>, rsize, dsize)
    {%Encoder{encoder | dec_iv: iv, dec_rest: {rest, byte_size(rest)}}, ret}
  end

  defp decode_aead(%AEADState{chunk: {_, chunk_data_size}}=state, acc, acc_size, res_data_acc)
  when acc_size < (chunk_data_size + @aead_tag_len) do
    {state, {acc, acc_size}, Enum.reverse(res_data_acc)}
  end
  defp decode_aead(state, acc, _acc_size, res_data_acc) do
    %AEADState{method: method, key: key, ctr: ctr, chunk: {_, chunk_data_size}} = state
    <<enc_chunk_data :: binary-size(chunk_data_size),
      chunk_tag      :: binary-size(@aead_tag_len),
      acc            :: binary
    >> = IO.iodata_to_binary(acc)
    case :crypto.block_decrypt(method, key, aead_nonce(ctr), {<<>>, enc_chunk_data, chunk_tag}) do
      :error ->
        exit(:decrypt_error)
      <<chunk_data::binary>> ->
        {state, res_data} = decode_aead_chunk(%AEADState{state | ctr: ctr+1}, chunk_data)
        decode_aead(state, acc, byte_size(acc), [res_data | res_data_acc])
    end
  end
  defp decode_aead_chunk(%AEADState{chunk: {:frame_len,  2}}=state, <<0::2, frame_data_size::14>>) do
    {%AEADState{state | chunk: {:frame_data, frame_data_size}}, <<>>}
  end
  defp decode_aead_chunk(%AEADState{chunk: {:frame_data, _frame_len}}=state, frame_data) do
    {%AEADState{state | chunk: {:frame_len, 2}}, frame_data}
  end

  @doc """
  encode for dgram package
  """
  def encode_once(%Encoder{type: :stream, method: method, key: key, enc_iv: eiv}, data) do
    iv = :crypto.strong_rand_bytes(byte_size(eiv))
    enc_data =
      init_stream(method, key, iv)
      |> :crypto.stream_encrypt(data)
      |> elem(1)
    <<iv::binary, enc_data::binary>>
  end
  def encode_once(%Encoder{type: :aead, method: method, key: key, enc_iv: eiv}, data) do
    iv = :crypto.strong_rand_bytes(byte_size(eiv))
    %AEADState{method: aead_method, key: aead_key} = init_stream(method, key, iv)
    {enc_data, enc_data_tag} = :crypto.block_encrypt(aead_method, aead_key, aead_nonce(0), {<<>>, data})
    [iv, enc_data, enc_data_tag]
  end
  def encode_once(%Encoder{type: :block, method: method, key: key, enc_iv: eiv}, data)
  when method in [:aes_128_cfb, :aes_192_cfb, :aes_256_cfb] do
    ivlen = byte_size(eiv)
    iv = :crypto.strong_rand_bytes(ivlen)
    len = div(byte_size(data), 16) * 16
    <<data2::binary-size(len), rest::binary>> = data

    enc_data = :crypto.block_encrypt(:aes_cfb128, key, iv, data2)
    rest_iv = :binary.part(<<iv::binary, enc_data::binary>>, byte_size(enc_data)+ivlen, -ivlen)
    enc_rest = :crypto.block_encrypt(:aes_cfb128, key, rest_iv, rest)
    :binary.part(<<iv::binary, enc_data::binary, enc_rest::binary>>, 0, byte_size(data)+ivlen)
  end

  @doc """
  decode for dgram package
  """
  def decode_once(%Encoder{type: :stream, method: method, key: key, enc_iv: eiv}, data) do
    ivlen = byte_size(eiv)
    <<iv::binary-size(ivlen), data::binary>> = data

    init_stream(method, key, iv)
    |> :crypto.stream_decrypt(data)
    |> elem(1)
  end
  def decode_once(%Encoder{type: :aead, method: method, key: key, enc_iv: eiv}, data) do
    ivlen = byte_size(eiv)
    payload_size = byte_size(data) - ivlen - @aead_tag_len
    <<iv::binary-size(ivlen), enc_payload::binary-size(payload_size), tag::binary-size(@aead_tag_len)>> = data
    %AEADState{method: aead_method, key: key} = init_stream(method, key, iv)
    case :crypto.block_decrypt(aead_method, key, aead_nonce(0), {<<>>, enc_payload, tag}) do
      :error -> exit(:decrypt_error)
      data   -> data
    end
  end
  def decode_once(%Encoder{type: :block, method: method, key: key, enc_iv: eiv}, data)
  when method in [:aes_128_cfb, :aes_192_cfb, :aes_256_cfb] do
    ivlen = byte_size(eiv)
    <<iv::binary-size(ivlen), data::binary>> = data

    dsize = byte_size(data)
    len = div(dsize, 16) * 16
    <<data2::binary-size(len), rest::binary>> = data

    dec_data = :crypto.block_decrypt(:aes_cfb128, key, iv, data2)
    iv = :binary.part(<<iv::binary, data2::binary>>, len+ivlen, -ivlen)
    dec_rest = :crypto.block_decrypt(:aes_cfb128, key, iv, rest)
    :binary.part(<<dec_data::binary, dec_rest::binary>>, 0, dsize)
  end

  defp aead_nonce(ctr) when ctr < (1 <<< @aead_nonce_len * 8) do
    len = @aead_nonce_len * 8
    <<ctr::little-size(len)>>
  end

  defp gen_key_iv({keylen, ivlen}, pass) do
    {gen_key(pass, keylen, <<>>), :crypto.strong_rand_bytes(ivlen)}
  end

  defp gen_key(_, keylen, acc) when byte_size(acc) >= keylen do
    <<key::binary-size(keylen), _::binary>> = acc
    key
  end
  defp gen_key(pass, keylen, acc) do
    digest = :crypto.hash(:md5, <<acc::binary, pass::binary>>)
    gen_key(pass, keylen, <<acc::binary, digest::binary>>)
  end

  defp init_stream(:rc4_md5, key, iv) do
    :crypto.stream_init(:rc4, :crypto.hash(:md5, <<key::binary, iv::binary>>))
  end
  defp init_stream(:aes_128_ctr, key, iv), do: :crypto.stream_init(:aes_ctr, key, iv)
  defp init_stream(:aes_192_ctr, key, iv), do: :crypto.stream_init(:aes_ctr, key, iv)
  defp init_stream(:aes_256_ctr, key, iv), do: :crypto.stream_init(:aes_ctr, key, iv)
  defp init_stream(method,       key, iv)
  when method in [:aead_aes_128_gcm, :aead_aes_192_gcm, :aead_aes_256_gcm] do
    aead_key = HKDF.expand(:sha, HKDF.extract(:sha, key, iv), byte_size(key), <<"ss-subkey">>)
    %AEADState{method: :aes_gcm, key: aead_key, chunk: {:frame_len, 2}}
  end
  defp init_stream(_, _, _), do: nil
end

