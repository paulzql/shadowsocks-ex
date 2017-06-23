defmodule Shadowsocks.Encoder do
  alias Shadowsocks.Encoder
  defstruct method: nil,key: nil, enc_iv: nil, dec_iv: nil, enc_stream: nil, dec_stream: nil, enc_rest: <<>>, dec_rest: <<>>, type: :stream

  @type t :: %Shadowsocks.Encoder{}

  # {method, {key_len, iv_len}, crypto_type}
  @methods %{
    "rc4-md5" => {:rc4_md5, {16, 16}, :stream},
    "aes-128-ctr" => {:aes_128_ctr, {16, 16}, :stream},
    "aes-192-ctr" => {:aes_192_ctr, {24, 16}, :stream},
    "aes-256-ctr" => {:aes_256_ctr, {32, 16}, :stream},
    "aes-128-cfb" => {:aes_128_cfb, {16, 16}, :block},
    "aes-192-cfb" => {:aes_192_cfb, {24, 16}, :block},
    "aes-256-cfb" => {:aes_256_cfb, {32, 16}, :block}
  }

  @doc """
  get all supported method name
  """
  def methods(), do: Map.keys(@methods)

  @doc """
  init encoder by method and password
  """
  def init(method, pass) do
    {method, kv_len, type} = @methods[method]

    method = @methods[method]
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
  def encode(%Encoder{key: key, enc_iv: iv, enc_rest: rest}=encoder, data) do
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

  @doc """
  decode for stream package
  """
  def decode(%Encoder{type: :stream, dec_stream: stream}=encoder, data) do
    {stream, dec_data} = :crypto.stream_decrypt(stream, data)
    {%Encoder{encoder | dec_stream: stream}, dec_data}
  end
  def decode(%Encoder{key: key, dec_iv: iv, dec_rest: rest}=encoder, data) do
    dsize = byte_size(data)
    rsize = byte_size(rest)
    len = div((dsize+rsize), 16) * 16
    <<data::binary-size(len), rest::binary>> = <<rest::binary, data::binary>>

    dec_data = :crypto.block_decrypt(:aes_cfb128, key, iv, data)
    iv = :binary.part(<<iv::binary, data::binary>>, byte_size(data)+16, -16)
    dec_rest = :crypto.block_decrypt(:aes_cfb128, key, iv, rest)
    ret = :binary.part(<<dec_data::binary, dec_rest::binary>>, rsize, dsize)
    {%Encoder{encoder | dec_iv: iv, dec_rest: rest}, ret}
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
  def encode_once(%Encoder{key: key, enc_iv: eiv}, data) do
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
  def decode_once(%Encoder{key: key, enc_iv: eiv}, data) do
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
  defp init_stream(_, _, _), do: nil
end

