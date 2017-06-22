defmodule Shadowsocks.Encoder do
  alias Shadowsocks.Encoder
  defstruct method: nil,key: nil, enc_iv: nil, dec_iv: nil, enc_stream: nil, dec_stream: nil, iv_sent: false, enc_rest: <<>>, dec_rest: <<>>

  @methods %{
    "rc4-md5" => :rc4_md5,
    "aes-128-ctr" => :aes_128_ctr,
    "aes-192-ctr" => :aes_192_ctr,
    "aes-256-ctr" => :aes_256_ctr,
    "aes-128-cfb" => :aes_128_cfb,
    "aes-192-cfb" => :aes_192_cfb,
    "aes-256-cfb" => :aes_256_cfb
  }

  @key_iv_len %{
    rc4_md5: {16, 16},
    aes_128_ctr: {16, 16},
    aes_192_ctr: {24, 16},
    aes_256_ctr: {32, 16},
    aes_128_cfb: {16, 16},
    aes_192_cfb: {24, 16},
    aes_256_cfb: {32, 16}
  }

  def methods(), do: Map.keys(@methods)

  def init(method, pass) do
    method = @methods[method]
    {key, iv} = @key_iv_len[method] |> gen_key_iv(pass)
    %Shadowsocks.Encoder{method: method,
                         key: key,
                         enc_iv: iv,
                         enc_stream: init_stream(method, key, iv)}
  end

  def init_decode(%Encoder{method: method, key: key}=encoder, iv) do
    %Encoder{encoder | dec_iv: iv, dec_stream: init_stream(method, key, iv)}
  end

  def encode(%Encoder{enc_stream: stream}=encoder, data) when stream != nil do
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


  def decode(%Encoder{dec_stream: stream}=encoder, data) when stream != nil do
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

