defmodule UDPRelayTest do
  use ExUnit.Case
  alias Shadowsocks.Encoder
  alias Shadowsocks.Protocol

  @data <<"test hello world", 10, 0, 20, "ok">>
  @pass "mypassword-test-hello-world,01234567890"
  @method "aes-128-cfb"
  @addr {192,168,11,23}
  @port 20201

  test "test encode once" do
    data =
      Encoder.init(@method, @pass)
      |> Encoder.encode_once(@data)
    data2 =
      Encoder.init(@method, @pass)
      |> Encoder.decode_once(data)

    assert @data == data2
  end

  test "encode and pack" do
    data =
      Encoder.init(@method, @pass)
      |> Encoder.encode_once(Protocol.pack(@addr, @port, @data))

    {addr, port, data2} =
      Encoder.init(@method, @pass)
      |> Encoder.decode_once(data)
      |> Protocol.unpack

    assert @addr == addr
    assert @port == port
    assert @data == data2
  end
end
