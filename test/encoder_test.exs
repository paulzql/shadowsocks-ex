defmodule EncoderTest do
  use ExUnit.Case
  alias Shadowsocks.Encoder

  doctest Shadowsocks.Encoder

  @data <<"test hello world", 10, 0, 20, "ok">>
  @pass "mypassword"

  test "bad methods" do
    assert_raise FunctionClauseError, fn -> Encoder.init("bad-method", "sss") end
  end

  test "init" do
    Encoder.init("rc4-md5", @pass)
  end

  test "rc4-md5" do
    e = Encoder.init("rc4-md5", @pass)
    {e, d} = Encoder.encode(e, @data)
    {e, d} = Encoder.decode(e, d)
    assert @data == d
  end

  test "aes-128-cfb" do
    e = Encoder.init("aes-128-cfb", @pass)
    {e, d} = Encoder.encode(e, @data)
    {_, d} = Encoder.decode(e, d)
    assert @data == d
  end
end
