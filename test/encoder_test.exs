defmodule EncoderTest do
  use ExUnit.Case
  alias Shadowsocks.Encoder

  doctest Shadowsocks.Encoder

  @data <<"test hello world", 10, 0, 20, "ok">>
  @pass "mypassword-test-hello-world,01234567890"

  test "bad methods" do
    assert_raise FunctionClauseError, fn -> Encoder.init("bad-method", "sss") end
  end

  test "init" do
    Encoder.init("rc4-md5", @pass)
  end

  test "rc4-md5" do
    e = Encoder.init("rc4-md5", @pass)
    {e, d} = Encoder.encode(e, @data)
    {_, d} = Encoder.decode(e, d)
    assert @data == d
  end

  test "aes-128-cfb" do
    e = Encoder.init("aes-128-cfb", @pass)
    {e, d} = Encoder.encode(e, @data)
    {_, d} = Encoder.decode(e, d)
    assert @data == d
  end

  test "aes-256-cfb" do
    e = Encoder.init("aes-256-cfb", @pass)
    {e, d} = Encoder.encode(e, @data)
    <<iv::binary-size(16), d::binary>> = d
    {_, d} = e |> Encoder.init_decode(iv) |> Encoder.decode(d)

    assert @data == d
  end

  test "decode from other app" do
    origin = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    e = Encoder.init("aes-256-cfb", "mypass")
    <<d3::binary-size(20), d4::binary>> = File.read!("test/50F_aes256cfb.data")
    {e, r3} = Encoder.decode(e, d3)
    {_, r4} = Encoder.decode(e, d4)
    IO.inspect r3
    assert origin == <<r3::binary, r4::binary>>
  end
end
