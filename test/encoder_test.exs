defmodule EncoderTest do
  use ExUnit.Case
  alias Shadowsocks.Encoder

  doctest Shadowsocks.Encoder

  @data <<"test hello world", 10, 0, 20, "ok">>
  @pass "mypassword-test-hello-world,01234567890"

  test "bad methods" do
    assert_raise MatchError, fn -> Encoder.init("bad-method", "sss") end
  end

  test "init" do
    Encoder.init("rc4-md5", @pass)
  end

  test "rc4-md5" do
    e = Encoder.init("rc4-md5", @pass)
    {e, d} = Encoder.encode(e, @data)
    {_, d} = e |> Encoder.init_decode(e.enc_iv) |> Encoder.decode(d)
    assert @data == d
  end

  test "tt" do
    e1 = Encoder.init("aes-128-cfb", @pass)
    e2 = Encoder.init("aes-128-cfb", @pass) |> Encoder.init_decode(e1.enc_iv)

    {_, d1} = Encoder.encode(e1, @data)
    {_, d2} = Encoder.decode(e2, d1)
    assert d2 == @data
  end
  test "aes-128-cfb" do
    e1 = Encoder.init("aes-128-cfb", @pass)
    e2 = Encoder.init_decode(e1, e1.enc_iv)
    {_, d} = Encoder.encode(e1, @data)
    {_, d} = Encoder.decode(e2, d)
    assert @data == d
  end

  test "aes-256-cfb" do
    e1 = Encoder.init("aes-256-cfb", @pass)
    e2 = Encoder.init_decode(e1, e1.enc_iv)
    {_, d} = Encoder.encode(e1, @data)
    {_, d} = Encoder.decode(e2, d)
    assert @data == d
  end

  # test "decode from other app" do
  #   origin = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
  #   <<iv::binary-size(16), d4::binary>> = File.read!("test/50F_aes256cfb.data")
  #   e = Encoder.init("aes-256-cfb", "mypass") |> Encoder.init_decode(iv) |> IO.inspect
  #   {_, r4} = Encoder.decode(e, d4)

  #   assert origin == r4
  # end
end
