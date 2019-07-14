defmodule JokenCrypto.CryptoWrapperTest do
  use ExUnit.Case, async: true

  alias JokenCrypto.CryptoWrapper
  alias JokenCrypto.Padding.PKCS7

  @key :crypto.strong_rand_bytes(16)

  describe "block_encrypt/3,4" do
    test "succeeds for ecb without iv" do
      assert is_binary(CryptoWrapper.block_encrypt(:aes_ecb, @key, PKCS7.pad("Anything")))
    end

    test "succeeds for cbc" do
      assert is_binary(
               CryptoWrapper.block_encrypt(
                 :aes_cbc128,
                 @key,
                 :crypto.strong_rand_bytes(16),
                 PKCS7.pad("Anything")
               )
             )
    end

    test "raises more meaningful error when algorithm unknown" do
      assert_raise(RuntimeError, fn ->
        CryptoWrapper.block_encrypt(:unknown, @key, PKCS7.pad("Anything", nil))
      end).message =~ "the arguments passed to `:crypto` are not valid"
    end

    test "raises more meaningful error when input not padded" do
      assert_raise(RuntimeError, fn ->
        CryptoWrapper.block_encrypt(:aes_ecb, @key, "Anything")
      end).message =~ "the arguments passed to `:crypto` are not valid"
    end

    test "raises more meaningful error when key is not valid" do
      assert_raise(RuntimeError, fn ->
        CryptoWrapper.block_encrypt(:aes_ecb, :crypto.strong_rand_bytes(7), "Anything")
      end).message =~ "the arguments passed to `:crypto` are not valid"
    end

    test "raises more meaningful error when IVec is not valid" do
      assert_raise(RuntimeError, fn ->
        CryptoWrapper.block_encrypt(
          :aes_cbc128,
          @key,
          :crypto.strong_rand_bytes(7),
          PKCS7.pad("Anything")
        )
      end).message =~ "the arguments passed to `:crypto` are not valid"
    end
  end
end
