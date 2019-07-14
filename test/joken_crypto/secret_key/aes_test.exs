defmodule JokenCrypto.SK.BlockCipher.AESTest do
  use ExUnit.Case, async: true

  alias JokenCrypto.SK.BlockCipher.AES
  alias Test.CLIOpenSSL

  @key_128 :crypto.strong_rand_bytes(16)
  @key_192 :crypto.strong_rand_bytes(24)
  @key_256 :crypto.strong_rand_bytes(32)

  @ivec :crypto.strong_rand_bytes(16)

  @tag :openssl
  describe "ECB mode" do
    test "encrypts using 128 bits the same as OpenSSL" do
      result = AES.encrypt("hello", @key_128, :ecb)
      ossl_result = CLIOpenSSL.encrypt("hello", "-aes-128-ecb", @key_128)
      assert result.ciphertext == ossl_result
      assert result.key |> bit_size() == 128
      assert result.mode == :ecb
      assert result.plaintext == "hello"
      assert result.ivec == nil
    end

    test "encrypts using 192 bits the same as OpenSSL" do
      result = AES.encrypt("hello", @key_192, :ecb)
      ossl_result = CLIOpenSSL.encrypt("hello", "-aes-192-ecb", @key_192)
      assert result.ciphertext == ossl_result
      assert result.key |> bit_size() == 192
      assert result.mode == :ecb
      assert result.plaintext == "hello"
      assert result.ivec == nil
    end

    test "encrypts using 256 bits the same as OpenSSL" do
      result = AES.encrypt("hello", @key_256, :ecb)
      ossl_result = CLIOpenSSL.encrypt("hello", "-aes-256-ecb", @key_256)
      assert result.ciphertext == ossl_result
      assert result.key |> bit_size() == 256
      assert result.mode == :ecb
      assert result.plaintext == "hello"
      assert result.ivec == nil
    end

    test "decrypts OpenSSL 128 bit key generated ciphertext" do
      ossl_result = CLIOpenSSL.encrypt("hello", "-aes-128-ecb", @key_128)
      result = AES.decrypt(ossl_result, @key_128, :ecb)
      assert result.ciphertext == ossl_result
      assert result.key |> bit_size() == 128
      assert result.mode == :ecb
      assert result.plaintext == "hello"
      assert result.ivec == nil
    end

    test "decrypts OpenSSL 192 bit key generated ciphertext" do
      ossl_result = CLIOpenSSL.encrypt("hello", "-aes-192-ecb", @key_192)
      result = AES.decrypt(ossl_result, @key_192, :ecb)
      assert result.ciphertext == ossl_result
      assert result.key |> bit_size() == 192
      assert result.mode == :ecb
      assert result.plaintext == "hello"
      assert result.ivec == nil
    end

    test "decrypts OpenSSL 256 bit key generated ciphertext" do
      ossl_result = CLIOpenSSL.encrypt("hello", "-aes-256-ecb", @key_256)
      result = AES.decrypt(ossl_result, @key_256, :ecb)
      assert result.ciphertext == ossl_result
      assert result.key |> bit_size() == 256
      assert result.mode == :ecb
      assert result.plaintext == "hello"
      assert result.ivec == nil
    end
  end

  @tag :openssl
  describe "CBC mode" do
    test "encrypts using 128 bits the same as OpenSSL" do
      result = AES.encrypt("hello", @key_128, :cbc, ivec: @ivec)
      ossl_result = CLIOpenSSL.encrypt("hello", "-aes-128-cbc", @key_128, @ivec)
      assert result.ciphertext == ossl_result
      assert result.key |> bit_size() == 128
      assert result.mode == :cbc
      assert result.plaintext == "hello"
      assert result.ivec == @ivec
    end

    test "encrypts using 192 bits the same as OpenSSL" do
      result = AES.encrypt("hello", @key_192, :cbc, ivec: @ivec)
      ossl_result = CLIOpenSSL.encrypt("hello", "-aes-192-cbc", @key_192, @ivec)
      assert result.ciphertext == ossl_result
      assert result.key |> bit_size() == 192
      assert result.mode == :cbc
      assert result.plaintext == "hello"
      assert result.ivec == @ivec
    end

    test "encrypts using 256 bits the same as OpenSSL" do
      result = AES.encrypt("hello", @key_256, :cbc, ivec: @ivec)
      ossl_result = CLIOpenSSL.encrypt("hello", "-aes-256-cbc", @key_256, @ivec)
      assert result.ciphertext == ossl_result
      assert result.key |> bit_size() == 256
      assert result.mode == :cbc
      assert result.plaintext == "hello"
      assert result.ivec == @ivec
    end

    test "decrypts OpenSSL 128 bit key generated ciphertext" do
      ossl_result = CLIOpenSSL.encrypt("hello", "-aes-128-cbc", @key_128, @ivec)
      result = AES.decrypt(ossl_result, @key_128, :cbc, ivec: @ivec)
      assert result.ciphertext == ossl_result
      assert result.key |> bit_size() == 128
      assert result.mode == :cbc
      assert result.plaintext == "hello"
      assert result.ivec == @ivec
    end

    test "decrypts OpenSSL 192 bit key generated ciphertext" do
      ossl_result = CLIOpenSSL.encrypt("hello", "-aes-192-cbc", @key_192, @ivec)
      result = AES.decrypt(ossl_result, @key_192, :cbc, ivec: @ivec)
      assert result.ciphertext == ossl_result
      assert result.key |> bit_size() == 192
      assert result.mode == :cbc
      assert result.plaintext == "hello"
      assert result.ivec == @ivec
    end

    test "decrypts OpenSSL 256 bit key generated ciphertext" do
      ossl_result = CLIOpenSSL.encrypt("hello", "-aes-256-cbc", @key_256, @ivec)
      result = AES.decrypt(ossl_result, @key_256, :cbc, ivec: @ivec)
      assert result.ciphertext == ossl_result
      assert result.key |> bit_size() == 256
      assert result.mode == :cbc
      assert result.plaintext == "hello"
      assert result.ivec == @ivec
    end
  end
end
