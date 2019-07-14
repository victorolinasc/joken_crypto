defmodule JokenCrypto.SK.BlockCipher.AES do
  @moduledoc """
  Block cipher implementation of AES (Advanced Encryption Standard).

  This implementation uses only what is available on `:crypto` module.

  ## Options

  Encrypt and decrypt operations accepts the following options:
    - `:padding` - module() (defaults: `JokenCrypto.Padding.PKCS7`)
    - `:ivec` - binary() (defaults are different per mode of operation)
    - `:aad` - binary() (defaults to cipher name with mode of operation)

  """

  alias JokenCrypto.BlockCipher.Result
  alias JokenCrypto.CryptoWrapper
  alias JokenCrypto.Padding.PKCS7

  @behaviour JokenCrypto.BlockCipher

  @supported_modes [:gcm, :ecb, :cbc, :ige, :cfb, :ccm]

  @result %Result{name: __MODULE__}

  @impl true
  def name, do: :aes

  @impl true
  def modes_of_operation_supported, do: @supported_modes

  @impl true
  def encrypt(plaintext, key, mode, opts \\ []) do
    with {:ok, crypto_mode, result} <- opts_for_mode(mode, key, @result, opts) do
      do_encrypt(crypto_mode, plaintext, key, %{result | plaintext: plaintext, key: key})
    end
  end

  @impl true
  def decrypt(ciphertext, key, mode, opts \\ []) do
    with {:ok, crypto_mode, result} <- opts_for_mode(mode, key, @result, opts) do
      do_decrypt(crypto_mode, ciphertext, key, %{result | ciphertext: ciphertext, key: key})
    end
  end

  # ECB
  defp opts_for_mode(:ecb, key, result, opts) when bit_size(key) in [128, 193, 256] do
    padding = opts[:padding] || PKCS7
    pad_opts = opts[:padding_options] || []
    {:ok, :aes_ecb, %{result | mode: :ecb, padding: padding, padding_options: pad_opts}}
  end

  # CBC
  defp opts_for_mode(:cbc, key, result, opts) when bit_size(key) in [128, 192, 256] do
    padding = opts[:padding] || PKCS7
    pad_opts = opts[:padding_options] || []
    ivec = opts[:ivec] || raise "missing initialization vector for CBC mode"

    if byte_size(ivec) != 16,
      do: raise("IV for CBC must be the same size of the block size (16 bytes for AES)")

    {:ok, :aes_cbc,
     %{result | mode: :cbc, padding: padding, padding_options: pad_opts, ivec: ivec}}
  end

  # Unknown
  defp opts_for_mode(_, _, _, _) do
    raise """
    invalid options for AES. 

    Please check:
      - keys for AES must be 128, 192 or 256 bits long;
      - Supported modes are: #{inspect(modes_of_operation_supported())};
    """
  end

  # ECB
  defp do_encrypt(:aes_ecb, plaintext, key, result) do
    padded_plaintext = result.padding.pad(plaintext, result.padding_options)
    ciphertext = CryptoWrapper.block_encrypt(:aes_ecb, key, padded_plaintext)
    %{result | ciphertext: ciphertext}
  end

  # CBC
  defp do_encrypt(:aes_cbc, plaintext, key, result) do
    padded_plaintext = result.padding.pad(plaintext, result.padding_options)
    ciphertext = CryptoWrapper.block_encrypt(:aes_cbc, key, result.ivec, padded_plaintext)
    %{result | ciphertext: ciphertext}
  end

  # ECB
  defp do_decrypt(:aes_ecb, ciphertext, key, result) do
    padded_plaintext = CryptoWrapper.block_decrypt(:aes_ecb, key, ciphertext)
    plaintext = result.padding.unpad(padded_plaintext, result.padding_options)
    %{result | plaintext: plaintext}
  end

  # CBC
  defp do_decrypt(:aes_cbc, ciphertext, key, result) do
    padded_plaintext = CryptoWrapper.block_decrypt(:aes_cbc, key, result.ivec, ciphertext)
    plaintext = result.padding.unpad(padded_plaintext, result.padding_options)
    %{result | plaintext: plaintext}
  end
end
