defmodule JokenCrypto.SecretKey do
  @moduledoc """
  > Symmetric-key algorithms[a] are algorithms for cryptography that use 
  > the same cryptographic keys for both encryption of plaintext and 
  > decryption of ciphertext. -- https://en.wikipedia.org/wiki/Symmetric-key_algorithm
  """

  def encrypt(cipher, plaintext, key, mode, opts \\ []) do
    cipher.encrypt(plaintext, key, mode, opts)
  end

  def decrypt(cipher, plaintext, key, mode, opts \\ []) do
    cipher.decrypt(plaintext, key, mode, opts)
  end

  def authenticate, do: :ok

  def verify, do: :ok
end
