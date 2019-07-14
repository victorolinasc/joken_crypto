defmodule JokenCrypto.PublicKey do
  @moduledoc """
  Public-key cryptography, or asymmetric cryptography, is a cryptographic 
  system that uses pairs of keys: public keys which may be disseminated 
  widely, and private keys which are known only to the owner.

  > https://en.wikipedia.org/wiki/Public-key_cryptography
  """

  # @callback encrypt_private(cipher, key, plaintext, opts)
  # @callback encrypt_public(cipher, key, plaintext, opts)
  # @callback decrypt_private(cipher, key, ciphertext, opts)
  # @callback decrypt_public(cipher, key, ciphertext, opts)

  # @callback sign(cipher, key, plaintext, opts)
  # @callback verify(cipher, key, signature, opts)
end
