defmodule JokenCrypto.BlockCipher do
  @moduledoc """
  Defines the operations for a block cipher.

  In cryptography, a block cipher is a deterministic algorithm operating 
  on fixed-length groups of bits, called a block, with an unvarying transformation
  that is specified by a symmetric key. Block ciphers operate as important 
  elementary components in the design of many cryptographic protocols, and are 
  widely used to implement encryption of bulk data. 

  > https://en.wikipedia.org/wiki/Block_cipher

  ## Modes of operation

  Block ciphers use modes of operation to ensure they can operate on data bigger
  than its block size. Those modes have additional parameters associated with them
  like:
    - IV (initialization vector)
    - Padding scheme
    - Authentication tag

  > In Erlang/OTP `:crypto` modes are part of the block cipher name like 
  > `:aes_gcm`.

  ## Instrospection

  This protocol provides some introspection to help documenting and developing
  tools around each implementation.

    - modes of operation supported
    - custom options provided
    - key type and key size supported

  ## Default options

  Every implementation is expected to handle the following options:

    - `padding`: padding implementation
    - `ivec`: initialization vector
    - `aad`: associated authentication data
  """

  alias JokenCrypto.Padding.PKCS7

  defmodule Result do
    @moduledoc """
    Holds the results and options used to generate those results for block ciphers.

    For some modes, some fields will be empty (like with ECB there will be no IVec).
    """

    @type t :: %__MODULE__{
            name: module(),
            mode: atom(),
            padding: module(),
            padding_options: keyword(),
            key: binary(),
            ivec: binary(),
            aad: binary(),
            plaintext: binary(),
            ciphertext: binary(),
            ciphertag: binary()
          }

    defstruct name: nil,
              mode: nil,
              padding: PKCS7,
              padding_options: [],
              key: nil,
              ivec: nil,
              aad: nil,
              plaintext: nil,
              ciphertext: nil,
              ciphertag: nil
  end

  @doc """
  Returns the name of the block cipher implementation. For example:
    - `:aes`
    - `:des`
    - `:3des`
  """
  @callback name() :: atom()

  @doc """
  Returns which modes of operation it supports.
  """
  @callback modes_of_operation_supported :: list(atom())

  @doc """
  Performs encryption of `plaintext` using the given `key` with `opts`.
  """
  @callback encrypt(plaintext :: binary(), key :: binary(), mode :: atom(), opts :: keyword()) ::
              Result.t()

  @doc """
  Performs decryption of `ciphertext` using the given `key` with `opts`.
  """
  @callback decrypt(ciphertext :: binary(), key :: binary(), opts :: keyword) :: Result.t()
end
