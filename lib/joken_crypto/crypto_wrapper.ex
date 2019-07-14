defmodule JokenCrypto.CryptoWrapper do
  @moduledoc """
  Wraps the `:crypto` module to ease interfacing with it.
  """

  def block_encrypt(alg, key, payload) do
    :crypto.block_encrypt(alg, key, payload)
  catch
    :error, :notsup -> raise_notsup(alg)
    :error, :badarg -> raise_badarg(alg)
  end

  def block_encrypt(alg, key, ivec, payload) do
    :crypto.block_encrypt(alg, key, ivec, payload)
  catch
    :error, :notsup -> raise_notsup(alg)
    :error, :badarg -> raise_badarg(alg)
  end

  def block_decrypt(alg, key, payload) do
    :crypto.block_decrypt(alg, key, payload)
  catch
    :error, :notsup -> raise_notsup(alg)
    :error, :badarg -> raise_badarg(alg)
  end

  def block_decrypt(alg, key, ivec, payload) do
    :crypto.block_decrypt(alg, key, ivec, payload)
  catch
    :error, :notsup -> raise_notsup(alg)
    :error, :badarg -> raise_badarg(alg)
  end

  defp raise_notsup(algo) do
    raise "the algorithm #{inspect(algo)} is not supported by your Erlang/OTP installation. " <>
            "Please make sure it was compiled with the correct OpenSSL/BoringSSL bindings"
  end

  defp raise_badarg(algo) do
    raise """
    the arguments passed to `:crypto` are not valid. Please make sure:
      - the algorithm is recognized by the OpenSSL/BoringSSL bindings (passed #{inspect(algo)});
      - the plaintext is properly padded (make sure you have a proper padding setting);
      - the key is of appropriate size;
    """
  end
end
