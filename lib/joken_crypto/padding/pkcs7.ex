defmodule JokenCrypto.Padding.PKCS7 do
  @moduledoc """
  Implementation of padding scheme defined in PKCS#7.

  https://tools.ietf.org/html/rfc2315

  Inspired by https://github.com/potatosalad/erlang-jose/blob/master/src/jose_jwa_pkcs7.erl
  """

  @behaviour JokenCrypto.Padding

  @impl true
  def pad(binary, _options \\ []) do
    size = 16 - rem(byte_size(binary), 16)
    do_pad(size, binary)
  end

  @impl true
  def unpad(binary, _options \\ []) do
    p = :binary.last(binary)
    s = byte_size(binary) - p

    case binary do
      <<bin::size(s)-binary, ^p>> ->
        bin

      <<bin::size(s)-binary, ^p, ^p>> ->
        bin

      <<bin::size(s)-binary, ^p, ^p, ^p>> ->
        bin

      <<bin::size(s)-binary, ^p, ^p, ^p, ^p>> ->
        bin

      <<bin::size(s)-binary, ^p, ^p, ^p, ^p, ^p>> ->
        bin

      <<bin::size(s)-binary, ^p, ^p, ^p, ^p, ^p, ^p>> ->
        bin

      <<bin::size(s)-binary, ^p, ^p, ^p, ^p, ^p, ^p, ^p>> ->
        bin

      <<bin::size(s)-binary, ^p, ^p, ^p, ^p, ^p, ^p, ^p, ^p>> ->
        bin

      <<bin::size(s)-binary, ^p, ^p, ^p, ^p, ^p, ^p, ^p, ^p, ^p>> ->
        bin

      <<bin::size(s)-binary, ^p, ^p, ^p, ^p, ^p, ^p, ^p, ^p, ^p, ^p>> ->
        bin

      <<bin::size(s)-binary, ^p, ^p, ^p, ^p, ^p, ^p, ^p, ^p, ^p, ^p, ^p>> ->
        bin

      <<bin::size(s)-binary, ^p, ^p, ^p, ^p, ^p, ^p, ^p, ^p, ^p, ^p, ^p, ^p>> ->
        bin

      <<bin::size(s)-binary, ^p, ^p, ^p, ^p, ^p, ^p, ^p, ^p, ^p, ^p, ^p, ^p, ^p>> ->
        bin

      <<bin::size(s)-binary, ^p, ^p, ^p, ^p, ^p, ^p, ^p, ^p, ^p, ^p, ^p, ^p, ^p, ^p>> ->
        bin

      <<bin::size(s)-binary, ^p, ^p, ^p, ^p, ^p, ^p, ^p, ^p, ^p, ^p, ^p, ^p, ^p, ^p, ^p>> ->
        bin

      <<bin::size(s)-binary, ^p, ^p, ^p, ^p, ^p, ^p, ^p, ^p, ^p, ^p, ^p, ^p, ^p, ^p, ^p, ^p>> ->
        bin
    end
  end

  defp do_pad(p = 1, bin), do: <<bin::binary, p>>
  defp do_pad(p = 2, bin), do: <<bin::binary, p, p>>
  defp do_pad(p = 3, bin), do: <<bin::binary, p, p, p>>
  defp do_pad(p = 4, bin), do: <<bin::binary, p, p, p, p>>
  defp do_pad(p = 5, bin), do: <<bin::binary, p, p, p, p, p>>
  defp do_pad(p = 6, bin), do: <<bin::binary, p, p, p, p, p, p>>
  defp do_pad(p = 7, bin), do: <<bin::binary, p, p, p, p, p, p, p>>
  defp do_pad(p = 8, bin), do: <<bin::binary, p, p, p, p, p, p, p, p>>
  defp do_pad(p = 9, bin), do: <<bin::binary, p, p, p, p, p, p, p, p, p>>
  defp do_pad(p = 10, bin), do: <<bin::binary, p, p, p, p, p, p, p, p, p, p>>
  defp do_pad(p = 11, bin), do: <<bin::binary, p, p, p, p, p, p, p, p, p, p, p>>
  defp do_pad(p = 12, bin), do: <<bin::binary, p, p, p, p, p, p, p, p, p, p, p, p>>
  defp do_pad(p = 13, bin), do: <<bin::binary, p, p, p, p, p, p, p, p, p, p, p, p, p>>
  defp do_pad(p = 14, bin), do: <<bin::binary, p, p, p, p, p, p, p, p, p, p, p, p, p, p>>
  defp do_pad(p = 15, bin), do: <<bin::binary, p, p, p, p, p, p, p, p, p, p, p, p, p, p, p>>
  defp do_pad(p = 16, bin), do: <<bin::binary, p, p, p, p, p, p, p, p, p, p, p, p, p, p, p, p>>
end
