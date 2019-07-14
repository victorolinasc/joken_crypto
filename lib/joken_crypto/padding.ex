defmodule JokenCrypto.Padding do
  @moduledoc """
  Behaviour for implementing padding specifications.
  """

  @doc """
  Pads an input
  """
  @callback pad(input :: binary(), opts :: keyword()) :: binary()

  @doc """
  Unpads an input
  """
  @callback unpad(input :: binary(), opts :: keyword()) :: binary()
end
