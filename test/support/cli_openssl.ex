defmodule Test.CLIOpenSSL do
  @moduledoc """
  A helper module to ensure the output of OpenSSL is the same as our current 
  implementation.

  It calls the OpenSSL library available on path. 
  """

  @openssl_ciphers :os.cmd('openssl enc -ciphers')
                   |> to_string()
                   |> String.split("\n")
                   |> Enum.map(&String.split(&1, "\s"))
                   |> List.flatten()
                   |> Enum.filter(&String.starts_with?(&1, "-"))

  def encrypt(plaintext, algo, key, iv \\ nil) when algo in @openssl_ciphers and is_binary(key) do
    key = Base.encode16(key)

    cmd = 'echo -n "#{plaintext}" | openssl enc -e #{algo} -nosalt -K #{key}'

    cmd =
      if iv do
        iv = Base.encode16(iv)
        cmd ++ ' -iv #{iv}'
      else
        cmd
      end

    :os.cmd(cmd) |> :binary.list_to_bin()
  end

  def all_ciphers, do: @openssl_ciphers
end
