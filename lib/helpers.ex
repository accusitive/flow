defmodule Flow.Helpers.VarintHelper do
  def read_byte_by_byte(get_next_byte, acc, previous) do
    current = get_next_byte.(acc)

    if Flow.Helpers.VarintHelper.does_have_next_byte(current) do
      read_byte_by_byte(get_next_byte, acc + 1, previous <> current)
    else
      previous <> current
    end
  end

  def does_have_next_byte(<<has_next::1, _byte::7, _rest::binary>>) do
    has_next == 1
  end

  def read_length_prefixed_packet(socket) do
    read_one_byte = fn _ac ->
      {:ok, byte} = :gen_tcp.recv(socket, 1)
      byte
    end

    {len, _rest0} =
      Varint.LEB128.decode(Flow.Helpers.VarintHelper.read_byte_by_byte(read_one_byte, 0, <<>>))

    if len == 0 do
      {len, 0, <<>>}
    else
      {:ok, data} = :gen_tcp.recv(socket, len)
      {id, data} = Varint.LEB128.decode(data)

      {len, id, data}
    end
  end

  def read_encrypted_length_prefixed_packet(socket, decryptor) do
    read_one_byte = fn _ac ->
      {:ok, byte} = :gen_tcp.recv(socket, 1)
      :crypto.crypto_update(decryptor, byte)
    end

    {len, _rest0} =
      Varint.LEB128.decode(Flow.Helpers.VarintHelper.read_byte_by_byte(read_one_byte, 0, <<>>))

    if len == 0 do
      {len, 0, <<>>}
    else
      {:ok, data} = :gen_tcp.recv(socket, len)
      data = :crypto.crypto_update(decryptor, data)
      {id, data} = Varint.LEB128.decode(data)

      {len, id, data}
    end
  end

  def write_length_id_prefixed_packet(socket, id, data) do
    full = Varint.LEB128.encode(id) <> data
    len = Varint.LEB128.encode(byte_size(full))
    :gen_tcp.send(socket, len <> full)
  end

  def write_encrypted_length_id_prefixed_packet(socket, crypto_state, id, data) do
    full = Varint.LEB128.encode(id) <> data
    len = Varint.LEB128.encode(byte_size(full))
    enc = :crypto.crypto_update(crypto_state, len <> full)

    :gen_tcp.send(socket, enc)
  end

  def read_mc_string(data) do
    {string_length, data} = Varint.LEB128.decode(data)
    <<string::binary-size(string_length), data::binary>> = data

    {string, data}
  end

  def write_mc_string(s) do
    len = Varint.LEB128.encode(byte_size(s))
    data = <<s::bitstring>>
    len <> data
  end

  def read_length_prefixed_binary(data) do
    {bin_length, data} = Varint.LEB128.decode(data)
    <<bin::binary-size(bin_length), data::binary>> = data

    {bin, data}
  end

  def write_length_prefixed_binary(b) do
    len = Varint.LEB128.encode(byte_size(b))

    len <> b
  end
end

defmodule Flow.Helpers.OfflinePlayerUUID do
  @namespace "OfflinePlayer"

  def generate(username) do
    UUID.uuid3(@namespace, username)
  end
end

defmodule Flow.Helpers.ConnectionHelper do
  # TODO
end

defmodule Flow.Helpers.PadHelpers do
  def pad(data, block_size) do
    to_add = block_size - rem(byte_size(data), block_size)
    data <> to_string(:string.chars(to_add, to_add))
  end

  def unpad(data) do
    to_remove = :binary.last(data)
    :binary.part(data, 0, byte_size(data) - to_remove)
  end
end

# Source: https://github.com/thecodeboss/minecraft/blob/f40fd388058deb176dbca77fe3f11e1d605c9a47/lib/minecraft/crypto/sha.ex
# i spent hours on this and really didnt want to copy/paste but alas

# MIT License

# Copyright (c) 2018 Michael Oliver

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

defmodule Flow.Helpers.StupidSha do
  def sha(message) do
    case :crypto.hash(:sha, message) do
      <<hash::signed-integer-160>> when hash < 0 ->
        "-" <> String.downcase(Integer.to_string(-hash, 16))

      <<hash::signed-integer-160>> ->
        String.downcase(Integer.to_string(hash, 16))
    end
  end
end
