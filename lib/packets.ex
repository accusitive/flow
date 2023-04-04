defmodule Flow.Packets.Handshaking do
  def s_read_handshake(data) do
    {protocol_version, data} = Varint.LEB128.decode(data)
    {server_address, data} = Flow.Helpers.VarintHelper.read_mc_string(data)
    <<port::16, data::binary>> = data
    {next_state, _data} = Varint.LEB128.decode(data)

    {protocol_version, server_address, port, next_state}
  end

  def c_write_handshake(protocol, address, port, next_state) do
    protocol = Varint.LEB128.encode(protocol)
    address = Flow.Helpers.VarintHelper.write_mc_string(address)
    port = <<port::16>>
    next_state = Varint.LEB128.encode(next_state)

    protocol <> address <> port <> next_state
  end
end

defmodule Flow.Packets.Status do
  def s_read_status_request(_data) do
  end

  def c_write_status_response(protocol) do
    default_response = %{
      version: %{
        name: "Flow",
        protocol: protocol
      },
      players: %{
        max: 100,
        online: 5,
        sample: [
          %{
            name: "thinkofdeath",
            id: "4566e69f-c907-48ee-8d71-d7ba5aa00d20"
          }
        ]
      },
      description: %{
        text: "FLOW PROXY :) #{protocol}"
      },
      favicon: "data:image/png;base64,<data>",
      enforcesSecureChat: false
    }

    json_string = Jason.encode!(default_response)
    data = Varint.LEB128.encode(byte_size(json_string))

    data <> json_string
  end

  def s_read_ping_request(data) do
    <<payload::64, _data::binary>> = data

    payload
  end

  def c_write_ping_response(payload) do
    <<payload::big-signed-64>>
  end
end

defmodule Flow.Packets.Login do
  def s_read_login_start(data) do
    {name, data} = Flow.Helpers.VarintHelper.read_mc_string(data)
    <<has_uuid::8, data::binary>> = data

    if has_uuid == 1 do
      <<uuid::128, _data::binary>> = data
      {name, uuid}
    else
      {name, Flow.Helpers.OfflinePlayerUUID.generate(name)}
    end
  end

  def c_write_login_start(name, uuid) do
    name = Flow.Helpers.VarintHelper.write_mc_string(name)
    has_uuid = <<1::8>>
    uuid = <<uuid::128>>

    name <> has_uuid <> uuid
  end

  @spec c_write_encryption_request(
          {:ECPoint | {:ECPoint, any}, any}
          | {:RSAPublicKey, any, any}
          | {:SubjectPublicKeyInfo, any, any},
          binary
        ) :: binary
  def c_write_encryption_request(pub, verify_token) do
    server_id = Flow.Helpers.VarintHelper.write_mc_string("")
    der = X509.PublicKey.to_der(pub)
    pk = Flow.Helpers.VarintHelper.write_length_prefixed_binary(der)
    verify_token = Flow.Helpers.VarintHelper.write_length_prefixed_binary(verify_token)

    server_id <> pk <> verify_token
  end

  def s_read_encryption_response(data) do
    {shared_secret, data} = Flow.Helpers.VarintHelper.read_length_prefixed_binary(data)
    {verify_token, _data} = Flow.Helpers.VarintHelper.read_length_prefixed_binary(data)

    {shared_secret, verify_token}
  end

  def c_write_login_success(uuid, username, properties) do
    uuid = <<uuid::128>>
    username = Flow.Helpers.VarintHelper.write_mc_string(username)
    properties_len = Varint.LEB128.encode(length(properties))

    full_props = Flow.Packets.Login.write_properties(properties)

    uuid <> username <> properties_len <> full_props
  end

  def write_properties(properties) do
    full_props =
      List.foldl(properties, <<>>, fn x, acc ->
        %{
          "name" => xname,
          "value" => xvalue,
          "signature" => xsignature
        } = x

        xsigned = 1
        name = Flow.Helpers.VarintHelper.write_mc_string(xname)
        value = Flow.Helpers.VarintHelper.write_mc_string(xvalue)
        signed = <<xsigned::8>>

        signature = Flow.Helpers.VarintHelper.write_mc_string(xsignature)
        name <> value <> signed <> signature <> acc
      end)

    full_props
  end

  def c_write_plugin_message(channel, data) do
    channel = Flow.Helpers.VarintHelper.write_mc_string(channel)

    channel <> data
  end

  def c_write_plugin_request(message_id, channel, data) do
    message_id = Varint.LEB128.encode(message_id)
    channel = Flow.Helpers.VarintHelper.write_mc_string(channel)
    message_id <> channel <> data
  end

  def s_read_plugin_request(data) do
    {message_id, data} = Varint.LEB128.decode(data)
    {channel, data} = Flow.Helpers.VarintHelper.read_mc_string(data)

    {message_id, channel, data}
  end

  def s_read_plugin_response(data) do
    {message_id, data} = Varint.LEB128.decode(data)
    <<successful::8, data::binary>> = data

    {message_id, successful, data}
  end

  def c_write_plugin_response(message_id, success, data) do
    message_id = Varint.LEB128.encode(message_id)
    success = <<success::8>>

    message_id <> success <> data
  end
end

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

  def write_encrypted_length_id_prefixed_packet(socket, encryptor, id, data) do
    full = Varint.LEB128.encode(id) <> data
    len = Varint.LEB128.encode(byte_size(full))
    enc = :crypto.crypto_update(encryptor, len <> full)

    :gen_tcp.send(socket, enc)
  end

  def write_compressed_encrypted_length_id_prefixed_packet(socket, crypto_state, id, data) do
    {_enc, _dec, _compressor, _decompressor} = crypto_state
    compressor = :zlib.open()
    :zlib.deflateInit(compressor)

    idv = Varint.LEB128.encode(id)
    compressed_packet_id = :zlib.deflate(compressor, idv)
    compressed_data = :zlib.deflate(compressor, data)

    data_length = byte_size(idv) + byte_size(data)
    data_lengthv = Varint.LEB128.encode(data_length)
    packet_length = byte_size(data_lengthv) + byte_size(compressed_packet_id <> compressed_data)

    enc =
      :crypto.crypto_update(
        crypto_state,
        Varint.LEB128.encode(packet_length) <>
          data_lengthv <> compressed_packet_id <> compressed_data
      )

    :gen_tcp.send(socket, enc)
    # full = Varint.LEB128.encode(id) <> data
    # data_length = byte_size(full)
    # compressed = :zlib.inflate(z, full)
    # data_length_varint = Varint.LEB128.encode(data_length)
    # packet_length = byte_size(data_length_varint) + compressed

    # len = Varint.LEB128.encode(byte_size(full))
    # enc = :crypto.crypto_update(crypto_state, packet_length <> data_length_varint <> full)
    # :gen_tcp.send(socket, enc)

    # :gen_tcp.send(socket, enc)
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
