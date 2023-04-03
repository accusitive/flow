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

    # IO.puts("#{inspect data}")
    data <> json_string
  end

  def s_read_ping_request(data) do
    <<payload::64, _data::binary>> = data
    payload
  end

  def c_write_ping_response(payload) do
    # <<payload::64, data::binary>> = data
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

        # if x.signed == 1 do
        signature = Flow.Helpers.VarintHelper.write_mc_string(xsignature)
        name <> value <> signed <> signature <> acc
        # else
        #   {name <> value <> signed <> acc}
        # end
      end)

    # Enum.flat_map(properties, fn a, b ->
    #     name = Flow.Helpers.VarintHelper.write_mc_string()
    # end)

    uuid <> username <> properties_len <> full_props
  end

  def c_write_plugin_message(channel, data) do
    channel = Flow.Helpers.VarintHelper.write_mc_string(channel)
    channel <> data
  end
end
