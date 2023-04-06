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
  alias Flow.Versions

  def s_read_login_start(version, data) when version == :MC_1_19_4 or version == :MC_1_19_3 do
    {name, data} = Flow.Helpers.VarintHelper.read_mc_string(data)
    <<has_uuid::8, data::binary>> = data

    uuid =
      if has_uuid == 1 do
        <<uuid::128, _data::binary>> = data
        uuid
      else
        Flow.Helpers.OfflinePlayerUUID.generate(name)
      end

    {name, :none, uuid}
  end

  def s_read_login_start(version, data) when version == :MC_1_19_1 do
    {name, data} = Flow.Helpers.VarintHelper.read_mc_string(data)
    <<has_sig::8, data::binary>> = data

    {sig, data} =
      if has_sig == 1 do
        <<timestamp::64, data::binary>> = data
        {public_key, data} = Flow.Helpers.VarintHelper.read_length_prefixed_binary(data)
        {signature, data} = Flow.Helpers.VarintHelper.read_length_prefixed_binary(data)

        IO.puts("#{byte_size(data)} bytes remaining after reading login_start")
        {{:some, timestamp, public_key, signature}, data}
      else
        {{:none}, data}
      end

    <<has_uuid::8, data::binary>> = data
    IO.puts("#{has_uuid}")

    uuid =
      if has_uuid == 1 do
        <<uuid::128, data::binary>> = data
        IO.puts("data fter uuid :: #{Hexdump.to_string(data)} #{uuid}")
        uuid
      else
        # {name, Flow.Helpers.OfflinePlayerUUID.generate(name)}
        # TODO: fix uuid
        127_127_127_127
      end

    {name, sig, uuid}
  end

  def c_write_login_start(version, name, uuid)
      when version == :MC_1_19_4 or version == :MC_1_19_3 do
    name = Flow.Helpers.VarintHelper.write_mc_string(name)
    has_uuid = <<1::8>>
    uuid = <<uuid::128>>

    name <> has_uuid <> uuid
  end

  def c_write_login_start(version, name, uuid) when version == :MC_1_19_1 do
    name = Flow.Helpers.VarintHelper.write_mc_string(name)
    has_sig_data = <<0::8>>
    has_uuid = <<1::8>>
    uuid = <<uuid::128>>

    name <> has_sig_data <> has_uuid <> uuid
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

  def s_read_encryption_response(version, data)
      when version == :MC_1_19_4 or version == :MC_1_19_3 do
    {shared_secret, data} = Flow.Helpers.VarintHelper.read_length_prefixed_binary(data)
    {verify_token, _data} = Flow.Helpers.VarintHelper.read_length_prefixed_binary(data)

    {shared_secret, verify_token}
  end

  def s_read_encryption_response(version, data) when version == :MC_1_19_1 do
    {shared_secret, data} = Flow.Helpers.VarintHelper.read_length_prefixed_binary(data)

    # {verify_token, _data} = Flow.Helpers.VarintHelper.read_length_prefixed_binary(data)
    <<has_verify_token::8, data::binary>> = data

    case has_verify_token == 1 do
      true ->
        {verify_token, data} = Flow.Helpers.VarintHelper.read_length_prefixed_binary(data)
        {:verify, shared_secret, verify_token}

      false ->
        <<salt::64, data::binary>> = data
        {message_signature, data} = Flow.Helpers.VarintHelper.read_length_prefixed_binary(data)

        {:no_verify, shared_secret, salt, message_signature}
    end

    # {shared_secret, verify_token}
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

  def s_read_plugin_message(data) do
    {channel, data} = Flow.Helpers.VarintHelper.read_mc_string(data)

    {channel, data}
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

defmodule Flow.Packets.Play do
  def s_read_chat_message(data) do
    {message, data} = Flow.Helpers.VarintHelper.read_mc_string(data)
    # TODO read the rest of the packet
    {message, data}
  end

  def c_write_respawn(
        dimension_type,
        dimension_name,
        hashed_seed,
        gamemode,
        previous_gamemode,
        is_debug,
        is_flat,
        copy_metadata
      ) do
    dimension_type = Flow.Helpers.VarintHelper.write_mc_string(dimension_type)
    dimension_name = Flow.Helpers.VarintHelper.write_mc_string(dimension_name)
    hashed_seed = <<hashed_seed::64>>
    gamemode = <<gamemode::8>>
    previous_gamemode = <<previous_gamemode::8>>
    is_debug = <<is_debug::8>>
    is_flat = <<is_flat::8>>
    copy_metadata = <<copy_metadata::8>>
    has_death_location = <<0::8>>

    dimension_type <>
      dimension_name <>
      hashed_seed <>
      gamemode <>
      previous_gamemode <>
      is_debug <>
      is_flat <>
      copy_metadata <> has_death_location
  end

  def s_read_join_game(data) do
    <<entity_id::32, data::binary>> = data
    <<is_hardcore::8, data::binary>> = data
    <<gamemode::8, data::binary>> = data
    <<previous_gamemode::8, data::binary>> = data
    {dimension_count, data} = Varint.LEB128.decode(data)
    l = for n <- 0..(dimension_count - 1), do: n

    {dimensions, data} =
      List.foldl(l, {[], data}, fn x, {lizt, data} ->
        {s, data} = Flow.Helpers.VarintHelper.read_mc_string(data)
        IO.puts("called read string")
        {List.insert_at(lizt, x, s), data}
      end)

    data = Flow.Hematite.read_and_discard_nbt(data)
    {dimension_type, data} = Flow.Helpers.VarintHelper.read_mc_string(data)
    {dimension_name, data} = Flow.Helpers.VarintHelper.read_mc_string(data)
    <<hashed_seed::64, data::binary>> = data
    {max_players, data} = Varint.LEB128.decode(data)
    {simulation_distance, data} = Varint.LEB128.decode(data)
    {view_distance, data} = Varint.LEB128.decode(data)

    <<red_debug::8, respawn_screen::8, debug::8, flat::8, has_death_location::8, data::binary>> =
      data

    x =
      case has_death_location do
        1 ->
          {death_dimension_name, data} = Flow.Helpers.VarintHelper.read_mc_string(data)

          <<death_x::26, death_z::26, death_y::12, _data::binary>> = data

          {entity_id, is_hardcore, gamemode, previous_gamemode, dimension_count, dimensions,
           dimension_type, dimension_name, hashed_seed, max_players, view_distance,
           simulation_distance, red_debug, respawn_screen, debug, flat, has_death_location,
           death_dimension_name, {death_x, death_y, death_z}}

        _ ->
          {entity_id, is_hardcore, gamemode, previous_gamemode, dimension_count, dimensions,
           dimension_type, dimension_name, hashed_seed, max_players, view_distance,
           simulation_distance, red_debug, respawn_screen, debug, flat, has_death_location}
      end

    IO.puts("#{dimension_type} #{has_death_location}")
    x

    #  n = NBT.decode(List.last(dimensions))
    # n = NBT.decode(data)
    # p = :nbt_erlang.parse_nbt_compound(data, '', 0)

    #  IO.puts("#{inspect p}")
    # IO.puts("#{dimension_count} z is equal to #{inspect(z)}")
  end
end
