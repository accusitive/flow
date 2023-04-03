defmodule Flow.Packets.Handshaking do
  def s_read_handshake(data) do
    {protocol_version, data} = Varint.LEB128.decode(data)
    {string_length, data} = Varint.LEB128.decode(data)
    <<server_address::binary-size(string_length), data::binary>> = data
    <<port::16, data::binary>> = data
    {next_state, _data} = Varint.LEB128.decode(data)
    {protocol_version, server_address, port, next_state}
  end
end

defmodule Flow.Packets.Status do


  def s_read_status_request(_data) do
  end

  def c_write_status_response(protocol) do
    clam = %{
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
    json_string = Jason.encode!(clam)
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
