defmodule Flow.Helpers.VarintHelper do
  alias ElixirSense.Core.State.VarInfo

  def read_byte_by_byte(get_next_byte, acc, previous) do
    current = get_next_byte.(acc)

    if Flow.Helpers.VarintHelper.does_have_next_byte(current) do
      read_byte_by_byte(get_next_byte, acc + 1, previous <> current)
    else
      # IO.puts("read byte by byte: #{inspect(previous <> current)}")
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

    # IO.puts("Read packet with len #{len}")

    if len == 0 do
      {len, 0, <<>>}
    else
      {:ok, data} = :gen_tcp.recv(socket, len)

      {id, data} = Varint.LEB128.decode(data)
      # IO.puts("Read packet with id #{id}")

      {len, id, data}
    end
  end

  def write_length_id_prefixed_packet(socket, id, data) do
    full = Varint.LEB128.encode(id) <> data
    len = Varint.LEB128.encode(byte_size(full))
    :gen_tcp.send(socket, len <> full)
  end
end
