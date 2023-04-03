defmodule Flow.Application do
  use Application

  def start(_type, _args) do
    children = [
      {Flow.ListenerSup, {}},
      {Task.Supervisor, name: Flow.TaskSupervisor}
    ]

    Supervisor.start_link(children, strategy: :one_for_one)
  end
end

defmodule Flow.Protocols.Minecraft do
  alias Flow.Handshake
  @behaviour :ranch_protocol
  @timeout 5000
  @afterconnect_delay 1000
  def start_link(ref, transport, opts) do
    {:ok, spawn_link(__MODULE__, :init, [ref, transport, opts])}
  end

  def init(ref, _transport, _opts) do
    {:ok, socket} = :ranch.handshake(ref)

    {:ok, pid} =
      Task.Supervisor.start_child(Flow.TaskSupervisor, fn -> handle_new_client(socket) end)

    :gen_tcp.controlling_process(socket, pid)
  end

  def handle_new_client(socket) do
    # IO.puts("handling new client")
    Handshake.loop(socket, 0, %{})
  end

  # def loop(socket, transport) do

  #   loop(socket, transport)
  # end
end

defmodule Flow.Listeners.Minecraft do
  def child_spec(opts) do
    :ranch.child_spec(__MODULE__, :ranch_tcp, opts, Flow.Protocols.Minecraft, [])
  end
end

defmodule Flow.ListenerSup do
  use Supervisor

  def start_link(args) do
    Supervisor.start_link(__MODULE__, args)
  end

  @impl true
  def init({}) do
    children = [
      {Flow.Listeners.Minecraft, [{:port, 5555}]}
      # {Nexus.Listeners.EchoServer, [{:port, 5556}]}
    ]

    Supervisor.init(children, strategy: :one_for_one)
  end
end

defmodule Flow.Handshake do
  def loop(socket, state, kv) do
    IO.puts("Looping with state #{state}")

    {len, id, data} = Flow.Helpers.VarintHelper.read_length_prefixed_packet(socket)
    IO.puts("Sucessfully Read packet with len #{len} id #{id}")

    case {state, id} do
      {0, 0} ->
        {pv, _add, _port, next_state} = Flow.Packets.Handshaking.s_read_handshake(data)
        # IO.puts("#{pv} #{next_state}")
        Flow.Handshake.loop(socket, next_state, Map.merge(kv, %{pv: pv}))

      {1, 0x0} ->
        Flow.Packets.Status.s_read_status_request(data)
        response = Flow.Packets.Status.c_write_status_response(kv.pv)
        Flow.Helpers.VarintHelper.write_length_id_prefixed_packet(socket, 0x0, response)

        Flow.Handshake.loop(socket, state, kv)

      {1, 1} ->
        payload = Flow.Packets.Status.s_read_ping_request(data)
        p = Flow.Packets.Status.c_write_ping_response(payload)
        Flow.Helpers.VarintHelper.write_length_id_prefixed_packet(socket, 0x1, p)
        :gen_tcp.close(socket)
    end

    # loop(socket)
  end
end

defmodule Flow.Status do
end
