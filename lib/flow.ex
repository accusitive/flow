defmodule Flow.Application do
  use Application

  def start(_type, _args) do
    children = [
      {Flow.ListenerSup, {}},
      {Task.Supervisor, name: Flow.TaskSupervisor}
    ]

    :ets.new(:keys, [:set, :protected, :named_table])
    private_key = X509.PrivateKey.new_rsa(2048)
    public_key = X509.PublicKey.derive(private_key)
    :ets.insert(:keys, {:priv, private_key})
    :ets.insert(:keys, {:pub, public_key})

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
    Handshake.loop(socket, 0, %{}, {:none})
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
  alias X509.PrivateKey

  def loop(socket, state, kv, encryption_status, upstream \\ nil) do
    IO.puts("Looping with state #{state}")

    {len, id, data} =
      case encryption_status do
        {:none} ->
          Flow.Helpers.VarintHelper.read_length_prefixed_packet(socket)

        {:some, {_encryptor, decryptor}} ->
          # :timer.sleep(1000)
          Flow.Helpers.VarintHelper.read_encrypted_length_prefixed_packet(socket, decryptor)
      end

    IO.puts("Sucessfully Read packet with len #{len} id #{id}")

    case {state, id} do
      {0, 0x00} ->
        {pv, _add, _port, next_state} = Flow.Packets.Handshaking.s_read_handshake(data)
        # IO.puts("#{pv} #{next_state}")
        Flow.Handshake.loop(socket, next_state, Map.merge(kv, %{pv: pv}), encryption_status)

      # Status request
      {1, 0x00} ->
        Flow.Packets.Status.s_read_status_request(data)
        response = Flow.Packets.Status.c_write_status_response(kv.pv)
        Flow.Helpers.VarintHelper.write_length_id_prefixed_packet(socket, 0x0, response)

        Flow.Handshake.loop(socket, state, kv, encryption_status)

      # Ping request
      {1, 0x01} ->
        payload = Flow.Packets.Status.s_read_ping_request(data)
        p = Flow.Packets.Status.c_write_ping_response(payload)
        Flow.Helpers.VarintHelper.write_length_id_prefixed_packet(socket, 0x1, p)
        :gen_tcp.close(socket)

      # Login start
      {2, 0x00} ->
        {name, uuid} = Flow.Packets.Login.s_read_login_start(data)
        [{:priv, priv}] = :ets.lookup(:keys, :priv)
        [{:pub, pub}] = :ets.lookup(:keys, :pub)

        IO.puts("#{inspect(priv)}")
        IO.puts("#{inspect(pub)}")

        Flow.Helpers.VarintHelper.write_length_id_prefixed_packet(
          socket,
          0x01,
          Flow.Packets.Login.c_write_encryption_request(pub, <<0x00, 0x01, 0x02, 0x03>>)
        )

        Flow.Handshake.loop(
          socket,
          state,
          Map.merge(kv, %{uuid: uuid, name: name}),
          encryption_status
        )

      # Encryption Response
      {2, 0x01} ->
        {shared_secret, verify_token} = Flow.Packets.Login.s_read_encryption_response(data)
        [{:priv, priv}] = :ets.lookup(:keys, :priv)
        [{:pub, pub}] = :ets.lookup(:keys, :pub)

        shared = :public_key.decrypt_private(shared_secret, priv)
        verify = :public_key.decrypt_private(verify_token, priv)

        der = X509.PublicKey.to_der(pub)

        verif_hash = Flow.Helpers.StupidSha.sha(shared <> der)

        # TODO: move this into its own function
        url =
          "https://sessionserver.mojang.com/session/minecraft/hasJoined?username=#{kv[:name]}&serverId=#{verif_hash}"

        {:ok, %{status_code: status_code, body: body}} = HTTPoison.get(url)
        IO.puts("status code #{status_code}")
        # IO.puts("#{inspect response.body}")
        j = Jason.decode!(body)
        # %{properties: props} = j
        # IO.puts("j #{inspect(j)} ")
        # IO.puts("j #{inspect(Map.fetch(j, :properties))}")

        {id, name, properties} =
          case j do
            %{
              "id" => id,
              "name" => name,
              "properties" => properties
            } ->
              IO.puts("#{id}, #{name} #{inspect(properties)}")
              {id, name, properties}

            # Do something with id, name, and properties
            _ ->
              # IO.puts("clam")
              raise "failed to parse j"
              # Handle other cases
          end

        IO.puts(
          "verify token #{byte_size(shared_secret)} #{byte_size(verify_token)} #{inspect(shared)} #{inspect(verify)}"
        )

        # TODO: what is the boolean
        :crypto.start()
        encryptor = :crypto.crypto_init(:aes_cfb8, shared, shared, true)
        decryptor = :crypto.crypto_init(:aes_cfb8, shared, shared, false)
        crypto_state = {encryptor, decryptor}

        # send login success
        login_success = Flow.Packets.Login.c_write_login_success(kv[:uuid], kv[:name], properties)

        Flow.Helpers.VarintHelper.write_encrypted_length_id_prefixed_packet(
          socket,
          encryptor,
          0x02,
          login_success
        )

        {:ok, dest} =
          :gen_tcp.connect('localhost', 25565, [:binary, active: false, packet: 0, nodelay: true])

        # :gen_tcp.send()
        Flow.Helpers.VarintHelper.write_length_id_prefixed_packet(
          dest,
          0x0,
          Flow.Packets.Handshaking.c_write_handshake(kv[:pv], "localhost", 25565, 2)
        )

        Flow.Helpers.VarintHelper.write_length_id_prefixed_packet(
          dest,
          0x0,
          Flow.Packets.Login.c_write_login_start(kv[:name], kv[:uuid])
        )

        # id id isnt 0x02, the login wasn't successful
        {_len, id, data} = Flow.Helpers.VarintHelper.read_length_prefixed_packet(dest)
        IO.puts("Got packet from dest #{id}")

        {_len, id, data} = Flow.Helpers.VarintHelper.read_length_prefixed_packet(dest)
        IO.puts("Got packet from dest #{id}")

        Flow.Helpers.VarintHelper.write_encrypted_length_id_prefixed_packet(
          socket,
          encryptor,
          id,
          data
        )

        # plugin = Flow.Packets.Login.c_write_plugin_message("flow:test", <<>>)
        # Flow.Helpers.VarintHelper.write_encrypted_length_id_prefixed_packet(socket, crypto_state, 0x17, plugin)
        # plugin = Flow.Packets.Login.c_write_plugin_message("flow:test", <<>>)
        # Flow.Helpers.VarintHelper.write_encrypted_length_id_prefixed_packet(socket, crypto_state, 0x17, plugin)

        {:ok, _pid} =
          Task.Supervisor.start_child(Flow.TaskSupervisor, fn ->
            read_from_upstream(crypto_state, dest, socket)
          end)

        # :timer.sleep(1000)
        Flow.Handshake.loop(
          socket,
          3,
          kv,
          {:some, crypto_state},
          dest
        )
      # Player Session
      # Cancel this packet, otherwise the server will kick the player
      {3, 0x06} ->
        IO.puts("SHoudl dc")
        Flow.Handshake.loop(
          socket,
          state,
          kv,
          encryption_status,
          upstream
        )

      {3, _id2} ->
        IO.puts("received packet in play, forwarding")
        Flow.Helpers.VarintHelper.write_length_id_prefixed_packet(upstream, id, data)

        Flow.Handshake.loop(
          socket,
          state,
          kv,
          encryption_status,
          upstream
        )
    end

    # loop(socket)
  end

  def read_from_upstream({encryptor, decryptor}, upstream, downstream) do
    {_len, id, data} = Flow.Helpers.VarintHelper.read_length_prefixed_packet(upstream)
    # IO.puts("read from upstream: #{id}")

    Flow.Helpers.VarintHelper.write_encrypted_length_id_prefixed_packet(
      downstream,
      encryptor,
      id,
      data
    )

    # IO.puts("proxied packet with id #{id}")

    read_from_upstream({encryptor, decryptor}, upstream, downstream)
  end
end