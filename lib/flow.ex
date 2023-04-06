defmodule Flow.Application do
  use Application

  def start(_type, _args) do
    topologies = [
      example: [
        strategy: Cluster.Strategy.Epmd,
        config: [hosts: [:"a@127.0.0.1", :"b@127.0.0.1"]]
      ]
    ]

    children = [
      {Cluster.Supervisor, [topologies, [name: Flow.ClusterSupervisor]]},
      {Flow.ListenerSup, {}},
      {Task.Supervisor, name: Flow.TaskSupervisor}
    ]

    :ets.new(:keys, [:set, :protected, :named_table])
    :ets.new(:upstream, [:set, :public, :named_table])
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
    port =
      case node() do
        :"a@127.0.0.1" -> 5555
        :"b@127.0.0.1" -> 5556
        _ -> 5557
      end

    children = [
      {Flow.Listeners.Minecraft, [{:port, port}]}
    ]

    Supervisor.init(children, strategy: :one_for_one)
  end
end

defmodule Flow.Handshake do
  def loop(socket, state, kv, crypto_state, upstream \\ nil) do
    upstream =
      case upstream do
        nil ->
          nil

        _ ->
          [{:upstream, upstream}] = :ets.lookup(:upstream, :upstream)
          upstream
      end

    {_len, id, data} =
      case crypto_state do
        {:none} ->
          Flow.Helpers.VarintHelper.read_length_prefixed_packet(socket)

        {:some, {_encryptor, decryptor}} ->
          # :timer.sleep(1000)
          Flow.Helpers.VarintHelper.read_encrypted_length_prefixed_packet(socket, decryptor)
      end

    # IO.puts("Sucessfully Read packet with len #{len} id #{id}")
    version = kv[:version]
    session = Flow.Versions.session(version)

    case {state, id} do
      {0, 0x00} ->
        {pv, _add, _port, next_state} = Flow.Packets.Handshaking.s_read_handshake(data)
        version = Flow.Versions.get_version(pv)

        Flow.Handshake.loop(
          socket,
          next_state,
          Map.merge(kv, %{pv: pv, version: version}),
          crypto_state
        )

      # Status request
      {1, 0x00} ->
        Flow.Packets.Status.s_read_status_request(data)
        response = Flow.Packets.Status.c_write_status_response(kv.pv)
        Flow.Helpers.VarintHelper.write_length_id_prefixed_packet(socket, 0x0, response)

        Flow.Handshake.loop(socket, state, kv, crypto_state)

      # Ping request
      {1, 0x01} ->
        payload = Flow.Packets.Status.s_read_ping_request(data)
        p = Flow.Packets.Status.c_write_ping_response(payload)
        Flow.Helpers.VarintHelper.write_length_id_prefixed_packet(socket, 0x1, p)
        :gen_tcp.close(socket)

      # Login start
      {2, 0x00} ->
        {name, sig, uuid} = Flow.Packets.Login.s_read_login_start(kv[:version], data)
        # [{:priv, priv}] = :ets.lookup(:keys, :priv)
        [{:pub, pub}] = :ets.lookup(:keys, :pub)

        Flow.Helpers.VarintHelper.write_length_id_prefixed_packet(
          socket,
          0x01,
          Flow.Packets.Login.c_write_encryption_request(pub, <<0x00, 0x01, 0x02, 0x03>>)
        )

        Flow.Handshake.loop(
          socket,
          state,
          Map.merge(kv, %{uuid: uuid, name: name, sig: sig}),
          crypto_state
        )

      # Encryption Response
      {2, 0x01} ->
        {shared_secret, verify_token} =
          case Flow.Packets.Login.s_read_encryption_response(kv[:version], data) do
            {:verify, shared_secret, verify_token} -> {shared_secret, verify_token}
            {:no_verify, shared_secret, _salt, _message_signature} -> {shared_secret, :none}
          end

        [{:priv, priv}] = :ets.lookup(:keys, :priv)
        [{:pub, pub}] = :ets.lookup(:keys, :pub)

        shared = :public_key.decrypt_private(shared_secret, priv)

        if verify_token != :none do
          verify = :public_key.decrypt_private(verify_token, priv)

          if verify != <<0x01, 0x01, 0x02, 0x03>> do
            # In theory kick?
          end
        end

        der = X509.PublicKey.to_der(pub)

        verif_hash = Flow.Helpers.StupidSha.sha(shared <> der)

        # TODO: move this into its own function
        url =
          "https://sessionserver.mojang.com/session/minecraft/hasJoined?username=#{kv[:name]}&serverId=#{verif_hash}"

        {:ok, %{status_code: _status_code, body: body}} = HTTPoison.get(url)
        j = Jason.decode!(body)

        properties = j["properties"]
        kv = Map.put(kv, :properties, properties)
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

        upstream = Flow.Helpers.ConnectionHelper.establish_connection(kv, "localhost", 25565)
        :ets.insert(:upstream, {:upstream, upstream})
        # if id isnt 0x02, the login wasn't successful
        # TODO: handle this ^ and disconnect player
        {_len, id1, _data} = Flow.Helpers.VarintHelper.read_length_prefixed_packet(upstream)

        {_len, play_game_id, data} =
          Flow.Helpers.VarintHelper.read_length_prefixed_packet(upstream)

        IO.puts("Got packet from upstream #{id1} #{play_game_id}")

        # Login PLAY packet
        Flow.Helpers.VarintHelper.write_encrypted_length_id_prefixed_packet(
          socket,
          encryptor,
          play_game_id,
          data
        )

        # plugin = Flow.Packets.Login.c_write_plugin_message("flow:test", <<>>)
        # Flow.Helpers.VarintHelper.write_encrypted_length_id_prefixed_packet(socket, crypto_state, 0x17, plugin)

        {:ok, _pid} =
          Task.Supervisor.start_child(Flow.TaskSupervisor, fn ->
            read_from_upstream(crypto_state, kv, socket)
          end)

        Flow.Handshake.loop(
          socket,
          3,
          kv,
          {:some, crypto_state},
          upstream
        )

      {3, 0x05} ->
        {message, _data} = Flow.Packets.Play.s_read_chat_message(data)
        IO.puts("chat message: #{message}")

        case message do
          "2" ->
            Flow.Helpers.ConnectionHelper.fully_proxy(
              socket,
              upstream,
              crypto_state,
              kv,
              "localhost",
              25566
            )

          "1" ->
            Flow.Helpers.ConnectionHelper.fully_proxy(
              socket,
              upstream,
              crypto_state,
              kv,
              "localhost",
              25565
            )

          _ ->
            Flow.Helpers.VarintHelper.write_length_id_prefixed_packet(upstream, id, data)
        end

        Flow.Handshake.loop(
          socket,
          state,
          kv,
          crypto_state,
          upstream
        )

      # Player Session
      # Cancel this packet, otherwise the server will kick the player
      {3, ^session} ->
        # IO.puts("Cancelled Session Packet")

        Flow.Handshake.loop(
          socket,
          state,
          kv,
          crypto_state,
          upstream
        )

      {3, _id2} ->
        Flow.Helpers.VarintHelper.write_length_id_prefixed_packet(upstream, id, data)

        Flow.Handshake.loop(
          socket,
          state,
          kv,
          crypto_state,
          upstream
        )
    end
  end

  def read_from_upstream({encryptor, decryptor}, kv, downstream) do
    # upstream = :ets.first(:upstream)
    [{:upstream, upstream}] = :ets.lookup(:upstream, :upstream)
    {len, id, data} = Flow.Helpers.VarintHelper.read_length_prefixed_packet(upstream)
    # IO.puts("probably sending packet id #{id} len #{len} to downstream")

    plugin_message = Flow.Versions.plugin_message(kv[:version])

    case id do
      # play game
      0x02 ->
        nil

      ^plugin_message ->
        {channel, brand} = Flow.Packets.Login.s_read_plugin_message(data)

        case channel do
          "minecraft:brand" ->
            {brand, _} = Flow.Helpers.VarintHelper.read_mc_string(brand)

            plugin =
              Flow.Packets.Login.c_write_plugin_message(
                "minecraft:brand",
                Flow.Helpers.VarintHelper.write_mc_string("§c#{brand} §avia §bFlow§r")
              )

            # IO.puts("#{inspect data}")
            data |> Hexdump.to_string() |> IO.puts()

            Flow.Helpers.VarintHelper.write_encrypted_length_id_prefixed_packet(
              downstream,
              encryptor,
              plugin_message,
              plugin
            )

          _ ->
            Flow.Helpers.VarintHelper.write_encrypted_length_id_prefixed_packet(
              downstream,
              encryptor,
              id,
              data
            )
        end

      _ ->
        Flow.Helpers.VarintHelper.write_encrypted_length_id_prefixed_packet(
          downstream,
          encryptor,
          id,
          data
        )
    end

    read_from_upstream({encryptor, decryptor}, kv, downstream)
  end

  def has_joined() do
  end
end
