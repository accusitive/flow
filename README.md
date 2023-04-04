# Flow

Some minecraft proxy I wrote in elixir

# Running
Run the proxy with

```mix run --no-halt```

The proxy will listen on port 5555, and proxy connections to 25565

# Version support

| Version | Passthrough | Transferring | Planned |
|---------|-------------|--------------|---------|
| 1.19.4  | Yes         | No           | Yes     |
| 1.19.3  | No          | No           | Yes     |
| 1.19.2  | No          | No           | Yes     |
| 1.19.1  | No          | No           | Yes     |
| 1.19    | No          | No           | Yes     |
| 1.18.x  | No          | No           | Yes     |
| 1.17.x  | No          | No           | Later   |
| 1.16.x  | No          | No           | Yes     |
| 1.15.x  | No          | No           | Later   |
| 1.14.x  | No          | No           | Later   |
| 1.13.x  | No          | No           | Yes     |
| 1.12.x  | No          | No           | Later   |
| < 1.12  | No          | No           | No      |


# Features

- [x] Player <> proxy encryption
- [ ] Player <> proxy compression
- [x] Custom status handler
- [ ] Server transfer
- [ ] Plugin support (?)
- [-] Cluster support
- [ ] Forge support
- [ ] Fabric support
- [ ] Bungeecord compatible transfers
- [x] Velocity Modern Forwarding for 1.13+
