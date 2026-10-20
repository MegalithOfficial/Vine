<div align="center">
  <h1><img src="https://github.com/Pumpkin-MC.png" alt="Pumpkin" width="112" align="absmiddle"> <img src=".github/vine-title.svg" alt="Vine" height="78" align="absmiddle"></h1>
</div>

A Minecraft Java Edition proxy written in Rust, built on the [Pumpkin](https://github.com/Pumpkin-MC/Pumpkin) crates.

- Supports 1.7 through 26.x clients, with server switching on every version
- Velocity, BungeeCord and Vine forwarding
- WebAssembly plugins that can be reloaded without a restart
- Per-player translations in `lang/`

## Running

```sh
cargo build --release --locked
./target/release/vine
```

The first start writes `vine.toml`, `lang/en_us.json` and, when a backend uses modern forwarding, `forwarding.secret`.
Docker users can run `docker compose up -d`, and `egg-vine.json` is a Pterodactyl egg.

## License

GPL-3.0. See [NOTICE](NOTICE) and [LICENSE](LICENSE).
