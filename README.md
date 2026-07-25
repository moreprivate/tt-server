# TrustTunnel server

This repository builds the TrustTunnel server for a Linux VPS. It accepts
authenticated TCP, UDP, and ICMP traffic over HTTP/1.1, HTTP/2, or QUIC.

Related repositories:

- [tt-client](https://github.com/moreprivate/tt-client) — console and native clients
- [tt-mobile](https://github.com/moreprivate/tt-mobile) — Flutter mobile client
- [tt-manage](https://github.com/moreprivate/tt-manage) — installation and administration scripts

## Install a release

Run the manager as root on a supported Debian/Ubuntu VPS:

```sh
git clone https://github.com/moreprivate/tt-manage.git
cd tt-manage
sudo bash tt-server.sh install \
  --custom-sni camouflage.example
```

`--custom-sni` is mandatory. It must be an ASCII DNS hostname, not an IP
address. The manager installs the selected server release under
`/opt/trusttunnel`, creates the systemd service, configures the firewall, and
obtains a certificate unless `--skip-certbot` is specified.

Install a specific release or a locally built binary with:

```sh
sudo bash tt-server.sh install --custom-sni camouflage.example \
  --version RELEASE_TAG
sudo bash tt-server.sh install --custom-sni camouflage.example \
  --local ./tt-server-RELEASE_TAG-linux-x86_64
```

Release assets use the form `tt-server-RELEASE_TAG-linux-ARCH` and include
checksums and a manifest.

## Add clients

The server may run with no users; that is a deliberate deny-all state. Add a
user and copy the generated TOML to the client device:

```sh
sudo bash tt-server.sh add-user router
sudo cp /opt/trusttunnel/clients/router.toml /secure/path/router.toml
```

The generated profile contains the server address, SNI, credentials, and the
default four HTTP/2 connections. Keep it private. Use the same TOML with
`tt-client`, `tt-client-openwrt.sh`, or the mobile app.

## Administration

```sh
sudo bash tt-server.sh status
sudo bash tt-server.sh add-user NAME
sudo bash tt-server.sh del-user NAME
sudo bash tt-server.sh upgrade [--version RELEASE_TAG]
sudo bash tt-server.sh rollback
sudo bash tt-server.sh disable
sudo bash tt-server.sh enable
sudo bash tt-server.sh purge
```

`install` is for a clean installation. Use `upgrade` for an installed server;
it preserves the current working binary for rollback. `purge` removes the
TrustTunnel installation and policy but leaves the operating system intact.

After an upgrade or configuration change:

```sh
sudo systemctl --no-pager --full status trusttunnel
```

## Verify a session

On the VPS, established client sessions on the standard listener are visible
with:

```sh
sudo ss -tn state established '( sport = :443 )'
```

The server-side health check also reports the configured ICMP egress interface
and `CAP_NET_RAW` status. For client-side routing and leak checks, use the
client repository's documentation.

## Build from source

```sh
make init
cargo build --bins --release
```

See [DEVELOPMENT.md](DEVELOPMENT.md) for prerequisites, tests, cross-builds,
and local configuration. The build workflow runs manually from the
`privacy/server-hardening` branch; upstream rebasing is intentionally manual.

## Configuration and certificates

- [CONFIGURATION.md](CONFIGURATION.md) — server and client configuration
- [CERT_RENEWAL.md](CERT_RENEWAL.md) — certificate renewal
- [VERIFY_RELEASES.md](VERIFY_RELEASES.md) — release and checksum verification

## License

Apache 2.0. See [LICENSE](LICENSE).
