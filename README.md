# MorePrivate tt-server

[tt-server](https://github.com/moreprivate/tt-server) is the Linux VPS TrustTunnel server for the 
[tt-client](https://github.com/moreprivate/tt-client) and
[tt-mobile](https://github.com/moreprivate/tt-mobile) clients. It accepts
authenticated TCP, UDP, and ICMP traffic over HTTP/1.1, HTTP/2, or QUIC.

Deployment scripts are in [tt-manage](https://github.com/moreprivate/tt-manage);
this repository contains the server source, tests, and release workflow.

## Install a release

On a supported Debian/Ubuntu VPS, run the manager as root:

```sh
git clone https://github.com/moreprivate/tt-manage.git
cd tt-manage
sudo bash tt-server.sh install --custom-sni camouflage.example
sudo bash tt-server.sh add-user router
```

`--custom-sni` is required and must be an ASCII DNS hostname, not an IP
address. Installation configures the systemd service, firewall, certificates,
and server. Generated profiles are stored in
`/opt/moreprivate/tt-server/clients/`; copy them securely to clients.

Generated profiles default to:

```toml
upstream_protocol = "http2"
http_connections_num = 4
```

`4` is the generated TOML default; setting it to `0` selects the client
library fallback of 8. Select another transport
with `--upstream-protocol auto|http2|http3`. The server supports H2 and H3
regardless of the profile choice. The server may run with no users; this is
a deliberate deny-all state.

To pin an asset or use a local build:

```sh
sudo bash tt-server.sh install --custom-sni camouflage.example \\
  --version RELEASE_TAG
sudo bash tt-server.sh install --custom-sni camouflage.example \\
  --binary ./tt-server-RELEASE_TAG-linux-x86_64
```

Release downloads require the matching checksum sidecar and manifest.

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

`upgrade` changes only the server binary and preserves configuration,
credentials, certificates, and firewall state. `rollback` returns to the
previous retained binary. `purge` removes TrustTunnel while leaving the
operating system intact.

## Verify a session

```sh
sudo systemctl --no-pager --full status moreprivate-tt-server
sudo ss -tn state established '( sport = :443 )'
```

`status` also reports the configured ICMP egress interface and whether the
service has `CAP_NET_RAW`, which is required for tunneled ICMP.

## Build and test

For native development:

```sh
make init
cargo build --bins --release
cargo test --workspace
```

See [DEVELOPMENT.md](DEVELOPMENT.md) for prerequisites and debugging. The
reproducible cross-target workflow is
`.github/workflows/build-server-targets.yml`; it is manually dispatched and
is invoked by the `tt-manage` release chain before client and mobile builds.

## Documentation

- [CONFIGURATION.md](CONFIGURATION.md)
- [CERT_RENEWAL.md](CERT_RENEWAL.md)
- [VERIFY_RELEASES.md](VERIFY_RELEASES.md)
- [DEVELOPMENT.md](DEVELOPMENT.md)

## License

Apache 2.0. See [LICENSE](LICENSE).
