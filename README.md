# TrustTunnel server

TrustTunnel server is the Linux VPS endpoint for the private
[tt-client](https://github.com/moreprivate/tt-client) and
[tt-mobile](https://github.com/moreprivate/tt-mobile) clients. It accepts
authenticated TCP, UDP, and ICMP traffic over HTTP/1.1, HTTP/2, or QUIC.

Deployment scripts are in [tt-manage](https://github.com/moreprivate/tt-manage);
this repository contains the endpoint source, tests, and release workflow.

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
and endpoint. Generated profiles are stored in
`/opt/trusttunnel/clients/`; copy them securely to clients.

Generated profiles default to:

```toml
upstream_protocol = "http2"
http_connections_num = 0
```

`0` selects the client's default connection count. Select another transport
with `--upstream-protocol auto|http2|http3`. The endpoint supports H2 and H3
regardless of the profile choice. The endpoint may run with no users; this is
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

`upgrade` changes only the endpoint binary and preserves configuration,
credentials, certificates, and firewall state. `rollback` returns to the
previous retained binary. `purge` removes TrustTunnel while leaving the
operating system intact.

## Verify a session

```sh
sudo systemctl --no-pager --full status trusttunnel
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
