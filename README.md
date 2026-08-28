# augur
⚡️ Watch over active SSH connections and destroy

Augur monitors established `sshd` connections on configured ports and terminates sessions whose remote network is not recognized. Network fingerprints are based on the remote address or CIDR and are not cryptographic device identity.

## Configuration

Copy `config/augur.example.json` to `/etc/augur/config.json` and replace the example network with the networks that should be allowed. Enforcement is enabled by default; set `enforce` to `false` while testing.

Run a single audit scan without starting the service:

```sh
augur -config /etc/augur/config.json -once -dry-run
```

The service writes structured JSON audit logs to stderr unless `log_path` is configured. The supplied launchd plist runs it as root and routes stdout and stderr to `/var/log/augur.log`.

Build the binary and launchd artifact with Nix:

```sh
nix build
```

The outputs are available under `result/bin/augur`, `result/share/augur/config.example.json`, and `result/share/launchd/com.ch55secake.augur.plist`.

## Development

Start the Nix development shell from the repository root:

```sh
nix develop
```

The shell provides the pinned Go toolchain. Use `make dev-shell` as an equivalent shortcut.

Common checks are available through the Makefile:

```sh
make build
make test
make check
```
