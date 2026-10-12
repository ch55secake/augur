# augur
⚡️ Watch over active SSH connections and destroy

Augur monitors established `sshd` connections on configured ports and terminates sessions whose authenticated SSH key is not recognized. SSH public-key fingerprints identify credentials, not physical hardware. Network settings can restrict where a recognized device is allowed to connect.

Set `mode` to `observe` to record connections and network observations without terminating sessions. Set it to `enforce` for termination behavior. In enforce mode, `observation_policy.allow_addresses` always permits listed source addresses; when `terminate_addresses` is non-empty, only listed observed source addresses are eligible for termination. SSH key fingerprints remain the primary recognized-device allow mechanism.

## Network Inventory

Network inventory is disabled by default. To enable audit-only inventory, list the names of private or link-local networks to scan in `probe_networks` and set `network_probes.enabled` to `true`. The names must refer to entries in `recognized_networks`; unnamed networks cannot be probed.

Each scan reads the macOS ARP and NDP neighbor caches, then performs bounded TCP connect probes against the configured `tcp_ports`. `max_hosts`, `concurrency`, `timeout`, and `interval` limit scan size and traffic. Results are short-lived in-memory observations and structured audit logs; they do not recognize devices, terminate SSH sessions, or change PF rules.

Optional OS enrichment uses an explicitly configured `nmap -O` binary against only hosts where a TCP probe succeeded. Set `network_probes.os_detection.enabled` to `true`, provide the binary path or name, and keep `max_hosts` small. Augur requests XML output, limits retries, and applies the configured command timeout. Nmap must be installed separately and may require root privileges for OS detection; an unavailable or failed Nmap run leaves the base inventory intact and is logged as a warning.

TCP and OS results are heuristic observations, not cryptographic device identities. Keep SSH key fingerprints as the admission decision.

## Configuration

Copy `config/augur.example.json` to `/etc/augur/config.json` and replace the example fingerprint, username, and network with the values for the devices that should be allowed. A device with no `networks` restriction is allowed from any address; when `recognized_networks` is configured, devices without an explicit restriction are limited to those networks. Enforcement is enabled by default; set `enforce` to `false` while testing.

Get an SSH public-key fingerprint with:

```sh
ssh-keygen -lf ~/.ssh/id_ed25519.pub -E sha256
```

Augur reads successful SSH authentication records from the root-controlled macOS unified log. Install the supplied managed drop-in before enabling enforcement:

```sh
sudo mkdir -p /etc/ssh/sshd_config.d
sudo cp /path/to/000-augur.conf /etc/ssh/sshd_config.d/000-augur.conf
sudo /usr/sbin/sshd -t
sudo /usr/sbin/sshd -T | grep loglevel
```

The host's `/etc/ssh/sshd_config` must include `/etc/ssh/sshd_config.d/*` before any existing `LogLevel` directive, because OpenSSH uses the first value for each setting. Existing SSH sessions must reconnect after the setting is installed so their authentication is recorded for Augur. The Nix package provides the drop-in at `share/ssh/sshd_config.d/000-augur.conf`.

Run a single audit scan without starting the service:

```sh
augur -config /etc/augur/config.json -once -dry-run
```

The service writes structured JSON audit logs to stderr unless `log_path` is configured. The supplied launchd plist runs it as root and routes stdout and stderr to `/var/log/augur.log`.

## Installation

Install a released binary and example configuration on Linux or macOS with:

```sh
curl -fsSL https://raw.githubusercontent.com/ch55secake/augur/main/scripts/install.sh | sudo sh
```

The installer detects the platform and architecture, leaves an existing `/etc/augur/config.json` untouched, and supports `--version`, `--prefix`, `--config-dir`, `--dry-run`, and `--uninstall`. Review the generated configuration before starting Augur.

For a complete macOS LaunchDaemon installation, including the managed SSH verbose-logging drop-in:

```sh
curl -fsSL https://raw.githubusercontent.com/ch55secake/augur/main/scripts/install-macos.sh | sudo sh
```

The macOS installer validates the plist and SSH configuration, refuses to overwrite an existing LaunchDaemon or SSH drop-in, and leaves configuration files in place during uninstall. Use `--dry-run` to inspect actions without changing the host.

Build the binary and launchd artifact with Nix:

```sh
nix build
```

The outputs are available under `result/bin/augur`, `result/share/augur/config.example.json`, `result/share/ssh/sshd_config.d/000-augur.conf`, and `result/share/launchd/com.ch55secake.augur.plist`.

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
