#!/bin/sh
set -eu

REPOSITORY=${AUGUR_REPOSITORY:-ch55secake/augur}
VERSION=${AUGUR_VERSION:-latest}
PREFIX=${AUGUR_PREFIX:-/usr/local}
CONFIG_DIR=${AUGUR_CONFIG_DIR:-/etc/augur}
LAUNCHD_PATH=/Library/LaunchDaemons/com.ch55secake.augur.plist
SSH_DROPIN_DIR=/etc/ssh/sshd_config.d
SSH_DROPIN_PATH=$SSH_DROPIN_DIR/000-augur.conf
DRY_RUN=0
UNINSTALL=0

usage() {
	cat <<EOF
Usage: sudo $0 [--version VERSION] [--prefix DIR] [--config-dir DIR] [--dry-run] [--uninstall]

Install Augur on macOS as a root LaunchDaemon. Existing configuration and
SSH configuration are never overwritten.
EOF
}

run() {
	if [ "$DRY_RUN" -eq 1 ]; then
		printf '+ '
		printf '%s ' "$@"
		printf '\n'
		return 0
	fi
	"$@"
}

while [ "$#" -gt 0 ]; do
	case "$1" in
		--version) [ "$#" -ge 2 ] || { echo "--version requires a value" >&2; exit 2; }; VERSION=$2; shift 2 ;;
		--prefix) [ "$#" -ge 2 ] || { echo "--prefix requires a value" >&2; exit 2; }; PREFIX=$2; shift 2 ;;
		--config-dir) [ "$#" -ge 2 ] || { echo "--config-dir requires a value" >&2; exit 2; }; CONFIG_DIR=$2; shift 2 ;;
		--dry-run) DRY_RUN=1; shift ;;
		--uninstall) UNINSTALL=1; shift ;;
		-h|--help) usage; exit 0 ;;
		*) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
	esac
done

[ "$(uname -s)" = Darwin ] || { echo "this installer only supports macOS" >&2; exit 1; }
if [ "$(id -u)" -ne 0 ] && [ "$DRY_RUN" -eq 0 ]; then
	echo "run this installer as root (for example: sudo $0)" >&2
	exit 1
fi

if [ "$UNINSTALL" -eq 1 ]; then
	if [ "$DRY_RUN" -eq 0 ] && [ "$(id -u)" -ne 0 ]; then
		echo "run this installer as root (for example: sudo $0 --uninstall)" >&2
		exit 1
	fi
	if [ "$DRY_RUN" -eq 0 ]; then
		/bin/launchctl bootout system "$LAUNCHD_PATH" 2>/dev/null || true
	fi
	run rm -f "$LAUNCHD_PATH" "$SSH_DROPIN_PATH" "$PREFIX/bin/augur"
	echo "removed Augur program files; configuration was left untouched"
	exit 0
fi

case "$VERSION" in
	latest)
		if [ "$DRY_RUN" -eq 0 ]; then
			command -v curl >/dev/null 2>&1 || { echo "curl is required" >&2; exit 1; }
			VERSION=$(curl --fail --silent --show-error --location "https://api.github.com/repos/$REPOSITORY/releases/latest" | awk -F'"' '/"tag_name"/ { print $4; exit }')
			[ -n "$VERSION" ] || { echo "could not resolve latest release" >&2; exit 1; }
		fi
		VERSION_PATH=$VERSION
		;;
	v[0-9]*.[0-9]*.[0-9]*) VERSION_PATH=$VERSION ;;
	[0-9]*.[0-9]*.[0-9]*) VERSION_PATH=v$VERSION; VERSION=v$VERSION ;;
	*) echo "version must be latest or semantic version" >&2; exit 2 ;;
esac
case "$(uname -m)" in
	arm64) GOARCH=arm64 ;;
	x86_64) GOARCH=amd64 ;;
	*) echo "unsupported architecture" >&2; exit 1 ;;
esac

if [ -e "$CONFIG_DIR/config.json" ]; then
	echo "leaving existing configuration untouched: $CONFIG_DIR/config.json"
fi
if [ -e "$SSH_DROPIN_PATH" ]; then
	echo "leaving existing SSH drop-in untouched: $SSH_DROPIN_PATH"
fi
if [ -e "$LAUNCHD_PATH" ]; then
	echo "leaving existing LaunchDaemon untouched: $LAUNCHD_PATH"
	exit 1
fi

ARCHIVE="augur_${VERSION#v}_darwin_${GOARCH}.tar.gz"
BASE_URL="https://github.com/$REPOSITORY/releases/$VERSION_PATH/download"
RAW_URL="https://raw.githubusercontent.com/$REPOSITORY/$VERSION_PATH"
TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/augur-macos-install.XXXXXX")
cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT INT TERM

run mkdir -p "$TMP_DIR" "$PREFIX/bin" "$CONFIG_DIR" "$SSH_DROPIN_DIR"
if [ "$DRY_RUN" -eq 0 ]; then
	curl --fail --silent --show-error --location "$BASE_URL/$ARCHIVE" -o "$TMP_DIR/$ARCHIVE"
	tar -xzf "$TMP_DIR/$ARCHIVE" -C "$TMP_DIR"
	curl --fail --silent --show-error --location "$RAW_URL/packaging/com.ch55secake.augur.plist" -o "$TMP_DIR/augur.plist"
	curl --fail --silent --show-error --location "$RAW_URL/packaging/sshd_config.d/000-augur.conf" -o "$TMP_DIR/000-augur.conf"
	curl --fail --silent --show-error --location "$RAW_URL/config/augur.example.json" -o "$TMP_DIR/config.example.json"
	command -v plutil >/dev/null 2>&1 && plutil -lint "$TMP_DIR/augur.plist"
fi
run install -m 0755 "$TMP_DIR/augur" "$PREFIX/bin/augur"
run install -m 0644 "$TMP_DIR/augur.plist" "$LAUNCHD_PATH"
run install -m 0644 "$TMP_DIR/000-augur.conf" "$SSH_DROPIN_PATH"
if [ ! -e "$CONFIG_DIR/config.json" ]; then
	run install -m 0600 "$TMP_DIR/config.example.json" "$CONFIG_DIR/config.json"
fi
if [ "$DRY_RUN" -eq 0 ]; then
	/usr/sbin/sshd -t
	/bin/launchctl bootstrap system "$LAUNCHD_PATH"
fi
echo "installed Augur LaunchDaemon; review $CONFIG_DIR/config.json before enabling enforcement"
