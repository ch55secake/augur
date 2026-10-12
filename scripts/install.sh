#!/bin/sh
set -eu

REPOSITORY=${AUGUR_REPOSITORY:-ch55secake/augur}
VERSION=${AUGUR_VERSION:-latest}
PREFIX=${AUGUR_PREFIX:-/usr/local}
CONFIG_DIR=${AUGUR_CONFIG_DIR:-/etc/augur}
DRY_RUN=0
UNINSTALL=0

usage() {
	cat <<EOF
Usage: $0 [--version VERSION] [--prefix DIR] [--config-dir DIR] [--dry-run] [--uninstall]

Install or remove the Augur release binary and example configuration.
Set AUGUR_REPOSITORY, AUGUR_VERSION, AUGUR_PREFIX, or AUGUR_CONFIG_DIR to
override the defaults.
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
		--version)
			[ "$#" -ge 2 ] || { echo "--version requires a value" >&2; exit 2; }
			VERSION=$2
			shift 2
			;;
		--prefix)
			[ "$#" -ge 2 ] || { echo "--prefix requires a value" >&2; exit 2; }
			PREFIX=$2
			shift 2
			;;
		--config-dir)
			[ "$#" -ge 2 ] || { echo "--config-dir requires a value" >&2; exit 2; }
			CONFIG_DIR=$2
			shift 2
			;;
		--dry-run) DRY_RUN=1; shift ;;
		--uninstall) UNINSTALL=1; shift ;;
		-h|--help) usage; exit 0 ;;
		*) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
	esac
done

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

case "$(uname -s)" in
	Linux) GOOS=linux ;;
	Darwin) GOOS=darwin ;;
	*) echo "unsupported operating system" >&2; exit 1 ;;
esac
case "$(uname -m)" in
	x86_64|amd64) GOARCH=amd64 ;;
	aarch64|arm64) GOARCH=arm64 ;;
	*) echo "unsupported architecture" >&2; exit 1 ;;
esac

BINARY_PATH=$PREFIX/bin/augur
CONFIG_PATH=$CONFIG_DIR/config.json
if [ "$UNINSTALL" -eq 1 ]; then
	run rm -f "$BINARY_PATH"
	if [ -f "$CONFIG_PATH" ]; then
		echo "leaving existing configuration untouched: $CONFIG_PATH"
	fi
	exit 0
fi

ARCHIVE="augur_${VERSION#v}_${GOOS}_${GOARCH}.tar.gz"
BASE_URL="https://github.com/$REPOSITORY/releases/$VERSION_PATH/download"
RAW_URL="https://raw.githubusercontent.com/$REPOSITORY/$VERSION_PATH"
TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/augur-install.XXXXXX")
cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT INT TERM

run mkdir -p "$TMP_DIR" "$PREFIX/bin" "$CONFIG_DIR"
if [ "$DRY_RUN" -eq 0 ]; then
	curl --fail --silent --show-error --location "$BASE_URL/$ARCHIVE" -o "$TMP_DIR/$ARCHIVE"
	tar -xzf "$TMP_DIR/$ARCHIVE" -C "$TMP_DIR"
	curl --fail --silent --show-error --location "$RAW_URL/config/augur.example.json" -o "$TMP_DIR/config.example.json"
fi
run install -m 0755 "$TMP_DIR/augur" "$BINARY_PATH"
if [ ! -e "$CONFIG_PATH" ]; then
	run install -m 0600 "$TMP_DIR/config.example.json" "$CONFIG_PATH"
	echo "installed example configuration: $CONFIG_PATH; review it before starting Augur"
else
	echo "leaving existing configuration untouched: $CONFIG_PATH"
fi
echo "installed $BINARY_PATH"
