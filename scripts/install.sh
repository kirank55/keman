#!/bin/sh
# Install the keman binary from a GitHub release.
#
#   curl -fsSL https://raw.githubusercontent.com/kirank55/keman/main/scripts/install.sh | sh
#
# KEMAN_VERSION   tag to install (default: newest release, prereleases included)
# KEMAN_INSTALL_DIR  where to put keman (default: /usr/local/bin if writable, else ~/.local/bin)
#
# The SHA-256 sum is always checked. When cosign is installed, the keyless
# signature is checked too.
set -eu

REPO="kirank55/keman"

fail() {
  echo "install.sh: $*" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || fail "$1 is required"
}

need curl
need uname

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) fail "unsupported OS $(uname -s); download a binary from https://github.com/$REPO/releases" ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *) fail "unsupported CPU $(uname -m)" ;;
esac

version="${KEMAN_VERSION:-}"
if [ -z "$version" ]; then
  # /releases/latest skips prereleases, and the beta is one.
  version="$(curl -fsSL "https://api.github.com/repos/$REPO/releases?per_page=1" |
    sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)"
  [ -n "$version" ] || fail "could not find a release; set KEMAN_VERSION"
fi

bin="keman_${os}_${arch}"
base="https://github.com/$REPO/releases/download/$version"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

echo "downloading keman $version for $os/$arch"
curl -fsSL -o "$tmp/$bin" "$base/$bin" || fail "download failed: $base/$bin"
curl -fsSL -o "$tmp/$bin.sha256" "$base/$bin.sha256" || fail "download failed: $base/$bin.sha256"

want="$(awk '{ print $1 }' "$tmp/$bin.sha256")"
if command -v sha256sum >/dev/null 2>&1; then
  got="$(sha256sum "$tmp/$bin" | awk '{ print $1 }')"
elif command -v shasum >/dev/null 2>&1; then
  got="$(shasum -a 256 "$tmp/$bin" | awk '{ print $1 }')"
else
  fail "sha256sum or shasum is required to check the download"
fi
[ "$got" = "$want" ] || fail "checksum mismatch for $bin (got $got, want $want)"
echo "checksum ok"

if command -v cosign >/dev/null 2>&1; then
  curl -fsSL -o "$tmp/$bin.bundle" "$base/$bin.bundle" || fail "download failed: $base/$bin.bundle"
  cosign verify-blob --bundle "$tmp/$bin.bundle" \
    --certificate-identity-regexp "^https://github.com/$REPO/\.github/workflows/release\.yml@" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    "$tmp/$bin" >/dev/null 2>&1 || fail "cosign signature check failed for $bin"
  echo "signature ok"
fi

dir="${KEMAN_INSTALL_DIR:-}"
if [ -z "$dir" ]; then
  if [ -w /usr/local/bin ]; then
    dir=/usr/local/bin
  else
    dir="$HOME/.local/bin"
  fi
fi
mkdir -p "$dir"
chmod 755 "$tmp/$bin"
mv "$tmp/$bin" "$dir/keman"
echo "installed $dir/keman"

case ":$PATH:" in
  *":$dir:"*) ;;
  *) echo "add $dir to your PATH:  export PATH=\"$dir:\$PATH\"" ;;
esac
echo
echo "next:"
echo "  keman scan . --history    find keys you already leaked (no setup)"
echo "  keman init && keman       set up, then open the terminal UI"
