#!/bin/sh
# Package already-built Linux x86_64 binaries; never installs on the build host.
set -eu
cd "$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
manager=$(realpath "$1")
engine=$(realpath "$2")
mkdir -p "$3"
artifacts=$(realpath "$3")
version=$(awk -F '"' '/^version = "/ { print $2; exit }' headless/Cargo.toml)
test -n "$version"
for binary in "$manager" "$engine"; do
  test -f "$binary" && test -x "$binary"
  test "$(od -An -tx1 -N4 "$binary" | tr -d ' \n')" = 7f454c46
  test "$(od -An -tx1 -j18 -N2 "$binary" | tr -d ' \n')" = 3e00
done
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
archive_root="$work/openfortivpn-manager-headless-linux-x86_64"
mkdir -p "$archive_root/bin" "$archive_root/libexec" "$archive_root/examples"
install -m 0755 "$manager" "$archive_root/bin/openfortivpn-manager-headless"
install -m 0755 "$engine" "$archive_root/libexec/openfortivpn"
install -m 0755 headless/scripts/install-bundle.sh "$archive_root/install.sh"
install -m 0644 headless/README.md "$archive_root/README.md"
cp -a headless/examples/. "$archive_root/examples/"
tar -C "$work" -czf "$artifacts/openfortivpn-manager-headless_${version}_linux_x86_64.tar.gz" \
  openfortivpn-manager-headless-linux-x86_64

deb_root="$work/debian"
mkdir -p "$deb_root/DEBIAN" "$deb_root/usr/lib/openfortivpn-manager-headless" \
  "$deb_root/usr/share/doc/openfortivpn-manager-headless/examples"
sed "s/^Version:.*/Version: $version/" headless/packaging/debian/control > "$deb_root/DEBIAN/control"
install -m 0755 headless/packaging/debian/postinst "$deb_root/DEBIAN/postinst"
install -m 0755 headless/packaging/debian/prerm "$deb_root/DEBIAN/prerm"
install -m 0755 "$manager" "$deb_root/usr/lib/openfortivpn-manager-headless/manager"
install -m 0755 "$engine" "$deb_root/usr/lib/openfortivpn-manager-headless/openfortivpn"
install -m 0644 headless/README.md "$deb_root/usr/share/doc/openfortivpn-manager-headless/README.md"
cp -a headless/examples/. "$deb_root/usr/share/doc/openfortivpn-manager-headless/examples/"
dpkg-deb --build --root-owner-group "$deb_root" "$artifacts/openfortivpn-manager-headless_${version}_amd64.deb"
