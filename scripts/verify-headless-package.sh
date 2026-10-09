#!/bin/sh
# Real dpkg file transitions with a synthetic systemctl, inside Docker only.
set -eu
if [ "$(uname -s)" != Linux ] || [ "$(id -u)" != 0 ] || [ ! -f /.dockerenv ] || [ "${OFV_DISPOSABLE_PACKAGE_TEST:-0}" != 1 ]; then
  echo "This test requires an explicitly enabled disposable Linux Docker container" >&2
  exit 2
fi
package=$(realpath "$1")
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
dpkg-deb --raw-extract "$package" "$work/old"
candidate_version=$(dpkg-deb --field "$package" Version)
old_version="${candidate_version}~matrix1"
sed "s/^Version:.*/Version: $old_version/" "$work/old/DEBIAN/control" > "$work/control"
mv "$work/control" "$work/old/DEBIAN/control"
printf '\nsynthetic-prior-manager-payload\n' >> "$work/old/usr/lib/openfortivpn-manager-headless/manager"
printf '\nsynthetic-prior-engine-payload\n' >> "$work/old/usr/lib/openfortivpn-manager-headless/openfortivpn"
dpkg-deb --build --root-owner-group "$work/old" "$work/old.deb"

cat > /usr/bin/systemctl <<'CONTROL'
#!/bin/sh
printf '%s\n' "$*" >> /tmp/ofv-package-systemctl-calls
exit 0
CONTROL
chmod 755 /usr/bin/systemctl
manager=/usr/local/sbin/openfortivpn-manager-headless
engine=/usr/local/libexec/openfortivpn-manager-headless/openfortivpn
unit=/etc/systemd/system/openfortivpn-manager-headless.service
hash() { sha256sum "$1" | cut -d ' ' -f 1; }
old_manager=$(hash "$work/old/usr/lib/openfortivpn-manager-headless/manager")
old_engine=$(hash "$work/old/usr/lib/openfortivpn-manager-headless/openfortivpn")
dpkg -i "$work/old.deb"
test "$(hash "$manager")" = "$old_manager"
test "$(hash "$engine")" = "$old_engine"
printf '\n# synthetic prior unit payload\n' >> "$unit"
old_unit=$(hash "$unit")
token_before=$(hash /etc/openfortivpn-manager-headless/access-token)

# An unfinished durable owner blocks every maintenance operation, even after
# its process lock was lost. This is only a synthetic record in this container.
authority=/var/lib/openfortivpn-manager/network/active.json
cat > "$authority" <<'OWNER'
{"schemaVersion":2,"owner":{"attemptId":"synthetic-package-owner","manager":"headless","uid":0,"processGroup":0,"preSpawnGated":true}}
OWNER
chmod 600 "$authority"
for action in install rollback uninstall; do
  case "$action" in
    install) set -- install --engine "$engine" --no-start --quiet ;;
    rollback) set -- rollback --no-start ;;
    uninstall) set -- uninstall ;;
  esac
  if "$manager" "$@" > "$work/busy" 2>&1; then
    echo "Maintenance bypassed the durable network owner: $action" >&2
    exit 1
  fi
  grep -q 'system network authority requires recovery' "$work/busy"
  test "$(hash "$manager")" = "$old_manager"
  test "$(hash "$engine")" = "$old_engine"
  test "$(hash "$unit")" = "$old_unit"
  test "$(hash /etc/openfortivpn-manager-headless/access-token)" = "$token_before"
done
rm "$authority"

# Unpack updates only package staging. The running installation is unchanged
# until postinst commits all fixed targets through the durable bundle journal.
dpkg --unpack "$package"
test "$(hash "$manager")" = "$old_manager"
test "$(hash "$engine")" = "$old_engine"
test "$(hash "$unit")" = "$old_unit"
dpkg --configure openfortivpn-manager-headless
test "$(hash "$manager")" = "$(hash /usr/lib/openfortivpn-manager-headless/manager)"
test "$(hash "$engine")" = "$(hash /usr/lib/openfortivpn-manager-headless/openfortivpn)"
test "$(hash "$unit")" != "$old_unit"
test "$(hash /etc/openfortivpn-manager-headless/access-token)" = "$token_before"
"$manager" rollback --no-start
test "$(hash "$manager")" = "$old_manager"
test "$(hash "$engine")" = "$old_engine"
test "$(hash "$unit")" = "$old_unit"
test "$(hash /etc/openfortivpn-manager-headless/access-token)" = "$token_before"
"$manager" --help >/dev/null
dpkg --remove openfortivpn-manager-headless
test ! -e "$manager"
test ! -e "$engine"
test ! -e "$unit"
test -e /etc/openfortivpn-manager-headless/access-token
printf '%s\n' 'PASS: dpkg staging, upgrade, manager/engine/unit rollback, busy-owner refusal, token preservation and removal; systemctl was synthetic'
