#!/bin/sh
# Build as the invoking user, then execute only inside a fresh network namespace.
set -eu
if [ "$(uname -s)" != Linux ]; then
  echo "Linux network namespace verification requires Linux" >&2
  exit 2
fi
cd "$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
artifacts=$(mktemp)
trap 'rm -f "$artifacts"' EXIT HUP INT TERM
cargo test --locked -p openfortivpn-manager-core --features linux-network \
  --no-run --message-format=json > "$artifacts"
test_binary=$(python3 - "$artifacts" <<'PY'
import json, pathlib, sys
matches=[]
for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
    item=json.loads(line)
    if item.get('reason')=='compiler-artifact' and item.get('target',{}).get('name')=='openfortivpn_manager_core' and item.get('profile',{}).get('test') and item.get('executable'):
        matches.append(item['executable'])
if len(matches)!=1:
    raise SystemExit('Cannot identify the Linux core test executable')
print(pathlib.Path(matches[0]).resolve())
PY
)
sudo -n unshare --net -- /bin/sh -eu -c '
  ip link set lo up
  OFV_ISOLATED_NETWORK_TEST=1 exec "$1" network_ --include-ignored --test-threads=1 --nocapture
' sh "$test_binary"
