#!/bin/zsh
set -eu
set -o pipefail
cd "${0:A:h:h}"
export GIT_TERMINAL_PROMPT=0

manifests=(Cargo.toml headless/Cargo.toml app/src-tauri/helper/Cargo.toml)
if [[ "${VERIFY_SKIP_DESKTOP:-0}" != 1 ]]; then
  manifests+=(app/src-tauri/Cargo.toml)
fi
for manifest in $manifests; do
  cargo fmt --manifest-path "$manifest" --all -- --check
  cargo test --locked --manifest-path "$manifest" --all-targets --all-features
  cargo clippy --locked --manifest-path "$manifest" --all-targets --all-features -- -D warnings
done
if [[ "${VERIFY_SKIP_DESKTOP:-0}" != 1 ]]; then
  (cd app && corepack pnpm check && corepack pnpm build)
  node --test tests/desktop-state.test.mjs
  node --test tests/desktop-settings.test.mjs
fi
node --test tests/remote-client.test.mjs
node --test tests/release-manifest.test.mjs
node --test tests/dependency-audit.test.mjs
if [[ -n "${VERIFY_POWERSHELL:-}" ]]; then
  python3 crates/manager-core/tests/windows_nrpt_script.py --powershell "$VERIFY_POWERSHELL"
fi
build_dir="${VERIFY_C_BUILD_DIR:-${TMPDIR:-/tmp}/openfortivpn-verify-cmake}"
cmake -S . -B "$build_dir" -DBUILD_TESTING=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build "$build_dir" --parallel 4
ctest --test-dir "$build_dir" --output-on-failure
