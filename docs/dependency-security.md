# Dependency security evidence

The 2026-10-09 scan used cargo-audit 0.22.2 and npm's bulk advisory API against
the installed graph from pnpm 10.24.0. It identified and prompted these fixes:

- RUSTSEC-2026-0285: rustls 0.23.43 → 0.23.45 in all shipped consumers.
- RUSTSEC-2026-0258: h2 0.4.15 → 0.4.16 in desktop and headless.
- High npm findings in nanoid, source-map-js and devalue: compatible locked
  dependency updates. A cookie 0.6 low advisory was removed by the tested 0.7.2
  override. No advisories are suppressed in the scanner.

The desktop's Linux GTK dependency graph still reports advisory warnings for
glib 0.18.5 (RUSTSEC-2024-0429) and unmaintained proc-macro-error/unic crates.
glib is constrained by Tauri's GTK 3 stack; 0.20 is not a compatible transitive
replacement. The manager does not use VariantStrIter directly, but this is not
proof that all upstream call paths are unreachable. These remain tracked
upstream risks, not a claim that the whole graph is free of warnings. Do not
hide them with `--ignore`; review upstream Tauri/GTK changes before release.

The dependency-security workflow runs weekly and on PRs, with a separate
dependency review gate. Network or registry failures fail the scan. Platform
SBOMs include Cargo/npm dependencies, runtime DLL hashes and the engine's
OpenSSL version; operating-system OpenSSL/runtime packages also need the
platform vendor's patch policy and release acceptance.

The latest continuation re-ran cargo-audit 0.22.2 against all four lockfiles:
zero vulnerabilities, with the desktop warnings above still present. The
installed npm graph contained 121 packages and no advisories. Retained JSON
evidence is in `.codex-tasks/reliability-control-plane/evidence/`.
