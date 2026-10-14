# Project development rules

- Use `codex/` branches for substantial changes; commits explain the change in Chinese and English.
- Follow `$git-safe-ops` for Git operations; never reset or force-push shared branches.
- Use `rtk` for shell commands and zsh-compatible scripts on macOS.
- Run `zsh scripts/verify-local.zsh` before reporting completion. Platform/gateway tests require isolated environments; never modify the developer host network in tests.
- Preserve the traditional C CLI and v1 API. New capabilities must be explicit and may only be advertised after their platform tests pass.
- Keep child/process/network ownership until wait/reap and cleanup finish. Never use a log message or a stop request as proof of process exit.
- Credentials never belong in logs, API snapshots, task records, or fixtures containing real secrets.
- Browser validation uses `agent-browser`, headed Edge by default, and DOM inspection.
