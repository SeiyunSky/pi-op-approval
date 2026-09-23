# pi-op-approval

A [Pi](https://pi.dev) extension that intercepts destructive agent operations and requires explicit user approval before execution.

## What it does

Every time the Pi agent proposes a destructive operation — file deletion, Docker resource removal, process/service termination, Git history rewrite, database truncation, infrastructure teardown, or software install/uninstall — a confirmation dialog appears **before the command runs**:

```
⚠ Protected operation: Delete or clear local files or directories.

Risk: Deleted local data may be unrecoverable.

Proposed bash operation:
rm -rf /var/tmp/cache

Allow this operation once?
[Yes]  [No]
```

If you deny, the command **does not execute**. The agent receives a clear block reason and stops retrying.

## Covered operations

| Category | Examples |
|---|---|
| File delete / clear | `rm -rf`, `Remove-Item`, `del`, `shutil.rmtree`, `find -delete` |
| File overwrite | `>` redirect, `Set-Content`, `Out-File`, Pi `write` on existing file |
| Docker stop | `docker stop`, `docker compose down`, `docker kill` |
| Docker delete | `docker rm`, `docker volume prune`, `docker image rm`, `docker system prune` |
| Process terminate | `kill`, `taskkill`, `pkill`, `killall`, `Stop-Process` |
| Service stop / delete | `systemctl stop/disable`, `sc stop/delete`, `net stop`, `pm2 stop/delete` |
| Git destructive | `git reset --hard`, `git clean -fd`, `git restore`, `git branch -D` |
| Database destructive | `DROP TABLE/DATABASE`, `TRUNCATE`, `DELETE FROM` |
| Orchestrator delete | `kubectl delete`, `helm uninstall`, `terraform destroy` |
| Uninstall | `npm uninstall`, `pip uninstall`, `winget uninstall`, `choco uninstall` |
| Install | `npm install`, `pip install`, `docker pull`, `apt install`, `winget install` |
| MCP tools | Any MCP tool whose name or arguments contain `delete/remove/stop/kill/terminate/uninstall/install` |

## What it does NOT intercept

- Commands you type manually with `!` or `!!` in Pi — those are your explicit actions.
- Operations initiated outside Pi (external terminals, other programs).

## Audit log

Every approval decision (allow or deny) is appended to:

```
~/.pi/agent/destructive-operation-guard.jsonl
```

Format:

```json
{"timestamp":"2025-09-17T10:23:45.000Z","operation":"file-delete","tool":"bash","approved":false}
```

## Installation

```bash
pi install npm:pi-op-approval
```

Or install from git:

```bash
pi install git:github.com/SeiyunSky/pi-op-approval
```

## Requirements

- Pi `>= 0.85.0`
- Node.js `>= 18`

## License

MIT
