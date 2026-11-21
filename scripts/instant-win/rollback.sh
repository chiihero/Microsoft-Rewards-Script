#!/usr/bin/env bash
# Restore source and dist from an Instant Win backup. Holds the SAME flock.
# Does not reset the repo, and does not rebuild live dist in-place when dist is in the backup.
set -euo pipefail
export TZ="${TZ:-Asia/Shanghai}"
APP_ROOT="${APP_ROOT:-/opt/mrs-keep-earning/app}"
LOCK_FILE="${LOCK_FILE:-/opt/mrs-keep-earning/login-desktop/login.lock}"
BACKUP_ROOT="${BACKUP_ROOT:-/opt/mrs-keep-earning/backups}"
BACKUP_DIR="${1:-}"
if [[ -z "${BACKUP_DIR}" && -f "${BACKUP_ROOT}/mrs-daily-instant-win-latest" ]]; then
  BACKUP_DIR="$(cat "${BACKUP_ROOT}/mrs-daily-instant-win-latest")"
fi
if [[ -z "${BACKUP_DIR}" || ! -d "${BACKUP_DIR}" ]]; then
  printf 'Usage: %s /path/to/mrs-daily-instant-win-YYYYMMDD-HHMMSS\n' "$0" >&2
  exit 1
fi

mkdir -p "$(dirname "${LOCK_FILE}")"
exec 9>>"${LOCK_FILE}"
if ! flock -n 9; then
  printf 'Rewards or login lock is held (%s); not rolling back.\n' "${LOCK_FILE}" >&2
  exit 75
fi
printf 'LOCK_HELD %s pid=%s\n' "${LOCK_FILE}" "$$"

python3 - "${APP_ROOT}" "$$" << 'PY'
import os, sys
from pathlib import Path
app = os.path.abspath(sys.argv[1])
self_pid = sys.argv[2]
busy = []
for entry in Path('/proc').iterdir():
    if not entry.name.isdigit() or entry.name == self_pid:
        continue
    try:
        cmd = Path(entry, 'cmdline').read_bytes().replace(b'\x00', b' ').decode('utf-8', 'replace')
    except OSError:
        continue
    if 'deploy-aws.sh' in cmd or 'rollback.sh' in cmd:
        continue
    if 'dist/index.js' in cmd or 'login-desktop' in cmd or (app in cmd and 'npm start' in cmd):
        busy.append(f'{entry.name} {cmd.strip()}')
if busy:
    sys.stderr.write('App or login process is running; not rolling back:\n')
    sys.stderr.write('\n'.join(busy) + '\n')
    sys.exit(75)
print('IDLE_OK')
PY

python3 - "${APP_ROOT}" "${BACKUP_DIR}" << 'PY'
import os, shutil, sys
from pathlib import Path
app = Path(sys.argv[1])
backup = Path(sys.argv[2])
for path in backup.rglob('*'):
    if not path.is_file() and not path.is_symlink():
        continue
    rel = path.relative_to(backup)
    dest = app / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() or dest.is_symlink():
        if dest.is_dir() and not dest.is_symlink():
            continue
        dest.unlink()
    if path.is_symlink():
        dest.symlink_to(os.readlink(path))
    else:
        shutil.copy2(path, dest)
    print('restored', rel)
# If dist was backed up as a tree, copytree already happened file-by-file.
print('RESTORE_OK')
PY

printf 'ROLLBACK_OK from %s at %s\n' "${BACKUP_DIR}" "$(date '+%F %T %Z')"
