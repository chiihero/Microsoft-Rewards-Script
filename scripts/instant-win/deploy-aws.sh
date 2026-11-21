#!/usr/bin/env bash
# Narrow Instant Win deploy. Holds the SAME Rewards flock from idle
# validation through backup, staging build, and activation.
# Does not change VPN, cron, region, login, KeepEarning, .env, or sessions.
# Does not build live dist in-place. Do not deploy while the daily service cycle
# is still running; this script will exit 75 if the lock or app is busy.
set -euo pipefail
export TZ="${TZ:-Asia/Shanghai}"

APP_ROOT="${APP_ROOT:-/opt/mrs-keep-earning/app}"
LOCK_FILE="${LOCK_FILE:-/opt/mrs-keep-earning/login-desktop/login.lock}"
BACKUP_ROOT="${BACKUP_ROOT:-/opt/mrs-keep-earning/backups}"
HANDOFF_DIR="$(cd "$(dirname "$0")" && pwd)"
TS="$(date '+%Y%m%d-%H%M%S')"
BACKUP_DIR="${BACKUP_ROOT}/mrs-daily-instant-win-${TS}"
STAGING_ROOT="${STAGING_ROOT:-$(dirname "${APP_ROOT}")/instant-win-stage-deploy}"
NODE_BIN="${NODE_BIN:-$(command -v node)}"
NPM_BIN="${NPM_BIN:-$(command -v npm)}"

if [[ ! -f "${APP_ROOT}/src/index.ts" ]]; then
  printf 'APP_ROOT does not look like the Rewards script: %s\n' "${APP_ROOT}" >&2
  exit 1
fi
if [[ -z "${NODE_BIN}" || -z "${NPM_BIN}" || ! -x "${NODE_BIN}" || ! -x "${NPM_BIN}" ]]; then
  printf 'Isolated Node/npm not found. Set NODE_BIN and NPM_BIN.\n' >&2
  exit 1
fi

mkdir -p "$(dirname "${LOCK_FILE}")"
# Acquire the same Rewards flock, or inherit an already-held FD from a
# wrapper that waited on this lock. Never reopen the lock file on a new FD
# while a parent still holds it (that would self-deadlock).
if [[ -n "${INSTANT_WIN_LOCK_FD:-}" ]]; then
  if [[ ! -e "/proc/self/fd/${INSTANT_WIN_LOCK_FD}" ]]; then
    printf 'INSTANT_WIN_LOCK_FD=%s is not open in this process.\n' "${INSTANT_WIN_LOCK_FD}" >&2
    exit 75
  fi
  held="$(readlink "/proc/self/fd/${INSTANT_WIN_LOCK_FD}" 2>/dev/null || true)"
  want="$(readlink -f "${LOCK_FILE}" 2>/dev/null || realpath "${LOCK_FILE}" 2>/dev/null || echo "${LOCK_FILE}")"
  if [[ -n "${held}" && -n "${want}" && "${held}" != "${want}" ]]; then
    printf 'INSTANT_WIN_LOCK_FD=%s points at %s, not %s.\n' "${INSTANT_WIN_LOCK_FD}" "${held}" "${want}" >&2
    exit 75
  fi
  if ! flock -n "${INSTANT_WIN_LOCK_FD}"; then
    printf 'Inherited lock FD %s does not hold %s.\n' "${INSTANT_WIN_LOCK_FD}" "${LOCK_FILE}" >&2
    exit 75
  fi
  if [[ "${INSTANT_WIN_LOCK_FD}" != "9" ]]; then
    eval "exec 9>&${INSTANT_WIN_LOCK_FD}"
  fi
  printf 'LOCK_INHERITED fd=%s %s pid=%s\n' "${INSTANT_WIN_LOCK_FD}" "${LOCK_FILE}" "$$"
else
  exec 9>>"${LOCK_FILE}"
  if ! flock -n 9; then
    printf 'Rewards or login lock is held (%s); not deploying.\n' "${LOCK_FILE}" >&2
    exit 75
  fi
  printf 'LOCK_HELD %s pid=%s\n' "${LOCK_FILE}" "$$"
fi

if [[ -n "${SYSTEMD_UNIT:-}" ]]; then
  if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet "${SYSTEMD_UNIT}"; then
      printf 'systemd unit %s is still active; not deploying.\n' "${SYSTEMD_UNIT}" >&2
      exit 75
    fi
    printf 'SYSTEMD_INACTIVE %s\n' "${SYSTEMD_UNIT}"
  fi
fi

if [[ "${INSTANT_WIN_DEPLOY_SKIP_MUTATION:-0}" == "1" ]]; then
  if [[ -n "${INSTANT_WIN_DEPLOY_HOLD_SECONDS:-}" ]]; then
    sleep "${INSTANT_WIN_DEPLOY_HOLD_SECONDS}"
  fi
  printf 'SKIP_MUTATION lock still held by pid %s\n' "$$"
  exit 0
fi

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
    if 'deploy-aws.sh' in cmd or 'rollback.sh' in cmd or 'wait-and-deploy' in cmd or 'iw-queue-' in cmd:
        continue
    if 'dist/index.js' in cmd or 'login-desktop' in cmd:
        busy.append(f'{entry.name} {cmd.strip()}')
        continue
    if app in cmd and ('npm start' in cmd or 'npm run start' in cmd):
        busy.append(f'{entry.name} {cmd.strip()}')
if busy:
    sys.stderr.write('App or login process is running under the lock; not deploying:\n')
    sys.stderr.write('\n'.join(busy) + '\n')
    sys.exit(75)
print('IDLE_OK')
PY

mkdir -p "${BACKUP_DIR}"
chmod 700 "${BACKUP_DIR}"
python3 - "${APP_ROOT}" "${BACKUP_DIR}" << 'PY'
import os, shutil, sys
from pathlib import Path
app = Path(sys.argv[1])
backup = Path(sys.argv[2])
relatives = [
    'src/index.ts',
    'src/functions/Activities.ts',
    'src/constants/urls.ts',
    'src/interface/Config.ts',
    'src/util/Validator.ts',
    'src/util/ConfigEnvOverrides.ts',
    'config.example.json',
    'src/functions/activities/rewards/DailyInstantWin.ts',
    'src/functions/activities/rewards/totalPrizeDropPage.ts',
    'src/functions/activities/rewards/instantWinStatus.ts',
    'src/functions/activities/rewards/instantWinSignup.ts',
    'src/functions/activities/rewards/InstantWinSignupRunner.ts',
]
for rel in relatives:
    src = app / rel
    if src.is_file():
        dest = backup / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)
dist = app / 'dist'
if dist.is_dir():
    shutil.copytree(dist, backup / 'dist', dirs_exist_ok=True, symlinks=True)
print('BACKUP_OK')
PY
printf 'BACKUP_DIR %s\n' "${BACKUP_DIR}"
printf '%s\n' "${BACKUP_DIR}" > "${BACKUP_ROOT}/mrs-daily-instant-win-latest"
chmod 600 "${BACKUP_ROOT}/mrs-daily-instant-win-latest"

rm -rf "${STAGING_ROOT}"
mkdir -p "${STAGING_ROOT}"
chmod 700 "${STAGING_ROOT}"
python3 - "${APP_ROOT}" "${STAGING_ROOT}" << 'PY'
import os, shutil, sys
from pathlib import Path
app = Path(sys.argv[1])
staging = Path(sys.argv[2])
exclude = {'.git', 'node_modules', 'sessions', 'logs', 'dist', '.env'}
def ignore(directory, names):
    dropped = set()
    for name in names:
        if name in exclude or name == 'config.json' or name.endswith('.env'):
            dropped.add(name)
    return dropped
shutil.copytree(app, staging, dirs_exist_ok=True, ignore=ignore, symlinks=True)
node_modules = app / 'node_modules'
if node_modules.is_dir():
    dest = staging / 'node_modules'
    if dest.exists() or dest.is_symlink():
        dest.unlink()
    os.symlink(node_modules, dest)
print('STAGING_COPY_OK')
PY

python3 "${HANDOFF_DIR}/apply-narrow-patch.py" --app-root "${STAGING_ROOT}" --payload "${HANDOFF_DIR}"

export PATH="$(dirname "${NODE_BIN}"):/usr/bin:/bin"
hash -r
(
  cd "${STAGING_ROOT}"
  "${NPM_BIN}" run build
)
printf 'STAGING_BUILD_OK %s\n' "$(date '+%F %T %Z')"

python3 - "${APP_ROOT}" "${STAGING_ROOT}" "${HANDOFF_DIR}" << 'PY'
import hashlib, shutil, sys
from pathlib import Path
live = Path(sys.argv[1])
staging = Path(sys.argv[2])
protected = [
    'src/functions/activities/rewards/KeepEarning.ts',
    'src/functions/activities/rewards/keepEarningDom.ts',
    'src/functions/activities/rewards/keepEarningOffers.ts',
]
activate = [
    'src/functions/activities/rewards/DailyInstantWin.ts',
    'src/functions/activities/rewards/totalPrizeDropPage.ts',
    'src/functions/activities/rewards/instantWinStatus.ts',
    'src/functions/activities/rewards/instantWinSignup.ts',
    'src/functions/activities/rewards/InstantWinSignupRunner.ts',
    'src/functions/Activities.ts',
    'src/constants/urls.ts',
    'src/interface/Config.ts',
    'src/util/Validator.ts',
    'src/util/ConfigEnvOverrides.ts',
    'src/index.ts',
    'config.example.json',
]
def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
for rel in protected:
    left = live / rel
    right = staging / rel
    if left.is_file() or right.is_file():
        if not left.is_file() or not right.is_file() or sha(left) != sha(right):
            sys.exit(f'protected file mismatch, refusing activation: {rel}')
print('keepEarning_unchanged_ok')
for rel in activate:
    src = staging / rel
    if not src.is_file():
        continue
    dest = live / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dest)
handoff = Path(sys.argv[3])
spec_path = handoff / 'atomic_dist.py'
if not spec_path.is_file():
    sys.exit('atomic_dist.py missing from handoff')
import importlib.util
spec = importlib.util.spec_from_file_location('atomic_dist', spec_path)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
mod.activate_dist(live, staging)
for rel in protected:
    left = live / rel
    right = staging / rel
    if left.is_file() and sha(left) != sha(right):
        sys.exit(f'protected file changed during activation: {rel}')
print('ACTIVATION_OK')
PY

printf 'BUILD_OK %s\n' "$(date '+%F %T %Z')"
printf 'Next: see README.md for ONLY-mode verification, locks, and receipt rules.\n'
