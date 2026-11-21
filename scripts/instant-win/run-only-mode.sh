#!/usr/bin/env bash
# Run only the daily Instant Win activity, reusing existing sessions and today's searches.
# Does not farm extra search points. Takes the existing Rewards lock.
set -euo pipefail
export TZ="${TZ:-Asia/Shanghai}"
APP_ROOT="${APP_ROOT:-/opt/mrs-keep-earning/app}"
LOCK_FILE="${LOCK_FILE:-/opt/mrs-keep-earning/login-desktop/login.lock}"
LOG="${LOG:-/opt/mrs-keep-earning/logs/rewards-instant-win-$(date '+%Y%m%d-%H%M%S').log}"
DIAGNOSE="${DAILY_INSTANT_WIN_DIAGNOSE:-0}"
mkdir -p "$(dirname "${LOG}")"
chmod 700 "$(dirname "${LOG}")" 2>/dev/null || true
touch "${LOG}"
chmod 600 "${LOG}"

if pgrep -f 'dist/index.js' >/dev/null 2>&1; then
  printf 'dist/index.js already running; not starting a second copy.\n' >&2
  exit 75
fi

exec 9>"${LOCK_FILE}"
if ! flock -n 9; then
  printf 'SKIP: existing Rewards or login workload holds %s\n' "${LOCK_FILE}" >&2
  exit 75
fi

export DAILY_INSTANT_WIN_ONLY=1
if [[ "${DIAGNOSE}" == "1" ]]; then
  export DAILY_INSTANT_WIN_DIAGNOSE=1
  export DAILY_INSTANT_WIN_DIAGNOSE_DIR="${DAILY_INSTANT_WIN_DIAGNOSE_DIR:-/opt/mrs-keep-earning/logs/instant-win-diagnose-$(date '+%Y%m%d')}"
  mkdir -p "${DAILY_INSTANT_WIN_DIAGNOSE_DIR}"
  chmod 700 "${DAILY_INSTANT_WIN_DIAGNOSE_DIR}"
fi

{
  printf '======= START %s diagnose=%s =======\n' "$(date '+%F %T %Z')" "${DIAGNOSE}"
  cd "${APP_ROOT}"
  timeout 40m npm start
  printf '======= END %s exit:%s =======\n' "$(date '+%F %T %Z')" "$?"
} >>"${LOG}" 2>&1
printf 'LOG %s\n' "${LOG}"
