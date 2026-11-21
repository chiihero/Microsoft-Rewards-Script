#!/usr/bin/env bash
# Explicit Instant Win signup (and optional daily-only follow-up).
# Never starts a full Rewards rerun. Never copies sessions or profiles.
# Acquires the same Rewards flock, or inherits INSTANT_WIN_LOCK_FD.
# Contact data must already be in a mode 0600 file; this script does not
# accept phone numbers on the command line.
set -euo pipefail
export TZ="${TZ:-Asia/Shanghai}"

APP_ROOT="${APP_ROOT:-/root/Microsoft-Rewards-Script}"
LOCK_FILE="${LOCK_FILE:-/tmp/rewards-daily.lock}"
PROFILE="${DAILY_INSTANT_WIN_SIGNUP_PROFILE:-}"

if [[ "${DAILY_INSTANT_WIN_SIGNUP:-}" != "1" ]]; then
  printf 'Refusing to start: set DAILY_INSTANT_WIN_SIGNUP=1 explicitly.\n' >&2
  exit 2
fi
if [[ -z "${PROFILE}" || ! -f "${PROFILE}" ]]; then
  printf 'Refusing to start: DAILY_INSTANT_WIN_SIGNUP_PROFILE must be a 0600 file.\n' >&2
  exit 2
fi
mode=$(stat -c '%a' "${PROFILE}" 2>/dev/null || stat -f '%OLp' "${PROFILE}")
if [[ "${mode}" != "600" ]]; then
  printf 'Refusing to start: signup profile mode is %s, required 600.\n' "${mode}" >&2
  exit 2
fi

if [[ -n "${INSTANT_WIN_LOCK_FD:-}" ]]; then
  if [[ ! -e "/proc/self/fd/${INSTANT_WIN_LOCK_FD}" ]]; then
    printf 'INSTANT_WIN_LOCK_FD=%s is not open in this process.\n' "${INSTANT_WIN_LOCK_FD}" >&2
    exit 75
  fi
  held="$(readlink "/proc/self/fd/${INSTANT_WIN_LOCK_FD}" 2>/dev/null || true)"
  want="$(readlink -f "${LOCK_FILE}" 2>/dev/null || echo "${LOCK_FILE}")"
  if [[ -n "${held}" && -n "${want}" && "${held}" != "${want}" ]]; then
    printf 'INSTANT_WIN_LOCK_FD points at %s, not %s.\n' "${held}" "${want}" >&2
    exit 75
  fi
  if ! flock -n "${INSTANT_WIN_LOCK_FD}"; then
    printf 'Inherited lock FD does not hold %s.\n' "${LOCK_FILE}" >&2
    exit 75
  fi
  printf 'LOCK_INHERITED fd=%s %s pid=%s\n' "${INSTANT_WIN_LOCK_FD}" "${LOCK_FILE}" "$$"
else
  exec 9>>"${LOCK_FILE}"
  if ! flock -n 9; then
    printf 'Rewards lock is held (%s); not starting signup.\n' "${LOCK_FILE}" >&2
    exit 75
  fi
  printf 'LOCK_HELD %s pid=%s\n' "${LOCK_FILE}" "$$"
fi

if pgrep -f "node ./dist/index.js" >/dev/null; then
  printf 'node ./dist/index.js is already running; not starting a second session.\n' >&2
  exit 75
fi

cd "${APP_ROOT}"
export DAILY_INSTANT_WIN_SIGNUP=1
# Daily click is opt-in and still will not auto-register.
# Leave DAILY_INSTANT_WIN_ONLY as the caller set it.
npm start
