#!/usr/bin/env python3
"""Atomic dist activation with rename swap and restore-on-failure."""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

REQUIRED_SOURCE = [
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
]


def activate_dist(live: Path, staging: Path) -> None:
    dist_src = staging / 'dist'
    dist_live = live / 'dist'
    if not dist_src.is_dir():
        raise SystemExit('staging dist missing')
    next_dir = live / 'dist.next'
    prev_dir = live / 'dist.prev'
    if next_dir.exists():
        shutil.rmtree(next_dir)
    shutil.copytree(dist_src, next_dir, symlinks=True)
    try:
        if dist_live.exists():
            if prev_dir.exists():
                shutil.rmtree(prev_dir)
            dist_live.rename(prev_dir)
        next_dir.rename(dist_live)
    except Exception:
        if prev_dir.exists() and not dist_live.exists():
            prev_dir.rename(dist_live)
        if next_dir.exists():
            shutil.rmtree(next_dir, ignore_errors=True)
        raise


def restore_dist(live: Path, backup_dist: Path) -> None:
    dist_live = live / 'dist'
    if not backup_dist.is_dir():
        raise SystemExit('backup dist missing')
    tmp = live / 'dist.restore'
    if tmp.exists():
        shutil.rmtree(tmp)
    shutil.copytree(backup_dist, tmp, symlinks=True)
    if dist_live.exists():
        shutil.rmtree(dist_live)
    tmp.rename(dist_live)


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print('usage: atomic_dist.py activate LIVE STAGING | restore LIVE BACKUP_DIST', file=sys.stderr)
        return 2
    cmd = argv[1]
    if cmd == 'activate':
        activate_dist(Path(argv[2]), Path(argv[3]))
        print('DIST_ACTIVATED')
        return 0
    if cmd == 'restore':
        restore_dist(Path(argv[2]), Path(argv[3]))
        print('DIST_RESTORED')
        return 0
    print('unknown command', cmd, file=sys.stderr)
    return 2


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
