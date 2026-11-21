#!/usr/bin/env python3
"""Narrow-merge Daily Instant Win into an existing Microsoft-Rewards-Script tree.

Never overwrites KeepEarning / keepEarningDom / keepEarningOffers.
Never touches .env, sessions, VPN, cron, or account geo settings.
Compatible with 4.3.2.4 (optional worker flag, no markExecuted) and 4.3.6+.
"""
from __future__ import annotations

import argparse
import hashlib
import shutil
import sys
from pathlib import Path

PROTECTED = [
    'src/functions/activities/rewards/KeepEarning.ts',
    'src/functions/activities/rewards/keepEarningDom.ts',
    'src/functions/activities/rewards/keepEarningOffers.ts',
]

def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def copy_new_modules(app: Path, payload: Path) -> None:
    dest = app / 'src/functions/activities/rewards'
    dest.mkdir(parents=True, exist_ok=True)
    activity = (payload / 'src/functions/activities/rewards/DailyInstantWin.ts').read_text()
    # 4.3.2.4 BaseActivity has no markExecuted
    base = (app / 'src/functions/activities/BaseActivity.ts').read_text() if (app / 'src/functions/activities/BaseActivity.ts').exists() else ''
    if 'markExecuted' not in base:
        activity = activity.replace('        this.markExecuted()\n', '')
        print('adapted DailyInstantWin.ts for BaseActivity without markExecuted')
    (dest / 'DailyInstantWin.ts').write_text(activity)
    for name in (
        'totalPrizeDropPage.ts',
        'instantWinStatus.ts',
        'instantWinSignup.ts',
        'InstantWinSignupRunner.ts',
    ):
        src = payload / 'src/functions/activities/rewards' / name
        if not src.is_file():
            sys.exit(f'missing payload module: {name}')
        shutil.copy2(src, dest / name)
    print('copied DailyInstantWin.ts, totalPrizeDropPage.ts, instantWinStatus.ts, instantWinSignup.ts, InstantWinSignupRunner.ts')



def ensure_signup_activities(app: Path) -> None:
    path = app / 'src/functions/Activities.ts'
    text = path.read_text()
    if 'doInstantWinSignup' in text:
        print('Activities.ts already has InstantWinSignup')
        return
    if "import { DailyInstantWin } from './activities/rewards/DailyInstantWin'\n" in text and 'InstantWinSignup' not in text:
        text = text.replace(
            "import { DailyInstantWin } from './activities/rewards/DailyInstantWin'\n"
            "import type { DailyInstantWinResult } from './activities/rewards/DailyInstantWin'\n",
            "import { DailyInstantWin } from './activities/rewards/DailyInstantWin'\n"
            "import type { DailyInstantWinResult } from './activities/rewards/DailyInstantWin'\n"
            "import { InstantWinSignup } from './activities/rewards/InstantWinSignupRunner'\n"
            "import type { InstantWinSignupResult } from './activities/rewards/InstantWinSignupRunner'\n",
            1,
        )
    needle = (
        "    doDailyInstantWin = async (): Promise<DailyInstantWinResult> => {\n"
        "        const activity = new DailyInstantWin(this.bot)\n"
        "        return await activity.run()\n"
        "    }\n"
    )
    if needle not in text:
        sys.exit('doDailyInstantWin method not found; cannot add signup hook')
    addition = (
        needle
        + "\n"
        + "    doInstantWinSignup = async (): Promise<InstantWinSignupResult> => {\n"
        + "        const activity = new InstantWinSignup(this.bot)\n"
        + "        return await activity.run()\n"
        + "    }\n"
    )
    path.write_text(text.replace(needle, addition, 1))
    print('patched Activities.ts signup hook')


def ensure_signup_index(path: Path, text: str) -> None:
    if "DAILY_INSTANT_WIN_SIGNUP === '1'" in text:
        print('index.ts already has signup-only hooks')
        return
    if "if (process.env.DAILY_INSTANT_WIN_ONLY === '1') {" in text:
        text = text.replace(
            "if (process.env.DAILY_INSTANT_WIN_ONLY === '1') {",
            "if (process.env.DAILY_INSTANT_WIN_ONLY === '1' || process.env.DAILY_INSTANT_WIN_SIGNUP === '1') {",
            1,
        )
    old_body = (
        "                opened.session = await this.createDesktopSession(account)\n"
        "                await this.activities.doDailyInstantWin()\n"
        "                return { initialPoints: this.userData.currentPoints ?? 0, collectedPoints: 0 }\n"
    )
    new_body = (
        "                opened.session = await this.createDesktopSession(account)\n"
        "                if (process.env.DAILY_INSTANT_WIN_SIGNUP === '1') {\n"
        "                    await this.activities.doInstantWinSignup()\n"
        "                }\n"
        "                if (process.env.DAILY_INSTANT_WIN_ONLY === '1') {\n"
        "                    await this.activities.doDailyInstantWin()\n"
        "                }\n"
        "                return { initialPoints: this.userData.currentPoints ?? 0, collectedPoints: 0 }\n"
    )
    if old_body in text:
        text = text.replace(old_body, new_body, 1)
    path.write_text(text)
    print('index.ts signup-only hooks added')


def patch_activities(app: Path) -> None:
    path = app / 'src/functions/Activities.ts'
    text = path.read_text()
    if 'DailyInstantWin' in text:
        print('Activities.ts already has DailyInstantWin')
        return
    if "import { PunchCards } from './activities/rewards/PunchCards'\n" in text:
        text = text.replace(
            "import { PunchCards } from './activities/rewards/PunchCards'\n",
            "import { PunchCards } from './activities/rewards/PunchCards'\n"
            "import { DailyInstantWin } from './activities/rewards/DailyInstantWin'\n"
            "import type { DailyInstantWinResult } from './activities/rewards/DailyInstantWin'\n",
        )
    elif "import { KeepEarning } from './activities/rewards/KeepEarning'\n" in text:
        text = text.replace(
            "import { KeepEarning } from './activities/rewards/KeepEarning'\n",
            "import { KeepEarning } from './activities/rewards/KeepEarning'\n"
            "import { DailyInstantWin } from './activities/rewards/DailyInstantWin'\n"
            "import type { DailyInstantWinResult } from './activities/rewards/DailyInstantWin'\n",
        )
    else:
        sys.exit('unexpected Activities.ts imports; abort')
    needle = '    doClaimBonusPoints = async (): Promise<void> => {'
    if needle not in text:
        sys.exit('doClaimBonusPoints not found in Activities.ts; abort')
    text = text.replace(
        needle,
        '    doDailyInstantWin = async (): Promise<DailyInstantWinResult> => {\n'
        '        const activity = new DailyInstantWin(this.bot)\n'
        '        return await activity.run()\n'
        '    }\n\n' + needle,
        1,
    )
    path.write_text(text)
    print('patched Activities.ts')


def patch_urls(app: Path) -> None:
    path = app / 'src/constants/urls.ts'
    text = path.read_text()
    if 'sweepsBonus' in text:
        print('urls.ts already has sweepsBonus')
        return
    if '        dashboard: `${REWARDS}/dashboard`,' not in text:
        sys.exit('unexpected urls.ts; abort')
    path.write_text(text.replace(
        '        dashboard: `${REWARDS}/dashboard`,',
        '        dashboard: `${REWARDS}/dashboard`,\n        sweepsBonus: `${REWARDS}/sweeps/bonus`,',
        1,
    ))
    print('patched urls.ts')


def patch_config_type(app: Path) -> None:
    path = app / 'src/interface/Config.ts'
    text = path.read_text()
    if 'doDailyInstantWin' in text:
        print('Config.ts already has doDailyInstantWin')
        return
    if '    doVisualSearch: boolean\n}' not in text:
        sys.exit('unexpected ConfigWorkers; abort')
    path.write_text(text.replace(
        '    doVisualSearch: boolean\n}',
        '    doVisualSearch: boolean\n    doDailyInstantWin?: boolean\n}',
        1,
    ))
    print('patched Config.ts (optional worker, existing config.json unchanged)')


def patch_index(app: Path) -> None:
    path = app / 'src/index.ts'
    text = path.read_text()
    if 'runDailyInstantWinForAccount' in text:
        print('index.ts already patched for daily Instant Win')
        ensure_signup_index(path, text)
        return

    if 'const keepEarningOnly = process.env.KEEP_EARNING_ONLY === \'1\'' in text and 'if (!keepEarningOnly && shouldSkipRunToday())' in text:
        old_skip = '''        if (this.config.clusters <= 1 || cluster.isPrimary) {
            if (!keepEarningOnly && shouldSkipRunToday()) {
'''
        new_skip = '''        const dailyInstantWinOnly = process.env.DAILY_INSTANT_WIN_ONLY === '1'

        if (this.config.clusters <= 1 || cluster.isPrimary) {
            if (!keepEarningOnly && !dailyInstantWinOnly && shouldSkipRunToday()) {
'''
        if old_skip not in text:
            sys.exit('unexpected keepEarning skip block; abort')
        text = text.replace(old_skip, new_skip, 1)
        old_quiet = '''            if (!keepEarningOnly) {
                await waitForQuietHours()
            }
'''
        new_quiet = '''            if (!keepEarningOnly && !dailyInstantWinOnly) {
                await waitForQuietHours()
            }
'''
        if old_quiet not in text:
            sys.exit('unexpected quiet-hours block; abort')
        text = text.replace(old_quiet, new_quiet, 1)
        text = text.replace(
            '        if (!keepEarningOnly && cluster.isPrimary) {',
            '        if (!keepEarningOnly && !dailyInstantWinOnly && cluster.isPrimary) {',
            1,
        )
        if "this.logger.info('main', 'DAILY-INSTANT-WIN', '仅运行每日 Instant Win，跳过搜索和其他积分任务')" not in text:
            text = text.replace(
                old_quiet.replace('keepEarningOnly', 'keepEarningOnly && !dailyInstantWinOnly') if False else '',
                '',
                0,
            )
            # log line after quiet-hours close
            marker = '''            if (!keepEarningOnly && !dailyInstantWinOnly) {
                await waitForQuietHours()
            }
        }
'''
            if marker in text and '仅运行每日 Instant Win' not in text:
                text = text.replace(
                    marker,
                    marker + '''
        if (dailyInstantWinOnly) {
            this.logger.info('main', 'DAILY-INSTANT-WIN', '仅运行每日 Instant Win，跳过搜索和其他积分任务')
        }
''',
                    1,
                )
    else:
        old_skip = '''        if (this.config.clusters <= 1 || cluster.isPrimary) {
            if (shouldSkipRunToday()) {
'''
        new_skip = '''        const dailyInstantWinOnly = process.env.DAILY_INSTANT_WIN_ONLY === '1'

        if (this.config.clusters <= 1 || cluster.isPrimary) {
            if (!dailyInstantWinOnly && shouldSkipRunToday()) {
'''
        if old_skip not in text:
            sys.exit('unexpected skip-today block; abort')
        text = text.replace(old_skip, new_skip, 1)
        old_quiet = '''            await waitForQuietHours()
        }
'''
        new_quiet = '''            if (!dailyInstantWinOnly) {
                await waitForQuietHours()
            }
        }

        if (dailyInstantWinOnly) {
            this.logger.info('main', 'DAILY-INSTANT-WIN', '仅运行每日 Instant Win，跳过搜索和其他积分任务')
        }
'''
        if old_quiet not in text:
            sys.exit('unexpected quiet-hours block; abort')
        text = text.replace(old_quiet, new_quiet, 1)

    old_hook = '''                this.logger.info(
                    'main',
                    'SEARCH-MANAGER',
                    `搜索汇总 | 移动端=${mobilePoints} | 桌面端=${desktopPoints} | 额外=${bonusPoints} | 总计=${
                        mobilePoints + desktopPoints + bonusPoints
                    }`
                )

                if (this.config.workers.doClaimBonusPoints) {
'''
    new_hook = '''                this.logger.info(
                    'main',
                    'SEARCH-MANAGER',
                    `搜索汇总 | 移动端=${mobilePoints} | 桌面端=${desktopPoints} | 额外=${bonusPoints} | 总计=${
                        mobilePoints + desktopPoints + bonusPoints
                    }`
                )

                if (this.config.workers.doDailyInstantWin !== false) {
                    await this.runDailyInstantWinForAccount(account)
                }

                if (this.config.workers.doClaimBonusPoints) {
'''
    if old_hook not in text:
        sys.exit('unexpected SEARCH-MANAGER hook point; abort')
    text = text.replace(old_hook, new_hook, 1)

    marker = '    async createDesktopSession(account: Account): Promise<BrowserSession> {'
    helper = r'''    private async runDailyInstantWinForAccount(account: Account): Promise<void> {
        if (this.config.workers.doDailyInstantWin === false) return

        const hasPage =
            (this.mainDesktopPage && !this.mainDesktopPage.isClosed()) ||
            (this.mainMobilePage && !this.mainMobilePage.isClosed())
        if (hasPage) {
            try {
                await this.activities.doDailyInstantWin()
            } catch (error) {
                this.logger.warn(
                    'main',
                    'DAILY-INSTANT-WIN',
                    `每日 Instant Win 未阻断后续任务 | ${error instanceof Error ? error.message : String(error)}`
                )
            }
            return
        }

        const opened: { session: BrowserSession | null } = { session: null }
        try {
            await executionContext.run({ isMobile: false, account }, async () => {
                opened.session = await this.createDesktopSession(account)
                await this.activities.doDailyInstantWin()
            })
        } catch (error) {
            this.logger.warn(
                'main',
                'DAILY-INSTANT-WIN',
                `每日 Instant Win 未阻断后续任务 | ${error instanceof Error ? error.message : String(error)}`
            )
        } finally {
            if (opened.session) {
                const session = opened.session
                await executionContext.run({ isMobile: false, account }, async () => {
                    await this.browser.func.checkpointActiveSession('PRE-BROWSER-CLOSE')
                    await this.browser.func.closeBrowser(session.context, account.email)
                })
            }
        }
    }

    private async mainDailyInstantWinOnly(account: Account): Promise<AccountRunResult> {
        this.accessToken = ''
        this.cookies = { mobile: [], desktop: [] }
        this.fingerprintMobile = undefined
        this.fingerprintDesktop = undefined
        const opened: { session: BrowserSession | null } = { session: null }
        try {
            return await executionContext.run({ isMobile: false, account }, async () => {
                opened.session = await this.createDesktopSession(account)
                await this.activities.doDailyInstantWin()
                return { initialPoints: this.userData.currentPoints ?? 0, collectedPoints: 0 }
            })
        } finally {
            if (opened.session) {
                const session = opened.session
                await executionContext.run({ isMobile: false, account }, async () => {
                    await this.browser.func.checkpointActiveSession('PRE-BROWSER-CLOSE')
                    await this.browser.func.closeBrowser(session.context, account.email)
                })
            }
        }
    }

'''
    if marker not in text:
        sys.exit('createDesktopSession not found; abort')
    text = text.replace(marker, helper + marker, 1)

    old_main = '''    async Main(account: Account): Promise<AccountRunResult> {
        const accountEmail = account.email
        this.logger.info('main', 'FLOW', `开始为 ${accountEmail} 创建会话`)
'''
    new_main = '''    async Main(account: Account): Promise<AccountRunResult> {
        const accountEmail = account.email
        this.logger.info('main', 'FLOW', `开始为 ${accountEmail} 创建会话`)

        if (process.env.DAILY_INSTANT_WIN_ONLY === '1') {
            return await this.mainDailyInstantWinOnly(account)
        }
'''
    if old_main not in text:
        sys.exit('Main() start not found; abort')
    if 'mainDailyInstantWinOnly' not in text or 'DAILY_INSTANT_WIN_ONLY === \'1\') {\n            return await this.mainDailyInstantWinOnly' not in text:
        text = text.replace(old_main, new_main, 1)
    path.write_text(text)
    print('patched index.ts')


def patch_validator(app: Path) -> None:
    path = app / 'src/util/Validator.ts'
    if not path.is_file():
        print('Validator.ts missing; skip')
        return
    text = path.read_text()
    if 'doDailyInstantWin' in text:
        print('Validator.ts already has doDailyInstantWin')
        return
    old = (
        '        doVisualSearch: z.boolean().default(false)\n'
        '    }),'
    )
    new = (
        '        doVisualSearch: z.boolean().default(false),\n'
        '        doDailyInstantWin: z.boolean().default(true)\n'
        '    }),'
    )
    if old not in text:
        sys.exit('unexpected Validator workers schema; abort')
    path.write_text(text.replace(old, new, 1))
    print('patched Validator.ts so doDailyInstantWin=false is preserved')


def patch_config_env_overrides(app: Path) -> None:
    path = app / 'src/util/ConfigEnvOverrides.ts'
    if not path.is_file():
        print('ConfigEnvOverrides.ts missing; skip')
        return
    text = path.read_text()
    if 'CONFIG_WORKER_DAILY_INSTANT_WIN' in text:
        print('ConfigEnvOverrides.ts already has CONFIG_WORKER_DAILY_INSTANT_WIN')
        return
    old = "    { env: 'CONFIG_WORKER_VISUAL_SEARCH', path: 'workers.doVisualSearch', type: 'bool' },"
    if old not in text:
        sys.exit('unexpected ConfigEnvOverrides workers block; abort')
    addition = "    { env: 'CONFIG_WORKER_DAILY_INSTANT_WIN', path: 'workers.doDailyInstantWin', type: 'bool' },"
    path.write_text(text.replace(old, old + '\n' + addition, 1))
    print('patched ConfigEnvOverrides.ts')


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--app-root', required=True, help='Existing Microsoft-Rewards-Script root, e.g. /opt/mrs-keep-earning/app')
    parser.add_argument('--payload', required=True, help='Path to this handoff directory')
    args = parser.parse_args()
    app = Path(args.app_root).resolve()
    payload = Path(args.payload).resolve()
    if not (app / 'src/index.ts').is_file():
        sys.exit(f'app root does not look like the script tree: {app}')

    before = {rel: sha256(app / rel) if (app / rel).is_file() else None for rel in PROTECTED}
    print('PROTECTED_SHA256_BEFORE')
    for rel, digest in before.items():
        print(digest or 'MISSING', rel)

    copy_new_modules(app, payload)
    patch_activities(app)
    ensure_signup_activities(app)
    patch_urls(app)
    patch_config_type(app)
    patch_validator(app)
    patch_config_env_overrides(app)
    patch_index(app)

    after = {rel: sha256(app / rel) if (app / rel).is_file() else None for rel in PROTECTED}
    print('PROTECTED_SHA256_AFTER')
    for rel, digest in after.items():
        print(digest or 'MISSING', rel)
        if before[rel] != digest:
            sys.exit(f'protected file changed, abort and restore backup: {rel}')
    print('keepEarning_unchanged_ok')
    print('DONE')


if __name__ == '__main__':
    main()
