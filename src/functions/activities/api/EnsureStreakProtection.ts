import { URLs } from '../../../constants/urls'
import { Workers } from '../../Workers'

const STREAK_PROTECTION_ACTION_NAMES = [
    'reportSetStreakProtection',
    'reportToggleStreakProtection',
    'reportEnableStreakProtection',
    'setStreakProtection',
    'reportStreakProtection'
]

export class EnsureStreakProtection extends Workers {
    public async ensureStreakProtection() {
        const resolved = this.resolveActionId()
        if (!resolved) {
            this.bot.logger.warn(
                this.bot.isMobile,
                'ENABLE-STREAK-PROTECTION',
                `跳过：未在 bundle 中发现连击保护的 action id（已查找 [${STREAK_PROTECTION_ACTION_NAMES.join(', ')}] 及任何 "*streak*protect*" 键）`
            )
            return
        }

        const before = this.bot.reactSnapshot?.streakProtection ?? null

        if (before?.isProtectionOn) {
            this.bot.logger.info(
                this.bot.isMobile,
                'ENABLE-STREAK-PROTECTION',
                `连击保护已启用（剩余天数=${before.remainingDays ?? '?'}）`,
                'green'
            )
            return
        }

        if (before && before.remainingDays === 0) {
            this.bot.logger.info(
                this.bot.isMobile,
                'ENABLE-STREAK-PROTECTION',
                '没有剩余的保护天数 - 开关已被禁用，跳过'
            )
            return
        }

        const beforeDesc = before ? `on=${before.isProtectionOn},days=${before.remainingDays ?? '?'}` : 'unknown'
        this.bot.logger.info(
            this.bot.isMobile,
            'ENABLE-STREAK-PROTECTION',
            `开始确保连击保护 | action=${resolved.name} | 之前=${beforeDesc}`
        )

        try {
            // Fired from the streaks page, so url/referer point there
            const { status, acknowledged } = await this.bot.browser.func.reportServerAction(resolved.id, [true], {
                url: URLs.rewards.earnStreaks,
                referer: URLs.rewards.earnStreaks
            })

            const after = await this.readStreakProtection()

            if (after?.isProtectionOn) {
                this.bot.logger.info(
                    this.bot.isMobile,
                    'ENABLE-STREAK-PROTECTION',
                    `已完成 | 连击保护已启用=true | 剩余天数=${after.remainingDays ?? '?'} | 状态=${status}`,
                    'green'
                )
            } else if (after === null) {
                this.bot.logger.warn(
                    this.bot.isMobile,
                    'ENABLE-STREAK-PROTECTION',
                    `已触发但无法从最新快照确认状态 | 已确认=${acknowledged} | 状态=${status}`
                )
            } else {
                this.bot.logger.warn(
                    this.bot.isMobile,
                    'ENABLE-STREAK-PROTECTION',
                    `开关未生效 - 触发后仍然关闭 | 状态=${status}`
                )
            }

            await this.bot.utils.wait(this.bot.utils.randomDelay(5000, 10000))
        } catch (error) {
            this.bot.logger.error(
                this.bot.isMobile,
                'ENABLE-STREAK-PROTECTION',
                `ensureStreakProtection 出错 | 消息=${error instanceof Error ? error.message : String(error)}`
            )
        }
    }

    private async readStreakProtection() {
        try {
            const page = this.bot.isMobile ? this.bot.mainMobilePage : this.bot.mainDesktopPage
            const res = await page.request.get(URLs.rewards.earn)
            if (!res.ok()) {
                this.bot.logger.warn(
                    this.bot.isMobile,
                    'ENABLE-STREAK-PROTECTION',
                    `验证请求失败 | 状态=${res.status()}`
                )
                return null
            }
            return this.bot.browser.react.getStreakProtection(await res.text())
        } catch (error) {
            this.bot.logger.warn(
                this.bot.isMobile,
                'ENABLE-STREAK-PROTECTION',
                `验证读取出错 | ${error instanceof Error ? error.message : String(error)}`
            )
            return null
        }
    }

    private resolveActionId(): { name: string; id: string } | null {
        const actions = this.bot.nextActions

        for (const name of STREAK_PROTECTION_ACTION_NAMES) {
            const id = actions[name]
            if (id) return { name, id }
        }

        const fuzzy = Object.keys(actions).find(k => /streak/i.test(k) && /protect/i.test(k))
        if (fuzzy) return { name: fuzzy, id: actions[fuzzy]! }

        return null
    }
}
