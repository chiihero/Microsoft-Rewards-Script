import { Workers } from '../../Workers'

export class ClaimBonusPoints extends Workers {
    public async claimBonusPoints() {
        const actionId = this.bot.nextActions.reportClaimAllPoints
        if (!actionId) {
            this.bot.logger.warn(
                this.bot.isMobile,
                'CLAIM-BONUS-POINTS',
                '跳过：未在 bundle 中发现 "reportClaimAllPoints" 的 action id'
            )
            return
        }

        const oldBalance = this.bot.userData.currentPoints

        this.bot.logger.info(
            this.bot.isMobile,
            'CLAIM-BONUS-POINTS',
            `开始 ClaimBonusPoints | 地区=${this.bot.userData.geoLocale} | 旧余额=${oldBalance}`
        )

        try {
            const { status, acknowledged } = await this.bot.browser.func.reportServerAction(actionId, [])

            const newBalance = await this.bot.browser.func.getCurrentPoints()
            const gainedPoints = newBalance - oldBalance

            this.bot.logger.debug(
                this.bot.isMobile,
                'CLAIM-BONUS-POINTS',
                `响应 | 状态=${status} | 已确认=${acknowledged} | 旧余额=${oldBalance} | 新余额=${newBalance} | 获得积分=${gainedPoints}`
            )

            if (acknowledged) {
                if (gainedPoints > 0) {
                    this.bot.userData.currentPoints = newBalance
                    this.bot.userData.gainedPoints = (this.bot.userData.gainedPoints ?? 0) + gainedPoints
                }

                this.bot.logger.info(
                    this.bot.isMobile,
                    'CLAIM-BONUS-POINTS',
                    `ClaimBonusPoints 完成 | 已确认=true${gainedPoints > 0 ? ` | 获得积分=${gainedPoints}` : ''} | 新余额=${newBalance}`,
                    'green'
                )
            } else {
                this.bot.logger.info(
                    this.bot.isMobile,
                    'CLAIM-BONUS-POINTS',
                    `未领取到任何内容 | 状态=${status} | 余额未变，仍为 ${newBalance}`
                )
            }

            await this.bot.utils.wait(this.bot.utils.randomDelay(5000, 10000))
        } catch (error) {
            this.bot.logger.error(
                this.bot.isMobile,
                'CLAIM-BONUS-POINTS',
                `claimBonusPoints 出错 | 消息=${error instanceof Error ? error.message : String(error)}`
            )
        }
    }
}
