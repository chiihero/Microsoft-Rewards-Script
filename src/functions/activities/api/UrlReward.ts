import type { BasePromotion } from '../../../interface/DashboardData'
import { Workers } from '../../Workers'

export class UrlReward extends Workers {
    public async doUrlReward(promotion: BasePromotion) {
        const offerId = promotion.offerId

        const actionId = this.bot.nextActions.reportActivity
        if (!actionId) {
            this.bot.logger.warn(
                this.bot.isMobile,
                'URL-REWARD',
                `跳过 ${offerId}：未在 bundle 中发现 "reportActivity"`
            )
            return
        }

        const live = this.bot.reactSnapshot?.offers.find(o => o.offerId === offerId)
        if (!live) {
            this.bot.logger.warn(this.bot.isMobile, 'URL-REWARD', `跳过 ${offerId}：页面快照中不存在`)
            return
        }
        if (!live.reportable) {
            this.bot.logger.warn(
                this.bot.isMobile,
                'URL-REWARD',
                `跳过 ${offerId}：不可上报（已完成/已锁定/无 hash/未来日期）`
            )
            return
        }

        if (this.bot.config.skipNonPointTasks && this.isNonCrediting(live.points, live.promotionSubtype, live.title)) {
            this.bot.logger.info(
                this.bot.isMobile,
                'URL-REWARD',
                `跳过 ${offerId}：不奖励积分（积分=${live.points}${live.promotionSubtype ? ` 子类型=${live.promotionSubtype}` : ''}）- 可能是免费试用/不计积分的活动。设置 skipNonPointTasks=false 可强制尝试。`
            )
            return
        }

        const oldBalance = this.bot.userData.currentPoints
        const expectedPoints = live.points
        const activityType = Number(promotion.activityType ?? 11)

        this.bot.logger.info(
            this.bot.isMobile,
            'URL-REWARD',
            `开始 UrlReward | offerId=${offerId} | 地区=${this.bot.userData.geoLocale} | 旧余额=${oldBalance}`
        )

        try {
            const { status, acknowledged } = await this.bot.browser.func.reportServerAction(actionId, [
                live.hash,
                activityType,
                {
                    offerid: offerId,
                    isPromotional: live.isPromotional ? true : '$undefined',
                    timezoneOffset: this.bot.userData.timezoneOffset
                }
            ])

            const newBalance = await this.bot.browser.func.getCurrentPoints()
            const gainedPoints = newBalance - oldBalance

            this.bot.logger.debug(
                this.bot.isMobile,
                'URL-REWARD',
                `响应 | offerId=${offerId} | 状态=${status} | 已确认=${acknowledged} | 获得积分=${gainedPoints}`
            )

            if (gainedPoints > 0) {
                this.bot.userData.currentPoints = newBalance
                this.bot.userData.gainedPoints = (this.bot.userData.gainedPoints ?? 0) + gainedPoints

                const shortfall = expectedPoints > 0 && gainedPoints < expectedPoints
                this.bot.logger.info(
                    this.bot.isMobile,
                    'URL-REWARD',
                    `UrlReward 完成 | offerId=${offerId} | 获得积分=${gainedPoints}${expectedPoints > 0 ? `/${expectedPoints}` : ''} | 新余额=${newBalance}${shortfall ? ' | 警告：实际到账少于宣传数量' : ''}`,
                    'green'
                )
            } else if (acknowledged && expectedPoints === 0) {
                this.bot.logger.info(
                    this.bot.isMobile,
                    'URL-REWARD',
                    `UrlReward 完成（设计上无积分） | offerId=${offerId} | 已确认=true | 余额=${newBalance}`,
                    'green'
                )
            } else {
                this.bot.logger.warn(
                    this.bot.isMobile,
                    'URL-REWARD',
                    `UrlReward 未到账积分 | offerId=${offerId} | 已确认=${acknowledged} | 预期=${expectedPoints} | 余额=${newBalance}`
                )
            }

            await this.bot.utils.wait(this.bot.utils.randomDelay(5000, 10000))
        } catch (error) {
            this.bot.logger.error(
                this.bot.isMobile,
                'URL-REWARD',
                `doUrlReward 出错 | offerId=${offerId} | 消息=${error instanceof Error ? error.message : String(error)}`
            )
        }
    }

    private isNonCrediting(points: number, subtype: string | null, title: string): boolean {
        if (points > 0) return false
        const haystack = `${subtype ?? ''} ${title ?? ''}`.toLowerCase()

        // Make proper language independant
        return points === 0 || /free trial|trial|subscription|sign up|sign-up|signup/.test(haystack)
    }
}
