import { BaseActivity } from '../BaseActivity'
import type { BasePromotion } from '../../../interface/DashboardData'

export class PromotionActivityRunner extends BaseActivity {
    public async run(promotions: BasePromotion[]): Promise<boolean> {
        for (const [index, promotion] of promotions.entries()) {
            try {
                if (!(await this.runPromotion(promotion))) continue
                this.markExecuted()
                if (index < promotions.length - 1) {
                    await this.bot.utils.wait(this.bot.utils.randomDelay(15000, 60000))
                }
            } catch (error) {
                this.bot.logger.error(
                    this.bot.isMobile,
                    'ACTIVITY',
                    `解决活动 "${promotion.title}" 时出错 | message=${
                        error instanceof Error ? error.message : String(error)
                    }`
                )
            }
        }
        return this.didExecute()
    }

    private async runPromotion(promotion: BasePromotion): Promise<boolean> {
        const type = promotion.promotionType?.toLowerCase() ?? ''
        const name = promotion.name?.toLowerCase() ?? ''
        const offerId = promotion.offerId

        this.bot.logger.debug(
            this.bot.isMobile,
            'ACTIVITY',
            `处理活动 | 标题="${promotion.title}" | offerId=${offerId} | 类型=${type}`
        )

        if (type !== 'urlreward') {
            this.bot.logger.warn(
                this.bot.isMobile,
                'ACTIVITY',
                `跳过活动 "${promotion.title}" | offerId=${offerId} | 原因：不支持的类型 "${promotion.promotionType}"`
            )
            return false
        }

        const isSearchOnBing = name.includes('exploreonbing')
        if (isSearchOnBing && !this.bot.config.activities.searchOnBing) {
            this.logDisabled('SearchOnBing', offerId)
            return false
        }
        if (!isSearchOnBing && !this.bot.config.activities.urlReward) {
            this.logDisabled('UrlReward', offerId)
            return false
        }

        if (isSearchOnBing) {
            this.bot.logger.info(
                this.bot.isMobile,
                'ACTIVITY',
                `发现活动类型 "SearchOnBing" | 标题="${promotion.title}" | offerId=${offerId}`
            )
            const page = this.bot.isMobile ? this.bot.mainMobilePage : this.bot.mainDesktopPage
            return this.bot.activities.doSearchOnBing(promotion, page)
        }

        this.bot.logger.info(
            this.bot.isMobile,
            'ACTIVITY',
            `发现活动类型 "UrlReward" | 标题="${promotion.title}" | offerId=${offerId}`
        )
        return this.bot.activities.doUrlReward(promotion)
    }

    private logDisabled(activity: string, offerId: string): void {
        this.bot.logger.info(this.bot.isMobile, 'ACTIVITY', `跳过 "${activity}"（配置中已禁用） | offerId=${offerId}`)
    }
}
