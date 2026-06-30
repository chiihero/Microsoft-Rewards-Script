import type { Dashboard, DashboardData } from '../../../interface/DashboardData'
import { Workers } from '../../Workers'

export interface SearchMultiplierPerk {
    offerId: string
    multiplier: number
}

export function detectSearchMultiplierPerk(dashboard: Dashboard): SearchMultiplierPerk | null {
    const candidates = [dashboard.promotionalItem, ...(dashboard.promotionalItems ?? [])]

    for (const item of candidates) {
        if (!item) continue

        const attributes = item.attributes
        const offerId = item.offerId || attributes?.offerid || ''
        const description = item.description || attributes?.description || ''
        if (!offerId) continue

        const multiplierAttr = attributes?.searchMultiplier
        const multiplierFromAttr = multiplierAttr != null ? Number(multiplierAttr) : NaN

        // Date-agnostic fallbacks
        const fromDescription = /search\s*(\d+)\s*x\s*more/i.exec(description)
        const fromOfferId = /optin[_-]?(\d+)x(?:[_-]|$)/i.exec(offerId)

        const isSearchMultiplier =
            (Number.isFinite(multiplierFromAttr) && multiplierFromAttr > 1) ||
            fromDescription !== null ||
            fromOfferId !== null
        if (!isSearchMultiplier) continue

        const multiplier =
            Number.isFinite(multiplierFromAttr) && multiplierFromAttr > 1
                ? multiplierFromAttr
                : fromDescription
                  ? Number(fromDescription[1])
                  : fromOfferId
                    ? Number(fromOfferId[1])
                    : 2

        return { offerId, multiplier }
    }

    return null
}

export class ActivateSearchPerk extends Workers {
    public async activate(data: DashboardData) {
        const perk = detectSearchMultiplierPerk(data.dashboard)
        if (!perk) {
            this.bot.logger.debug(
                this.bot.isMobile,
                'ACTIVATE-SEARCH-PERK',
                '仪表板上不存在搜索倍数特权'
            )
            return
        }

        const live = this.bot.reactSnapshot?.offers.find(o => o.offerId === perk.offerId)
        if (!live) {
            this.bot.logger.warn(
                this.bot.isMobile,
                'ACTIVATE-SEARCH-PERK',
                `${perk.multiplier} 倍搜索特权存在于仪表板，但页面快照中缺失 - 无法激活 | offerId=${perk.offerId}`
            )
            return
        }

        if (!live.reportable) {
            this.bot.logger.info(
                this.bot.isMobile,
                'ACTIVATE-SEARCH-PERK',
                `${perk.multiplier} 倍搜索特权已激活（或不可激活） | offerId=${perk.offerId}`,
                'green'
            )
            return
        }

        const actionId = this.bot.nextActions.reportActivity
        if (!actionId) {
            this.bot.logger.warn(
                this.bot.isMobile,
                'ACTIVATE-SEARCH-PERK',
                '跳过：未在 bundle 中发现 "reportActivity" 的 action id'
            )
            return
        }

        const activityType = live.activityType ?? 11

        this.bot.logger.info(
            this.bot.isMobile,
            'ACTIVATE-SEARCH-PERK',
            `正在激活 ${perk.multiplier} 倍搜索特权 | offerId=${perk.offerId} | 地区=${this.bot.userData.geoLocale}`
        )

        try {
            const { status, acknowledged } = await this.bot.browser.func.reportServerAction(actionId, [
                live.hash,
                activityType,
                {
                    offerid: perk.offerId,
                    isPromotional: 'true',
                    timezoneOffset: this.bot.userData.timezoneOffset
                }
            ])

            this.bot.logger.debug(
                this.bot.isMobile,
                'ACTIVATE-SEARCH-PERK',
                `响应 | offerId=${perk.offerId} | 状态=${status} | 已确认=${acknowledged}`
            )

            if (acknowledged) {
                this.bot.logger.info(
                    this.bot.isMobile,
                    'ACTIVATE-SEARCH-PERK',
                    `已激活 ${perk.multiplier} 倍搜索特权 | offerId=${perk.offerId} | 每日搜索上限现已提升`,
                    'green'
                )
            } else {
                this.bot.logger.warn(
                    this.bot.isMobile,
                    'ACTIVATE-SEARCH-PERK',
                    `激活未被确认 | offerId=${perk.offerId} | 状态=${status}`
                )
            }

            await this.bot.utils.wait(this.bot.utils.randomDelay(5000, 10000))
        } catch (error) {
            this.bot.logger.error(
                this.bot.isMobile,
                'ACTIVATE-SEARCH-PERK',
                `激活搜索特权出错 | offerId=${perk.offerId} | 消息=${error instanceof Error ? error.message : String(error)}`
            )
        }
    }
}
