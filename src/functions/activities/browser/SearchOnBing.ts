import type { Page } from 'patchright'
import * as fs from 'fs'
import path from 'path'

import { Workers } from '../../Workers'
import { URLs } from '../../../constants/urls'

import type { BasePromotion, Dashboard } from '../../../interface/DashboardData'

interface ActivityQueries {
    title: string
    queries: string[]
}

export class SearchOnBing extends Workers {
    private gainedPoints = 0
    private success = false
    private oldBalance = 0

    public async doSearchOnBing(promotion: BasePromotion, page: Page) {
        const offerId = promotion.offerId
        this.oldBalance = Number(this.bot.userData.currentPoints ?? 0)
        this.gainedPoints = 0
        this.success = false

        this.bot.logger.info(
            this.bot.isMobile,
            'SEARCH-ON-BING',
            `开始 Bing 站内搜索 | offerId=${offerId} | 标题="${promotion.title}" | 当前积分=${this.oldBalance}`
        )

        try {
            const activated = await this.activateSearchTask(promotion)
            if (!activated) {
                this.bot.logger.warn(
                    this.bot.isMobile,
                    'SEARCH-ON-BING',
                    `搜索活动无法激活，中止 | offerId=${offerId}`
                )
                return
            }

            const queries = await this.getSearchQueries(promotion)
            await this.searchBing(page, queries, promotion)

            if (this.success) {
                this.bot.logger.info(
                    this.bot.isMobile,
                    'SEARCH-ON-BING',
                    `Bing 站内搜索完成 | offerId=${offerId} | 起始余额=${this.oldBalance} | 最终余额=${this.bot.userData.currentPoints}`,
                    'green'
                )
            } else {
                this.bot.logger.warn(
                    this.bot.isMobile,
                    'SEARCH-ON-BING',
                    `Bing 站内搜索失败 | offerId=${offerId} | 起始余额=${this.oldBalance} | 最终余额=${this.bot.userData.currentPoints}`
                )
            }
        } catch (error) {
            this.bot.logger.error(
                this.bot.isMobile,
                'SEARCH-ON-BING',
                `doSearchOnBing 出错 | offerId=${offerId} | 错误信息=${error instanceof Error ? error.message : String(error)}`
            )
        } finally {
            await page.goto(URLs.rewards.earn).catch(() => {})
        }
    }

    private async activateSearchTask(promotion: BasePromotion): Promise<boolean> {
        const offerId = promotion.offerId

        const actionId = this.bot.nextActions.reportActivity
        if (!actionId) {
            this.bot.logger.warn(
                this.bot.isMobile,
                'SEARCH-ON-BING-ACTIVATE',
                `跳过 ${offerId}: 在 bundle 中未发现 "reportActivity"`
            )
            return false
        }

        const live = this.bot.reactSnapshot?.offers.find(o => o.offerId === offerId)
        const hash = live?.hash ?? promotion.hash ?? null
        if (!hash) {
            this.bot.logger.warn(
                this.bot.isMobile,
                'SEARCH-ON-BING-ACTIVATE',
                `跳过 ${offerId}: 激活活动没有实时 hash`
            )
            return false
        }

        try {
            const { status, acknowledged } = await this.bot.browser.func.reportServerAction(actionId, [
                hash,
                11,
                {
                    offerid: offerId,
                    isPromotional: '$undefined',
                    timezoneOffset: this.bot.userData.timezoneOffset
                }
            ])

            this.bot.logger.info(
                this.bot.isMobile,
                'SEARCH-ON-BING-ACTIVATE',
                `活动已激活 | offerId=${offerId} | 状态=${status} | 已确认=${acknowledged}`
            )

            return acknowledged
        } catch (error) {
            this.bot.logger.error(
                this.bot.isMobile,
                'SEARCH-ON-BING-ACTIVATE',
                `激活失败 | offerId=${offerId} | 错误信息=${error instanceof Error ? error.message : String(error)}`
            )
            return false
        }
    }

    private async searchBing(page: Page, queries: string[], promotion: BasePromotion) {
        queries = [...new Set(queries)]
        const offerId = promotion.offerId

        this.bot.logger.debug(
            this.bot.isMobile,
            'SEARCH-ON-BING-SEARCH',
            `开始搜索循环 | 查询词数量=${queries.length} | 目标积分=${promotion.pointProgressMax} | 原始余额=${this.oldBalance}`
        )

        await this.ensureSearchReady(page)

        let lastBalance = this.oldBalance
        let i = 0

        for (const query of queries) {
            try {
                this.bot.logger.debug(this.bot.isMobile, 'SEARCH-ON-BING-SEARCH', `处理查询词 | query="${query}"`)

                await this.typeSearch(page, query)

                await this.bot.utils.wait(this.bot.utils.randomDelay(5000, 7000))

                const dashboard = (await this.bot.browser.func.getDashboardData()).dashboard
                const newBalance = dashboard.userStatus.availablePoints
                const offer = this.findOffer(dashboard, offerId)

                const delta = newBalance - lastBalance
                if (delta > 0) {
                    this.bot.userData.gainedPoints = (this.bot.userData.gainedPoints ?? 0) + delta
                    lastBalance = newBalance
                }
                this.bot.userData.currentPoints = newBalance
                this.gainedPoints = newBalance - this.oldBalance

                const offerProgress = offer ? `${offer.pointProgress}/${offer.pointProgressMax}` : 'unknown'
                const offerComplete =
                    !!offer &&
                    (offer.complete || (offer.pointProgressMax > 0 && offer.pointProgress >= offer.pointProgressMax))

                this.bot.logger.debug(
                    this.bot.isMobile,
                    'SEARCH-ON-BING-SEARCH',
                    `进度检查 | query="${query}" | 活动进度=${offerProgress} | 活动是否完成=${offerComplete} | 新余额=${newBalance}`
                )

                if (offerComplete) {
                    this.success = true
                    this.bot.logger.info(
                        this.bot.isMobile,
                        'SEARCH-ON-BING-SEARCH',
                        `Bing 站内搜索活动完成 | query="${query}" | 活动进度=${offerProgress} | 获得积分=${this.gainedPoints}`,
                        'green'
                    )
                    return
                }

                this.bot.logger.warn(
                    this.bot.isMobile,
                    'SEARCH-ON-BING-SEARCH',
                    `${++i}/${queries.length} | 活动未完成 | 活动进度=${offerProgress} | query="${query}"`
                )
            } catch (error) {
                this.bot.logger.error(
                    this.bot.isMobile,
                    'SEARCH-ON-BING-SEARCH',
                    `搜索循环出错 | query="${query}" | 错误信息=${error instanceof Error ? error.message : String(error)}`
                )
            } finally {
                await this.bot.utils.wait(this.bot.utils.randomDelay(5000, 15000))
            }
        }

        this.bot.logger.warn(
            this.bot.isMobile,
            'SEARCH-ON-BING-SEARCH',
            `已尝试所有查询词但活动未完成 | 已尝试查询词数=${queries.length} | offerId=${offerId} | 原始余额=${this.oldBalance} | 最终余额=${this.bot.userData.currentPoints}`
        )
    }

    private async ensureSearchReady(page: Page) {
        const searchBox = page.locator('#sb_form_q')
        if (await searchBox.isVisible().catch(() => false)) return

        await page.goto(URLs.bing.origin)
        await page.waitForLoadState('domcontentloaded', { timeout: 8000 }).catch(() => {})
        await this.bot.browser.utils.tryDismissAllMessages(page)
    }

    private async typeSearch(page: Page, query: string) {
        await this.ensureSearchReady(page)

        const selector = '#sb_form_q'
        const searchBox = page.locator(selector)
        await searchBox.waitFor({ state: 'visible', timeout: 15000 })

        await this.bot.utils.wait(500)
        await this.bot.browser.utils.ghostClick(page, selector, { clickCount: 3 })
        await searchBox.fill('')

        await page.keyboard.type(query, { delay: this.bot.utils.randomDelay(45, 90) })
        await page.keyboard.press('Enter')
        await page.waitForLoadState('domcontentloaded', { timeout: 8000 }).catch(() => {})
    }

    private findOffer(dashboard: Dashboard, offerId: string) {
        const pools = [
            ...Object.values(dashboard.dailySetPromotions ?? {}).flat(),
            ...(dashboard.morePromotions ?? []),
            ...(dashboard.promotionalItems ?? []),
            ...(dashboard.promotionalItem ? [dashboard.promotionalItem] : [])
        ]
        return pools.find(o => o.offerId === offerId)
    }

    private async getSearchQueries(promotion: BasePromotion): Promise<string[]> {
        try {
            let activities: ActivityQueries[]

            if (this.bot.config.searchOnBingLocalQueries) {
                this.bot.logger.debug(this.bot.isMobile, 'SEARCH-ON-BING-QUERY', '使用本地查询词配置文件')
                const data = fs.readFileSync(path.join(__dirname, '../../bing-search-activity-queries.json'), 'utf8')
                activities = JSON.parse(data)
            } else {
                this.bot.logger.debug(
                    this.bot.isMobile,
                    'SEARCH-ON-BING-QUERY',
                    '从远程仓库获取查询词配置'
                )
                const response = await this.bot.http.request<ActivityQueries[]>({
                    method: 'GET',
                    url: URLs.github.searchOnBingQueries
                })
                activities = response.data
            }

            const match = activities.find(
                x => this.bot.utils.normalizeString(x.title) === this.bot.utils.normalizeString(promotion.title)
            )

            if (match && match.queries.length > 0) {
                const shuffled = this.bot.utils.shuffleArray(match.queries)
                this.bot.logger.info(
                    this.bot.isMobile,
                    'SEARCH-ON-BING-QUERY',
                    `已为 "${promotion.title}" 找到 ${shuffled.length} 个查询词 | 来源=${this.bot.config.searchOnBingLocalQueries ? '本地' : '远程'}`
                )
                return shuffled
            }

            this.bot.logger.info(
                this.bot.isMobile,
                'SEARCH-ON-BING-QUERY',
                `"${promotion.title}" 没有精选查询词，回退到活动标题和描述`
            )
            return this.fallbackQueries(promotion)
        } catch (error) {
            this.bot.logger.error(
                this.bot.isMobile,
                'SEARCH-ON-BING-QUERY',
                `解析搜索查询词出错 | 标题="${promotion.title}" | 错误信息=${error instanceof Error ? error.message : String(error)} | 回退=标题与描述`
            )
            return this.fallbackQueries(promotion)
        }
    }

    private fallbackQueries(promotion: BasePromotion): string[] {
        const title = (promotion.title ?? '').trim()
        const description = (promotion.description ?? '').trim()
        const derived = this.extractSearchTerm(description)

        return [...new Set([derived, title, description].map(s => s.trim()).filter(Boolean))]
    }

    // Sadly, still language dependant, will not work on non-english
    private extractSearchTerm(description: string): string {
        if (!description) return ''

        return description
            .trim()
            .replace(
                /^\s*(?:search(?:\s+on\s+bing|\s+bing|\s+the\s+web)?\s+for|look\s+up|find|explore|discover)\b[\s:]+/i,
                ''
            )
            .replace(/^["'“”‘’]+|["'“”‘’]+$/g, '')
            .replace(/[.!?]+$/g, '')
            .trim()
    }
}
