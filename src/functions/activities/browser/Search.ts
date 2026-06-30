import type { Page } from 'patchright'

import { URLs } from '../../../constants/urls'
import { QueryCore } from '../../QueryEngine'
import { Workers } from '../../Workers'
import { BonusTracker } from '../SearchBonus'
import type { SearchTracker } from '../../../interface/Search'
import type { MissingSearchPoints } from '../../../interface/Points'
import type { MicrosoftRewardsBot } from '../../../index'

const REFRESH_EVERY = 10
const MAX_QUERY_ATTEMPTS = 5

const POINTS_MAX_SEARCHES = 100
const POINTS_STAGNANT_LIMIT = 10

const SEARCH_BOX = '#sb_form_q'
const RESULT_LINK = '#b_results .b_algo h2'

interface SessionStats {
    totalGained: number
    performed: number
    stagnant: number
}

export class Search extends Workers {
    private searchCount = 0

    public async doSearch(page: Page, isMobile: boolean): Promise<number> {
        const startBalance = Number(this.bot.userData.currentPoints ?? 0)
        this.bot.logger.info(isMobile, 'SEARCH-BING', `开始 Bing 搜索 | 当前积分=${startBalance}`)

        const tracker = new PointsTracker(this.bot, isMobile)
        try {
            const stats = await this.runSearchSession(page, isMobile, tracker)

            if (stats.performed >= tracker.maxSearches && !tracker.done()) {
                this.bot.logger.warn(
                    isMobile,
                    tracker.context,
                    `达到 ${tracker.maxSearches} 次搜索上限但积分仍有剩余 | ${tracker.progress()}`
                )
            }

            this.bot.logger.info(
                isMobile,
                tracker.context,
                `Bing 搜索完成 | 起始余额=${startBalance} | 获得=${stats.totalGained} | 搜索次数=${stats.performed} | ${tracker.progress()}`
            )
            return stats.totalGained
        } finally {
            await page.goto(URLs.bing.origin).catch(() => {})
        }
    }

    public async doBonusSearches(page: Page): Promise<number> {
        const isMobile = this.bot.isMobile
        const tracker = new BonusTracker(this.bot, isMobile)

        const stats = await this.runSearchSession(page, isMobile, tracker)

        // No active offer (or the feature is off): prepare() already logged why
        if (!tracker.started) return 0

        const done = tracker.done() && !tracker.offerLost
        const reason = done
            ? 'offer complete'
            : tracker.offerLost
              ? 'offer no longer present'
              : stats.performed >= tracker.maxSearches
                ? 'reached maxBonusSearches'
                : stats.stagnant >= tracker.stagnantLimit
                  ? `${tracker.stagnantLimit} idle searches`
                  : 'query pool exhausted'

        this.bot.logger.info(
            isMobile,
            tracker.context,
            `奖励刷取${done ? '完成' : '已停止'} (${reason}) | ${tracker.progress()} | 搜索次数=${stats.performed} | 获得=+${stats.totalGained}`,
            done || stats.totalGained > 0 ? 'green' : undefined
        )
        return stats.totalGained
    }

    private async runSearchSession(page: Page, isMobile: boolean, tracker: SearchTracker): Promise<SessionStats> {
        const stats: SessionStats = { totalGained: 0, performed: 0, stagnant: 0 }

        try {
            const ready = await tracker.prepare()
            if (!ready) return stats

            const queryCore = new QueryCore(this.bot)
            let queries = await this.generatePool(queryCore)
            if (!queries.length) {
                this.bot.logger.warn(isMobile, tracker.context, '没有可用的查询词，跳过')
                return stats
            }
            this.bot.logger.info(isMobile, tracker.context, `查询词池就绪 | 数量=${queries.length}`)

            await page.goto(URLs.bing.origin)
            await page.waitForLoadState('domcontentloaded', { timeout: 8000 }).catch(() => {})
            await this.bot.browser.utils.tryDismissAllMessages(page)

            let index = 0

            while (!tracker.done() && stats.performed < tracker.maxSearches && stats.stagnant < tracker.stagnantLimit) {
                // Out of queries: pull a fresh batch, dedupe, and reshuffle
                if (index >= queries.length) {
                    const extra = await this.generatePool(queryCore)
                    queries = this.bot.utils.shuffleArray([...new Set([...queries, ...extra])])
                    if (index >= queries.length) {
                        this.bot.logger.warn(isMobile, tracker.context, '查询词池已耗尽，停止')
                        break
                    }
                    this.bot.logger.debug(isMobile, tracker.context, `查询词池已重新生成 | 数量=${queries.length}`)
                }

                // Query still has to be decoded, RSS entries often have html entities, but to add a whole dependancy for that? Doesn't look natural however
                const query = queries[index++] as string
                await this.bingSearch(page, query, isMobile)
                stats.performed++

                const gained = await tracker.measure()
                if (gained > 0) {
                    stats.stagnant = 0
                    stats.totalGained += gained
                    this.bot.logger.info(
                        isMobile,
                        tracker.context,
                        `+${gained} | query="${query}" | ${tracker.progress()}`,
                        'green'
                    )
                } else {
                    stats.stagnant++
                    this.bot.logger.info(
                        isMobile,
                        tracker.context,
                        `未获得积分 ${stats.stagnant}/${tracker.stagnantLimit} | query="${query}" | ${tracker.progress()}`
                    )
                }
            }

            return stats
        } catch (error) {
            this.bot.logger.error(
                isMobile,
                tracker.context,
                `搜索会话出错 | ${error instanceof Error ? error.message : String(error)}`
            )
            return stats
        }
    }

    private async generatePool(queryCore: QueryCore): Promise<string[]> {
        const pool = await queryCore.queryManager({
            shuffle: true,
            related: true,
            langCode: (this.bot.userData.langCode ?? 'en').toLowerCase(),
            geoLocale: (this.bot.userData.geoLocale ?? 'US').toUpperCase(),
            sourceOrder: this.bot.config.searchSettings.queryEngines
        })
        return [...new Set(pool.map(q => q.trim()).filter(Boolean))]
    }

    private async bingSearch(page: Page, query: string, isMobile: boolean): Promise<void> {
        this.searchCount++

        if (this.searchCount % REFRESH_EVERY === 0) {
            await page.goto(URLs.bing.origin)
            await page.waitForLoadState('domcontentloaded', { timeout: 8000 }).catch(() => {})
            await this.bot.browser.utils.tryDismissAllMessages(page)
        }

        for (let attempt = 1; attempt <= MAX_QUERY_ATTEMPTS; attempt++) {
            try {
                const searchBox = page.locator(SEARCH_BOX)

                await page.evaluate(() => window.scrollTo({ left: 0, top: 0, behavior: 'auto' }))
                await page.keyboard.press('Home')
                await searchBox.waitFor({ state: 'visible', timeout: 15000 })

                await this.bot.utils.wait(1000)
                await this.bot.browser.utils.ghostClick(page, SEARCH_BOX, { clickCount: 3 })
                await searchBox.fill('')

                await page.keyboard.type(query, { delay: this.bot.utils.randomDelay(45, 90) })
                await page.keyboard.press('Enter')
                await this.bot.utils.wait(3000)

                if (this.bot.config.searchSettings.scrollRandomResults) {
                    await this.bot.utils.wait(2000)
                    await this.randomScroll(page, isMobile)
                }
                if (this.bot.config.searchSettings.clickRandomResults) {
                    await this.bot.utils.wait(2000)
                    await this.clickRandomLink(page, isMobile)
                }

                await this.bot.utils.wait(
                    this.bot.utils.randomDelay(
                        this.bot.config.searchSettings.searchDelay.min,
                        this.bot.config.searchSettings.searchDelay.max
                    )
                )

                return
            } catch (error) {
                this.bot.logger.warn(
                    isMobile,
                    'SEARCH-BING',
                    `第 ${attempt}/${MAX_QUERY_ATTEMPTS} 次搜索尝试失败 | query="${query}" | ${error instanceof Error ? error.message : String(error)}`
                )
                await this.bot.utils.wait(2000)
            }
        }
    }

    private async randomScroll(page: Page, isMobile: boolean) {
        try {
            const viewportHeight = await page.evaluate(() => window.innerHeight)
            const totalHeight = await page.evaluate(() => document.body.scrollHeight)
            const scrollPos = Math.floor(Math.random() * Math.max(1, totalHeight - viewportHeight))
            await page.evaluate(pos => window.scrollTo({ left: 0, top: pos, behavior: 'auto' }), scrollPos)
        } catch (error) {
            this.bot.logger.error(
                isMobile,
                'SEARCH-RANDOM-SCROLL',
                `随机滚动失败 | ${error instanceof Error ? error.message : String(error)}`
            )
        }
    }

    private async clickRandomLink(page: Page, isMobile: boolean) {
        try {
            const searchPageUrl = page.url()
            await this.bot.browser.utils.ghostClick(page, RESULT_LINK)
            await this.bot.utils.wait(this.bot.config.searchSettings.searchResultVisitTime)

            if (isMobile) {
                await page.goto(searchPageUrl)
            } else {
                const newTab = await this.bot.browser.utils.getLatestTab(page)
                await this.bot.browser.utils.closeTabs(newTab)
            }
        } catch (error) {
            this.bot.logger.error(
                isMobile,
                'SEARCH-RANDOM-CLICK',
                `随机点击失败 | ${error instanceof Error ? error.message : String(error)}`
            )
        }
    }
}

class PointsTracker implements SearchTracker {
    public readonly context = 'SEARCH-BING'
    public readonly maxSearches = POINTS_MAX_SEARCHES
    public readonly stagnantLimit = POINTS_STAGNANT_LIMIT

    private missing: MissingSearchPoints = { mobilePoints: 0, desktopPoints: 0, edgePoints: 0, totalPoints: 0 }
    private readonly runOnZeroPoints: boolean

    constructor(
        private bot: MicrosoftRewardsBot,
        private isMobile: boolean
    ) {
        this.runOnZeroPoints = this.bot.config.searchSettings.runOnZeroPoints ?? false
    }

    async prepare(): Promise<boolean> {
        this.missing = this.bot.browser.func.missingSearchPoints(
            await this.bot.browser.func.getSearchPoints(),
            this.isMobile
        )
        this.bot.logger.info(
            this.isMobile,
            this.context,
            `剩余搜索积分 | Edge=${this.missing.edgePoints} | 桌面端=${this.missing.desktopPoints} | 移动端=${this.missing.mobilePoints}`
        )

        if (this.missing.totalPoints <= 0) {
            if (!this.runOnZeroPoints) {
                this.bot.logger.info(
                    this.isMobile,
                    this.context,
                    '没有可获得的搜索积分，跳过 (runOnZeroPoints 已禁用)'
                )
                return false
            }
            this.bot.logger.info(
                this.isMobile,
                this.context,
                '没有报告搜索积分，但 runOnZeroPoints 已启用，继续搜索'
            )
        }
        return true
    }

    async measure(): Promise<number> {
        const updated = this.bot.browser.func.missingSearchPoints(
            await this.bot.browser.func.getSearchPoints(),
            this.isMobile
        )
        const gained = Math.max(0, this.missing.totalPoints - updated.totalPoints)
        this.missing = updated

        if (gained > 0) {
            this.bot.userData.currentPoints = Number(this.bot.userData.currentPoints ?? 0) + gained
            this.bot.userData.gainedPoints = (this.bot.userData.gainedPoints ?? 0) + gained
        }
        return gained
    }

    done(): boolean {
        return !this.runOnZeroPoints && this.missing.totalPoints <= 0
    }

    progress(): string {
        return `remaining=${this.missing.totalPoints}`
    }
}
