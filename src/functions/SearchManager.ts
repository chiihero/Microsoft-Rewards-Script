import { MicrosoftRewardsBot, executionContext } from '../index'
import type { Account } from '../interface/Account'
import { URLs } from '../constants/urls'

interface SearchResults {
    mobilePoints: number
    desktopPoints: number
}

export class SearchManager {
    constructor(private bot: MicrosoftRewardsBot) {}

    async doSearches(account: Account): Promise<SearchResults> {
        const counters = await this.bot.browser.func.getSearchPoints()
        const mobileMissing = this.bot.browser.func.missingSearchPoints(counters, true).totalPoints
        const desktopMissing = this.bot.browser.func.missingSearchPoints(counters, false).totalPoints

        const doMobile = this.bot.config.workers.doMobileSearch && mobileMissing > 0
        const doDesktop = this.bot.config.workers.doDesktopSearch && desktopMissing > 0

        this.bot.logger.info(
            'main',
            'SEARCH-MANAGER',
            `移动端: ${this.status(this.bot.config.workers.doMobileSearch, mobileMissing)} | 桌面端: ${this.status(
                this.bot.config.workers.doDesktopSearch,
                desktopMissing
            )}`
        )

        if (!doMobile && !doDesktop) {
            return { mobilePoints: 0, desktopPoints: 0 }
        }

        let mobilePoints = 0
        let desktopPoints = 0

        if (doMobile || doDesktop) {
            const parallel = this.bot.config.searchSettings.parallelSearching
            this.bot.logger.info('main', 'SEARCH-MANAGER', `运行方式: ${parallel ? '并行' : '顺序'}`)

            if (parallel) {
                ;[mobilePoints, desktopPoints] = await Promise.all([
                    doMobile ? this.runMobile(account) : Promise.resolve(0),
                    doDesktop ? this.runDesktop(account) : Promise.resolve(0)
                ])
            } else {
                mobilePoints = doMobile ? await this.runMobile(account) : 0
                desktopPoints = doDesktop ? await this.runDesktop(account) : 0
            }
        }

        return this.summarize(mobilePoints, desktopPoints)
    }

    private status(enabled: boolean, missing: number): string {
        if (!enabled) return 'skip (disabled)'
        if (missing <= 0) return 'skip (no points)'
        return `run (missing ${missing})`
    }

    private summarize(mobilePoints: number, desktopPoints: number): SearchResults {
        this.bot.logger.info(
            'main',
            'SEARCH-MANAGER',
            `搜索汇总 | 移动端=${mobilePoints} | 桌面端=${desktopPoints} | 总计=${mobilePoints + desktopPoints}`
        )
        return { mobilePoints, desktopPoints }
    }

    async doBonusSearches(account: Account): Promise<number> {
        if (!this.bot.config.workers.doBonusSearches) return 0

        this.bot.logger.info('main', 'SEARCH-MANAGER', '开始奖励搜索刷取')

        const gained = await executionContext.run({ isMobile: true, account }, async () => {
            try {
                return await this.bot.activities.doBonusSearches(this.bot.mainMobilePage)
            } catch (error) {
                this.bot.logger.error(
                    'main',
                    'SEARCH-MANAGER',
                    `奖励搜索失败 | ${error instanceof Error ? error.message : String(error)}`
                )
                return 0
            } finally {
                await this.bot.mainMobilePage.goto(URLs.bing.origin).catch(() => {})
            }
        })

        this.bot.logger.info('main', 'SEARCH-MANAGER', `奖励搜索汇总 | 获得=+${gained}`)
        return gained
    }

    private runMobile(account: Account): Promise<number> {
        return executionContext.run({ isMobile: true, account }, async () => {
            try {
                return await this.bot.activities.doSearch(this.bot.mainMobilePage, true)
            } catch (error) {
                this.bot.logger.error(
                    'main',
                    'SEARCH-MANAGER',
                    `移动端搜索失败 | ${error instanceof Error ? error.message : String(error)}`
                )
                return 0
            }
        })
    }

    private runDesktop(account: Account): Promise<number> {
        return executionContext.run({ isMobile: false, account }, async () => {
            const session = await this.bot.createDesktopSession(account)
            try {
                return await this.bot.activities.doSearch(this.bot.mainDesktopPage, false)
            } catch (error) {
                this.bot.logger.error(
                    'main',
                    'SEARCH-MANAGER',
                    `桌面端搜索失败 | ${error instanceof Error ? error.message : String(error)}`
                )
                return 0
            } finally {
                await this.bot.browser.func.closeBrowser(session.context, account.email).catch(() => {})
            }
        })
    }
}
