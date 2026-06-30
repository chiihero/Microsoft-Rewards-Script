import { QueryCore } from '../../QueryEngine'
import { Workers } from '../../Workers'
import { BonusTracker } from '../SearchBonus'

const STAGNANT_LIMIT = 10
const MAX_SEARCHES = 60

export class Search extends Workers {
    public async doSearch(isMobile: boolean): Promise<number> {
        const startBalance = Number(this.bot.userData.currentPoints ?? 0)
        let totalGained = 0

        this.bot.logger.info(isMobile, 'SEARCH-BING', `开始 Bing 搜索 | 当前积分=${startBalance}`)

        try {
            const missing = this.bot.browser.func.missingSearchPoints(
                await this.bot.browser.func.getSearchPoints(),
                isMobile
            )
            this.bot.logger.info(
                isMobile,
                'SEARCH-BING',
                `剩余搜索积分 | Edge=${missing.edgePoints} | 桌面端=${missing.desktopPoints} | 移动端=${missing.mobilePoints}`
            )
            if (missing.totalPoints <= 0) {
                this.bot.logger.info(isMobile, 'SEARCH-BING', '没有可获得的搜索积分，跳过')
                return 0
            }

            const queryCore = new QueryCore(this.bot)
            let queries = await this.generatePool(queryCore)
            this.bot.logger.info(isMobile, 'SEARCH-BING', `查询词池就绪 | 数量=${queries.length}`)

            let stagnant = 0
            let index = 0
            let performed = 0
            let lastEarned: number | null = null

            while (performed < MAX_SEARCHES) {
                if (index >= queries.length) {
                    const extra = await this.generatePool(queryCore)
                    queries = this.bot.utils.shuffleArray([...new Set([...queries, ...extra])])
                    if (index >= queries.length) {
                        this.bot.logger.warn(isMobile, 'SEARCH-BING', '查询词池已耗尽，停止')
                        break
                    }
                }

                const query = queries[index++] as string
                const res = await this.bot.browser.func.reportSearchActivity(query)
                performed++

                if (!res.ig) {
                    this.bot.logger.warn(isMobile, 'SEARCH-BING', `查询词="${query}" 没有 IG - 跳过`)
                    continue
                }

                if (res.balance != null) this.bot.userData.currentPoints = res.balance

                const earned = res.searchPointsEarned
                const limit = res.searchPointsLimit
                const capReached = earned != null && limit != null && limit > 0 && earned >= limit
                const cap = earned != null && limit != null ? `${earned}/${limit}` : 'n/a'

                const gained = res.gained ?? 0
                const searchProgress = earned != null && lastEarned != null ? earned - lastEarned : gained
                if (earned != null) lastEarned = earned

                if (gained > 0) {
                    totalGained += gained
                    this.bot.userData.gainedPoints = (this.bot.userData.gainedPoints ?? 0) + gained
                }

                if (searchProgress > 0) {
                    stagnant = 0
                    this.bot.logger.info(
                        isMobile,
                        'SEARCH-BING',
                        `获得积分=${gained} | query="${query}" | 余额=${res.balance} | 搜索积分=${cap}`,
                        'green'
                    )
                } else {
                    stagnant++
                    this.bot.logger.info(
                        isMobile,
                        'SEARCH-BING',
                        `未获得积分 ${stagnant}/${STAGNANT_LIMIT} | query="${query}" | 搜索积分=${cap}`
                    )
                }

                if (capReached) {
                    this.bot.logger.info(
                        isMobile,
                        'SEARCH-BING',
                        `搜索积分已达上限 (${cap})，停止`,
                        'green'
                    )
                    break
                }

                if (stagnant >= STAGNANT_LIMIT) {
                    this.bot.logger.warn(
                        isMobile,
                        'SEARCH-BING',
                        `连续 ${STAGNANT_LIMIT} 次搜索未获得积分，中止`
                    )
                    break
                }

                await this.bot.utils.wait(
                    this.bot.utils.randomDelay(
                        this.bot.config.searchSettings.searchDelay.min,
                        this.bot.config.searchSettings.searchDelay.max
                    )
                )
            }

            this.bot.logger.info(
                isMobile,
                'SEARCH-BING',
                `Bing 搜索完成 | 起始余额=${startBalance} | 获得=${totalGained} | 搜索次数=${performed}`
            )
            return totalGained
        } catch (error) {
            this.bot.logger.error(
                isMobile,
                'SEARCH-BING',
                `doSearch 出错 | ${error instanceof Error ? error.message : String(error)}`
            )
            return totalGained
        }
    }

    public async doBonusSearches(): Promise<number> {
        const isMobile = this.bot.isMobile
        const tracker = new BonusTracker(this.bot, isMobile)

        const ready = await tracker.prepare()
        if (!ready || !tracker.started) return 0

        let totalGained = 0
        let performed = 0
        let stagnant = 0

        try {
            const queryCore = new QueryCore(this.bot)
            let queries = await this.generatePool(queryCore)
            if (!queries.length) {
                this.bot.logger.warn(isMobile, tracker.context, '没有可用的查询词，跳过')
                return 0
            }
            this.bot.logger.info(isMobile, tracker.context, `查询词池就绪 | 数量=${queries.length}`)

            let index = 0

            while (!tracker.done() && performed < tracker.maxSearches && stagnant < tracker.stagnantLimit) {
                if (index >= queries.length) {
                    const extra = await this.generatePool(queryCore)
                    queries = this.bot.utils.shuffleArray([...new Set([...queries, ...extra])])
                    if (index >= queries.length) {
                        this.bot.logger.warn(isMobile, tracker.context, '查询词池已耗尽，停止')
                        break
                    }
                }

                const query = queries[index++] as string
                const res = await this.bot.browser.func.reportSearchActivity(query)
                performed++

                if (!res.ig) {
                    this.bot.logger.warn(isMobile, tracker.context, `查询词="${query}" 没有 IG - 跳过`)
                    continue
                }

                const gained = await tracker.measure()
                if (gained > 0) {
                    stagnant = 0
                    totalGained += gained
                    this.bot.logger.info(
                        isMobile,
                        tracker.context,
                        `+${gained} | query="${query}" | ${tracker.progress()}`,
                        'green'
                    )
                } else {
                    stagnant++
                    this.bot.logger.info(
                        isMobile,
                        tracker.context,
                        `未获得积分 ${stagnant}/${tracker.stagnantLimit} | query="${query}" | ${tracker.progress()}`
                    )
                }

                await this.bot.utils.wait(
                    this.bot.utils.randomDelay(
                        this.bot.config.searchSettings.searchDelay.min,
                        this.bot.config.searchSettings.searchDelay.max
                    )
                )
            }
        } catch (error) {
            this.bot.logger.error(
                isMobile,
                tracker.context,
                `奖励会话出错 | ${error instanceof Error ? error.message : String(error)}`
            )
        }

        const done = tracker.done() && !tracker.offerLost
        const reason = done
            ? 'offer complete'
            : tracker.offerLost
              ? 'offer no longer present'
              : performed >= tracker.maxSearches
                ? 'reached maxBonusSearches'
                : stagnant >= tracker.stagnantLimit
                  ? `${tracker.stagnantLimit} idle searches`
                  : 'query pool exhausted'

        this.bot.logger.info(
            isMobile,
            tracker.context,
            `奖励刷取${done ? '完成' : '已停止'} (${reason}) | ${tracker.progress()} | 搜索次数=${performed} | 获得=+${totalGained}`,
            done || totalGained > 0 ? 'green' : undefined
        )
        return totalGained
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
}
