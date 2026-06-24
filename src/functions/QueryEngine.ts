import { AxiosError, type AxiosRequestConfig, type AxiosResponse } from 'axios'
import * as fs from 'fs'
import path from 'path'
import type { GoogleSearch, GoogleTrendsResponse, RedditListing, WikipediaTopResponse } from '../interface/Search'
import type { MicrosoftRewardsBot } from '../index'
import { QueryEngine } from '../interface/Config'

/**
 * 中国热搜源触发了 gmya.net 免费档的频率限制。
 * 携带 rateLimited 标记，供 getChinaTrends 做退避决策。
 */
class ChinaApiRateLimitError extends Error {
    rateLimited = true
    constructor(source: string, detail: string) {
        super(`${source} 触发限流：${detail}（建议配置 searchSettings.chinaApi.appkey）`)
        this.name = 'ChinaApiRateLimitError'
    }
}

export class QueryCore {
    constructor(private bot: MicrosoftRewardsBot) {}

    async queryManager(
        options: {
            shuffle?: boolean
            sourceOrder?: QueryEngine[]
            related?: boolean
            langCode?: string
            geoLocale?: string
        } = {}
    ): Promise<string[]> {
        const {
            shuffle = false,
            sourceOrder = ['china', 'google', 'wikipedia', 'reddit', 'local'],
            related = true,
            langCode = 'zh',
            geoLocale = 'CN'
        } = options

        try {
            this.bot.logger.debug(
                this.bot.isMobile,
                'QUERY-MANAGER',
                `开始 | shuffle=${shuffle}, related=${related}, lang=${langCode}, geo=${geoLocale}, sources=${sourceOrder.join(',')}`
            )

            const topicLists: string[][] = []

            const sourceHandlers: Record<
                'china' | 'google' | 'wikipedia' | 'reddit' | 'local',
                (() => Promise<string[]>) | (() => string[])
            > = {
                google: async () => {
                    const topics = await this.getGoogleTrends(geoLocale.toUpperCase()).catch(() => [])
                    this.bot.logger.debug(this.bot.isMobile, 'QUERY-MANAGER', `谷歌: ${topics.length}`)
                    return topics
                },
                wikipedia: async () => {
                    const topics = await this.getWikipediaTrending(langCode).catch(() => [])
                    this.bot.logger.debug(this.bot.isMobile, 'QUERY-MANAGER', `维基百科: ${topics.length}`)
                    return topics
                },
                reddit: async () => {
                    const topics = await this.getRedditTopics().catch(() => [])
                    this.bot.logger.debug(this.bot.isMobile, 'QUERY-MANAGER', `Reddit: ${topics.length}`)
                    return topics
                },
                local: () => {
                    const topics = this.getLocalQueryList()
                    this.bot.logger.debug(this.bot.isMobile, 'QUERY-MANAGER', `本地: ${topics.length}`)
                    return topics
                },
                china: async () => {
                    const topics = await this.getChinaTrends(geoLocale.toUpperCase()).catch(() => [])
                    this.bot.logger.debug(this.bot.isMobile, 'QUERY-MANAGER', `中国: ${topics.length}`)
                    return topics
                }
            }

            for (const source of sourceOrder) {
                const handler = sourceHandlers[source]
                if (!handler) continue

                const topics = await Promise.resolve(handler())
                if (topics.length) topicLists.push(topics)
            }

            this.bot.logger.debug(
                this.bot.isMobile,
                'QUERY-MANAGER',
                `源组合 | 原始总数=${topicLists.flat().length}`
            )

            const baseTopics = this.normalizeAndDedupe(topicLists.flat())

            if (!baseTopics.length) {
                this.bot.logger.debug(this.bot.isMobile, 'QUERY-MANAGER', '未找到基础主题（所有源均为空）')
                return []
            }

            this.bot.logger.debug(
                this.bot.isMobile,
                'QUERY-MANAGER',
                `基础主题去重 | 之前=${topicLists.flat().length} | 之后=${baseTopics.length}`
            )
            this.bot.logger.debug(this.bot.isMobile, 'QUERY-MANAGER', `基础主题: ${baseTopics.length}`)

            const clusters = related ? await this.buildRelatedClusters(baseTopics, langCode) : baseTopics.map(t => [t])

            this.bot.utils.shuffleArray(clusters)
            this.bot.logger.debug(this.bot.isMobile, 'QUERY-MANAGER', '聚类已打乱')

            let finalQueries = clusters.flat()
            this.bot.logger.debug(
                this.bot.isMobile,
                'QUERY-MANAGER',
                `聚类已展平 | 总数=${finalQueries.length}`
            )

            // 不要聚类搜索并打乱
            if (shuffle) {
                this.bot.utils.shuffleArray(finalQueries)
                this.bot.logger.debug(this.bot.isMobile, 'QUERY-MANAGER', '最终查询已打乱')
            }

            finalQueries = this.normalizeAndDedupe(finalQueries)
            this.bot.logger.debug(
                this.bot.isMobile,
                'QUERY-MANAGER',
                `最终查询去重 | 之后=${finalQueries.length}`
            )

            if (!finalQueries.length) {
                this.bot.logger.debug(this.bot.isMobile, 'QUERY-MANAGER', '最终查询去重后为0')
                return []
            }

            this.bot.logger.debug(this.bot.isMobile, 'QUERY-MANAGER', `最终查询: ${finalQueries.length}`)

            return finalQueries
        } catch (error) {
            this.bot.logger.debug(
                this.bot.isMobile,
                'QUERY-MANAGER',
                `错误: ${error instanceof Error ? `${error.name}: ${error.message}\n${error.stack ?? ''}` : String(error)}`
            )
            return []
        }
    }

    private async buildRelatedClusters(baseTopics: string[], langCode: string): Promise<string[][]> {
        const clusters: string[][] = []

        const LIMIT = 50
        const head = baseTopics.slice(0, LIMIT)
        const tail = baseTopics.slice(LIMIT)

        // 统计计数器（替代原来每条一日志的噪音）
        const stats = {
            emptySuggestionCount: 0, // 空建议次数
            emptyRelatedCount: 0, // 空相关次数
            failedRequestCount: 0, // 请求失败次数
            totalSuggestions: 0, // 总建议词数
            totalRelated: 0, // 总相关词数
            expandedTopics: 0 // 成功扩展的主题数（≥1 条建议或相关）
        }

        // 记录每个主题的扩展结果，用于最后输出清单
        const topicResults: Array<{ topic: string; suggCount: number; relCount: number }> = []

        // 进度采样阈值：每 25% 输出一次
        const sampleStep = Math.max(1, Math.ceil(head.length / 4))

        this.bot.logger.debug(
            this.bot.isMobile,
            'QUERY-MANAGER',
            `启用相关搜索 | 基础主题=${baseTopics.length} | 扩展=${head.length} | 直接通过=${tail.length} | 语言=${langCode}`
        )

        for (let i = 0; i < head.length; i++) {
            const topic = head[i] as string
            const suggestions = await this.getBingSuggestions(topic, langCode).catch(() => {
                stats.failedRequestCount++
                return []
            })
            const relatedTerms = await this.getBingRelatedTerms(topic).catch(() => {
                stats.failedRequestCount++
                return []
            })

            if (!suggestions.length) stats.emptySuggestionCount++
            if (!relatedTerms.length) stats.emptyRelatedCount++
            if (suggestions.length || relatedTerms.length) stats.expandedTopics++

            stats.totalSuggestions += suggestions.length
            stats.totalRelated += relatedTerms.length
            topicResults.push({ topic, suggCount: suggestions.length, relCount: relatedTerms.length })

            const usedSuggestions = suggestions.slice(0, 6)
            const usedRelated = relatedTerms.slice(0, 3)
            const cluster = this.normalizeAndDedupe([topic, ...usedSuggestions, ...usedRelated])
            clusters.push(cluster)

            // 进度采样：每 25% 或最后一个输出一次
            const isLast = i === head.length - 1
            if ((i + 1) % sampleStep === 0 || isLast) {
                const pct = Math.round(((i + 1) / head.length) * 100)
                this.bot.logger.debug(
                    this.bot.isMobile,
                    'QUERY-MANAGER',
                    `扩展进度 ${i + 1}/${head.length} (${pct}%) | 当前="${topic}" | ` +
                        `空建议=${stats.emptySuggestionCount} 空相关=${stats.emptyRelatedCount} ` +
                        `失败=${stats.failedRequestCount} 累计聚类=${clusters.reduce((s, c) => s + c.length, 0)}`
                )
            }
        }

        if (tail.length) {
            for (const topic of tail) clusters.push([topic])
            this.bot.logger.debug(
                this.bot.isMobile,
                'QUERY-MANAGER',
                `直通主题 | 数量=${tail.length} (超过 LIMIT=${LIMIT})`
            )
        }

        // 最终汇总（一条代替原来几十条）
        this.bot.logger.debug(
            this.bot.isMobile,
            'QUERY-MANAGER',
            `扩展完成 | 主题数=${baseTopics.length} | 成功扩展=${stats.expandedTopics} ` +
                `| 空建议=${stats.emptySuggestionCount}/${head.length} ` +
                `| 空相关=${stats.emptyRelatedCount}/${head.length} ` +
                `| 请求失败=${stats.failedRequestCount} ` +
                `| 总建议词=${stats.totalSuggestions} 总相关词=${stats.totalRelated} ` +
                `| 最终聚类=${clusters.length} 聚类总词数=${clusters.reduce((s, c) => s + c.length, 0)}`
        )

        // 输出热搜词使用清单（INFO 级别，默认可见）
        this.logTopicUsageReport(topicResults, tail)

        return clusters
    }

    /**
     * 输出热搜词使用清单，分三类展示：
     * - 可扩展（有建议/相关词）
     * - 未扩展（Bing 无建议/相关，直接作为搜索词）
     * - 直通（超过 LIMIT 没参与扩展）
     * 每类最多展示 20 个，避免日志过长。
     */
    private logTopicUsageReport(
        topicResults: Array<{ topic: string; suggCount: number; relCount: number }>,
        tail: string[]
    ): void {
        const MAX_DISPLAY = 20
        const total = topicResults.length + tail.length

        const expanded = topicResults.filter(r => r.suggCount > 0 || r.relCount > 0)
        const unexpanded = topicResults.filter(r => r.suggCount === 0 && r.relCount === 0)

        this.bot.logger.info(this.bot.isMobile, 'QUERY-MANAGER', `热搜词使用清单 | 共 ${total} 个词`)

        if (expanded.length) {
            const shown = expanded.slice(0, MAX_DISPLAY)
            const overflow = expanded.length - shown.length
            this.bot.logger.info(
                this.bot.isMobile,
                'QUERY-MANAGER',
                `可扩展的热搜词（${expanded.length} 个，已获得建议/相关词）:\n` +
                    shown.map(r => `  ✓ "${r.topic}" (建议=${r.suggCount}, 相关=${r.relCount})`).join('\n') +
                    (overflow > 0 ? `\n  ... 还有 ${overflow} 个` : '')
            )
        }

        if (unexpanded.length) {
            const shown = unexpanded.slice(0, MAX_DISPLAY)
            const overflow = unexpanded.length - shown.length
            this.bot.logger.info(
                this.bot.isMobile,
                'QUERY-MANAGER',
                `未扩展的热搜词（${unexpanded.length} 个，Bing 无建议/相关，将直接作为搜索词）:\n` +
                    shown.map(r => `  ✗ "${r.topic}"`).join('\n') +
                    (overflow > 0 ? `\n  ... 还有 ${overflow} 个` : '')
            )
        }

        if (tail.length) {
            const shown = tail.slice(0, MAX_DISPLAY)
            const overflow = tail.length - shown.length
            this.bot.logger.info(
                this.bot.isMobile,
                'QUERY-MANAGER',
                `直通热搜词（${tail.length} 个，超过 LIMIT 直接使用）:\n` +
                    shown.map(t => `  • "${t}"`).join('\n') +
                    (overflow > 0 ? `\n  ... 还有 ${overflow} 个` : '')
            )
        }
    }

    private normalizeAndDedupe(queries: string[]): string[] {
        const seen = new Set<string>()
        const out: string[] = []

        for (const q of queries) {
            if (!q) continue
            const trimmed = q.trim()
            if (!trimmed) continue

            const norm = trimmed.replace(/\s+/g, ' ').toLowerCase()
            if (seen.has(norm)) continue

            seen.add(norm)
            out.push(trimmed)
        }

        return out
    }

    async getGoogleTrends(geoLocale: string): Promise<string[]> {
        const queryTerms: GoogleSearch[] = []

        try {
            const request: AxiosRequestConfig = {
                url: 'https://trends.google.com/_/TrendsUi/data/batchexecute',
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
                },
                data: `f.req=[[[i0OFE,"[null, null, \\"${geoLocale.toUpperCase()}\\", 0, null, 48]"]]]`
            }

            const response = await this.bot.axios.request(request, this.bot.config.proxy.queryEngine)
            const trendsData = this.extractJsonFromResponse(response.data)
            if (!trendsData) {
                this.bot.logger.debug(this.bot.isMobile, 'SEARCH-GOOGLE-TRENDS', '未能从响应中解析趋势数据')
                return []
            }

            const mapped = trendsData.map(q => [q[0], q[9]!.slice(1)])

            if (mapped.length < 90 && geoLocale !== 'US') {
                return this.getGoogleTrends('US')
            }

            for (const [topic, related] of mapped) {
                queryTerms.push({
                    topic: topic as string,
                    related: related as string[]
                })
            }
        } catch (error) {
            this.bot.logger.debug(
                this.bot.isMobile,
                'SEARCH-GOOGLE-TRENDS',
                `请求失败: ${
                    error instanceof Error ? `${error.name}: ${error.message}\n${error.stack ?? ''}` : String(error)
                }`
            )
            return []
        }

        return queryTerms.flatMap(x => [x.topic, ...x.related])
    }

    private extractJsonFromResponse(text: string): GoogleTrendsResponse[1] | null {
        for (const line of text.split('\n')) {
            const trimmed = line.trim()
            if (!trimmed.startsWith('[')) continue
            try {
                return JSON.parse(JSON.parse(trimmed)[0][2])[1]
            } catch {}
        }
        return null
    }

    async getBingSuggestions(query = '', langCode = 'zh'): Promise<string[]> {
        try {
            const request: AxiosRequestConfig = {
                url: `https://www.bingapis.com/api/v7/suggestions?q=${encodeURIComponent(
                    query
                )}&appid=6D0A9B8C5100E9ECC7E11A104ADD76C10219804B&cc=xl&setlang=${langCode}`,
                method: 'POST',
                headers: {
                    ...(this.bot.fingerprint?.headers ?? {}),
                    'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
                }
            }

            const response = await this.bot.axios.request(request, this.bot.config.proxy.queryEngine)
            // 静默返回：空结果和错误的统计交给调用方 buildRelatedClusters 处理
            return (
                response.data.suggestionGroups?.[0]?.searchSuggestions?.map((x: { query: string }) => x.query) ?? []
            )
        } catch {
            return []
        }
    }

    async getBingRelatedTerms(query: string): Promise<string[]> {
        try {
            const request: AxiosRequestConfig = {
                url: `https://api.bing.com/osjson.aspx?query=${encodeURIComponent(query)}`,
                method: 'GET',
                headers: {
                    ...(this.bot.fingerprint?.headers ?? {})
                }
            }

            const response = await this.bot.axios.request(request, this.bot.config.proxy.queryEngine)
            const related = response.data?.[1]
            return Array.isArray(related) ? related : []
        } catch {
            return []
        }
    }

    async getBingTrendingTopics(langCode = 'zh'): Promise<string[]> {
        try {
            const request: AxiosRequestConfig = {
                url: `https://www.bing.com/api/v7/news/trendingtopics?appid=91B36E34F9D1B900E54E85A77CF11FB3BE5279E6&cc=xl&setlang=${langCode}`,
                method: 'GET',
                headers: {
                    Authorization: `Bearer ${this.bot.accessToken}`,
                    'User-Agent':
                        'Bing/32.5.431027001 (com.microsoft.bing; build:431027001; iOS 17.6.1) Alamofire/5.10.2',
                    'Content-Type': 'application/json',
                    'X-Rewards-Country': this.bot.userData.geoLocale,
                    'X-Rewards-Language': 'zh-CN',
                    'X-Rewards-ismobile': 'true'
                }
            }

            const response = await this.bot.axios.request(request, this.bot.config.proxy.queryEngine)
            const topics =
                response.data.value?.map(
                    (x: { query: { text: string }; name: string }) => x.query?.text?.trim() || x.name.trim()
                ) ?? []

            if (!topics.length) {
                this.bot.logger.debug(
                    this.bot.isMobile,
                    'SEARCH-BING-TRENDING',
                    `空热门话题 | 语言=${langCode}`
                )
            }

            return topics
        } catch (error) {
            this.bot.logger.debug(
                this.bot.isMobile,
                'SEARCH-BING-TRENDING',
                `请求失败 | 语言=${langCode} | 错误=${
                    error instanceof Error ? `${error.name}: ${error.message}\n${error.stack ?? ''}` : String(error)
                }`
            )
            return []
        }
    }

    async getWikipediaTrending(langCode = 'zh'): Promise<string[]> {
        try {
            const date = new Date(Date.now() - 24 * 60 * 60 * 1000)
            const yyyy = date.getUTCFullYear()
            const mm = String(date.getUTCMonth() + 1).padStart(2, '0')
            const dd = String(date.getUTCDate()).padStart(2, '0')

            const request: AxiosRequestConfig = {
                url: `https://wikimedia.org/api/rest_v1/metrics/pageviews/top/${langCode}.wikipedia/all-access/${yyyy}/${mm}/${dd}`,
                method: 'GET',
                headers: {
                    ...(this.bot.fingerprint?.headers ?? {})
                }
            }

            const response = await this.bot.axios.request(request, this.bot.config.proxy.queryEngine)
            const articles = (response.data as WikipediaTopResponse).items?.[0]?.articles ?? []

            const out = articles.slice(0, 50).map(a => a.article.replace(/_/g, ' '))

            if (!out.length) {
                this.bot.logger.debug(
                    this.bot.isMobile,
                    'SEARCH-WIKIPEDIA-TRENDING',
                    `空维基百科热门 | 语言=${langCode}`
                )
            }

            return out
        } catch (error) {
            this.bot.logger.debug(
                this.bot.isMobile,
                'SEARCH-WIKIPEDIA-TRENDING',
                `请求失败 | 语言=${langCode} | 错误=${
                    error instanceof Error ? `${error.name}: ${error.message}\n${error.stack ?? ''}` : String(error)
                }`
            )
            return []
        }
    }

    async getRedditTopics(subreddit = 'popular'): Promise<string[]> {
        try {
            const safe = subreddit.replace(/[^a-zA-Z0-9_+]/g, '')
            const request: AxiosRequestConfig = {
                url: `https://www.reddit.com/r/${safe}.json?limit=50`,
                method: 'GET',
                headers: {
                    ...(this.bot.fingerprint?.headers ?? {})
                }
            }

            const response = await this.bot.axios.request(request, this.bot.config.proxy.queryEngine)
            const posts = (response.data as RedditListing).data?.children ?? []

            const out = posts.filter(p => !p.data.over_18).map(p => p.data.title)

            if (!out.length) {
                this.bot.logger.debug(
                    this.bot.isMobile,
                    'SEARCH-REDDIT-TRENDING',
                    `空Reddit列表 | 子版块=${safe}`
                )
            }

            return out
        } catch (error) {
            this.bot.logger.debug(
                this.bot.isMobile,
                'SEARCH-REDDIT',
                `请求失败 | 子版块=${subreddit} | 错误=${
                    error instanceof Error ? `${error.name}: ${error.message}\n${error.stack ?? ''}` : String(error)
                }`
            )
            return []
        }
    }

    getLocalQueryList(): string[] {
        try {
            const file = path.join(__dirname, './search-queries.json')
            const queries = JSON.parse(fs.readFileSync(file, 'utf8')) as string[]
            const out = Array.isArray(queries) ? queries : []

            this.bot.logger.debug(
                this.bot.isMobile,
                'SEARCH-LOCAL-QUERY-LIST',
                '本地查询已加载 | 文件=search-queries.json'
            )

            if (!out.length) {
                this.bot.logger.debug(
                    this.bot.isMobile,
                    'SEARCH-LOCAL-QUERY-LIST',
                    'search-queries.json 已解析但为空或无效'
                )
            }

            return out
        } catch (error) {
            this.bot.logger.debug(
                this.bot.isMobile,
                'SEARCH-LOCAL-QUERY-LIST',
                `读取/解析失败 | 错误=${
                    error instanceof Error ? `${error.name}: ${error.message}\n${error.stack ?? ''}` : String(error)
                }`
            )
            return []
        }
    }

    /**
     * 获取中国地区的热门搜索词（百度、抖音、微博、头条、知乎等）。
     * 数据源：gmya.net 热门词 API。
     * 策略：
     *   - appkey 配置在 searchSettings.chinaApi.appkey；留空走免费档。
     *   - 随机选取若干源聚合结果，分散 API 负载、增加搜索词多样性。
     *   - 免费档（无 appkey）有激进的频率限制：源与源之间插入随机退避，
     *     命中限流（403）后对后续源做指数退避；有 appkey 则不退避。
     *   - 某个源失败时自动 fallback 到剩余源，确保至少拿到 1 个源的数据。
     *
     * @param geoLocale - 地理区域代码，默认为'CN'
     * @returns 热搜标题字符串数组
     */
    async getChinaTrends(geoLocale: string = 'CN'): Promise<string[]> {
        const allSources = ['BaiduHot', 'TouTiaoHot', 'DouYinHot', 'WeiBoHot', 'ZhiHuHot']
        const baseUrl = 'https://api.gmya.net/Api/'
        // appkey 来自配置；留空走免费档（有频率限制），填入则解除限流
        const appkey = this.bot.config.searchSettings.chinaApi?.appkey?.trim() ?? ''
        const hasAppkey = appkey.length > 0
        // 免费档容易被限流：减少首选源数量以降低触发面；有 appkey 则保持 2 个兼顾多样性
        const pickedCount = hasAppkey ? 2 : 1
        // 免费档源间退避参数（毫秒）；有 appkey 不需要退避
        const backoffMin = 1200
        const backoffMax = 2500

        // 随机打乱源顺序，取前 pickedCount 个作为首选；其余作为 fallback 备用
        const shuffled = this.bot.utils.shuffleArray([...allSources])
        const picked = shuffled.slice(0, pickedCount)
        const fallback = shuffled.slice(pickedCount)

        this.bot.logger.info(
            this.bot.isMobile,
            'SEARCH-CHINA-TRENDS',
            `正在获取中国热搜 | 地区=${geoLocale} | appkey=${hasAppkey ? '已配置' : '免费档'} | 首选源=${picked.join(', ')} | 备用源=${fallback.length}个`
        )

        /**
         * 免费档在源与源之间插入随机退避，降低连续请求触发 403 限流的概率。
         * 命中限流后对后续源做指数退避（multiplier 递增）。
         * @param multiplier 基础退避倍数，限流后递增
         */
        const maybeBackoff = async (multiplier: number): Promise<void> => {
            if (hasAppkey) return
            await this.bot.utils.waitRandom(backoffMin * multiplier, backoffMax * multiplier)
        }

        const titles = new Set<string>()
        const failedSources: string[] = []
        let backoffMultiplier = 1 // 限流命中后递增

        // 先依次尝试首选源
        for (let i = 0; i < picked.length; i++) {
            if (i > 0) await maybeBackoff(backoffMultiplier)
            const source = picked[i]!
            try {
                const result = await this.fetchChinaHotWords(this.buildChinaApiUrl(baseUrl, source, appkey), source)
                if (result.length) {
                    result.forEach(t => titles.add(t))
                    this.bot.logger.info(
                        this.bot.isMobile,
                        'SEARCH-CHINA-TRENDS',
                        `获取 ${source} 成功 | 数量=${result.length} | 累计=${titles.size}`
                    )
                } else {
                    this.bot.logger.warn(this.bot.isMobile, 'SEARCH-CHINA-TRENDS', `${source} 返回空列表`)
                    failedSources.push(source)
                }
            } catch (error) {
                failedSources.push(source)
                if (error instanceof ChinaApiRateLimitError) backoffMultiplier *= 1.5
                this.bot.logger.warn(
                    this.bot.isMobile,
                    'SEARCH-CHINA-TRENDS',
                    `${source} 请求失败 | 错误=${error instanceof Error ? error.message : String(error)}`
                )
            }
        }

        // 如果首选源全部失败，逐个 fallback 直到拿到数据
        if (titles.size === 0 && fallback.length) {
            this.bot.logger.warn(
                this.bot.isMobile,
                'SEARCH-CHINA-TRENDS',
                `首选源全部失败（${failedSources.join(', ')}），尝试备用源 ${fallback.join(', ')}`
            )
            for (let i = 0; i < fallback.length; i++) {
                await maybeBackoff(backoffMultiplier)
                const source = fallback[i]!
                try {
                    const result = await this.fetchChinaHotWords(
                        this.buildChinaApiUrl(baseUrl, source, appkey),
                        source
                    )
                    if (result.length) {
                        result.forEach(t => titles.add(t))
                        this.bot.logger.info(
                            this.bot.isMobile,
                            'SEARCH-CHINA-TRENDS',
                            `备用源 ${source} 成功 | 数量=${result.length} | 累计=${titles.size}`
                        )
                        break // 拿到数据就停
                    }
                } catch (error) {
                    if (error instanceof ChinaApiRateLimitError) backoffMultiplier *= 1.5
                    this.bot.logger.warn(
                        this.bot.isMobile,
                        'SEARCH-CHINA-TRENDS',
                        `备用源 ${source} 也失败 | 错误=${error instanceof Error ? error.message : String(error)}`
                    )
                }
            }
        }

        if (titles.size === 0) {
            this.bot.logger.warn(
                this.bot.isMobile,
                'SEARCH-CHINA-TRENDS',
                `所有 ${allSources.length} 个热搜源均失败，将仅依赖其他查询源`
            )
        } else {
            this.bot.logger.info(
                this.bot.isMobile,
                'SEARCH-CHINA-TRENDS',
                `中国热搜获取完成 | 最终词数=${titles.size} | 成功源=${picked.filter(s => !failedSources.includes(s)).join(',') || fallback.filter(s => titles.size > 0).join(',')}`,
                'green'
            )
        }

        return Array.from(titles)
    }

    /**
     * 构造 gmya.net 热搜 API 的请求 URL。
     */
    private buildChinaApiUrl(baseUrl: string, source: string, appkey: string): string {
        return appkey ? `${baseUrl}${source}?format=json&appkey=${appkey}` : `${baseUrl}${source}`
    }

    /**
     * 请求单个中国热搜源并解析标题。
     * 走 bot.axios（统一代理、错误诊断、fingerprint headers），带 10s 超时。
     *
     * 诊断策略：正常就 return；任何异常都把"原始返回值"打到日志里，让看日志的人直接判断
     * 是限流、HTML 拦截页、维护 JSON 还是接口结构变更——比预先贴标签更有用。
     * 唯一例外是限流：上层退避需要它做控制流，所以用 ChinaApiRateLimitError 单独标记，
     * 但错误信息同样带上原始响应。
     */
    private async fetchChinaHotWords(url: string, source: string): Promise<string[]> {
        const request: AxiosRequestConfig = {
            url,
            method: 'GET',
            headers: {
                ...(this.bot.fingerprint?.headers ?? {})
            },
            timeout: 10000
        }

        // 请求失败（HTTP 非 2xx / 超时 / 网络错误）：直接吐原始返回，不再预先贴标签
        let response: AxiosResponse
        try {
            response = await this.bot.axios.request(request, this.bot.config.proxy.queryEngine)
        } catch (error) {
            const { rateLimited, text } = this.describeAxiosError(error)
            if (rateLimited) throw new ChinaApiRateLimitError(source, text)
            throw new Error(`${source} 失败 | 原始响应=${text}`)
        }

        const data = response.data

        // 限流：上层退避需要这个标记；信息里仍带原始响应
        if (this.isChinaRateLimited(response)) {
            throw new ChinaApiRateLimitError(source, `原始响应=${this.summarizeBody(data)}`)
        }

        // 正常结构：{ data: [{ title: string }, ...] }
        if (data && Array.isArray(data.data)) {
            return data.data
                .filter((item: { title?: unknown }) => item && typeof item.title === 'string')
                .map((item: { title: string }) => item.title)
                .filter((title: string) => title.trim().length > 0)
        }

        // 结构非预期：直接吐原始返回，由人判断（HTML 拦截页 / 维护 JSON / 结构变更）
        throw new Error(`${source} 失败 | 原始响应=${this.summarizeBody(data)}`)
    }

    /**
     * 判断响应是否为 gmya.net 免费档限流。
     * 免费档限流响应：{ code: "403", msg: "您请求过于频繁，未使用账号appkey请求将限制请求频率" }
     * 没有 data 数组，需和真正的格式异常区分，否则会误导排查方向。
     */
    private isChinaRateLimited(response: AxiosResponse): boolean {
        const status = response.status
        const data = response.data
        const code = data?.code
        const msg = typeof data?.msg === 'string' ? data.msg : ''
        return (
            status === 403 ||
            status === 429 ||
            code === '403' ||
            code === 403 ||
            code === '429' ||
            msg.includes('请求过于频繁') ||
            msg.includes('appkey')
        )
    }

    /**
     * 把响应体序列化为可读字符串，诊断失败时用。
     * - 对象走 JSON.stringify
     * - 字符串原样返回（可能是 HTML 拦截/维护页）
     * - undefined/空记为 <无响应体>
     * - 非 UTF-8 响应体（gzip 压缩流 / GBK HTML 错误页 / CDN 二进制拦截页）：
     *   axios 默认按 UTF-8 解码，非法字节被替换成 U+FFFD(�)，原始字节已丢失。
     *   原样写日志会产生乱码，且二进制流里的 0x0A(换行字节) 会把一条日志拆成
     *   多行、污染日志结构。这里检测到高密度替换符时改写为可读的诊断摘要。
     * 兜底截断到 1000 字符，防止上游误返回超大 HTML 污染日志。
     */
    private summarizeBody(body: unknown): string {
        if (body === undefined || body === null || body === '') return '<无响应体>'
        const text = typeof body === 'string' ? body : JSON.stringify(body)
        // 检测损坏的非 UTF-8 内容：替换符 U+FFFD 占比 >= 5% 即判定为二进制/非文本响应体
        const replacementCount = (text.match(/\uFFFD/g) ?? []).length
        if (replacementCount > 0 && replacementCount / Math.max(text.length, 1) >= 0.05) {
            // hex 指纹便于人工判断内容类型（gzip=1F8B、HTML=3C68746D6C、GBK错误页 等）
            const hex = Buffer.from(text, 'utf8').subarray(0, 32).toString('hex')
            return `<非UTF-8响应体 | 长度=${text.length} | 替换符=${replacementCount} | 疑似gzip/二进制/GBK错误页 | hex前32=${hex}>`
        }
        return text.length > 1000 ? `${text.slice(0, 1000)}...(+${text.length - 1000}字符)` : text
    }

    /**
     * 描述 axios 抛出的错误，返回可读文本 + 是否为限流。
     * - 有 response：吐原始响应体（限流标记由 HTTP 状态码 403/429 判定）
     * - 无 response（超时/断网/DNS）：吐 axios 错误码 + message
     */
    private describeAxiosError(error: unknown): { rateLimited: boolean; text: string } {
        if (error instanceof AxiosError) {
            if (error.response) {
                return {
                    rateLimited: error.response.status === 403 || error.response.status === 429,
                    text: this.summarizeBody(error.response.data)
                }
            }
            return {
                rateLimited: false,
                text: `<无响应体> | axiosCode=${error.code ?? '无'} | ${error.message}`
            }
        }
        return {
            rateLimited: false,
            text: `<无响应体> | ${error instanceof Error ? error.message : String(error)}`
        }
    }
}
