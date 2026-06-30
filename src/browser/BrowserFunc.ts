import { randomBytes } from 'crypto'

import { URLs } from '../constants/urls'
import { BING_APP_USER_AGENT } from '../constants/userAgents'
import type { BrowserContext, Cookie, Page } from 'patchright'
import type { HttpRequestConfig } from '../util/Http'

import type { MicrosoftRewardsBot } from '../index'
import { saveStorageState } from '../util/SessionStore'
import { isBrowserClosedError } from '../util/Utils'

import type { Counters, DashboardData } from './../interface/DashboardData'
import type { AppUserData } from '../interface/AppUserData'
import type { AppEarnablePoints, BrowserEarnablePoints, MissingSearchPoints } from '../interface/Points'
import type { AppDashboardData } from '../interface/AppDashBoardData'

export default class BrowserFunc {
    private bot: MicrosoftRewardsBot

    private bingJars = new Map<string, Map<string, string>>()

    constructor(bot: MicrosoftRewardsBot) {
        this.bot = bot
    }

    async getDashboardData(cookies?: Cookie[]): Promise<DashboardData> {
        try {
            const request: HttpRequestConfig = {
                url: URLs.rewards.userInfoApi,
                method: 'GET',
                headers: {
                    ...(this.bot.fingerprint?.headers ?? {}),
                    Cookie: this.buildCookieHeader(cookies ?? this.bot.cookies.mobile, [
                        'bing.com',
                        'live.com',
                        'microsoftonline.com'
                    ]),
                    Referer: URLs.rewards.referer,
                    Origin: URLs.rewards.origin
                }
            }

            const response = await this.bot.http.request(request)

            if (response.data) {
                return response.data as DashboardData
            }
            throw new Error('Dashboard data missing from API response')
        } catch (error) {
            throw this.bot.logger.error(
                this.bot.isMobile,
                'GET-DASHBOARD-DATA',
                `获取仪表板数据失败: ${error instanceof Error ? error.message : String(error)}`
            )
        }
    }

    async getAppDashboardData(): Promise<AppDashboardData> {
        try {
            const request: HttpRequestConfig = {
                url: URLs.platform.me('SAIOS'),
                method: 'GET',
                headers: {
                    Authorization: `Bearer ${this.bot.accessToken}`,
                    'User-Agent': BING_APP_USER_AGENT
                }
            }

            const response = await this.bot.http.request(request)
            return response.data as AppDashboardData
        } catch (error) {
            this.bot.logger.error(
                this.bot.isMobile,
                'GET-APP-DASHBOARD-DATA',
                `获取应用仪表板数据失败: ${error instanceof Error ? error.message : String(error)}`
            )
            throw error
        }
    }

    async getSearchPoints(): Promise<Counters> {
        const dashboardData = await this.getDashboardData() // Always fetch newest data

        return dashboardData.dashboard.userStatus.counters
    }

    missingSearchPoints(counters: Counters, isMobile: boolean): MissingSearchPoints {
        const mobileData = counters.mobileSearch?.[0]
        const desktopData = counters.pcSearch?.[0]
        const edgeData = counters.pcSearch?.[1]

        const mobilePoints = mobileData ? Math.max(0, mobileData.pointProgressMax - mobileData.pointProgress) : 0
        const desktopPoints = desktopData ? Math.max(0, desktopData.pointProgressMax - desktopData.pointProgress) : 0
        const edgePoints = edgeData ? Math.max(0, edgeData.pointProgressMax - edgeData.pointProgress) : 0

        const totalPoints = isMobile ? mobilePoints : desktopPoints + edgePoints

        return { mobilePoints, desktopPoints, edgePoints, totalPoints }
    }

    async getBrowserEarnablePoints(): Promise<BrowserEarnablePoints> {
        try {
            const data = await this.getDashboardData()

            const desktopSearchPoints =
                data.dashboard.userStatus.counters.pcSearch?.reduce(
                    (sum: number, x: { pointProgressMax: number; pointProgress: number }) =>
                        sum + (x.pointProgressMax - x.pointProgress),
                    0
                ) ?? 0

            const mobileSearchPoints =
                data.dashboard.userStatus.counters.mobileSearch?.reduce(
                    (sum: number, x: { pointProgressMax: number; pointProgress: number }) =>
                        sum + (x.pointProgressMax - x.pointProgress),
                    0
                ) ?? 0

            const todayDate = this.bot.utils.getFormattedDate()
            const dailySetPoints =
                data.dashboard.dailySetPromotions[todayDate]?.reduce(
                    (sum: number, x: { pointProgressMax: number; pointProgress: number }) =>
                        sum + (x.pointProgressMax - x.pointProgress),
                    0
                ) ?? 0

            const morePromotionsPoints =
                data.dashboard.morePromotions?.reduce((sum, x) => {
                    if (x.promotionType === 'urlreward' && x.exclusiveLockedFeatureStatus !== 'locked') {
                        return sum + (x.pointProgressMax - x.pointProgress)
                    }
                    return sum
                }, 0) ?? 0

            const totalEarnablePoints = desktopSearchPoints + mobileSearchPoints + dailySetPoints + morePromotionsPoints

            return {
                dailySetPoints,
                morePromotionsPoints,
                desktopSearchPoints,
                mobileSearchPoints,
                totalEarnablePoints
            }
        } catch (error) {
            this.bot.logger.error(
                this.bot.isMobile,
                'GET-BROWSER-EARNABLE-POINTS',
                `发生错误: ${error instanceof Error ? error.message : String(error)}`
            )
            throw error
        }
    }

    async getAppEarnablePoints(): Promise<AppEarnablePoints> {
        try {
            const eligibleOffers = ['ENUS_readarticle3_30points', 'Gamification_Sapphire_DailyCheckIn']

            const request: HttpRequestConfig = {
                url: URLs.platform.me('SAAndroid'),
                method: 'GET',
                headers: {
                    Authorization: `Bearer ${this.bot.accessToken}`,
                    'X-Rewards-Country': this.bot.userData.geoLocale,
                    'X-Rewards-Language': 'en',
                    'X-Rewards-ismobile': 'true'
                }
            }

            const response = await this.bot.http.request<AppUserData>(request)
            const userData: AppUserData = response.data
            const eligibleActivities = userData.response.promotions.filter(x =>
                eligibleOffers.includes(x.attributes.offerid ?? '')
            )

            let readToEarn = 0
            let checkIn = 0

            for (const item of eligibleActivities) {
                const attrs = item.attributes

                if (attrs.type === 'msnreadearn') {
                    const pointMax = parseInt(attrs.pointmax ?? '0')
                    const pointProgress = parseInt(attrs.pointprogress ?? '0')
                    readToEarn = Math.max(0, pointMax - pointProgress)
                } else if (attrs.type === 'checkin') {
                    const progress = parseInt(attrs.progress ?? '0')
                    const checkInDay = progress % 7
                    const lastUpdated = new Date(attrs.last_updated ?? '')
                    const today = new Date()

                    if (checkInDay < 6 && today.getDate() !== lastUpdated.getDate()) {
                        checkIn = parseInt(attrs[`day_${checkInDay + 1}_points`] ?? '0')
                    }
                }
            }

            const totalEarnablePoints = readToEarn + checkIn

            return {
                readToEarn,
                checkIn,
                totalEarnablePoints
            }
        } catch (error) {
            this.bot.logger.error(
                this.bot.isMobile,
                'GET-APP-EARNABLE-POINTS',
                `发生错误: ${error instanceof Error ? error.message : String(error)}`
            )
            throw error
        }
    }

    async getCurrentPoints(): Promise<number> {
        try {
            const data = await this.getDashboardData()

            return data.dashboard.userStatus.availablePoints
        } catch (error) {
            this.bot.logger.error(
                this.bot.isMobile,
                'GET-CURRENT-POINTS',
                `发生错误: ${error instanceof Error ? error.message : String(error)}`
            )
            throw error
        }
    }

    async bootstrap(page: Page): Promise<void> {
        try {
            // /earn is the offers page
            await page.goto(URLs.rewards.earn, { waitUntil: 'domcontentloaded' })
            const earnHtml = await page.content()

            this.bot.nextRouterStateTree = this.bot.browser.react.routerStateTree('earn')

            //offers (valid hashes), streaks, account state
            this.bot.reactSnapshot = this.bot.browser.react.snapshotPage(earnHtml)

            // pull /dashboard HTML to capture chunks that /earn doesn't show
            let dashboardHtml = ''
            try {
                const res = await page.request.get(URLs.rewards.dashboard)
                if (res.ok()) {
                    dashboardHtml = await res.text()
                } else {
                    this.bot.logger.warn(
                        this.bot.isMobile,
                        'BOOTSTRAP',
                        `获取 /dashboard HTML 失败 | status=${res.status()} - action 发现可能不完整`
                    )
                }
            } catch (error) {
                this.bot.logger.warn(
                    this.bot.isMobile,
                    'BOOTSTRAP',
                    `获取 /dashboard HTML 失败 | error=${error instanceof Error ? error.message : String(error)} - action 发现可能不完整`
                )
            }

            // discovered from chunks referenced by either page
            this.bot.nextActions = await this.resolveActionIds(page, [earnHtml, dashboardHtml])

            const dashboardRendered = /<section\b[^>]*\bid=["']dailyset["']/i.test(dashboardHtml || earnHtml)
            if (!dashboardRendered) {
                throw new Error(
                    'Rewards dashboard did not render (no section#dailyset) - likely a login/redirect issue, aborting'
                )
            }

            if (!this.bot.reactSnapshot.offers.length) {
                this.bot.logger.warn(
                    this.bot.isMobile,
                'BOOTSTRAP',
                '未解析到 offers - 页面可能未渲染 RSC payload（请检查登录/重定向）'
            )
            }

            if (!Object.keys(this.bot.nextActions).length) {
                this.bot.logger.warn(
                    this.bot.isMobile,
                'BOOTSTRAP',
                '未发现 action id - server-action 调用将失败（bundle 可能已剥离名称）'
            )
            }

            this.bot.logger.info(
                this.bot.isMobile,
                'BOOTSTRAP',
                `上下文已就绪 | actions=${Object.keys(this.bot.nextActions).length} | reportable=${this.bot.reactSnapshot.reportable.length} | available=${this.bot.reactSnapshot.account.availablePoints}`
            )

            this.bot.logger.info(
                this.bot.isMobile,
                'BUILD',
                `奖励构建 | id=${this.bot.browser.react.buildId(earnHtml) ?? 'unknown'}`
            )
        } catch (error) {
            this.bot.logger.error(
                this.bot.isMobile,
                'BOOTSTRAP',
                `获取上下文失败 | error=${error instanceof Error ? error.message : String(error)}`
            )
            throw error
        }
    }

    private async resolveActionIds(page: Page, htmls: string[]): Promise<Record<string, string>> {
        const result: Record<string, string> = {}

        try {
            const initialChunks = new Set<string>()
            const chunkRegex = /(?:\/_next\/)?(static\/chunks\/[\w\-./()]+?\.js)/g
            for (const html of htmls) {
                if (!html) continue
                for (const match of html.matchAll(chunkRegex)) {
                    initialChunks.add('/_next/' + match[1]!)
                }
            }

            if (initialChunks.size === 0) {
                this.bot.logger.warn(
                    this.bot.isMobile,
                    'BOOTSTRAP',
                    'HTML 中未发现初始 chunks - chunk 引用结构可能已变更'
                )
            }

            this.bot.logger.debug(this.bot.isMobile, 'BOOTSTRAP', `正在获取 ${initialChunks.size} 个初始 JS chunks`)
            const jsByPath = await this.fetchJsChunks(page, [...initialChunks])

            // dynamically-imported chunks, server actions inside popover
            const dynamicPaths: string[] = []
            for (const js of jsByPath.values()) {
                for (const path of this.extractDynamicChunkPaths(js)) {
                    if (!jsByPath.has(path) && !dynamicPaths.includes(path)) {
                        dynamicPaths.push(path)
                    }
                }
            }

            if (dynamicPaths.length) {
                this.bot.logger.debug(
                    this.bot.isMobile,
                    'BOOTSTRAP',
                    `正在获取 ${dynamicPaths.length} 个通过 webpack manifest 发现的动态 chunks`
                )
                const moreJs = await this.fetchJsChunks(page, dynamicPaths)
                for (const [path, js] of moreJs) jsByPath.set(path, js)
            }

            for (const [path, js] of jsByPath) {
                const filename = path.split('/').pop() ?? path
                const ids = this.bot.browser.react.extractActionIds(js)
                const names = Object.keys(ids.byName)

                if (names.length) {
                    Object.assign(result, ids.byName)
                    this.bot.logger.debug(
                        this.bot.isMobile,
                        'BOOTSTRAP',
                        `在 ${filename} 中找到 ${names.length} 个 action id: [${names.join(', ')}]`
                    )
                } else {
                    this.bot.logger.debug(this.bot.isMobile, 'BOOTSTRAP', `${filename} 中未找到 server-action id`)
                }

                const namedSet = new Set(Object.values(ids.byName))
                const unnamed = ids.all.filter(id => !namedSet.has(id))
                if (unnamed.length) {
                    this.bot.logger.debug(
                        this.bot.isMobile,
                        'BOOTSTRAP',
                        `在 ${filename} 中找到 ${unnamed.length} 个未命名 action id: [${unnamed.join(', ')}]`
                    )
                }
            }

            this.bot.logger.debug(
                this.bot.isMobile,
                'BOOTSTRAP',
                `已发现 ${Object.keys(result).length} 个 action id: [${Object.keys(result).join(', ')}]`
            )
        } catch (error) {
            this.bot.logger.error(
                this.bot.isMobile,
                'BOOTSTRAP',
                `解析 action id 失败 | error=${error instanceof Error ? error.message : String(error)}`
            )
        }

        return result
    }

    private async fetchJsChunks(page: Page, paths: string[]): Promise<Map<string, string>> {
        const result = new Map<string, string>()

        await Promise.all(
            paths.map(async path => {
                try {
                    const res = await page.request.get(URLs.rewards.path(path))
                    if (res.ok()) {
                        result.set(path, await res.text())
                    }
                } catch (error) {
                    this.bot.logger.debug(
                        this.bot.isMobile,
                        'BOOTSTRAP',
                        `Chunk 获取失败 | path=${path} | ${error instanceof Error ? error.message : String(error)}`
                    )
                }
            })
        )

        return result
    }

    private extractDynamicChunkPaths(js: string): string[] {
        const seen = new Set<string>()

        const builder = /static\/chunks\/"\s*\+\s*\w+\s*\+\s*"([-.])"\s*\+\s*\{([\s\S]*?)\}\s*\[/g
        for (const match of js.matchAll(builder)) {
            const sep = match[1]!
            for (const [, id, hash] of match[2]!.matchAll(/(\d+)\s*:\s*"([a-f0-9]+)"/g)) {
                seen.add(`/_next/static/chunks/${id}${sep}${hash}.js`)
            }
        }

        // If the builder shape changes, scan id:hash pairs globally
        if (!seen.size) {
            for (const [, id, hash] of js.matchAll(/\b(\d{2,6}):"([a-f0-9]{12,})"/g)) {
                seen.add(`/_next/static/chunks/${id}-${hash}.js`)
                seen.add(`/_next/static/chunks/${id}.${hash}.js`)
            }
        }

        return [...seen]
    }

    async closeBrowser(browser: BrowserContext, email: string) {
        const rootBrowser = browser.browser?.() || null

        try {
            // Store state (cookies + localStorage) for next run
            const storageState = await browser.storageState()
            this.bot.logger.debug(
                this.bot.isMobile,
                'CLOSE-BROWSER',
                `保存会话 | cookies=${storageState.cookies.length} | origins=${storageState.origins.length}`
            )
            saveStorageState(this.bot.config.sessionPath, email, this.bot.isMobile, storageState)

            await this.bot.utils.wait(2000)
        } catch (error) {
            if (isBrowserClosedError(error)) {
                this.bot.logger.debug(
                    this.bot.isMobile,
                    'CLOSE-BROWSER',
                    `会话未保存（浏览器正在关闭）: ${error instanceof Error ? error.message : String(error)}`
                )
            } else {
                this.bot.logger.error(this.bot.isMobile, 'CLOSE-BROWSER', `保存会话失败: ${error}`)
            }
        } finally {
            try {
                await browser.close()

                if (rootBrowser) {
                    await rootBrowser.close().catch(() => {})
                }

                this.bot.logger.info(this.bot.isMobile, 'CLOSE-BROWSER', '所有浏览器资源已关闭。')
            } catch (error) {
                if (isBrowserClosedError(error)) {
                    this.bot.logger.debug(this.bot.isMobile, 'CLOSE-BROWSER', '浏览器已关闭。')
                } else {
                    this.bot.logger.warn(
                        this.bot.isMobile,
                        'CLOSE-BROWSER',
                        '关闭时遇到错误，但进程正在退出。'
                    )
                }
            }
        }
    }

    buildCookieHeader(cookies: Cookie[], allowedDomains?: string[]): string {
        return [
            ...new Map(
                cookies
                    .filter(c => {
                        if (!allowedDomains || allowedDomains.length === 0) return true
                        return (
                            typeof c.domain === 'string' &&
                            allowedDomains.some(d => c.domain.toLowerCase().endsWith(d.toLowerCase()))
                        )
                    })
                    .map(c => [c.name, c])
            ).values()
        ]
            .map(c => `${c.name}=${c.value}`)
            .join('; ')
    }

    // Fire a nextjs RSC server action shared by UrlReward / ClaimReward / ClaimBonusPoints
    async reportServerAction(
        actionId: string,
        body: unknown[],
        opts?: { url?: string; referer?: string; routerStateTree?: string }
    ): Promise<{ status: number; acknowledged: boolean }> {
        const url = opts?.url ?? URLs.rewards.earn
        const referer = opts?.referer ?? url
        const routerStateTree = opts?.routerStateTree ?? this.bot.nextRouterStateTree

        const cookieHeader = this.buildCookieHeader(
            this.bot.isMobile ? this.bot.cookies.mobile : this.bot.cookies.desktop,
            ['bing.com', 'live.com', 'microsoftonline.com']
        )

        const fingerprintHeaders = { ...this.bot.fingerprint.headers }
        delete fingerprintHeaders['Cookie']
        delete fingerprintHeaders['cookie']

        const request: HttpRequestConfig = {
            url,
            method: 'POST',
            headers: {
                ...fingerprintHeaders,
                Cookie: cookieHeader,
                Referer: referer,
                Origin: URLs.rewards.origin,
                Accept: 'text/x-component',
                'Content-Type': 'text/plain;charset=UTF-8',
                'Next-Action': actionId,
                'Next-Router-State-Tree': routerStateTree
            },
            data: JSON.stringify(body)
        }

        const response = await this.bot.http.request(request)
        const acknowledged = this.bot.utils.serverActionAcknowledged(response.data)

        return { status: response.status, acknowledged }
    }

    async reportSearchActivity(
        query: string,
        opts?: { cvid?: string; cg?: string }
    ): Promise<{
        ig: string | null
        balance: number | null
        previousBalance: number | null
        gained: number | null
        searchPointsEarned: number | null
        searchPointsLimit: number | null
    }> {
        const cvid = opts?.cvid ?? randomBytes(16).toString('hex')
        const searchUrl = URLs.bing.search(query, cvid)
        const jar = this.getBingJar()

        const base = { ...(this.bot.fingerprint?.headers ?? {}) }
        delete base['Cookie']
        delete base['cookie']

        const empty = {
            ig: null,
            balance: null,
            previousBalance: null,
            searchPointsEarned: null,
            searchPointsLimit: null
        }

        const searchRes = await this.bot.http.request({
            url: searchUrl,
            method: 'GET',
            headers: {
                ...base,
                Cookie: this.jarToHeader(jar),
                Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'none',
                'Sec-Fetch-User': '?1',
                'Upgrade-Insecure-Requests': '1'
            }
        })
        this.mergeSetCookies(jar, searchRes.headers?.['set-cookie'] as string[] | string | undefined)

        const ig =
            typeof searchRes.data === 'string'
                ? ((searchRes.data.match(/\bIG:"([A-F0-9]{32})"/i) ??
                      searchRes.data.match(/[?&]IG=([A-F0-9]{32})\b/i))?.[1] ?? null)
                : null
        if (!ig) {
            this.bot.logger.warn(
                this.bot.isMobile,
                'SEARCH-REPORT',
                `查询 "${query}" 无 IG - SERP 未按预期返回`
            )
            return { ...empty, gained: null }
        }

        const params = new URLSearchParams({ IG: ig, IID: 'SERP.5064', q: query, FORM: 'ANNTA1', cvid, ajaxreq: '1' })
        // Credit the offer rather than only the daily search counter!
        const reportUrl = `${URLs.bing.origin}/rewardsapp/reportActivity?${params.toString()}${opts?.cg ? `&cg=${opts.cg}` : ''}`

        const reportRes = await this.bot.http.request({
            url: reportUrl,
            method: 'POST',
            headers: {
                ...base,
                Cookie: this.jarToHeader(jar),
                Accept: '*/*',
                'Content-Type': 'application/x-www-form-urlencoded',
                Referer: searchUrl,
                Origin: URLs.bing.origin,
                'Sec-Fetch-Dest': 'empty',
                'Sec-Fetch-Mode': 'cors',
                'Sec-Fetch-Site': 'same-origin',
                'X-Requested-With': 'XMLHttpRequest'
            },
            data: `url=${encodeURIComponent(searchUrl)}&V=web`
        })
        this.mergeSetCookies(jar, reportRes.headers?.['set-cookie'] as string[] | string | undefined)

        const parsed = this.parseReportResponse(reportRes.data)
        const gained =
            parsed.balance != null && parsed.previousBalance != null ? parsed.balance - parsed.previousBalance : null

        this.bot.logger.debug(
            this.bot.isMobile,
            'SEARCH-REPORT',
            `已上报 "${query}" | ig=${ig} | gained=${gained ?? 'n/a'} | balance=${parsed.balance ?? 'n/a'} | searchPts=${parsed.searchPointsEarned ?? 'n/a'}/${parsed.searchPointsLimit ?? 'n/a'}`
        )

        return { ig, ...parsed, gained }
    }

    private getBingJar(): Map<string, string> {
        const src = this.bot.isMobile ? this.bot.cookies.mobile : this.bot.cookies.desktop
        const key = `${src.find(c => c.name === '_U')?.value ?? ''}|${this.bot.isMobile}`
        let jar = this.bingJars.get(key)
        if (!jar) {
            jar = new Map<string, string>()
            for (const c of src) {
                const domain = c.domain.replace(/^\./, '')
                if (domain === 'bing.com' || domain.endsWith('.bing.com')) jar.set(c.name, c.value)
            }
            this.bingJars.set(key, jar)
        }
        return jar
    }

    private mergeSetCookies(jar: Map<string, string>, setCookie?: string[] | string): void {
        if (!setCookie) return
        for (const raw of Array.isArray(setCookie) ? setCookie : [setCookie]) {
            const pair = raw.split(';', 1)[0] ?? ''
            const eq = pair.indexOf('=')
            if (eq <= 0) continue
            const name = pair.slice(0, eq).trim()
            const value = pair.slice(eq + 1).trim()
            if (!name) continue
            if (value === '' || /expires=Thu,\s*01\s*Jan\s*1970/i.test(raw) || /\bmax-age=0\b/i.test(raw))
                jar.delete(name)
            else jar.set(name, value)
        }
    }

    private jarToHeader(jar: Map<string, string>): string {
        return [...jar.entries()].map(([n, v]) => `${n}=${v}`).join('; ')
    }

    private parseReportResponse(data: unknown): {
        balance: number | null
        previousBalance: number | null
        searchPointsEarned: number | null
        searchPointsLimit: number | null
    } {
        const empty = { balance: null, previousBalance: null, searchPointsEarned: null, searchPointsLimit: null }
        if (typeof data !== 'string') return empty
        const m = data.match(/ModernRewards\.ReportActivity\((\{[\s\S]*?\})\)\s*;/)
        if (!m) return empty
        try {
            const s = JSON.parse(m[1] ?? '{}').RewardsSessionData ?? {}
            const num = (v: unknown) => (typeof v === 'number' ? v : null)
            return {
                balance: num(s.Balance),
                previousBalance: num(s.PreviousBalance),
                searchPointsEarned: num(s.DailySearchPointsEarned),
                searchPointsLimit: num(s.DailySearchPointsLimit)
            }
        } catch {
            return empty
        }
    }
}
