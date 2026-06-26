import type { BrowserContext, Cookie, Page } from 'patchright'
import type { AxiosRequestConfig } from 'axios'

import type { MicrosoftRewardsBot } from '../index'
import { saveSessionData } from '../util/Load'

import type { Counters, DashboardData } from './../interface/DashboardData'
import type { AppUserData } from '../interface/AppUserData'
import type { XboxDashboardData } from './../interface/XboxDashboardData'
import type { AppEarnablePoints, BrowserEarnablePoints, MissingSearchPoints } from '../interface/Points'
import type { AppDashboardData } from '../interface/AppDashBoardData'
import { PanelFlyoutData } from '../interface/PanelFlyoutData'

export default class BrowserFunc {
    private bot: MicrosoftRewardsBot

    /**
     * 新版 UI（modern dashboard）基于 Next.js App Router，业务操作走 Server Actions。
     * next-action hash 在编译时生成，绑定到具体部署版本（dpl）。
     * 下面是通过网络请求记录得到的当前部署版本的 hash 表；部署更新后 hash 会失效，由调用方做版本守卫。
     */
    // hash 抓录时的部署版本 ID（仅作日志对照参考；版本不匹配不再拦截调用，见 callServerAction）
    public static readonly SUPPORTED_DEPLOYMENT_ID = '20260624-3'

    // Server Action hash 表（在 SUPPORTED_DEPLOYMENT_ID 下记录得到）
    public static readonly SERVER_ACTION_HASHES = {
        // 连击保护 toggle：body=[true] 开启 / [false] 关闭
        toggleStreakProtection: '40eddd39784c87de1e9c077e72117f3ed9a016a2d2',
        // 领取积分：body=[]
        claimBonusPoints: '00cf5ba7699f0e920ffcff223f9e48fea78fd49784'
    } as const

    constructor(bot: MicrosoftRewardsBot) {
        this.bot = bot
    }

    /**
     * 获取用户桌面仪表板数据
     * @returns {DashboardData} 用户必应奖励仪表板数据对象
     */
    async getDashboardData(): Promise<DashboardData> {
        try {
            const request: AxiosRequestConfig = {
                url: 'https://rewards.bing.com/api/getuserinfo?type=1',
                method: 'GET',
                headers: {
                    ...(this.bot.fingerprint?.headers ?? {}),
                    Cookie: this.buildCookieHeader(this.bot.cookies.mobile, [
                        'bing.com',
                        'live.com',
                        'microsoftonline.com'
                    ]),
                    Referer: 'https://rewards.bing.com/',
                    Origin: 'https://rewards.bing.com'
                }
            }

            const response = await this.bot.axios.request(request)

            if (response.data?.dashboard) {
                return response.data.dashboard as DashboardData
            }
            throw new Error('Dashboard data missing from API response')
        } catch (error) {
            this.bot.logger.warn(this.bot.isMobile, 'GET-DASHBOARD-DATA', 'API失败，尝试HTML回退方案')

            // 尝试使用仪表板页面的脚本
            try {
                const request: AxiosRequestConfig = {
                    url: this.bot.config.baseURL,
                    method: 'GET',
                    headers: {
                        ...(this.bot.fingerprint?.headers ?? {}),
                        Cookie: this.buildCookieHeader(this.bot.cookies.mobile),
                        Referer: 'https://rewards.bing.com/',
                        Origin: 'https://rewards.bing.com'
                    }
                }

                const response = await this.bot.axios.request(request)
                const match = response.data.match(/var\s+dashboard\s*=\s*({.*?});/s)

                if (!match?.[1]) {
                    throw new Error('在HTML中未找到仪表板脚本')
                }

                return JSON.parse(match[1]) as DashboardData
            } catch (fallbackError) {
                // 如果两者都失败
                this.bot.logger.error(this.bot.isMobile, 'GET-DASHBOARD-DATA', '获取仪表板数据失败')
                throw fallbackError
            }
        }
    }

  /**
     * Fetch user panel flyout data
     * @returns {PanelFlyoutData} Object of user bing rewards dashboard data
     */
    async getPanelFlyoutData(): Promise<PanelFlyoutData> {
        try {
            const request: AxiosRequestConfig = {
                url: 'https://cn.bing.com/rewards/panelflyout/getuserinfo?channel=BingFlyout&partnerId=BingRewards',
                method: 'GET',
                headers: {
                    ...(this.bot.fingerprint?.headers ?? {}),
                    Cookie: this.buildCookieHeader(this.bot.cookies.mobile, [
                        'bing.com',
                        'live.com',
                        'microsoftonline.com'
                    ]),
                    Origin: 'https://cn.bing.com'
                }
            }

            const response = await this.bot.axios.request(request)
            return response.data as PanelFlyoutData
        } catch (error) {
            this.bot.logger.error(
                this.bot.isMobile,
                'GET-PANEL-FLYOUT-DATA',
                `获取面板数据出错: ${error instanceof Error ? error.message : String(error)}`
            )
            throw error
        }
    }

    /**
     * 获取用户应用仪表板数据
     * @returns {AppDashboardData} 用户必应奖励仪表板数据对象
     */
    async getAppDashboardData(): Promise<AppDashboardData> {
        try {
            const request: AxiosRequestConfig = {
                url: 'https://prod.rewardsplatform.microsoft.com/dapi/me?channel=SAIOS&options=613',
                method: 'GET',
                headers: {
                    Authorization: `Bearer ${this.bot.accessToken}`,
                    'User-Agent':
                        'Bing/32.5.431027001 (com.microsoft.bing; build:431027001; iOS 17.6.1) Alamofire/5.10.2'
                }
            }

            const response = await this.bot.axios.request(request)
            return response.data as AppDashboardData
        } catch (error) {
            this.bot.logger.error(
                this.bot.isMobile,
                'GET-APP-DASHBOARD-DATA',
                `获取仪表板数据出错: ${error instanceof Error ? error.message : String(error)}`
            )
            throw error
        }
    }

    /**
     * 获取用户xbox仪表板数据
     * @returns {XboxDashboardData} 用户必应奖励仪表板数据对象
     */
    async getXBoxDashboardData(): Promise<XboxDashboardData> {
        try {
            const request: AxiosRequestConfig = {
                url: 'https://prod.rewardsplatform.microsoft.com/dapi/me?channel=xboxapp&options=6',
                method: 'GET',
                headers: {
                    Authorization: `Bearer ${this.bot.accessToken}`,
                    'User-Agent':
                        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; Xbox; Xbox One X) AppleWebKit/537.36 (KHTML, like Gecko) Edge/18.19041'
                }
            }

            const response = await this.bot.axios.request(request)
            return response.data as XboxDashboardData
        } catch (error) {
            this.bot.logger.error(
                this.bot.isMobile,
                'GET-XBOX-DASHBOARD-DATA',
                `获取仪表板数据出错: ${error instanceof Error ? error.message : String(error)}`
            )
            throw error
        }
    }

    /**
     * 获取搜索积分计数器
     */
    async getSearchPoints(): Promise<Counters> {
        const dashboardData = await this.getDashboardData() // 始终获取最新数据

        return dashboardData.userStatus.counters
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

    /**
     * 获取通过网页浏览器可赚取的总积分
     */
    async getBrowserEarnablePoints(): Promise<BrowserEarnablePoints> {
        try {
            const data = await this.getDashboardData()

            const desktopSearchPoints =
                data.userStatus.counters.pcSearch?.reduce(
                    (sum, x) => sum + (x.pointProgressMax - x.pointProgress),
                    0
                ) ?? 0

            const mobileSearchPoints =
                data.userStatus.counters.mobileSearch?.reduce(
                    (sum, x) => sum + (x.pointProgressMax - x.pointProgress),
                    0
                ) ?? 0

            const todayDate = this.bot.utils.getFormattedDate()
            const dailySetPoints =
                data.dailySetPromotions[todayDate]?.reduce(
                    (sum, x) => sum + (x.pointProgressMax - x.pointProgress),
                    0
                ) ?? 0

            const morePromotionsPoints =
                data.morePromotions?.reduce((sum, x) => {
                    if (
                        ['quiz', 'urlreward'].includes(x.promotionType) &&
                        x.exclusiveLockedFeatureStatus !== 'locked'
                    ) {
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

    /**
     * 获取通过移动应用可赚取的总积分
     */
    async getAppEarnablePoints(): Promise<AppEarnablePoints> {
        try {
            const eligibleOffers = ['ENUS_readarticle3_30points', 'Gamification_Sapphire_DailyCheckIn']

            const request: AxiosRequestConfig = {
                url: 'https://prod.rewardsplatform.microsoft.com/dapi/me?channel=SAAndroid&options=613',
                method: 'GET',
                headers: {
                    Authorization: `Bearer ${this.bot.accessToken}`,
                    'X-Rewards-Country': this.bot.userData.geoLocale,
                    'X-Rewards-Language': 'zh-CN',
                    'X-Rewards-ismobile': 'true'
                }
            }

            const response = await this.bot.axios.request(request)
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
    /**
     * 获取当前积分金额
     * @returns {number} 当前总积分金额
     */
    async getCurrentPoints(): Promise<number> {
        try {
            const data = await this.getDashboardData()

            return data.userStatus.availablePoints
        } catch (error) {
            this.bot.logger.error(
                this.bot.isMobile,
                'GET-CURRENT-POINTS',
                `发生错误: ${error instanceof Error ? error.message : String(error)}`
            )
            throw error
        }
    }

    /**
     * 从 dashboard 页面提取 Next.js 部署版本 ID（dpl）。
     * 仅用于日志对照：SUPPORTED_DEPLOYMENT_ID 是抓录时的版本，部署更新后 dpl 会变，
     * 但 Server Action hash 通常不变（微软重新部署≠改了函数）。因此不匹配时不拦截，
     * 只打 warning 提示 hash 可能失效；真正能否调用由 callServerAction 用 HTTP 状态码判定。
     * 仅在提取不到任何 dpl 时返回 null。
     */
    async extractDeploymentId(page: Page): Promise<string | null> {
        try {
            // 优先用页面 DOM 提取（已加载时）
            let html: string | null = null
            try {
                html = await page.content()
            } catch {
                html = null
            }

            // DOM 没拿到时用 axios 直接请求页面
            if (!html) {
                const request: AxiosRequestConfig = {
                    url: 'https://rewards.bing.com/dashboard',
                    method: 'GET',
                    headers: {
                        ...(this.bot.fingerprint?.headers ?? {}),
                        Cookie: this.buildCookieHeader(this.bot.cookies.mobile, [
                            'bing.com',
                            'live.com',
                            'microsoftonline.com'
                        ]),
                        Referer: 'https://rewards.bing.com/'
                    }
                }
                const response = await this.bot.axios.request(request)
                html = typeof response.data === 'string' ? response.data : String(response.data)
            }

            // 从 script src 里提取 dpl（如 ...?dpl=20260612-3）
            const match = html.match(/dpl=([0-9]+-[0-9]+)/)
            const deploymentId = match?.[1] ?? null

            if (!deploymentId) {
                this.bot.logger.warn(
                    this.bot.isMobile,
                    'SERVER-ACTION',
                    '未能从 dashboard 页面提取部署 ID，新版 Server Action 功能将跳过'
                )
                return null
            }

            if (deploymentId !== BrowserFunc.SUPPORTED_DEPLOYMENT_ID) {
                this.bot.logger.warn(
                    this.bot.isMobile,
                    'SERVER-ACTION',
                    `部署版本不匹配 | 当前=${deploymentId} | 支持=${BrowserFunc.SUPPORTED_DEPLOYMENT_ID} | ` +
                        '微软可能更新了 dashboard，内置的 Server Action hash 可能已失效；将照常尝试，若返回非 2xx 则自动降级'
                )
            }

            return deploymentId
        } catch (error) {
            this.bot.logger.warn(
                this.bot.isMobile,
                'SERVER-ACTION',
                `提取部署 ID 失败: ${error instanceof Error ? error.message : String(error)}`
            )
            return null
        }
    }

    /**
     * 调用新版 dashboard 的 Next.js Server Action。
     * 认证靠 Cookie（无需 requestToken / accessToken），返回的响应是 RSC 流，只看 HTTP 状态码判断成功。
     *
     * @param actionName SERVER_ACTION_HASHES 中的键名
     * @param args Server Action 参数数组（如 [true] 开启连击保护；[] 无参数领积分）
     * @param tag 日志标签
     * @returns 成功返回 true，失败/降级返回 false
     */
    async callServerAction(
        actionName: keyof typeof BrowserFunc.SERVER_ACTION_HASHES,
        args: unknown[],
        tag: string
    ): Promise<boolean> {
        // 版本守卫：仅当完全没提取到部署 ID（dashboard 没加载/解析失败）时跳过；
        // 版本号不匹配时不再拦截——hash 通常不随部署变更，照常发请求，靠响应码判定成败。
        if (!this.bot.serverActions.deploymentId) {
            this.bot.logger.warn(
                this.bot.isMobile,
                tag,
                '跳过：未提取到部署 ID（dashboard 未加载或解析失败），Server Action 无法调用'
            )
            return false
        }

        const actionHash = BrowserFunc.SERVER_ACTION_HASHES[actionName]

        try {
            const request: AxiosRequestConfig = {
                url: 'https://rewards.bing.com/dashboard',
                method: 'POST',
                headers: {
                    Accept: 'text/x-component',
                    'Content-Type': 'text/plain;charset=UTF-8',
                    'next-action': actionHash,
                    // next-router-state-tree 是 Next.js App Router 内部状态，服务端用于路由匹配
                    // 这里传一个最小化的 dashboard 路由树（通过请求分析得到的结构）
                    'next-router-state-tree':
                        '%5B%22%22%2C%7B%22children%22%3A%5B%22(nav)%22%2C%7B%22children%22%3A%5B%22dashboard%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%2Cnull%2Cnull%2C0%5D%7D%2Cnull%2Cnull%2C0%5D%7D%2Cnull%2Cnull%2C0%5D%7D%2Cnull%2Cnull%2C16%5D',
                    'x-deployment-id': this.bot.serverActions.deploymentId,
                    Referer: 'https://rewards.bing.com/dashboard',
                    Cookie: this.buildCookieHeader(this.bot.cookies.mobile, [
                        'bing.com',
                        'live.com',
                        'microsoftonline.com'
                    ])
                },
                // Server Action 参数序列化为 JSON 数组字符串
                data: JSON.stringify(args)
            }

            this.bot.logger.debug(
                this.bot.isMobile,
                tag,
                `发送 Server Action 请求 | action=${actionName} | hash=${actionHash} | args=${JSON.stringify(args)}`
            )

            const response = await this.bot.axios.request(request)

            this.bot.logger.debug(
                this.bot.isMobile,
                tag,
                `收到 Server Action 响应 | action=${actionName} | 状态=${response.status}`
            )

            if (response.status >= 200 && response.status < 300) {
                return true
            }

            this.bot.logger.warn(
                this.bot.isMobile,
                tag,
                `Server Action 失败 | action=${actionName} | 状态=${response.status}`
            )
            return false
        } catch (error) {
            this.bot.logger.error(
                this.bot.isMobile,
                tag,
                `Server Action 出错 | action=${actionName} | 消息=${error instanceof Error ? error.message : String(error)}`
            )
            return false
        }
    }

    async closeBrowser(browser: BrowserContext, email: string) {
        const rootBrowser = (browser as any).browser?.() || null

        try {
            // Try to save cookies
            const cookies = await browser.cookies()
            this.bot.logger.debug(this.bot.isMobile, 'CLOSE-BROWSER', `Saving ${cookies.length} cookies.`)
            await saveSessionData(this.bot.config.sessionPath, cookies, email, this.bot.isMobile)

            await this.bot.utils.wait(2000)
        } catch (error) {
            this.bot.logger.error(this.bot.isMobile, 'CLOSE-BROWSER', `保存会话失败: ${error}`)
        } finally {
            try {
                await browser.close()

                if (rootBrowser) {
                    await rootBrowser.close().catch(() => {})
                }

                this.bot.logger.info(this.bot.isMobile, 'CLOSE-BROWSER', '浏览器已干净地关闭！')
            } catch (closeError) {
                this.bot.logger.warn(
                    this.bot.isMobile,
                    'CLOSE-BROWSER',
                    '关闭时遇到错误，但进程正在退出。'
                )
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
}
