import { AsyncLocalStorage } from 'node:async_hooks'
import cluster, { Worker } from 'cluster'
import type { BrowserContext, Cookie, Page } from 'patchright'
import pkg from '../package.json'

import type { BrowserFingerprintWithHeaders } from 'fingerprint-generator'

import Browser from './browser/Browser'
import BrowserFunc from './browser/BrowserFunc'
import BrowserUtils from './browser/BrowserUtils'
import ReactFunc from './browser/ReactFunc'
import type { PageSnapshot } from './browser/ReactFunc'

import { IpcLog, Logger } from './logging/Logger'
import Utils, { isBrowserClosedError } from './util/Utils'
import { loadAccounts, loadConfig } from './util/Load'
import { closeSessionStore } from './util/SessionStore'
import { checkNodeVersion } from './util/Validator'

import { Login } from './browser/auth/Login'
import { Workers } from './functions/Workers'
import Activities from './functions/Activities'
import { SearchManager } from './functions/SearchManager'
import { PunchcardManager } from './functions/PunchcardManager'

import type { Account } from './interface/Account'
import HttpClient from './util/Http'
import { sendDiscord, flushDiscordQueue } from './logging/Discord'
import { sendNtfy, flushNtfyQueue } from './logging/Ntfy'
import { sendPushPlus, flushPushPlusQueue } from './logging/PushPlus'
import type { DashboardData } from './interface/DashboardData'
import type { AppDashboardData } from './interface/AppDashBoardData'

interface ExecutionContext {
    isMobile: boolean
    account: Account
}

interface BrowserSession {
    context: BrowserContext
    fingerprint: BrowserFingerprintWithHeaders
}

interface AccountStats {
    email: string
    initialPoints: number
    finalPoints: number
    collectedPoints: number
    duration: number
    success: boolean
    error?: string
}

const executionContext = new AsyncLocalStorage<ExecutionContext>()

export function getCurrentContext(): ExecutionContext {
    const context = executionContext.getStore()
    if (!context) {
        return { isMobile: false, account: {} as Account }
    }
    return context
}

async function flushAllWebhooks(timeoutMs = 5000): Promise<void> {
    await Promise.allSettled([
        flushDiscordQueue(timeoutMs),
        flushNtfyQueue(timeoutMs),
        flushPushPlusQueue(timeoutMs)
    ])
    closeSessionStore()
}

interface UserData {
    userName: string
    geoLocale: string
    langCode: string
    timezoneOffset: string
    initialPoints: number
    currentPoints: number
    gainedPoints: number
}

export class MicrosoftRewardsBot {
    public logger: Logger
    public config
    public utils: Utils
    public activities: Activities = new Activities(this)
    public browser: { func: BrowserFunc; utils: BrowserUtils; react: ReactFunc }

    public mainMobilePage!: Page
    public mainDesktopPage!: Page

    public userData: UserData

    public nextActions: Record<string, string> = {}
    public nextRouterStateTree = ''
    public reactSnapshot: PageSnapshot | null = null

    public accessToken = ''
    public cookies: { mobile: Cookie[]; desktop: Cookie[] }
    private fingerprintMobile?: BrowserFingerprintWithHeaders
    private fingerprintDesktop?: BrowserFingerprintWithHeaders

    get fingerprint(): BrowserFingerprintWithHeaders {
        const ctx = this.isMobile ? this.fingerprintMobile : this.fingerprintDesktop
        return (ctx ?? this.fingerprintMobile ?? this.fingerprintDesktop) as BrowserFingerprintWithHeaders
    }

    private activeWorkers: number
    private exitedWorkers: number[]
    private browserFactory: Browser = new Browser(this)
    private accounts: Account[]
    public workers: Workers
    private searchManager: SearchManager
    private punchcardManager: PunchcardManager
    private login = new Login(this)

    public http!: HttpClient

    constructor() {
        this.userData = {
            userName: '',
            geoLocale: 'US',
            langCode: 'en',
            timezoneOffset: '60',
            initialPoints: 0,
            currentPoints: 0,
            gainedPoints: 0
        }
        this.logger = new Logger(this)
        this.accounts = []
        this.cookies = { mobile: [], desktop: [] }
        this.utils = new Utils()
        this.workers = new Workers(this)
        this.searchManager = new SearchManager(this)
        this.punchcardManager = new PunchcardManager(this)
        this.browser = {
            func: new BrowserFunc(this),
            utils: new BrowserUtils(this),
            react: new ReactFunc(this)
        }
        this.config = loadConfig()
        this.activeWorkers = this.config.clusters
        this.exitedWorkers = []
    }

    get isMobile(): boolean {
        return getCurrentContext().isMobile
    }

    // 构建 PushPlus 每日积分摘要文本
    private buildSummaryMessage(accountStats: AccountStats[], runStartTime: number, hadWorkerFailure: boolean): string {
        const totalCollectedPoints = accountStats.reduce((sum, s) => sum + s.collectedPoints, 0)
        const totalInitialPoints = accountStats.reduce((sum, s) => sum + s.initialPoints, 0)
        const totalFinalPoints = accountStats.reduce((sum, s) => sum + s.finalPoints, 0)
        const totalDurationMinutes = ((Date.now() - runStartTime) / 1000 / 60).toFixed(1)
        const timestamp = new Date().toISOString().replace('T', ' ').slice(0, 19)

        const lines: string[] = [
            `每日积分摘要 | ${timestamp}`,
            `状态: ${hadWorkerFailure ? '异常' : '完成'}`,
            `账户数: ${accountStats.length}`,
            `总收集积分: +${totalCollectedPoints}`,
            `原始总计: ${totalInitialPoints} → 新总计: ${totalFinalPoints}`,
            `总运行时间: ${totalDurationMinutes}分钟`
        ]

        if (accountStats.length > 0) {
            lines.push('')
            lines.push('账户明细:')
            for (const stat of accountStats) {
                const status = stat.success ? '成功' : '失败'
                const duration = Number.isFinite(stat.duration) ? stat.duration.toFixed(1) : String(stat.duration)
                const error = stat.error ? ` | ${stat.error}` : ''
                lines.push(
                    `${stat.email} | +${stat.collectedPoints} | ${stat.initialPoints}→${stat.finalPoints} | ${duration}秒 | ${status}${error}`
                )
            }
        }

        return lines.join('\n')
    }

    // 发送 PushPlus 摘要（仅当配置启用时）
    private async sendPushPlusSummary(
        accountStats: AccountStats[],
        runStartTime: number,
        hadWorkerFailure: boolean
    ): Promise<void> {
        const pushplus = this.config?.webhook?.pushplus
        if (!pushplus?.enabled || !pushplus.token) {
            return
        }

        const content = this.buildSummaryMessage(accountStats, runStartTime, hadWorkerFailure)
        await sendPushPlus(pushplus, content)
    }

    async initialize(): Promise<void> {
        this.accounts = loadAccounts()
        this.warnExperimental()
    }

    // Move to utils
    private warnExperimental(): void {
        const exp = this.config.experimental
        const enabled = [exp.apiSearch && 'apiSearch', exp.apiSearchOnBing && 'apiSearchOnBing'].filter(
            Boolean
        ) as string[]
        if (!enabled.length) return

        this.logger.warn(
            'main',
            'EXPERIMENTAL',
            `${enabled.join(' + ')} 已启用 - 这些通过 HTTP 执行搜索，没有真实浏览器。` +
                `此路径是实验性的且不安全，可能导致您的账户被标记或封禁。` +
                `如果不确定，请在 config.experimental 下禁用。`,
            'redBright'
        )
    }

    async run(): Promise<void> {
        const totalAccounts = this.accounts.length
        const runStartTime = Date.now()

        this.logger.info(
            'main',
            'RUN-START',
            `启动 Microsoft Rewards 脚本 | v${pkg.version} | 账户数: ${totalAccounts} | 集群数: ${this.config.clusters}`
        )

        if (this.config.clusters > 1) {
            if (cluster.isPrimary) {
                await this.runMaster(runStartTime)
            } else {
                this.runWorker(runStartTime)
            }
        } else {
            await this.runTasks(this.accounts, runStartTime)
        }
    }

    private async runMaster(runStartTime: number): Promise<void> {
        void this.logger.info('main', 'CLUSTER-PRIMARY', `主进程已启动 | PID: ${process.pid}`)

        const rawChunks = this.utils.chunkArray(this.accounts, this.config.clusters)
        const accountChunks = rawChunks.filter(c => c && c.length > 0)
        this.activeWorkers = accountChunks.length

        const allAccountStats: AccountStats[] = []
        let hadWorkerFailure = false

        for (const chunk of accountChunks) {
            const worker = cluster.fork()
            worker.send?.({ chunk, runStartTime })

            worker.on('message', (msg: { __ipcLog?: IpcLog; __stats?: AccountStats[] }) => {
                if (msg.__stats) {
                    allAccountStats.push(...msg.__stats)
                }

                const log = msg.__ipcLog
                if (log && typeof log.content === 'string') {
                    const { webhook } = this.config
                    const { content, level } = log

                    if (webhook.discord?.enabled && webhook.discord.url) {
                        sendDiscord(webhook.discord.url, content, level)
                    }
                    if (webhook.ntfy?.enabled && webhook.ntfy.url) {
                        sendNtfy(webhook.ntfy, content, level)
                    }
                }
            })

            // Startup delay for clusters due to resource usage
            if (accountChunks.indexOf(chunk) !== accountChunks.length - 1) {
                await this.utils.wait(5000)
            }
        }

        const onWorkerExit = async (worker: Worker, code?: number, signal?: string): Promise<void> => {
            const { pid } = worker.process

            if (!pid || this.exitedWorkers.includes(pid)) {
                return
            }

            this.exitedWorkers.push(pid)
            this.activeWorkers -= 1

            const failed = (code ?? 0) !== 0 || Boolean(signal)
            if (failed) {
                hadWorkerFailure = true
            }

            this.logger.warn(
                'main',
                'CLUSTER-WORKER-EXIT',
                `工作进程 ${pid} 退出 | 代码: ${code ?? 'n/a'} | 信号: ${signal ?? 'n/a'} | 活动工作进程数: ${this.activeWorkers}`
            )

            if (this.activeWorkers <= 0) {
                const totalCollectedPoints = allAccountStats.reduce((sum, s) => sum + s.collectedPoints, 0)
                const totalInitialPoints = allAccountStats.reduce((sum, s) => sum + s.initialPoints, 0)
                const totalFinalPoints = allAccountStats.reduce((sum, s) => sum + s.finalPoints, 0)
                const totalDurationMinutes = ((Date.now() - runStartTime) / 1000 / 60).toFixed(1)

                this.logger.info(
                    'main',
                    'RUN-END',
                    `所有账户处理完成 | 处理账户数: ${allAccountStats.length} | 总收集积分: +${totalCollectedPoints} | 原始总计: ${totalInitialPoints} → 新总计: ${totalFinalPoints} | 总运行时间: ${totalDurationMinutes}分钟`,
                    'green'
                )

                await this.sendPushPlusSummary(allAccountStats, runStartTime, hadWorkerFailure)
                await flushAllWebhooks()

                process.exit(hadWorkerFailure ? 1 : 0)
            }
        }

        cluster.on('exit', (worker, code, signal) => {
            void onWorkerExit(worker, code ?? undefined, signal ?? undefined)
        })

        cluster.on('disconnect', worker => {
            const pid = worker.process?.pid
            this.logger.warn('main', 'CLUSTER-WORKER-DISCONNECT', `工作进程 ${pid ?? '?'} 已断开连接`)
        })
    }

    private runWorker(runStartTimeFromMaster?: number): void {
        void this.logger.info('main', 'CLUSTER-WORKER-START', `工作进程已启动 | PID: ${process.pid}`)

        process.on('message', async ({ chunk, runStartTime }: { chunk: Account[]; runStartTime: number }) => {
            void this.logger.info(
                'main',
                'CLUSTER-WORKER-TASK',
                `工作进程 ${process.pid} 接收到 ${chunk.length} 个账户。`
            )

            try {
                const stats = await this.runTasks(chunk, runStartTime ?? runStartTimeFromMaster ?? Date.now())

                if (process.send) {
                    process.send({ __stats: stats })
                }

                await flushAllWebhooks()
                process.exit(0)
            } catch (error) {
                this.logger.error(
                    'main',
                    'CLUSTER-WORKER-ERROR',
                    `工作进程任务崩溃: ${error instanceof Error ? error.message : String(error)}`
                )

                await flushAllWebhooks()
                process.exit(1)
            }
        })
    }

    private async runTasks(accounts: Account[], runStartTime: number): Promise<AccountStats[]> {
        const accountStats: AccountStats[] = []

        for (const account of accounts) {
            const accountStartTime = Date.now()
            const accountEmail = account.email
            this.userData.userName = this.utils.getEmailUsername(accountEmail)
            this.userData.timezoneOffset = String(new Date().getTimezoneOffset())
            this.userData.langCode = account.langCode ?? 'en'

            try {
                this.logger.info(
                    'main',
                    'ACCOUNT-START',
                    `开始处理账户: ${accountEmail} | geoLocale: ${account.geoLocale}`
                )

                this.http = new HttpClient(account.proxy)

                const result: { initialPoints: number; collectedPoints: number } | undefined = await this.Main(
                    account
                ).catch(error => {
                    void this.logger.error(
                        true,
                        'FLOW',
                        `${accountEmail} 的移动端流程失败: ${error instanceof Error ? error.message : String(error)}`
                    )
                    return undefined
                })

                const durationSeconds = ((Date.now() - accountStartTime) / 1000).toFixed(1)

                if (result) {
                    const collectedPoints = result.collectedPoints ?? 0
                    const accountInitialPoints = result.initialPoints ?? 0
                    const accountFinalPoints = accountInitialPoints + collectedPoints

                    accountStats.push({
                        email: accountEmail,
                        initialPoints: accountInitialPoints,
                        finalPoints: accountFinalPoints,
                        collectedPoints: collectedPoints,
                        duration: parseFloat(durationSeconds),
                        success: true
                    })

                    this.logger.info(
                        'main',
                        'ACCOUNT-END',
                        `账户处理完成: ${accountEmail} | 总计: +${collectedPoints} | 原始: ${accountInitialPoints} → 新: ${accountFinalPoints} | 用时: ${durationSeconds}秒`,
                        'green'
                    )
                } else {
                    accountStats.push({
                        email: accountEmail,
                        initialPoints: 0,
                        finalPoints: 0,
                        collectedPoints: 0,
                        duration: parseFloat(durationSeconds),
                        success: false,
                        error: 'Flow failed'
                    })
                }
            } catch (error) {
                const durationSeconds = ((Date.now() - accountStartTime) / 1000).toFixed(1)
                this.logger.error(
                    'main',
                    'ACCOUNT-ERROR',
                    `账户处理出错 ${accountEmail}: ${error instanceof Error ? error.message : String(error)}`
                )

                accountStats.push({
                    email: accountEmail,
                    initialPoints: 0,
                    finalPoints: 0,
                    collectedPoints: 0,
                    duration: parseFloat(durationSeconds),
                    success: false,
                    error: error instanceof Error ? error.message : String(error)
                })
            }
        }

        if (this.config.clusters <= 1 && cluster.isPrimary) {
            const totalCollectedPoints = accountStats.reduce((sum, s) => sum + s.collectedPoints, 0)
            const totalInitialPoints = accountStats.reduce((sum, s) => sum + s.initialPoints, 0)
            const totalFinalPoints = accountStats.reduce((sum, s) => sum + s.finalPoints, 0)
            const totalDurationMinutes = ((Date.now() - runStartTime) / 1000 / 60).toFixed(1)

            this.logger.info(
                'main',
                'RUN-END',
                `所有账户处理完成 | 处理账户数: ${accountStats.length} | 总收集积分: +${totalCollectedPoints} | 原始总计: ${totalInitialPoints} → 新总计: ${totalFinalPoints} | 总运行时间: ${totalDurationMinutes}分钟`,
                'green'
            )

            const hadFailure = accountStats.some(s => !s.success)
            await this.sendPushPlusSummary(accountStats, runStartTime, hadFailure)
            await flushAllWebhooks()
            process.exit(0)
        }

        return accountStats
    }

    async createDesktopSession(account: Account): Promise<BrowserSession> {
        const session = await this.browserFactory.createBrowser(account)
        this.mainDesktopPage = await session.context.newPage()
        this.fingerprintDesktop = session.fingerprint

        this.logger.info(this.isMobile, 'BROWSER', `桌面浏览器已启动 | ${account.email}`)

        await this.login.login(this.mainDesktopPage, account)
        this.cookies.desktop = await session.context.cookies()

        return session
    }

    async Main(account: Account): Promise<{ initialPoints: number; collectedPoints: number }> {
        const accountEmail = account.email
        this.logger.info('main', 'FLOW', `开始会话: ${accountEmail}`)

        let mobileSession: BrowserSession | null = null
        let mobileContextClosed = false

        try {
            return await executionContext.run({ isMobile: true, account }, async () => {
                mobileSession = await this.browserFactory.createBrowser(account)
                const initialContext: BrowserContext = mobileSession.context
                this.mainMobilePage = await initialContext.newPage()

                this.logger.info('main', 'BROWSER', `移动端浏览器已启动 | ${accountEmail}`)

                await this.login.login(this.mainMobilePage, account)

                try {
                    this.accessToken = await this.login.getAppAccessToken(this.mainMobilePage, accountEmail)
                } catch (error) {
                    this.logger.error(
                        'main',
                        'FLOW',
                        `获取移动端访问令牌失败: ${error instanceof Error ? error.message : String(error)}`
                    )
                }

                this.cookies.mobile = await initialContext.cookies()
                this.fingerprintMobile = mobileSession.fingerprint

                const data: DashboardData = await this.browser.func.getDashboardData()
                const appData: AppDashboardData = await this.browser.func.getAppDashboardData()
                void appData

                this.userData.geoLocale =
                    account.geoLocale === 'auto'
                        ? data.dashboard.userProfile.attributes.country
                        : account.geoLocale.toLowerCase()
                if (this.userData.geoLocale.length > 2) {
                    this.logger.warn(
                        'main',
                        'GEO-LOCALE',
                        `提供的 geoLocale 长度超过 2 (${this.userData.geoLocale} | auto=${account.geoLocale === 'auto'})，这很可能是无效的，可能导致错误！`
                    )
                }

                this.userData.initialPoints = data.dashboard.userStatus.availablePoints
                this.userData.currentPoints = data.dashboard.userStatus.availablePoints
                const initialPoints = this.userData.initialPoints ?? 0

                const browserEarnable = await this.browser.func.getBrowserEarnablePoints()
                const appEarnable = await this.browser.func.getAppEarnablePoints()

                const pointsCanCollect = browserEarnable.mobileSearchPoints + (appEarnable?.totalEarnablePoints ?? 0)

                this.logger.info(
                    'main',
                    'POINTS',
                `今日可获积分 | 移动端: ${pointsCanCollect} | 浏览器: ${
                    browserEarnable.mobileSearchPoints
                } | 应用: ${appEarnable?.totalEarnablePoints ?? 0} | ${accountEmail} | 区域: ${this.userData.geoLocale}`
                )

                if (this.config.ensureStreakProtection) {
                    await this.activities.doEnsureStreakProtection()
                }
                if (this.config.workers.doDailySet) await this.workers.doDailySet(data)
                if (this.config.workers.doActivateSearchPerk) await this.activities.doActivateSearchPerk(data)
                if (this.config.workers.doMorePromotions) await this.workers.doMorePromotions(data)
                if (this.config.workers.doDailyCheckIn) await this.activities.doDailyCheckIn()
                if (this.config.workers.doAppPromotions) await this.workers.doAppPromotions(appData)
                if (this.config.workers.doReadToEarn) await this.activities.doReadToEarn()
                if (this.config.workers.doPunchCards) await this.punchcardManager.run(account, data)

                if (this.config.workers.doMobileSearch || this.config.workers.doDesktopSearch) {
                    await this.searchManager.doSearches(account)
                }

                // Bonus farming is its own pass that runs AFTER the normal searches
                if (this.config.workers.doBonusSearches) {
                    await this.searchManager.doBonusSearches(account)
                }

                // Do this last due to random bonus points from searching
                if (this.config.workers.doClaimBonusPoints) await this.workers.doClaimBonusPoints(data)

                this.cookies.mobile = await initialContext.cookies()

                await this.browser.func.closeBrowser(initialContext, accountEmail)
                mobileContextClosed = true

                const finalPoints = await this.browser.func.getCurrentPoints()
                const collectedPoints = finalPoints - initialPoints

                this.logger.info('main', 'FLOW', `已收集: +${collectedPoints} | ${accountEmail}`)

                return {
                    initialPoints,
                    collectedPoints: collectedPoints || 0
                }
            })
        } finally {
            if (mobileSession && !mobileContextClosed) {
                try {
                    await executionContext.run({ isMobile: true, account }, async () => {
                        await this.browser.func.closeBrowser(mobileSession!.context, accountEmail)
                    })
                } catch (error) {
                    this.logger.debug(
                        'main',
                        'CLEANUP',
                        `移动端上下文关闭失败 | ${error instanceof Error ? error.message : String(error)}`
                    )
                }
            }
        }
    }
}

export { executionContext }

async function main(): Promise<void> {
    checkNodeVersion()
    const rewardsBot = new MicrosoftRewardsBot()

    process.on('beforeExit', () => {
        void flushAllWebhooks()
    })
    process.on('SIGINT', async () => {
        rewardsBot.logger.warn('main', 'PROCESS', '收到 SIGINT 信号，正在刷新并退出...')
        await flushAllWebhooks()
        process.exit(130)
    })
    process.on('SIGTERM', async () => {
        rewardsBot.logger.warn('main', 'PROCESS', '收到 SIGTERM 信号，正在刷新并退出...')
        await flushAllWebhooks()
        process.exit(143)
    })
    process.on('uncaughtException', async error => {
        if (isBrowserClosedError(error)) {
            rewardsBot.logger.debug(
                'main',
                'UNCAUGHT-EXCEPTION',
                `忽略销毁过程中的良性浏览器关闭错误 | ${error instanceof Error ? error.message : String(error)}`
            )
            return
        }
        rewardsBot.logger.error('main', 'UNCAUGHT-EXCEPTION', error)
        await flushAllWebhooks()
        process.exit(1)
    })
    process.on('unhandledRejection', async reason => {
        if (isBrowserClosedError(reason)) {
            rewardsBot.logger.debug(
                'main',
                'UNHANDLED-REJECTION',
                `忽略销毁过程中的良性浏览器关闭拒绝 | ${reason instanceof Error ? reason.message : String(reason)}`
            )
            return
        }
        rewardsBot.logger.error('main', 'UNHANDLED-REJECTION', reason as Error)
        await flushAllWebhooks()
        process.exit(1)
    })

    try {
        await rewardsBot.initialize()
        await rewardsBot.run()
    } catch (error) {
        rewardsBot.logger.error('main', 'MAIN-ERROR', error as Error)
    }
}

main().catch(async error => {
    const tmpBot = new MicrosoftRewardsBot()
    tmpBot.logger.error('main', 'MAIN-ERROR', error as Error)
    await flushAllWebhooks()
    process.exit(1)
})
