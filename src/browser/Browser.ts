import rebrowser, { BrowserContext } from 'patchright'
import { newInjectedContext } from 'fingerprint-injector'
import { BrowserFingerprintWithHeaders, FingerprintGenerator } from 'fingerprint-generator'

import type { MicrosoftRewardsBot } from '../index'
import { loadSessionData, saveFingerprintData } from '../util/Load'
import { UserAgentManager } from './UserAgent'

import type { Account, AccountProxy } from '../interface/Account'

/* 测试相关
https://abrahamjuliot.github.io/creepjs/
https://botcheck.luminati.io/
https://fv.pro/
https://pixelscan.net/
https://www.browserscan.net/
*/

interface BrowserCreationResult {
    context: BrowserContext
    fingerprint: BrowserFingerprintWithHeaders
}

class Browser {
    private readonly bot: MicrosoftRewardsBot
    // 浏览器启动参数配置
    private static readonly BROWSER_ARGS = [
        '--no-sandbox', // 不使用沙盒模式
        '--mute-audio', // 静音
        '--disable-setuid-sandbox', // 禁用setuid沙盒
        '--ignore-certificate-errors', // 忽略证书错误
        '--ignore-certificate-errors-spki-list', // 忽略证书错误SPKI列表
        '--ignore-ssl-errors', // 忽略SSL错误
        '--no-first-run', // 不是首次运行
        '--no-default-browser-check', // 不检查默认浏览器
        '--disable-user-media-security=true', // 禁用用户媒体安全
        '--disable-blink-features=Attestation', // 禁用Blink特性认证
        '--disable-features=WebAuthentication,PasswordManagerOnboarding,PasswordManager,EnablePasswordsAccountStorage,Passkeys,WebAuthenticationProxy,U2F', // 禁用特定功能
        '--disable-save-password-bubble', // 禁用保存密码提示
        '--lang=zh-CN'

    ] as const

    constructor(bot: MicrosoftRewardsBot) {
        this.bot = bot
    }

    // 创建浏览器实例
    async createBrowser(account: Account): Promise<BrowserCreationResult> {
        let browser: rebrowser.Browser
        try {
            // 配置代理服务器
            const proxyConfig = account.proxy.url
                ? {
                      server: this.formatProxyServer(account.proxy),
                      ...(account.proxy.username &&
                          account.proxy.password && {
                              username: account.proxy.username,
                              password: account.proxy.password
                          })
                  }
                : undefined

            // 启动浏览器
            browser = await rebrowser.chromium.launch({
                headless: this.bot.config.headless, // 是否无头模式
                ...(proxyConfig && { proxy: proxyConfig }), // 代理配置
                args: [...Browser.BROWSER_ARGS] // 浏览器启动参数
            })
        } catch (error) {
            const errorMessage = error instanceof Error ? error.message : String(error)
            this.bot.logger.error(this.bot.isMobile, 'BROWSER', `启动失败: ${errorMessage}`)
            throw error
        }

        try {
            // 加载会话数据
            const sessionData = await loadSessionData(
                this.bot.config.sessionPath,
                account.email,
                account.saveFingerprint,
                this.bot.isMobile
            )

            // 获取或生成浏览器指纹
            const fingerprint = sessionData.fingerprint ?? (await this.generateFingerprint(this.bot.isMobile))
            // 创建带指纹的浏览器上下文
            const context = await newInjectedContext(browser as any, {
                fingerprint,
                newContextOptions: {
                    permissions: [],
                    ignoreHTTPSErrors: true
                }
            })

            // 添加初始化脚本以禁用WebAuthn
            await context.addInitScript(() => {
                Object.defineProperty(navigator, 'credentials', {
                    value: {
                        create: () => Promise.reject(new Error('WebAuthn disabled')),
                        get: () => Promise.reject(new Error('WebAuthn disabled'))
                    }
                })
            })

            // 设置默认超时时间
            context.setDefaultTimeout(this.bot.utils.stringToNumber(this.bot.config?.globalTimeout ?? 30000))

            // 添加保存的cookies
            await context.addCookies(sessionData.cookies)

            // 如果需要保存指纹数据
            if (
                (account.saveFingerprint.mobile && this.bot.isMobile) ||
                (account.saveFingerprint.desktop && !this.bot.isMobile)
            ) {
                await saveFingerprintData(this.bot.config.sessionPath, account.email, this.bot.isMobile, fingerprint)
            }

            // 记录浏览器创建信息
            this.bot.logger.info(
                this.bot.isMobile,
                'BROWSER',
                `创建浏览器，用户代理: "${fingerprint.fingerprint.navigator.userAgent}"`
            )
            this.bot.logger.debug(this.bot.isMobile, 'BROWSER-FINGERPRINT', JSON.stringify(fingerprint))

            return { context: context as unknown as BrowserContext, fingerprint }
        } catch (error) {
            await browser.close().catch(() => {}) // 出错时关闭浏览器
            throw error
        }
    }

    // 格式化代理服务器地址
    private formatProxyServer(proxy: AccountProxy): string {
        try {
            const urlObj = new URL(proxy.url)
            const protocol = urlObj.protocol.replace(':', '')
            return `${protocol}://${urlObj.hostname}:${proxy.port}`
        } catch {
            return `${proxy.url}:${proxy.port}`
        }
    }

    // 生成浏览器指纹
    async generateFingerprint(isMobile: boolean) {
        // 使用指纹生成器创建指纹数据
        const fingerPrintData = new FingerprintGenerator().getFingerprint({
            devices: isMobile ? ['mobile'] : ['desktop'], // 根据是否为移动端选择设备类型
            operatingSystems: isMobile ? ['android', 'ios'] : ['windows', 'linux'], // 根据是否为移动端选择操作系统
            browsers: [{ name: 'edge' }], // 使用Edge浏览器
            locales: ['zh-CN']
        })

        // 更新用户代理
        const userAgentManager = new UserAgentManager(this.bot)
        const updatedFingerPrintData = await userAgentManager.updateFingerprintUserAgent(fingerPrintData, isMobile)

        return updatedFingerPrintData
    }
}

export default Browser
