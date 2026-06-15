import type { Page } from 'patchright'
import { randomBytes } from 'crypto'
import { URLSearchParams } from 'url'

import type { MicrosoftRewardsBot } from '../../../index'

export class MobileAccessLogin {
    private clientId = '0000000040170455'
    private authUrl = 'https://login.live.com/oauth20_authorize.srf'
    private redirectUrl = 'https://login.live.com/oauth20_desktop.srf'
    private tokenUrl = 'https://login.microsoftonline.com/consumers/oauth2/v2.0/token'
    private scope = 'service::prod.rewardsplatform.microsoft.com::MBI_SSL'
    private maxTimeout = 180_000 // 3min

    // Selectors for handling Passkey prompt during OAuth
    private readonly selectors = {
        secondaryButton: 'button[data-testid="secondaryButton"]',
        passKeyError: '[data-testid="registrationImg"]',
        passKeyVideo: '[data-testid="biometricVideo"]'
    } as const

    constructor(
        private bot: MicrosoftRewardsBot,
        private page: Page
    ) {}

    private async checkSelector(selector: string): Promise<boolean> {
        return this.page
            .waitForSelector(selector, { state: 'visible', timeout: 200 })
            .then(() => true)
            .catch(() => false)
    }

    private async handlePasskeyPrompt(): Promise<void> {
        try {
            // Handle Passkey prompt - click secondary button to skip
            const hasPasskeyError = await this.checkSelector(this.selectors.passKeyError)
            const hasPasskeyVideo = await this.checkSelector(this.selectors.passKeyVideo)
            if (hasPasskeyError || hasPasskeyVideo) {
                this.bot.logger.info(this.bot.isMobile, 'LOGIN-APP', '在OAuth页面上发现Passkey提示，跳过')
                await this.bot.browser.utils.ghostClick(this.page, this.selectors.secondaryButton)
                await this.page.waitForLoadState('networkidle', { timeout: 5000 }).catch(() => {})
            }
        } catch {
            // 忽略提示处理中的错误
        }
    }

    async get(email: string): Promise<string> {
        try {
            const authorizeUrl = new URL(this.authUrl)
            authorizeUrl.searchParams.append('response_type', 'code')
            authorizeUrl.searchParams.append('client_id', this.clientId)
            authorizeUrl.searchParams.append('redirect_uri', this.redirectUrl)
            authorizeUrl.searchParams.append('scope', this.scope)
            authorizeUrl.searchParams.append('state', randomBytes(16).toString('hex'))
            authorizeUrl.searchParams.append('access_type', 'offline_access')
            authorizeUrl.searchParams.append('login_hint', email)

            this.bot.logger.debug(
                this.bot.isMobile,
                'LOGIN-APP',
                `认证URL构建完成: ${authorizeUrl.origin}${authorizeUrl.pathname}`
            )

            await this.bot.browser.utils.disableFido(this.page)

            this.bot.logger.debug(this.bot.isMobile, 'LOGIN-APP', '导航到OAuth授权URL')

            await this.page.goto(authorizeUrl.href).catch(err => {
                this.bot.logger.debug(
                    this.bot.isMobile,
                    'LOGIN-APP',
                    `page.goto() 失败: ${err instanceof Error ? err.message : String(err)}`
                )
            })

            this.bot.logger.info(this.bot.isMobile, 'LOGIN-APP', '等待移动OAuth代码...')

            const start = Date.now()
            let code = ''
            let lastUrl = ''

            while (Date.now() - start < this.maxTimeout) {
                const currentUrl = this.page.url()

                // 仅在URL更改时记录（高信号，无垃圾信息）
                if (currentUrl !== lastUrl) {
                    this.bot.logger.debug(this.bot.isMobile, 'LOGIN-APP', `OAuth轮询URL已更改 → ${currentUrl}`)
                    lastUrl = currentUrl
                }

                try {
                    const url = new URL(currentUrl)

                    if (url.hostname === 'login.live.com' && url.pathname === '/oauth20_desktop.srf') {
                        code = url.searchParams.get('code') || ''

                        if (code) {
                            this.bot.logger.debug(this.bot.isMobile, 'LOGIN-APP', '在重定向URL中检测到OAuth代码')
                            break
                        }
                    }

                    // 如果出现Passkey提示则处理
                    await this.handlePasskeyPrompt()
                } catch {
                    this.bot.logger.debug(
                        this.bot.isMobile,
                        'LOGIN-APP',
                        `轮询期间URL无效: ${String(currentUrl)}`
                    )
                }

                await this.bot.utils.wait(1000)
            }

            if (!code) {
                this.bot.logger.warn(
                    this.bot.isMobile,
                    'LOGIN-APP',
                    `等待OAuth代码超时，已等待 ${Math.round((Date.now() - start) / 1000)}秒`
                )

                this.bot.logger.debug(this.bot.isMobile, 'LOGIN-APP', `最终页面URL: ${this.page.url()}`)

                return ''
            }

            const data = new URLSearchParams()
            data.append('grant_type', 'authorization_code')
            data.append('client_id', this.clientId)
            data.append('code', code)
            data.append('redirect_uri', this.redirectUrl)

            this.bot.logger.debug(this.bot.isMobile, 'LOGIN-APP', '交换OAuth代码以获取访问令牌')

            const response = await this.bot.axios.request({
                url: this.tokenUrl,
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                data: data.toString()
            })

            const token = (response?.data?.access_token as string) ?? ''

            if (!token) {
                this.bot.logger.warn(this.bot.isMobile, 'LOGIN-APP', '令牌响应中没有access_token')
                this.bot.logger.debug(
                    this.bot.isMobile,
                    'LOGIN-APP',
                    `令牌响应负载: ${JSON.stringify(response?.data)}`
                )
                return ''
            }

            this.bot.logger.info(this.bot.isMobile, 'LOGIN-APP', '移动访问令牌已接收')
            return token
        } catch (error) {
            this.bot.logger.error(
                this.bot.isMobile,
                'LOGIN-APP',
                `MobileAccess错误: ${error instanceof Error ? error.stack || error.message : String(error)}`
            )
            return ''
        } finally {
            this.bot.logger.debug(this.bot.isMobile, 'LOGIN-APP', '返回基础URL')
            await this.page.goto(this.bot.config.baseURL, { timeout: 10000 }).catch(() => {})
        }
    }
}
