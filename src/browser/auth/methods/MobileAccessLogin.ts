import { URLs } from '../../../constants/urls'
import type { Page } from 'patchright'
import { randomBytes } from 'crypto'
import { URLSearchParams } from 'url'

import type { MicrosoftRewardsBot } from '../../../index'

export class MobileAccessLogin {
    private clientId = '0000000040170455'
    private authUrl = URLs.auth.oauthAuthorize
    private redirectUrl = URLs.auth.oauthRedirect
    private tokenUrl = URLs.auth.oauthToken
    private scope = 'service::prod.rewardsplatform.microsoft.com::MBI_SSL'

    constructor(
        private bot: MicrosoftRewardsBot,
        private page: Page
    ) {}

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
                `已构造认证 URL: ${authorizeUrl.origin}${authorizeUrl.pathname}`
            )

            this.bot.logger.debug(this.bot.isMobile, 'LOGIN-APP', '通过请求解析移动端 OAuth 验证码')

            let code = ''
            try {
                const resp = await this.page.request.get(authorizeUrl.href, { maxRedirects: 20 })
                const finalUrl = new URL(resp.url())

                this.bot.logger.debug(
                    this.bot.isMobile,
                    'LOGIN-APP',
                    `OAuth 重定向已解析 → ${finalUrl.origin}${finalUrl.pathname} (状态 ${resp.status()})`
                )

                if (finalUrl.pathname === '/oauth20_desktop.srf') {
                    code = finalUrl.searchParams.get('code') || ''
                }
            } catch (err) {
                this.bot.logger.debug(
                    this.bot.isMobile,
                    'LOGIN-APP',
                    `OAuth 验证码请求失败: ${err instanceof Error ? err.message : String(err)}`
                )
            }

            if (!code) {
                this.bot.logger.warn(
                    this.bot.isMobile,
                    'LOGIN-APP',
                    '无法解析移动端 OAuth 验证码 - 本次运行将跳过应用活动'
                )
                return ''
            }

            this.bot.logger.debug(this.bot.isMobile, 'LOGIN-APP', 'OAuth 验证码已解析, 正在换取访问令牌')

            const data = new URLSearchParams()
            data.append('grant_type', 'authorization_code')
            data.append('client_id', this.clientId)
            data.append('code', code)
            data.append('redirect_uri', this.redirectUrl)

            const response = await this.bot.http.request<{ access_token?: string }>({
                url: this.tokenUrl,
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                data: data.toString()
            })

            const token = response?.data?.access_token ?? ''

            if (!token) {
                this.bot.logger.warn(this.bot.isMobile, 'LOGIN-APP', '令牌响应中没有 access_token')
                this.bot.logger.debug(
                    this.bot.isMobile,
                    'LOGIN-APP',
                    `令牌响应内容: ${JSON.stringify(response?.data)}`
                )
                return ''
            }

            this.bot.logger.info(this.bot.isMobile, 'LOGIN-APP', '已收到移动端访问令牌')
            return token
        } catch (error) {
            this.bot.logger.error(
                this.bot.isMobile,
                'LOGIN-APP',
                `移动端访问错误: ${error instanceof Error ? error.stack || error.message : String(error)}`
            )
            return ''
        }
    }
}
