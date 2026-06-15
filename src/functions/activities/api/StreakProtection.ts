import type { AxiosRequestConfig } from 'axios'
import { Workers } from '../../Workers'

export class StreakProtection extends Workers {
    /**
     * 启用连击保护（Streak Protection）。
     *
     * 新版 UI（modern dashboard）下走 Next.js Server Action：
     *   POST https://rewards.bing.com/dashboard
     *   next-action: <toggleStreakProtection hash>
     *   body: [true]  // 服务端幂等，已开启再调用也无害
     * 认证靠 Cookie，无需 requestToken / accessToken。
     * 部署版本不匹配时降级跳过（不会 400），旧版 UI 仍走原 REST API。
     */
    public async ensureStreakProtection() {
        try {
            // 新版 UI：通过 Server Action 启用
            if (this.bot.rewardsVersion === 'modern' || !this.bot.requestToken) {
                this.bot.logger.info(
                    this.bot.isMobile,
                    'ENABLE-STREAK-PROTECTION',
                    '新版 UI：通过 Server Action 启用连击保护'
                )
                const ok = await this.bot.browser.func.callServerAction(
                    'toggleStreakProtection',
                    [true],
                    'ENABLE-STREAK-PROTECTION'
                )
                if (ok) {
                    this.bot.logger.info(
                        this.bot.isMobile,
                        'ENABLE-STREAK-PROTECTION',
                        '连击保护已启用（Server Action）',
                        'green'
                    )
                }
                return
            }

            // 旧版 UI：走 REST API（需要 requestToken）
            const formData = new URLSearchParams({
                isOn: 'true',
                activityAmount: '1',
                timeZone: this.bot.userData.timezoneOffset,
                __RequestVerificationToken: this.bot.requestToken
            })

            const request: AxiosRequestConfig = {
                url: 'https://rewards.bing.com/api/togglestreakasync?X-Requested-With=XMLHttpRequest',
                method: 'POST',
                headers: {
                    ...(this.bot.fingerprint?.headers ?? {}),
                    Cookie: this.bot.browser.func.buildCookieHeader(this.bot.cookies.mobile, [
                        'bing.com',
                        'live.com',
                        'microsoftonline.com'
                    ]),
                    Referer: 'https://rewards.bing.com/',
                    Origin: 'https://rewards.bing.com'
                },
                data: formData
            }

            await this.bot.axios.request(request)

            this.bot.logger.info(
                this.bot.isMobile,
                'ENABLE-STREAK-PROTECTION',
                '连击保护已启用（REST API）',
                'green'
            )
        } catch (error) {
            this.bot.logger.error(
                this.bot.isMobile,
                'ENABLE-STREAK-PROTECTION',
                `启用连击保护出错: ${error instanceof Error ? error.message : String(error)}`
            )
            throw error
        }
    }
}
