import type { AxiosRequestConfig } from 'axios'
import { Workers } from '../../Workers'

export class ClaimBonusPoints extends Workers {
    private cookieHeader: string = ''

    private fingerprintHeader: { [x: string]: string } = {}

    private gainedPoints: number = 0

    private oldBalance: number = this.bot.userData.currentPoints

    public async claimBonusPoints() {
        this.bot.logger.info(
            this.bot.isMobile,
            'CLAIM-BONUS-POINTS',
            `开始领取奖励积分 | 地区=${this.bot.userData.geoLocale} | 旧余额=${this.oldBalance}`
        )

        try {
            // 新版 UI（modern）：走 Next.js Server Action（认证靠 Cookie，无需 requestToken）
            if (this.bot.rewardsVersion === 'modern' || !this.bot.requestToken) {
                const ok = await this.bot.browser.func.callServerAction(
                    'claimBonusPoints',
                    [],
                    'CLAIM-BONUS-POINTS'
                )

                if (!ok) {
                    this.bot.logger.warn(
                        this.bot.isMobile,
                        'CLAIM-BONUS-POINTS',
                        'Server Action 调用未成功（可能是部署版本不匹配或网络错误），跳过'
                    )
                    return
                }

                // 通过余额差确认实际获得积分
                const newBalance = await this.bot.browser.func.getCurrentPoints()
                this.gainedPoints = newBalance - this.oldBalance

                if (this.gainedPoints > 0) {
                    this.bot.userData.currentPoints = newBalance
                    this.bot.userData.gainedPoints = (this.bot.userData.gainedPoints ?? 0) + this.gainedPoints
                    this.bot.logger.info(
                        this.bot.isMobile,
                        'CLAIM-BONUS-POINTS',
                        `完成领取奖励积分（Server Action） | 获得积分=${this.gainedPoints} | 新余额=${newBalance}`,
                        'green'
                    )
                } else {
                    this.bot.logger.warn(
                        this.bot.isMobile,
                        'CLAIM-BONUS-POINTS',
                        `领取奖励积分完成但无积分变化 | 旧余额=${this.oldBalance} | 新余额=${newBalance}`
                    )
                }

                await this.bot.utils.wait(this.bot.utils.randomDelay(5000, 10000))
                return
            }

            // 旧版 UI：走 REST API（需要 requestToken）
            this.cookieHeader = this.bot.browser.func.buildCookieHeader(
                this.bot.isMobile ? this.bot.cookies.mobile : this.bot.cookies.desktop,
                ['bing.com', 'live.com', 'microsoftonline.com']
            )

            const fingerprintHeaders = { ...this.bot.fingerprint.headers }
            delete fingerprintHeaders['Cookie']
            delete fingerprintHeaders['cookie']
            this.fingerprintHeader = fingerprintHeaders

            this.bot.logger.debug(
                this.bot.isMobile,
                'CLAIM-BONUS-POINTS',
                `准备好的领取奖励积分头部信息 | cookie长度=${this.cookieHeader.length} | 指纹头部键=${Object.keys(this.fingerprintHeader).length}`
            )

            const formData = new URLSearchParams({
                timeZone: this.bot.userData.timezoneOffset,
                __RequestVerificationToken: this.bot.requestToken
            })

            this.bot.logger.debug(
                this.bot.isMobile,
                'CLAIM-BONUS-POINTS',
                `准备好的领取奖励积分表单数据 | 时区=${this.bot.userData.timezoneOffset} | 活动量=1`
            )

            const request: AxiosRequestConfig = {
                url: 'https://rewards.bing.com/api/claimallpointsasync?X-Requested-With=XMLHttpRequest',
                method: 'POST',
                headers: {
                    ...(this.bot.fingerprint?.headers ?? {}),
                    Cookie: this.cookieHeader,
                    Referer: 'https://rewards.bing.com/',
                    Origin: 'https://rewards.bing.com'
                },
                data: formData
            }

            this.bot.logger.debug(
                this.bot.isMobile,
                'CLAIM-BONUS-POINTS',
                `发送领取奖励积分请求 | url=${request.url}`
            )

            const response = await this.bot.axios.request(request)

            this.bot.logger.debug(
                this.bot.isMobile,
                'CLAIM-BONUS-POINTS',
                `收到领取奖励积分响应 | 状态=${response.status}`
            )

            const newBalance = await this.bot.browser.func.getCurrentPoints()
            this.gainedPoints = newBalance - this.oldBalance

            this.bot.logger.debug(
                this.bot.isMobile,
                'CLAIM-BONUS-POINTS',
                `领取奖励积分后余额差额 | 旧余额=${this.oldBalance} | 新余额=${newBalance} | 获得积分=${this.gainedPoints}`
            )

            if (this.gainedPoints > 0) {
                this.bot.userData.currentPoints = newBalance
                this.bot.userData.gainedPoints = (this.bot.userData.gainedPoints ?? 0) + this.gainedPoints

                this.bot.logger.info(
                    this.bot.isMobile,
                    'CLAIM-BONUS-POINTS',
                    `完成领取奖励积分 | 状态=${response.status} | 获得积分=${this.gainedPoints} | 新余额=${newBalance}`,
                    'green'
                )
            } else {
                this.bot.logger.warn(
                    this.bot.isMobile,
                    'CLAIM-BONUS-POINTS',
                    `领取奖励积分失败，没有积分 | 状态=${response.status} | 旧余额=${this.oldBalance} | 新余额=${newBalance}`
                )
            }

            this.bot.logger.debug(this.bot.isMobile, 'CLAIM-BONUS-POINTS', `领取奖励积分后等待`)

            await this.bot.utils.wait(this.bot.utils.randomDelay(5000, 10000))
        } catch (error) {
            this.bot.logger.error(
                this.bot.isMobile,
                'CLAIM-BONUS-POINTS',
                `doClaimBonusPoints中出错 | 消息=${error instanceof Error ? error.message : String(error)}`
            )
        }
    }
}
