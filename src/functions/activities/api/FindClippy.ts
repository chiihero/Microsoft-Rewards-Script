import type { AxiosRequestConfig } from 'axios'
import type { FindClippyPromotion } from '../../../interface/DashboardData'
import { Workers } from '../../Workers'

export class FindClippy extends Workers {
    private cookieHeader: string = ''

    private fingerprintHeader: { [x: string]: string } = {}

    private gainedPoints: number = 0

    private oldBalance: number = this.bot.userData.currentPoints

    public async doFindClippy(promotion: FindClippyPromotion) {
        const offerId = promotion.offerId
        const activityType = promotion.activityType

        try {
            if (!this.bot.requestToken && this.bot.rewardsVersion === 'legacy') {
                this.bot.logger.warn(
                    this.bot.isMobile,
                    'FIND-CLIPPY',
                    '跳过：请求令牌不可用，此活动需要它！'
                )
                return
            }

            this.cookieHeader = this.bot.browser.func.buildCookieHeader(
                this.bot.isMobile ? this.bot.cookies.mobile : this.bot.cookies.desktop,
                ['bing.com', 'live.com', 'microsoftonline.com']
            )

            const fingerprintHeaders = { ...this.bot.fingerprint.headers }
            delete fingerprintHeaders['Cookie']
            delete fingerprintHeaders['cookie']
            this.fingerprintHeader = fingerprintHeaders

            this.bot.logger.info(
                this.bot.isMobile,
                'FIND-CLIPPY',
                `开始查找Clippy | offerId=${offerId} | 活动类型=${activityType} | 旧余额=${this.oldBalance}`
            )

            this.bot.logger.debug(
                this.bot.isMobile,
                'FIND-CLIPPY',
                `准备好的头部信息 | cookie长度=${this.cookieHeader.length} | 指纹头部键=${Object.keys(this.fingerprintHeader).length}`
            )

            const formData = new URLSearchParams({
                id: offerId,
                hash: promotion.hash,
                timeZone: this.bot.userData.timezoneOffset,
                activityAmount: '1',
                dbs: '0',
                form: '',
                type: activityType,
                __RequestVerificationToken: this.bot.requestToken
            })

            this.bot.logger.debug(
                this.bot.isMobile,
                'FIND-CLIPPY',
                `准备好的查找Clippy表单数据 | offerId=${offerId} | hash=${promotion.hash} | 时区=480 | 活动量=1 | 类型=${activityType}`
            )

            const request: AxiosRequestConfig = {
                url: 'https://rewards.bing.com/api/reportactivity?X-Requested-With=XMLHttpRequest',
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
                'FIND-CLIPPY',
                `发送查找Clippy请求 | offerId=${offerId} | url=${request.url}`
            )

            const response = await this.bot.axios.request(request)

            this.bot.logger.debug(
                this.bot.isMobile,
                'FIND-CLIPPY',
                `收到查找Clippy响应 | offerId=${offerId} | 状态=${response.status}`
            )

            const newBalance = await this.bot.browser.func.getCurrentPoints()
            this.gainedPoints = newBalance - this.oldBalance

            this.bot.logger.debug(
                this.bot.isMobile,
                'FIND-CLIPPY',
                `查找Clippy后余额差额 | offerId=${offerId} | 旧余额=${this.oldBalance} | 新余额=${newBalance} | 获得积分=${this.gainedPoints}`
            )

            if (this.gainedPoints > 0) {
                this.bot.userData.currentPoints = newBalance
                this.bot.userData.gainedPoints = (this.bot.userData.gainedPoints ?? 0) + this.gainedPoints

                this.bot.logger.info(
                    this.bot.isMobile,
                    'FIND-CLIPPY',
                    `找到Clippy | offerId=${offerId} | 状态=${response.status} | 获得积分=${this.gainedPoints} | 新余额=${newBalance}`,
                    'green'
                )
            } else {
                this.bot.logger.warn(
                    this.bot.isMobile,
                    'FIND-CLIPPY',
                    `找到Clippy但未获得积分 | offerId=${offerId} | 状态=${response.status} | 旧余额=${this.oldBalance} | 新余额=${newBalance}`
                )
            }

            this.bot.logger.debug(this.bot.isMobile, 'FIND-CLIPPY', `查找Clippy后等待 | offerId=${offerId}`)

            await this.bot.utils.wait(this.bot.utils.randomDelay(5000, 10000))
        } catch (error) {
            this.bot.logger.error(
                this.bot.isMobile,
                'FIND-CLIPPY',
                `doFindClippy中出错 | offerId=${offerId} | 消息=${error instanceof Error ? error.message : String(error)}`
            )
        }
    }
}
