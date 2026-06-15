import type { AxiosRequestConfig } from 'axios'
import { Workers } from '../../Workers'
import { PromotionalItem } from '../../../interface/DashboardData'

export class DoubleSearchPoints extends Workers {
    private cookieHeader: string = ''

    private fingerprintHeader: { [x: string]: string } = {}

    public async doDoubleSearchPoints(promotion: PromotionalItem) {
        const offerId = promotion.offerId
        const activityType = promotion.activityType

        try {
            if (!this.bot.requestToken && this.bot.rewardsVersion === 'legacy') {
                this.bot.logger.warn(
                    this.bot.isMobile,
                    'DOUBLE-SEARCH-POINTS',
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
                'DOUBLE-SEARCH-POINTS',
                `开始双倍搜索积分 | offerId=${offerId}`
            )

            this.bot.logger.debug(
                this.bot.isMobile,
                'DOUBLE-SEARCH-POINTS',
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
                'DOUBLE-SEARCH-POINTS',
                `准备好的双倍搜索积分表单数据 | offerId=${offerId} | hash=${promotion.hash} | 时区=480 | 活动量=1 | 类型=${activityType}`
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
                'DOUBLE-SEARCH-POINTS',
                `发送双倍搜索积分请求 | offerId=${offerId} | url=${request.url}`
            )

            const response = await this.bot.axios.request(request)

            this.bot.logger.debug(
                this.bot.isMobile,
                'DOUBLE-SEARCH-POINTS',
                `收到双倍搜索积分响应 | offerId=${offerId} | 状态=${response.status}`
            )

            const data = await this.bot.browser.func.getDashboardData()
            const promotionalItem = data.promotionalItems.find(item =>
                item.name.toLowerCase().includes('ww_banner_optin_2x')
            )

            // 如果成功，不应再在促销项目中显示
            if (promotionalItem) {
                this.bot.logger.warn(
                    this.bot.isMobile,
                    'DOUBLE-SEARCH-POINTS',
                    `无法找到或激活双倍搜索积分 | offerId=${offerId} | 状态=${response.status}`
                )
            } else {
                this.bot.logger.info(
                    this.bot.isMobile,
                    'DOUBLE-SEARCH-POINTS',
                    `已激活双倍搜索积分 | offerId=${offerId} | 状态=${response.status}`,
                    'green'
                )
            }

            this.bot.logger.debug(
                this.bot.isMobile,
                'DOUBLE-SEARCH-POINTS',
                `双倍搜索积分后等待 | offerId=${offerId}`
            )

            await this.bot.utils.wait(this.bot.utils.randomDelay(5000, 10000))
        } catch (error) {
            this.bot.logger.error(
                this.bot.isMobile,
                'DOUBLE-SEARCH-POINTS',
                `doDoubleSearchPoints中出错 | offerId=${offerId} | 消息=${error instanceof Error ? error.message : String(error)}`
            )
        }
    }
}
