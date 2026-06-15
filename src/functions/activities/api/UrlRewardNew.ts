import type { AxiosRequestConfig } from 'axios'
import type { BasePromotion } from '../../../interface/DashboardData'
import type { PanelFlyoutData } from '../../../interface/PanelFlyoutData'
import { Workers } from '../../Workers'

export class UrlRewardNew extends Workers {
    private cookieHeader: string = ''

    private fingerprintHeader: { [x: string]: string } = {}

    private gainedPoints: number = 0

    private oldBalance: number = this.bot.userData.currentPoints

    private panelData: PanelFlyoutData = this.bot.panelData

    public async doUrlReward(promotion: BasePromotion) {

        const offerId = promotion.offerId

        const todayKey = this.bot.utils.getFormattedDate()

        // find promotion in panelData promotions or flyoutResult.morePromotions
        const panelPromotion = 
            this.panelData.flyoutResult.morePromotions.find(p => p.offerId === offerId) ||
            this.panelData.flyoutResult.dailySetPromotions[todayKey]?.find(p => p.offerId === offerId)

        if (!panelPromotion) {
            this.bot.logger.warn(
                this.bot.isMobile, 
                'URL-REWARD',
                `在面板数据中未找到活动 | offerId=${offerId}`
            )
            return
        }

        this.bot.logger.info(
            this.bot.isMobile,
            'URL-REWARD',
            `开始UrlReward | offerId=${offerId} | 地区=${this.bot.userData.geoLocale} | 旧余额=${this.oldBalance}`
        )

        try {
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
                'URL-REWARD',
                `准备好的UrlReward头部 | offerId=${offerId} | cookie长度=${this.cookieHeader.length} | 指纹头部键=${Object.keys(this.fingerprintHeader).length}`
            )

            const jsonData = {
                ActivityCount: 1,
                ActivityType: panelPromotion.activityType,
                ActivitySubType: "",
                OfferId: offerId,
                AuthKey: panelPromotion.hash,
                Channel: this.panelData.channel,
                PartnerId: this.panelData.partnerId,
                UserId: this.panelData.userId,
            }

            this.bot.logger.debug(
                this.bot.isMobile,
                'URL-REWARD',
                `准备好的UrlReward表单数据 | offerId=${offerId} | hash=${panelPromotion.hash} | 时区=60 | 活动量=1`
            )

            const request: AxiosRequestConfig = {
                url: 'https://cn.bing.com/msrewards/api/v1/reportactivity',
                method: 'POST',
                // headers: {
                //     ...(this.bot.fingerprint?.headers ?? {}),
                //     Accept: '*/*',
                //     "Content-Type": 'text/plain;charset=UTF-8',
                //     Origin: 'https://www.bing.com',
                // },
                data: jsonData
            }

            this.bot.logger.debug(
                this.bot.isMobile,
                'URL-REWARD',
                `发送UrlReward请求 | offerId=${offerId} | url=${request.url}`
            )

            const response = await this.bot.axios.request(request)

            this.bot.logger.debug(
                this.bot.isMobile,
                'URL-REWARD',
                `收到UrlReward响应 | offerId=${offerId} | 状态=${response.status}`
            )

            const newBalance = await this.bot.browser.func.getCurrentPoints()
            this.gainedPoints = newBalance - this.oldBalance

            this.bot.logger.debug(
                this.bot.isMobile,
                'URL-REWARD',
                `UrlReward后的余额差额 | offerId=${offerId} | 旧余额=${this.oldBalance} | 新余额=${newBalance} | 获得积分=${this.gainedPoints}`
            )

            if (this.gainedPoints > 0) {
                this.bot.userData.currentPoints = newBalance
                this.bot.userData.gainedPoints = (this.bot.userData.gainedPoints ?? 0) + this.gainedPoints

                this.bot.logger.info(
                    this.bot.isMobile,
                    'URL-REWARD',
                    `完成UrlReward | offerId=${offerId} | 状态=${response.status} | 获得积分=${this.gainedPoints} | 新余额=${newBalance}`,
                    'green'
                )
            } else {
                this.bot.logger.warn(
                    this.bot.isMobile,
                    'URL-REWARD',
                    `UrlReward失败，没有积分 | offerId=${offerId} | 状态=${response.status} | 旧余额=${this.oldBalance} | 新余额=${newBalance}`
                )
            }

            this.bot.logger.debug(this.bot.isMobile, 'URL-REWARD', `等待UrlReward后 | offerId=${offerId}`)

            await this.bot.utils.wait(this.bot.utils.randomDelay(5000, 10000))
        } catch (error) {
            this.bot.logger.error(
                this.bot.isMobile,
                'URL-REWARD',
                `doUrlReward中出错 | offerId=${promotion.offerId} | 消息=${error instanceof Error ? error.message : String(error)}`
            )
        }
    }
}