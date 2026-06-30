import { URLs } from '../../../constants/urls'
import { BING_APP_USER_AGENT } from '../../../constants/userAgents'
import type { HttpRequestConfig } from '../../../util/Http'
import { randomBytes } from 'crypto'
import { Workers } from '../../Workers'

export class ReadToEarn extends Workers {
    public async doReadToEarn() {
        if (!this.bot.accessToken) {
            this.bot.logger.warn(
                this.bot.isMobile,
                'READ-TO-EARN',
                '跳过：应用访问令牌不可用，此活动需要它！'
            )
            return
        }

        const delayMin = this.bot.config.searchSettings.readDelay.min
        const delayMax = this.bot.config.searchSettings.readDelay.max
        const startBalance = Number(this.bot.userData.currentPoints ?? 0)

        this.bot.logger.info(
            this.bot.isMobile,
            'READ-TO-EARN',
            `开始阅读赚积分 | 地区=${this.bot.userData.geoLocale} | 延迟范围=${delayMin}-${delayMax} | 当前积分=${startBalance}`
        )

        try {
            const jsonData = {
                amount: 1,
                id: '1',
                type: 101,
                attributes: {
                    offerid: 'ENUS_readarticle3_30points'
                },
                country: this.bot.userData.geoLocale
            }

            const articleCount = 10
            let totalGained = 0
            let articlesRead = 0
            let oldBalance = startBalance

            for (let i = 0; i < articleCount; ++i) {
                jsonData.id = randomBytes(64).toString('hex')

                this.bot.logger.debug(
                    this.bot.isMobile,
                    'READ-TO-EARN',
                    `正在提交阅读赚积分活动 | 文章=${i + 1}/${articleCount} | id=${jsonData.id} | 地区=${jsonData.country}`
                )

                const request: HttpRequestConfig = {
                    url: URLs.platform.activities,
                    method: 'POST',
                    headers: {
                        Authorization: `Bearer ${this.bot.accessToken}`,
                        'User-Agent': BING_APP_USER_AGENT,
                        'Content-Type': 'application/json',
                        'X-Rewards-Country': this.bot.userData.geoLocale,
                        'X-Rewards-Language': 'en',
                        'X-Rewards-ismobile': 'true'
                    },
                    data: JSON.stringify(jsonData)
                }

                const response = await this.bot.http.request<{ response?: { balance?: number } }>(request)

                this.bot.logger.debug(
                    this.bot.isMobile,
                    'READ-TO-EARN',
                    `已收到阅读赚积分响应 | 文章=${i + 1}/${articleCount} | 状态=${response?.status ?? 'unknown'}`
                )

                const newBalance = Number(response?.data?.response?.balance ?? oldBalance)
                const gainedPoints = newBalance - oldBalance

                this.bot.logger.debug(
                    this.bot.isMobile,
                    'READ-TO-EARN',
                    `文章后的积分变化 | 文章=${i + 1}/${articleCount} | 旧余额=${oldBalance} | 新余额=${newBalance} | 获得积分=${gainedPoints}`
                )

                if (gainedPoints <= 0) {
                    this.bot.logger.info(
                        this.bot.isMobile,
                        'READ-TO-EARN',
                        `未获得积分，停止阅读赚积分 | 文章=${i + 1}/${articleCount} | 状态=${response.status} | 旧余额=${oldBalance} | 新余额=${newBalance}`
                    )
                    break
                }

                // Update point tracking
                this.bot.userData.currentPoints = newBalance
                this.bot.userData.gainedPoints = (this.bot.userData.gainedPoints ?? 0) + gainedPoints
                totalGained += gainedPoints
                articlesRead = i + 1
                oldBalance = newBalance

                this.bot.logger.info(
                    this.bot.isMobile,
                    'READ-TO-EARN',
                    `已阅读文章 ${i + 1}/${articleCount} | 状态=${response.status} | 获得积分=${gainedPoints} | 新余额=${newBalance}`,
                    'green'
                )

                // Wait random delay between articles
                this.bot.logger.debug(
                    this.bot.isMobile,
                    'READ-TO-EARN',
                    `文章间等待中 | 文章=${i + 1}/${articleCount} | 延迟范围=${delayMin}-${delayMax}`
                )

                await this.bot.utils.wait(this.bot.utils.randomDelay(delayMin, delayMax))
            }

            const finalBalance = Number(this.bot.userData.currentPoints ?? startBalance)

            this.bot.logger.info(
                this.bot.isMobile,
                'READ-TO-EARN',
                `阅读赚积分完成 | 已读文章=${articlesRead} | 共获得=${totalGained} | 起始余额=${startBalance} | 最终余额=${finalBalance}`
            )
        } catch (error) {
            this.bot.logger.error(
                this.bot.isMobile,
                'READ-TO-EARN',
                `阅读赚积分出错 | 消息=${error instanceof Error ? error.message : String(error)}`
            )
        }
    }
}
