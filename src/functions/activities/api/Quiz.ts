import type { AxiosRequestConfig } from 'axios'
import type { BasePromotion } from '../../../interface/DashboardData'
import { Workers } from '../../Workers'

export class Quiz extends Workers {
    private cookieHeader: string = ''

    private fingerprintHeader: { [x: string]: string } = {}

    private gainedPoints: number = 0

    private oldBalance: number = this.bot.userData.currentPoints

    async doQuiz(promotion: BasePromotion) {
        const offerId = promotion.offerId
        this.oldBalance = Number(this.bot.userData.currentPoints ?? 0)
        const startBalance = this.oldBalance

        this.bot.logger.info(
            this.bot.isMobile,
            'QUIZ',
            `开始测验 | offerId=${offerId} | 最大点数进度=${promotion.pointProgressMax} | 最大活动进度=${promotion.activityProgressMax} | 当前积分=${startBalance}`
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
                'QUIZ',
                `准备好的测验头部 | offerId=${offerId} | cookie长度=${this.cookieHeader.length} | 指纹头部键=${Object.keys(this.fingerprintHeader).length}`
            )

            // 8题测验
            if (promotion.activityProgressMax === 80) {
                this.bot.logger.warn(
                    this.bot.isMobile,
                    'QUIZ',
                    `检测到8题测验 (activityProgressMax=80)，标记为已完成 | offerId=${offerId}`
                )

                // 未实现
                return
            }

            // 标准积分测验 (20/30/40/50 最大值)
            if ([20, 30, 40, 50].includes(promotion.pointProgressMax)) {
                let oldBalance = startBalance
                let gainedPoints = 0
                const maxAttempts = 20
                let totalGained = 0
                let attempts = 0

                this.bot.logger.debug(
                    this.bot.isMobile,
                    'QUIZ',
                    `开始ReportActivity循环 | offerId=${offerId} | 最大尝试次数=${maxAttempts} | 起始余额=${oldBalance}`
                )

                for (let i = 0; i < maxAttempts; i++) {
                    try {
                        const jsonData = {
                            UserId: null,
                            timeZone: this.bot.userData.timezoneOffset,
                            OfferId: offerId,
                            ActivityCount: 1,
                            QuestionIndex: '-1'
                        }

                        const request: AxiosRequestConfig = {
                            url: 'https://www.bing.com/bingqa/ReportActivity?ajaxreq=1',
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                                cookie: this.cookieHeader,
                                ...this.fingerprintHeader
                            },
                            data: JSON.stringify(jsonData)
                        }

                        this.bot.logger.debug(
                            this.bot.isMobile,
                            'QUIZ',
                            `发送ReportActivity请求 | 尝试=${i + 1}/${maxAttempts} | offerId=${offerId} | url=${request.url}`
                        )

                        const response = await this.bot.axios.request(request)

                        this.bot.logger.debug(
                            this.bot.isMobile,
                            'QUIZ',
                            `收到ReportActivity响应 | 尝试=${i + 1}/${maxAttempts} | offerId=${offerId} | 状态=${response.status}`
                        )

                        const newBalance = await this.bot.browser.func.getCurrentPoints()
                        gainedPoints = newBalance - oldBalance

                        this.bot.logger.debug(
                            this.bot.isMobile,
                            'QUIZ',
                            `ReportActivity后的余额差额 | 尝试=${i + 1}/${maxAttempts} | offerId=${offerId} | 旧余额=${oldBalance} | 新余额=${newBalance} | 获得积分=${gainedPoints}`
                        )

                        attempts = i + 1

                        if (gainedPoints > 0) {
                            this.bot.userData.currentPoints = newBalance
                            this.bot.userData.gainedPoints = (this.bot.userData.gainedPoints ?? 0) + gainedPoints

                            oldBalance = newBalance
                            totalGained += gainedPoints
                            this.gainedPoints += gainedPoints

                            this.bot.logger.info(
                                this.bot.isMobile,
                                'QUIZ',
                                `ReportActivity ${i + 1} → ${response.status} | offerId=${offerId} | 获得积分=${gainedPoints} | 新余额=${newBalance}`,
                                'green'
                            )
                        } else {
                            this.bot.logger.warn(
                                this.bot.isMobile,
                                'QUIZ',
                                `ReportActivity ${i + 1} | offerId=${offerId} | 没有获得更多积分，结束测验 | 最后余额=${newBalance}`
                            )
                            break
                        }

                        this.bot.logger.debug(
                            this.bot.isMobile,
                            'QUIZ',
                            `ReportActivity尝试之间等待 | 尝试=${i + 1}/${maxAttempts} | offerId=${offerId}`
                        )

                        await this.bot.utils.wait(this.bot.utils.randomDelay(5000, 7000))
                    } catch (error) {
                        this.bot.logger.error(
                            this.bot.isMobile,
                            'QUIZ',
                            `ReportActivity期间出错 | 尝试=${i + 1}/${maxAttempts} | offerId=${offerId} | 消息=${error instanceof Error ? error.message : String(error)}`
                        )
                        break
                    }
                }

                this.bot.logger.info(
                    this.bot.isMobile,
                    'QUIZ',
                    `成功完成测验 | offerId=${offerId} | 尝试次数=${attempts} | 总获得=${totalGained} | 起始余额=${startBalance} | 最终余额=${this.bot.userData.currentPoints}`
                )
            } else {
                this.bot.logger.warn(
                    this.bot.isMobile,
                    'QUIZ',
                    `不支持的测验配置 | offerId=${offerId} | pointProgressMax=${promotion.pointProgressMax} | activityProgressMax=${promotion.activityProgressMax}`
                )
            }
        } catch (error) {
            this.bot.logger.error(
                this.bot.isMobile,
                'QUIZ',
                `doQuiz中出错 | offerId=${promotion.offerId} | 消息=${error instanceof Error ? error.message : String(error)}`
            )
        }
    }
}
