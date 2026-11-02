import { URLs } from '../../../constants/urls'
import type { HttpRequestConfig } from '../../../util/Http'
import { randomUUID } from 'crypto'
import { BaseActivity } from '../BaseActivity'
import { resolveCheckInState, type CheckInState } from './CheckInState'

export class DailyCheckIn extends BaseActivity {
    private gainedPoints: number = 0

    private oldBalance: number = this.bot.userData.currentPoints

    public async doDailyCheckIn() {
        if (!this.bot.accessToken) {
            this.bot.logger.warn(this.bot.isMobile, 'DAILY-CHECK-IN', '跳过：应用访问令牌不可用，此活动需要它！')
            return
        }

        this.oldBalance = Number(this.bot.userData.currentPoints ?? 0)
        const before = await this.getCheckInState()
        if (before.status === 'complete') {
            this.bot.logger.info(
                this.bot.isMobile,
                'DAILY-CHECK-IN',
                `今日已签到，跳过重复请求 | updatedAt=${before.updatedAt} | currentBalance=${this.oldBalance}`
            )
            return
        }

        this.bot.logger.info(
            this.bot.isMobile,
            'DAILY-CHECK-IN',
            `开始每日签到 | geo=${this.bot.userData.geoLocale} | currentBalance=${this.oldBalance} | state=${before.status} | expected=${before.remaining ?? '未知'}`
        )

        try {
            const response = await this.submitDaily()
            if (
                response.status < 200 ||
                response.status >= 300 ||
                (response.data?.code !== undefined && response.data.code !== 0)
            ) {
                throw new Error(
                    `签到接口未确认成功 | status=${response.status} | code=${response.data?.code ?? 'unknown'}`
                )
            }

            this.bot.logger.debug(
                this.bot.isMobile,
                'DAILY-CHECK-IN',
                `已收到每日签到响应 | status=${response?.status ?? 'unknown'}`
            )

            const responseBalance = response.data?.response?.balance
            const newBalance =
                typeof responseBalance === 'number' && Number.isFinite(responseBalance)
                    ? responseBalance
                    : await this.bot.browser.func.getCurrentPoints()
            if (!Number.isFinite(newBalance) || newBalance < 0) throw new Error('无法取得有效余额，签到到账状态未知')
            this.gainedPoints = newBalance - this.oldBalance

            this.bot.logger.debug(
                this.bot.isMobile,
                'DAILY-CHECK-IN',
                `每日签到后的积分变化 | type=103 | previousBalance=${this.oldBalance} | currentBalance=${newBalance} | pointsGained=${this.gainedPoints}`
            )

            if (this.gainedPoints > 0) {
                this.bot.userData.currentPoints = newBalance
                this.bot.userData.gainedPoints = (this.bot.userData.gainedPoints ?? 0) + this.gainedPoints

                this.bot.logger.info(
                    this.bot.isMobile,
                    'DAILY-CHECK-IN',
                    `每日签到完成 | type=103 | pointsGained=${this.gainedPoints} | currentBalance=${newBalance}`,
                    'green'
                )
            } else {
                const after = await this.getCheckInState()
                if (after.status !== 'complete') {
                    throw new Error(
                        `签到未确认到账 | pointsGained=${this.gainedPoints} | currentBalance=${newBalance} | state=${after.status}`
                    )
                }
                this.bot.logger.info(
                    this.bot.isMobile,
                    'DAILY-CHECK-IN',
                    `已确认今日签到，本次无新增积分 | pointsGained=0 | currentBalance=${newBalance} | updatedAt=${after.updatedAt}`
                )
            }
        } catch (error) {
            this.bot.logger.error(
                this.bot.isMobile,
                'DAILY-CHECK-IN',
                `每日签到出错 | message=${error instanceof Error ? error.message : String(error)}`
            )
            throw error
        }
    }

    private async getCheckInState(): Promise<CheckInState> {
        try {
            const data = await this.bot.browser.func.getAppDashboardData('SAAndroid')
            return resolveCheckInState(data.response?.promotions ?? [], this.bot.userData.geoLocale)
        } catch (error) {
            this.bot.logger.warn(
                this.bot.isMobile,
                'DAILY-CHECK-IN',
                `签到状态读取失败 | ${error instanceof Error ? error.message : String(error)}`
            )
            return { status: 'unknown', remaining: null, updatedAt: null, reason: '状态读取失败' }
        }
    }

    private async submitDaily() {
        try {
            const jsonData = {
                risk_context: {},
                type: 103,
                channel: 'SAIOS',
                attributes: {},
                id: randomUUID(),
                amount: 1,
                country: this.bot.userData.geoLocale
            }

            this.bot.logger.debug(
                this.bot.isMobile,
                'DAILY-CHECK-IN',
                `正在准备每日签到载荷 | type=${jsonData.type} | id=${jsonData.id} | amount=${jsonData.amount} | country=${jsonData.country}`
            )

            const request: HttpRequestConfig = {
                url: URLs.platform.activities,
                method: 'POST',
                headers: {
                    Authorization: `Bearer ${this.bot.accessToken}`,
                    'Content-Type': 'application/json',
                    Accept: '*/*',
                    'User-Agent':
                        'Mozilla/5.0 (iPad; CPU iPad OS 26_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.5 Mobile/15E148 Safari/605.1.15 BingSapphire/33.4.440603001',
                    'X-Rewards-AppId': 'SAIOS/33.4.440603001',
                    'X-Rewards-PartnerId': 'startapp',
                    'X-Rewards-Country': this.bot.userData.geoLocale,
                    'X-Rewards-Language': this.bot.userData.langCode,
                    'X-Rewards-Flights': 'rwgobig',
                    'X-Rewards-IsMobile': 'true'
                },
                data: JSON.stringify(jsonData)
            }

            this.bot.logger.debug(
                this.bot.isMobile,
                'DAILY-CHECK-IN',
                `正在发送每日签到请求 | type=${jsonData.type} | url=${request.url}`
            )

            return this.bot.http.request<{ code?: number; response?: { balance?: number } }>(request)
        } catch (error) {
            this.bot.logger.error(
                this.bot.isMobile,
                'DAILY-CHECK-IN',
                `submitDaily 出错 | message=${error instanceof Error ? error.message : String(error)}`
            )
            throw error
        }
    }
}
