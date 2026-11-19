import { URLs } from '../../../constants/urls'
import type { HttpRequestConfig } from '../../../util/Http'
import { randomUUID } from 'crypto'
import { BaseActivity } from '../BaseActivity'
import { resolveCheckInState, type CheckInState } from './CheckInState'

interface CheckInResponse {
    code?: number
    response?: {
        balance?: number
        activity?: {
            p?: number
            type?: number
        }
        isDuplicate?: boolean
    }
}

export class DailyCheckIn extends BaseActivity {
    private gainedPoints: number = 0

    private oldBalance: number = this.bot.userData.currentPoints

    public async doDailyCheckIn(): Promise<boolean> {
        if (!this.bot.accessToken) {
            this.bot.logger.warn(this.bot.isMobile, 'DAILY-CHECK-IN', '跳过：应用访问令牌不可用，此活动需要它！')
            return false
        }

        this.oldBalance = Number(this.bot.userData.currentPoints ?? 0)
        const before = await this.getCheckInState()
        if (before.status === 'complete') {
            this.bot.logger.info(
                this.bot.isMobile,
                'DAILY-CHECK-IN',
                `签到推广已标记完成，跳过重复请求 | reason=${before.reason} | updatedAt=${before.updatedAt} | currentBalance=${this.oldBalance}`
            )
            return false
        }

        this.bot.logger.info(
            this.bot.isMobile,
            'DAILY-CHECK-IN',
            `开始每日签到 | geo=${this.bot.userData.geoLocale} | currentBalance=${this.oldBalance} | state=${before.status} | expected=${before.remaining ?? '未知'} | reason=${before.reason}`
        )
        this.markExecuted()

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

            const payload = response.data?.response
            const rawAwarded = Number(payload?.activity?.p ?? 0)
            const awarded = Number.isFinite(rawAwarded) && rawAwarded > 0 ? rawAwarded : 0
            const isDuplicate = payload?.isDuplicate === true

            this.bot.logger.debug(
                this.bot.isMobile,
                'DAILY-CHECK-IN',
                `已收到每日签到响应 | status=${response.status} | activity.p=${awarded} | activity.type=${payload?.activity?.type ?? '未知'} | isDuplicate=${isDuplicate} | responseBalance=${payload?.balance ?? '未提供'}`
            )

            // 1. 接口直接给出本次活动得分：以此为准，不再依赖余额或状态回读
            if (awarded > 0) {
                const balance = await this.readBalance(payload?.balance)
                const newBalance = Math.max(balance ?? this.oldBalance + awarded, this.oldBalance + awarded)
                this.gainedPoints = newBalance - this.oldBalance
                this.bot.userData.currentPoints = newBalance
                this.bot.userData.gainedPoints = (this.bot.userData.gainedPoints ?? 0) + this.gainedPoints

                this.bot.logger.info(
                    this.bot.isMobile,
                    'DAILY-CHECK-IN',
                    `每日签到完成 | type=${payload?.activity?.type ?? 103} | pointsGained=${this.gainedPoints} | currentBalance=${newBalance}`,
                    'green'
                )
                return true
            }

            // 2. 没有活动得分，但余额有变化：按实际到账记账
            const balance = await this.readBalance(payload?.balance)
            const balanceDelta = balance === null ? null : balance - this.oldBalance
            if (balance !== null && balanceDelta !== null && balanceDelta > 0) {
                this.gainedPoints = balanceDelta
                this.bot.userData.currentPoints = balance
                this.bot.userData.gainedPoints = (this.bot.userData.gainedPoints ?? 0) + this.gainedPoints

                this.bot.logger.info(
                    this.bot.isMobile,
                    'DAILY-CHECK-IN',
                    `每日签到完成（按余额变化确认） | pointsGained=${this.gainedPoints} | currentBalance=${balance}`,
                    'green'
                )
                return true
            }

            // 3. 接口标记重复：今天已在其他端签过，不算失败
            if (isDuplicate) {
                this.bot.logger.info(
                    this.bot.isMobile,
                    'DAILY-CHECK-IN',
                    `今日签到已完成（接口标记重复） | isDuplicate=true | pointsGained=0 | currentBalance=${balance ?? '未知'}`
                )
                return true
            }

            // 4. 兜底：回读推广状态，只有明确完成才算成功
            const after = await this.getCheckInState()
            if (after.status !== 'complete') {
                throw new Error(
                    balance === null
                        ? `无法取得有效余额，签到到账状态未知 | state=${after.status}`
                        : `签到未确认到账 | pointsGained=0 | currentBalance=${balance} | state=${after.status} | isDuplicate=${isDuplicate}`
                )
            }
            this.bot.logger.info(
                this.bot.isMobile,
                'DAILY-CHECK-IN',
                `已确认今日签到，本次无新增积分 | pointsGained=0 | currentBalance=${balance ?? '未知'} | updatedAt=${after.updatedAt}`
            )
            return true
        } catch (error) {
            this.bot.logger.error(
                this.bot.isMobile,
                'DAILY-CHECK-IN',
                `每日签到出错 | message=${error instanceof Error ? error.message : String(error)}`
            )
            throw error
        }
    }

    private async readBalance(responseBalance: number | undefined): Promise<number | null> {
        if (typeof responseBalance === 'number' && Number.isFinite(responseBalance) && responseBalance >= 0) {
            return responseBalance
        }
        try {
            const balance = await this.bot.browser.func.getCurrentPoints()
            return Number.isFinite(balance) && balance >= 0 ? balance : null
        } catch {
            return null
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

            return this.bot.http.request<CheckInResponse>(request)
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
