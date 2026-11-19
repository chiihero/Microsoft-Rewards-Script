import type { Promotion } from '../../../interface/AppDashBoardData'

export interface CheckInState {
    status: 'complete' | 'pending' | 'unknown'
    remaining: number | null
    updatedAt: string | null
    reason: string
}

function isTrue(value: string | undefined): boolean {
    return value?.toLowerCase() === 'true'
}

function dateKey(value: string | Date, country: string): string | null {
    const date = new Date(value)
    if (!Number.isFinite(date.getTime())) return null
    return new Intl.DateTimeFormat('en-CA', {
        timeZone: country.toUpperCase() === 'CN' ? 'Asia/Shanghai' : undefined,
        year: 'numeric',
        month: '2-digit',
        day: '2-digit'
    }).format(date)
}

/**
 * 判断今日签到是否需要提交。
 *
 * 只信任签到推广自身的 `attributes.complete`。`last_updated` 在生产日志中被观察到
 * 等于“服务器刷新时间”而不是真实签到时间（宿主机慢 5 分钟时它反而超前 6 分钟），
 * 因此绝不能作为“今日已签到”的依据；这里只把它写进 reason，方便对账时识别。
 * 无法确认完成时一律返回 pending / unknown，让调用方继续提交（接口幂等）。
 */
export function resolveCheckInState(
    promotions: Pick<Promotion, 'name' | 'attributes'>[],
    country: string,
    now = new Date()
): CheckInState {
    const checkIn = promotions.find(item => item.attributes.offerid === 'Gamification_Sapphire_DailyCheckIn')
    const updatedAt = checkIn?.attributes.last_updated ?? null
    const unknown = (reason: string): CheckInState => ({ status: 'unknown', remaining: null, updatedAt, reason })
    if (!checkIn) return unknown('未找到签到推广')

    const attrs = checkIn.attributes
    if (isTrue(attrs.complete)) {
        return { status: 'complete', remaining: 0, updatedAt, reason: '签到推广已标记完成' }
    }
    if (isTrue(attrs.hidden) || attrs.give_eligible?.toLowerCase() === 'false') {
        return unknown('旧签到推广不可作为今日可领取额度')
    }

    const progress = attrs.progress ? Number(attrs.progress) : NaN
    if (!Number.isInteger(progress) || progress < 0) return unknown('签到进度不可确认')
    const points = attrs[`day_${(progress % 7) + 1}_points`]
    const remaining = points ? Number(points) : NaN
    if (!Number.isFinite(remaining) || remaining < 0) return unknown('未提供当日签到积分')

    const today = dateKey(now, country)
    const updatedDay = updatedAt ? dateKey(updatedAt, country) : null
    const note = updatedDay && today && updatedDay === today ? '（last_updated 为今日，不作为完成依据）' : ''
    return { status: 'pending', remaining, updatedAt, reason: `签到推广未标记完成${note}` }
}
