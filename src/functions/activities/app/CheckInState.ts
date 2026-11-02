import type { Promotion } from '../../../interface/AppDashBoardData'

export interface CheckInState {
    status: 'complete' | 'pending' | 'unknown'
    remaining: number | null
    updatedAt: string | null
    reason: string
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

export function resolveCheckInState(
    promotions: Pick<Promotion, 'name' | 'attributes'>[],
    country: string,
    now = new Date()
): CheckInState {
    const today = dateKey(now, country)
    const checkIn = promotions.find(item => item.attributes.offerid === 'Gamification_Sapphire_DailyCheckIn')
    const streak = promotions.find(item => item.name === 'Gamification_Streak_Counter_Promotion')
    for (const item of [streak, checkIn]) {
        const updatedAt = item?.attributes.last_updated
        if (updatedAt && dateKey(updatedAt, country) === today) {
            return { status: 'complete', remaining: 0, updatedAt, reason: '签到记录已更新到今天' }
        }
    }

    const attrs = checkIn?.attributes
    const updatedAt = attrs?.last_updated ?? null
    const updatedDay = updatedAt ? dateKey(updatedAt, country) : null
    const unknown = (reason: string): CheckInState => ({ status: 'unknown', remaining: null, updatedAt, reason })
    if (!attrs || !updatedDay || !today || updatedDay > today) return unknown('缺少有效的签到更新时间')
    if (attrs.hidden?.toLowerCase() === 'true' || attrs.give_eligible?.toLowerCase() === 'false') {
        return unknown('旧签到推广不可作为今日可领取额度')
    }
    const progress = attrs.progress ? Number(attrs.progress) : NaN
    if (!Number.isInteger(progress) || progress < 0) return unknown('签到进度不可确认')
    const points = attrs[`day_${(progress % 7) + 1}_points`]
    const remaining = points ? Number(points) : NaN
    if (!Number.isFinite(remaining) || remaining < 0) return unknown('未提供当日签到积分')
    return { status: 'pending', remaining, updatedAt, reason: '今日尚无签到记录' }
}
