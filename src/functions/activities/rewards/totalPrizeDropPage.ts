/**
 * Visible-state helpers for the Total Prize Drop daily Instant Win page.
 * Only official/public wording is used as click or receipt targets.
 * Unknown page states stay unverified and are never treated as claimed.
 */

export const TOTAL_PRIZE_DROP_URL = 'https://rewards.bing.com/sweeps/bonus'

export type InstantWinOutcome =
    | 'claimed'
    | 'already_claimed'
    | 'ineligible'
    | 'login_required'
    | 'unverified'
    | 'error'
    | 'unavailable'
    | 'claimable'

export interface PageCta {
    tag: string
    role: string
    text: string
    href: string
}

export interface PrizeDropSnapshot {
    url: string
    title?: string
    visibleText: string
    ctas: PageCta[]
}

export interface InstantWinDecision {
    outcome: InstantWinOutcome
    reason: string
    dailyCta: PageCta | null
    diagnostics: {
        url: string
        title?: string
        ctaTexts: string[]
        visibleExcerpt: string
    }
}

/** Official English FAQ: tap “Check if you’re a winner”. */
export const DAILY_INSTANT_WIN_CTA_TEXTS = [
    "Check if you're a winner",
    'Check if you’re a winner',
    '查看你是否成为即时获奖者'
] as const

/** Public signed-out login CTAs on /sweeps/bonus. Not daily Instant Win controls. */
const LOGIN_CTA_TEXTS = [
    'sign in',
    '登录',
    'to claim your free entry, sign in',
    '要领取您的免费参与资格，请登录'
] as const

/** One-time entry / bonus-activity CTAs that must never be clicked. */
const FORBIDDEN_CTA_PATTERNS: RegExp[] = [
    /claim your free entry/i,
    /领取您的免费参赛资格/,
    /领取您的免费参与资格/,
    /trade in 1,?000 points/i,
    /兑换\s*1,?000\s*积分/,
    /install rewards extension/i,
    /安装rewards扩展/,
    /download the microsoft rewards desktop app/i,
    /下载microsoft rewards桌面应用/,
    /install bing wallpaper/i,
    /安装必应壁纸/,
    /set edge as default/i,
    /将 edge 设为默认/,
    /microsoft 365/i,
    /spend \$25/i,
    /在 microsoft 商城消费/,
    /set bing on mobile/i,
    /在移动设备上设置 bing/,
    /windows backup/i,
    /windows 备份/,
    /browse with edge/i,
    /使用 edge 浏览/,
    /daily set/i,
    /每日套装/,
    /official rules/i,
    /官方规则/,
    /^winners$/i,
    /^中奖者$/
]

const UNAVAILABLE_PATTERNS: RegExp[] = [
    /promotion has ended/i,
    /this promotion is over/i,
    /no longer available/i,
    /活动已结束/,
    /活动已过期/,
    /不再提供/
]

const INELIGIBLE_PATTERNS: RegExp[] = [
    /not eligible/i,
    /you('re| are) not eligible/i,
    /not available in your (region|country|market)/i,
    /不符合(参加|参与)?条件/,
    /所在(地区|国家|市场).{0,12}(不可用|不适用|无法参加|无法参与)/
]

/** Confirmed already-used-today receipts only. Unknown “maybe done” text stays unverified. */
const ALREADY_CLAIMED_PATTERNS: RegExp[] = [
    /already (used|played|claimed|checked) (today'?s |today )?((instant )?win(ner)? )?chance/i,
    /you('ve| have) already (played|tried|checked) today/i,
    /come back tomorrow to (play|try|check)/i,
    /today'?s (instant win )?chance (has )?already (been )?(used|played|claimed)/i,
    /今天(的)?(即时赢|即时中奖|机会)?.{0,8}已经(使用|领取|抽过|玩过|尝试)/,
    /请明天再(来|试|查看)/,
    /明天再来(尝试|查看)?/
]

/** Clear post-click receipts that the daily chance was consumed. */
const CLAIMED_RECEIPT_PATTERNS: RegExp[] = [
    /congratulations[,!.]? you (won|are a winner)/i,
    /you (won|are) (an? )?(instant )?prize/i,
    /you are not a winner today/i,
    /you didn't win today/i,
    /you did not win today/i,
    /better luck (next time|tomorrow)/i,
    /sorry[,!.]? you (did not|didn't) win/i,
    /thanks for playing[.!]? (come back )?tomorrow/i,
    /恭喜.{0,8}(中奖|获奖)/,
    /今天(没有|未)(中奖|获奖)/,
    /很遗憾.{0,8}(未中奖|没有中奖)/,
    /谢谢参与.{0,12}明天/
]

export function normalizeVisibleText(text: string): string {
    return text
        .replace(/\u00a0/g, ' ')
        .replace(/[’‘]/g, "'")
        .replace(/\s+/g, ' ')
        .trim()
}

export function redactDiagnostics(text: string, max = 400): string {
    const cleaned = text
        .replace(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, '[alias]')
        .replace(/(authorization|token|cookie|password)=\S+/gi, '$1=[redacted]')
        .replace(/eyJ[\w\-.=]+/g, '[redacted]')
    return normalizeVisibleText(cleaned).slice(0, max)
}

export function isDailyInstantWinCtaText(text: string): boolean {
    const normalized = normalizeVisibleText(text).toLowerCase()
    return DAILY_INSTANT_WIN_CTA_TEXTS.some(label => normalizeVisibleText(label).toLowerCase() === normalized)
}

export function isForbiddenCtaText(text: string): boolean {
    const normalized = normalizeVisibleText(text)
    if (isDailyInstantWinCtaText(normalized)) return false
    return FORBIDDEN_CTA_PATTERNS.some(pattern => pattern.test(normalized))
}

export function isLoginCtaText(text: string): boolean {
    const normalized = normalizeVisibleText(text).toLowerCase()
    return LOGIN_CTA_TEXTS.some(label => normalized === label || normalized.includes(label))
}

export function selectDailyInstantWinCta(ctas: PageCta[]): {
    cta: PageCta | null
    reason: 'unique' | 'none' | 'ambiguous'
} {
    const matches = ctas.filter(cta => isDailyInstantWinCtaText(cta.text) && !isForbiddenCtaText(cta.text))
    if (matches.length === 1) return { cta: matches[0] ?? null, reason: 'unique' }
    if (matches.length > 1) return { cta: null, reason: 'ambiguous' }
    return { cta: null, reason: 'none' }
}

function hasPattern(text: string, patterns: RegExp[]): boolean {
    return patterns.some(pattern => pattern.test(text))
}

function looksLikeLoginUrl(url: string): boolean {
    return /\/auth\/login|login\.live\.com|login\.microsoftonline\.com/i.test(url)
}

export function classifyPrizeDropSnapshot(snapshot: PrizeDropSnapshot): InstantWinDecision {
    const visible = normalizeVisibleText(snapshot.visibleText)
    const url = snapshot.url || ''
    const ctaTexts = snapshot.ctas.map(cta => redactDiagnostics(cta.text, 120)).filter(Boolean)
    const diagnostics = {
        url: redactDiagnostics(url, 200),
        title: snapshot.title ? redactDiagnostics(snapshot.title, 160) : undefined,
        ctaTexts,
        visibleExcerpt: redactDiagnostics(visible, 400)
    }

    const selected = selectDailyInstantWinCta(snapshot.ctas)
    if (selected.reason === 'ambiguous') {
        return {
            outcome: 'unverified',
            reason: 'multiple daily Instant Win controls were visible; fail closed',
            dailyCta: null,
            diagnostics
        }
    }

    if (hasPattern(visible, UNAVAILABLE_PATTERNS)) {
        return {
            outcome: 'unavailable',
            reason: 'page states the promotion is ended or unavailable',
            dailyCta: null,
            diagnostics
        }
    }

    if (hasPattern(visible, INELIGIBLE_PATTERNS)) {
        return {
            outcome: 'ineligible',
            reason: 'page states this account or market is not eligible',
            dailyCta: null,
            diagnostics
        }
    }

    if (hasPattern(visible, ALREADY_CLAIMED_PATTERNS) && !selected.cta) {
        return {
            outcome: 'already_claimed',
            reason: 'page shows a confirmed already-used-today Instant Win receipt',
            dailyCta: null,
            diagnostics
        }
    }

    if (hasPattern(visible, CLAIMED_RECEIPT_PATTERNS) && !selected.cta) {
        return {
            outcome: 'claimed',
            reason: 'page shows a confirmed Instant Win result receipt',
            dailyCta: null,
            diagnostics
        }
    }

    if (selected.cta) {
        return {
            outcome: 'claimable',
            reason: 'unique official daily Instant Win control is visible',
            dailyCta: selected.cta,
            diagnostics
        }
    }

    const hasLoginCta = snapshot.ctas.some(cta => isLoginCtaText(cta.text) || looksLikeLoginUrl(cta.href))
    if (hasLoginCta || looksLikeLoginUrl(url)) {
        return {
            outcome: 'login_required',
            reason: 'page requires sign-in and no daily Instant Win control is visible',
            dailyCta: null,
            diagnostics
        }
    }

    return {
        outcome: 'unverified',
        reason: 'no official daily Instant Win control or confirmed receipt was visible',
        dailyCta: null,
        diagnostics
    }
}

export function extractCtasFromHtml(html: string): PageCta[] {
    const ctas: PageCta[] = []
    const pattern = /<(a|button)([^>]*)>([\s\S]*?)<\/\1>/gi
    for (const match of html.matchAll(pattern)) {
        const rawTag = match[1]
        const attrs = match[2] ?? ''
        const inner = match[3]
        if (!rawTag || inner === undefined) continue
        const tag = rawTag.toLowerCase()
        const text = normalizeVisibleText(inner.replace(/<[^>]+>/g, ' '))
        if (!text || text.length > 180) continue
        const href = /href\s*=\s*["']([^"']*)["']/i.exec(attrs)?.[1] ?? ''
        const role = /role\s*=\s*["']([^"']*)["']/i.exec(attrs)?.[1] ?? (tag === 'button' ? 'button' : 'link')
        ctas.push({ tag, role, text, href })
    }
    return ctas
}

export function snapshotFromHtml(html: string, url = TOTAL_PRIZE_DROP_URL): PrizeDropSnapshot {
    const withoutNoise = html.replace(/<(script|style)[^>]*>[\s\S]*?<\/\1>/gi, ' ')
    const title = /<title[^>]*>([\s\S]*?)<\/title>/i.exec(withoutNoise)?.[1]
    const visibleText = normalizeVisibleText(withoutNoise.replace(/<[^>]+>/g, ' '))
    return {
        url,
        title: title ? normalizeVisibleText(title) : undefined,
        visibleText,
        ctas: extractCtasFromHtml(html)
    }
}
