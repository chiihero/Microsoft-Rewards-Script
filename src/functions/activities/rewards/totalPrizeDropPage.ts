import { createHash } from 'node:crypto'
import { hasSearchRequiredCopy, inspectSignupState } from './instantWinSignup'

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
    | 'retryable_error'
    | 'unavailable'
    | 'claimable'
    | 'needs_registration'
    | 'missing_profile_fields'
    | 'search_required'

export interface PageCta {
    tag: string
    role: string
    text: string
    href: string
    inForm?: boolean
    formAction?: string
    inputType?: string
    contextText?: string
}

export interface FormFieldInventory {
    name: string
    label: string
    type: string
    required: boolean
    hasValue: boolean
    valueLength?: number
    selectedText?: string
    checked?: boolean
    disabled?: boolean
    options?: string[]
}

export interface PrizeDropSnapshot {
    url: string
    title?: string
    visibleText: string
    ctas: PageCta[]
    formFields?: FormFieldInventory[]
}

export interface InstantWinDecision {
    outcome: InstantWinOutcome
    reason: string
    dailyCta: PageCta | null
    blockedFields?: string[]
    signupComplete?: boolean
    challenge?: boolean
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

/**
 * Logged-in CN outer marketing / HVA card. This is NOT an official Check-winner
 * control and must never be selected for the daily auto-claim click.
 */
const CN_DAILY_INSTANT_WIN_CARD =
    /^每天在\s*Bing\s*上搜索，看看您是否中奖(?:\s*(正在进行|已完成|已领取|已查看|已参与))?$/

/** href / form actions that mean signup, login, or legal docs — never auto-click. */
const UNSAFE_DAILY_CTA_HREF =
    /\/sweeps\/signup|aka\.ms\/win-signup|\/auth\/login|login\.live\.com|login\.microsoftonline\.com|official.?rules|aka\.ms\/win-IW-Rules|aka\.ms\/win-SW-Rules/i

/** CTA-local entry-form or additional-terms context. Not applied to the whole page. */
const UNSAFE_DAILY_CTA_CONTEXT =
    /填写报名表|填写参与表单|完成(?:您的)?参赛表格|官方规则|权益说明|查看条款|立即参与|officialRulesAccepted|entry form|additional terms|official rules/i

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
    /^中奖者$/,
    /填写参与表单/,
    /完成参赛表格/,
    /获取您的免费中奖机会/,
    /可用积分/,
    /获得\d+\s*积分/,
    /赚取\d+\s*积分/,
    /获取\s*\d+\s*积分/,
    /获得\s*\d+\s*分/
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
        .replace(/(?:\+?86[\s-]?)?1[3-9]\d{9}/g, '[phone]')
    return normalizeVisibleText(cleaned).slice(0, max)
}

/** Stable anonymous folder name. Never use a raw username or email in evidence paths. */
export function accountEvidenceAlias(userName: string | undefined | null): string {
    const source = String(userName || 'account')
    return `acct-${createHash('sha256').update(source).digest('hex').slice(0, 12)}`
}

export function isOuterDailyMarketingCardText(text: string): boolean {
    return CN_DAILY_INSTANT_WIN_CARD.test(normalizeVisibleText(text))
}

export function isOfficialDailyCheckWinnerText(text: string): boolean {
    const normalized = normalizeVisibleText(text)
    return DAILY_INSTANT_WIN_CTA_TEXTS.some(
        label => normalizeVisibleText(label).toLowerCase() === normalized.toLowerCase()
    )
}

export function dailyInstantWinCtaKind(text: string): 'claimable' | null {
    const normalized = normalizeVisibleText(text)
    if (isForbiddenCtaText(normalized)) return null
    if (isOuterDailyMarketingCardText(normalized)) return null
    if (isOfficialDailyCheckWinnerText(normalized)) return 'claimable'
    return null
}

export function isDailyInstantWinCtaText(text: string): boolean {
    return dailyInstantWinCtaKind(text) === 'claimable'
}

export function isUnsafeDailyClaimCta(cta: PageCta): boolean {
    const href = `${cta.href || ''} ${cta.formAction || ''}`
    if (UNSAFE_DAILY_CTA_HREF.test(href)) return true
    if (cta.inForm) return true
    if ((cta.inputType || '').toLowerCase() === 'submit') return true
    const context = normalizeVisibleText(`${cta.text} ${cta.contextText || ''}`)
    if (UNSAFE_DAILY_CTA_CONTEXT.test(context)) return true
    return false
}

export function isSafeOfficialDailyClaimCta(cta: PageCta): boolean {
    return dailyInstantWinCtaKind(cta.text) === 'claimable' && !isUnsafeDailyClaimCta(cta)
}

export function isForbiddenCtaText(text: string): boolean {
    const normalized = normalizeVisibleText(text)
    return FORBIDDEN_CTA_PATTERNS.some(pattern => pattern.test(normalized))
}

export function isLoginCtaText(text: string): boolean {
    const normalized = normalizeVisibleText(text).toLowerCase()
    const exact = new Set(['sign in', 'signin', 'log in', 'login', '登录'])
    if (exact.has(normalized)) return true
    const phrases = [
        'to claim your free entry, sign in',
        '要领取您的免费参与资格，请登录'
    ]
    return phrases.some(label => normalized.includes(label))
}

export function selectDailyInstantWinCta(ctas: PageCta[]): {
    cta: PageCta | null
    reason: 'unique' | 'none' | 'ambiguous'
    kind: 'claimable' | null
} {
    const matches = ctas
        .filter(cta => isSafeOfficialDailyClaimCta(cta))
        .map(cta => ({ cta, kind: 'claimable' as const }))
    if (matches.length === 1) {
        const item = matches[0]
        return { cta: item?.cta ?? null, reason: 'unique', kind: item?.kind ?? null }
    }
    if (matches.length > 1) return { cta: null, reason: 'ambiguous', kind: null }
    return { cta: null, reason: 'none', kind: null }
}

function hasPattern(text: string, patterns: RegExp[]): boolean {
    return patterns.some(pattern => pattern.test(text))
}

function looksLikeLoginUrl(url: string): boolean {
    return /\/auth\/login|login\.live\.com|login\.microsoftonline\.com/i.test(url)
}


/** CTAs observed after the CN daily card was opened, without a Check-winner control. */
export const EXPANDED_DETAILS_CTA_TEXTS = ['填写报名表', '权益说明', '查看条款'] as const

export function detectExpandedDetailsPanel(before: PrizeDropSnapshot, after: PrizeDropSnapshot): boolean {
    const beforeTexts = new Set(before.ctas.map(cta => normalizeVisibleText(cta.text)))
    const added = after.ctas
        .map(cta => normalizeVisibleText(cta.text))
        .filter(text => text && !beforeTexts.has(text))
    const addedDetails = added.filter(text =>
        EXPANDED_DETAILS_CTA_TEXTS.some(label => text === label || text.includes(label))
    )
    return addedDetails.length > 0
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

    if (selected.cta && selected.kind === 'claimable' && isSafeOfficialDailyClaimCta(selected.cta)) {
        return {
            outcome: 'claimable',
            reason: 'unique official daily Instant Win control is visible',
            dailyCta: selected.cta,
            diagnostics
        }
    }

    const hasLoginCta = snapshot.ctas.some(cta => isLoginCtaText(cta.text))
    if (hasLoginCta || looksLikeLoginUrl(url)) {
        return {
            outcome: 'login_required',
            reason: 'page requires sign-in and no daily Instant Win control is visible',
            dailyCta: null,
            diagnostics
        }
    }

    if (hasSearchRequiredCopy(visible)) {
        return {
            outcome: 'search_required',
            reason: 'page asks for a Bing search before the daily Instant Win chance can be used',
            dailyCta: null,
            diagnostics
        }
    }

    const signup = inspectSignupState({
        url,
        visibleText: visible,
        fields: snapshot.formFields,
        hasOfficialDailyCta: false
    })
    if (signup.challenge) {
        return {
            outcome: 'unverified',
            reason: signup.reason,
            dailyCta: null,
            blockedFields: signup.blockedFields,
            challenge: true,
            diagnostics
        }
    }
    if (signup.signupComplete) {
        return {
            outcome: 'unverified',
            reason: signup.reason,
            dailyCta: null,
            signupComplete: true,
            diagnostics
        }
    }
    if (signup.outcome === 'missing_profile_fields' || signup.outcome === 'needs_registration') {
        return {
            outcome: signup.outcome,
            reason: signup.reason,
            dailyCta: null,
            blockedFields: signup.blockedFields,
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

function enclosingFormMeta(html: string, index: number): { inForm: boolean; formAction: string } {
    const before = html.slice(0, index)
    const lastForm = /<form\b([^>]*)>/gi
    let formAttrs = ''
    let formIndex = -1
    for (const match of before.matchAll(lastForm)) {
        formIndex = match.index ?? -1
        formAttrs = match[1] ?? ''
    }
    if (formIndex < 0) return { inForm: false, formAction: '' }
    const close = before.toLowerCase().lastIndexOf('</form>')
    if (close > formIndex) return { inForm: false, formAction: '' }
    const action = /action\s*=\s*["']([^"']*)["']/i.exec(formAttrs)?.[1] ?? ''
    return { inForm: true, formAction: action }
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
        const inputType = /type\s*=\s*["']([^"']*)["']/i.exec(attrs)?.[1] ?? ''
        const form = enclosingFormMeta(html, match.index ?? 0)
        ctas.push({ tag, role, text, href, inForm: form.inForm, formAction: form.formAction, inputType })
    }
    return ctas
}

export function extractFormFieldsFromHtml(html: string): FormFieldInventory[] {
    const fields: FormFieldInventory[] = []
    const pattern = /<(input|select|textarea)([^>]*)>/gi
    for (const match of html.matchAll(pattern)) {
        const tag = (match[1] || '').toLowerCase()
        const attrs = match[2] ?? ''
        const name = /name\s*=\s*["']([^"']*)["']/i.exec(attrs)?.[1] ?? ''
        const type = /type\s*=\s*["']([^"']*)["']/i.exec(attrs)?.[1] ?? tag
        const required = /\brequired\b/i.test(attrs)
        const disabled = /\bdisabled\b/i.test(attrs)
        const rawValue = /value\s*=\s*["']([^"']*)["']/i.exec(attrs)?.[1] ?? ''
        let options: string[] = []
        let selectedText = ''
        if (tag === 'select') {
            const start = match.index ?? 0
            const close = html.toLowerCase().indexOf('</select>', start)
            const inner = close > start ? html.slice(start, close + 9) : ''
            options = Array.from(inner.matchAll(/<option[^>]*>([\s\S]*?)<\/option>/gi)).map(item =>
                normalizeVisibleText(item[1] || '')
            ).filter(Boolean)
            const selected = /<option[^>]*selected[^>]*>([\s\S]*?)<\/option>/i.exec(inner) || /<option[^>]*>([\s\S]*?)<\/option>/i.exec(inner)
            selectedText = selected ? normalizeVisibleText(selected[1] || '') : ''
        }
        fields.push({
            name,
            label: name,
            type: type.toLowerCase(),
            required,
            hasValue: Boolean(rawValue || (tag === 'select' && selectedText)),
            valueLength: rawValue ? rawValue.length : selectedText ? selectedText.length : 0,
            selectedText,
            disabled,
            options: options.length ? options : undefined
        })
    }
    return fields
}

export function snapshotFromHtml(html: string, url = TOTAL_PRIZE_DROP_URL): PrizeDropSnapshot {
    const withoutNoise = html.replace(/<(script|style)[^>]*>[\s\S]*?<\/\1>/gi, ' ')
    const title = /<title[^>]*>([\s\S]*?)<\/title>/i.exec(withoutNoise)?.[1]
    const visibleText = normalizeVisibleText(withoutNoise.replace(/<[^>]+>/g, ' '))
    return {
        url,
        title: title ? normalizeVisibleText(title) : undefined,
        visibleText,
        ctas: extractCtasFromHtml(html),
        formFields: extractFormFieldsFromHtml(withoutNoise)
    }
}
