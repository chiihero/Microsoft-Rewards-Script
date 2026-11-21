/**
 * Public Instant Win status, same-day persistence, and receipt kind.
 * Records are redacted: no names, emails, phones, or usernames.
 */
import { chmodSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import type { InstantWinOutcome } from './totalPrizeDropPage'

export type InstantWinPublicStatus =
    | 'needs_registration'
    | 'missing_profile_fields'
    | 'login_required'
    | 'ineligible'
    | 'search_required'
    | 'available'
    | 'confirmed'
    | 'unverified'
    | 'retryable_error'
    | 'unavailable'

export type InstantWinReceiptKind = 'won' | 'lost' | 'already_claimed'

export interface InstantWinStatusRecord {
    date: string
    outcome: InstantWinOutcome
    publicStatus: InstantWinPublicStatus
    receiptKind?: InstantWinReceiptKind
    reason: string
    clicked: boolean
    blockedFields?: string[]
    signupComplete?: boolean
    attempts: number
    diagnose?: boolean
}

export function instantWinTodayKey(now = new Date(), timeZone = process.env.TZ || 'Asia/Shanghai'): string {
    return new Intl.DateTimeFormat('en-CA', {
        timeZone,
        year: 'numeric',
        month: '2-digit',
        day: '2-digit'
    }).format(now)
}

export function toPublicStatus(outcome: InstantWinOutcome): InstantWinPublicStatus {
    switch (outcome) {
        case 'claimable':
            return 'available'
        case 'claimed':
        case 'already_claimed':
            return 'confirmed'
        case 'error':
        case 'retryable_error':
            return 'retryable_error'
        case 'needs_registration':
        case 'missing_profile_fields':
        case 'login_required':
        case 'ineligible':
        case 'search_required':
        case 'unverified':
        case 'unavailable':
            return outcome
        default:
            return 'unverified'
    }
}

const WON_PATTERNS: RegExp[] = [
    /congratulations[,!.]? you (won|are a winner)/i,
    /you (won|are) (an? )?(instant )?prize/i,
    /恭喜.{0,8}(中奖|获奖)/
]

const LOST_PATTERNS: RegExp[] = [
    /you are not a winner today/i,
    /you didn't win today/i,
    /you did not win today/i,
    /better luck (next time|tomorrow)/i,
    /sorry[,!.]? you (did not|didn't) win/i,
    /thanks for playing[.!]? (come back )?tomorrow/i,
    /今天(没有|未)(中奖|获奖)/,
    /很遗憾.{0,8}(未中奖|没有中奖)/,
    /谢谢参与.{0,12}明天/
]

export function receiptKindFrom(outcome: InstantWinOutcome, text: string): InstantWinReceiptKind | undefined {
    if (outcome === 'already_claimed') return 'already_claimed'
    if (outcome !== 'claimed') return undefined
    if (WON_PATTERNS.some(pattern => pattern.test(text))) return 'won'
    if (LOST_PATTERNS.some(pattern => pattern.test(text))) return 'lost'
    return undefined
}

export function isConfirmedOutcome(outcome: InstantWinOutcome): boolean {
    return outcome === 'claimed' || outcome === 'already_claimed'
}

/** Same-day blocked input is observable and must not infinite-retry clicks or submits. */
export function isBlockedPendingInput(outcome: InstantWinOutcome): boolean {
    return outcome === 'needs_registration' || outcome === 'missing_profile_fields'
}

/**
 * Skip another official Check-winner click or signup submit today.
 * Cross-day records are ignored so the page can be classified again.
 */
export function shouldSkipSameDayAction(state: InstantWinStatusRecord | null, today: string): boolean {
    if (!state || state.date !== today) return false
    if (state.diagnose) return false
    // Missing registration is observable and must not infinite-retry submits, but it
    // must not hide a later official Check-winner control on the same day.
    if (isConfirmedOutcome(state.outcome)) return true
    if (state.clicked) return true
    return false
}

export function buildStatusRecord(input: {
    outcome: InstantWinOutcome
    reason: string
    clicked: boolean
    visibleText?: string
    blockedFields?: string[]
    signupComplete?: boolean
    attempts?: number
    diagnose?: boolean
    previous?: InstantWinStatusRecord | null
    now?: Date
}): InstantWinStatusRecord {
    const date = instantWinTodayKey(input.now)
    const previous = input.previous && input.previous.date === date ? input.previous : null
    return {
        date,
        outcome: input.outcome,
        publicStatus: toPublicStatus(input.outcome),
        receiptKind: receiptKindFrom(input.outcome, `${input.reason} ${input.visibleText || ''}`),
        reason: input.reason,
        clicked: Boolean(input.clicked || previous?.clicked),
        blockedFields: input.blockedFields,
        signupComplete: Boolean(input.signupComplete || previous?.signupComplete),
        attempts: (previous?.attempts || 0) + (input.attempts ?? 1),
        diagnose: input.diagnose
    }
}

export function stateFilePath(dir: string, alias: string): string {
    return join(dir, `${alias}.json`)
}

export function loadStatusRecord(dir: string, alias: string): InstantWinStatusRecord | null {
    try {
        const raw = readFileSync(stateFilePath(dir, alias), 'utf8')
        const parsed = JSON.parse(raw) as InstantWinStatusRecord
        if (!parsed || typeof parsed.outcome !== 'string' || typeof parsed.date !== 'string') return null
        return parsed
    } catch {
        return null
    }
}

export function saveStatusRecord(dir: string, alias: string, record: InstantWinStatusRecord): void {
    mkdirSync(dir, { recursive: true, mode: 0o700 })
    const path = stateFilePath(dir, alias)
    const tmp = `${path}.tmp`
    writeFileSync(tmp, JSON.stringify(record, null, 2))
    try {
        chmodSync(dir, 0o700)
        chmodSync(tmp, 0o600)
    } catch {
        // best-effort
    }
    renameSync(tmp, path)
    try {
        chmodSync(path, 0o600)
    } catch {
        // best-effort
    }
}

/** A same-day official click or submit attempt must not be retried even if the later receipt read fails. */
export function clickedAfterExecutionError(clickAttemptCommitted: boolean, previousClicked = false): boolean {
    return Boolean(clickAttemptCommitted || previousClicked)
}

export function defaultStatusDir(): string {
    return process.env.DAILY_INSTANT_WIN_STATE_DIR || '/tmp/rewards-instant-win-state'
}
