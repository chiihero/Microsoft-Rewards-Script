/**
 * One-time Instant Win entry-form helpers. Separate from the daily Check-winner click.
 * Never log or return raw profile values. Unknown challenges fail closed.
 */
import type { FormFieldInventory } from './totalPrizeDropPage'

export const SIGNUP_URL_PATTERN = /\/sweeps\/signup|aka\.ms\/win-signup/i

export const NEEDS_REGISTRATION_PATTERNS: RegExp[] = [
    /首先[，,]?完成您的参赛表格/,
    /要参与，请填写报名表/,
    /complete (your )?(the )?entry form/i,
    /填写报名表/,
    /填写参与表单/,
    /完成参赛表格/
]

export const SIGNUP_SUCCESS_PATTERNS: RegExp[] = [
    /thanks for entering/i,
    /you('re| are) (now )?entered/i,
    /entry (has been |was )?submitted/i,
    /报名成功/,
    /已完成报名/,
    /已提交报名/,
    /参赛表格已提交/,
    /您已完成参赛表格/
]

export const SEARCH_REQUIRED_PATTERNS: RegExp[] = [
    /complete (a |one )?bing search (first|today|to (enter|play|check))?/i,
    /search on bing (at least )?once/i,
    /先(在)?\s*Bing\s*上搜索/,
    /请先(在)?\s*Bing\s*(上)?搜索/
]

export const CHALLENGE_PATTERNS: RegExp[] = [
    /verification code/i,
    /one[- ]time (code|password|passcode)/i,
    /enter the code (we sent|you received)/i,
    /sms (code|verification)/i,
    /two[- ]factor/i,
    /密码/,
    /验证码/,
    /短信验证/,
    /手机验证码/
]

const CONTACT_FIELD_NAMES = new Set(['phonecountrycode', 'nationalphonenumber', 'phone', 'email', 'firstname', 'lastname'])

export function looksLikeSignupUrl(url: string): boolean {
    return SIGNUP_URL_PATTERN.test(url || '')
}

export function hasNeedsRegistrationCopy(text: string): boolean {
    return NEEDS_REGISTRATION_PATTERNS.some(pattern => pattern.test(text || ''))
}

export function isSignupSuccessReceipt(text: string): boolean {
    return SIGNUP_SUCCESS_PATTERNS.some(pattern => pattern.test(text || ''))
}

export function hasSearchRequiredCopy(text: string): boolean {
    return SEARCH_REQUIRED_PATTERNS.some(pattern => pattern.test(text || ''))
}

export function detectAuthChallenge(text: string, fields: FormFieldInventory[] = []): boolean {
    if (CHALLENGE_PATTERNS.some(pattern => pattern.test(text || ''))) return true
    return fields.some(field => {
        const type = (field.type || '').toLowerCase()
        const name = `${field.name} ${field.label}`.toLowerCase()
        return type === 'password' || name.includes('otp') || name.includes('验证码') || type === 'one-time-code'
    })
}

export function missingRequiredFieldNames(fields: FormFieldInventory[] = []): string[] {
    const missing: string[] = []
    for (const field of fields) {
        if (!field.required) continue
        const type = (field.type || '').toLowerCase()
        if (type === 'submit' || type === 'button' || type === 'checkbox') continue
        if (field.hasValue) continue
        missing.push(field.name || field.label || field.type)
    }
    return missing
}

export function countryOptionsIncludeChina(options: string[] = []): boolean {
    return options.some(option => /^(cn|china|中国)$/i.test(String(option).trim()) || String(option).includes('中国'))
}

export function isAllowedAuthorizedResidence(value: string): boolean {
    return /^(cn|china|中国)$/i.test(String(value || '').trim())
}

export interface SignupInspection {
    outcome: 'missing_profile_fields' | 'needs_registration' | 'registration_complete' | null
    reason: string
    blockedFields: string[]
    signupComplete: boolean
    challenge: boolean
}

export function inspectSignupState(input: {
    url: string
    visibleText: string
    fields?: FormFieldInventory[]
    hasOfficialDailyCta?: boolean
}): SignupInspection {
    const challenge = detectAuthChallenge(input.visibleText, input.fields)
    if (challenge) {
        return {
            outcome: null,
            reason: 'page_requires_additional_verification',
            blockedFields: ['additional_verification'],
            signupComplete: false,
            challenge: true
        }
    }
    if (isSignupSuccessReceipt(input.visibleText)) {
        return {
            outcome: 'registration_complete',
            reason: 'signup success receipt is visible; not a daily Instant Win result',
            blockedFields: [],
            signupComplete: true,
            challenge: false
        }
    }
    const onSignup = looksLikeSignupUrl(input.url) || (input.fields || []).some(field =>
        CONTACT_FIELD_NAMES.has(String(field.name || '').toLowerCase())
    )
    const missing = missingRequiredFieldNames(input.fields)
    if (onSignup && missing.length > 0) {
        return {
            outcome: 'missing_profile_fields',
            reason: 'signup form is visible and required profile fields are empty',
            blockedFields: missing,
            signupComplete: false,
            challenge: false
        }
    }
    if (!input.hasOfficialDailyCta && (onSignup || hasNeedsRegistrationCopy(input.visibleText))) {
        return {
            outcome: 'needs_registration',
            reason: 'page asks for the one-time entry form and no official daily Check-winner control is visible',
            blockedFields: [],
            signupComplete: false,
            challenge: false
        }
    }
    return {
        outcome: null,
        reason: '',
        blockedFields: [],
        signupComplete: false,
        challenge: false
    }
}
