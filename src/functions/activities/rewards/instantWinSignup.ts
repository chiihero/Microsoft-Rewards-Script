/**
 * One-time Instant Win entry-form helpers and an explicit signup-only planner.
 * Separate from the daily Check-winner click. Daily Instant Win must never
 * auto-register. Never log or return raw profile values. Unknown challenges,
 * unknown required fields, and unsupported countries fail closed.
 */
import { chmodSync, lstatSync, readFileSync } from 'node:fs'
import type { FormFieldInventory, PageCta, PrizeDropSnapshot } from './totalPrizeDropPage'

function normalizeVisibleText(text: string): string {
    return text
        .replace(/\u00a0/g, ' ')
        .replace(/[’‘]/g, "'")
        .replace(/\s+/g, ' ')
        .trim()
}

function redactDiagnostics(text: string, max = 80): string {
    const cleaned = text
        .replace(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, '[alias]')
        .replace(/(authorization|token|cookie|password)=\S+/gi, '$1=[redacted]')
        .replace(/(?:\+?86[\s-]?)?1[3-9]\d{9}/g, '[phone]')
    return normalizeVisibleText(cleaned).slice(0, max)
}

export const SIGNUP_URL = 'https://rewards.bing.com/sweeps/signup'
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

export const ALREADY_ENTERED_PATTERNS: RegExp[] = [
    /you (have )?already (entered|registered|signed up)/i,
    /already completed (your )?entry/i,
    /您已(经)?(完成)?报名/,
    /已经完成报名/,
    /已登记(参赛)?/
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

export const CAPTCHA_PATTERNS: RegExp[] = [
    /recaptcha/i,
    /h-?captcha/i,
    /funcaptcha/i,
    /arkose/i,
    /\[data-sitekey\]/,
    /图形验证/,
    /滑动验证/,
    /请完成(安全|人机)?验证/
]

export const OFFICIAL_SIGNUP_SUBMIT_TEXTS = ['立即参与', 'Submit', 'Enter now', '提交报名', '提交参赛表格'] as const

const CONTACT_FIELD_NAMES = new Set(['phonecountrycode', 'nationalphonenumber', 'phone', 'email', 'firstname', 'lastname'])
const FILLABLE_FIELD_NAMES = new Set([
    'phonecountrycode',
    'nationalphonenumber',
    'phone',
    'country',
    'countryofresidence',
    'residence',
    'officialrulesaccepted'
])
const PREFILL_ONLY_FIELD_NAMES = new Set(['firstname', 'lastname', 'email'])
const IDENTITY_PROFILE_KEYS = new Set([
    'firstname',
    'lastname',
    'email',
    'name',
    'address',
    'birthday',
    'birthdate',
    'age',
    'dob'
])

export function looksLikeSignupUrl(url: string): boolean {
    return SIGNUP_URL_PATTERN.test(url || '')
}

export function hasNeedsRegistrationCopy(text: string): boolean {
    return NEEDS_REGISTRATION_PATTERNS.some(pattern => pattern.test(text || ''))
}

export function isSignupSuccessReceipt(text: string): boolean {
    return SIGNUP_SUCCESS_PATTERNS.some(pattern => pattern.test(text || ''))
}

export function isAlreadyEnteredCopy(text: string): boolean {
    return ALREADY_ENTERED_PATTERNS.some(pattern => pattern.test(text || ''))
}

export function hasSearchRequiredCopy(text: string): boolean {
    return SEARCH_REQUIRED_PATTERNS.some(pattern => pattern.test(text || ''))
}

export function detectCaptchaChallenge(text: string, fields: FormFieldInventory[] = []): boolean {
    if (CAPTCHA_PATTERNS.some(pattern => pattern.test(text || ''))) return true
    return fields.some(field => {
        const blob = `${field.name} ${field.label} ${field.type}`.toLowerCase()
        return /captcha|recaptcha|hcaptcha|funcaptcha|arkose/.test(blob)
    })
}

export function detectAuthChallenge(text: string, fields: FormFieldInventory[] = []): boolean {
    if (CHALLENGE_PATTERNS.some(pattern => pattern.test(text || ''))) return true
    if (detectCaptchaChallenge(text, fields)) return true
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

export function isDefaultUsResidence(value: string): boolean {
    const normalized = normalizeVisibleText(value || '')
    return /^(us|usa|united states|美国)$/i.test(normalized)
}

export function isOfficialSignupSubmitCta(cta: Pick<PageCta, 'text' | 'href' | 'inForm' | 'inputType' | 'tag'>): boolean {
    const text = normalizeVisibleText(cta.text || '')
    if (!OFFICIAL_SIGNUP_SUBMIT_TEXTS.some(label => normalizeVisibleText(label) === text)) return false
    if (/\/sweeps\/bonus|aka\.ms\/win-/i.test(`${cta.href || ''}`)) return false
    const type = (cta.inputType || '').toLowerCase()
    return type === 'submit' || Boolean(cta.inForm) || (cta.tag || '').toLowerCase() === 'button'
}

export function selectOfficialSignupSubmitCta(ctas: PageCta[]): { cta: PageCta | null; reason: 'unique' | 'none' | 'ambiguous' } {
    const matches = (ctas || []).filter(cta => isOfficialSignupSubmitCta(cta))
    if (matches.length === 1) return { cta: matches[0] ?? null, reason: 'unique' }
    if (matches.length > 1) return { cta: null, reason: 'ambiguous' }
    return { cta: null, reason: 'none' }
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
    if (isSignupSuccessReceipt(input.visibleText) || isAlreadyEnteredCopy(input.visibleText)) {
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

export interface InstantWinSignupProfile {
    residence: string
    phoneCountryCode: string
    nationalPhoneNumber: string
}

export type SignupPlanAction = 'submit' | 'stop' | 'already_registered'

export interface SignupFillIntent {
    field: string
    kind: 'select-country' | 'phone-country-code' | 'national-phone' | 'accept-terms'
    option?: string
}

export interface SignupPlan {
    action: SignupPlanAction
    outcome:
        | 'needs_registration'
        | 'missing_profile_fields'
        | 'registration_complete'
        | 'ineligible'
        | 'unverified'
        | 'login_required'
    reason: string
    blockedFields: string[]
    fills: SignupFillIntent[]
    submitText?: string
    challenge: boolean
    signupComplete: boolean
}

const EMPTY_STOP: Omit<SignupPlan, 'reason' | 'blockedFields' | 'outcome'> = {
    action: 'stop',
    fills: [],
    challenge: false,
    signupComplete: false
}

export function maskPhoneNumber(value: string): string {
    const digits = String(value || '').replace(/\D/g, '')
    if (!digits) return '[phone]'
    if (digits.length < 7) return '[phone]'
    return `${digits.slice(0, 2)}****${digits.slice(-2)}`
}

export function redactSignupValue(field: string, value: string): string {
    const name = field.toLowerCase()
    if (name.includes('phone') || name === 'nationalphonenumber' || name === 'phonecountrycode') {
        return maskPhoneNumber(value)
    }
    return redactDiagnostics(value, 80)
}

export function normalizeAuthorizedPhoneCountryCode(value: string): string | null {
    const compact = String(value || '').trim().replace(/\s+/g, '')
    if (/^\+?86$/.test(compact) || compact === '0086') return '+86'
    if (/^(cn|china|中国)$/i.test(compact)) return '+86'
    return null
}

export function isAuthorizedCnMobile(value: string): boolean {
    return /^1[3-9]\d{9}$/.test(String(value || '').trim())
}

function fieldKey(field: FormFieldInventory): string {
    return String(field.name || field.label || field.type || '').trim()
}

function fieldName(field: FormFieldInventory): string {
    return String(field.name || '').trim().toLowerCase()
}

function isPrefillOnlyField(field: FormFieldInventory): boolean {
    const name = fieldName(field)
    const type = (field.type || '').toLowerCase()
    return PREFILL_ONLY_FIELD_NAMES.has(name) || type === 'email'
}

function isTermsField(field: FormFieldInventory): boolean {
    const name = fieldName(field)
    const label = `${field.label || ''}`.toLowerCase()
    return name === 'officialrulesaccepted' || /官方规则|official rules|age of majority|成年/.test(label)
}

function isCountryField(field: FormFieldInventory): boolean {
    const name = fieldName(field)
    return name === 'country' || name === 'countryofresidence' || name === 'residence'
}

function isPhoneCountryField(field: FormFieldInventory): boolean {
    return fieldName(field) === 'phonecountrycode'
}

function isNationalPhoneField(field: FormFieldInventory): boolean {
    const name = fieldName(field)
    const type = (field.type || '').toLowerCase()
    return name === 'nationalphonenumber' || name === 'phone' || type === 'tel'
}

function chinaOptionFrom(options: string[] = []): string | null {
    const exact = options.find(option => /^(cn|china|中国)$/i.test(String(option).trim()) || /^中国/.test(String(option).trim()))
    if (exact) return exact
    const includes = options.find(option => String(option).includes('中国'))
    return includes || null
}

function phoneCodeOptionFrom(options: string[] = []): string | null {
    const match = options.find(option => normalizeAuthorizedPhoneCountryCode(option) === '+86' || String(option).includes('中国'))
    return match || null
}

export function loadSignupProfileFromFile(filePath: string): { profile?: InstantWinSignupProfile; error?: string } {
    if (!filePath) return { error: 'signup profile path is empty' }
    let stat
    try {
        stat = lstatSync(filePath)
    } catch {
        return { error: 'signup profile file is missing' }
    }
    if (!stat.isFile() || stat.isSymbolicLink()) {
        return { error: 'signup profile must be a regular file' }
    }
    if ((stat.mode & 0o077) !== 0) {
        return { error: 'signup profile file must not be group- or world-accessible (use mode 0600)' }
    }
    try {
        chmodSync(filePath, 0o600)
    } catch {
        // best-effort
    }
    let parsed: Record<string, unknown>
    try {
        parsed = JSON.parse(readFileSync(filePath, 'utf8')) as Record<string, unknown>
    } catch {
        return { error: 'signup profile is not valid JSON' }
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        return { error: 'signup profile is empty' }
    }
    const unexpected = Object.keys(parsed).filter(key => IDENTITY_PROFILE_KEYS.has(key.toLowerCase()))
    if (unexpected.length > 0) {
        return { error: 'signup profile must not include name, email, address, or birthday fields' }
    }
    const residence = String(parsed.residence ?? parsed.country ?? '').trim()
    const phoneCountryCode = String(parsed.phoneCountryCode ?? '').trim()
    const nationalPhoneNumber = String(parsed.nationalPhoneNumber ?? '').trim()
    if (!residence && !phoneCountryCode && !nationalPhoneNumber) {
        return { error: 'signup profile has no contact fields' }
    }
    if (!isAllowedAuthorizedResidence(residence)) {
        return { error: 'signup profile residence is not the authorized China value' }
    }
    if (!normalizeAuthorizedPhoneCountryCode(phoneCountryCode)) {
        return { error: 'signup profile phoneCountryCode is not the authorized +86 value' }
    }
    if (!isAuthorizedCnMobile(nationalPhoneNumber)) {
        return { error: 'signup profile nationalPhoneNumber failed the authorized CN mobile pattern' }
    }
    return {
        profile: {
            residence: 'CN',
            phoneCountryCode: '+86',
            nationalPhoneNumber
        }
    }
}

export function planSignupSubmit(input: {
    snapshot: PrizeDropSnapshot
    profile?: InstantWinSignupProfile | null
    profileError?: string
    enabled?: boolean
    alreadySubmitted?: boolean
}): SignupPlan {
    const snapshot = input.snapshot
    const visible = snapshot.visibleText || ''
    const fields = snapshot.formFields || []
    const ctas = snapshot.ctas || []

    if (!input.enabled) {
        return {
            ...EMPTY_STOP,
            outcome: 'unverified',
            reason: 'signup runner is disabled unless DAILY_INSTANT_WIN_SIGNUP=1',
            blockedFields: []
        }
    }

    const inspection = inspectSignupState({
        url: snapshot.url,
        visibleText: visible,
        fields,
        hasOfficialDailyCta: false
    })
    if (inspection.challenge) {
        return {
            ...EMPTY_STOP,
            outcome: 'unverified',
            reason: 'stop: signup page requires OTP, password, or captcha; not read, not screenshotted, not guessed',
            blockedFields: inspection.blockedFields,
            challenge: true
        }
    }
    if (inspection.signupComplete || isSignupSuccessReceipt(visible) || isAlreadyEnteredCopy(visible)) {
        return {
            action: 'already_registered',
            outcome: 'registration_complete',
            reason: 'signup receipt already present; not submitting again; this is not a daily Instant Win receipt',
            blockedFields: [],
            fills: [],
            challenge: false,
            signupComplete: true
        }
    }

    if (input.alreadySubmitted) {
        return {
            ...EMPTY_STOP,
            outcome: 'unverified',
            reason: 'a signup submit was already attempted without a success receipt; not submitting again',
            blockedFields: []
        }
    }

    if (!input.profile) {
        return {
            ...EMPTY_STOP,
            outcome: 'missing_profile_fields',
            reason: input.profileError || 'signup profile is empty; never submit',
            blockedFields: ['signup_profile']
        }
    }

    const unknownRequired = fields
        .filter(field => field.required)
        .filter(field => {
            const type = (field.type || '').toLowerCase()
            if (type === 'submit' || type === 'button') return false
            if (isTermsField(field) || isCountryField(field) || isPhoneCountryField(field) || isNationalPhoneField(field) || isPrefillOnlyField(field)) {
                return false
            }
            return !FILLABLE_FIELD_NAMES.has(fieldName(field))
        })
        .map(field => fieldKey(field))
        .filter(Boolean)
    if (unknownRequired.length > 0) {
        return {
            ...EMPTY_STOP,
            outcome: 'missing_profile_fields',
            reason: 'stop: unknown required field is present; not guessed and not submitted',
            blockedFields: unknownRequired
        }
    }

    const missingPrefill = fields
        .filter(field => isPrefillOnlyField(field) && (field.required || fieldName(field) === 'email' || (field.type || '').toLowerCase() === 'email'))
        .filter(field => !field.hasValue)
        .map(field => fieldKey(field) || 'email')
    if (missingPrefill.length > 0) {
        return {
            ...EMPTY_STOP,
            outcome: 'missing_profile_fields',
            reason: 'stop: official name or email prefill is missing; values are not invented',
            blockedFields: missingPrefill
        }
    }

    const countryField = fields.find(isCountryField)
    if (countryField) {
        const options = countryField.options || []
        if (!countryOptionsIncludeChina(options)) {
            return {
                ...EMPTY_STOP,
                outcome: 'ineligible',
                reason: 'stop: China is not a selectable country option; not bypassing and not submitting',
                blockedFields: [fieldKey(countryField) || 'country']
            }
        }
    } else if (!fields.some(isPhoneCountryField)) {
        return {
            ...EMPTY_STOP,
            outcome: 'missing_profile_fields',
            reason: 'stop: no country or phoneCountryCode field was found on the known signup form',
            blockedFields: ['country']
        }
    }

    const phoneCountryField = fields.find(isPhoneCountryField)
    if (phoneCountryField && (phoneCountryField.options || []).length > 0 && !phoneCodeOptionFrom(phoneCountryField.options)) {
        return {
            ...EMPTY_STOP,
            outcome: 'ineligible',
            reason: 'stop: +86 is not a selectable phone country code',
            blockedFields: [fieldKey(phoneCountryField) || 'phoneCountryCode']
        }
    }

    const phoneField = fields.find(isNationalPhoneField)
    if (!phoneField) {
        return {
            ...EMPTY_STOP,
            outcome: 'missing_profile_fields',
            reason: 'stop: national phone field was not found',
            blockedFields: ['nationalPhoneNumber']
        }
    }

    const termsField = fields.find(isTermsField)
    if (!termsField) {
        return {
            ...EMPTY_STOP,
            outcome: 'missing_profile_fields',
            reason: 'stop: official rules checkbox was not found; terms are not assumed',
            blockedFields: ['officialRulesAccepted']
        }
    }

    const submit = selectOfficialSignupSubmitCta(ctas)
    if (submit.reason !== 'unique' || !submit.cta) {
        return {
            ...EMPTY_STOP,
            outcome: 'unverified',
            reason: submit.reason === 'ambiguous'
                ? 'stop: multiple official signup submit controls were visible'
                : 'stop: no unique official signup submit button was visible',
            blockedFields: []
        }
    }

    const fills: SignupFillIntent[] = []
    if (countryField) {
        const option = chinaOptionFrom(countryField.options || []) || 'CN'
        fills.push({ field: countryField.name || 'country', kind: 'select-country', option })
    }
    if (phoneCountryField) {
        const option = phoneCodeOptionFrom(phoneCountryField.options || []) || '+86'
        fills.push({ field: phoneCountryField.name || 'phoneCountryCode', kind: 'phone-country-code', option })
    }
    fills.push({
        field: phoneField.name || 'nationalPhoneNumber',
        kind: 'national-phone'
    })
    fills.push({
        field: termsField.name || 'officialRulesAccepted',
        kind: 'accept-terms'
    })

    if (countryField && isDefaultUsResidence(countryField.selectedText || '') && !fills.some(item => item.kind === 'select-country')) {
        return {
            ...EMPTY_STOP,
            outcome: 'ineligible',
            reason: 'stop: country defaults to US and cannot be safely replaced with China',
            blockedFields: [fieldKey(countryField) || 'country']
        }
    }

    return {
        action: 'submit',
        outcome: 'needs_registration',
        reason: 'authorized China contact and official prefill are ready; official submit button is unique',
        blockedFields: [],
        fills,
        submitText: submit.cta.text,
        challenge: false,
        signupComplete: false
    }
}

export function evaluateSignupSubmitResult(input: {
    before: PrizeDropSnapshot
    after: PrizeDropSnapshot
    submitted: boolean
}): {
    success: boolean
    outcome: 'registration_complete' | 'unverified' | 'missing_profile_fields'
    reason: string
    signupComplete: boolean
    dailyCtaVisible: boolean
    resubmit: boolean
} {
    const afterText = input.after.visibleText || ''
    const afterFields = input.after.formFields || []
    const dailyCtaVisible = (input.after.ctas || []).some(cta => /check if you('re| are) a winner|查看你是否成为即时获奖者/i.test(normalizeVisibleText(cta.text || '')))
    if (detectAuthChallenge(afterText, afterFields)) {
        return {
            success: false,
            outcome: 'unverified',
            reason: 'stop: OTP, password, or captcha appeared after submit; not read, not screenshotted, not guessed, not retried',
            signupComplete: false,
            dailyCtaVisible,
            resubmit: false
        }
    }
    if (isSignupSuccessReceipt(afterText) || isAlreadyEnteredCopy(afterText)) {
        return {
            success: true,
            outcome: 'registration_complete',
            reason: 'signup success receipt is visible; daily Check-winner is a separate control and was not treated as this receipt',
            signupComplete: true,
            dailyCtaVisible,
            resubmit: false
        }
    }
    const submit = selectOfficialSignupSubmitCta(input.after.ctas || [])
    const disabled = (afterFields || []).some(field => (field.type || '').toLowerCase() === 'submit' && field.disabled)
    if (disabled || (submit.cta && submit.cta.inputType === 'submit')) {
        // A disabled or still-visible submit button is not a success receipt.
        return {
            success: false,
            outcome: 'unverified',
            reason: 'no signup success receipt after submit; a disabled or remaining button is not treated as success; not submitting again',
            signupComplete: false,
            dailyCtaVisible,
            resubmit: false
        }
    }
    return {
        success: false,
        outcome: 'unverified',
        reason: 'no signup success receipt after submit; not submitting again',
        signupComplete: false,
        dailyCtaVisible,
        resubmit: false
    }
}

export function signupRunnerEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
    return env.DAILY_INSTANT_WIN_SIGNUP === '1'
}

export function signupProfilePath(env: NodeJS.ProcessEnv = process.env): string {
    return (env.DAILY_INSTANT_WIN_SIGNUP_PROFILE || '').trim()
}
