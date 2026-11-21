import type { Page } from 'patchright'
import { BaseActivity } from '../BaseActivity'
import {
    classifyPrizeDropSnapshot,
    isSafeOfficialDailyClaimCta,
    redactDiagnostics,
    type PrizeDropSnapshot
} from './totalPrizeDropPage'
import {
    SIGNUP_URL,
    evaluateSignupSubmitResult,
    loadSignupProfileFromFile,
    planSignupSubmit,
    redactSignupValue,
    signupProfilePath,
    signupRunnerEnabled,
    type InstantWinSignupProfile,
    type SignupFillIntent,
    type SignupPlan
} from './instantWinSignup'
import {
    buildStatusRecord,
    clickedAfterExecutionError,
    defaultStatusDir,
    loadStatusRecord,
    saveStatusRecord,
    shouldSkipSameDayAction
} from './instantWinStatus'
import { accountEvidenceAlias } from './totalPrizeDropPage'

export interface InstantWinSignupResult {
    outcome: SignupPlan['outcome'] | 'unverified' | 'retryable_error'
    reason: string
    submitted: boolean
    signupComplete: boolean
    dailyCtaVisible: boolean
    blockedFields?: string[]
    challenge?: boolean
    enabled: boolean
}

/**
 * Explicit signup-only runner. Disabled unless DAILY_INSTANT_WIN_SIGNUP=1.
 * Uses the existing logged-in desktop/mobile page. Never invents identity
 * fields, never retries a submit without a receipt, never treats a daily
 * Check-winner control as a signup receipt.
 */
export class InstantWinSignup extends BaseActivity {
    public async run(): Promise<InstantWinSignupResult> {
        const enabled = signupRunnerEnabled()
        const alias = accountEvidenceAlias(this.bot.userData.userName)
        const persisted = loadStatusRecord(defaultStatusDir(), alias)
        if (!enabled) {
            return this.finish({
                outcome: 'unverified',
                reason: 'signup runner disabled; daily Instant Win will not auto-register',
                submitted: false,
                signupComplete: Boolean(persisted?.signupComplete),
                dailyCtaVisible: false,
                enabled: false
            })
        }

        const loaded = loadSignupProfileFromFile(signupProfilePath())
        const page = this.getActivePage()
        if (!page) {
            return this.finish({
                outcome: 'retryable_error',
                reason: 'no active browser page was available for signup',
                submitted: false,
                signupComplete: false,
                dailyCtaVisible: false,
                enabled: true,
                blockedFields: loaded.error ? ['signup_profile'] : undefined
            })
        }

        let submitAttemptCommitted = false
        try {
            this.bot.logger.info(
                this.bot.isMobile,
                'INSTANT-WIN-SIGNUP',
                `打开报名页 | url=${SIGNUP_URL} | profile=${loaded.profile ? 'loaded' : 'missing'}`
            )
            await page.goto(SIGNUP_URL, { waitUntil: 'domcontentloaded', timeout: 30000 })
            // Do not run the generic popup handler; it may accept terms or press a primary button.
            await this.bot.utils.wait(this.bot.utils.randomDelay(1500, 3000))

            const before = await this.captureSnapshot(page)
            const classified = classifyPrizeDropSnapshot(before)
            this.bot.logger.info(
                this.bot.isMobile,
                'INSTANT-WIN-SIGNUP',
                `page | status=${classified.outcome} | reason=${classified.reason}`
            )

            const plan = planSignupSubmit({
                snapshot: before,
                profile: loaded.profile,
                profileError: loaded.error,
                enabled: true,
                alreadySubmitted: Boolean(persisted?.clicked && persisted.date && !persisted.signupComplete)
            })
            this.logPlan(plan)

            if (plan.action !== 'submit') {
                const dailyCtaVisible = Boolean(classified.dailyCta && isSafeOfficialDailyClaimCta(classified.dailyCta))
                return this.finish({
                    outcome: plan.outcome,
                    reason: plan.reason,
                    submitted: false,
                    signupComplete: plan.signupComplete,
                    dailyCtaVisible,
                    blockedFields: plan.blockedFields,
                    challenge: plan.challenge,
                    enabled: true
                })
            }

            if (shouldSkipSameDayAction(persisted, this.todayKey())) {
                return this.finish({
                    outcome: 'unverified',
                    reason: 'same-day official signup or daily action already recorded; not submitting again',
                    submitted: Boolean(persisted?.clicked),
                    signupComplete: Boolean(persisted?.signupComplete),
                    dailyCtaVisible: false,
                    enabled: true
                })
            }

            const filled = await this.applyFills(page, plan.fills, loaded.profile)
            if (!filled.ok) {
                return this.finish({
                    outcome: 'unverified',
                    reason: filled.reason,
                    submitted: false,
                    signupComplete: false,
                    dailyCtaVisible: false,
                    blockedFields: filled.blockedFields,
                    enabled: true
                })
            }

            const mid = await this.captureSnapshot(page)
            const midPlan = planSignupSubmit({
                snapshot: mid,
                profile: loaded.profile,
                enabled: true
            })
            if (midPlan.action !== 'submit' || midPlan.challenge) {
                return this.finish({
                    outcome: midPlan.outcome,
                    reason: `stop after fill, before submit: ${midPlan.reason}`,
                    submitted: false,
                    signupComplete: midPlan.signupComplete,
                    dailyCtaVisible: false,
                    blockedFields: midPlan.blockedFields,
                    challenge: midPlan.challenge,
                    enabled: true
                })
            }

            const pending = buildStatusRecord({
                outcome: 'unverified',
                reason: 'official signup submit attempted; receipt pending',
                clicked: true,
                previous: persisted
            })
            saveStatusRecord(defaultStatusDir(), alias, pending)
            submitAttemptCommitted = true

            const submitted = await this.clickOfficialSubmit(page, plan.submitText || '')
            if (!submitted) {
                return this.finish({
                    outcome: 'unverified',
                    reason: 'official signup submit button could not be clicked uniquely; not retried',
                    submitted: true,
                    signupComplete: false,
                    dailyCtaVisible: false,
                    enabled: true
                })
            }

            await this.bot.utils.wait(this.bot.utils.randomDelay(2000, 4000))
            const after = await this.captureSnapshot(page)
            const result = evaluateSignupSubmitResult({ before, after, submitted: true })
            this.bot.logger.info(
                this.bot.isMobile,
                'INSTANT-WIN-SIGNUP',
                `receipt | success=${result.success} | dailyCtaVisible=${result.dailyCtaVisible} | reason=${result.reason}`
            )
            return this.finish({
                outcome: result.outcome,
                reason: result.reason,
                submitted: true,
                signupComplete: result.signupComplete,
                dailyCtaVisible: result.dailyCtaVisible,
                enabled: true
            })
        } catch (error) {
            const message = error instanceof Error ? error.message : String(error)
            this.bot.logger.warn(
                this.bot.isMobile,
                'INSTANT-WIN-SIGNUP',
                `执行出错，已失败关闭 | ${redactDiagnostics(message, 200)}`
            )
            return this.finish({
                outcome: 'retryable_error',
                reason: redactDiagnostics(message, 200),
                submitted: clickedAfterExecutionError(submitAttemptCommitted, Boolean(persisted?.clicked)),
                signupComplete: Boolean(persisted?.signupComplete),
                dailyCtaVisible: false,
                enabled: true
            })
        }
    }

    private todayKey(): string {
        return new Intl.DateTimeFormat('en-CA', {
            timeZone: process.env.TZ || 'Asia/Shanghai',
            year: 'numeric',
            month: '2-digit',
            day: '2-digit'
        }).format(new Date())
    }

    private getActivePage(): Page | null {
        const desktop = this.bot.mainDesktopPage
        if (desktop && !desktop.isClosed()) return desktop
        const mobile = this.bot.mainMobilePage
        if (mobile && !mobile.isClosed()) return mobile
        return null
    }

    private async captureSnapshot(page: Page): Promise<PrizeDropSnapshot> {
        const data = await page.evaluate(() => {
            const visible = (el: Element): boolean => {
                const style = window.getComputedStyle(el)
                const rect = el.getBoundingClientRect()
                return (
                    style.visibility !== 'hidden' &&
                    style.display !== 'none' &&
                    Number(style.opacity) !== 0 &&
                    rect.width + rect.height > 0
                )
            }
            const ctas = Array.from(document.querySelectorAll('button, a, [role="button"], [role="link"]'))
                .filter(el => visible(el))
                .map(el => {
                    const form = el.closest('form')
                    return {
                        tag: el.tagName.toLowerCase(),
                        role: el.getAttribute('role') || (el.tagName.toLowerCase() === 'button' ? 'button' : 'link'),
                        text: (el.textContent || '').replace(/\s+/g, ' ').trim(),
                        href: el.getAttribute('href') || '',
                        inForm: Boolean(form),
                        formAction: form?.getAttribute('action') || '',
                        inputType: (el as HTMLElement).getAttribute('type') || ''
                    }
                })
                .filter(cta => Boolean(cta.text) && cta.text.length <= 180)
            const formFields = Array.from(
                document.querySelectorAll('form input, form select, form textarea, input, select, textarea')
            ).map(el => {
                const input = el as HTMLInputElement
                const tag = el.tagName.toLowerCase()
                let selectedText = ''
                let options: string[] = []
                if (tag === 'select') {
                    const sel = el as HTMLSelectElement
                    selectedText = sel.selectedOptions?.[0]?.text?.trim() || sel.selectedOptions?.[0]?.value || ''
                    options = Array.from(sel.options).map(item => (item.text || item.value || '').trim()).filter(Boolean)
                }
                return {
                    name: input.name || '',
                    label: input.name || '',
                    type: (input.type || tag).toLowerCase(),
                    required: Boolean(input.required),
                    hasValue: Boolean(input.value) || (tag === 'select' && Boolean(selectedText)),
                    valueLength: (input.value || selectedText || '').length,
                    selectedText,
                    checked: input.type === 'checkbox' || input.type === 'radio' ? Boolean(input.checked) : undefined,
                    disabled: Boolean(input.disabled),
                    options: options.length ? options : undefined
                }
            })
            return {
                url: location.href,
                title: document.title || '',
                visibleText: (document.body?.innerText || '').replace(/\s+/g, ' ').trim(),
                ctas,
                formFields
            }
        })
        return {
            url: data.url,
            title: data.title,
            visibleText: data.visibleText,
            ctas: data.ctas,
            formFields: data.formFields
        }
    }

    private async applyFills(
        page: Page,
        fills: SignupFillIntent[],
        profile?: InstantWinSignupProfile
    ): Promise<{ ok: boolean; reason: string; blockedFields?: string[] }> {
        if (!profile) return { ok: false, reason: 'signup profile missing at fill time', blockedFields: ['signup_profile'] }
        for (const fill of fills) {
            const locator = page.locator(`[name="${fill.field}"]`).first()
            if ((await locator.count()) < 1) {
                return { ok: false, reason: `fill target not found: ${fill.field}`, blockedFields: [fill.field] }
            }
            if (fill.kind === 'select-country' || fill.kind === 'phone-country-code') {
                const option = fill.option || ''
                try {
                    await locator.selectOption({ label: option })
                } catch {
                    try {
                        await locator.selectOption({ value: option })
                    } catch {
                        await locator.fill(option)
                    }
                }
                this.bot.logger.info(
                    this.bot.isMobile,
                    'INSTANT-WIN-SIGNUP',
                    `已选择 ${fill.field}=${redactSignupValue(fill.field, option)}`
                )
            } else if (fill.kind === 'national-phone') {
                await locator.fill(profile.nationalPhoneNumber)
                this.bot.logger.info(
                    this.bot.isMobile,
                    'INSTANT-WIN-SIGNUP',
                    `已填写 ${fill.field}=${redactSignupValue(fill.field, profile.nationalPhoneNumber)}`
                )
            } else if (fill.kind === 'accept-terms') {
                const checked = await locator.isChecked().catch(() => false)
                if (!checked) await locator.check()
                this.bot.logger.info(this.bot.isMobile, 'INSTANT-WIN-SIGNUP', `已勾选 ${fill.field}`)
            }
        }
        return { ok: true, reason: 'filled authorized contact and terms only' }
    }

    private async clickOfficialSubmit(page: Page, text: string): Promise<boolean> {
        const locator = page.locator(`form button[type="submit"], button[type="submit"], form input[type="submit"]`).filter({
            hasText: new RegExp(`^${this.escapeRegExp(text)}$`)
        })
        if ((await locator.count()) !== 1) return false
        await locator.first().click({ timeout: 8000 })
        this.bot.logger.info(this.bot.isMobile, 'INSTANT-WIN-SIGNUP', `已点击报名提交 | text=${redactDiagnostics(text, 40)}`)
        return true
    }

    private escapeRegExp(value: string): string {
        return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    }

    private logPlan(plan: SignupPlan): void {
        const fills = plan.fills.map(item => `${item.kind}:${item.field}`).join(',')
        this.bot.logger.info(
            this.bot.isMobile,
            'INSTANT-WIN-SIGNUP',
            `plan | action=${plan.action} | outcome=${plan.outcome} | fills=${fills || 'none'} | blocked=${(plan.blockedFields || []).join(',') || 'none'} | reason=${plan.reason}`
        )
    }

    private finish(result: InstantWinSignupResult): InstantWinSignupResult {
        const alias = accountEvidenceAlias(this.bot.userData.userName)
        const record = buildStatusRecord({
            outcome: result.outcome === 'registration_complete' ? 'needs_registration' : result.outcome === 'retryable_error' ? 'retryable_error' : result.outcome,
            reason: result.reason,
            clicked: result.submitted,
            blockedFields: result.blockedFields,
            signupComplete: result.signupComplete
        })
        // registration_complete is signup, not a daily receipt; persist signupComplete and do not invent a won/lost kind.
        if (result.signupComplete) record.signupComplete = true
        if (result.outcome === 'registration_complete') {
            record.outcome = 'unverified'
            record.publicStatus = 'unverified'
            record.signupComplete = true
            record.receiptKind = undefined
        }
        saveStatusRecord(defaultStatusDir(), alias, record)
        this.bot.logger.info(
            this.bot.isMobile,
            'INSTANT-WIN-SIGNUP',
            `完成 | actionSubmitted=${result.submitted} | signupComplete=${result.signupComplete} | dailyCtaVisible=${result.dailyCtaVisible} | reason=${result.reason}`
        )
        return result
    }
}
