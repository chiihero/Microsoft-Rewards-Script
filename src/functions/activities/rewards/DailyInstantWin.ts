import type { Page } from 'patchright'
import { BaseActivity } from '../BaseActivity'
import { chmodSync, mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import {
    accountEvidenceAlias,
    classifyPrizeDropSnapshot,
    detectExpandedDetailsPanel,
    isSafeOfficialDailyClaimCta,
    redactDiagnostics,
    TOTAL_PRIZE_DROP_URL,
    type FormFieldInventory,
    type InstantWinDecision,
    type InstantWinOutcome,
    type PageCta,
    type PrizeDropSnapshot
} from './totalPrizeDropPage'
import {
    buildStatusRecord,
    defaultStatusDir,
    isConfirmedOutcome,
    loadStatusRecord,
    saveStatusRecord,
    shouldSkipSameDayAction,
    toPublicStatus,
    type InstantWinStatusRecord
} from './instantWinStatus'

export interface DailyInstantWinResult {
    outcome: InstantWinOutcome
    reason: string
    clicked: boolean
    publicStatus?: ReturnType<typeof toPublicStatus>
    receiptKind?: InstantWinStatusRecord['receiptKind']
    blockedFields?: string[]
    signupComplete?: boolean
    diagnose?: boolean
    diagnostics: InstantWinDecision['diagnostics']
}

export class DailyInstantWin extends BaseActivity {
    private lastResult: DailyInstantWinResult | null = null

    public getLastResult(): DailyInstantWinResult | null {
        return this.lastResult
    }

    public async run(): Promise<DailyInstantWinResult> {
        const alias = accountEvidenceAlias(this.bot.userData.userName)
        const persisted = loadStatusRecord(defaultStatusDir(), alias)
        if (this.lastResult && this.isTerminal(this.lastResult.outcome)) {
            this.bot.logger.info(
                this.bot.isMobile,
                'DAILY-INSTANT-WIN',
                `幂等跳过 | status=${this.lastResult.outcome} | public=${toPublicStatus(this.lastResult.outcome)} | reason=${this.lastResult.reason}`
            )
            return this.lastResult
        }

        this.markExecuted()
        const page = this.getActivePage()
        if (!page) {
            return this.finish({
                outcome: 'retryable_error',
                reason: 'no active browser page was available to open the Instant Win page',
                clicked: false,
                diagnostics: {
                    url: TOTAL_PRIZE_DROP_URL,
                    ctaTexts: [],
                    visibleExcerpt: ''
                }
            }, persisted)
        }

        try {
            const diagnose = process.env.DAILY_INSTANT_WIN_DIAGNOSE === '1'
            const targetUrl = diagnose
                ? process.env.DAILY_INSTANT_WIN_DIAGNOSE_URL?.trim() || TOTAL_PRIZE_DROP_URL
                : TOTAL_PRIZE_DROP_URL
            const diagnoseStage = process.env.DAILY_INSTANT_WIN_DIAGNOSE_STAGE?.trim() || 'landing'
            this.bot.logger.info(
                this.bot.isMobile,
                'DAILY-INSTANT-WIN',
                `打开每日 Instant Win 页面 | url=${targetUrl} | geo=${this.bot.userData.geoLocale} | diagnose=${diagnose}`
            )
            await page.goto(targetUrl, { waitUntil: 'domcontentloaded', timeout: 30000 })
            // Strict diagnose is capture-only: never dismiss popups, never click, never submit.
            if (!diagnose) {
                await this.bot.browser.utils.tryDismissAllMessages(page)
            }
            await this.bot.utils.wait(this.bot.utils.randomDelay(1500, 3000))

            const before = await this.captureSnapshot(page)
            const decision = classifyPrizeDropSnapshot(before)
            this.logDecision('page', decision)

            if (diagnose) {
                await this.saveDiagnoseArtifacts(page, before, diagnoseStage)
                return this.finish({
                    outcome: decision.outcome,
                    reason: `diagnose-only capture, no click (${decision.reason})`,
                    clicked: false,
                    diagnose: true,
                    blockedFields: decision.blockedFields,
                    signupComplete: decision.signupComplete,
                    diagnostics: decision.diagnostics
                }, persisted)
            }

            if (decision.signupComplete) {
                return this.finish({
                    outcome: decision.outcome,
                    reason: decision.reason,
                    clicked: false,
                    signupComplete: true,
                    diagnostics: decision.diagnostics
                }, persisted)
            }

            if (decision.outcome !== 'claimable' || !decision.dailyCta) {
                return this.finish({
                    outcome: decision.outcome,
                    reason: decision.reason,
                    clicked: false,
                    blockedFields: decision.blockedFields,
                    signupComplete: decision.signupComplete,
                    diagnostics: decision.diagnostics
                }, persisted)
            }

            if (shouldSkipSameDayAction(persisted, this.todayKey()) || (this.lastResult && this.lastResult.clicked)) {
                return this.finish({
                    outcome: persisted?.outcome && persisted.clicked ? persisted.outcome : 'unverified',
                    reason: 'same-day official click or signup action already recorded; not retrying blindly',
                    clicked: Boolean(persisted?.clicked || this.lastResult?.clicked),
                    blockedFields: decision.blockedFields,
                    diagnostics: decision.diagnostics
                }, persisted)
            }

            if (!isSafeOfficialDailyClaimCta(decision.dailyCta)) {
                return this.finish({
                    outcome: 'unverified',
                    reason: 'daily control failed href/form/terms safety checks; not clicked',
                    clicked: false,
                    diagnostics: decision.diagnostics
                }, persisted)
            }

            const clicked = await this.clickOfficialDailyCta(page, decision.dailyCta)
            if (!clicked) {
                return this.finish({
                    // unique official control could not be clicked; do not invent a receipt
                    outcome: 'unverified',
                    reason: 'official daily Instant Win control was found in the snapshot but could not be clicked uniquely',
                    clicked: false,
                    diagnostics: decision.diagnostics
                }, persisted)
            }

            await this.bot.utils.wait(this.bot.utils.randomDelay(2000, 4000))
            const after = await this.captureSnapshot(page)
            const receipt = classifyPrizeDropSnapshot(after)
            this.logDecision('receipt', receipt)

            if (detectExpandedDetailsPanel(before, after)) {
                return this.finish({
                    outcome: 'unverified',
                    reason: 'click opened a details panel (填写报名表/权益说明/查看条款) while the daily card stayed in progress; no distinct Check-winner control or receipt was visible',
                    clicked: true,
                    diagnostics: receipt.diagnostics
                }, persisted)
            }

            if (receipt.outcome === 'claimable') {
                return this.finish({
                    outcome: 'unverified',
                    reason: 'clicked the official daily control but the page still looks claimable and has no confirmed receipt',
                    clicked: true,
                    diagnostics: receipt.diagnostics
                }, persisted)
            }

            if (receipt.outcome === 'claimed' || receipt.outcome === 'already_claimed') {
                return this.finish({
                    outcome: receipt.outcome,
                    reason: receipt.reason,
                    clicked: true,
                    diagnostics: receipt.diagnostics
                }, persisted)
            }

            return this.finish({
                outcome: receipt.outcome === 'login_required' || receipt.outcome === 'error' ? receipt.outcome : 'unverified',
                reason: `clicked the official daily control but the receipt was not confirmed (${receipt.outcome}: ${receipt.reason})`,
                clicked: true,
                diagnostics: receipt.diagnostics
            }, persisted)
        } catch (error) {
            const message = error instanceof Error ? error.message : String(error)
            this.bot.logger.warn(
                this.bot.isMobile,
                'DAILY-INSTANT-WIN',
                `执行出错，已失败关闭且不阻断后续任务 | ${redactDiagnostics(message, 200)}`
            )
            return this.finish({
                outcome: 'retryable_error',
                reason: redactDiagnostics(message, 200),
                clicked: false,
                diagnostics: {
                    url: redactDiagnostics(page.url(), 200),
                    ctaTexts: [],
                    visibleExcerpt: ''
                }
            }, persisted)
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

    private isTerminal(outcome: InstantWinOutcome): boolean {
        // Confirmed receipts and missing-data blocks must not infinite-retry in this run.
        // unverified / retryable_error stay retryable, but same-day clicks are gated separately.
        return isConfirmedOutcome(outcome) || outcome === 'needs_registration' || outcome === 'missing_profile_fields'
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
            const ctas = Array.from(
                document.querySelectorAll('button, a, [role="button"], [role="link"]')
            )
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
                    selectedText = sel.selectedOptions?.[0]?.text?.trim() || ''
                    options = Array.from(sel.options).map(option => option.text.trim()).filter(Boolean)
                }
                const value = input.value || ''
                return {
                    name: input.name || '',
                    label: input.name || input.getAttribute('aria-label') || '',
                    type: (input.type || tag).toLowerCase(),
                    required: Boolean(input.required),
                    hasValue: Boolean(value || selectedText),
                    valueLength: value ? String(value).length : selectedText.length,
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
            url: data.url || page.url() || TOTAL_PRIZE_DROP_URL,
            title: data.title,
            visibleText: data.visibleText,
            ctas: data.ctas as PageCta[],
            formFields: data.formFields as FormFieldInventory[]
        }
    }

    private async clickOfficialDailyCta(page: Page, cta: PageCta): Promise<boolean> {
        const locator = page
            .locator('button, a, [role="button"], [role="link"]')
            .filter({ hasText: new RegExp(`^\\s*${this.escapeRegExp(cta.text)}\\s*$`, 'i') })
        const count = await locator.count()
        if (count !== 1) {
            this.bot.logger.warn(
                this.bot.isMobile,
                'DAILY-INSTANT-WIN',
                `拒绝点击：目标控件数量=${count} | text=${redactDiagnostics(cta.text, 80)}`
            )
            return false
        }
        const handle = locator.first()
        const live = await handle.evaluate(el => {
            const form = (el as Element).closest('form')
            return {
                text: ((el as HTMLElement).innerText || '').replace(/\s+/g, ' ').trim(),
                href: (el as HTMLElement).getAttribute('href') || '',
                inForm: Boolean(form),
                formAction: form?.getAttribute('action') || '',
                inputType: (el as HTMLElement).getAttribute('type') || '',
                tag: (el as HTMLElement).tagName.toLowerCase(),
                role: (el as HTMLElement).getAttribute('role') || ''
            }
        })
        const candidate = {
            tag: live.tag,
            role: live.role,
            text: live.text,
            href: live.href,
            inForm: live.inForm,
            formAction: live.formAction,
            inputType: live.inputType
        }
        if (!isSafeOfficialDailyClaimCta(candidate)) {
            this.bot.logger.warn(
                this.bot.isMobile,
                'DAILY-INSTANT-WIN',
                `拒绝点击：控件未通过官方文本或 href/form/条款安全检查 | text=${redactDiagnostics(live.text, 80)}`
            )
            return false
        }
        await handle.click({ timeout: 8000 })
        this.bot.logger.info(
            this.bot.isMobile,
            'DAILY-INSTANT-WIN',
            `已点击官方每日 Instant Win 控件 | text=${redactDiagnostics(cta.text, 80)}`
        )
        return true
    }

    private escapeRegExp(value: string): string {
        return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    }

    private logDecision(stage: 'page' | 'receipt', decision: InstantWinDecision): void {
        this.bot.logger.info(
            this.bot.isMobile,
            'DAILY-INSTANT-WIN',
            `${stage} | status=${decision.outcome} | reason=${decision.reason} | ctas=${JSON.stringify(decision.diagnostics.ctaTexts)} | excerpt=${decision.diagnostics.visibleExcerpt}`
        )
    }

    private finish(result: DailyInstantWinResult, previous: InstantWinStatusRecord | null = null): DailyInstantWinResult {
        const alias = accountEvidenceAlias(this.bot.userData.userName)
        const record = buildStatusRecord({
            outcome: result.outcome,
            reason: result.reason,
            clicked: result.clicked,
            visibleText: result.diagnostics.visibleExcerpt,
            blockedFields: result.blockedFields,
            signupComplete: result.signupComplete,
            diagnose: result.diagnose,
            previous
        })
        result.publicStatus = record.publicStatus
        result.receiptKind = record.receiptKind
        result.signupComplete = record.signupComplete
        this.lastResult = result
        if (!result.diagnose) {
            saveStatusRecord(defaultStatusDir(), alias, record)
        }
        const blocked = result.blockedFields?.length ? ` | blocked=${result.blockedFields.join(',')}` : ''
        const receipt = record.receiptKind ? ` | receipt=${record.receiptKind}` : ''
        this.bot.logger.info(
            this.bot.isMobile,
            'DAILY-INSTANT-WIN',
            `完成 | status=${result.outcome} | public=${record.publicStatus}${receipt} | clicked=${result.clicked}${blocked} | reason=${result.reason}`
        )
        return result
    }


    private async captureFormInventory(page: Page): Promise<{ url: string; fields: Record<string, unknown>[] }> {
        const inventory = await page.evaluate(() => {
            const labelFor = (el: Element): string => {
                const labelled = el.getAttribute('aria-labelledby')
                if (labelled) {
                    return labelled
                        .split(/\s+/)
                        .map(id => document.getElementById(id)?.innerText || '')
                        .join(' ')
                        .replace(/\s+/g, ' ')
                        .trim()
                }
                const aria = el.getAttribute('aria-label') || ''
                if (aria) return aria.trim()
                const id = el.getAttribute('id')
                if (id) {
                    const lab = document.querySelector(`label[for="${CSS.escape(id)}"]`)
                    if (lab) return (lab as HTMLElement).innerText.replace(/\s+/g, ' ').trim()
                }
                const parent = el.closest('label')
                return parent ? (parent as HTMLElement).innerText.replace(/\s+/g, ' ').trim() : ''
            }
            const nodes = Array.from(
                document.querySelectorAll('form input, form select, form textarea, form button[type="submit"], input, select, textarea, button[type="submit"]')
            )
            return {
                url: location.href,
                fields: nodes.map(el => {
                    const input = el as HTMLInputElement
                    const type = (input.type || el.tagName.toLowerCase()).toLowerCase()
                    const value = input.value || ''
                    const tag = el.tagName.toLowerCase()
                    let selectedText = ''
                    if (tag === 'select') {
                        const sel = el as HTMLSelectElement
                        selectedText = sel.selectedOptions?.[0]?.text?.trim() || ''
                    }
                    const text = tag === 'button' ? (el as HTMLElement).innerText.replace(/\s+/g, ' ').trim() : ''
                    return {
                        tag,
                        type,
                        name: input.name || '',
                        id: input.id || '',
                        label: labelFor(el),
                        text,
                        required: Boolean(input.required),
                        disabled: Boolean(input.disabled),
                        readOnly: Boolean(input.readOnly),
                        hasValue: Boolean(value),
                        valueLength: value ? String(value).length : 0,
                        checked: type === 'checkbox' || type === 'radio' ? Boolean(input.checked) : undefined,
                        selectedText,
                        autoComplete: input.autocomplete || '',
                        href: el.getAttribute('href') || ''
                    }
                })
            }
        })
        inventory.url = redactDiagnostics(inventory.url, 300)
        inventory.fields = inventory.fields.map(field => ({
            ...field,
            label: redactDiagnostics(String(field.label || ''), 180),
            text: redactDiagnostics(String(field.text || ''), 180),
            selectedText: redactDiagnostics(String(field.selectedText || ''), 80)
        }))
        this.bot.logger.info(
            this.bot.isMobile,
            'DAILY-INSTANT-WIN',
            `表单盘点 | fields=${inventory.fields
                .map(field => {
                    const bits = [
                        field.label || field.name || field.type,
                        field.type,
                        field.required ? 'required' : '',
                        field.hasValue ? `prefilled:${field.valueLength}` : 'empty',
                        field.checked === undefined ? '' : `checked=${field.checked}`,
                        field.selectedText ? `selected=${field.selectedText}` : ''
                    ].filter(Boolean)
                    return bits.join('/')
                })
                .join(' ; ')}`
        )
        return inventory
    }

    private async saveDiagnoseArtifacts(page: Page, snapshot: PrizeDropSnapshot, stage: string): Promise<void> {
        const root = process.env.DAILY_INSTANT_WIN_DIAGNOSE_DIR || '/tmp/rewards-instant-win-diagnose'
        const alias = accountEvidenceAlias(this.bot.userData.userName)
        const dir = join(root, alias, stage)
        mkdirSync(root, { recursive: true, mode: 0o700 })
        mkdirSync(dir, { recursive: true, mode: 0o700 })
        try {
            chmodSync(root, 0o700)
            chmodSync(dir, 0o700)
        } catch {
            // best-effort on platforms that cannot chmod
        }
        const dialogs = await page.evaluate(() => {
            const nodes = Array.from(document.querySelectorAll('[role="dialog"], [role="alertdialog"], [aria-modal="true"]'))
            return nodes.map(node => (node as HTMLElement).innerText || '').map(text => text.replace(/\s+/g, ' ').trim()).filter(Boolean)
        })
        const payload = {
            url: redactDiagnostics(snapshot.url, 300),
            title: snapshot.title ? redactDiagnostics(snapshot.title, 200) : undefined,
            ctaTexts: snapshot.ctas.map(cta => ({
                tag: cta.tag,
                role: cta.role,
                text: redactDiagnostics(cta.text, 180),
                href: redactDiagnostics(cta.href, 200)
            })),
            dialogs: dialogs.map(text => redactDiagnostics(text, 2000)),
            visibleText: redactDiagnostics(snapshot.visibleText, 20000)
        }
        const formInventory = await this.captureFormInventory(page)
        const snapshotPath = join(dir, 'snapshot.json')
        const visiblePath = join(dir, 'visible.txt')
        const inventoryPath = join(dir, 'form-inventory.json')
        const screenshotPath = join(dir, 'page.png')
        writeFileSync(snapshotPath, JSON.stringify(payload, null, 2))
        writeFileSync(visiblePath, payload.visibleText)
        writeFileSync(inventoryPath, JSON.stringify(formInventory, null, 2))
        const mask = page.locator(
            'input, textarea, select, [type="email"], [type="tel"], [type="password"], [name="firstName"], [name="lastName"], [name="nationalPhoneNumber"], [name="phoneCountryCode"], [autocomplete="tel-national"], [autocomplete="tel-country-code"], img, [aria-label*="个人资料"], [aria-label*="profile" i], [aria-label*="查看个人资料"]'
        )
        await page.screenshot({
            path: screenshotPath,
            fullPage: true,
            mask: [mask],
            maskColor: '#5a5a5a'
        })
        for (const filePath of [snapshotPath, visiblePath, inventoryPath, screenshotPath]) {
            try {
                chmodSync(filePath, 0o600)
            } catch {
                // best-effort
            }
        }
        this.bot.logger.info(
            this.bot.isMobile,
            'DAILY-INSTANT-WIN',
            `已保存只读取证 | alias=${alias} | stage=${stage} | ctas=${payload.ctaTexts.length} | dialogs=${payload.dialogs.length} | fields=${formInventory.fields.length}`
        )
    }
}


