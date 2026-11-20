import type { Page } from 'patchright'
import { BaseActivity } from '../BaseActivity'
import { mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import {
    classifyPrizeDropSnapshot,
    detectExpandedDetailsPanel,
    isDailyInstantWinCtaText,
    redactDiagnostics,
    TOTAL_PRIZE_DROP_URL,
    type InstantWinDecision,
    type InstantWinOutcome,
    type PageCta,
    type PrizeDropSnapshot
} from './totalPrizeDropPage'

export interface DailyInstantWinResult {
    outcome: InstantWinOutcome
    reason: string
    clicked: boolean
    diagnostics: InstantWinDecision['diagnostics']
}

export class DailyInstantWin extends BaseActivity {
    private lastResult: DailyInstantWinResult | null = null

    public getLastResult(): DailyInstantWinResult | null {
        return this.lastResult
    }

    public async run(): Promise<DailyInstantWinResult> {
        if (this.lastResult && this.isTerminal(this.lastResult.outcome)) {
            this.bot.logger.info(
                this.bot.isMobile,
                'DAILY-INSTANT-WIN',
                `幂等跳过 | status=${this.lastResult.outcome} | reason=${this.lastResult.reason}`
            )
            return this.lastResult
        }

        this.markExecuted()
        const page = this.getActivePage()
        if (!page) {
            return this.finish({
                outcome: 'error',
                reason: 'no active browser page was available to open the Instant Win page',
                clicked: false,
                diagnostics: {
                    url: TOTAL_PRIZE_DROP_URL,
                    ctaTexts: [],
                    visibleExcerpt: ''
                }
            })
        }

        try {
            this.bot.logger.info(
                this.bot.isMobile,
                'DAILY-INSTANT-WIN',
                `打开每日 Instant Win 页面 | url=${TOTAL_PRIZE_DROP_URL} | geo=${this.bot.userData.geoLocale}`
            )
            await page.goto(TOTAL_PRIZE_DROP_URL, { waitUntil: 'domcontentloaded', timeout: 30000 })
            await this.bot.browser.utils.tryDismissAllMessages(page)
            await this.bot.utils.wait(this.bot.utils.randomDelay(1500, 3000))

            const before = await this.captureSnapshot(page)
            const decision = classifyPrizeDropSnapshot(before)
            this.logDecision('page', decision)

            if (process.env.DAILY_INSTANT_WIN_DIAGNOSE === '1') {
                await this.saveDiagnoseArtifacts(page, before, 'landing')
                return this.finish({
                    outcome: 'unverified',
                    reason: 'diagnose-only capture, no click',
                    clicked: false,
                    diagnostics: decision.diagnostics
                })
            }

            if (decision.outcome !== 'claimable' || !decision.dailyCta) {
                return this.finish({
                    outcome: decision.outcome,
                    reason: decision.reason,
                    clicked: false,
                    diagnostics: decision.diagnostics
                })
            }

            const clicked = await this.clickOfficialDailyCta(page, decision.dailyCta)
            if (!clicked) {
                return this.finish({
                    outcome: 'unverified',
                    reason: 'official daily Instant Win control was found in the snapshot but could not be clicked uniquely',
                    clicked: false,
                    diagnostics: decision.diagnostics
                })
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
                })
            }

            if (receipt.outcome === 'claimable') {
                return this.finish({
                    outcome: 'unverified',
                    reason: 'clicked the official daily control but the page still looks claimable and has no confirmed receipt',
                    clicked: true,
                    diagnostics: receipt.diagnostics
                })
            }

            if (receipt.outcome === 'claimed' || receipt.outcome === 'already_claimed') {
                return this.finish({
                    outcome: receipt.outcome,
                    reason: receipt.reason,
                    clicked: true,
                    diagnostics: receipt.diagnostics
                })
            }

            return this.finish({
                outcome: receipt.outcome === 'login_required' || receipt.outcome === 'error' ? receipt.outcome : 'unverified',
                reason: `clicked the official daily control but the receipt was not confirmed (${receipt.outcome}: ${receipt.reason})`,
                clicked: true,
                diagnostics: receipt.diagnostics
            })
        } catch (error) {
            const message = error instanceof Error ? error.message : String(error)
            this.bot.logger.warn(
                this.bot.isMobile,
                'DAILY-INSTANT-WIN',
                `执行出错，已失败关闭且不阻断后续任务 | ${redactDiagnostics(message, 200)}`
            )
            return this.finish({
                outcome: 'error',
                reason: redactDiagnostics(message, 200),
                clicked: false,
                diagnostics: {
                    url: redactDiagnostics(page.url(), 200),
                    ctaTexts: [],
                    visibleExcerpt: ''
                }
            })
        }
    }

    private isTerminal(outcome: InstantWinOutcome): boolean {
        return outcome === 'claimed' || outcome === 'already_claimed'
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
                .map(el => ({
                    tag: el.tagName.toLowerCase(),
                    role: el.getAttribute('role') || (el.tagName.toLowerCase() === 'button' ? 'button' : 'link'),
                    text: (el.textContent || '').replace(/\s+/g, ' ').trim(),
                    href: el.getAttribute('href') || ''
                }))
                .filter(cta => Boolean(cta.text) && cta.text.length <= 180)
            return {
                url: location.href,
                title: document.title || '',
                visibleText: (document.body?.innerText || '').replace(/\s+/g, ' ').trim(),
                ctas
            }
        })
        return {
            url: data.url || page.url() || TOTAL_PRIZE_DROP_URL,
            title: data.title,
            visibleText: data.visibleText,
            ctas: data.ctas as PageCta[]
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
        const text = normalizeForCompare(await locator.first().innerText())
        if (!isDailyInstantWinCtaText(text)) {
            this.bot.logger.warn(
                this.bot.isMobile,
                'DAILY-INSTANT-WIN',
                `拒绝点击：可见文本已不再匹配官方每日控件 | text=${redactDiagnostics(text, 80)}`
            )
            return false
        }
        await locator.first().click({ timeout: 8000 })
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

    private finish(result: DailyInstantWinResult): DailyInstantWinResult {
        this.lastResult = result
        this.bot.logger.info(
            this.bot.isMobile,
            'DAILY-INSTANT-WIN',
            `完成 | status=${result.outcome} | clicked=${result.clicked} | reason=${result.reason}`
        )
        return result
    }

    private async saveDiagnoseArtifacts(page: Page, snapshot: PrizeDropSnapshot, stage: string): Promise<void> {
        const root = process.env.DAILY_INSTANT_WIN_DIAGNOSE_DIR || '/tmp/rewards-instant-win-diagnose'
        const alias = this.bot.userData.userName || 'account'
        const dir = join(root, alias, stage)
        mkdirSync(dir, { recursive: true, mode: 0o700 })
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
        writeFileSync(join(dir, 'snapshot.json'), JSON.stringify(payload, null, 2))
        writeFileSync(join(dir, 'visible.txt'), payload.visibleText)
        await page.screenshot({ path: join(dir, 'page.png'), fullPage: true })
        this.bot.logger.info(
            this.bot.isMobile,
            'DAILY-INSTANT-WIN',
            `已保存只读取证 | dir=${dir} | ctas=${payload.ctaTexts.length} | dialogs=${payload.dialogs.length}`
        )
    }
}

function normalizeForCompare(text: string): string {
    return text.replace(/\u00a0/g, ' ').replace(/[’‘]/g, "'").replace(/\s+/g, ' ').trim()
}

