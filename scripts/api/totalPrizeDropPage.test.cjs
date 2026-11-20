const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const test = require('node:test')

require('../../node_modules/ts-node/register/transpile-only.js')

const {
    classifyPrizeDropSnapshot,
    isDailyInstantWinCtaText,
    isForbiddenCtaText,
    selectDailyInstantWinCta,
    snapshotFromHtml,
    TOTAL_PRIZE_DROP_URL
} = require('../../src/functions/activities/rewards/totalPrizeDropPage.ts')

const fixtures = path.join(__dirname, 'fixtures')

function decisionFromHtml(file, url = TOTAL_PRIZE_DROP_URL) {
    const html = fs.readFileSync(path.join(fixtures, file), 'utf8')
    return classifyPrizeDropSnapshot(snapshotFromHtml(html, url))
}

function snapshot(overrides = {}) {
    return {
        url: TOTAL_PRIZE_DROP_URL,
        visibleText: '',
        ctas: [],
        ...overrides
    }
}

test('signed-out English public page is login_required and never claimable', () => {
    const decision = decisionFromHtml('sweeps-bonus-signed-out.html', 'https://rewards.bing.com/auth/login?ru=%2Fsweeps%2Fbonus')
    assert.equal(decision.outcome, 'login_required')
    assert.equal(decision.dailyCta, null)
    assert.equal(selectDailyInstantWinCta(decision.diagnostics.ctaTexts.map(text => ({ tag: 'a', role: 'link', text, href: '/auth/login' }))).reason, 'none')
})

test('signed-out Chinese public page is login_required and does not click paragraph wording', () => {
    const decision = decisionFromHtml('sweeps-bonus-signed-out-zh.html')
    assert.equal(decision.outcome, 'login_required')
    assert.equal(decision.dailyCta, null)
})

test('unique official English daily CTA is claimable', () => {
    const decision = classifyPrizeDropSnapshot(
        snapshot({
            visibleText: 'Thousands of Instant Win prizes. You can try EVERY day. Check if you are ready.',
            ctas: [
                { tag: 'button', role: 'button', text: "Check if you're a winner", href: '' },
                { tag: 'a', role: 'link', text: 'Instant Win Official Rules', href: 'https://aka.ms/win-IW-Rules' }
            ]
        })
    )
    assert.equal(decision.outcome, 'claimable')
    assert.equal(decision.dailyCta.text, "Check if you're a winner")
})

test('unique official typographic-apostrophe CTA normalizes to claimable', () => {
    const decision = classifyPrizeDropSnapshot(
        snapshot({
            visibleText: 'Instant Win',
            ctas: [{ tag: 'button', role: 'button', text: 'Check if you’re a winner', href: '' }]
        })
    )
    assert.equal(decision.outcome, 'claimable')
    assert.equal(isDailyInstantWinCtaText('Check if you’re a winner'), true)
})

test('unique official Chinese daily CTA is claimable', () => {
    const decision = classifyPrizeDropSnapshot(
        snapshot({
            visibleText: '数千个即时赢奖品。你每天都可以尝试。',
            ctas: [{ tag: 'button', role: 'button', text: '查看你是否成为即时获奖者', href: '' }]
        })
    )
    assert.equal(decision.outcome, 'claimable')
    assert.equal(decision.dailyCta.text, '查看你是否成为即时获奖者')
})

test('does not treat bonus-activity or one-time entry CTAs as the daily control', () => {
    const ctas = [
        { tag: 'a', role: 'link', text: 'Claim your free entry', href: '/auth/login' },
        { tag: 'a', role: 'link', text: 'Earn 4 entries: Trade in 1,000 points', href: '/auth/login' },
        { tag: 'a', role: 'link', text: 'Earn 20 entries: Install Rewards extension', href: '/auth/login' },
        { tag: 'a', role: 'link', text: '中奖者', href: 'https://aka.ms/win-winners' }
    ]
    for (const cta of ctas) {
        assert.equal(isForbiddenCtaText(cta.text) || !isDailyInstantWinCtaText(cta.text), true)
    }
    const decision = classifyPrizeDropSnapshot(snapshot({ visibleText: 'Get closer to the Grand Prize with bonus entries', ctas }))
    assert.notEqual(decision.outcome, 'claimable')
    assert.notEqual(decision.outcome, 'claimed')
    assert.notEqual(decision.outcome, 'already_claimed')
    assert.equal(selectDailyInstantWinCta(ctas).reason, 'none')
})

test('ambiguous official CTAs fail closed as unverified', () => {
    const decision = classifyPrizeDropSnapshot(
        snapshot({
            visibleText: 'Instant Win',
            ctas: [
                { tag: 'button', role: 'button', text: "Check if you're a winner", href: '' },
                { tag: 'button', role: 'button', text: '查看你是否成为即时获奖者', href: '' }
            ]
        })
    )
    assert.equal(decision.outcome, 'unverified')
    assert.equal(decision.dailyCta, null)
})

test('confirmed already-used-today receipt is already_claimed and idempotent on retry', () => {
    const page = snapshot({
        visibleText: "You've already played today. Come back tomorrow to try again.",
        ctas: []
    })
    const first = classifyPrizeDropSnapshot(page)
    const second = classifyPrizeDropSnapshot(page)
    assert.equal(first.outcome, 'already_claimed')
    assert.equal(second.outcome, 'already_claimed')
})

test('confirmed post-click win and lose receipts are claimed, not unverified', () => {
    const won = classifyPrizeDropSnapshot(
        snapshot({ visibleText: 'Congratulations! You won an instant prize.', ctas: [] })
    )
    const lost = classifyPrizeDropSnapshot(
        snapshot({ visibleText: "Sorry, you didn't win. Better luck tomorrow.", ctas: [] })
    )
    assert.equal(won.outcome, 'claimed')
    assert.equal(lost.outcome, 'claimed')
})

test('unknown page is unverified and is never written as claimed', () => {
    const decision = classifyPrizeDropSnapshot(
        snapshot({
            url: TOTAL_PRIZE_DROP_URL,
            visibleText: 'Something happened. Please wait.',
            ctas: [{ tag: 'button', role: 'button', text: 'Continue', href: '' }]
        })
    )
    assert.equal(decision.outcome, 'unverified')
    assert.notEqual(decision.outcome, 'claimed')
    assert.notEqual(decision.outcome, 'already_claimed')
})

test('visible ineligible and ended states are classified without changing region', () => {
    const ineligible = classifyPrizeDropSnapshot(
        snapshot({ visibleText: 'You are not eligible for this offer in your region.', ctas: [] })
    )
    const ended = classifyPrizeDropSnapshot(
        snapshot({ visibleText: 'This promotion has ended. Thank you for your interest.', ctas: [] })
    )
    assert.equal(ineligible.outcome, 'ineligible')
    assert.equal(ended.outcome, 'unavailable')
})

test('legal footer end date alone does not mark the promotion unavailable', () => {
    const decision = classifyPrizeDropSnapshot(
        snapshot({
            visibleText:
                'NO PURCHASE NECESSARY. Instant Win and Sweepstakes: Ends 01/15/27 at 11:59:59 PM PT. Must be age of majority to enter.',
            ctas: [{ tag: 'a', role: 'link', text: 'Sign in', href: '/auth/login' }]
        })
    )
    assert.equal(decision.outcome, 'login_required')
    assert.notEqual(decision.outcome, 'unavailable')
})

test('diagnostics redact emails and do not include a claimed outcome for login pages', () => {
    const decision = classifyPrizeDropSnapshot(
        snapshot({
            url: 'https://rewards.bing.com/auth/login',
            visibleText: 'Sign in as person@example.com to continue',
            ctas: [{ tag: 'a', role: 'link', text: 'Sign in', href: '/auth/login' }]
        })
    )
    assert.equal(decision.outcome, 'login_required')
    assert.match(decision.diagnostics.visibleExcerpt, /\[alias\]/)
    assert.doesNotMatch(decision.diagnostics.visibleExcerpt, /person@example.com/)
})

test('logged-in CN daily card in progress is claimable and unique', () => {
    const decision = classifyPrizeDropSnapshot(
        snapshot({
            visibleText: '奖品赠送 每天在 Bing 上搜索，看看您是否中奖 正在进行 填写参与表单 获得100积分：安装Rewards扩展程序',
            ctas: [
                { tag: 'a', role: 'link', text: '填写参与表单', href: '' },
                { tag: 'button', role: 'button', text: '每天在 Bing 上搜索，看看您是否中奖正在进行', href: '' },
                { tag: 'a', role: 'link', text: '获得100积分：安装Rewards扩展程序', href: '' },
                { tag: 'a', role: 'link', text: '完成参赛表格', href: '' },
                { tag: 'a', role: 'link', text: '获取您的免费中奖机会填写参与表单', href: '' }
            ]
        })
    )
    assert.equal(decision.outcome, 'claimable')
    assert.equal(decision.dailyCta.text, '每天在 Bing 上搜索，看看您是否中奖正在进行')
})

test('logged-in CN daily card marked completed is already_claimed and is not clicked', () => {
    const decision = classifyPrizeDropSnapshot(
        snapshot({
            visibleText: '每天在 Bing 上搜索，看看您是否中奖 已完成',
            ctas: [{ tag: 'button', role: 'button', text: '每天在 Bing 上搜索，看看您是否中奖已完成', href: '' }]
        })
    )
    assert.equal(decision.outcome, 'already_claimed')
    assert.equal(decision.dailyCta, null)
})
