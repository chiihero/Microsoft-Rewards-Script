const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const test = require('node:test')

require('../../node_modules/ts-node/register/transpile-only.js')

const {
    accountEvidenceAlias,
    classifyPrizeDropSnapshot,
    isDailyInstantWinCtaText,
    isForbiddenCtaText,
    isOuterDailyMarketingCardText,
    isSafeOfficialDailyClaimCta,
    isUnsafeDailyClaimCta,
    selectDailyInstantWinCta,
    snapshotFromHtml,
    detectExpandedDetailsPanel,
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

test('logged-in CN outer daily card in progress is never claimable', () => {
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
    assert.equal(isOuterDailyMarketingCardText('每天在 Bing 上搜索，看看您是否中奖正在进行'), true)
    assert.equal(decision.outcome, 'unverified')
    assert.equal(decision.dailyCta, null)
    assert.notEqual(decision.outcome, 'claimable')
    assert.notEqual(decision.outcome, 'already_claimed')
    assert.notEqual(decision.outcome, 'claimed')
})

test('undated CN outer card marked completed is not already_claimed', () => {
    const decision = classifyPrizeDropSnapshot(
        snapshot({
            visibleText: '每天在 Bing 上搜索，看看您是否中奖 已完成',
            ctas: [{ tag: 'button', role: 'button', text: '每天在 Bing 上搜索，看看您是否中奖已完成', href: '' }]
        })
    )
    assert.equal(decision.outcome, 'unverified')
    assert.equal(decision.dailyCta, null)
    assert.notEqual(decision.outcome, 'already_claimed')
    assert.notEqual(decision.outcome, 'claimable')
    assert.notEqual(decision.outcome, 'claimed')
})

const landingCtas = [
    { tag: 'a', role: 'link', text: '填写参与表单', href: '' },
    { tag: 'a', role: 'link', text: '可用积分7,686兑换', href: '' },
    { tag: 'button', role: 'button', text: '每天在 Bing 上搜索，看看您是否中奖正在进行', href: '' },
    { tag: 'a', role: 'link', text: '获得100积分：安装Rewards扩展程序', href: '' },
    { tag: 'a', role: 'link', text: '完成参赛表格', href: '' },
    { tag: 'a', role: 'link', text: '获取您的免费中奖机会填写参与表单', href: '' }
]

const afterPanelCtas = [
    ...landingCtas,
    { tag: 'button', role: 'button', text: '填写报名表', href: '' },
    { tag: 'a', role: 'link', text: '权益说明', href: '' },
    { tag: 'a', role: 'link', text: '查看条款', href: '' }
]

test('real CN landing page with only the outer card is unverified, not claimed', () => {
    const decision = classifyPrizeDropSnapshot(
        snapshot({
            visibleText: '奖品赠送 每天在 Bing 上搜索，看看您是否中奖 正在进行 首先，完成您的参赛表格。完成参赛表格 获取您的免费中奖机会 填写参与表单',
            ctas: landingCtas
        })
    )
    assert.equal(decision.outcome, 'unverified')
    assert.equal(decision.dailyCta, null)
    assert.notEqual(decision.outcome, 'claimable')
    assert.notEqual(decision.outcome, 'already_claimed')
    assert.notEqual(decision.outcome, 'claimed')
})

test('opening the CN details panel is unverified, not a win or already-claimed receipt', () => {
    const before = snapshot({
        visibleText: '每天在 Bing 上搜索，看看您是否中奖 正在进行 首先，完成您的参赛表格。',
        ctas: landingCtas
    })
    const after = snapshot({
        visibleText: '每天在 Bing 上搜索，看看您是否中奖 正在进行 首先，完成您的参赛表格。填写报名表 权益说明 查看条款',
        ctas: afterPanelCtas
    })
    assert.equal(classifyPrizeDropSnapshot(after).outcome, 'unverified')
    assert.equal(classifyPrizeDropSnapshot(after).dailyCta, null)
    assert.equal(detectExpandedDetailsPanel(before, after), true)
    assert.notEqual(classifyPrizeDropSnapshot(after).outcome, 'claimed')
    assert.notEqual(classifyPrizeDropSnapshot(after).outcome, 'already_claimed')
    assert.notEqual(classifyPrizeDropSnapshot(after).outcome, 'claimable')
})

test('unverified outcomes stay retryable and do not become already_claimed', () => {
    const DailyInstantWin = require('../../src/functions/activities/rewards/DailyInstantWin.ts').DailyInstantWin
    const activity = Object.create(DailyInstantWin.prototype)
    activity.lastResult = {
        outcome: 'unverified',
        reason: 'click opened a details panel',
        clicked: true,
        diagnostics: { url: TOTAL_PRIZE_DROP_URL, ctaTexts: [], visibleExcerpt: '' }
    }
    assert.equal(activity.isTerminal('unverified'), false)
    assert.equal(activity.isTerminal('error'), false)
    assert.equal(activity.isTerminal('ineligible'), false)
    assert.equal(activity.isTerminal('login_required'), false)
    assert.equal(activity.isTerminal('unavailable'), false)
    assert.equal(activity.isTerminal('claimable'), false)
    assert.equal(activity.isTerminal('claimed'), true)
    assert.equal(activity.isTerminal('already_claimed'), true)
})

test('authorization: official Check-winner linked to signup is not claimable', () => {
    const decision = decisionFromHtml('sweeps-check-winner-signup-href.html')
    assert.equal(decision.outcome, 'unverified')
    assert.equal(decision.dailyCta, null)
    const cta = { tag: 'a', role: 'link', text: "Check if you're a winner", href: 'https://rewards.bing.com/sweeps/signup' }
    assert.equal(isUnsafeDailyClaimCta(cta), true)
    assert.equal(isSafeOfficialDailyClaimCta(cta), false)
    assert.equal(selectDailyInstantWinCta([cta]).reason, 'none')
})

test('authorization: Check-winner in an entry-form or additional-terms context is not claimable', () => {
    const decision = decisionFromHtml('sweeps-check-winner-in-form.html')
    assert.equal(decision.outcome, 'unverified')
    assert.equal(decision.dailyCta, null)
    const inForm = {
        tag: 'button',
        role: 'button',
        text: "Check if you're a winner",
        href: '',
        inForm: true,
        formAction: '/sweeps/signup',
        inputType: 'submit',
        contextText: 'Additional terms and official rules must be accepted.'
    }
    assert.equal(isUnsafeDailyClaimCta(inForm), true)
    assert.equal(isSafeOfficialDailyClaimCta(inForm), false)
    const termsContext = {
        tag: 'button',
        role: 'button',
        text: "Check if you're a winner",
        href: '',
        contextText: '填写报名表 权益说明 查看条款'
    }
    assert.equal(isUnsafeDailyClaimCta(termsContext), true)
    assert.equal(isSafeOfficialDailyClaimCta(termsContext), false)
})

test('authorization: signup / 报名条款 page is never a daily claim target', () => {
    const decision = decisionFromHtml('sweeps-signup-form-zh.html', 'https://rewards.bing.com/sweeps/signup')
    assert.notEqual(decision.outcome, 'claimable')
    assert.notEqual(decision.outcome, 'claimed')
    assert.notEqual(decision.outcome, 'already_claimed')
    assert.equal(decision.dailyCta, null)
    assert.ok(['unverified', 'login_required'].includes(decision.outcome))
})

test('explicit already-used-today receipt is still already_claimed; undated 已完成 is not', () => {
    const dated = classifyPrizeDropSnapshot(
        snapshot({ visibleText: "You've already played today. Come back tomorrow to try again.", ctas: [] })
    )
    const undated = classifyPrizeDropSnapshot(
        snapshot({
            visibleText: '活动状态：已完成',
            ctas: [{ tag: 'button', role: 'button', text: '每天在 Bing 上搜索，看看您是否中奖已完成', href: '' }]
        })
    )
    assert.equal(dated.outcome, 'already_claimed')
    assert.equal(undated.outcome, 'unverified')
    assert.notEqual(undated.outcome, 'already_claimed')
})

test('account evidence alias is stable and does not contain the username', () => {
    const alias = accountEvidenceAlias('SecretUser@example.com')
    assert.match(alias, /^acct-[a-f0-9]{12}$/)
    assert.equal(alias, accountEvidenceAlias('SecretUser@example.com'))
    assert.doesNotMatch(alias, /SecretUser/i)
    assert.doesNotMatch(alias, /example/)
    assert.notEqual(alias, accountEvidenceAlias('other-user'))
})

test('error and unverified results are not cached as today-complete on retry', async () => {
    const DailyInstantWin = require('../../src/functions/activities/rewards/DailyInstantWin.ts').DailyInstantWin
    const activity = Object.create(DailyInstantWin.prototype)
    activity.isTerminal = DailyInstantWin.prototype.isTerminal
    activity.finish = DailyInstantWin.prototype.finish
    activity.logDecision = () => {}
    activity.markExecuted = () => {}
    activity.lastResult = {
        outcome: 'error',
        reason: 'temporary failure',
        clicked: false,
        diagnostics: { url: TOTAL_PRIZE_DROP_URL, ctaTexts: [], visibleExcerpt: '' }
    }
    assert.equal(activity.isTerminal(activity.lastResult.outcome), false)
    let ran = false
    activity.getActivePage = () => {
        ran = true
        return null
    }
    activity.bot = { isMobile: false, logger: { info() {}, warn() {} }, userData: { geoLocale: 'CN' } }
    const result = await DailyInstantWin.prototype.run.call(activity)
    assert.equal(ran, true)
    assert.equal(result.outcome, 'error')
    assert.equal(result.clicked, false)
    assert.equal(activity.isTerminal(result.outcome), false)
})

test('DIAGNOSE never dismisses popups, never clicks, and never submits', async () => {
    const DailyInstantWin = require('../../src/functions/activities/rewards/DailyInstantWin.ts').DailyInstantWin
    const activity = Object.create(DailyInstantWin.prototype)
    let dismissCalls = 0
    let clickCalls = 0
    let submitCalls = 0
    let artifacts = 0
    activity.lastResult = null
    activity.isTerminal = DailyInstantWin.prototype.isTerminal
    activity.finish = DailyInstantWin.prototype.finish
    activity.logDecision = () => {}
    activity.markExecuted = () => {}
    activity.saveDiagnoseArtifacts = async () => {
        artifacts += 1
    }
    activity.clickOfficialDailyCta = async () => {
        clickCalls += 1
        return true
    }
    activity.captureSnapshot = async () =>
        snapshot({
            visibleText: 'Instant Win',
            ctas: [{ tag: 'button', role: 'button', text: "Check if you're a winner", href: '' }]
        })
    const page = {
        url: () => TOTAL_PRIZE_DROP_URL,
        goto: async () => {},
        click: async () => {
            clickCalls += 1
        },
        locator: () => ({
            filter: () => ({ count: async () => 1, first: () => ({ click: async () => { clickCalls += 1 } }) })
        })
    }
    activity.getActivePage = () => page
    activity.bot = {
        isMobile: false,
        userData: { geoLocale: 'CN', userName: 'SecretUser' },
        logger: { info() {}, warn() {} },
        browser: {
            utils: {
                tryDismissAllMessages: async () => {
                    dismissCalls += 1
                },
                acceptButton: async () => {
                    clickCalls += 1
                }
            }
        },
        utils: { wait: async () => {}, randomDelay: () => 1 },
        mainDesktopPage: page
    }
    const previous = process.env.DAILY_INSTANT_WIN_DIAGNOSE
    process.env.DAILY_INSTANT_WIN_DIAGNOSE = '1'
    try {
        const result = await DailyInstantWin.prototype.run.call(activity)
        assert.equal(result.outcome, 'unverified')
        assert.equal(result.clicked, false)
        assert.match(result.reason, /diagnose-only/)
        assert.equal(dismissCalls, 0)
        assert.equal(clickCalls, 0)
        assert.equal(submitCalls, 0)
        assert.equal(artifacts, 1)
        assert.equal(activity.isTerminal(result.outcome), false)
    } finally {
        if (previous === undefined) delete process.env.DAILY_INSTANT_WIN_DIAGNOSE
        else process.env.DAILY_INSTANT_WIN_DIAGNOSE = previous
    }
})
