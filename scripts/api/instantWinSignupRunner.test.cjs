const assert = require('node:assert/strict')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const test = require('node:test')

require('../../node_modules/ts-node/register/transpile-only.js')

const {
    classifyPrizeDropSnapshot,
    snapshotFromHtml,
    TOTAL_PRIZE_DROP_URL
} = require('../../src/functions/activities/rewards/totalPrizeDropPage.ts')

const {
    buildStatusRecord,
    clickedAfterExecutionError,
    instantWinTodayKey,
    loadStatusRecord,
    saveStatusRecord,
    shouldSkipSameDayAction,
    toPublicStatus
} = require('../../src/functions/activities/rewards/instantWinStatus.ts')

const {
    evaluateSignupSubmitResult,
    loadSignupProfileFromFile,
    maskPhoneNumber,
    planSignupSubmit,
    signupRunnerEnabled
} = require('../../src/functions/activities/rewards/instantWinSignup.ts')

const fixtures = path.join(__dirname, 'fixtures')
const PLACEHOLDER_PHONE = '13000000000'

function html(file, url) {
    return snapshotFromHtml(fs.readFileSync(path.join(fixtures, file), 'utf8'), url)
}

function writeProfile(overrides = {}, mode = 0o600) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'iw-profile-'))
    const file = path.join(dir, 'profile.json')
    const body = {
        residence: 'CN',
        phoneCountryCode: '+86',
        nationalPhoneNumber: PLACEHOLDER_PHONE,
        ...overrides
    }
    fs.writeFileSync(file, JSON.stringify(body))
    fs.chmodSync(file, mode)
    return { dir, file }
}

test('signup runner stays disabled unless the explicit env flag is set', () => {
    const prev = process.env.DAILY_INSTANT_WIN_SIGNUP
    delete process.env.DAILY_INSTANT_WIN_SIGNUP
    assert.equal(signupRunnerEnabled(), false)
    const snapshot = html('sweeps-signup-prefilled-zh.html', 'https://rewards.bing.com/sweeps/signup')
    const plan = planSignupSubmit({ snapshot, profile: { residence: 'CN', phoneCountryCode: '+86', nationalPhoneNumber: PLACEHOLDER_PHONE }, enabled: false })
    assert.equal(plan.action, 'stop')
    assert.match(plan.reason, /disabled/)
    process.env.DAILY_INSTANT_WIN_SIGNUP = prev
})

test('empty or unreadable signup profile never submits', () => {
    const snapshot = html('sweeps-signup-prefilled-zh.html', 'https://rewards.bing.com/sweeps/signup')
    const empty = planSignupSubmit({ snapshot, profile: null, profileError: 'signup profile is empty', enabled: true })
    assert.equal(empty.action, 'stop')
    assert.equal(empty.outcome, 'missing_profile_fields')
    assert.notEqual(empty.action, 'submit')

    const loose = writeProfile({}, 0o644)
    const loadedLoose = loadSignupProfileFromFile(loose.file)
    assert.ok(loadedLoose.error)
    assert.match(loadedLoose.error, /0600|group- or world/)
    const planLoose = planSignupSubmit({ snapshot, profile: loadedLoose.profile, profileError: loadedLoose.error, enabled: true })
    assert.equal(planLoose.action, 'stop')
    fs.rmSync(loose.dir, { recursive: true, force: true })

    const missing = loadSignupProfileFromFile('')
    assert.ok(missing.error)
})

test('authorized 0600 profile with official prefill, China option, and US default can be planned without keeping US', () => {
    const { dir, file } = writeProfile()
    const loaded = loadSignupProfileFromFile(file)
    assert.equal(loaded.error, undefined)
    assert.equal(loaded.profile.phoneCountryCode, '+86')
    assert.equal(loaded.profile.residence, 'CN')
    const snapshot = html('sweeps-signup-prefilled-zh.html', 'https://rewards.bing.com/sweeps/signup')
    const country = snapshot.formFields.find(field => field.name === 'country')
    assert.equal(country.selectedText.includes('美国') || country.selectedText === '美国', true)
    const plan = planSignupSubmit({ snapshot, profile: loaded.profile, enabled: true })
    assert.equal(plan.action, 'submit')
    assert.ok(plan.fills.some(item => item.kind === 'select-country' && /中国|CN/i.test(item.option)))
    assert.ok(plan.fills.some(item => item.kind === 'phone-country-code'))
    assert.ok(plan.fills.some(item => item.kind === 'national-phone'))
    assert.ok(plan.fills.some(item => item.kind === 'accept-terms'))
    assert.equal(plan.submitText, '立即参与')
    assert.equal(plan.fills.some(item => item.kind === 'select-country' && /美国|US/.test(item.option) && !/中国|CN/i.test(item.option)), false)
    const raw = fs.readFileSync(file, 'utf8')
    // placeholder only; masked helper never echoes the full number in logs
    assert.equal(maskPhoneNumber(PLACEHOLDER_PHONE).includes(PLACEHOLDER_PHONE), false)
    assert.doesNotMatch(maskPhoneNumber(PLACEHOLDER_PHONE), /13000000000/)
    fs.rmSync(dir, { recursive: true, force: true })
    void raw
})

test('China missing from country options fails closed and does not submit', () => {
    const snapshot = {
        url: 'https://rewards.bing.com/sweeps/signup',
        visibleText: '要参与，请填写报名表',
        ctas: [{ tag: 'button', role: 'button', text: '立即参与', href: '', inForm: true, inputType: 'submit' }],
        formFields: [
            { name: 'firstName', label: '法定名字', type: 'text', required: true, hasValue: true, valueLength: 8 },
            { name: 'lastName', label: '法定姓氏', type: 'text', required: true, hasValue: true, valueLength: 7 },
            { name: 'email', label: '电子邮件', type: 'email', required: true, hasValue: true, valueLength: 18 },
            { name: 'nationalPhoneNumber', label: '电话号码', type: 'tel', required: true, hasValue: false, valueLength: 0 },
            { name: 'country', label: '国家/地区', type: 'select-one', required: true, hasValue: true, selectedText: '美国', options: ['美国', '加拿大'] },
            { name: 'officialRulesAccepted', label: '官方规则', type: 'checkbox', required: false, hasValue: false, checked: false }
        ]
    }
    const plan = planSignupSubmit({
        snapshot,
        profile: { residence: 'CN', phoneCountryCode: '+86', nationalPhoneNumber: PLACEHOLDER_PHONE },
        enabled: true
    })
    assert.equal(plan.action, 'stop')
    assert.equal(plan.outcome, 'ineligible')
    assert.match(plan.reason, /China is not a selectable/)
})

test('unknown required field fails closed and is not guessed', () => {
    const snapshot = html('sweeps-signup-prefilled-zh.html', 'https://rewards.bing.com/sweeps/signup')
    snapshot.formFields.push({
        name: 'dateOfBirth',
        label: '出生日期',
        type: 'date',
        required: true,
        hasValue: false,
        valueLength: 0
    })
    const plan = planSignupSubmit({
        snapshot,
        profile: { residence: 'CN', phoneCountryCode: '+86', nationalPhoneNumber: PLACEHOLDER_PHONE },
        enabled: true
    })
    assert.equal(plan.action, 'stop')
    assert.ok(plan.blockedFields.includes('dateOfBirth'))
    assert.match(plan.reason, /unknown required field/)
})

test('missing official name or email prefill is not invented and is not submitted', () => {
    const snapshot = html('sweeps-signup-form-zh.html', 'https://rewards.bing.com/sweeps/signup')
    const plan = planSignupSubmit({
        snapshot,
        profile: { residence: 'CN', phoneCountryCode: '+86', nationalPhoneNumber: PLACEHOLDER_PHONE },
        enabled: true
    })
    assert.equal(plan.action, 'stop')
    assert.equal(plan.outcome, 'missing_profile_fields')
    assert.match(plan.reason, /prefill is missing/)
})

test('profile identity fields are rejected so official prefill cannot be overwritten', () => {
    const { dir, file } = writeProfile()
    fs.writeFileSync(file, JSON.stringify({
        residence: 'CN',
        phoneCountryCode: '+86',
        nationalPhoneNumber: PLACEHOLDER_PHONE,
        firstName: 'Invented'
    }))
    fs.chmodSync(file, 0o600)
    const loaded = loadSignupProfileFromFile(file)
    assert.ok(loaded.error)
    assert.match(loaded.error, /must not include name/)
    fs.rmSync(dir, { recursive: true, force: true })
})

test('already-registered receipt does not submit again', () => {
    const snapshot = {
        url: 'https://rewards.bing.com/sweeps/signup',
        visibleText: '报名成功，您已完成参赛表格',
        ctas: [{ tag: 'button', role: 'button', text: "Check if you're a winner", href: '' }],
        formFields: []
    }
    const plan = planSignupSubmit({
        snapshot,
        profile: { residence: 'CN', phoneCountryCode: '+86', nationalPhoneNumber: PLACEHOLDER_PHONE },
        enabled: true
    })
    assert.equal(plan.action, 'already_registered')
    assert.equal(plan.signupComplete, true)
})

test('privacy mask does not leak the placeholder phone into diagnostics helpers', () => {
    const masked = maskPhoneNumber(PLACEHOLDER_PHONE)
    assert.equal(masked, '13****00')
    assert.doesNotMatch(masked, /13000000000/)
})

test('OTP or captcha on a signup page with an outside-form Check-winner is not claimable', () => {
    const decision = classifyPrizeDropSnapshot(
        html('sweeps-signup-otp-outside-cta.html', 'https://rewards.bing.com/sweeps/signup')
    )
    assert.notEqual(decision.outcome, 'claimable')
    assert.equal(decision.challenge, true)
    assert.equal(decision.dailyCta, null)
    assert.equal(decision.outcome, 'unverified')
})

test('signup page prize-example wording is not a daily claimed receipt', () => {
    const decision = classifyPrizeDropSnapshot(
        html('sweeps-signup-prize-example.html', 'https://rewards.bing.com/sweeps/signup')
    )
    assert.notEqual(decision.outcome, 'claimed')
    assert.notEqual(decision.outcome, 'already_claimed')
    assert.equal(decision.outcome, 'missing_profile_fields')
    assert.ok(decision.blockedFields.includes('nationalPhoneNumber'))
})

test('undated English used-chance text is unverified, not today confirmed', () => {
    const decision = classifyPrizeDropSnapshot({
        url: TOTAL_PRIZE_DROP_URL,
        visibleText: 'You already used instant win chance.',
        ctas: []
    })
    assert.notEqual(decision.outcome, 'already_claimed')
    assert.notEqual(decision.outcome, 'claimed')
    assert.equal(decision.outcome, 'unverified')
    assert.notEqual(toPublicStatus(decision.outcome), 'confirmed')
})

test('dated already-played-today receipt remains already_claimed', () => {
    const decision = classifyPrizeDropSnapshot({
        url: TOTAL_PRIZE_DROP_URL,
        visibleText: "You've already played today. Come back tomorrow to try again.",
        ctas: []
    })
    assert.equal(decision.outcome, 'already_claimed')
})

test('click attempt is recorded before a receipt error so a second instance does not click again', () => {
    const today = instantWinTodayKey(new Date('2026-11-22T12:00:00+08:00'), 'Asia/Shanghai')
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'iw-attempt-'))
    const first = buildStatusRecord({
        outcome: 'unverified',
        reason: 'official daily click attempted; receipt pending',
        clicked: true,
        now: new Date('2026-11-22T12:00:00+08:00')
    })
    saveStatusRecord(dir, 'acct-demo000001', first)
    // receipt capture throws; finish must preserve clicked=true
    const afterError = clickedAfterExecutionError(true, false)
    assert.equal(afterError, true)
    const saved = loadStatusRecord(dir, 'acct-demo000001')
    const secondSkip = shouldSkipSameDayAction(saved, today)
    assert.equal(secondSkip, true)
    assert.equal(saved.clicked, true)
    assert.notEqual(saved.outcome, 'claimed')
    fs.rmSync(dir, { recursive: true, force: true })
})

test('signup success receipt is not a daily win and a disabled button is not success', () => {
    const before = html('sweeps-signup-prefilled-zh.html', 'https://rewards.bing.com/sweeps/signup')
    const success = evaluateSignupSubmitResult({
        before,
        after: {
            url: 'https://rewards.bing.com/sweeps/signup',
            visibleText: '报名成功，您已完成参赛表格',
            ctas: [{ tag: 'button', role: 'button', text: "Check if you're a winner", href: '' }],
            formFields: []
        },
        submitted: true
    })
    assert.equal(success.success, true)
    assert.equal(success.signupComplete, true)
    assert.equal(success.dailyCtaVisible, true)
    assert.equal(success.resubmit, false)

    const disabledOnly = evaluateSignupSubmitResult({
        before,
        after: {
            url: 'https://rewards.bing.com/sweeps/signup',
            visibleText: '要参与，请填写报名表',
            ctas: [{ tag: 'button', role: 'button', text: '立即参与', href: '', inForm: true, inputType: 'submit' }],
            formFields: [{ name: 'submit', label: '立即参与', type: 'submit', required: false, hasValue: false, disabled: true }]
        },
        submitted: true
    })
    assert.equal(disabledOnly.success, false)
    assert.equal(disabledOnly.signupComplete, false)
    assert.equal(disabledOnly.resubmit, false)
    assert.match(disabledOnly.reason, /not treated as success/)
})

test('status files are written 0600 and never contain the placeholder phone', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'iw-state-'))
    const record = buildStatusRecord({
        outcome: 'missing_profile_fields',
        reason: 'signup form is visible and required profile fields are empty',
        clicked: false,
        blockedFields: ['nationalPhoneNumber']
    })
    saveStatusRecord(dir, 'acct-demo000002', record)
    const file = path.join(dir, 'acct-demo000002.json')
    const raw = fs.readFileSync(file, 'utf8')
    const mode = fs.statSync(file).mode & 0o777
    assert.equal(mode, 0o600)
    assert.doesNotMatch(raw, new RegExp(PLACEHOLDER_PHONE))
    fs.rmSync(dir, { recursive: true, force: true })
})
