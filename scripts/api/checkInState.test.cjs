const assert = require('node:assert/strict')
const test = require('node:test')
require('../../node_modules/ts-node/register/transpile-only.js')
const BrowserFunc = require('../../src/browser/BrowserFunc.ts').default
const { DailyCheckIn } = require('../../src/functions/activities/app/DailyCheckIn.ts')
const { resolveCheckInState } = require('../../src/functions/activities/app/CheckInState.ts')
const { createBot: createActivityBot, account } = require('./rewardsPoints.fixture.cjs')

const now = new Date('2026-10-24T05:00:00Z')
for (const channel of [undefined, 'SAAndroid']) {
    test(`App dashboard query uses ${channel ?? 'the existing SAIOS default'}`, async t => {
        const { bot } = createActivityBot(t)
        bot.http.request = t.mock.fn(async () => ({ data: { response: { promotions: [] } } }))
        await new BrowserFunc(bot).getAppDashboardData(channel)
        assert.ok(bot.http.request.mock.calls[0].arguments[0].url.includes(`channel=${channel ?? 'SAIOS'}`))
    })
}
function legacy(overrides = {}) {
    return {
        name: 'Gamification_Sapphire_DailyCheckIn_Promotion',
        attributes: {
            offerid: 'Gamification_Sapphire_DailyCheckIn',
            type: 'checkin',
            progress: '1',
            day_1_points: '5',
            day_2_points: '5',
            last_updated: '2026-10-22T17:00:00Z',
            ...overrides
        }
    }
}
function streak(updatedAt = '2026-10-23T17:26:19.6377348+00:00') {
    return {
        name: 'Gamification_Streak_Counter_Promotion',
        attributes: {
            type: 'streak',
            activity_progress: '26',
            last_updated: updatedAt
        }
    }
}
const recordedLegacy = legacy({ hidden: 'True', last_updated: '2024-10-18T08:21:27.1990138+00:00' })

test('Main leaves the App remaining total unknown when only stale check-in data is available', async t => {
    t.mock.timers.enable({ apis: ['Date'], now: now.getTime() })
    const { bot } = createActivityBot(t)
    bot.config.workers.doDailyCheckIn = true
    bot.http.request = t.mock.fn(async () => ({ data: { response: { promotions: [recordedLegacy] } } }))
    bot.browser.func.getAppEarnablePoints = () => new BrowserFunc(bot).getAppEarnablePoints()
    await bot.Main(account)
    const message = bot.logger.info.mock.calls.find(call => call.arguments[1] === 'POINTS').arguments[2]
    assert.match(message, /App: 未知/)
})

for (const [name, promotions, status, remaining] of [
    ['recorded current check-in overrides stale hidden promotion', [recordedLegacy, streak()], 'complete', 0],
    ['stale hidden promotion alone does not invent five points', [recordedLegacy], 'unknown', null],
    ['missing timestamp remains unknown', [legacy({ last_updated: '' })], 'unknown', null],
    ['invalid timestamp remains unknown', [legacy({ last_updated: 'invalid' })], 'unknown', null],
    [
        'same day number in a previous month is not today',
        [legacy({ last_updated: '2026-09-24T01:00:00Z' })],
        'pending',
        5
    ],
    [
        'same day number in a previous year is not today',
        [legacy({ last_updated: '2025-10-24T01:00:00Z' })],
        'pending',
        5
    ],
    ['China date uses the date after UTC midnight offset', [streak()], 'complete', 0],
    ['previous China date is not already checked in', [legacy(), streak('2026-10-23T15:59:00Z')], 'pending', 5],
    ['seventh day reads its explicit reward', [legacy({ progress: '6', day_7_points: '20' })], 'pending', 20],
    ['new seven-day cycle returns to the first day', [legacy({ progress: '7' })], 'pending', 5],
    [
        'future timestamp is not a completed check-in',
        [legacy({ last_updated: '2026-10-25T05:00:00Z' })],
        'unknown',
        null
    ],
    ['invalid progress does not invent points', [legacy({ progress: 'bad' })], 'unknown', null],
    ['missing promotion remains unknown', [], 'unknown', null]
]) {
    test(name, () => {
        const state = resolveCheckInState(promotions, 'CN', now)
        assert.equal(state.status, status)
        assert.equal(state.remaining, remaining)
    })
}

for (const completed of [true, false]) {
    test(`App remaining points ${completed ? 'confirm today complete' : 'stay unknown for stale hidden data'}`, async t => {
        t.mock.timers.enable({ apis: ['Date'], now: now.getTime() })
        const { bot } = createActivityBot(t)
        bot.http.request = t.mock.fn(async () => ({
            data: {
                response: {
                    promotions: completed ? [recordedLegacy, streak()] : [recordedLegacy]
                }
            }
        }))
        const points = await new BrowserFunc(bot).getAppEarnablePoints()
        assert.equal(points.checkIn, completed ? 0 : null)
        assert.equal(points.totalEarnablePoints, completed ? 0 : null)
    })
}

function checkInBot(t, promotions = [legacy()]) {
    t.mock.timers.enable({ apis: ['Date'], now: now.getTime() })
    const { bot } = createActivityBot(t)
    bot.accessToken = 'offline-token'
    bot.http.request = t.mock.fn(async () => ({ status: 200, data: { code: 0, response: { balance: 100 } } }))
    bot.browser.func.getAppDashboardData = t.mock.fn(async () => ({ response: { promotions } }))
    return bot
}

test('already checked-in account skips the repeated request', async t => {
    const bot = checkInBot(t, [recordedLegacy, streak()])
    const activity = new DailyCheckIn(bot)
    await activity.doDailyCheckIn()

    assert.equal(bot.http.request.mock.callCount(), 0)
    assert.equal(bot.userData.gainedPoints, 0)
})

test('a pending check-in credits only the observed balance change', async t => {
    const bot = checkInBot(t)
    bot.http.request = t.mock.fn(async () => ({ status: 200, data: { code: 0, response: { balance: 105 } } }))
    const activity = new DailyCheckIn(bot)
    await activity.doDailyCheckIn()

    assert.equal(bot.http.request.mock.callCount(), 1)
    assert.equal(bot.userData.currentPoints, 105)
    assert.equal(bot.userData.gainedPoints, 5)
})

for (const promotions of [[legacy()], []]) {
    test(`zero balance change with ${promotions.length ? 'pending' : 'unknown'} task state is not called complete`, async t => {
        const bot = checkInBot(t, promotions)
        const activity = new DailyCheckIn(bot)
        await assert.rejects(activity.doDailyCheckIn(), /签到未确认到账/)

        assert.equal(bot.userData.gainedPoints, 0)
        assert.ok(!bot.logger.info.mock.calls.some(call => /每日签到完成/.test(call.arguments[2])))
    })
}

for (const response of [
    { status: 500, data: { code: 0, response: { balance: 105 } } },
    { status: 200, data: { code: 9, response: { balance: 105 } } }
]) {
    test(`unsuccessful check-in status=${response.status} code=${response.data.code} does not credit points`, async t => {
        const bot = checkInBot(t)
        bot.http.request = async () => response
        await assert.rejects(new DailyCheckIn(bot).doDailyCheckIn(), /签到接口未确认成功/)
        assert.equal(bot.userData.gainedPoints, 0)
    })
}

test('missing response balance is verified by a fresh balance query', async t => {
    const bot = checkInBot(t)
    bot.http.request = async () => ({ status: 200, data: { code: 0 } })
    bot.browser.func.getCurrentPoints = t.mock.fn(async () => 105)
    await new DailyCheckIn(bot).doDailyCheckIn()
    assert.equal(bot.browser.func.getCurrentPoints.mock.callCount(), 1)
    assert.equal(bot.userData.gainedPoints, 5)
})

test('invalid balance cannot be replaced with a successful zero-point result', async t => {
    const bot = checkInBot(t)
    bot.http.request = async () => ({ status: 200, data: { code: 0 } })
    bot.browser.func.getCurrentPoints = async () => NaN
    await assert.rejects(new DailyCheckIn(bot).doDailyCheckIn(), /无法取得有效余额/)
})

test('connection reset is propagated to the caller', async t => {
    const bot = checkInBot(t)
    bot.http.request = async () => {
        throw new Error('ConnectionReset (10054)')
    }
    await assert.rejects(new DailyCheckIn(bot).doDailyCheckIn(), /10054/)
})

test('a post-request completion record confirms the day without inventing a balance gain', async t => {
    const bot = checkInBot(t)
    let reads = 0
    bot.browser.func.getAppDashboardData = async () => ({
        response: { promotions: ++reads === 1 ? [legacy()] : [streak()] }
    })
    await new DailyCheckIn(bot).doDailyCheckIn()
    assert.equal(bot.userData.gainedPoints, 0)
    assert.ok(bot.logger.info.mock.calls.some(call => /本次无新增积分/.test(call.arguments[2])))
})

for (const mode of ['browser', 'full-api']) {
    test(mode + ': unconfirmed check-in preserves later tasks and the failure result', async t => {
        const { bot } = createActivityBot(t)
        bot.config.workers = { doDailyCheckIn: true, doReadToEarn: true, doMobileSearch: true }
        bot.config.experimental.apiSearch = mode === 'full-api'
        bot.http.request = t.mock.fn(async () => ({ status: 200, data: { code: 0, response: { balance: 100 } } }))
        bot.activities.doDailyCheckIn = () => new DailyCheckIn(bot).doDailyCheckIn()
        const later = []
        bot.activities.doReadToEarn = async () => {
            later.push('read')
        }
        bot.searchManager.getSearchPoints = async () => ({ doMobile: true, doDesktop: false })
        bot.searchManager.searchMobile = async () => {
            later.push('search')
            return 10
        }
        bot.browser.func.getCurrentPoints = async () => 110
        const result = await bot.Main(account)
        assert.deepEqual(later, ['read', 'search'])
        assert.match(result.error, /签到未确认到账/)
        assert.equal(result.initialPoints, 100)
        assert.equal(result.collectedPoints, 10)
        assert.deepEqual(
            bot.utils.wait.mock.calls.map(call => call.arguments),
            [[60000], [60000]]
        )
    })
}
