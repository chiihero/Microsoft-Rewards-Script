const assert = require('node:assert/strict')
const test = require('node:test')
require('../../node_modules/ts-node/register/transpile-only.js')
const Activities = require('../../src/functions/Activities.ts').default
const { createActivityBot, createFlowBot, account } = require('./workerGaps.fixture.cjs')

function setupFlow(t, { needMobile = false, punchCards = false, restoreError = false, closeError = false } = {}) {
    const { bot, events } = createFlowBot(t, 'browser')
    bot.config.workers = { doReadToEarn: true, doMobileSearch: true, doPunchCards: punchCards }
    bot.config.ensureStreakProtection = false
    let session = 0
    bot.browserFactory.createBrowser = t.mock.fn(async () => {
        session++
        events.push('create:' + session)
        if (session > 1 && restoreError) throw new Error('restore failed')
        return { context: { newPage: async () => ({ id: session }), cookies: async () => [] }, fingerprint: {} }
    })
    bot.browser.func.closeBrowser = t.mock.fn(async () => {
        events.push('close')
        if (closeError) throw new Error('close failed')
    })
    bot.login.login = t.mock.fn(async page => events.push('login:' + page.id))
    bot.activities.doReadToEarn = t.mock.fn(async cb => {
        events.push('read')
        if (cb) {
            events.push('read-release')
            try {
                await cb()
            } catch {
                events.push('release-error')
            }
        }
        events.push('read-wait')
        return true
    })
    bot.activities.doPunchCardsMobile = t.mock.fn(async () => {
        events.push('punch:' + bot.mainMobilePage.id)
        return false
    })
    bot.searchManager.getSearchPoints = t.mock.fn(async () => ({ doMobile: needMobile, doDesktop: false }))
    bot.searchManager.searchMobile = t.mock.fn(async () => {
        events.push('search:' + bot.mainMobilePage.id)
        return 0
    })
    return { bot, events }
}

test('closes the idle mobile browser before reading waits', async t => {
    const { bot, events } = setupFlow(t)
    await bot.Main(account)
    assert.equal(bot.browserFactory.createBrowser.mock.callCount(), 1)
    assert.ok(events.indexOf('close') < events.indexOf('read-wait'))
})

test('restores the mobile session before punchcards and reuses it for mobile search', async t => {
    const { bot, events } = setupFlow(t, { needMobile: true, punchCards: true })
    await bot.Main(account)
    assert.equal(bot.browserFactory.createBrowser.mock.callCount(), 3)
    assert.ok(events.indexOf('read-wait') < events.indexOf('login:2'))
    assert.ok(events.indexOf('login:2') < events.indexOf('punch:2'))
    assert.ok(events.indexOf('punch:2') < events.indexOf('search:2'))
    assert.equal(bot.browser.func.closeBrowser.mock.callCount(), 3)
})

test('restores the mobile session before search when punchcards are disabled', async t => {
    const { bot, events } = setupFlow(t, { needMobile: true })
    await bot.Main(account)
    assert.ok(events.indexOf('login:2') < events.indexOf('search:2'))
})

test('a failed session restore does not run punchcards or search on a closed page', async t => {
    const { bot } = setupFlow(t, { needMobile: true, punchCards: true, restoreError: true })
    await assert.rejects(() => bot.Main(account), /restore failed/)
    assert.equal(bot.activities.doPunchCardsMobile.mock.callCount(), 0)
    assert.equal(bot.searchManager.searchMobile.mock.callCount(), 0)
})

test('a failed close keeps the session available for cleanup', async t => {
    const { bot, events } = setupFlow(t, { closeError: true })
    await assert.rejects(() => bot.Main(account), /close failed/)
    assert.ok(events.includes('release-error'))
    assert.ok(bot.browser.func.closeBrowser.mock.callCount() >= 2)
})

for (const [name, configure] of [
    ['parallel search', bot => (bot.config.searchSettings.parallelSearching = true)],
    ['bonus search', bot => (bot.config.workers.doBonusSearches = true)],
    ['background Edge activity', bot => (bot.config.experimental.edgeBrowsing = true)],
    ['API search', bot => (bot.config.experimental.apiSearch = true)]
]) {
    test(name + ' retains its original browser lifecycle', async t => {
        const { bot, events } = setupFlow(t)
        configure(bot)
        bot.searchManager.bonusMobile = async () => 0
        bot.activities.doEdgeBrowsing = async () => {}
        await bot.Main(account)
        assert.equal(events.includes('read-release'), false)
    })
}

test('releases once before the first reading wait without changing requests or intervals', async t => {
    const { bot } = createActivityBot(t)
    bot.accessToken = 'test-token'
    let balance = 100
    bot.http.request = t.mock.fn(async () => ({ status: 200, data: { response: { balance: (balance += 3) } } }))
    let released = 0
    await new Activities(bot).doReadToEarn(async () => {
        assert.equal(bot.http.request.mock.callCount(), 1)
        assert.equal(bot.utils.wait.mock.callCount(), 0)
        released++
    })
    assert.equal(released, 1)
    assert.equal(bot.http.request.mock.callCount(), 10)
    assert.equal(bot.utils.wait.mock.callCount(), 9)
})

test('a first response without points does not release or wait', async t => {
    const { bot } = createActivityBot(t)
    bot.accessToken = 'test-token'
    const release = t.mock.fn(async () => {})
    await new Activities(bot).doReadToEarn(release)
    assert.equal(release.mock.callCount(), 0)
    assert.equal(bot.utils.wait.mock.callCount(), 0)
})

test('a release error preserves reading requests and intervals', async t => {
    const { bot } = createActivityBot(t)
    bot.accessToken = 'test-token'
    let balance = 100
    bot.http.request = t.mock.fn(async () => ({ status: 200, data: { response: { balance: (balance += 3) } } }))
    await new Activities(bot).doReadToEarn(async () => {
        throw new Error('close failed')
    })
    assert.equal(bot.http.request.mock.callCount(), 10)
    assert.equal(bot.utils.wait.mock.callCount(), 9)
    assert.ok(bot.logger.warn.mock.calls.some(call => String(call.arguments[2]).includes('close failed')))
})
