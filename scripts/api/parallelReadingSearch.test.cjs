const assert = require('node:assert/strict')
const test = require('node:test')

require('../../node_modules/ts-node/register/transpile-only.js')
const { account, createFlowBot } = require('./workerGaps.fixture.cjs')

function deferred() {
    let resolve
    let reject
    const promise = new Promise((res, rej) => {
        resolve = res
        reject = rej
    })
    return { promise, resolve, reject }
}

async function waitFor(predicate, message) {
    for (let attempt = 0; attempt < 200; attempt++) {
        if (predicate()) return
        await new Promise(resolve => setImmediate(resolve))
    }
    assert.fail(message)
}

function prepareParallelFlow(t, { readGate, desktopGate } = {}) {
    const { bot, events } = createFlowBot(t, 'browser')
    bot.config.searchSettings.parallelSearching = true
    bot.config.ensureStreakProtection = false
    bot.config.workers = {
        doReadToEarn: true,
        doPunchCards: false,
        doMobileSearch: true,
        doDesktopSearch: true
    }
    bot.searchManager.getSearchPoints = async () => ({ doMobile: true, doDesktop: true })
    bot.activities.doReadToEarn = t.mock.fn(async () => {
        events.push('read-start')
        if (readGate) await readGate.promise
        events.push('read-end')
        return true
    })
    bot.searchManager.searchMobile = t.mock.fn(async () => {
        events.push('mobile-search')
        return 3
    })
    bot.searchManager.searchDesktop = t.mock.fn(async () => {
        events.push('desktop-start')
        if (desktopGate) await desktopGate.promise
        events.push('desktop-end')
        return 7
    })
    return { bot, events }
}

test('parallelSearching overlaps desktop search with reading without removing the read gap', async t => {
    const readGate = deferred()
    const desktopGate = deferred()
    const { bot, events } = prepareParallelFlow(t, { readGate, desktopGate })
    const mainPromise = bot.Main(account)
    void mainPromise.catch(() => {})

    await waitFor(
        () => events.includes('read-start') && events.includes('desktop-start'),
        'read and desktop search did not both start'
    )
    assert.ok(!events.includes('read-end'), 'reading should still be in progress')

    readGate.resolve()
    await waitFor(
        () => events.some(event => Array.isArray(event) && event[0] === 'wait' && event[1] === 60000),
        'the post-reading gap was not preserved'
    )
    assert.ok(events.indexOf('desktop-start') < events.indexOf('read-end'), 'desktop search must overlap reading')
    assert.ok(!events.includes('desktop-end'), 'desktop search should still be running during the read gap')

    desktopGate.resolve()
    const result = await mainPromise

    assert.equal(result.error, undefined)
    assert.ok(events.indexOf('desktop-end') > events.indexOf('read-end'))
    assert.equal(bot.searchManager.searchMobile.mock.callCount(), 1)
    assert.equal(bot.searchManager.searchDesktop.mock.callCount(), 1)

    const summary = bot.logger.info.mock.calls.find(call => String(call.arguments[2]).includes('搜索汇总'))
    assert.ok(summary, 'search summary was not logged')
    assert.match(String(summary.arguments[2]), /桌面端=7/)
    assert.match(String(summary.arguments[2]), /移动端=3/)
})

test('parallel overlap keeps mobile punchcards before desktop punchcards and both gaps', async t => {
    const readGate = deferred()
    const desktopGate = deferred()
    const { bot, events } = prepareParallelFlow(t, { readGate, desktopGate })
    bot.config.workers.doPunchCards = true
    bot.activities.doPunchCardsMobile = t.mock.fn(async () => {
        events.push('mobile-punch')
        return true
    })
    bot.activities.doPunchCardsDesktop = t.mock.fn(async () => {
        events.push('desktop-punch')
    })
    const mainPromise = bot.Main(account)
    void mainPromise.catch(() => {})

    await waitFor(
        () => events.includes('read-start') && events.includes('desktop-start'),
        'read and desktop search did not both start'
    )
    assert.ok(events.indexOf('mobile-punch') < events.indexOf('desktop-punch'))
    assert.ok(events.indexOf('desktop-punch') < events.indexOf('desktop-start'))
    assert.ok(!events.includes('read-end'), 'reading should still be in progress')

    readGate.resolve()
    await waitFor(
        () => events.filter(event => Array.isArray(event) && event[0] === 'wait').length === 2,
        'punchcard and reading gaps were not both preserved'
    )
    assert.ok(events.indexOf('desktop-start') < events.indexOf('read-end'), 'desktop search must overlap reading')
    assert.ok(!events.includes('desktop-end'), 'desktop search should still be running during the read gap')

    desktopGate.resolve()
    await mainPromise
    assert.deepEqual(
        bot.utils.wait.mock.calls.map(call => call.arguments[0]),
        [60000, 60000]
    )
})

test('parallelSearching disabled keeps desktop search after reading', async t => {
    const { bot, events } = prepareParallelFlow(t)
    bot.config.searchSettings.parallelSearching = false

    await bot.Main(account)

    assert.ok(events.indexOf('read-end') < events.indexOf('desktop-start'), 'desktop search must wait for reading')
    assert.ok(events.indexOf('mobile-search') < events.indexOf('desktop-start'))
    assert.equal(bot.utils.wait.mock.callCount(), 1)
})

test('a desktop search failure does not cancel reading or mobile search', async t => {
    const { bot, events } = prepareParallelFlow(t)
    bot.searchManager.searchDesktop = t.mock.fn(async () => {
        events.push('desktop-start')
        throw new Error('desktop search failed')
    })

    await assert.rejects(bot.Main(account), /desktop search failed/)

    assert.ok(events.includes('read-start'))
    assert.ok(events.includes('read-end'))
    assert.ok(events.includes('mobile-search'))
    assert.ok(bot.browser.func.closeBrowser.mock.callCount() > 0)
})

test('a desktop session failure does not cancel reading or mobile search', async t => {
    const { bot, events } = prepareParallelFlow(t)
    let sessions = 0
    bot.browserFactory.createBrowser = t.mock.fn(async () => {
        sessions++
        if (sessions > 1) throw new Error('desktop session failed')
        return { context: { newPage: async () => ({}), cookies: async () => [] }, fingerprint: {} }
    })

    await assert.rejects(bot.Main(account), /desktop session failed/)

    assert.ok(events.includes('read-start'))
    assert.ok(events.includes('read-end'))
    assert.ok(events.includes('mobile-search'))
})
