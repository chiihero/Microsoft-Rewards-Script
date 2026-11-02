const assert = require('node:assert/strict')
const test = require('node:test')
const fs = require('node:fs')
const cluster = require('node:cluster')
const { EventEmitter } = require('node:events')
require('../../node_modules/ts-node/register/transpile-only.js')
const HttpClient = require('../../src/util/Http.ts').default
const Utils = require('../../src/util/Utils.ts').default
const sessionStore = require('../../src/util/SessionStore.ts')
const { DailyCheckIn } = require('../../src/functions/activities/app/DailyCheckIn.ts')
const { createBot, account: accountFixture } = require('./rewardsPoints.fixture.cjs')
const account = { ...accountFixture, proxy: { proxyHttp: false, url: '', port: 0, username: '', password: '' } }

function flowBot(t, mode, failure) {
    const { bot } = createBot(t)
    bot.config.workers = { doDailyCheckIn: true, doReadToEarn: true, doMobileSearch: true }
    bot.config.experimental.apiSearch = mode === 'full-api'
    const response = async () => {
        if (failure === 'reset') throw new Error('ConnectionReset (10054)')
        return { status: 200, data: { code: 0, response: { balance: failure ? 100 : 105 } } }
    }
    bot.http.request = t.mock.fn(response)
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
    return { bot, later, response }
}

for (const mode of ['browser', 'full-api']) {
    for (const failure of [false, 'reset']) {
        test(mode + ': check-in ' + (failure || 'success') + ' retains later work and normal intervals', async t => {
            const { bot, later } = flowBot(t, mode, failure)
            const result = await bot.Main(account)
            assert.deepEqual(
                later,
                ['read', 'search'],
                JSON.stringify(bot.logger.error.mock.calls.map(call => call.arguments))
            )
            assert.equal(result.collectedPoints, 10)
            if (failure) assert.match(result.error, /10054/)
            else assert.equal(result.error, undefined)
            assert.deepEqual(
                bot.utils.wait.mock.calls.map(call => call.arguments),
                [[60000], [60000]]
            )
        })
    }
}

function isolateRun(t, bot, primary) {
    const previousPrimary = cluster.isPrimary
    cluster.isPrimary = primary
    t.after(() => {
        cluster.isPrimary = previousPrimary
    })
    t.mock.method(sessionStore, 'loadResolvedRegion', () => null)
    const writes = t.mock.method(fs, 'writeFileSync', () => {})
    t.mock.method(fs, 'mkdirSync', () => {})
    const exits = t.mock.method(process, 'exit', () => {})
    bot.utils = Object.assign(new Utils(), bot.utils)
    bot.accounts = [account]
    bot.exitedWorkers = []
    bot.config.clusters = primary ? 1 : 2
    bot.config.humanize = { enabled: false }
    bot.config.webhook = {}
    bot.config.sessionPath = 'offline-sessions'
    return { writes, exits }
}

for (const primary of [true, false]) {
    for (const failed of [false, true]) {
        test(
            (primary ? 'single process' : 'worker') + ': check-in outcome reaches the final result, failed=' + failed,
            async t => {
                const { bot, later, response } = flowBot(t, 'browser', failed)
                const { writes, exits } = isolateRun(t, bot, primary)
                t.mock.method(HttpClient.prototype, 'request', response)
                let workerTask
                const messages = []
                if (!primary) {
                    t.mock.method(process, 'on', (event, handler) => {
                        if (event === 'message') workerTask = handler
                        return process
                    })
                    const previousSend = process.send
                    process.send = message => {
                        messages.push(message)
                    }
                    t.after(() => {
                        if (previousSend === undefined) delete process.send
                        else process.send = previousSend
                    })
                }
                await bot.run()
                if (!primary) await workerTask({ chunk: [account], runStartTime: Date.now() })
                assert.deepEqual(
                    later,
                    ['read', 'search'],
                    JSON.stringify(bot.logger.error.mock.calls.map(call => call.arguments))
                )
                assert.equal(exits.mock.calls.at(-1).arguments[0], failed ? 1 : 0)
                assert.equal(writes.mock.callCount(), primary && !failed ? 1 : 0)
                if (primary) {
                    const footer = bot.logger.info.mock.calls.find(call => call.arguments[1] === 'RUN-END').arguments
                    assert.equal(footer[3], failed ? 'red' : 'green')
                    assert.match(footer[2], /获得积分=10/)
                    if (failed) assert.match(footer[2], /存在失败活动/)
                } else {
                    const result = messages[0].__stats[0]
                    assert.equal(result.success, !failed)
                    assert.equal(result.initialPoints, 100)
                    assert.equal(result.finalPoints, 110)
                    if (failed) assert.match(result.error, /签到未确认到账/)
                }
            }
        )
    }
}

for (const failed of [false, true]) {
    test('cluster primary preserves an account failure even when the worker exits zero, failed=' + failed, async t => {
        const { bot } = createBot(t)
        const { writes, exits } = isolateRun(t, bot, true)
        bot.config.clusters = 2
        bot.utils.chunkArray = accounts => [accounts]
        const worker = new EventEmitter()
        worker.process = { pid: 12345 }
        worker.send = () => {}
        t.mock.method(cluster, 'fork', () => worker)
        let onExit
        t.mock.method(cluster, 'on', (event, handler) => {
            if (event === 'exit') onExit = handler
            return cluster
        })
        let finished
        const completion = new Promise(resolve => {
            finished = resolve
        })
        exits.mock.mockImplementation(code => {
            finished(code)
        })
        await bot.run()
        worker.emit('message', {
            __stats: [
                {
                    email: account.email,
                    initialPoints: 100,
                    finalPoints: 110,
                    collectedPoints: 10,
                    duration: 1,
                    success: !failed,
                    error: failed ? '签到未确认到账' : undefined
                }
            ]
        })
        onExit(worker, 0)
        assert.equal(await completion, failed ? 1 : 0)
        assert.equal(writes.mock.callCount(), failed ? 0 : 1)
        const footer = bot.logger.info.mock.calls.find(call => call.arguments[1] === 'RUN-END').arguments
        assert.equal(footer[3], failed ? 'red' : 'green')
        assert.match(footer[2], /获得积分=10/)
    })
}

for (const app of ['未知', '0']) {
    test('log parser preserves an App allowance of ' + app, async () => {
        const { createRunState, parseLogLine, applyLogToRunState, summarizeRunState } = await import('./logParser.js')
        const state = createRunState()
        applyLogToRunState(
            state,
            parseLogLine(
                '[2026/10/24 13:00:00] [test] [INFO] MAIN [POINTS] 今日可赚取 | 移动端: 0 | 浏览器: 0 | App: ' +
                    app +
                    ' | test@example.invalid | locale: zh-CN'
            )
        )
        assert.deepEqual(summarizeRunState(state).accounts[0]?.earnable, {
            mobile: 0,
            browser: 0,
            app: app === '未知' ? null : 0
        })
    })
}

for (const failed of [false, true]) {
    test('log parser retains final points and account outcome, failed=' + failed, async () => {
        const { createRunState, parseLogLine, applyLogToRunState, summarizeRunState } = await import('./logParser.js')
        const state = createRunState()
        const messages = [
            '[ACCOUNT-END] 账户' +
                (failed ? '存在失败活动' : '完成') +
                ': test@example.invalid | 获得积分=10 | 原余额=100 | 现余额=110 | 持续秒数=1',
            '[RUN-END] ' +
                (failed ? '账户处理结束，存在失败活动' : '全部账户完成') +
                ' | 处理账户数=1 | 获得积分=10 | 原余额=100 | 现余额=110 | 运行分钟数=1'
        ]
        for (const message of messages)
            applyLogToRunState(state, parseLogLine('[2026/10/24 13:00:00] [MAIN] [INFO] MAIN ' + message))
        const summary = summarizeRunState(state)
        assert.equal(summary.finished, true)
        assert.equal(summary.collected, 10)
        assert.equal(summary.accounts[0].success, !failed)
        assert.equal(summary.accounts[0].finalPoints, 110)
    })
}
