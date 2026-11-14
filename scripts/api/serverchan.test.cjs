const assert = require('node:assert/strict')
const test = require('node:test')

require('../../node_modules/ts-node/register/transpile-only.js')

const http = require('../../src/util/Http.ts')
const { sendServerChan } = require('../../src/logging/ServerChan.ts')
const { validateConfig } = require('../../src/util/Validator.ts')
const exampleConfig = require('../../config.example.json')

test('validateConfig keeps webhook.serverchan', () => {
    const input = structuredClone(exampleConfig)
    input.webhook.serverchan = { enabled: true, sendKey: 'SCT_TEST', title: 'ServerChan test' }

    const config = validateConfig(input)

    assert.deepEqual(config.webhook.serverchan, {
        enabled: true,
        sendKey: 'SCT_TEST',
        title: 'ServerChan test'
    })
})

test('sendServerChan posts to the ServerChan Turbo endpoint', async t => {
    const calls = []
    t.mock.method(http, 'httpRequest', async request => {
        calls.push(request)
    })

    await sendServerChan({ enabled: true, sendKey: 'SCT_TEST', title: 'ServerChan test' }, 'summary')

    assert.equal(calls.length, 1)
    assert.equal(calls[0].method, 'POST')
    assert.equal(calls[0].url, 'https://sctapi.ftqq.com/SCT_TEST.send')
    assert.deepEqual(calls[0].data, { title: 'ServerChan test', desp: 'summary' })
})

test('sendServerChan reports non-429 delivery failures', async t => {
    t.mock.method(http, 'httpRequest', async () => {
        const error = new Error('upstream unavailable')
        error.response = { status: 503 }
        throw error
    })
    const warn = t.mock.method(console, 'warn', () => {})

    await sendServerChan({ enabled: true, sendKey: 'SCT_TEST' }, 'summary')

    assert.equal(warn.mock.callCount(), 1)
    assert.match(String(warn.mock.calls[0].arguments[0]), /HTTP 503/)
})
