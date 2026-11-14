const assert = require('node:assert/strict')
const test = require('node:test')
require('../../node_modules/ts-node/register/transpile-only.js')
const { Login, isFidoLoginUrl } = require('../../src/browser/auth/Login.ts')
const { createBot, account } = require('./rewardsPoints.fixture.cjs')

const FIDO_URL = 'https://login.microsoft.com/consumers/fido/get?pid=deadbeef'

for (const [url, expected] of [
    [FIDO_URL, true],
    ['https://login.microsoft.com/consumers/fido/get', true],
    ['https://login.microsoft.com/consumers/fido/create?x=1', true],
    ['https://login.live.com/consumers/fido/get', true],
    ['https://login.microsoft.com/consumers/oauth2/v2.0/authorize', false],
    ['https://login.microsoftonline.com/consumers/fido/get', false],
    ['https://login.microsoft.com/consumers/fidoget', false],
    ['not a url', false]
]) {
    test(`FIDO URL classification: ${url} -> ${expected}`, () => {
        assert.equal(isFidoLoginUrl(url), expected)
    })
}

function pageStub(t, url, { ghostClick = false } = {}) {
    let current = url
    const bot = createBot(t).bot
    bot.browser.utils = { ghostClick: t.mock.fn(async () => ghostClick) }
    const page = {
        waitForLoadState: async () => {},
        waitForSelector: async () => {
            throw new Error('selector not found')
        },
        locator: () => ({ first: () => ({ innerText: async () => '' }) }),
        url: () => current,
        goto: t.mock.fn(async next => {
            current = next
        })
    }
    return { bot, page }
}

test('issue #74 URL is detected as FIDO_PASSKEY instead of UNKNOWN', async t => {
    const { bot, page } = pageStub(t, FIDO_URL)
    const login = new Login(bot)

    assert.equal(await login.detectCurrentState(page), 'FIDO_PASSKEY')
})

test('a non-FIDO login URL still falls through to UNKNOWN', async t => {
    const { bot, page } = pageStub(t, 'https://login.live.com/oauth20_authorize.srf?client_id=x')
    const login = new Login(bot)

    assert.equal(await login.detectCurrentState(page), 'UNKNOWN')
})

test('first FIDO encounter escapes back to the Rewards login entry', async t => {
    const { bot, page } = pageStub(t, FIDO_URL)
    const login = new Login(bot)

    assert.equal(await login.handleState('FIDO_PASSKEY', page, account), true)
    assert.equal(page.goto.mock.callCount(), 1)
    assert.match(page.goto.mock.calls[0].arguments[0], /rewards\.bing\.com\/auth\/login/)
})

test('a visible passkey cancel control resumes the normal login flow without navigation', async t => {
    const { bot, page } = pageStub(t, FIDO_URL, { ghostClick: true })
    page.waitForSelector = async () => ({})
    const login = new Login(bot)

    assert.equal(await login.handleState('FIDO_PASSKEY', page, account), true)
    assert.equal(bot.browser.utils.ghostClick.mock.callCount(), 1)
    assert.equal(page.goto.mock.callCount(), 0)
})

test('a second stuck FIDO encounter fails with an actionable error instead of 25 UNKNOWN iterations', async t => {
    const { bot, page } = pageStub(t, FIDO_URL)
    page.goto = t.mock.fn(async () => {})
    const login = new Login(bot)

    assert.equal(await login.handleState('FIDO_PASSKEY', page, account), true)
    await assert.rejects(login.handleState('FIDO_PASSKEY', page, account), /Passkey.*WebAuthn/)
    assert.equal(page.goto.mock.callCount(), 1)
})
