const assert = require('node:assert/strict')
const test = require('node:test')

require('../../node_modules/ts-node/register/transpile-only.js')

const { ConfigSchema } = require('../../src/util/Validator.ts')

const ORIGINAL_TWELVE = [
    'doDailySet',
    'doMorePromotions',
    'doClaimBonusPoints',
    'doPunchCards',
    'doAppPromotions',
    'doDesktopSearch',
    'doMobileSearch',
    'doBonusSearches',
    'doDailyCheckIn',
    'doReadToEarn',
    'doActivateSearchPerk',
    'doVisualSearch'
]

function twelveWorkers(overrides = {}) {
    return {
        doDailySet: true,
        doMorePromotions: true,
        doClaimBonusPoints: true,
        doPunchCards: true,
        doAppPromotions: true,
        doDesktopSearch: true,
        doMobileSearch: true,
        doBonusSearches: false,
        doDailyCheckIn: true,
        doReadToEarn: true,
        doActivateSearchPerk: true,
        doVisualSearch: false,
        ...overrides
    }
}

test('Validator preserves doDailyInstantWin=false and does not drop the original 12 workers', () => {
    const parsed = ConfigSchema.shape.workers.parse(twelveWorkers({ doDailyInstantWin: false }))
    assert.equal(parsed.doDailyInstantWin, false)
    for (const key of ORIGINAL_TWELVE) {
        assert.equal(Object.prototype.hasOwnProperty.call(parsed, key), true, key)
        assert.equal(parsed[key], twelveWorkers()[key], key)
    }
})

test('Validator default for a missing doDailyInstantWin is true, and explicit true is kept', () => {
    const missing = ConfigSchema.shape.workers.parse(twelveWorkers())
    const enabled = ConfigSchema.shape.workers.parse(twelveWorkers({ doDailyInstantWin: true }))
    assert.equal(missing.doDailyInstantWin, true)
    assert.equal(enabled.doDailyInstantWin, true)
    for (const key of ORIGINAL_TWELVE) {
        assert.equal(Object.prototype.hasOwnProperty.call(missing, key), true, key)
    }
})
