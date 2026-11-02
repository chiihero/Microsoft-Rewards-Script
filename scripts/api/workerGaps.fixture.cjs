const { MicrosoftRewardsBot } = require('../../src/index.ts')

const stages = [
    'doEnsureStreakProtection',
    'doDailySet',
    'doActivateSearchPerk',
    'doMorePromotions',
    'doDailyCheckIn',
    'doAppPromotions',
    'doReadToEarn',
    'doPunchCardsMobile',
    'doPunchCardsDesktop',
    'doClaimBonusPoints'
]
const postWaitStages = [
    'doDailySet',
    'doActivateSearchPerk',
    'doMorePromotions',
    'doDailyCheckIn',
    'doAppPromotions',
    'doReadToEarn',
    'doPunchCardsMobile'
]
const account = { email: 'offline@example.invalid', geoLocale: 'CN', langCode: 'zh-CN' }

function promotion(overrides = {}) {
    return {
        offerId: 'offline-offer',
        title: 'Offline task',
        promotionType: 'urlreward',
        complete: false,
        pointProgress: 0,
        pointProgressMax: 10,
        priority: 1,
        attributes: {},
        ...overrides
    }
}

function createActivityBot(t) {
    const dashboard = {
        dashboard: {
            dailySetPromotions: {},
            morePromotions: [],
            morePromotionsWithoutPromotionalItems: [],
            punchCards: [],
            userWarnings: [],
            userStatus: { availablePoints: 100 },
            userProfile: { attributes: { country: 'CN' } }
        }
    }
    const bot = {
        isMobile: false,
        accessToken: '',
        nextActions: {},
        cookies: { desktop: [] },
        userData: { currentPoints: 100, gainedPoints: 0, geoLocale: 'CN', langCode: 'zh-CN' },
        config: {
            workers: { doPunchCards: true },
            skipNonPointTasks: true,
            searchSettings: { readDelay: { min: 1000, max: 2000 } }
        },
        logger: Object.fromEntries(['info', 'warn', 'error', 'debug'].map(level => [level, t.mock.fn()])),
        utils: {
            getFormattedDate: () => '2026-10-24',
            randomDelay: t.mock.fn(min => min),
            wait: t.mock.fn(async () => {})
        },
        http: {
            request: t.mock.fn(async () => ({ status: 200, data: { response: { balance: 100 } } })),
            setDefaultHeaders: t.mock.fn()
        },
        activities: { doAppReward: t.mock.fn(async () => {}) },
        browser: {
            func: {
                getDashboardData: t.mock.fn(async () => dashboard),
                getAppDashboardData: t.mock.fn(async () => ({ response: { promotions: [] } })),
                getCurrentPoints: t.mock.fn(async () => 100),
                reportServerAction: t.mock.fn(async () => ({ status: 200, acknowledged: true })),
                ensureOffer: t.mock.fn(async () => null),
                getRewardsPageHtml: t.mock.fn(async () => 'offline-html'),
                checkpointActiveSession: t.mock.fn(async () => {}),
                closeBrowser: t.mock.fn(async () => {}),
                getBrowserEarnablePoints: t.mock.fn(async () => ({ mobileSearchPoints: 0, desktopSearchPoints: 0 })),
                getAppEarnablePoints: t.mock.fn(async () => ({ totalEarnablePoints: 0 }))
            },
            react: {
                getStreakProtection: () => ({ isProtectionOn: true, remainingDays: 3 }),
                routerStateTree: () => 'offline-router-state'
            }
        }
    }
    return { bot, dashboard }
}

function createFlowBot(t, mode, executed = []) {
    const { bot, dashboard } = createActivityBot(t)
    delete bot.isMobile
    Object.setPrototypeOf(bot, MicrosoftRewardsBot.prototype)
    const events = []
    bot.config.ensureStreakProtection = true
    bot.config.workers = Object.fromEntries(
        [
            'doDailySet',
            'doActivateSearchPerk',
            'doMorePromotions',
            'doDailyCheckIn',
            'doAppPromotions',
            'doReadToEarn',
            'doPunchCards',
            'doClaimBonusPoints'
        ].map(name => [name, true])
    )
    bot.config.experimental = { apiSearch: mode === 'full-api', apiSearchOnBing: false, edgeBrowsing: false }
    bot.config.activities = { searchOnBing: false }
    bot.config.searchSettings.parallelSearching = false
    bot.accountLocale = { country: 'CN' }
    bot.login = { login: async () => {}, getAppAccessToken: async () => 'offline-token' }
    bot.browserFactory = {
        createBrowser: t.mock.fn(async () => ({
            context: { newPage: async () => ({}), cookies: async () => [] },
            fingerprint: {}
        }))
    }
    bot.searchManager = { getSearchPoints: async () => ({ doMobile: false, doDesktop: false }) }
    if (executed.includes('doClaimBonusPoints')) bot.nextActions.reportClaimAllPoints = 'offline-claim-action'
    bot.activities = Object.fromEntries(
        stages.map(name => [
            name,
            t.mock.fn(async () => {
                events.push(name)
                return executed.includes(name)
            })
        ])
    )
    bot.utils.wait = t.mock.fn(async delay => events.push(['wait', delay]))
    return { bot, dashboard, events }
}

module.exports = { stages, postWaitStages, account, promotion, createActivityBot, createFlowBot }
