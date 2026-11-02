const { MicrosoftRewardsBot } = require('../../src/index.ts')

function createBot(t) {
    const bot = Object.create(MicrosoftRewardsBot.prototype)
    const dashboard = {
        dashboard: {
            userStatus: { availablePoints: 100, counters: {} },
            userProfile: { attributes: { country: 'CN' } },
            dailySetPromotions: {},
            morePromotions: [],
            userWarnings: []
        }
    }
    bot.userData = { currentPoints: 100, gainedPoints: 0, geoLocale: 'CN', langCode: 'zh-CN' }
    bot.nextActions = {}
    bot.accessToken = ''
    bot.cookies = { mobile: [], desktop: [] }
    bot.accountLocale = { country: 'CN' }
    bot.config = {
        workers: {},
        experimental: { apiSearch: false, apiSearchOnBing: false, edgeBrowsing: false },
        activities: { searchOnBing: false },
        searchSettings: { parallelSearching: false }
    }
    bot.utils = { getFormattedDate: () => '2026-10-24', randomDelay: min => min, wait: t.mock.fn(async () => {}) }
    bot.logger = Object.fromEntries(['info', 'warn', 'error', 'debug'].map(level => [level, t.mock.fn()]))
    bot.http = {
        request: t.mock.fn(async () => {
            throw new Error('Unexpected HTTP request')
        }),
        setDefaultHeaders: () => {}
    }
    bot.login = { login: async () => {}, getAppAccessToken: async () => 'test-token' }
    bot.browserFactory = {
        createBrowser: async () => ({
            context: {
                newPage: async () => ({}),
                cookies: async () => []
            },
            fingerprint: {}
        })
    }
    bot.browser = {
        func: {
            getDashboardData: async () => dashboard,
            getAppDashboardData: async () => ({ response: { promotions: [] } }),
            getCurrentPoints: t.mock.fn(async () => 100),
            checkpointActiveSession: async () => {},
            closeBrowser: async () => {},
            getBrowserEarnablePoints: async () => ({ desktopSearchPoints: 0, mobileSearchPoints: 0 }),
            getAppEarnablePoints: async () => ({ totalEarnablePoints: 0 })
        }
    }
    bot.searchManager = { getSearchPoints: async () => ({ doMobile: false, doDesktop: false }) }
    bot.activities = { doDailyCheckIn: async () => {} }
    return { bot, dashboard }
}

module.exports = { createBot, account: { email: 'test@example.invalid', geoLocale: 'CN', langCode: 'zh-CN' } }
