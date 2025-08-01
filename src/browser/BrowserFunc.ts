import { BrowserContext, Page } from 'rebrowser-playwright'
import { CheerioAPI, load } from 'cheerio'
import { AxiosRequestConfig } from 'axios'

import { MicrosoftRewardsBot } from '../index'
import { saveSessionData } from '../util/Load'

import { Counters, DashboardData, MorePromotion, PromotionalItem } from './../interface/DashboardData'
import { QuizData } from './../interface/QuizData'
import { AppUserData } from '../interface/AppUserData'
import { EarnablePoints } from '../interface/Points'


export default class BrowserFunc {
    private bot: MicrosoftRewardsBot

    constructor(bot: MicrosoftRewardsBot) {
        this.bot = bot
    }


    /**
     * Navigate the provided page to rewards homepage
     * @param {Page} page Playwright page
    */
    async goHome(page: Page) {

        try {
            const dashboardURL = new URL(this.bot.config.baseURL)

            if (page.url() === dashboardURL.href) {
                return
            }

            await page.goto(this.bot.config.baseURL)

            const maxIterations = 5 // Maximum iterations set to 5

            for (let iteration = 1; iteration <= maxIterations; iteration++) {
                await this.bot.utils.waitRandom(3000,5000, 'normal')
                await this.bot.browser.utils.tryDismissAllMessages(page)

                // Check if account is suspended
                const isSuspended = await page.waitForSelector('#suspendedAccountHeader', { state: 'visible', timeout: 2000 }).then(() => true).catch(() => false)
                if (isSuspended) {
                    this.bot.log(this.bot.isMobile, '返回主页', '此账户已被暂停!', 'error')
                    throw new Error('Account has been suspended!')
                }

                try {
                    // If activities are found, exit the loop
                    await page.waitForSelector('#more-activities', { timeout: 1000 })
                    this.bot.log(this.bot.isMobile, '返回主页', '成功访问主页')
                    break

                } catch (error) {
                    // Continue if element is not found
                }

                // Below runs if the homepage was unable to be visited
                const currentURL = new URL(page.url())

                if (currentURL.hostname !== dashboardURL.hostname) {
                    await this.bot.browser.utils.tryDismissAllMessages(page)

                    await this.bot.utils.waitRandom(2000,5000, 'normal')
                    await page.goto(this.bot.config.baseURL)
                } else {
                    this.bot.log(this.bot.isMobile, '返回主页', '成功访问主页')
                    break
                }

                await this.bot.utils.waitRandom(5000,9000, 'normal')
            }

        } catch (error) {
            throw this.bot.log(this.bot.isMobile, '返回主页', '发生错误:' + error, 'error')
        }
    }

    /**
     * Fetch user dashboard data
     * @returns {DashboardData} Object of user bing rewards dashboard data
    */
    async getDashboardData(): Promise<DashboardData> {
        const dashboardURL = new URL(this.bot.config.baseURL)
        const currentURL = new URL(this.bot.homePage.url())

        try {
            // Should never happen since tasks are opened in a new tab!
            if (currentURL.hostname !== dashboardURL.hostname) {
                this.bot.log(this.bot.isMobile, 'DASHBOARD-DATA', '提供的页面不是仪表盘页面，正在重定向到仪表盘页面')
                await this.goHome(this.bot.homePage)
            }

            // Reload the page to get new data
            await this.bot.homePage.reload({ waitUntil: 'domcontentloaded' })

            const scriptContent = await this.bot.homePage.evaluate(() => {
                const scripts = Array.from(document.querySelectorAll('script'))
                const targetScript = scripts.find(script => script.innerText.includes('var dashboard'))

                return targetScript?.innerText ? targetScript.innerText : null
            })

            if (!scriptContent) {
                throw this.bot.log(this.bot.isMobile, '获取仪表盘数据', '脚本中未找到仪表盘数据', 'error')
            }

            // Extract the dashboard object from the script content
            const dashboardData = await this.bot.homePage.evaluate(scriptContent => {
                // Extract the dashboard object using regex
                const regex = /var dashboard = (\{.*?\});/s
                const match = regex.exec(scriptContent)

                if (match && match[1]) {
                    return JSON.parse(match[1])
                }

            }, scriptContent)

            if (!dashboardData) {
                throw this.bot.log(this.bot.isMobile, '获取仪表盘数据', '无法解析仪表盘脚本', 'error')
            }

            return dashboardData

        } catch (error) {
            throw this.bot.log(this.bot.isMobile, '获取仪表盘数据', `获取仪表盘数据时出错: ${error}`, 'error')
        }

    }

    /**
     * Get search point counters
     * @returns {Counters} Object of search counter data
    */
    async getSearchPoints(): Promise<Counters> {
        const dashboardData = await this.getDashboardData() // Always fetch newest data

        return dashboardData.userStatus.counters
    }

    /**
     * Get total earnable points with web browser
     * @returns {number} Total earnable points
    */
    async getBrowserEarnablePoints(): Promise<EarnablePoints> {
        try {
            let desktopSearchPoints = 0
            let mobileSearchPoints = 0
            let dailySetPoints = 0
            let morePromotionsPoints = 0

            const data = await this.getDashboardData()

            // Desktop Search Points
            if (data.userStatus.counters.pcSearch?.length) {
                data.userStatus.counters.pcSearch.forEach(x => desktopSearchPoints += (x.pointProgressMax - x.pointProgress))
            }

            // Mobile Search Points
            if (data.userStatus.counters.mobileSearch?.length) {
                data.userStatus.counters.mobileSearch.forEach(x => mobileSearchPoints += (x.pointProgressMax - x.pointProgress))
            }

            // Daily Set
            data.dailySetPromotions[this.bot.utils.getFormattedDate()]?.forEach(x => dailySetPoints += (x.pointProgressMax - x.pointProgress))

            // More Promotions
            if (data.morePromotions?.length) {
                data.morePromotions.forEach(x => {
                    // Only count points from supported activities
                    if (['quiz', 'urlreward'].includes(x.promotionType) && x.exclusiveLockedFeatureStatus !== 'locked') {
                        morePromotionsPoints += (x.pointProgressMax - x.pointProgress)
                    }
                })
            }

            const totalEarnablePoints = desktopSearchPoints + mobileSearchPoints + dailySetPoints + morePromotionsPoints

            return {
                dailySetPoints,
                morePromotionsPoints,
                desktopSearchPoints,
                mobileSearchPoints,
                totalEarnablePoints
            }
        } catch (error) {
            throw this.bot.log(this.bot.isMobile, '获取浏览器可赚积分', '发生错误:' + error, 'error')
        }
    }

    /**
     * Get total earnable points with mobile app
     * @returns {number} Total earnable points
    */
    async getAppEarnablePoints(accessToken: string) {
        try {
            const points = {
                readToEarn: 0,
                checkIn: 0,
                totalEarnablePoints: 0
            }

            const eligibleOffers = [
                'ENUS_readarticle3_30points',
                'Gamification_Sapphire_DailyCheckIn'
            ]

            const data = await this.getDashboardData()
            let geoLocale = data.userProfile.attributes.country
            geoLocale = (this.bot.config.searchSettings.useGeoLocaleQueries && geoLocale.length === 2) ? geoLocale.toLowerCase() : 'cn'
            if (this.bot.config.searchSettings.useLocale != ""){
                geoLocale = this.bot.config.searchSettings.useLocale.toLowerCase()
            }
            this.bot.log(this.bot.isMobile, '设置地区', '地区:' + geoLocale)
            const userDataRequest: AxiosRequestConfig = {
                url: 'https://prod.rewardsplatform.microsoft.com/dapi/me?channel=SAAndroid&options=613',
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${accessToken}`,
                    'X-Rewards-Country': geoLocale,
                    'X-Rewards-Language': 'en'
                }
            }

            const userDataResponse: AppUserData = (await this.bot.axios.request(userDataRequest)).data
            const userData = userDataResponse.response
            const eligibleActivities = userData.promotions.filter((x) => eligibleOffers.includes(x.attributes.offerid ?? ''))

            for (const item of eligibleActivities) {
                if (item.attributes.type === 'msnreadearn') {
                    points.readToEarn = parseInt(item.attributes.pointmax ?? '') - parseInt(item.attributes.pointprogress ?? '')
                    break
                } else if (item.attributes.type === 'checkin') {
                    const checkInDay = parseInt(item.attributes.progress ?? '') % 7

                    if (checkInDay < 6 && (new Date()).getDate() != (new Date(item.attributes.last_updated ?? '')).getDate()) {
                        points.checkIn = parseInt(item.attributes['day_' + (checkInDay + 1) + '_points'] ?? '')
                    }
                    break
                }
            }

            points.totalEarnablePoints = points.readToEarn + points.checkIn

            return points
        } catch (error) {
            throw this.bot.log(this.bot.isMobile, '获取应用可赚积分', '发生错误:' + error, 'error')
        }
    }

    /**
     * Get current point amount
     * @returns {number} Current total point amount
    */
    async getCurrentPoints(): Promise<number> {
        try {
            const data = await this.getDashboardData()

            return data.userStatus.availablePoints
        } catch (error) {
            throw this.bot.log(this.bot.isMobile, '获取当前积分', '发生错误:' + error, 'error')
        }
    }

    /**
     * Parse quiz data from provided page
     * @param {Page} page Playwright page
     * @returns {QuizData} Quiz data object
    */
    async getQuizData(page: Page): Promise<QuizData> {
        try {
            const html = await page.content()
            const $ = load(html)

            const scriptContent = $('script').filter((index, element) => {
                return $(element).text().includes('_w.rewardsQuizRenderInfo')
            }).text()

            if (scriptContent) {
                const regex = /_w\.rewardsQuizRenderInfo\s*=\s*({.*?});/s
                const match = regex.exec(scriptContent)

                if (match && match[1]) {
                    const quizData = JSON.parse(match[1])
                    return quizData
                } else {
                    throw this.bot.log(this.bot.isMobile, 'GET-QUIZ-DATA获取测验数据', '脚本中未找到测验数据', 'error')
                }
            } else {
                throw this.bot.log(this.bot.isMobile, 'GET-QUIZ-DATA获取测验数据', '包含测验数据的脚本未找到', 'error')
            }

        } catch (error) {
            throw this.bot.log(this.bot.isMobile, 'GET-QUIZ-DATA获取测验数据', '发生错误:' + error, 'error')
        }

    }

    async waitForQuizRefresh(page: Page): Promise<boolean> {
        try {
            await page.waitForSelector('span.rqMCredits', { state: 'visible', timeout: 10000 })
            await this.bot.utils.waitRandom(2000,5000, 'normal')

            return true
        } catch (error) {
            this.bot.log(this.bot.isMobile, '测验刷新', '发生错误:' + error, 'error')
            return false
        }
    }

    async checkQuizCompleted(page: Page): Promise<boolean> {
        try {
            await page.waitForSelector('#quizCompleteContainer', { state: 'visible', timeout: 2000 })
            await this.bot.utils.waitRandom(2000,5000, 'normal')

            return true
        } catch (error) {
            return false
        }
    }

    async loadInCheerio(page: Page): Promise<CheerioAPI> {
        const html = await page.content()
        const $ = load(html)

        return $
    }

    async getPunchCardActivity(page: Page, activity: PromotionalItem | MorePromotion): Promise<string> {
        let selector = ''
        try {
            const html = await page.content()
            const $ = load(html)

            const element = $('.offer-cta').toArray().find(x => x.attribs.href?.includes(activity.offerId))
            if (element) {
                selector = `a[href*="${element.attribs.href}"]`
            }
        } catch (error) {
            this.bot.log(this.bot.isMobile, '获取打卡活动', '发生错误:' + error, 'error')
        }

        return selector
    }

    async closeBrowser(browser: BrowserContext, email: string) {
        try {
            // Save cookies
            await saveSessionData(this.bot.config.sessionPath, browser, email, this.bot.isMobile)

            await this.bot.utils.waitRandom(2000,5000)

            // Close browser
            await browser.close()
            this.bot.log(this.bot.isMobile, '关闭浏览器', '浏览器已成功关闭!')
        } catch (error) {
            throw this.bot.log(this.bot.isMobile, '关闭浏览器', '发生错误:' + error, 'error')
        }
    }
}