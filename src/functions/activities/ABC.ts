import { Page } from 'rebrowser-playwright'

import { Workers } from '../Workers'


export class ABC extends Workers {

    async doABC(page: Page) {
        this.bot.log(this.bot.isMobile, 'ABC', '尝试完成投票')

        try {
            let $ = await this.bot.browser.func.loadInCheerio(page)

            // Don't loop more than 15 in case unable to solve, would lock otherwise
            const maxIterations = 15
            let i
            for (i = 0; i < maxIterations && !$('span.rw_icon').length; i++) {
                await page.waitForSelector('.wk_OptionClickClass', { state: 'visible', timeout: 10000 })

                const answers = $('.wk_OptionClickClass')
                const answer = answers[this.bot.utils.randomNumber(0, 2)]?.attribs['id']

                await page.waitForSelector(`#${answer}`, { state: 'visible', timeout: 10000 })

                await this.bot.utils.waitRandom(2000,5000)
                await page.click(`#${answer}`) // Click answer

                await this.bot.utils.waitRandom(4000,7000)
                await page.waitForSelector('div.wk_button', { state: 'visible', timeout: 10000 })
                await page.click('div.wk_button') // Click next question button

                page = await this.bot.browser.utils.getLatestTab(page)
                $ = await this.bot.browser.func.loadInCheerio(page)
                await this.bot.utils.waitRandom(1000,4000)
            }

            await this.bot.utils.waitRandom(4000,7000)
            await page.close()

            if (i === maxIterations) {
                this.bot.log(this.bot.isMobile, 'ABC', '未能解决测验，超出最大迭代次数15', 'warn')
            } else {
                this.bot.log(this.bot.isMobile, 'ABC', '成功完成ABC活动')
            }

        } catch (error) {
            await page.close()
            this.bot.log(this.bot.isMobile, 'ABC', '发生错误:' + error, 'error')
        }
    }

}