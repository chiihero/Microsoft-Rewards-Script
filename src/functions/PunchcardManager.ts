import { MicrosoftRewardsBot, executionContext } from '../index'
import type { Account } from '../interface/Account'
import type { DashboardData } from '../interface/DashboardData'

export class PunchcardManager {
    constructor(private bot: MicrosoftRewardsBot) {}

    async run(account: Account, mobileData: DashboardData): Promise<void> {
        await this.runMobile(mobileData)
        await this.runDesktop(account)
    }

    private async runMobile(data: DashboardData): Promise<void> {
        try {
            await this.bot.workers.doPunchCards(data, this.bot.mainMobilePage)
        } catch (error) {
            this.bot.logger.error(
                'main',
                'PUNCHCARD-MANAGER',
                `移动端打卡失败 | ${error instanceof Error ? error.message : String(error)}`
            )
        }
    }

    private runDesktop(account: Account): Promise<void> {
        return executionContext.run({ isMobile: false, account }, async () => {
            const session = await this.bot.createDesktopSession(account)
            try {
                const data = await this.bot.browser.func.getDashboardData(this.bot.cookies.desktop)
                await this.bot.workers.doPunchCards(data, this.bot.mainDesktopPage)
            } catch (error) {
                this.bot.logger.error(
                    'main',
                    'PUNCHCARD-MANAGER',
                    `桌面端打卡失败 | ${error instanceof Error ? error.message : String(error)}`
                )
            } finally {
                await this.bot.browser.func.closeBrowser(session.context, account.email).catch(() => {})
            }
        })
    }
}
