import type { MicrosoftRewardsBot } from '../index'

import { DailySet } from './activities/rewards/DailySet'
import { MorePromotions } from './activities/rewards/MorePromotions'
import { PunchCards } from './activities/rewards/PunchCards'

import { DailyCheckIn } from './activities/app/DailyCheckIn'
import { ReadToEarn } from './activities/app/ReadToEarn'
import { AppReward } from './activities/app/AppReward'
import { AppPromotions } from './activities/app/AppPromotions'

import { UrlReward } from './activities/api/UrlReward'
import { ClaimBonusPoints } from './activities/api/ClaimBonusPoints'
import { EnsureStreakProtection } from './activities/api/EnsureStreakProtection'
import { ClaimReward } from './activities/api/ClaimReward'
import { ActivateSearchPerk } from './activities/api/ActivateSearchPerk'
import { VisualSearch } from './activities/visualSearch/VisualSearch'

import { Search as BrowserSearch } from './activities/search/BrowserSearch'
import { SearchOnBing as BrowserSearchOnBing } from './activities/search/BrowserSearchOnBing'

import { ApiSearch } from './activities/experimental/ApiSearch'
import { ApiSearchOnBing } from './activities/experimental/ApiSearchOnBing'
import { EdgeBrowsing } from './activities/experimental/EdgeBrowsing'

import type { Page } from 'patchright'
import type { BasePromotion, DashboardData } from '../interface/DashboardData'
import type { AppDashboardData, Promotion } from '../interface/AppDashBoardData'
import type { QuestChild } from '../browser/ReactFunc'

export default class Activities {
    private bot: MicrosoftRewardsBot

    constructor(bot: MicrosoftRewardsBot) {
        this.bot = bot
    }

    doSearch = async (page: Page, isMobile: boolean): Promise<number> => {
        if (this.bot.config.experimental.apiSearch) {
            return await new ApiSearch(this.bot).doSearch(isMobile)
        }
        return await new BrowserSearch(this.bot).doSearch(page, isMobile)
    }

    doBonusSearches = async (page: Page): Promise<number> => {
        if (this.bot.config.experimental.apiSearch) {
            return await new ApiSearch(this.bot).doBonusSearches()
        }
        return await new BrowserSearch(this.bot).doBonusSearches(page)
    }

    doSearchOnBing = async (promotion: BasePromotion, page: Page): Promise<boolean> => {
        if (this.bot.config.experimental.apiSearchOnBing) {
            const activity = new ApiSearchOnBing(this.bot)
            await activity.doSearchOnBing(promotion)
            return activity.didExecute()
        }
        const activity = new BrowserSearchOnBing(this.bot)
        await activity.doSearchOnBing(promotion, page)
        return activity.didExecute()
    }

    doDailySet = async (data: DashboardData): Promise<boolean> => {
        const activity = new DailySet(this.bot)
        await activity.run(data)
        return activity.didExecute()
    }

    doMorePromotions = async (data: DashboardData): Promise<boolean> => {
        const activity = new MorePromotions(this.bot)
        await activity.run(data)
        return activity.didExecute()
    }

    doPunchCardsMobile = async (data: DashboardData): Promise<boolean> => {
        const activity = new PunchCards(this.bot)
        await activity.runMobile(data)
        return activity.didExecute()
    }

    doPunchCardsDesktop = async (): Promise<void> => {
        await new PunchCards(this.bot).runDesktop()
    }

    doUrlReward = async (promotion: BasePromotion): Promise<boolean> => {
        const activity = new UrlReward(this.bot)
        await activity.doUrlReward(promotion)
        return activity.didExecute()
    }

    doClaimBonusPoints = async (): Promise<void> => {
        const claimBonusPoints = new ClaimBonusPoints(this.bot)
        await claimBonusPoints.claimBonusPoints()
    }

    doEnsureStreakProtection = async (): Promise<void> => {
        const ensureStreakProtection = new EnsureStreakProtection(this.bot)
        await ensureStreakProtection.ensureStreakProtection()
    }

    doClaimReward = async (child: QuestChild, parentId: string): Promise<boolean> => {
        const claimReward = new ClaimReward(this.bot)
        await claimReward.claimReward(child, parentId)
        return claimReward.didExecute()
    }

    doActivateSearchPerk = async (data: DashboardData): Promise<boolean> => {
        const activity = new ActivateSearchPerk(this.bot)
        await activity.activate(data)
        return activity.didExecute()
    }

    doVisualSearch = async (data: DashboardData): Promise<number> => {
        const visualSearch = new VisualSearch(this.bot)
        return await visualSearch.doVisualSearch(data)
    }

    doAppReward = async (promotion: Promotion): Promise<void> => {
        const urlReward = new AppReward(this.bot)
        await urlReward.doAppReward(promotion)
    }

    doReadToEarn = async (): Promise<boolean> => {
        const activity = new ReadToEarn(this.bot)
        await activity.doReadToEarn()
        return activity.didExecute()
    }

    doDailyCheckIn = async (): Promise<boolean> => {
        const activity = new DailyCheckIn(this.bot)
        await activity.doDailyCheckIn()
        return activity.didExecute()
    }

    doAppPromotions = async (data: AppDashboardData): Promise<boolean> => {
        const activity = new AppPromotions(this.bot)
        await activity.run(data)
        return activity.didExecute()
    }

    doEdgeBrowsing = async (data: DashboardData, signal?: AbortSignal): Promise<void> => {
        const edgeBrowsing = new EdgeBrowsing(this.bot)
        await edgeBrowsing.run(data, signal)
    }
}
