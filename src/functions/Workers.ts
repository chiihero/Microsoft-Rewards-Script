import type { Page } from 'patchright'
import type { MicrosoftRewardsBot } from '../index'
import type {
    DashboardData,
    PunchCard,
    BasePromotion,
    FindClippyPromotion,
    PurplePromotionalItem
} from '../interface/DashboardData'
import type { AppDashboardData } from '../interface/AppDashBoardData'

export class Workers {
    public bot: MicrosoftRewardsBot

    constructor(bot: MicrosoftRewardsBot) {
        this.bot = bot
    }

    public async doDailySet(data: DashboardData, page: Page) {
        const todayKey = this.bot.utils.getFormattedDate()
        const todayData = data.dailySetPromotions[todayKey]

        const activitiesUncompleted = todayData?.filter(x => !x.complete && x.pointProgressMax > 0) ?? []


        if (!activitiesUncompleted.length) {
            this.bot.logger.info(this.bot.isMobile, 'DAILY-SET', '所有"每日任务"项目已完成')
            return
        }

        // 解决活动
        this.bot.logger.info(this.bot.isMobile, 'DAILY-SET', '开始解决"每日任务"项目')

        await this.solveActivities(activitiesUncompleted, page)

        this.bot.logger.info(this.bot.isMobile, 'DAILY-SET', '所有"每日任务"项目已完成')
    }

    public async doMorePromotions(data: DashboardData, page: Page) {
        const morePromotions: BasePromotion[] = [
            ...new Map(
                [...(data.morePromotions ?? []), ...(data.morePromotionsWithoutPromotionalItems ?? [])]
                    .filter(Boolean)
                    .map(p => [p.offerId, p as BasePromotion] as const)
            ).values()
        ]

        const activitiesUncompleted: BasePromotion[] =
            morePromotions?.filter(x => {
                if (x.complete) return false
                if (x.pointProgressMax <= 0) return false
                if (x.exclusiveLockedFeatureStatus === 'locked') return false
                if (!x.promotionType) return false

                return true
            }) ?? []

        if (!activitiesUncompleted.length) {
            this.bot.logger.info(
                this.bot.isMobile,
                'MORE-PROMOTIONS',
                '所有"更多推广"项目已完成'
            )
            return
        }

        this.bot.logger.info(
            this.bot.isMobile,
            'MORE-PROMOTIONS',
            `开始解决 ${activitiesUncompleted.length} 个"更多推广"项目`
        )

        await this.solveActivities(activitiesUncompleted, page)

        this.bot.logger.info(this.bot.isMobile, 'MORE-PROMOTIONS', '所有"更多推广"项目已完成')
    }

    public async doAppPromotions(data: AppDashboardData) {
        const appRewards = data.response.promotions.filter(x => {
            if (x.attributes['complete']?.toLowerCase() !== 'false') return false
            if (!x.attributes['offerid']) return false
            if (!x.attributes['type']) return false
            if (x.attributes['type'] !== 'sapphire') return false

            return true
        })

        if (!appRewards.length) {
            this.bot.logger.info(
                this.bot.isMobile,
                'APP-PROMOTIONS',
                '所有"应用推广"项目已完成'
            )
            return
        }

        for (const reward of appRewards) {
            await this.bot.activities.doAppReward(reward)
            // 完成每个活动之间的延迟
            await this.bot.utils.wait(this.bot.utils.randomDelay(5000, 15000))
        }

        this.bot.logger.info(this.bot.isMobile, 'APP-PROMOTIONS', '所有"应用推广"项目已完成')
    }

    public async doSpecialPromotions(data: DashboardData) {
        const specialPromotions: PurplePromotionalItem[] = [
            ...new Map(
                [...(data.promotionalItems ?? [])]
                    .filter(Boolean)
                    .map(p => [p.offerId, p as PurplePromotionalItem] as const)
            ).values()
        ]

        const supportedPromotions = ['ww_banner_optin_2x']

        const specialPromotionsUncompleted: PurplePromotionalItem[] =
            specialPromotions?.filter(x => {
                if (x.complete) return false
                if (x.exclusiveLockedFeatureStatus === 'locked') return false
                if (!x.promotionType) return false

                const offerId = (x.offerId ?? '').toLowerCase()
                return supportedPromotions.some(s => offerId.includes(s))
            }) ?? []

        for (const activity of specialPromotionsUncompleted) {
            try {
                const type = activity.promotionType?.toLowerCase() ?? ''
                const name = activity.name?.toLowerCase() ?? ''
                const offerId = (activity as PurplePromotionalItem).offerId

                this.bot.logger.debug(
                    this.bot.isMobile,
                    'SPECIAL-ACTIVITY',
                    `处理活动 | 标题="${activity.title}" | offerId=${offerId} | 类型=${type}"`
                )

                switch (type) {
                    // UrlReward
                    case 'urlreward': {
                        // 特殊"双倍搜索积分"激活
                        if (name.includes('ww_banner_optin_2x')) {
                            this.bot.logger.info(
                                this.bot.isMobile,
                                'ACTIVITY',
                                `发现活动类型 "Double Search Points" | 标题="${activity.title}" | offerId=${offerId}`
                            )

                            await this.bot.activities.doDoubleSearchPoints(activity)
                        }
                        break
                    }

                    // 不支持的类型
                    default: {
                        this.bot.logger.warn(
                            this.bot.isMobile,
                            'SPECIAL-ACTIVITY',
                            `跳过活动 "${activity.title}" | offerId=${offerId} | 原因: 不支持的类型 "${activity.promotionType}"`
                        )
                        break
                    }
                }
            } catch (error) {
                this.bot.logger.error(
                    this.bot.isMobile,
                    'SPECIAL-ACTIVITY',
                    `解决活动时出错 "${activity.title}" | 消息=${error instanceof Error ? error.message : String(error)}`
                )
            }
        }

        this.bot.logger.info(this.bot.isMobile, 'SPECIAL-ACTIVITY', '所有"特殊活动"项目已完成')
    }

    public async doPunchCards(data: DashboardData, page: Page) {
        const punchCards: PunchCard[] =
            data.punchCards.filter(x => !x.parentPromotion?.complete && x.parentPromotion?.pointProgressMax > 0) ?? []

        const punchCardActivities = punchCards.flatMap(x => x.childPromotions)

        const activitiesUncompleted: BasePromotion[] =
            punchCardActivities?.filter(x => {
                if (x.complete) return false
                if (x.exclusiveLockedFeatureStatus === 'locked') return false
                if (!x.promotionType) return false
                if (x.attributes.is_unlocked) return false
                return true
            }) ?? []

        if (!activitiesUncompleted.length) {
            this.bot.logger.info(this.bot.isMobile, 'PUNCHCARD', '所有"打卡"项目准备完成')
            return
        }

        this.bot.logger.info(
            this.bot.isMobile,
            'PUNCHCARD',
            `开始解决 ${activitiesUncompleted.length} 个"打卡"项目`
        )

        await this.solveActivities(activitiesUncompleted, page)

        this.bot.logger.info(this.bot.isMobile, 'PUNCHCARD', '所有"打卡"项目已完成')
    }

    private async solveActivities(activities: BasePromotion[], page: Page, punchCard?: PunchCard) {
        for (const activity of activities) {
            try {
                const type = activity.promotionType?.toLowerCase() ?? ''
                const name = activity.name?.toLowerCase() ?? ''
                const offerId = (activity as BasePromotion).offerId
                const destinationUrl = activity.destinationUrl?.toLowerCase() ?? ''

                this.bot.logger.debug(
                    this.bot.isMobile,
                    'ACTIVITY',
                    `处理活动 | 标题="${activity.title}" | offerId=${offerId} | 类型=${type} | punchCard="${punchCard?.parentPromotion?.title ?? 'none'}"`
                )

                switch (type) {
                    // 类似测验的活动（投票/常规测验变体）
                    case 'quiz': {
                        const basePromotion = activity as BasePromotion

                        // 投票（通常10分，URL中包含pollscenarioid）
                        if (activity.pointProgressMax === 10 && destinationUrl.includes('pollscenarioid')) {
                            this.bot.logger.info(
                                this.bot.isMobile,
                                'ACTIVITY',
                                `发现活动类型 "Poll" | 标题="${activity.title}" | offerId=${offerId}`
                            )

                            //await this.bot.activities.doPoll(basePromotion)
                            break
                        }

                        // 所有其他测验通过测验API处理
                        this.bot.logger.info(
                            this.bot.isMobile,
                            'ACTIVITY',
                            `发现活动类型 "Quiz" | 标题="${activity.title}" | offerId=${offerId}`
                        )

                        await this.bot.activities.doQuiz(basePromotion)
                        break
                    }

                    // UrlReward
                    case 'urlreward': {
                        const basePromotion = activity as BasePromotion

                        // 必应搜索是"urlreward"的子类型
                        if (name.includes('exploreonbing')) {
                            this.bot.logger.info(
                                this.bot.isMobile,
                                'ACTIVITY',
                                `发现活动类型 "SearchOnBing" | 标题="${activity.title}" | offerId=${offerId}`
                            )

                            await this.bot.activities.doSearchOnBing(basePromotion, page)
                        } else {
                            this.bot.logger.info(
                                this.bot.isMobile,
                                'ACTIVITY',
                                `发现活动类型 "UrlReward" | 标题="${activity.title}" | offerId=${offerId}`
                            )

                            await this.bot.activities.doUrlReward(basePromotion)
                        }
                        break
                    }

                    // Find Clippy特定推广类型
                    case 'findclippy': {
                        const clippyPromotion = activity as unknown as FindClippyPromotion

                        this.bot.logger.info(
                            this.bot.isMobile,
                            'ACTIVITY',
                            `发现活动类型 "FindClippy" | 标题="${activity.title}" | offerId=${offerId}`
                        )

                        await this.bot.activities.doFindClippy(clippyPromotion)
                        break
                    }

                    // 不支持的类型
                    default: {
                        this.bot.logger.warn(
                            this.bot.isMobile,
                            'ACTIVITY',
                            `跳过活动 "${activity.title}" | offerId=${offerId} | 原因: 不支持的类型 "${activity.promotionType}"`
                        )
                        break
                    }
                }

                // 冷却时间
                await this.bot.utils.wait(this.bot.utils.randomDelay(5000, 15000))
            } catch (error) {
                this.bot.logger.error(
                    this.bot.isMobile,
                    'ACTIVITY',
                    `解决活动时出错 "${activity.title}" | 消息=${error instanceof Error ? error.message : String(error)}`
                )
            }
        }
    }
}
