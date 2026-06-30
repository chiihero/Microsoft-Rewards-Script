import { URLs } from '../constants/urls'
import type { Page } from 'patchright'
import type { MicrosoftRewardsBot } from '../index'
import type { DashboardData, PunchCard, BasePromotion } from '../interface/DashboardData'
import type { AppDashboardData } from '../interface/AppDashBoardData'
import type { QuestChild, ParentQuest } from '../browser/ReactFunc'

export class Workers {
    public bot: MicrosoftRewardsBot

    constructor(bot: MicrosoftRewardsBot) {
        this.bot = bot
    }

    public async doDailySet(data: DashboardData) {
        const todayKey = this.bot.utils.getFormattedDate()
        const todayData = data.dashboard.dailySetPromotions[todayKey]

        const activitiesUncompleted = todayData?.filter(x => !x?.complete && x.pointProgressMax > 0) ?? []

        if (!activitiesUncompleted.length) {
            this.bot.logger.info(this.bot.isMobile, 'DAILY-SET', '所有"每日任务"项目已完成')
            return
        }

        this.bot.logger.info(this.bot.isMobile, 'DAILY-SET', '开始处理"每日任务"项目')

        await this.solveActivities(activitiesUncompleted)

        this.bot.logger.info(this.bot.isMobile, 'DAILY-SET', '所有"每日任务"项目已完成')
    }

    public async doMorePromotions(data: DashboardData) {
        const morePromotions: BasePromotion[] = [
            ...new Map(
                [
                    ...(data.dashboard.morePromotions ?? []),
                    ...(data.dashboard.morePromotionsWithoutPromotionalItems ?? [])
                ]
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
                if (x.priority < 0 && x.exclusiveLockedFeatureStatus !== 'unlocked') return false
                if (x.attributes?.promotional === 'True') return false
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
            `开始处理 ${activitiesUncompleted.length} 个"更多推广"项目`
        )

        await this.solveActivities(activitiesUncompleted)

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
            await this.bot.utils.wait(this.bot.utils.randomDelay(5000, 15000))
        }

        this.bot.logger.info(this.bot.isMobile, 'APP-PROMOTIONS', '所有"应用推广"项目已完成')
    }

    public async doPunchCards(data: DashboardData, page: Page) {
        let parents: ParentQuest[]

        try {
            const earn = await page.request.get(URLs.rewards.earn)
            if (!earn.ok()) {
                this.bot.logger.warn(this.bot.isMobile, 'PUNCHCARD', `/earn ${earn.status()} - 无法获取任务列表`)
                return
            }
            const html = await earn.text()
            parents = this.bot.browser.react.snapshotQuestList(html)

            // Some deploys render the carousel only on /dashboard
            if (!parents.length) {
                const dash = await page.request.get(URLs.rewards.dashboard)
                if (dash.ok()) parents = this.bot.browser.react.snapshotQuestList(html, await dash.text())
            }
        } catch (error) {
            this.bot.logger.warn(
                this.bot.isMobile,
                'PUNCHCARD',
                `获取任务列表 /earn 失败 | ${error instanceof Error ? error.message : String(error)}`
            )
            return
        }

        const apiById = new Map(
            (data.dashboard.punchCards ?? [])
                .filter(c => c.parentPromotion?.offerId)
                .map(c => [c.parentPromotion.offerId, c] as const)
        )

        const seen = new Set(parents.map(p => p.offerId))
        for (const card of apiById.values()) {
            const pp = card.parentPromotion
            if (!pp?.offerId || seen.has(pp.offerId)) continue
            parents.push({
                offerId: pp.offerId,
                title: pp.title ?? '',
                pointProgressMax: pp.pointProgressMax ?? 0,
                complete: !!pp.complete
            })
            seen.add(pp.offerId)
        }

        for (const p of parents) {
            if (p.pointProgressMax <= 0) {
                p.pointProgressMax = apiById.get(p.offerId)?.parentPromotion?.pointProgressMax ?? p.pointProgressMax
            }
        }

        const incomplete = parents.filter(p => {
            if (p.complete) return false
            if (this.bot.config.skipNonPointTasks && p.pointProgressMax <= 0) return false
            return true
        })
        if (!incomplete.length) {
            this.bot.logger.info(this.bot.isMobile, 'PUNCHCARD', '没有可执行的任务')
            return
        }

        this.bot.logger.info(
            this.bot.isMobile,
            'PUNCHCARD',
            `在 /earn 上发现 ${incomplete.length} 个未完成的任务 | api 匹配数=${incomplete.filter(p => apiById.has(p.offerId)).length}`
        )

        for (const parent of incomplete) {
            try {
                await this.solvePunchCard(parent, apiById.get(parent.offerId), page)
            } catch (error) {
                this.bot.logger.error(
                    this.bot.isMobile,
                    'PUNCHCARD',
                    `处理任务 "${parent.title || parent.offerId}" 时出错 | 消息=${error instanceof Error ? error.message : String(error)}`
                )
            }
        }

        this.bot.logger.info(this.bot.isMobile, 'PUNCHCARD', '任务处理完成')
    }

    public async doClaimBonusPoints(data: DashboardData) {
        const pointsActivity = data.dashboard.pointClaimBannerPromotion

        if (!pointsActivity) {
            this.bot.logger.info(this.bot.isMobile, 'CLAIM-BONUS-POINTS', '未找到领取奖励积分横幅')
            return
        }

        if (pointsActivity.complete) {
            this.bot.logger.info(
                this.bot.isMobile,
                'CLAIM-BONUS-POINTS',
                `奖励积分已被领取 | offerId=${pointsActivity.offerId}`
            )
            return
        }

        await this.bot.activities.doClaimBonusPoints()

        this.bot.logger.info(
            this.bot.isMobile,
            'CLAIM-BONUS-POINTS',
            `已领取奖励积分 | 标题="${pointsActivity.title}" | offerId=${pointsActivity.offerId}`
        )
    }

    private async solvePunchCard(parent: ParentQuest, apiCard: PunchCard | undefined, page: Page) {
        const parentId = parent.offerId
        const title = parent.title || apiCard?.parentPromotion?.title || parentId

        let questChildren: QuestChild[]
        try {
            const res = await page.request.get(URLs.rewards.quest(parentId))
            if (!res.ok()) {
                this.bot.logger.warn(
                    this.bot.isMobile,
                    'PUNCHCARD',
                    `"${title}" 的任务页 ${res.status()} - 跳过`
                )
                return
            }
            questChildren = this.bot.browser.react.snapshotQuestPage(await res.text())
        } catch (error) {
            this.bot.logger.warn(
                this.bot.isMobile,
                'PUNCHCARD',
                `获取 "${title}" 的任务页失败 | ${error instanceof Error ? error.message : String(error)}`
            )
            return
        }

        if (!questChildren.length) {
            this.bot.logger.info(this.bot.isMobile, 'PUNCHCARD', `"${title}" 未渲染出可执行的子任务`)
            return
        }

        const apiChildById = new Map(
            (apiCard?.childPromotions ?? []).filter(c => c.offerId).map(c => [c.offerId, c] as const)
        )
        const ordered = [...questChildren].sort(
            (a, b) =>
                (apiChildById.get(a.offerId)?.priority ?? Number.MAX_SAFE_INTEGER) -
                (apiChildById.get(b.offerId)?.priority ?? Number.MAX_SAFE_INTEGER)
        )

        this.bot.logger.info(
            this.bot.isMobile,
            'PUNCHCARD',
            `正在处理 "${title}" | 子任务数=${ordered.length} | 可上报数=${ordered.filter(c => c.reportable).length}`
        )

        const startBalance = this.bot.userData.currentPoints
        let reported = 0
        let remaining = 0

        for (const child of ordered) {
            const offerId = child.offerId
            const api = apiChildById.get(offerId)

            if (!child.reportable) {
                remaining++
                this.bot.logger.debug(
                    this.bot.isMobile,
                    'PUNCHCARD',
                    `跳过 ${offerId}: 不可上报 (已锁定=${child.isLocked} 已禁用=${child.isDisabled} 已完成=${child.isCompleted} hash=${!!child.hash})`
                )
                continue
            }

            if (this.isSearchQuotaChild(offerId, api)) {
                remaining++
                this.bot.logger.info(this.bot.isMobile, 'PUNCHCARD', `跳过 ${offerId}: 多日搜索任务`)
                continue
            }

            if (this.isClaimChild(offerId, api)) {
                if (!this.bot.config.autoClaimPunchcardRewards) {
                    remaining++
                    this.bot.logger.info(
                        this.bot.isMobile,
                        'PUNCHCARD',
                        `"${title}" 的奖励可领取 - 留待手动兑换 (autoClaimPunchcardRewards=false) | ${offerId}`
                    )
                    continue
                }
                await this.bot.activities.doClaimReward(child, parentId)
                reported++
                continue
            }

            await this.reportQuestChild(child, parentId)
            reported++
            await this.bot.utils.wait(this.bot.utils.randomDelay(5000, 15000))
        }

        const gained = this.bot.userData.currentPoints - startBalance
        this.bot.logger.info(
            this.bot.isMobile,
            'PUNCHCARD',
            `任务 "${title}" ${remaining === 0 ? '已完成' : '进行中'} | 已上报=${reported}${remaining ? ` | 剩余=${remaining}` : ''} | 获得积分=${gained}${parent.pointProgressMax > 0 ? `/${parent.pointProgressMax}` : ''}`,
            gained > 0 ? 'green' : undefined
        )
    }

    private async reportQuestChild(child: QuestChild, parentId: string) {
        const offerId = child.offerId
        const actionId = this.bot.nextActions.reportActivity
        if (!actionId) {
            this.bot.logger.warn(this.bot.isMobile, 'PUNCHCARD', `跳过 ${offerId}: 未发现 "reportActivity"`)
            return
        }
        if (!child.hash) {
            this.bot.logger.warn(this.bot.isMobile, 'PUNCHCARD', `跳过 ${offerId}: 任务子项无有效 hash`)
            return
        }

        const oldBalance = this.bot.userData.currentPoints
        try {
            const questUrl = URLs.rewards.quest(parentId)
            const { status, acknowledged } = await this.bot.browser.func.reportServerAction(
                actionId,
                [
                    child.hash,
                    11,
                    { offerid: offerId, isPromotional: '$undefined', timezoneOffset: this.bot.userData.timezoneOffset }
                ],
                {
                    url: questUrl,
                    referer: questUrl,
                    routerStateTree: this.bot.browser.react.questRouterStateTree(parentId)
                }
            )

            const newBalance = await this.bot.browser.func.getCurrentPoints()
            const gained = newBalance - oldBalance
            if (gained > 0) {
                this.bot.userData.currentPoints = newBalance
                this.bot.userData.gainedPoints = (this.bot.userData.gainedPoints ?? 0) + gained
            }

            this.bot.logger.info(
                this.bot.isMobile,
                'PUNCHCARD',
                `已上报子任务 | offerId=${offerId} | 状态=${status} | 已确认=${acknowledged}${gained > 0 ? ` | 获得积分=${gained}` : ''}`,
                gained > 0 || acknowledged ? 'green' : undefined
            )
        } catch (error) {
            this.bot.logger.error(
                this.bot.isMobile,
                'PUNCHCARD',
                `上报子任务出错 | offerId=${offerId} | 消息=${error instanceof Error ? error.message : String(error)}`
            )
        }
    }

    private async solveActivities(activities: BasePromotion[]) {
        for (const activity of activities) {
            try {
                const type = activity.promotionType?.toLowerCase() ?? ''
                const name = activity.name?.toLowerCase() ?? ''
                const offerId = (activity as BasePromotion).offerId

                this.bot.logger.debug(
                    this.bot.isMobile,
                    'ACTIVITY',
                    `处理活动 | 标题="${activity.title}" | offerId=${offerId} | 类型=${type}`
                )

                switch (type) {
                    case 'urlreward': {
                        const basePromotion = activity as BasePromotion

                        // Search on Bing are subtypes of "urlreward"
                        const isSearchOnBing = name.includes('exploreonbing')

                        if (isSearchOnBing && !this.bot.config.activities.searchOnBing) {
                            this.bot.logger.info(
                                this.bot.isMobile,
                                'ACTIVITY',
                                `跳过 "SearchOnBing" (已在配置中禁用) | offerId=${offerId}`
                            )
                            continue
                        }
                        if (!isSearchOnBing && !this.bot.config.activities.urlReward) {
                            this.bot.logger.info(
                                this.bot.isMobile,
                                'ACTIVITY',
                                `跳过 "UrlReward" (已在配置中禁用) | offerId=${offerId}`
                            )
                            continue
                        }

                        if (isSearchOnBing) {
                            this.bot.logger.info(
                                this.bot.isMobile,
                                'ACTIVITY',
                                `发现活动类型 "SearchOnBing" | 标题="${activity.title}" | offerId=${offerId}`
                            )

                            const page = this.bot.isMobile ? this.bot.mainMobilePage : this.bot.mainDesktopPage
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

                    default: {
                        this.bot.logger.warn(
                            this.bot.isMobile,
                            'ACTIVITY',
                            `跳过活动 "${activity.title}" | offerId=${offerId} | 原因: 不支持的类型 "${activity.promotionType}"`
                        )
                        break
                    }
                }

                await this.bot.utils.wait(this.bot.utils.randomDelay(5000, 15000))
            } catch (error) {
                this.bot.logger.error(
                    this.bot.isMobile,
                    'ACTIVITY',
                    `处理活动时出错 "${activity.title}" | 消息=${error instanceof Error ? error.message : String(error)}`
                )
            }
        }
    }

    // Util
    private isSearchQuotaChild(offerId: string, api?: BasePromotion): boolean {
        if (api) {
            const type = (api.promotionType ?? '').toLowerCase()
            const attrType = String(api.attributes?.type ?? '').toLowerCase()
            const dest = (api.destinationUrl ?? '').toLowerCase()
            if (type === 'search' || attrType === 'search' || /bing\.com\/search/.test(dest)) {
                return true
            }
        }

        return /search/i.test(offerId) && /(day|streak|\dx)/i.test(offerId)
    }

    private isClaimChild(offerId: string, api?: BasePromotion): boolean {
        const dest = (api?.destinationUrl ?? '').toLowerCase()
        if (/\/redeem\//.test(dest)) return true
        return /(redeem|claim|(?<!url)reward)/i.test(offerId)
    }
}
