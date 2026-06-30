import type { MicrosoftRewardsBot } from '../index'

export interface ParsedOffer {
    offerId: string
    hash: string | null
    title: string
    description: string
    points: number
    promotionSubtype: string | null
    destination: string
    isCompleted: boolean
    isPromotional: boolean
    isLocked: boolean
    unlockCriteria: string | null
    date: string | null
    activityType: number | null
    reportable: boolean
}

export interface QuestChild {
    offerId: string
    hash: string | null
    points: number
    isCompleted: boolean
    isLocked: boolean
    isDisabled: boolean
    reportable: boolean
}

export interface ParentQuest {
    offerId: string
    title: string
    pointProgressMax: number
    complete: boolean
}

export interface StreakState {
    partner: string
    activitiesCompleted: number
    activitiesTotal: number
    completedDays: number
    currentDay: number
    totalDays: number
    isCurrentDayCompleted: boolean
    isEnabled: boolean
    dailyPoints: number[]
}

export interface StreakProtectionState {
    isProtectionOn: boolean
    remainingDays: number | null
}

export interface AccountState {
    level: number | null
    pointsProgress: number | null
    pointsRemaining: number | null
    lifetimeEarn: number | null
    availablePoints: number | null
}

export interface PageSnapshot {
    offers: ParsedOffer[]
    reportable: ParsedOffer[]
    streaks: StreakState[]
    streakProtection: StreakProtectionState | null
    account: AccountState
}

export default class ReactFunc {
    private bot: MicrosoftRewardsBot

    constructor(bot: MicrosoftRewardsBot) {
        this.bot = bot
    }

    // Parse all avalable data from provided page
    public snapshotPage(html: string): PageSnapshot {
        const combined = this.concatFlightChunks(html)

        const offers = this.parseOffers(combined)
        const streaks = this.parseStreaks(combined)
        const streakProtection = this.parseStreakProtection(combined)
        const account = this.parseAccountData(combined)

        this.bot.logger.info(
            this.bot.isMobile,
            'REACT-PARSE',
            `快照完成 | 活动=${offers.length} | 可上报=${offers.filter(o => o.reportable).length} | 连击=${streaks.length} | 保护=${streakProtection ? `开启=${streakProtection.isProtectionOn},天数=${streakProtection.remainingDays ?? '?'}` : '无'} | 等级=${account.level}`
        )

        return {
            offers,
            reportable: offers.filter(o => o.reportable),
            streaks,
            streakProtection,
            account
        }
    }

    public getReportableOffers(html: string): ParsedOffer[] {
        return this.parseOffers(this.concatFlightChunks(html)).filter(o => o.reportable)
    }

    public getStreakProtection(html: string): StreakProtectionState | null {
        return this.parseStreakProtection(this.concatFlightChunks(html))
    }

    public buildId(html: string): string | null {
        const combined = this.concatFlightChunks(html)
        return (
            combined.match(/"buildId":"([A-Za-z0-9_-]{21})"/)?.[1] ??
            combined.match(/"b":"([A-Za-z0-9_-]{21})"/)?.[1] ??
            html.match(/\/_next\/static\/([A-Za-z0-9_-]{21})\//)?.[1] ??
            null
        )
    }

    private concatFlightChunks(html: string): string {
        try {
            const pushRe = /self\.__next_f\.push\(\[1,\s*"((?:[^"\\]|\\.)*)"\]\)/g
            let combined = ''
            let count = 0

            for (const match of html.matchAll(pushRe)) {
                try {
                    // Re-wrap in quotes so JSON.parse decodes
                    combined += JSON.parse(`"${match[1]}"`)
                    count++
                } catch (err) {
                    this.bot.logger.debug(
                        this.bot.isMobile,
                        'REACT-PARSE',
                        `跳过无法解码的 flight 数据块 | 错误=${err instanceof Error ? err.message : String(err)}`
                    )
                }
            }

            this.bot.logger.debug(
                this.bot.isMobile,
                'REACT-PARSE',
                `已拼接 flight 数据块 | 块数=${count} | 长度=${combined.length}`
            )

            if (count === 0) {
                this.bot.logger.warn(
                    this.bot.isMobile,
                    'REACT-PARSE',
                    '未找到 __next_f flight 数据块 - 页面可能不是 RSC 渲染或标记已变更'
                )
            }

            return combined
        } catch (error) {
            this.bot.logger.error(
                this.bot.isMobile,
                'REACT-PARSE',
                `拼接 flight 数据块失败 | 错误=${error instanceof Error ? error.message : String(error)}`
            )
            return ''
        }
    }

    // Find every object containing "anchor" and return them as parsed JSON
    private extractObjects(combined: string, anchor: string): Record<string, unknown>[] {
        const out: Record<string, unknown>[] = []
        let i = 0
        let failures = 0

        while ((i = combined.indexOf(anchor, i)) !== -1) {
            const start = combined.lastIndexOf('{', i)
            if (start === -1) {
                i += anchor.length
                continue
            }

            let depth = 0
            let end = -1
            let inStr = false
            let esc = false

            for (let j = start; j < combined.length; j++) {
                const c = combined[j]
                if (esc) {
                    esc = false
                    continue
                }
                if (c === '\\') {
                    esc = true
                    continue
                }
                if (c === '"') {
                    inStr = !inStr
                    continue
                }
                if (inStr) continue
                if (c === '{') depth++
                else if (c === '}') {
                    depth--
                    if (depth === 0) {
                        end = j
                        break
                    }
                }
            }

            if (end === -1) break

            const raw = combined.slice(start, end + 1)
            i = end

            try {
                out.push(JSON.parse(raw.replace(/"\$undefined"/g, 'null')))
            } catch {
                failures++
            }
        }

        if (failures > 0) {
            this.bot.logger.debug(
                this.bot.isMobile,
                'REACT-PARSE',
                `extractObjects("${anchor}") 有 ${failures} 个无法解析的匹配`
            )
        }

        return out
    }

    // Section parsers
    private parseOffers(combined: string): ParsedOffer[] {
        try {
            const seen = new Set<string>()
            const today = this.todayStamp()
            const offers: ParsedOffer[] = []

            for (const obj of this.extractObjects(combined, '"offerId"')) {
                const offerId = obj.offerId as string | undefined
                if (!offerId || seen.has(offerId)) continue
                seen.add(offerId)

                const hash = (obj.hash as string | null) ?? null
                const isCompleted = ((obj.isCompleted ?? obj.complete) as boolean | undefined) === true
                const isLocked = (obj.isLocked as boolean | undefined) === true
                const date = this.normaliseDate(obj.date as string | undefined)

                // Never try future-dated offers, lol
                const reportable = !!hash && !isCompleted && !isLocked && (date === null || date <= today)

                offers.push({
                    offerId,
                    hash,
                    title: (obj.title as string) ?? '',
                    description: (obj.description as string) ?? '',
                    points: (obj.points as number) ?? (obj.pointProgressMax as number) ?? 0,
                    promotionSubtype: (obj.promotionSubtype as string | null) ?? null,
                    destination: (obj.destination as string) ?? (obj.destinationUrl as string) ?? '',
                    isCompleted,
                    isPromotional: (obj.isPromotional as boolean | undefined) === true,
                    isLocked,
                    unlockCriteria: (obj.unlockCriteria as string | null) ?? null,
                    date,
                    activityType: null, // merge from getuserinfo later???
                    reportable
                })
            }

            this.bot.logger.debug(
                this.bot.isMobile,
                'REACT-PARSE',
                `已解析活动 | 总数=${offers.length} | 可上报=${offers.filter(o => o.reportable).length}`
            )

            return offers
        } catch (error) {
            this.bot.logger.error(
                this.bot.isMobile,
                'REACT-PARSE',
                `解析活动失败 | 错误=${error instanceof Error ? error.message : String(error)}`
            )
            return []
        }
    }

    private parseStreaks(combined: string): StreakState[] {
        try {
            const streaks = this.extractObjects(combined, '"dailyPoints"')
                .filter(o => typeof o.partner === 'string' && Array.isArray(o.dailyPoints))
                .map<StreakState>(o => ({
                    partner: o.partner as string,
                    activitiesCompleted: (o.activitiesCompleted as number) ?? 0,
                    activitiesTotal: (o.activitiesTotal as number) ?? 0,
                    completedDays: (o.completedDays as number) ?? 0,
                    currentDay: (o.currentDay as number) ?? 0,
                    totalDays: (o.totalDays as number) ?? 0,
                    isCurrentDayCompleted: (o.isCurrentDayCompleted as boolean | undefined) === true,
                    isEnabled: (o.isEnabled as boolean | undefined) === true,
                    dailyPoints: o.dailyPoints as number[]
                }))

            // de-dupe on partner
            const byPartner = new Map(streaks.map(s => [s.partner, s]))
            const unique = [...byPartner.values()]

            this.bot.logger.debug(
                this.bot.isMobile,
                'REACT-PARSE',
                `已解析连击 | ${unique.map(s => `${s.partner}:${s.completedDays}/${s.totalDays}`).join(', ') || '无'}`
            )

            return unique
        } catch (error) {
            this.bot.logger.error(
                this.bot.isMobile,
                'REACT-PARSE',
                `解析连击失败 | 错误=${error instanceof Error ? error.message : String(error)}`
            )
            return []
        }
    }

    private parseStreakProtection(combined: string): StreakProtectionState | null {
        try {
            const carriers = this.extractObjects(combined, '"isProtectionOn"').filter(o => 'isProtectionOn' in o)
            if (!carriers.length) return null

            // The flag and remainingDays
            const withDays = carriers.find(o => 'remainingDays' in o && typeof o.remainingDays === 'number')
            const withFlag = carriers.find(o => typeof o.isProtectionOn === 'boolean')

            const state: StreakProtectionState = {
                isProtectionOn: (withDays?.isProtectionOn ?? withFlag?.isProtectionOn) === true,
                remainingDays: withDays ? (withDays.remainingDays as number) : null
            }

            this.bot.logger.debug(
                this.bot.isMobile,
                'REACT-PARSE',
                `已解析连击保护 | 开启=${state.isProtectionOn} | 剩余天数=${state.remainingDays ?? '无'}`
            )

            return state
        } catch (error) {
            this.bot.logger.error(
                this.bot.isMobile,
                'REACT-PARSE',
                `解析连击保护失败 | 错误=${error instanceof Error ? error.message : String(error)}`
            )
            return null
        }
    }

    private parseAccountData(combined: string): AccountState {
        const empty: AccountState = {
            level: null,
            pointsProgress: null,
            pointsRemaining: null,
            lifetimeEarn: null,
            availablePoints: null
        }

        try {
            const membership =
                this.extractObjects(combined, '"pointsProgress"').find(
                    o => 'pointsRemaining' in o || 'lifetimeEarn' in o
                ) ?? {}

            // availablePoints renders in a separate header object
            const header = this.extractObjects(combined, '"availablePoints"').find(o => 'availablePoints' in o) ?? {}

            const account: AccountState = {
                level: (membership.level as number) ?? null,
                pointsProgress: (membership.pointsProgress as number) ?? null,
                pointsRemaining: (membership.pointsRemaining as number) ?? null,
                lifetimeEarn: (membership.lifetimeEarn as number) ?? null,
                availablePoints: (header.availablePoints as number) ?? (membership.availablePoints as number) ?? null
            }

            this.bot.logger.debug(
                this.bot.isMobile,
                'REACT-PARSE',
                `已解析账户 | 等级=${account.level} | 可用=${account.availablePoints} | 剩余=${account.pointsRemaining} | 总计=${account.lifetimeEarn}`
            )

            if (account.level === null && account.availablePoints === null) {
                this.bot.logger.warn(
                    this.bot.isMobile,
                    'REACT-PARSE',
                    '账户状态为空 - 载荷中未找到 membership/header 对象'
                )
            }

            return account
        } catch (error) {
            this.bot.logger.error(
                this.bot.isMobile,
                'REACT-PARSE',
                `解析账户失败 | 错误=${error instanceof Error ? error.message : String(error)}`
            )
            return empty
        }
    }

    public routerStateTree(segment: string): string {
        const tree = [
            '',
            {
                children: [
                    '(nav)',
                    {
                        children: [segment, { children: ['__PAGE__', {}, null, null, 0] }, null, null, 0]
                    },
                    null,
                    null,
                    0
                ]
            },
            null,
            null,
            16
        ]
        return encodeURIComponent(JSON.stringify(tree))
    }

    public questRouterStateTree(questId: string): string {
        const tree = [
            '',
            {
                children: [
                    '(nav)',
                    {
                        children: [
                            'earn',
                            {
                                children: [
                                    'quest',
                                    {
                                        children: [
                                            ['questId', questId, 'd', null],
                                            { children: ['__PAGE__', {}, null, null, 0] },
                                            null,
                                            null,
                                            0
                                        ]
                                    },
                                    null,
                                    null,
                                    0
                                ]
                            },
                            null,
                            null,
                            0
                        ]
                    },
                    null,
                    null,
                    0
                ]
            },
            null,
            null,
            16
        ]
        return encodeURIComponent(JSON.stringify(tree))
    }

    // Pull server-action ids out of a JS chunk
    public extractActionIds(jsText: string): {
        byName: Record<string, string>
        all: string[]
    } {
        const byName: Record<string, string> = {}
        const all = new Set<string>()

        // SHA-1 today (40 hex), allow growth to SHA-256 (64 hex)
        const HEX = '[a-f0-9]{40,64}'

        // Framework args that share the call shape but aren't the action name
        const KNOWN_NON_NAMES = new Set(['callServer', 'findSourceMapURL', 'encodeFormAction'])

        try {
            // I hate this so much honestly
            const callRegex = new RegExp(`createServerReference\\s*\\)?\\s*\\(\\s*"(${HEX})"([\\s\\S]{0,400}?)\\)`, 'g')
            const strLitRe = /"([A-Za-z_$][\w$]*)"/g

            for (const m of jsText.matchAll(callRegex)) {
                const id = m[1]!
                const argsBlock = m[2] ?? ''
                all.add(id)

                const candidates = [...argsBlock.matchAll(strLitRe)]
                    .map(x => x[1]!)
                    .filter(n => !KNOWN_NON_NAMES.has(n))
                if (candidates.length) byName[candidates[candidates.length - 1]!] = id
            }

            // bare reference without a name arg, still record the id
            const bareRegex = new RegExp(`createServerReference\\s*\\)?\\s*\\(\\s*"(${HEX})"`, 'g')
            for (const m of jsText.matchAll(bareRegex)) all.add(m[1]!)

            const actionIdRe = new RegExp(`\\$ACTION_ID_(${HEX})`, 'g')
            for (const m of jsText.matchAll(actionIdRe)) all.add(m[1]!)

            this.bot.logger.debug(
                this.bot.isMobile,
                'REACT-PARSE',
                `已提取 action id | 命名=${Object.keys(byName).length} | 总数=${all.size}`
            )

            if (all.size === 0) {
                this.bot.logger.debug(
                    this.bot.isMobile,
                    'REACT-PARSE',
                    'JS 数据块中未找到 server-action id - 数据块错误，或打包输出已变更'
                )
            }
        } catch (error) {
            this.bot.logger.error(
                this.bot.isMobile,
                'REACT-PARSE',
                `提取 action id 失败 | 错误=${error instanceof Error ? error.message : String(error)}`
            )
        }

        return { byName, all: [...all] }
    }

    // Quest pages (punchcards)
    public snapshotQuestPage(html: string): QuestChild[] {
        try {
            const combined = this.concatFlightChunks(html)
            const children = this.parseQuestOffers(combined)

            this.bot.logger.info(
                this.bot.isMobile,
                'REACT-PARSE',
                `任务快照 | 子任务=${children.length} | 可上报=${children.filter(c => c.reportable).length}`
            )

            return children
        } catch (error) {
            this.bot.logger.error(
                this.bot.isMobile,
                'REACT-PARSE',
                `解析任务页面失败 | 错误=${error instanceof Error ? error.message : String(error)}`
            )
            return []
        }
    }

    private parseQuestOffers(combined: string): QuestChild[] {
        const out: QuestChild[] = []
        const seen = new Set<string>()

        const idRe = /"offerId":"([^"]*pcchild[^"]*)"/g
        for (const questMatch of combined.matchAll(idRe)) {
            const offerId = questMatch[1] as string
            if (seen.has(offerId)) continue
            seen.add(offerId)

            const at = questMatch.index ?? 0
            const childAt = combined.indexOf('"children"', at)
            const windowEnd = childAt !== -1 && childAt - at < 1200 ? childAt : Math.min(at + 600, combined.length)
            const region = combined.slice(at, windowEnd)

            const hashMatch = region.match(/"hash":"([0-9a-f]{64})"/)
            const hash = hashMatch?.[1] ?? null

            const pointsMatch = region.match(/"points":(\d+)/)
            const points = pointsMatch ? Number(pointsMatch[1]) : 0

            const flag = (name: string): boolean => new RegExp(`"${name}":true`).test(region)
            const isCompleted = flag('isCompleted')
            const isLocked = flag('isLocked')
            const isDisabled = flag('isDisabled')

            const reportable = !!hash && !isCompleted && !isLocked && !isDisabled

            out.push({
                offerId,
                hash,
                points,
                isCompleted,
                isLocked,
                isDisabled,
                reportable
            })
        }

        this.bot.logger.debug(
            this.bot.isMobile,
            'REACT-PARSE',
            `已解析任务子项 | 总数=${out.length} | 可上报=${out.filter(c => c.reportable).length}`
        )

        return out
    }

    public snapshotQuestList(...htmls: string[]): ParentQuest[] {
        try {
            const combined = htmls.map(h => this.concatFlightChunks(h)).join('')

            const anchors: { id: string; at: number }[] = []
            for (const match of combined.matchAll(/\/earn\/quest\/([A-Za-z0-9_]+)/g)) {
                anchors.push({ id: match[1] as string, at: match.index ?? 0 })
            }
            for (const match of combined.matchAll(/"id":"quest_([A-Za-z0-9_]+)"/g)) {
                anchors.push({ id: match[1] as string, at: match.index ?? 0 })
            }
            for (const match of combined.matchAll(/[A-Za-z0-9_]*pcparent[A-Za-z0-9_]*/gi)) {
                anchors.push({ id: match[0] as string, at: match.index ?? 0 })
            }
            anchors.sort((a, b) => a.at - b.at)

            const byId = new Map<string, ParentQuest>()
            for (let k = 0; k < anchors.length; k++) {
                const { id, at } = anchors[k]!
                if (!this.isParentQuestId(id)) continue

                const next = anchors[k + 1]?.at ?? combined.length
                const region = combined.slice(at, Math.min(next, at + 3000))

                const title =
                    region.match(/"alt":"((?:[^"\\]|\\.)*)"/)?.[1] ??
                    region.match(/"title":"((?:[^"\\]|\\.)*)"/)?.[1] ??
                    ''

                const pointsMatch = region.match(/\["\+","([\d,]+)"\]/)
                const points = pointsMatch ? Number(pointsMatch[1]!.replace(/,/g, '')) : 0
                const taskM = region.match(/(\d+)\s*\/\s*(\d+)\s*tasks/)
                const complete = !!taskM && Number(taskM[1]) >= Number(taskM[2]!) && Number(taskM[2]) > 0

                // First wins for title/points
                const prev = byId.get(id)
                byId.set(id, {
                    offerId: id,
                    title: prev?.title || title,
                    pointProgressMax: prev?.pointProgressMax || points,
                    complete: prev?.complete || complete
                })
            }

            const out = [...byId.values()]
            this.bot.logger.info(
                this.bot.isMobile,
                'REACT-PARSE',
                `任务列表 | 父任务=${out.length} | 未完成=${out.filter(q => !q.complete).length}`
            )
            this.bot.logger.debug(
                this.bot.isMobile,
                'REACT-PARSE',
                `任务积分 | ${out.map(q => `${q.title || q.offerId}=${q.pointProgressMax}`).join(' | ') || '无'}`
            )
            if (!out.length) {
                this.bot.logger.warn(
                    this.bot.isMobile,
                    'REACT-PARSE',
                    '未解析到父任务 - 抓取的 HTML 可能缺少 QuestSection 数据块（Suspense/流式渲染或登录重定向）'
                )
            }
            return out
        } catch (error) {
            this.bot.logger.error(
                this.bot.isMobile,
                'REACT-PARSE',
                `解析任务列表失败 | 错误=${error instanceof Error ? error.message : String(error)}`
            )
            return []
        }
    }

    // <campaign>_pcparent_<name>_punchcard
    private isParentQuestId(offerId: string): boolean {
        const id = offerId.toLowerCase()
        if (id.includes('pcchild')) return false
        return id.includes('pcparent') || id.includes('punchcard')
    }

    // Utils
    private todayStamp(): string {
        const d = new Date()
        return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`
    }

    private normaliseDate(rawDate: string | undefined): string | null {
        if (!rawDate) return null
        const m = rawDate.match(/^(\d{2})\/(\d{2})\/(\d{4})$/)
        if (!m) return null
        return `${m[3]}-${m[1]}-${m[2]}`
    }
}
