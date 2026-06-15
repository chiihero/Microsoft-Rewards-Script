import { z } from 'zod'
import semver from 'semver'
import pkg from '../../package.json'

import { Config } from '../interface/Config'
import { Account } from '../interface/Account'

const NumberOrString = z.union([z.number(), z.string()])

const LogFilterSchema = z.object({
    enabled: z.boolean(),
    mode: z.enum(['whitelist', 'blacklist']),
    levels: z.array(z.enum(['debug', 'info', 'warn', 'error'])).optional(),
    keywords: z.array(z.string()).optional(),
    regexPatterns: z.array(z.string()).optional()
})

const DelaySchema = z.object({
    min: NumberOrString,
    max: NumberOrString
})

const QueryEngineSchema = z.enum(['china', 'google', 'wikipedia', 'reddit', 'local'])

// Webhook
const WebhookSchema = z.object({
    discord: z
        .object({
            enabled: z.boolean(),
            url: z.string()
        })
        .optional(),
    ntfy: z
        .object({
            enabled: z.boolean().optional(),
            url: z.string(),
            topic: z.string().optional(),
            token: z.string().optional(),
            title: z.string().optional(),
            tags: z.array(z.string()).optional(),
            priority: z.union([z.literal(1), z.literal(2), z.literal(3), z.literal(4), z.literal(5)]).optional()
        })
        .optional(),
    pushplus: z
        .object({
            enabled: z.boolean().optional(),
            token: z.string(),
            title: z.string().optional(),
            template: z.enum(['txt', 'html', 'markdown']).optional(),
            channel: z.string().optional()
        })
        .optional(),
    webhookLogFilter: LogFilterSchema
})

// Config
export const ConfigSchema = z.object({
    baseURL: z.string(),
    sessionPath: z.string(),
    headless: z.boolean(),
    clusters: z.number().int().nonnegative(),
    errorDiagnostics: z.boolean(),
    ensureStreakProtection: z.boolean(),
    workers: z.object({
        doDailySet: z.boolean(),
        doSpecialPromotions: z.boolean(),
        doMorePromotions: z.boolean(),
        doClaimBonusPoints: z.boolean(),
        doPunchCards: z.boolean(),
        doAppPromotions: z.boolean(),
        doDesktopSearch: z.boolean(),
        doMobileSearch: z.boolean(),
        doDailyCheckIn: z.boolean(),
        doReadToEarn: z.boolean()
    }),
    searchOnBingLocalQueries: z.boolean(),
    globalTimeout: NumberOrString,
    searchSettings: z.object({
        scrollRandomResults: z.boolean(),
        clickRandomResults: z.boolean(),
        parallelSearching: z.boolean(),
        queryEngines: z.array(QueryEngineSchema),
        searchResultVisitTime: NumberOrString,
        searchDelay: DelaySchema,
        readDelay: DelaySchema
    }),
    debugLogs: z.boolean(),
    proxy: z.object({
        queryEngine: z.boolean()
    }),
    consoleLogFilter: LogFilterSchema,
    webhook: WebhookSchema
})

// Account
export const AccountSchema = z.object({
    email: z.string(),
    password: z.string(),
    totpSecret: z.string().optional(),
    recoveryEmail: z.string(),
    geoLocale: z.string(),
    langCode: z.string(),
    proxy: z.object({
        proxyAxios: z.boolean(),
        url: z.string(),
        port: z.number(),
        password: z.string(),
        username: z.string()
    }),
    saveFingerprint: z.object({
        mobile: z.boolean(),
        desktop: z.boolean()
    })
})

const defaultConfig: Config = {
    baseURL: 'https://rewards.bing.com',
    sessionPath: 'sessions',
    headless: true,
    clusters: 1,
    errorDiagnostics: true,
    ensureStreakProtection: true,
    workers: {
        doDailySet: true,
        doSpecialPromotions: true,
        doMorePromotions: true,
        doClaimBonusPoints: true,
        doPunchCards: true,
        doAppPromotions: true,
        doDesktopSearch: true,
        doMobileSearch: true,
        doDailyCheckIn: true,
        doReadToEarn: true
    },
    searchOnBingLocalQueries: false,
    globalTimeout: '30sec',
    searchSettings: {
        scrollRandomResults: true,
        clickRandomResults: true,
        parallelSearching: true,
        queryEngines: ['google', 'wikipedia', 'reddit', 'local'],
        searchResultVisitTime: '10sec',
        searchDelay: { min: '30sec', max: '1min' },
        readDelay: { min: '30sec', max: '1min' }
    },
    debugLogs: false,
    proxy: { queryEngine: true },
    consoleLogFilter: {
        enabled: false,
        mode: 'whitelist',
        levels: ['info', 'warn', 'error'],
        keywords: [],
        regexPatterns: []
    },
    webhook: {
        webhookLogFilter: {
            enabled: false,
            mode: 'whitelist',
            levels: ['warn', 'error'],
            keywords: [],
            regexPatterns: []
        }
    }
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
    return typeof v === 'object' && v !== null && !Array.isArray(v)
}

function getByPath(obj: unknown, path: ReadonlyArray<string | number>): unknown {
    return path.reduce<unknown>((acc, key) => {
        if (acc == null) return undefined
        return (acc as Record<string | number, unknown>)[key]
    }, obj)
}

function setByPath<T>(obj: T, path: ReadonlyArray<string | number>, value: unknown): T {
    if (path.length === 0) return value as T
    const head = path[0]
    if (head === undefined) return value as T
    const rest = path.slice(1)
    const base = obj ?? (typeof head === 'number' ? [] : {})
    const cloned: any = Array.isArray(base) ? [...base] : { ...(base as object) }
    cloned[head] = setByPath((base as any)[head], rest, value)
    return cloned
}

function fillMissing(data: unknown, defaults: unknown, path = ''): unknown {
    if (!isPlainObject(defaults)) return data
    if (!isPlainObject(data)) {
        if (data === undefined) {
            console.warn(`[Config] "${path || '<root>'}" missing, using default`)
            return defaults
        }
        return data
    }
    const result: Record<string, unknown> = { ...data }
    for (const key of Object.keys(defaults)) {
        const p = path ? `${path}.${key}` : key
        if (!(key in result)) {
            console.warn(`[Config] "${p}" not found, using default: ${JSON.stringify(defaults[key])}`)
            result[key] = defaults[key]
        } else if (isPlainObject(defaults[key])) {
            result[key] = fillMissing(result[key], defaults[key], p)
        }
    }
    return result
}

export function validateConfig(data: unknown): Config {
    const filled = fillMissing(data, defaultConfig)
    let result = ConfigSchema.safeParse(filled)
    if (result.success) return result.data as Config

    let patched: unknown = filled
    for (const issue of result.error.issues) {
        const def = getByPath(defaultConfig, issue.path as (string | number)[])
        console.warn(
            `[Config] "${issue.path.join('.') || '<root>'}" invalid (${issue.message}), using default: ${JSON.stringify(def)}`
        )
        patched = setByPath(patched, issue.path as (string | number)[], def)
    }
    result = ConfigSchema.safeParse(patched)
    if (!result.success) {
        console.error('[Config] still invalid after applying defaults:', result.error.issues)
        throw new Error('Config validation failed')
    }
    return result.data as Config
}

export function validateAccounts(data: unknown): Account[] {
    const result = z.array(AccountSchema).safeParse(data)
    if (result.success) return result.data

    for (const issue of result.error.issues) {
        const path = issue.path.join('.') || '<root>'
        if (issue.code === 'invalid_type') {
            if (issue.input === undefined) {
                console.error(`[Accounts] "${path}" is missing (expected ${issue.expected})`)
            } else {
                console.error(
                    `[Accounts] "${path}" has wrong type: expected ${issue.expected}, got ${typeof issue.input}`
                )
            }
        } else if (issue.code === 'invalid_union') {
            console.error(`[Accounts] "${path}" does not match any allowed type: ${issue.message}`)
        } else {
            console.error(`[Accounts] "${path}" ${issue.message} (code: ${issue.code})`)
        }
    }
    throw new Error(`Accounts validation failed: ${result.error.issues.length} issue(s) — see logs above`)
}

export function checkNodeVersion(): void {
    try {
        const requiredVersion = pkg.engines?.node

        if (!requiredVersion) {
            console.warn('在package.json "engines" 字段中未找到Node.js版本要求。')
            return
        }

        if (!semver.satisfies(process.version, requiredVersion)) {
            console.error(`当前Node.js版本 ${process.version} 不满足要求: ${requiredVersion}`)
            process.exit(1)
        }
    } catch (error) {
        console.error('验证Node.js版本失败:', error)
        process.exit(1)
    }
}
