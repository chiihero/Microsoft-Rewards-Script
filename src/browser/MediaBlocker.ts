import type { BrowserContext } from 'patchright'

import type { MicrosoftRewardsBot } from '../index'

const BLOCKED_RESOURCE_TYPES = new Set(['image', 'media'])
const AUTHENTICATION_HOSTS = new Set([
    'account.live.com',
    'account.microsoft.com',
    'login.live.com',
    'login.microsoftonline.com',
    'signup.live.com'
])
const mediaBlockingState = new WeakMap<BrowserContext, { enabled: boolean }>()

function isAuthenticationPage(rawUrl: string): boolean {
    try {
        const url = new URL(rawUrl)
        const hostname = url.hostname.toLowerCase()
        return (
            AUTHENTICATION_HOSTS.has(hostname) ||
            (hostname === 'rewards.bing.com' && url.pathname.toLowerCase().startsWith('/auth'))
        )
    } catch {
        return false
    }
}

export function suspendMediaBlocking(bot: MicrosoftRewardsBot, context: BrowserContext): void {
    const state = mediaBlockingState.get(context)
    if (!state?.enabled) return

    state.enabled = false
    bot.logger.info(
        bot.isMobile,
        'BROWSER',
        '登录期间媒体加载已放行 | 图片与媒体请求暂不拦截'
    )
}

export async function configureMediaBlocking(bot: MicrosoftRewardsBot, context: BrowserContext): Promise<void> {
    if (!bot.config.experimental.blockMedia) return

    const existingState = mediaBlockingState.get(context)
    if (existingState) {
        if (existingState.enabled) return
        existingState.enabled = true
        bot.logger.info(
            bot.isMobile,
            'BROWSER',
            '登录后媒体加载已禁用 | 拦截资源类型=image,media | http缓存=已通过路由禁用'
        )
        return
    }

    const state = { enabled: true }

    await context.route('**/*', async route => {
        const request = route.request()
        const authenticationPage = (() => {
            try {
                return isAuthenticationPage(request.frame().page().url())
            } catch {
                return false
            }
        })()

        if (state.enabled && !authenticationPage && BLOCKED_RESOURCE_TYPES.has(request.resourceType())) {
            await route.abort()
            return
        }

        await route.fallback()
    })
    mediaBlockingState.set(context, state)

    bot.logger.info(
        bot.isMobile,
        'BROWSER',
        '登录后媒体加载已禁用 | 拦截资源类型=image,media | http缓存=已通过路由禁用'
    )
}
