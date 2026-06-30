import { httpRequest } from '../util/Http'
import type { HttpRequestConfig } from '../util/Http'
import PQueue from 'p-queue'
import type { WebhookPushPlusConfig } from '../interface/Config'

const pushPlusQueue = new PQueue({
    interval: 1000,
    intervalCap: 2,
    carryoverConcurrencyCount: true
})

export async function sendPushPlus(config: WebhookPushPlusConfig, content: string): Promise<void> {
    if (!config?.token) return

    const request: HttpRequestConfig = {
        method: 'POST',
        url: 'https://www.pushplus.plus/send',
        headers: { 'Content-Type': 'application/json' },
        data: {
            token: config.token,
            title: config.title,
            content,
            template: config.template,
            channel: config.channel
        },
        timeout: 10000
    }

    await pushPlusQueue.add(async () => {
        try {
            await httpRequest(request)
        } catch (err) {
            const status = (err as { response?: { status?: number } })?.response?.status
            if (status === 429) return
        }
    })
}

export async function flushPushPlusQueue(timeoutMs = 5000): Promise<void> {
    let timer: NodeJS.Timeout | undefined
    await Promise.race([
        pushPlusQueue.onIdle(),
        new Promise<void>((_, reject) => {
            timer = setTimeout(() => reject(new Error('pushplus flush timeout')), timeoutMs)
        })
    ]).catch(() => {})
    if (timer) clearTimeout(timer)
}
