import axios, { AxiosRequestConfig } from 'axios'
import PQueue from 'p-queue'
import type { WebhookPushPlusConfig } from '../interface/Config'

const pushPlusQueue = new PQueue({
    interval: 1000,
    intervalCap: 2,
    carryoverConcurrencyCount: true
})

export async function sendPushPlus(config: WebhookPushPlusConfig, content: string): Promise<void> {
    if (!config?.token) return

    const request: AxiosRequestConfig = {
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
            await axios(request)
        } catch (err: any) {
            const status = err?.response?.status
            if (status === 429) return
        }
    })
}

export async function flushPushPlusQueue(timeoutMs = 5000): Promise<void> {
    await Promise.race([
        (async () => {
            await pushPlusQueue.onIdle()
        })(),
        new Promise<void>((_, reject) => setTimeout(() => reject(new Error('pushplus刷新超时')), timeoutMs))
    ]).catch(() => {})
}
