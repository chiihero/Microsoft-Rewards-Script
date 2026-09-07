import { httpRequest } from '../util/Http'
import type { HttpRequestConfig } from '../util/Http'
import PQueue from 'p-queue'
import type { WebhookServerChanConfig } from '../interface/Config'
import { flushQueue } from './Queue'

const serverChanQueue = new PQueue({
    interval: 1000,
    intervalCap: 2,
    carryoverConcurrencyCount: true
})

export async function sendServerChan(config: WebhookServerChanConfig, content: string): Promise<void> {
    if (!config?.sendKey) return

    const request: HttpRequestConfig = {
        method: 'POST',
        url: `https://sctapi.ft07.com/${config.sendKey}.send`,
        headers: { 'Content-Type': 'application/json' },
        data: {
            title: config.title ?? 'Microsoft-Rewards-Script',
            desp: content
        },
        timeout: 10000
    }

    await serverChanQueue.add(async () => {
        try {
            await httpRequest(request)
        } catch (err) {
            const status = (err as { response?: { status?: number } })?.response?.status
            if (status === 429) return
        }
    })
}

export function flushServerChanQueue(timeoutMs = 5000): Promise<void> {
    return flushQueue(serverChanQueue, timeoutMs)
}
