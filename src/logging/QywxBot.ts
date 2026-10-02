import { httpRequest } from '../util/Http'
import type { HttpRequestConfig } from '../util/Http'
import PQueue from 'p-queue'
import type { WebhookQywxBotConfig } from '../interface/Config'
import { flushQueue } from './Queue'

const qywxBotQueue = new PQueue({
    interval: 1000,
    intervalCap: 2,
    carryoverConcurrencyCount: true
})

const QYWX_BOT_API = 'https://qyapi.weixin.qq.com/cgi-bin/webhook/send'
const TITLE = 'Microsoft-Rewards-Script'

export interface QywxBotSendResult {
    ok: boolean
    /** 未启用或缺少 sendKey，调用方无需记录日志 */
    skipped?: boolean
    message?: string
}

export async function sendQywxBot(config: WebhookQywxBotConfig, content: string): Promise<QywxBotSendResult> {
    if (!config?.enabled || !config?.sendKey) {
        return { ok: false, skipped: true, message: '未启用或 sendKey 为空' }
    }

    const request: HttpRequestConfig = {
        method: 'POST',
        url: `${QYWX_BOT_API}?key=${config.sendKey}`,
        headers: { 'Content-Type': 'application/json;charset=utf-8' },
        data: {
            msgtype: 'text',
            text: {
                content: `${TITLE}\n\n${content}`
            }
        },
        timeout: 15000
    }

    return qywxBotQueue.add(async () => {
        try {
            const response = await httpRequest<{ errcode?: number; errmsg?: string }>(request)
            const { errcode, errmsg } = response?.data ?? {}

            if (errcode === undefined || errcode === 0) {
                return { ok: true }
            }

            return { ok: false, message: `errcode=${errcode}${errmsg ? ` errmsg=${errmsg}` : ''}` }
        } catch (err) {
            const status = (err as { response?: { status?: number } })?.response?.status
            if (status === 429) {
                return { ok: false, message: '触发接口频率限制(429)，本次跳过' }
            }

            return { ok: false, message: err instanceof Error ? err.message : String(err) }
        }
    })
}

export function flushQywxBotQueue(timeoutMs = 5000): Promise<void> {
    return flushQueue(qywxBotQueue, timeoutMs)
}
