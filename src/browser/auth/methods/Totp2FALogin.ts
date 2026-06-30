import type { Page } from 'patchright'
import * as OTPAuth from 'otpauth'
import type { MicrosoftRewardsBot } from '../../../index'
import { getErrorMessage, promptInput } from './LoginUtils'

export class TotpLogin {
    private readonly textInputSelector =
        'form[name="OneTimeCodeViewForm"] input[type="text"], input#floatingLabelInput5'
    private readonly secondairyInputSelector = 'input[id="otc-confirmation-input"], input[name="otc"]'
    private readonly submitButtonSelector = 'button[type="submit"]'
    private readonly maxManualSeconds = 60
    private readonly maxManualAttempts = 5

    constructor(private bot: MicrosoftRewardsBot) {}

    private generateTotpCode(secret: string): string {
        return new OTPAuth.TOTP({ secret, digits: 6 }).generate()
    }

    private async fillCode(page: Page, code: string): Promise<boolean> {
        try {
            const visibleInput = await page
                .waitForSelector(this.textInputSelector, { state: 'visible', timeout: 500 })
                .catch(() => null)

            if (visibleInput) {
                await visibleInput.fill(code)
                this.bot.logger.info(this.bot.isMobile, 'LOGIN-TOTP', '已填写 TOTP 输入框')
                return true
            }

            const secondairyInput = await page.$(this.secondairyInputSelector)
            if (secondairyInput) {
                await secondairyInput.fill(code)
                this.bot.logger.info(this.bot.isMobile, 'LOGIN-TOTP', '已填写 TOTP 输入框')
                return true
            }

            this.bot.logger.warn(this.bot.isMobile, 'LOGIN-TOTP', '未找到 TOTP 输入框')
            return false
        } catch (error) {
            this.bot.logger.warn(
                this.bot.isMobile,
                'LOGIN-TOTP',
                `填写 TOTP 输入框失败: ${error instanceof Error ? error.message : String(error)}`
            )
            return false
        }
    }

    async handle(page: Page, totpSecret?: string): Promise<void> {
        try {
            this.bot.logger.info(this.bot.isMobile, 'LOGIN-TOTP', 'TOTP 双因素认证已请求')

            if (totpSecret) {
                const code = this.generateTotpCode(totpSecret)
                this.bot.logger.info(this.bot.isMobile, 'LOGIN-TOTP', '已根据密钥生成 TOTP 验证码')

                const filled = await this.fillCode(page, code)
                if (!filled) {
                    this.bot.logger.error(this.bot.isMobile, 'LOGIN-TOTP', '无法填写 TOTP 输入框')
                    throw new Error('TOTP input field not found')
                }

                await this.bot.utils.wait(500)
                await this.bot.browser.utils.ghostClick(page, this.submitButtonSelector)
                await page.waitForLoadState('networkidle', { timeout: 5000 }).catch(() => {})

                const errorMessage = await getErrorMessage(page)
                if (errorMessage) {
                    this.bot.logger.error(this.bot.isMobile, 'LOGIN-TOTP', `TOTP 失败: ${errorMessage}`)
                    throw new Error(`TOTP authentication failed: ${errorMessage}`)
                }

                this.bot.logger.info(this.bot.isMobile, 'LOGIN-TOTP', 'TOTP 认证完成成功')
                return
            }

            this.bot.logger.info(this.bot.isMobile, 'LOGIN-TOTP', '未提供 TOTP 密钥, 等待手动输入')

            for (let attempt = 1; attempt <= this.maxManualAttempts; attempt++) {
                const code = await promptInput({
                    question: `Enter the 6-digit TOTP code (waiting ${this.maxManualSeconds}s): `,
                    timeoutSeconds: this.maxManualSeconds,
                    validate: code => /^\d{6}$/.test(code)
                })

                if (!code || !/^\d{6}$/.test(code)) {
                    this.bot.logger.warn(
                        this.bot.isMobile,
                        'LOGIN-TOTP',
                        `无效或缺失的验证码 (第 ${attempt}/${this.maxManualAttempts} 次尝试) | 输入长度=${code?.length}`
                    )

                    if (attempt === this.maxManualAttempts) {
                        throw new Error('Manual TOTP input failed or timed out')
                    }
                    continue
                }

                const filled = await this.fillCode(page, code)
                if (!filled) {
                    this.bot.logger.error(
                        this.bot.isMobile,
                        'LOGIN-TOTP',
                        `无法填写 TOTP 输入框 (第 ${attempt}/${this.maxManualAttempts} 次尝试)`
                    )

                    if (attempt === this.maxManualAttempts) {
                        throw new Error('TOTP input field not found')
                    }
                    continue
                }

                await this.bot.utils.wait(500)
                await this.bot.browser.utils.ghostClick(page, this.submitButtonSelector)
                await page.waitForLoadState('networkidle', { timeout: 5000 }).catch(() => {})

                // Check if wrong code was entered
                const errorMessage = await getErrorMessage(page)
                if (errorMessage) {
                    this.bot.logger.warn(
                        this.bot.isMobile,
                        'LOGIN-TOTP',
                        `验证码错误: ${errorMessage} (第 ${attempt}/${this.maxManualAttempts} 次尝试)`
                    )

                    if (attempt === this.maxManualAttempts) {
                        throw new Error(`Maximum attempts reached: ${errorMessage}`)
                    }
                    continue
                }

                this.bot.logger.info(this.bot.isMobile, 'LOGIN-TOTP', 'TOTP 认证完成成功')
                return
            }

            throw new Error(`TOTP input failed after ${this.maxManualAttempts} attempts`)
        } catch (error) {
            this.bot.logger.error(
                this.bot.isMobile,
                'LOGIN-TOTP',
                `发生错误: ${error instanceof Error ? error.message : String(error)}`
            )
            throw error
        }
    }
}
