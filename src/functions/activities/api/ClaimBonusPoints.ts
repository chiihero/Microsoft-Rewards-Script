import type { AxiosRequestConfig } from 'axios'
import { Workers } from '../../Workers'

export class ClaimBonusPoints extends Workers {
    private cookieHeader: string = ''

    private fingerprintHeader: { [x: string]: string } = {}

    private gainedPoints: number = 0

    private oldBalance: number = this.bot.userData.currentPoints

    public async claimBonusPoints() {
        if (!this.bot.requestToken && this.bot.rewardsVersion === 'legacy') {
            this.bot.logger.warn(
                this.bot.isMobile,
                'CLAIM-BONUS-POINTS',
                'Skipping: Request token not available, this activity requires it!'
            )
            return
        }

        this.bot.logger.info(
            this.bot.isMobile,
            'CLAIM-BONUS-POINTS',
            `Starting ClaimBonusPoints | geo=${this.bot.userData.geoLocale} | oldBalance=${this.oldBalance}`
        )

        try {
            this.cookieHeader = this.bot.browser.func.buildCookieHeader(
                this.bot.isMobile ? this.bot.cookies.mobile : this.bot.cookies.desktop,
                ['bing.com', 'live.com', 'microsoftonline.com']
            )

            const fingerprintHeaders = { ...this.bot.fingerprint.headers }
            delete fingerprintHeaders['Cookie']
            delete fingerprintHeaders['cookie']
            this.fingerprintHeader = fingerprintHeaders

            this.bot.logger.debug(
                this.bot.isMobile,
                'CLAIM-BONUS-POINTS',
                `Prepared ClaimBonusPoints headers | cookieLength=${this.cookieHeader.length} | fingerprintHeaderKeys=${Object.keys(this.fingerprintHeader).length}`
            )

            const formData = new URLSearchParams({
                timeZone: this.bot.userData.timezoneOffset,
                __RequestVerificationToken: this.bot.requestToken
            })

            this.bot.logger.debug(
                this.bot.isMobile,
                'CLAIM-BONUS-POINTS',
                `Prepared ClaimBonusPoints form data | timeZone=${this.bot.userData.timezoneOffset} | activityAmount=1`
            )

            const request: AxiosRequestConfig = {
                url: 'https://rewards.bing.com/api/claimallpointsasync?X-Requested-With=XMLHttpRequest',
                method: 'POST',
                headers: {
                    ...(this.bot.fingerprint?.headers ?? {}),
                    Cookie: this.cookieHeader,
                    Referer: 'https://rewards.bing.com/',
                    Origin: 'https://rewards.bing.com'
                },
                data: formData
            }

            this.bot.logger.debug(
                this.bot.isMobile,
                'CLAIM-BONUS-POINTS',
                `Sending ClaimBonusPoints request | url=${request.url}`
            )

            const response = await this.bot.axios.request(request)

            this.bot.logger.debug(
                this.bot.isMobile,
                'CLAIM-BONUS-POINTS',
                `Received ClaimBonusPoints response | status=${response.status}`
            )

            const newBalance = await this.bot.browser.func.getCurrentPoints()
            this.gainedPoints = newBalance - this.oldBalance

            this.bot.logger.debug(
                this.bot.isMobile,
                'CLAIM-BONUS-POINTS',
                `Balance delta after ClaimBonusPoints | oldBalance=${this.oldBalance} | newBalance=${newBalance} | gainedPoints=${this.gainedPoints}`
            )

            if (this.gainedPoints > 0) {
                this.bot.userData.currentPoints = newBalance
                this.bot.userData.gainedPoints = (this.bot.userData.gainedPoints ?? 0) + this.gainedPoints

                this.bot.logger.info(
                    this.bot.isMobile,
                    'CLAIM-BONUS-POINTS',
                    `Completed ClaimBonusPoints | status=${response.status} | gainedPoints=${this.gainedPoints} | newBalance=${newBalance}`,
                    'green'
                )
            } else {
                this.bot.logger.warn(
                    this.bot.isMobile,
                    'CLAIM-BONUS-POINTS',
                    `Failed ClaimBonusPoints with no points | status=${response.status} | oldBalance=${this.oldBalance} | newBalance=${newBalance}`
                )
            }

            this.bot.logger.debug(this.bot.isMobile, 'CLAIM-BONUS-POINTS', `Waiting after ClaimBonusPoints`)

            await this.bot.utils.wait(this.bot.utils.randomDelay(5000, 10000))
        } catch (error) {
            this.bot.logger.error(
                this.bot.isMobile,
                'CLAIM-BONUS-POINTS',
                `Error in doClaimBonusPoints | message=${error instanceof Error ? error.message : String(error)}`
            )
        }
    }
}
