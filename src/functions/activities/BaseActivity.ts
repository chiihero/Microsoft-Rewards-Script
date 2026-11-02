import type { MicrosoftRewardsBot } from '../../index'

export abstract class BaseActivity {
    protected readonly bot: MicrosoftRewardsBot
    private executed = false

    constructor(bot: MicrosoftRewardsBot) {
        this.bot = bot
    }

    protected markExecuted(): void {
        this.executed = true
    }

    public didExecute(): boolean {
        return this.executed
    }
}
