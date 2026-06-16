import fs from 'fs'
import { chromium } from 'patchright'
import { newInjectedContext } from 'fingerprint-injector'
import {
    getDirname,
    getProjectRoot,
    log,
    parseArgs,
    validateEmail,
    loadConfig,
    loadAccounts,
    findAccountByEmail,
    getRuntimeBase,
    getSessionPath,
    loadCookies,
    loadFingerprint,
    buildProxyConfig,
    setupCleanupHandlers
} from '../utils.js'

const __dirname = getDirname(import.meta.url)
const projectRoot = getProjectRoot(__dirname)

const args = parseArgs()
args.dev = args.dev || false

validateEmail(args.email)

const { data: config } = loadConfig(projectRoot, args.dev)
const { data: accounts } = loadAccounts(projectRoot, args.dev)

const account = findAccountByEmail(accounts, args.email)
if (!account) {
    log('ERROR', `未找到账户: ${args.email}`)
    log('ERROR', '可用账户:')
    accounts.forEach(acc => {
        if (acc?.email) log('ERROR', `  - ${acc.email}`)
    })
    process.exit(1)
}

async function main() {
    const runtimeBase = getRuntimeBase(projectRoot, args.dev)
    const sessionBase = getSessionPath(runtimeBase, config.sessionPath, args.email)

    log('INFO', '验证会话数据...')

    if (!fs.existsSync(sessionBase)) {
        log('ERROR', `会话目录不存在: ${sessionBase}`)
        log('ERROR', '请确保此账户的会话已创建')
        process.exit(1)
    }

    if (!config.baseURL) {
        log('ERROR', 'baseURL 在 config.json 中未设置')
        process.exit(1)
    }

    let cookies = await loadCookies(sessionBase, 'desktop')
    let sessionType = 'desktop'

    if (cookies.length === 0) {
        log('WARN', '未找到桌面会话 cookies，尝试移动会话...')
        cookies = await loadCookies(sessionBase, 'mobile')
        sessionType = 'mobile'

        if (cookies.length === 0) {
            log('ERROR', '在桌面或移动会话中未找到 cookies')
            log('ERROR', `会话目录: ${sessionBase}`)
            log('ERROR', '请确保此账户存在有效会话')
            process.exit(1)
        }

        log('INFO', `使用移动会话 (${cookies.length} 个 cookies)`)
    }

    const isMobile = sessionType === 'mobile'
    const fingerprintEnabled = isMobile ? account.saveFingerprint?.mobile : account.saveFingerprint?.desktop

    let fingerprint = null
    if (fingerprintEnabled) {
        fingerprint = await loadFingerprint(sessionBase, sessionType)
        if (!fingerprint) {
            log('ERROR', `${sessionType} 的指纹功能已启用但未找到指纹文件`)
            log('ERROR', `预期文件: ${sessionBase}/session_fingerprint_${sessionType}.json`)
            log('ERROR', '当明确启用指纹时，无法在没有指纹的情况下启动浏览器')
            process.exit(1)
        }
        log('INFO', `已加载 ${sessionType} 指纹`)
    }

    const proxy = buildProxyConfig(account)

    if (account.proxy && account.proxy.url && (!proxy || !proxy.server)) {
        log('ERROR', '账户中配置了代理但代理数据无效或不完整')
        log('ERROR', '账户代理配置:', JSON.stringify(account.proxy, null, 2))
        log('ERROR', '必需字段: proxy.url, proxy.port')
        log('ERROR', '当明确配置代理时，无法在没有代理的情况下启动浏览器')
        process.exit(1)
    }

    const userAgent = fingerprint?.fingerprint?.navigator?.userAgent || fingerprint?.fingerprint?.userAgent || null

    log('INFO', `会话: ${args.email} (${sessionType})`)
    log('INFO', `  Cookies: ${cookies.length}`)
    log('INFO', `  指纹: ${fingerprint ? '是' : '否'}`)
    log('INFO', `  用户代理: ${userAgent || '默认'}`)
    log('INFO', `  代理: ${proxy ? '是' : '否'}`)
    log('INFO', '正在启动浏览器...')

    const browser = await chromium.launch({
        headless: false,
        ...(proxy ? { proxy } : {}),
        args: [
            '--no-sandbox',
            '--mute-audio',
            '--disable-setuid-sandbox',
            '--ignore-certificate-errors',
            '--ignore-certificate-errors-spki-list',
            '--ignore-ssl-errors',
            '--no-first-run',
            '--no-default-browser-check',
            '--disable-user-media-security=true',
            '--disable-blink-features=Attestation',
            '--disable-features=WebAuthentication,PasswordManagerOnboarding,PasswordManager,EnablePasswordsAccountStorage,Passkeys',
            '--disable-save-password-bubble'
        ]
    })

    let context
    if (fingerprint) {
        context = await newInjectedContext(browser, { fingerprint })

        await context.addInitScript(() => {
            Object.defineProperty(navigator, 'credentials', {
                value: {
                    create: () => Promise.reject(new Error('WebAuthn disabled')),
                    get: () => Promise.reject(new Error('WebAuthn disabled'))
                }
            })
        })

        log('SUCCESS', '指纹已应用到浏览器上下文中')
    } else {
        context = await browser.newContext({
            viewport: isMobile ? { width: 375, height: 667 } : { width: 1366, height: 768 }
        })
    }

    if (cookies.length) {
        await context.addCookies(cookies)
        log('INFO', `添加了 ${cookies.length} 个 cookies 到上下文`)
    }

    const page = await context.newPage()
    await page.goto(config.baseURL, { waitUntil: 'domcontentloaded' })

    log('SUCCESS', '浏览器已打开并加载了会话')
    log('INFO', `导航至: ${config.baseURL}`)

    setupCleanupHandlers(async () => {
        if (browser?.isConnected?.()) {
            await browser.close()
        }
    })
}

main()
