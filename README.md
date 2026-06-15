# 微软奖励脚本
自动化的微软奖励脚本，这次使用 TypeScript、Cheerio 和 Playwright 编写。

该项目来源于https://github.com/TheNetsky/Microsoft-Rewards-Script ，感谢原作者的付出

本项目不定时同步原项目代码，主要内容为本地化处理，主要针对的是国内用户无法访问外网google和输出日志简单翻译等问题，并在原有基础上完善功能。若有侵权请联系我删除。

本项目所有改动基于win11系统和docker环境。其他系统未测试，请根据原项目相关配置设置。

# 同步原项目时间
2026年6月15日16:12:44


# window环境 #
## 如何自动设置 ##
1. 下载或克隆源代码
2. win系统运行setup.bat部署环境（若使用setup.bat报错，请参考手动设置）
3. 在dist目录 `accounts.json`添加你的账户信息
4. 按照你的喜好修改dist目录 `config.json` 文件
5. 运行 `npm start`或运行 `run.bat` 启动构建好的脚本
## 如何手动设置 ##
1. 下载或克隆源代码
2. 下载安装nodejs 24和npm环境
3. 运行 `npm install` 安装依赖包
4. 若Error: browserType.launch: Executable doesn't exist报错执行 npx patchright install chromium
5. 将 `accounts.example.json` 重命名为 `accounts.json`，并添加你的账户信息
6. 按照你的喜好修改 `config.json` 文件
7. 运行 `npm run pre-build` 预构建脚本
8. 运行 `npm run build` 构建脚本
9. 运行 `npm start` 启动构建好的脚本


# Docker环境 #
1. 下载或克隆源代码
2. 确保`config.json`内的 `headless`设置为`true`
3. 编辑`compose.yaml` 
* 设置时区`TZ` 
* 设置调度`CRON_SCHEDULE` （默认为每天7点执行一次）
* 保持`RUN_ON_START=true`
4. 启动容器
~~~
docker compose up -d 
~~~

## 注意事项 ##
- 如果出现无法自动登录情况，请在代码执行登录过程中手动完成网页的登录，等待代码自动完成剩下流程。登录信息保存在sessions目录（需要多备份），后续运行根据该目录的会话文件来运行。
- 复制或重命名 `src/accounts.example.json` 为 `src/accounts.json` 并添加您的凭据
- 复制或重命名 `src/config.example.json` 为 `src/config.json` 并自定义您的偏好。
- 不要跳过此步骤。之前的 accounts.json 和 config.json 版本与当前版本不兼容。
- 您必须在对 accounts.json 和 config.json 进行任何更改后重新构建脚本。

## 配置参考

编辑 `src/config.json` 以自定义行为。
以下是关键配置部分的摘要。

### Core / 核心
| 设置 | 描述 | 默认值 |
|----------|-------------|----------|
| `baseURL` | Microsoft Rewards base URL | `https://rewards.bing.com` |
| `sessionPath` | 用于存储浏览器会话的文件夹 | `sessions` |
| `headless` | 在后台运行浏览器 | `false`（可见） |
| `dryRun` | 模拟执行而不运行任务 | `false` |
| `parallel` | 同时运行移动/桌面任务 | `true` |
| `runOnZeroPoints` | 在没有可用积分时继续 | `false` |
| `clusters` | 并发账户实例数 | `1` |


### Fingerprinting / 指纹识别
| 设置 | 描述 | 默认值 |
|---------|-------------|---------|
| `saveFingerprint.mobile` | 重用移动浏览器指纹 | `false` |
| `saveFingerprint.desktop` | 重用桌面浏览器指纹 | `false` |


### Job State / 任务状态
| 设置 | 描述 | 默认值 |
|---------|-------------|---------|
| `workers.doDailySet` | 完成每日集活动 | `true` |
| `workers.doMorePromotions` | 完成促销优惠 | `true` |
| `workers.doPunchCards` | 完成打卡活动 | `true` |
| `workers.doDesktopSearch` | 执行桌面搜索 | `true` |
| `workers.doMobileSearch` | 执行移动搜索 | `true` |
| `workers.doDailyCheckIn` | 完成每日签到 | `true` |
| `workers.doReadToEarn` | 完成阅读赚取活动 | `true` |
| `workers.doClaimBonusPoints` | 领取 dashboard 上的奖励积分（新版 UI 走 Server Action） | `true` |
| `ensureStreakProtection` | 启用连击保护（账户级配置，新版 UI 走 Server Action） | `true` |

### Search / 搜索
| 设置 | 描述 | 默认值 |
|---------|-------------|---------|
| `searchOnBingLocalQueries` | 使用本地查询 vs. 获取的查询 | `false` |
| `searchSettings.useGeoLocaleQueries` | 生成基于位置的查询 | `false` |
| `searchSettings.scrollRandomResults` | 随机滚动搜索结果 | `true` |
| `searchSettings.clickRandomResults` | 点击随机结果链接 | `true` |
| `searchSettings.searchDelay` | 搜索之间的延迟（最小/最大） | `3-5 分钟` |
| `searchSettings.retryMobileSearchAmount` | 移动搜索重试次数 | `2` |
| `searchSettings.queryEngines` | 查询源及顺序（数组），决定从哪些源获取搜索词 | `['google','wikipedia','reddit','local']` |

#### queryEngines 查询源说明
`searchSettings.queryEngines` 决定从哪些源获取搜索词，按数组顺序尝试。可选值：

| 值 | 来源 | 国内可用性 |
|---|---|---|
| `china` | 中国热搜（gmya.net：百度/头条/抖音/微博/知乎） | ✅ 直连 |
| `local` | 本地查询词（`search-queries.json`，392 个标准词） | ✅ 离线 |
| `google` | Google Trends | ❌ 需代理（见 `proxy.queryEngine`） |
| `wikipedia` | 维基百科热门 | ❌ 需代理 |
| `reddit` | Reddit 热门帖 | ❌ 需代理 |

**国内推荐配置**：`["china", "local"]`（示例配置默认值），无需代理即可获取丰富搜索词。

#### 查询词来源（中国地区）
当 `queryEngines` 包含 `china` 时，搜索词从中国热搜获取：
- **数据源**：gmya.net 热门词 API（百度/头条/抖音/微博/知乎热搜榜）
- **策略**：每次运行**随机选取 2 个源**聚合去重（避免每个账号都用同一个源），首选源全部失败时自动 fallback 到剩余源
- **扩展**：对每个热搜词调用 Bing Suggestions/Related Terms 扩展查询多样性（命中率取决于词的特性 —— 短词高、长句低），扩展进度采样输出，结尾输出"热搜词使用清单"（INFO 级别）
- **本地兜底**：`src/functions/search-queries.json` 提供 392 个标准查询词作为补充


### Humanization / 人性化
| 设置 | 描述 | 默认值 |
|----------|-------------|----------|
| `humanization.enabled` | 启用人类行为 | `true` |
| `stopOnBan` | 封禁时立即停止 | `true` |
| `immediateBanAlert` | 被封禁时立即提醒 | `true` |
| `actionDelay.min` | 每个操作的最小延迟(毫秒) | `500` |
| `actionDelay.max` | 每个操作的最大延迟(毫秒) | `2200` |
| `gestureMoveProb` | 随机鼠标移动几率 | `0.65` |
| `gestureScrollProb` | 随机滚动几率 | `0.4` |

### 高级设置
| 设置 | 描述 | 默认值 |
|---------|-------------|---------|
| `globalTimeout` | 操作超时持续时间 | `30s` |
| `logExcludeFunc` | 从日志中排除的函数 | `SEARCH-CLOSE-TABS` |
| `webhookLogExcludeFunc` | 从 webhooks 中排除的函数 | `SEARCH-CLOSE-TABS` |
| `proxy.proxyGoogleTrends` | 代理 Google Trends 请求 | `true` |
| `proxy.proxyBingTerms` | 代理 Bing Terms 请求 | `true` |
| `proxy.queryEngine` | 代理查询引擎请求（google/wikipedia/reddit 等需翻墙的源；china 源走 gmya.net 国内直连，无需开） | `false` |

### Webhook 设置
| 设置 | 描述 | 默认值 |
|---------|-------------|---------|
| `webhook.enabled` | 启用 Discord 通知 | `false` |
| `webhook.url` | Discord webhook URL | `null` |
| `conclusionWebhook.enabled` | 启用仅摘要 webhook | `false` |
| `conclusionWebhook.url` | 摘要 webhook URL | `null` |


### 新版 UI 兼容性（Server Action）

微软新版 dashboard（modern UI）改用 Next.js App Router，部分功能不再有对外 REST API，旧版 API（`togglestreakasync`、`claimallpointsasync`）在新版 UI 下因取不到 `requestToken` 会返回 `400 Bad Request`。

本项目通过**抓包逆向**得到了新版 UI 的真实调用方式 —— Next.js Server Action：

| 功能 | 调用方式 | 认证 |
|---|---|---|
| 连击保护 toggle | `POST /dashboard` + `next-action` hash + body `[true]` | Cookie |
| 领取积分 | `POST /dashboard` + `next-action` hash + body `[]` | Cookie |

**版本守卫机制**：`next-action` hash 在编译时生成、绑定到具体部署版本（`dpl`）。脚本启动时从 dashboard HTML 提取当前部署 ID，与脚本内置的支持版本（`20260612-3`）比对：
- ✅ **匹配** → 走 Server Action（新版 UI）
- ⚠️ **不匹配** → 微软可能更新了 dashboard，内置 hash 可能失效，相关功能**自动降级跳过**（不会 400，不影响其他任务）
- 旧版 UI（legacy）→ 仍走原 REST API（需要 `requestToken`）

如果降级跳过频繁出现，说明微软更新了部署，需要重新抓包更新 hash。

## ✨ 功能

**账户管理：**
- ✅ 多账户支持
- ✅ 会话存储与持久化
- ✅ 2FA 支持
- ✅ 无密码登录支持

**自动化与控制：**
- ✅ 无头浏览器操作
- ✅ 集群支持（同时多个账户）
- ✅ 可配置任务选择
- ✅ 代理支持
- ✅ 自动调度（Docker）

**搜索与活动：**
- ✅ 桌面与移动搜索
- ✅ Microsoft Edge 搜索模拟
- ✅ 地理定位搜索查询
- ✅ 模拟滚动与链接点击
- ✅ 每日集完成
- ✅ 促销活动
- ✅ 打卡完成
- ✅ 每日签到
- ✅ 阅读赚取活动
- ✅ 连击保护（新版 UI 走 Server Action）
- ✅ 领取 dashboard 奖励积分（新版 UI 走 Server Action）

**搜索词来源（中国地区）：**
- ✅ 中国热搜（百度/头条/抖音/微博/知乎，随机取 2 源聚合）
- ✅ Bing Suggestions / Related Terms 扩展（日志聚合输出）
- ✅ 本地查询词兜底（`search-queries.json`，392 个标准词）

**测验与互动内容：**
- ✅ 测验解答（10 分与 30-40 分变体）
- ✅ 此或彼测验（随机答案）
- ✅ ABC 测验解答
- ✅ 投票完成
- ✅ 点击奖励

**通知与监控：**
- ✅ Discord Webhook 集成
- ✅ 专用摘要 Webhook
- ✅ 全面日志记录
- ✅ Docker 支持与监控


## 更新日志 ##
1. 添加了移动端的活动领取-2025年6月24日
2. 添加了中文热搜内容-2025年6月25日
3. ~~优化大量随机性，优化模拟人类操作-2025年7月3日~~
4. 允许useLocale设置自定义地区-2025年7月10日
5. 添加了日志本地保存功能-2025年7月26日
6. 由于pnpm依赖导致无法编译问题，项目暂时改回使用npm管理-2025年11月11日
7. 补充docker的运行方式-2025年11月11日
8. **连击保护/领取积分迁移到新版 UI 的 Server Action**：抓包逆向新版 dashboard 的 Next.js Server Action 调用方式，修复旧版 REST API 在新版 UI 下 400 错误；带部署版本守卫，hash 失效自动降级跳过-2026年6月15日
9. **搜索查询日志聚合**：扩展循环从 100+ 条 DEBUG 降到 ~10 条采样汇总；新增"热搜词使用清单"（INFO 级别，分可扩展/未扩展/直通三类展示）-2026年6月15日
10. **中国热搜源重构**：修复 fallback Bug（原 while 循环始终用同一个源）；fetch→axios 架构对齐（走代理配置）；新增 ZhiHuHot 源；改为**随机取 2 个源聚合**（避免每个账号都用同一个源）-2026年6月15日
11. **连击保护独立文件**：从 BrowserFunc.ts 抽出 StreakProtection.ts，与 ClaimBonusPoints 结构对称-2026年6月15日

## ⚠️ 免责声明

**风险自负！** 使用自动化脚本时，您的 Microsoft Rewards 账户可能会被暂停或禁止。

此脚本仅供教育目的。作者对 Microsoft 采取的任何账户操作不承担责任。
