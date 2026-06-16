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
| `clusters` | 并发账户实例数 | `1` |
| `errorDiagnostics` | 出错时自动截图诊断 | `true` |
| `debugLogs` | 输出 DEBUG 级别日志（也可用 `-dev` 启动参数临时开启） | `false` |


### Fingerprinting / 指纹识别
| 设置 | 描述 | 默认值 |
|---------|-------------|---------|
| `saveFingerprint.mobile` | 重用移动浏览器指纹 | `false` |
| `saveFingerprint.desktop` | 重用桌面浏览器指纹 | `false` |


### Job State / 任务状态
| 设置 | 描述 | 默认值 |
|---------|-------------|---------|
| `workers.doDailySet` | 完成每日集活动 | `true` |
| `workers.doSpecialPromotions` | 完成特殊促销活动 | `true` |
| `workers.doMorePromotions` | 完成促销优惠 | `true` |
| `workers.doClaimBonusPoints` | 领取 dashboard 上的奖励积分（新版 UI 走 Server Action） | `true` |
| `workers.doPunchCards` | 完成打卡活动 | `true` |
| `workers.doAppPromotions` | 完成 App 端活动（ReadToEarn / DailyCheckIn 等） | `true` |
| `workers.doDesktopSearch` | 执行桌面搜索 | `true` |
| `workers.doMobileSearch` | 执行移动搜索 | `true` |
| `workers.doDailyCheckIn` | 完成每日签到 | `true` |
| `workers.doReadToEarn` | 完成阅读赚取活动 | `true` |
| `ensureStreakProtection` | 启用连击保护（账户级配置，新版 UI 走 Server Action） | `true` |

### Search / 搜索
| 设置 | 描述 | 默认值 |
|---------|-------------|---------|
| `searchOnBingLocalQueries` | 使用本地查询 vs. 获取的查询 | `false` |
| `searchSettings.scrollRandomResults` | 随机滚动搜索结果 | `true` |
| `searchSettings.clickRandomResults` | 点击随机结果链接 | `true` |
| `searchSettings.parallelSearching` | 桌面端/移动端搜索并行执行 | `false` |
| `searchSettings.queryEngines` | 查询源及顺序（数组），决定从哪些源获取搜索词 | `['china', 'local']` |
| `searchSettings.searchResultVisitTime` | 访问搜索结果页的停留时间 | `10sec` |
| `searchSettings.searchDelay` | 搜索之间的延迟（最小/最大） | `30sec - 1min` |
| `searchSettings.readDelay` | 阅读赚取活动的阅读间隔（最小/最大） | `30sec - 1min` |
| `searchSettings.chinaApi.appkey` | gmya.net appkey（填入解除免费档限流，留空走免费档） | `''`（空） |

> 注：示例配置 `config.example.json` 里 `searchDelay` 为 `6-12min`、`readDelay` 为 `6-11min`、`searchResultVisitTime` 为 `20sec`，比 Validator 默认值更保守，适合长时间挂机场景。

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
- **策略**：随机打乱 5 个源，取前 N 个聚合去重（避免每个账号都用同一个源）。N 由是否配置 `chinaApi.appkey` 决定：有 appkey 取 2 个；免费档取 1 个。首选源全部失败时自动 fallback 到剩余源
- **限流处理**：免费档（无 appkey）对连续请求有频率限制，会触发 403。本脚本在源与源之间插入随机退避（1.2~2.5s），命中限流后指数退避 ×1.5，并将限流错误如实上报（不再误报为"格式异常"）。想彻底避免限流，在 `searchSettings.chinaApi.appkey` 填入 gmya.net appkey
- **扩展**：对每个热搜词调用 Bing Suggestions/Related Terms 扩展查询多样性（命中率取决于词的特性 —— 短词高、长句低），扩展进度采样输出，结尾输出"热搜词使用清单"（INFO 级别）
- **本地兜底**：`src/functions/search-queries.json` 提供 392 个标准查询词作为补充


### 高级设置
| 设置 | 描述 | 默认值 |
|---------|-------------|---------|
| `globalTimeout` | 操作超时持续时间 | `30sec` |
| `proxy.queryEngine` | 代理查询引擎请求（google/wikipedia/reddit 等需翻墙的源；china 源走 gmya.net 国内直连，无需开） | `false` |
| `consoleLogFilter` | 控制台日志过滤（按级别/关键词/正则 白名单或黑名单） | 见下方说明 |
| `webhook.webhookLogFilter` | Webhook 推送日志过滤（结构同 consoleLogFilter） | 见下方说明 |

#### 日志过滤（consoleLogFilter / webhookLogFilter）
两个字段结构相同，用于过滤输出到控制台 / webhook 的日志：
```json
{
    "enabled": false,
    "mode": "whitelist",
    "levels": ["error", "warn"],
    "keywords": ["starting account"],
    "regexPatterns": []
}
```
- `mode`：`whitelist`（只输出匹配的）或 `blacklist`（排除匹配的）
- `levels`：日志级别筛选（`debug`/`info`/`warn`/`error`）
- `keywords`：日志消息包含这些关键词则命中
- `regexPatterns`：正则匹配

### Webhook 设置
本项目支持三种推送渠道（均在 `webhook` 对象下，可同时开启多个）：

| 设置 | 描述 | 默认值 |
|---------|-------------|---------|
| `webhook.discord.enabled` | 启用 Discord 推送 | `false` |
| `webhook.discord.url` | Discord webhook URL | `""` |
| `webhook.ntfy.enabled` | 启用 ntfy 推送 | `false` |
| `webhook.ntfy.url` | ntfy 服务器 URL | `""` |
| `webhook.ntfy.topic` | ntfy 主题 | `""` |
| `webhook.ntfy.token` | ntfy 认证 token | `""` |
| `webhook.ntfy.priority` | ntfy 优先级（1-5） | `3` |
| `webhook.pushplus.enabled` | 启用 PushPlus 推送（国内） | `false` |
| `webhook.pushplus.token` | PushPlus token | `""` |
| `webhook.pushplus.template` | PushPlus 模板（`txt`/`html`/`markdown`） | `txt` |

> **国内推荐**：PushPlus（微信推送，无需翻墙）。Discord/ntfy 需要能访问对应服务。


### 新版 UI 兼容性（Server Action）

微软新版 dashboard（modern UI）改用 Next.js App Router，部分功能不再有对外 REST API，旧版 API（`togglestreakasync`、`claimallpointsasync`）在新版 UI 下因取不到 `requestToken` 会返回 `400 Bad Request`。

| 功能 | 调用方式 | 认证 |
|---|---|---|
| 连击保护 toggle | `POST /dashboard` + `next-action` hash + body `[true]` | Cookie |
| 领取积分 | `POST /dashboard` + `next-action` hash + body `[]` | Cookie |

**版本守卫机制**：`next-action` hash 在编译时生成、绑定到具体部署版本（`dpl`）。脚本启动时从 dashboard HTML 提取当前部署 ID，与脚本内置的支持版本（`20260612-3`）比对：
- ✅ **匹配** → 走 Server Action（新版 UI）
- ⚠️ **不匹配** → 微软可能更新了 dashboard，内置 hash 可能失效，相关功能**自动降级跳过**（不会 400，不影响其他任务）
- 旧版 UI（legacy）→ 仍走原 REST API（需要 `requestToken`）

如果降级跳过频繁出现，说明微软更新了部署，需要重新更新 hash。

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
- ✅ 中国热搜（百度/头条/抖音/微博/知乎，多源聚合 + 限流退避）
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
- ✅ ntfy 推送支持
- ✅ PushPlus 推送支持（国内微信推送）
- ✅ 全面日志记录（带日志过滤、本地文件持久化）
- ✅ Docker 支持与监控


## ⚠️ 免责声明

**风险自负！** 使用自动化脚本时，您的 Microsoft Rewards 账户可能会被暂停或禁止。

此脚本仅供教育目的。作者对 Microsoft 采取的任何账户操作不承担责任。
