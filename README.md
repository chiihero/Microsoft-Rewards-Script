<div align="center">

# 微软奖励脚本

[![Version](https://img.shields.io/badge/version-4.0.1-blue.svg)](./package.json)
[![License](https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg)](./LICENSE)
[![Node](https://img.shields.io/badge/node-%3E%3D24-green.svg)](./package.json)
[![Last Sync](https://img.shields.io/badge/最后同步-2026--06--30（V4架构）-orange.svg)](#-同步与致谢)
[![Upstream](https://img.shields.io/badge/上游-TheNetsky/Microsoft--Rewards--Script-informational.svg)](https://github.com/TheNetsky/Microsoft-Rewards-Script)

**基于 TypeScript · Playwright · Cheerio 的微软奖励自动化脚本**

针对国内用户深度本地化：✅ 中国热搜查询源（百度/头条/抖音/微博/知乎） · ✅ 日志中文化 · ✅ PushPlus 微信推送

</div>

---

## 📑 目录

- [✨ 核心特性](#-核心特性)
- [🚀 快速开始](#-快速开始)
- [📦 Windows 部署](#-windows-部署)
- [🐳 Docker 部署](#-docker-部署)
- [⚙️ 配置参考](#-配置参考)
- [🔔 通知渠道](#-通知渠道)
- [❓ 常见问题](#-常见问题)
- [⚠️ 注意事项](#-注意事项)
- [📜 同步与致谢](#-同步与致谢)
- [⚠️ 免责声明](#-免责声明)

---

## ✨ 核心特性

**账户管理**
- ✅ 多账户支持
- ✅ 会话存储与持久化
- ✅ 2FA 支持
- ✅ 无密码登录支持

**自动化与控制**
- ✅ 无头浏览器操作
- ✅ 集群支持（同时多个账户）
- ✅ 可配置任务选择
- ✅ 代理支持
- ✅ 自动调度（Docker）

**搜索与活动**
- ✅ 桌面与移动搜索（Microsoft Edge 模拟）
- ✅ 地理定位搜索查询
- ✅ 模拟滚动与链接点击
- ✅ 每日集 / 促销活动 / 打卡 / 每日签到 / 阅读赚取
- ✅ 连击保护 & 领取 dashboard 奖励积分（新版 UI 走 Server Action）

**搜索词来源（中国地区）**
- ✅ 中国热搜（百度/头条/抖音/微博/知乎，多源聚合 + 限流退避）
- ✅ Bing Suggestions / Related Terms 扩展（日志聚合输出）
- ✅ 本地查询词兜底（`search-queries.json`，完整词库）

**通知与监控**
- ✅ Discord Webhook 集成
- ✅ ntfy 推送支持
- ✅ PushPlus 推送支持（国内微信推送）
- ✅ 全面日志记录（带日志过滤、本地文件持久化）
- ✅ Docker 支持与监控

---

## 🚀 快速开始

本脚本支持两种部署方式，**按你的场景二选一即可**：

| 维度 | 📦 Windows 直跑 | 🐳 Docker |
|---|---|---|
| **配置方式** | 手动编辑 `accounts.json` + `config.json` | `.env` + `compose.yaml` 环境变量 |
| **调度** | 手动 / 计划任务 | 内置 cron |
| **headless** | 可选（可见窗口） | 强制 `true`（无显示器） |
| **数据持久化** | `sessions/` 目录 | `./config/` + `./sessions/` 挂载 |
| **升级方式** | `git pull` + `npm run build` | `docker compose up -d --build` |
| **前置要求** | Node.js 24+ | Docker + Docker Compose |


详细步骤见下方对应章节。

---

## 📦 Windows 部署

> ⚠️ 本项目所有改动基于 Win11 系统测试，其他系统请参考[原项目](https://github.com/TheNetsky/Microsoft-Rewards-Script)相关配置。

<details>
<summary><b>🔧 自动设置（推荐，一键部署）</b></summary>

1. 下载或克隆源代码
2. Win 系统运行 `setup.bat` 部署环境（若 `setup.bat` 报错，请参考下方手动设置）
3. 在 `dist` 目录的 `accounts.json` 添加你的账户信息
4. 按照你的喜好修改 `dist` 目录的 `config.json` 文件
5. 运行 `npm start` 或运行 `run.bat` 启动构建好的脚本

</details>

<details>
<summary><b>🛠 手动设置（自动设置失败时使用）</b></summary>

1. 下载或克隆源代码
2. 下载安装 Node.js 24 和 npm 环境
3. 运行 `npm install` 安装依赖包
4. 若出现 `Error: browserType.launch: Executable doesn't exist` 报错，执行：

   ```bash
   npx patchright install chromium
   ```

5. 将 `accounts.example.json` 重命名为 `accounts.json`，并添加你的账户信息
6. 按照你的喜好修改 `config.json` 文件
7. 运行预构建脚本：

   ```bash
   npm run pre-build
   ```

8. 构建脚本：

   ```bash
   npm run build
   ```

9. 启动：

   ```bash
   npm start
   ```

</details>

---

## 🐳 Docker 部署
<details>
Docker 下账号和行为配置都通过环境变量传入，容器启动时由 `entrypoint.sh` 自动生成 `accounts.json` 和 `config.json`，**无需手动维护这两个文件**。

### 1. 准备账号文件（.env）

从模板复制并填写：

```bash
cp env.example .env
```

编辑 `.env`，至少填一个账号：

```dotenv
ACCOUNT_1_EMAIL=you@example.com
ACCOUNT_1_PASSWORD=your_password
# 国内账号推荐加：
ACCOUNT_1_GEO_LOCALE=cn
ACCOUNT_1_LANG_CODE=zh
```

> 多账号按 `ACCOUNT_2_*`、`ACCOUNT_3_*` 递增，编号必须连续。完整字段见 `env.example`。

### 2. 编辑 compose.yaml（可选）

默认配置开箱即用，如需调整取消对应行注释即可：

- `TZ`：时区（默认 `Asia/Shanghai`）
- `CRON_SCHEDULE`：调度（默认 `0 7 * * *`，每天 7 点）
- `RUN_ON_START`：容器启动时是否立即跑一次（默认 `true`）
- `CONFIG_QUERY_ENGINES`：查询源，国内推荐 `china,local`
- `CONFIG_CHINA_API_APPKEY`：gmya.net appkey，配合 china 查询源解除免费档限流（留空走免费档）
- `CONFIG_PUSHPLUS_*`：PushPlus 微信推送

> 完整的 `CONFIG_*` 环境变量列表见 `scripts/docker/entrypoint.sh` 顶部注释。

### 3. 关于 headless

无需手动设置。Docker 环境下 `headless` 被容器入口强制设为 `true`（容器内无显示器，无法开窗口模式）。

### 4. 构建并启动

```bash
docker compose up -d --build
```

> **重要**：改了代码或 Dockerfile 后，必须加 `--build` 参数重建镜像，否则跑的还是旧镜像。首次部署也建议带 `--build`。

### 5. 数据持久化

容器挂载了两个目录，重建容器不丢数据：

- `./config/`：配置和账号文件
- `./sessions/`：登录会话（首次登录后 cookie 存这里，后续自动复用）

### 常用命令

```bash
docker compose up -d --build   # 构建+启动
docker compose logs -f          # 查看日志
docker compose down             # 停止并删除容器
docker compose restart          # 重启（不重建）
```

---
</details>

## ⚙️ 配置参考

> 编辑 `src/config.json`（Windows）或通过 `CONFIG_*` 环境变量（Docker）自定义行为。
> 下面按功能分组，**点击各 summary 展开详情**。

<details>
<summary><b>🔵 Core / 核心配置</b></summary>

| 设置 | 描述 | 默认值 |
|----------|-------------|----------|
| `sessionPath` | 用于存储浏览器会话的文件夹 | `sessions` |
| `headless` | 在后台运行浏览器 | `false`（可见） |
| `clusters` | 并发账户实例数 | `1` |
| `globalTimeout` | 单次操作/任务的全局超时 | `30sec` |
| `autoClaimPunchcardRewards` | 自动领取打卡（PunchCards）已完成的奖励积分 | `false` |
| `skipNonPointTasks` | 跳过无积分产出的任务 | `true` |
| `errorDiagnostics` | 出错时自动截图诊断 | `true` |
| `debugLogs` | 输出 DEBUG 级别日志（也可用 `-dev` 启动参数临时开启） | `false` |

</details>

<details>
<summary><b>👆 Fingerprinting / 指纹识别</b></summary>

| 设置 | 描述 | 默认值 |
|---------|-------------|---------|
| `saveFingerprint.mobile` | 重用移动浏览器指纹 | `false` |
| `saveFingerprint.desktop` | 重用桌面浏览器指纹 | `false` |

</details>

<details>
<summary><b>🗂 Job State / 任务开关</b></summary>

| 设置 | 描述 | 默认值 |
|---------|-------------|---------|
| `workers.doDailySet` | 完成每日集活动 | `true` |
| `workers.doMorePromotions` | 完成促销优惠（More Promotions） | `true` |
| `workers.doClaimBonusPoints` | 领取 dashboard 上的奖励积分 | `true` |
| `workers.doPunchCards` | 完成打卡活动 | `true` |
| `workers.doAppPromotions` | 完成 App 端活动（ReadToEarn / DailyCheckIn 等） | `true` |
| `workers.doDesktopSearch` | 执行桌面搜索 | `true` |
| `workers.doMobileSearch` | 执行移动搜索 | `true` |
| `workers.doBonusSearches` | 刷取搜索奖励（Bonus Searches，次数由 `maxBonusSearches` 控制） | `false` |
| `workers.doDailyCheckIn` | 完成每日签到 | `true` |
| `workers.doReadToEarn` | 完成阅读赚取活动 | `true` |
| `workers.doActivateSearchPerk` | 激活搜索倍数特权（Search Perk） | `true` |
| `ensureStreakProtection` | 启用连击保护（账户级配置） | `true` |

</details>

<details>
<summary><b>🔍 Search / 搜索配置</b></summary>

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

> 📌 **注**：示例配置 `config.example.json` 里 `searchDelay` 为 `6-12min`、`readDelay` 为 `6-11min`、`searchResultVisitTime` 为 `20sec`，比 Validator 默认值更保守，适合长时间挂机场景。

</details>

<details>
<summary><b>🌐 queryEngines 查询源说明（含国内可用性）</b></summary>

`searchSettings.queryEngines` 决定从哪些源获取搜索词，按数组顺序尝试。可选值：

| 值 | 来源 | 国内可用性 |
|---|---|---|
| `china` | 中国热搜（gmya.net：百度/头条/抖音/微博/知乎） | ✅ 直连 |
| `local` | 本地查询词（`search-queries.json`，完整词库） | ✅ 离线 |
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
- **本地兜底**：`src/functions/search-queries.json` 提供完整本地查询词库作为补充

</details>

<details>
<summary><b>⚙️ 高级设置（超时 / 代理 / 日志过滤）</b></summary>

| 设置 | 描述 | 默认值 |
|---------|-------------|---------|
| `globalTimeout` | 操作超时持续时间 | `30sec` |
| `proxy.queryEngine` | 代理查询引擎请求（google/wikipedia/reddit 等需翻墙的源；china 源走 gmya.net 国内直连，无需开） | `false` |
| `consoleLogFilter` | 控制台日志过滤（按级别/关键词/正则 白名单或黑名单） | 见下方说明 |
| `webhook.webhookLogFilter` | Webhook 推送日志过滤（结构同 consoleLogFilter） | 见下方说明 |

#### 日志过滤结构（consoleLogFilter / webhookLogFilter）

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

</details>

<details>
<summary><b>🆕 新版 UI 兼容性（Server Action）</b></summary>

V4 全面拥抱新版 dashboard（Next.js App Router）。新版 UI 不再有对外 REST API，奖励上报、领取积分、连击保护等操作统一通过 **Next.js RSC Server Action** 完成，调用方式相同：

| 调用方式 | 认证 |
|---|---|
| `POST /rewards/earn` + `Next-Action` hash + RSC body | Cookie（bing.com/live.com/microsoftonline.com） |

涉及的 Server Action（由 action id 区分）：领取积分（`reportClaimAllPoints`）、奖励上报（`reportActivity`，含 UrlReward/SearchOnBing/ActivateSearchPerk 等）、连击保护 toggle。

**Action ID 动态发现机制**：Server Action 的 `Next-Action` hash 在编译时生成、绑定到具体部署版本。V4 **不再硬编码**任何部署版本号或 hash，而是启动时从 `/rewards/earn` 与 `/dashboard` 的 HTML 中提取初始 JS chunks，并顺着 webpack manifest 抓取动态 chunks，再从这些 chunk 里**实时解析出**当前部署可用的 action id（`reportActivity` / `reportClaimAllPoints` / 连击保护等）。

- ✅ 微软更新部署 → 脚本下次运行时自动从新 chunks 重新解析，**无需等待脚本更新**
- ⚠️ 仅当某次部署彻底改变 chunk 结构 / 剥离了 action 名称时，相关功能才会因解析不到 action id 而跳过（启动日志会明确提示 `未发现 action id`），不影响其他任务

日志里能看到：`奖励构建 | id=xxx`（buildId）、`上下文已就绪 | actions=N | reportable=M`。

</details>

---

## 🔔 通知渠道

本项目支持三种推送渠道（均在 `webhook` 对象下，**可同时开启多个**）：

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

> 💡 **国内推荐**：**PushPlus**（微信推送，无需翻墙）。Discord / ntfy 需要能访问对应服务。

---

## ❓ 常见问题

<details>
<summary><b>报错 <code>Error: browserType.launch: Executable doesn't exist</code> 怎么办？</b></summary>

Chromium 没装上，手动安装：

```bash
npx patchright install chromium
```

</details>

<details>
<summary><b>登录失败 / 卡住 / 每次都要重新登录？</b></summary>

首次运行时请**手动完成网页登录**一次，等待脚本自动接管剩余流程。登录后的 cookie 会保存到 `sessions/` 目录，后续运行会自动复用。

⚠️ `sessions/` 目录**需要多备份**，丢了就要重新登录。

</details>

<details>
<summary><b>Docker 改了配置为什么不生效？</b></summary>

改完 `compose.yaml` 或代码后，必须加 `--build` 重建镜像：

```bash
docker compose up -d --build
```

不加 `--build` 跑的是旧镜像。

</details>

<details>
<summary><b>国内查询词被限流（403）怎么办？</b></summary>

免费档对连续请求有频率限制。解决方法：

到 [gmya.net](https://gmya.net) 申请 appkey，填入 `searchSettings.chinaApi.appkey`（Docker 用 `CONFIG_CHINA_API_APPKEY` 环境变量），即可解除限流。

</details>

<details>
<summary><b>修改 <code>accounts.json</code> / <code>config.json</code> 后怎么生效？</b></summary>

- **Win 环境**：必须运行 `npm run build` 重新构建脚本
- **Docker 环境**：不要手动改容器内的 config 文件（重启会被 entrypoint 覆盖），改 `.env` 或 `compose.yaml` 后用 `docker compose up -d --build` 生效

</details>

<details>
<summary><b>旧版 <code>accounts.json</code> / <code>config.json</code> 能继续用吗？</b></summary>

不能。之前的版本与当前版本**不兼容**，必须重新基于 `accounts.example.json` / `config.example.json` 生成。

- **Win 环境**：复制或重命名 `src/accounts.example.json` 为 `src/accounts.json` 并添加凭据；同样 `src/config.example.json` → `src/config.json`

</details>

---

## ⚠️ 注意事项

- 如果出现无法自动登录情况，请在代码执行登录过程中**手动完成网页的登录**，等待代码自动完成剩下流程。登录信息保存在 `sessions/` 目录（需要多备份），后续运行根据该目录的会话文件来运行。
- **Win 环境**：复制或重命名 `src/accounts.example.json` 为 `src/accounts.json` 并添加您的凭据。
- **Win 环境**：复制或重命名 `src/config.example.json` 为 `src/config.json` 并自定义您的偏好。
- 不要跳过配置这一步。之前的 `accounts.json` 和 `config.json` 版本与当前版本不兼容。
- **Win 环境**：修改 `accounts.json` 或 `config.json` 后，必须运行 `npm run build` 重新构建脚本。
- **Docker 环境**：账号和行为配置通过 `.env` 和 `compose.yaml` 传入，不要手动改容器内的 config 文件（重启会被 entrypoint 覆盖）。改 compose.yaml 后用 `docker compose up -d --build` 生效。

---

## 📜 同步与致谢

本项目 fork 自 [TheNetsky/Microsoft-Rewards-Script](https://github.com/TheNetsky/Microsoft-Rewards-Script)，感谢原作者的付出。

本项目不定时同步原项目代码，主要内容为**本地化处理**：

- 针对国内用户无法访问 Google 等外网的问题，提供中国热搜查询源（百度/头条/抖音/微博/知乎）
- 输出日志的简单中文翻译
- 在原有基础上完善功能

**同步历史**：

- `2026-06-30`：从 upstream/v4（v4.0.1）新建分支，移植国内定制（china 热搜源、PushPlus），全面对齐 V4 架构（ReactFunc + Server Action）

若有侵权请联系删除。

**本项目所有改动基于 Win11 系统和委托他人 Docker 环境测试。其他系统未测试，请根据原项目相关配置设置。**

| 项目 | 信息 |
|---|---|
| 上游仓库 | [TheNetsky/Microsoft-Rewards-Script](https://github.com/TheNetsky/Microsoft-Rewards-Script) |
| 上游基础分支 | `v4`（v4.0.1） |
| 当前版本 | 4.0.1 |
| 最后同步原项目 | 2026-06-30 |
| License | GPL-3.0-or-later |

---

## ⚠️ 免责声明

**风险自负！** 使用自动化脚本时，您的 Microsoft Rewards 账户可能会被暂停或禁止。

此脚本仅供教育目的。作者对 Microsoft 采取的任何账户操作不承担责任。
