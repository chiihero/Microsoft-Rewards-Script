# 微软奖励脚本
自动化的微软奖励脚本，这次使用 TypeScript、Cheerio 和 Playwright 编写。

正在开发中，主要供个人使用！
该项目来源于https://github.com/TheNetsky/Microsoft-Rewards-Script，的基础上进行本地化处理
## 如何设置 ##
1. 下载或克隆源代码
2. 运行 `npm i` 安装依赖包（若Error: browserType.launch: Executable doesn't exist报错执行pnpm exec playwright install）
3. 将 `accounts.example.json` 重命名为 `accounts.json`，并添加你的账户信息
4. 按照你的喜好修改 `config.json` 文件
5. 运行 `npm run build` 构建脚本
6. 运行 `npm run start` 启动构建好的脚本

## 注意事项 ##
- 如果你在未先关闭浏览器窗口的情况下结束脚本（仅在 `headless` 为 `false` 时），会有 Chrome 进程继续占用资源。你可以使用任务管理器关闭这些进程，或者使用附带的 `npm run kill-chrome-win` 脚本（Windows 系统）。
- 如果你要自动化运行此脚本，请设置每天至少运行 2 次，以确保完成所有任务。将 `"runOnZeroPoints": false`，这样在没有可赚取积分时脚本不会运行。


### **设置源文件**

1. **下载源代码**

2. **更新 `accounts.json` 文件**

3. **编辑 `config.json` 文件**，确保设置以下值（其他设置可根据你的喜好调整）：

```json
"headless": true,
"clusters": 1,
```

## 配置 ## 
| 设置        | 描述           | 默认值  |
| :------------- |:-------------| :-----|
|  baseURL    | 微软奖励页面 | `https://rewards.bing.com` |
|  sessionPath    | 会话/指纹存储路径 | `sessions` （在 `./browser/sessions` 目录下） |
|  headless    | 浏览器窗口是否可见，是否在后台运行 | `false` （浏览器可见） |
|  parallel    | 是否并行运行移动设备和桌面端任务 | `true` |
|  runOnZeroPoints    | 当可赚取积分为 0 时是否继续运行脚本 | `false` （积分为 0 时不运行） |
|  clusters    | 启动时运行的实例数量，每个账户一个实例 | `1` （一次运行一个账户） |
|  saveFingerprint.mobile    | 每次是否重复使用相同的指纹 | `false` （每次生成新的指纹） |
|  saveFingerprint.desktop    | 每次是否重复使用相同的指纹 | `false` （每次生成新的指纹） |
|  workers.doDailySet    | 是否完成每日任务集 | `true`  |
|  workers.doMorePromotions    | 是否完成促销任务 | `true`  |
|  workers.doPunchCards    | 是否完成打卡任务 | `true`  |
|  workers.doDesktopSearch    | 是否完成每日桌面搜索任务 | `true`  |
|  workers.doMobileSearch    | 是否完成每日移动设备搜索任务 | `true`  |
|  workers.doDailyCheckIn    | 是否完成每日签到任务 | `true`  |
|  workers.doReadToEarn    | 是否完成阅读赚取积分任务 | `true`  |
|  searchOnBingLocalQueries    | 是否使用 `queries.json` 文件或从本仓库获取的查询来完成“在 Bing 上搜索”任务 | `false` （从本仓库获取）   |
|  globalTimeout    | 操作超时时间 | `30s`   |
|  searchSettings.useGeoLocaleQueries    | 是否根据你的地理位置生成搜索查询 | `false` （使用美国英语生成的查询）  |
|  searchSettings.scrollRandomResults    | 是否在搜索结果中随机滚动 | `true`   |
|  searchSettings.clickRandomResults    | 是否访问搜索结果中的随机网站 | `true`   |
|  searchSettings.searchDelay    | 搜索查询之间的最小和最大时间间隔（毫秒） | `min: 3min`    `max: 5min` |
|  searchSettings.retryMobileSearchAmount     | 移动设备搜索失败后的重试次数 | `2` |
|  logExcludeFunc | 从日志和 Webhook 中排除的函数 | `SEARCH-CLOSE-TABS` |
|  webhookLogExcludeFunc | 从 Webhook 日志中排除的函数 | `SEARCH-CLOSE-TABS` |
|  proxy.proxyGoogleTrends     | 是否通过设置的代理转发 Google 趋势请求 | `true` （将通过代理） |
|  proxy.proxyBingTerms     | 是否通过设置的代理转发 Bing 搜索词请求 | `true` （将通过代理） |
|  webhook.enabled     | 是否启用你设置的 Webhook | `false` |
|  webhook.url     | 你的 Discord Webhook URL | `null` |

## 功能 ##
- [x] 多账户支持
- [x] 会话存储
- [x] 双因素认证支持
- [x] 无密码登录支持
- [x] 无头模式支持
- [x] Discord Webhook 支持
- [x] 桌面搜索
- [x] 可配置任务
- [x] 微软 Edge 搜索
- [x] 移动设备搜索
- [x] 模拟滚动支持
- [x] 模拟链接点击支持
- [x] 地理位置搜索查询
- [x] 完成每日任务集
- [x] 完成更多促销任务
- [x] 解决 10 积分的测验
- [x] 解决 30 - 40 积分的测验
- [x] 完成点击奖励任务
- [x] 完成投票任务
- [x] 完成打卡任务
- [x] 解决随机的“这个还是那个”测验
- [x] 解决 ABC 测验
- [x] 完成每日签到
- [x] 完成阅读赚取积分任务
- [x] 集群支持
- [x] 代理支持
- [x] Docker 支持（实验性）
- [x] 自动调度（通过 Docker）

## 免责声明 ##
使用此脚本可能会导致你的账户被封禁或暂停，请注意！
<br /> 
请自行承担使用此脚本的风险！

        