---
name: rewards-server-actions
description: 抓取并更新微软 Rewards 新版 dashboard 的 Next.js Server Action hash（连击保护 toggleStreakProtection、领取奖励积分 claimBonusPoints）。当用户要更新连击保护、更新领取 dashboard 奖励积分、提到 Server Action hash 失效/过期、领取积分功能挂了、领积分 400/失败、或想重新抓 hash 时触发。开发维护微软 Rewards 脚本的 Server Action 适配时使用。
---

# Rewards Server Actions:抓取并更新 hash

新版微软 Rewards dashboard（modern UI）基于 Next.js App Router,业务操作走 Server Action:
`POST https://rewards.bing.com/dashboard`,请求头 `next-action: <hash>` 标识具体动作。

hash 在 Next.js 编译时生成,微软重新部署后**可能**变化。本 skill 引导你重新抓取 hash 并写回代码。

涉及两个 Server Action:
- `toggleStreakProtection` — 连击保护开关,body `[true]` 开 / `[false]` 关
- `claimBonusPoints` — 领取奖励积分,body `[]`

## 工作流

### 第一步:读取当前代码状态

读 `src/browser/BrowserFunc.ts` 开头的两个常量,**作为对照基准**(执行时再读,不要凭记忆):
- `SUPPORTED_DEPLOYMENT_ID` — hash 抓录时的部署版本(参考值)
- `SERVER_ACTION_HASHES.toggleStreakProtection` 和 `.claimBonusPoints` — 当前内置 hash

### 第二步:抓取新 hash

用 agent-browser 连接浏览器,在真实 dashboard 上触发动作,从 `POST /dashboard` 请求头里提取 `next-action`。详细步骤和踩坑提示见 `references/capture-walkthrough.md`,**执行抓包前先读它**。

抓包要点:
1. 用独立 session(如 `--session msr`)启动 agent-browser,登录到 `rewards.bing.com/dashboard`
2. 触发动作前先 `network requests --clear` + `network har start`
3. 触发动作 → 抓 `POST /dashboard` 请求 → 解析其 `next-action` 头和 `x-deployment-id` 头
4. 用 HAR 文件解析提取(不要靠目测),HAR 路径由 `network har stop <path>` 指定

### 第三步:对比并判断改不改

把抓到的 hash、`x-deployment-id` 和代码里的对照:

| 情况 | 处理 |
|------|------|
| hash 不变,只有 deployment-id 变 | **hash 不用改**;`SUPPORTED_DEPLOYMENT_ID` 可更新为参考(方案 A 后非必需,但保持准确更好) |
| hash 变了 | 更新 `SERVER_ACTION_HASHES` 对应键 |
| 完全抓不到请求 | 不是 hash 问题。常见是 cookie/session 过期、页面改版、网络问题,按 `references/capture-walkthrough.md` 的排障节排查 |

**关键判断:hash 没变就不要改 hash**。hash 是 Next.js 函数级标识,函数没改它就不变;微软多数重新部署只是重打包,hash 往往不变。盲目改对的 hash 反而会改坏。

### 第四步:更新代码并验证

改 `src/browser/BrowserFunc.ts` 对应常量后:
1. `npm run build` 编译,必须无错误
2. 确认 `dist/browser/BrowserFunc.js` 里新值已写入
3. 告知用户改了什么、为何改(或为何不改),附上抓包对照表

## 重要约束

- **代码是单一来源**:session 路径、常量行号、当前 hash 值等**都从代码现读**,不写进 skill。skill 只承载方法论。
- **幂等安全**:两个 Server Action 都幂等(`toggleStreakProtection` 已开启再调无害,`claimBonusPoints` 无积分时返回成功但不加分),抓包时反复触发不会损害账号。
- **方案 A 已落地**:`SUPPORTED_DEPLOYMENT_ID` 不匹配不再拦截调用(只记 warning),所以"部署版本不匹配"这条日志**本身不是故障**——只有 Server Action 真返回非 2xx 才需重新抓 hash。
- 遵循 `AGENTS.md`:中文输出,改代码前确认方案,代码改完更新相关文档/注释。
