# V4-china 问题跟踪

> 建立时间：2026-11-19
> 跟踪范围：GitHub issue / PR、123.4 生产部署、v5 同步
> 工作方式：**一次只推进一项**，当前项确认完成后再进入下一项。

## 状态说明

| 状态 | 含义 |
|---|---|
| 待确认 | 方案已给出，等待确认 |
| 进行中 | 已确认，正在改代码/配置 |
| 待验证 | 已改完，等待线上或测试验证 |
| 待上线 | 已通过实测验证，等待部署/发布 |
| 已完成 | 已验证通过 |
| 暂缓 | 暂不处理，保留结论 |

## 队列

| 序号 | 事项 | 类型 | 优先级 | 状态 |
|---|---|---|---|---|
| 01 | 生产签到每天被误跳过（#69 + 123.4 部署） | Bug / 生产 | P0 | **已完成**（v4.3.4） |
| 02 | 生产构建与版本错位（4.3.2.4 标签跑 4.3.3 代码） | 构建 / 运维 | P1 | **进行中** |
| 03 | 123.4 宿主机未校时（慢约 5 分钟） | 运维 | P1 | 排队 |
| 04 | #68 flyout 重试 + measure 容错 | PR | P1 | 排队 |
| 05 | #76 ServerChan 配置与域名 | PR | P2 | 排队 |
| 06 | #77 FIDO/Passkey 登录 | PR | P2 | 排队 |
| 07 | #78 阅读与桌面搜索并行 | PR / 性能 | P3 | 排队 |
| 08 | #75 阅读期间释放浏览器 | PR / 性能 | P3 | 暂缓 |
| 09 | #79 国区 reportActivity 缺失 | Issue | P1（社区） | 排队，等日志 |
| 10 | v5 同步与国内适配策略 | 分支 / 规划 | P3 | 排队 |

---

## 01 生产签到每天被误跳过

### 现象

123.4 生产日志从 11/14 起，每天出现：

```
[DAILY-CHECK-IN] 今日已签到，跳过重复请求 | updatedAt=... | currentBalance=...
```

但 11/13–11/19 的日志里 **“开始每日签到”出现 0 次**，即从未真正提交过签到。

### 证据

账号：`8538***@qq.com`，geo=CN，locale=zh-CN。

| 日期 | 跳过时间 | updatedAt | 当日收益 | 积分构成 | 签到贡献 |
|---|---|---|---|---|---|
| 11/17 | 08:55:12 | 09:01:28+08 | 157 | 每日任务 30 + 更多推广 40 + 阅读 30 + 搜索 57 | **0** |
| 11/18 | 08:52:04 | 08:58:24+08 | 117 | 每日任务 30 + 阅读 30 + 搜索 57 | **0** |
| 11/19 | 08:30:16 | 08:36:40+08 | 113 | 每日任务 30 + 更多推广 5 + 阅读 21 + 搜索 57 | **0** |

每天快照：

```
已解析 streaks | bing:3/7, dailyset:3/7, edge:5/7, bingapp:0/7
```

`bingapp`（App 签到连胜）连续多天都是 **0/7**。如果签到成功过，至少应为 1/7。

### 根因

`src/functions/activities/app/CheckInState.ts` 的 `resolveCheckInState` 把：

- `Gamification_Streak_Counter_Promotion.attributes.last_updated == 今天`
- 或 `Gamification_Sapphire_DailyCheckIn.attributes.last_updated == 今天`

直接判为 `complete`。

日志里的 `updatedAt` 比日志时间晚约 6 分钟，而宿主机时钟慢约 5 分钟，说明该字段很可能是“服务器当前时间/刷新时间”，并不是真实签到时间。`bingapp:0/7` 进一步证明签到没有发生。

**PR #69 的不足**：它只去掉了“连胜计数器”这个来源，仍然信任签到推广自身的 `last_updated`。如果该字段同样每天被刷新，合了 #69 仍会跳过。

### 深入分析（11/19 补充）

这条链路其实混了两个不同的活动：

| 活动 | 请求 | 状态载体 |
|---|---|---|
| Web 签到 | `POST /dapi/me/activities`，`type: 101` + `attributes.offerid=Gamification_Sapphire_DailyCheckIn` | `Gamification_Sapphire_DailyCheckIn` 推广的 `complete` / `progress` / `day_X_points` |
| Bing App 连签 | `POST /dapi/me/activities`，`type: 103`，无 offerid，`channel` 为 App 通道 | `Gamification_Streak_Counter_Promotion` / 页面 `bingapp` 连胜 |

V4 的 `DailyCheckIn` 提交的是 **type 103（App 连签）**，但前置判断读的是 **Web 签到推广** 和通用连胜计数器。用 A 活动的 `last_updated` 决定 B 活动是否执行，这个前提本身就不成立。

另外，提交响应当中其实带有更可靠的字段：

```json
{
  "response": {
    "balance": 15614,
    "activity": { "p": 5, "type": 103 },
    "isDuplicate": false
  }
}
```

- `activity.p`：本次活动实际获得的积分；
- `isDuplicate`：今天是否已经做过；
- 现有代码只声明了 `{ code, response.balance }`，把这两个字段丢掉了，只能靠余额差和 `last_updated` 猜。

同类实现可参考 `src/functions/activities/experimental/EdgeBrowsing.ts`，它已经解析了 `response.activity` 和 `response.isDuplicate`。

### 影响

- 每天损失一次签到积分（当前连胜为 0，按 day 1 约 5 分/天）。
- App 签到连胜永远起不来，第 7 天的奖励也拿不到。
- 至少从 11/03 部署该镜像起就存在，日志可见的 5 天已连续丢失。

### 方案（推荐，分两步）

**第一步：去掉错误的前置判断，补上响应解析（本次改）**

1. `resolveCheckInState` 删除 `[streak, checkIn]` 的 `last_updated` 循环；`complete` 只认 `checkIn.attributes.complete?.toLowerCase() === 'true'`。
2. `complete` 为 false 或缺失时，按 `progress` + `day_X_points` 计算 `remaining`，返回 `pending`。
3. `DailyCheckIn` 只在 `complete` 时跳过；否则提交 type 103。
4. `submitDaily` 的返回类型补上 `response.activity.p` 和 `response.isDuplicate`，日志输出这两个字段。
5. 判定顺序：`activity.p > 0` → 成功；`isDuplicate === true` → 今日已做，记 info 不报错；否则回读 `complete`，仍为 false 才报错。
6. 不在这一步改通道，避免同时动两个变量。

**第二步：看第一次线上结果再决定是否调通道**

> 已由 11/19 实测结论取代：`type:103` + `channel:SAIOS` + `X-Rewards-PartnerId:startapp` 在国区账号上正常加分（`activity.p=5`），**不需要改通道**。以下仅作存档。

- `activity.p > 0` 且 `bingapp` 变 `1/7` → 完成。
- `isDuplicate=false` 且 `p=0` → 再试 `SAAndroid`。
- `isDuplicate=true` → 今天已被其他端签过，无需再改。
- 如果 Web 签到本身也有独立积分 → 再补 `type:101 + offerid` 的 claim，作为独立活动处理。

### 测试用例

- 连胜计数器 `last_updated` 是今天、签到推广 `complete=false` → 必须提交。
- 签到推广 `complete=True` → 跳过。
- 签到推广 `complete` 缺失、`last_updated` 是今天 → 必须提交。
- 提交返回 `activity.p=5`、余额不变 → 按 5 分记账。
- 提交返回 `isDuplicate=true` → 不报错、不记账。
- 提交返回 `p=0`、`isDuplicate=false`、`complete` 仍为 false → 报错，不误判成功。

### 验证方式

- 本地已用真实账号验证通过（见下节），剩余为部署验证。
- 构建 v4.3.4，同步到 123.4 并重建镜像（与跟踪项 02 一起处理）。
- 次日检查：
  - 日志出现 `[DAILY-CHECK-IN] 开始每日签到`；
  - `activity.p` 为当日签到积分（day 1–6 约 5 分，day 7 约 20 分）；
  - `bingapp` 从 `1/7` 变为 `2/7`；
  - 不再出现“今日已签到”的误跳过。

### 已实施（2026-11-19，第一步）

改动文件：

| 文件 | 改动 |
|---|---|
| `src/functions/activities/app/CheckInState.ts` | 删除 `[streak, checkIn].last_updated` 判完成逻辑；`complete` 只认 `attributes.complete` 大小写不敏感的 `true`；其余情况按 `progress` + `day_X_points` 返回 `pending`/`unknown`；`last_updated` 只写进 `reason` 供对账 |
| `src/functions/activities/app/DailyCheckIn.ts` | 提交响应补 `activity.p` / `activity.type` / `isDuplicate`；判定顺序改为 `activity.p>0` → 余额变化 → `isDuplicate` → 回读 `complete`；跳过日志改为“签到推广已标记完成” |
| `scripts/api/checkInState.test.cjs` | 旧断言“今日时间戳=已签到”全部改为“必须提交”；新增 `complete` 大小写、`activity.p` 记账、`isDuplicate`、`p=0` 未确认等用例 |

关键行为变化：

- 签到推广没有 `complete=True` 时**每天都会提交一次**（接口幂等，最多返回 0 分或 `isDuplicate`）。
- 提交返回 `activity.p=5` 但余额未刷新时，按 5 分记账（以前会误报“签到未确认到账”）。
- `isDuplicate=true` 视为“今天已在其他端签过”，不再抛错。
- 仍未改动提交通道（`type:103` / `channel:SAIOS`），留给第二步。

验证结果：

- `node --test scripts/api/checkInState.test.cjs` → 35/35 通过
- `checkInFlow` 14/14、`searchCounterState` 17/17、`workerGaps` 119/119 通过
- `npx tsc --noEmit`、`npx eslint`（三个改动文件）、`npm run build` 均通过
- `logParser.test.js` 8 个失败为改动前既有问题，与本次无关（已用 stash 对比确认）

### 线上实测（2026-11-19 19:00，123.4 容器内隔离副本）

做法：把生产 `sessions/sessions.db`、`.env`、`config.json` 复制到容器内 `/tmp/live-test`，只开 `doDailyCheckIn`，用新构建的 `dist` 跑真实请求；跑完已删除临时目录（含 `.env`）与本地副本。运行日志留存在本地 `.workbuddy/tmp/logs/live-checkin-{1,2}.log`（未入库）。

第一次运行（今天尚未签到）：

```
[DAILY-CHECK-IN] 开始每日签到 | currentBalance=15617 | state=unknown | reason=旧签到推广不可作为今日可领取额度
[DAILY-CHECK-IN] 已收到响应 | status=200 | activity.p=5 | activity.type=103 | isDuplicate=false | responseBalance=15622
[DAILY-CHECK-IN] 每日签到完成 | type=103 | pointsGained=5 | currentBalance=15622
[ACCOUNT-END] 获得积分=5 | 原余额=15617 | 现余额=15622
```

连胜快照同一次运行内从 `bingapp:0/7` → `bingapp:1/7`。

**结论：修复有效，当天补签成功，+5 分，连胜起算。**

第二次运行（同日重跑）：

```
activity.p=0 | isDuplicate=false | responseBalance=15622 | state=unknown
每日签到出错 | 签到未确认到账
```

暴露两个事实：

1. 国区账号的 `Gamification_Sapphire_DailyCheckIn` 本身是 `hidden=True` 的旧推广，**没有 `complete` 字段**，所以 `resolveCheckInState` 对它永远返回 `unknown`（这也解释了为什么以前只能靠 `last_updated` 误判）。
2. type 103 重复提交时，接口返回 `p=0` 且 `isDuplicate=false`，**无法从响应区分“已签过”和“失败”**。

因此：首次运行判断准确；同一天重跑会误报一次“签到未确认到账”（不影响积分，只影响当次运行的成功标记和通知）。

### 发布与部署（2026-11-20）

- `V4-china` 已推送到 origin（当前 `ddcc16b`），标签 `v4.3.4` → `6221c18` 已推送。
- GitHub Release 已发布：`v4.3.4`，说明中记录了根因、实测数据和已知限制。
- **已部署到 123.4**（00:53）：源码以 `git archive V4-china` 覆盖部署目录的 `src/` 与 `scripts/`，保留 `config/`、`sessions/`、`.env`、`compose.yaml`。
  - 新镜像 tag：`microsoft-rewards-script:china-4.3.4`；旧镜像保留为 `china-20261103` 可回滚
  - 部署目录备份：`/data/1panel/docker/compose/microsoft-rewards-script.bak-20261120`
  - 启动日志确认：`启动微软奖励脚本 | v4.3.4 | 账户数: 1`，会话恢复 83 个 Cookie
- `compose.yaml` 的 `RUN_ON_START` 已改为 `false`：容器重启不再立即跑，只在 `CRON_SCHEDULE`（08:00 / 20:00）执行。
- 部署时启动的立即运行已完成 11/20 的每日任务（+30），在任务间隔被手动终止，未做签到；签到留给 08:00 那次。

### 剩余（可选）

1. “同日已签”本地标记（`logs/checkin-state.json`，按邮箱记日期，仅在 `activity.p>0` 后写入），用于消除同日重跑的误报；不加也可接受，生产每天只跑一次。
2. 部署后次日验证：日志出现 `开始每日签到`，`activity.p=5`，`bingapp` 从 `1/7` 变 `2/7`。

---

## 02 生产构建与版本错位

### 现象

1. 生产日志每次启动都打印 `启动微软奖励脚本 | v4.3.2.4`，但 `dist` 里是 #62 之后的代码（4.3.3 逻辑）。版本号只代表“最后一次 bump”，不代表代码。
2. `compose.yaml` 镜像写死 `microsoft-rewards-script:china`，每次 `--build` 覆盖同一 tag，无法区分新旧、无法回滚。
3. 部署目录 `/data/1panel/docker/compose/microsoft-rewards-script` 是 11/03 00:37 的文件快照，不是 git 仓库，无法 `git pull`、无法 diff、无法定位提交。
4. 本地标签 `v5.0.0` 指向 `b78f616`，远程是 `46a6fda`。

### 网络约束

服务器到 `github.com` 8 秒超时（curl 返回 000），到 `ghcr.io` 返回 401（可达）。因此服务器不能 `git pull`，只能「本地打包 + 服务器构建」或「拉 GHCR 镜像」。

### 已完成（2026-11-19）

- 本地 `v5.0.0` 标签已与远程对齐到 `46a6fda`。
- `package.json` / `package-lock.json` 从 4.3.3 → **4.3.4**（提交 `6221c18`）。
- 已打标签 `v4.3.4` → `6221c18`，并随分支一起推送到 origin（2026-11-20）。
- **构建信息部分不再在 V4 上做**：V4 进入维护模式，`build-info.json` / `ARG BUILD_COMMIT` 直接在 `v5-china` 落地。

### 待做

1. 构建信息：`copyAssets.js` 生成 `dist/build-info.json`（version / commit / builtAt），启动日志打印 `v4.3.4+<sha>`。
2. `Dockerfile` 增加 `ARG BUILD_COMMIT`，`compose.yaml` 的 image 改为 `microsoft-rewards-script:${IMAGE_TAG:-china}`。
3. 部署脚本：本地打包（排除 `node_modules/dist/config/sessions/.env/logs`）→ 传服务器 → 带 `BUILD_COMMIT`/`IMAGE_TAG` 构建 → 回读版本校验。

### 验证方式

- 部署后 `[RUN-START]` 显示 `v4.3.4+<sha>`，与 `git rev-parse --short HEAD` 一致。
- `docker images` 中存在 `microsoft-rewards-script:china-4.3.4`，旧的 `:china` 仍保留可回滚。

---

## 附录 A：123.4 部署现状

| 项目 | 实际情况 |
|---|---|
| 容器 | `microsoft-rewards-script` / 镜像 `microsoft-rewards-script:china` |
| 镜像构建 | 2026-11-02 16:53 UTC（= 11/03 00:53 CST） |
| 部署目录 | `/data/1panel/docker/compose/microsoft-rewards-script` |
| 源码状态 | **不是 git 仓库**，是 11/03 00:37 拷贝的快照，无法 `git pull` |
| 版本号 | `package.json` = 4.3.2.4，但 `dist` 已含 #62 的签到逻辑 |
| 原因 | 镜像构建落在 #62 合并（00:31）之后、v4.3.3 版本号提交（01:50）之前 |
| 日志目录 | 容器内 `/usr/src/microsoft-rewards-script/logs/` |
| 本地副本 | `.workbuddy/tmp/logs/`（临时，可删） |
| 时钟 | `System clock synchronized: no`，NTP 服务未启用，慢约 5 分钟 |

## 附录 B：关键日志位置

- 11/19 签到跳过：`logs/2026-11-19.log` 第 396 行
- 11/19 每日任务：第 353–381 行
- 11/19 阅读：第 398–434 行
- 11/19 搜索汇总：第 893 行附近
- 11/15 早间 503 失败：`logs/2026-11-15.log` 第 25–154 行
