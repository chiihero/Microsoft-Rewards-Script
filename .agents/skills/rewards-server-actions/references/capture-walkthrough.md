# 抓包实战步骤与踩坑提示

本文记录用 agent-browser 抓取微软 Rewards Server Action hash 的可靠流程。
**UI 会变,下面是方法论不是死脚本**——遇到和描述不符时,用 snapshot/eval 临场判断。

## 环境准备

- agent-browser 已安装(`agent-browser --version` 能返回即正常)
- 一个**已登录**的浏览器 session,或愿意在抓包过程中登录

## 启动 session

```bash
agent-browser --session msr --headed open "https://example.com"
```

⚠️ **Windows 已知坑**:`open` 命令在 Windows 上**经常阻塞不返回**,但浏览器其实已启动成功。
**验证办法**:不依赖 `open` 的退出,改用轻量命令探活:
```bash
agent-browser --session msr get url   # 能返回 URL = daemon 正常,浏览器已开
```
如果 `open` 卡住超过 ~30 秒,Ctrl+C 中断它,然后用 `get url` 确认浏览器在跑,后续命令照常工作。
**不要**反复重试 `open`,会堆积残留 chrome 进程。卡住时先 `agent-browser close --all` 清理。

## 登录

直接 navigate 到 dashboard,看是否被重定向到 welcome 页:
```bash
agent-browser --session msr navigate "https://rewards.bing.com/dashboard"
agent-browser --session msr get url
```

- URL 是 `.../dashboard` 且标题含"首页" → 已登录,跳到下一步
- URL 含 `/welcome` 或 `/login` → 未登录,需 `snapshot -i` 找登录入口手动/点击登录
  - 登录入口通常是页面里的"登录"链接,`snapshot -i` 找 `[link] "登录"` 的 ref 点击
  - 某些情况下连点登录链接会跳到服务条款页,这是选错了 ref,重新 navigate dashboard 多走一次重定向链可能直接进

确认已登录的可靠标志:`snapshot -i` 能看到"金牌/银牌会员"、用户名、可用积分数。

## 触发 claimBonusPoints(领取奖励积分)

1. 清空并开启抓包:
   ```bash
   agent-browser --session msr network requests --clear
   agent-browser --session msr network har start
   ```
2. `snapshot -i` 找"可领取 N 领取"按钮(通常是类似 `button "可领取 可领取 3 领取"`),点它
   - ⚠️ 这会**弹出对话框**,不是直接发请求
3. 对话框里有真正的"领取积分"按钮(快照里是 `button "领取积分"`),点**这个**才会触发 Server Action
4. 查请求:
   ```bash
   agent-browser --session msr network requests
   ```
   找 `POST https://rewards.bing.com/dashboard (Fetch)`。
5. 停止 HAR 保存,解析提取:
   ```bash
   agent-browser --session msr network har stop ./claim.har
   ```
   解析脚本(把 HAR 读出来提取请求头):
   ```js
   const fs = require('fs')
   const har = JSON.parse(fs.readFileSync('./claim.har', 'utf-8'))
   const entries = har.log.entries.filter(e =>
     e.request.method === 'POST' &&
     e.request.url.includes('rewards.bing.com/dashboard') &&
     !e.request.url.includes('?')
   )
   entries.forEach((e, i) => {
     const h = {}; e.request.headers.forEach(x => h[x.name.toLowerCase()] = x.value)
     console.log(`请求${i+1}: next-action=${h['next-action']} | x-deployment-id=${h['x-deployment-id']} | postData=${e.request.postData?.text} | 状态=${e.response.status}`)
   })
   ```
   - `postData` 应为 `[]`(无参数)
   - 状态码 2xx = 成功
   - 积分余额变化是成功的旁证(记下抓包前后余额)

## 触发 toggleStreakProtection(连击保护)

连签保护开关**不在首页直接可见**,藏在"每日连签"展开面板里:

1. `snapshot -i` 找"每日连签"按钮(类似 `button "每日连签 每日连签 N 天"`),点击展开
2. 展开后快照里找 `switch "连签保护"`(role=switch,有 checked 状态)
3. 点它切换状态触发 Server Action;**点两次**切回原状(保持账号设置不变),两次都会发请求
4. 按上面的方式停 HAR、解析:
   - 两次 `POST /dashboard` 的 `postData` 分别是 `[false]` 和 `[true]`(顺序取决于初始状态)
   - `next-action` 两次**相同**(同一个 toggle 动作)
   - 状态码都应 2xx

⚠️ 如果展开面板后 `snapshot -i` 没看到 switch,用 eval 全局搜:
```bash
cat <<'EOF' | agent-browser --session msr eval --stdin
JSON.stringify({
  hasProtect: document.body.innerText.includes('保护') || document.body.innerText.toLowerCase().includes('protect'),
  switches: Array.from(document.querySelectorAll('[role=switch]')).map(e=>({checked:e.checked, aria:e.getAttribute('aria-label')}))
})
EOF
```

## 抓不到请求时的排查

按可能性排序:

1. **cookie/session 过期** — `get url` 看是否被踢到登录页。重新登录或换 session。
2. **点错了按钮** — 有些"领取"是外链不是 Server Action。看请求列表有没有 `POST /dashboard`,没有就是没触发对。重新 snapshot 找真正按钮。
3. **请求被过滤了** — `network requests` 默认可能有显示上限。优先靠解析 HAR 文件,HAR 是完整记录。
4. **agent-browser 残留** — 多次卡住会留 chrome 进程。`agent-browser close --all` 后,必要时任务管理器清 chrome 进程,再重开 session。
5. **页面改版** — 按钮文案/结构变了。snapshot 看 DOM,eval 搜关键词,临场定位。

## 清理

抓完关闭 session,删除临时 HAR 文件(不要把 HAR 提交进 git,含敏感 cookie):
```bash
agent-browser --session msr close
rm -f ./claim.har ./streak.har
```
