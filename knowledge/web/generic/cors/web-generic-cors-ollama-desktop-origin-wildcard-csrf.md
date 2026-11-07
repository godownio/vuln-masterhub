---
id: web-generic-cors-ollama-desktop-origin-wildcard-csrf
title: Ollama OLLAMA_ORIGINS 桌面协议通配符：受信来源页面跨域调用本地 API
type: scenario
domain: web
path: web/generic/cors
technique: ollama-origins-desktop-wildcard
aliases:
- Ollama CORS 绕过
- OLLAMA_ORIGINS 通配符
- Ollama CSRF
- file:// 跨域调用 Ollama
- 桌面协议 Origin 通配
- 本地推理 API 跨域
tags:
- ollama
- cors
- csrf
- origin
- desktop-protocol
- file-protocol
- electron
- tauri
- vscode-webview
- ai-infrastructure
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V104
  verified_at: '2026-11-05T22:24:55+08:00'
  notes: 已对照原文与9张内嵌图核对：启动日志截图显示 OLLAMA_ORIGINS 含 app://*、file://*、tauri://*、vscode-webview://*、vscode-file://* 等协议通配符，原文用本地 HTML 在 Chrome fetch http://127.0.0.1:11434/api/tags 成功并渲染 JSON，与卡片一致。未验证点：仅实测读取 /api/tags，delete/pull/create 等写操作与响应外带未验证；file:// 页面实际 Origin 可能为 null，具体匹配逻辑依赖浏览器/客户端，卡片已标 confidence=medium 并在 PoC 中注明；frontmatter 无 sources/source_url；PoC 未本机复跑。
---

## 一句话结论

Ollama 默认的 `OLLAMA_ORIGINS` 把 `file://*`、`app://*`、`tauri://*`、`vscode-webview://*`、`vscode-file://*` 等桌面协议整体加入允许来源，且使用“协议通配符”而非精确域名白名单；因此从这些允许来源加载的页面（本地 HTML、Electron/Tauri 应用、VS Code Webview 等）可以跨域读取 Ollama API 响应，匿名调用 `/api/tags`、`/api/generate`、`/api/delete` 等端点。若攻击者能诱导管理员打开恶意本地页面或安装恶意桌面应用，就可在其机器上操作 Ollama。

## 原理

- 浏览器跨域请求是否允许读取响应由 CORS 决定。Ollama 使用 `OLLAMA_ORIGINS` 配置允许来源，默认值包含 localhost/127.0.0.1/0.0.0.0 的各端口变体，以及 `app://*`、`file://*`、`tauri://*`、`vscode-webview://*`、`vscode-file://*` 等桌面协议通配符。
- 这些通配符是为本地桌面客户端（Ollama Desktop、VS Code 插件、Tauri 应用）通信设计的，但它们只按协议前缀匹配，不是“只允许自己家的客户端”。任何以这些协议加载的页面都能获得跨域许可。
- 攻击者可以把恶意 HTML 保存为本地文件（`file://`）诱导管理员双击打开，或投递/诱导安装一个使用 `file://`/`app://`/`tauri://` WebView 的恶意桌面应用/插件；页面内的 JavaScript 即可 `fetch("http://127.0.0.1:11434/api/tags")` 并读取 JSON 响应。
- 由于 Ollama API 本身无认证，CORS 是浏览器侧唯一的跨域限制；一旦 Origin 被允许，页面就能读取模型列表/运行状态、调用推理、复制/删除/创建模型，等价于获得了本地 Ollama 的操作权限。
- 这与 DNS rebinding/CSRF 同属“浏览器作为跳板访问本地服务”的模式：攻击者不需要直接访问 11434，只需要让受害者浏览器从允许的 Origin 发起请求。

## 触发条件

- Ollama 在本机运行并监听 127.0.0.1:11434（或可达地址），`OLLAMA_ORIGINS` 保持默认或包含 `file://*`/`app://*`/`tauri://*`/`vscode-webview://*` 等通配符。
- 受害者被诱导打开本地恶意 HTML，或安装/运行使用这些协议加载不可信内容的桌面应用、插件、Webview。
- 浏览器/WebView 允许该 Origin 发起跨域请求（默认 CORS 配置下，Ollama 会返回允许头）。
- 目标 API 无额外认证（Ollama 默认无认证）。

## 利用步骤

1. 在受害者机器上确认 Ollama 可达（本地 127.0.0.1:11434 或内网地址），并读取 `OLLAMA_ORIGINS` 配置（启动日志或本地配置文件）。
2. 构造一个 HTML 页面，从允许的 Origin（如保存为本地 `.html` 用浏览器打开）发起 `fetch` 到 Ollama API，读取 `/api/tags`、`/api/ps` 或调用 `/api/generate`。
3. 将页面投递给管理员（伪装成报告、配置说明、快捷方式、恶意桌面应用/插件），诱导其打开。
4. 页面脚本读取响应并外带（如图片 URL、fetch 到攻击者服务器），或直接执行模型复制/删除等操作。
5. 授权测试中使用本地靶机与无害页面，只读取 `/api/tags` 验证 CORS 是否放行，不删除模型、不调用高成本推理。
6. 若浏览器/WebView 对 `file://` Origin 处理不同（如发送 `Origin: null`），需按实际客户端测试；不同 Ollama 版本/桌面客户端的匹配逻辑可能不同。

## PoC

```html
<html><body>
<script>
fetch('http://127.0.0.1:11434/api/tags')
  .then(r => r.json())
  .then(d => {
    document.body.innerHTML = '<pre>' + JSON.stringify(d, null, 2) + '</pre>';
    // 授权测试到此为止；真实攻击可继续把 d 外带
  })
  .catch(e => document.body.innerText = 'blocked: ' + e);
</script>
</body></html>
```

原文实测：把该页面在 Chrome 中打开时，请求成功发送并收到响应，页面渲染出 `/api/tags` 的 JSON；说明默认 `OLLAMA_ORIGINS` 中至少有一个来源匹配成功。具体是 `file://` 还是其他桌面协议取决于页面加载方式，利用时需按目标客户端验证。

## 变体与关联

- 变体：恶意 Electron/Tauri 应用、VS Code Webview 插件、`app://` 协议页面；这些来源天然匹配 `app://*`/`tauri://*`/`vscode-webview://*`。
- 变体：DNS rebinding 让攻击者域名解析到 127.0.0.1，绕过“只允许 localhost”类限制；与宽松 `OLLAMA_ORIGINS` 组合可扩大入口。
- 变体：CSRF 式调用不需要读取响应，可直接触发 `/api/delete`、`/api/pull`、`/api/generate` 等副作用；读取型请求需要 CORS 放行。
- 关联卡片：[[web-generic-auth-ollama-unauth-api-model-management]]（同一 Ollama 的无认证 API 暴露面）、[[web-generic-cors-options-preflight-authz-oracle]]（CORS 预检鉴权缺失）、[[ai-security-mcp-security-oauth-authz-server-missing-host-check-rebinding]]（本地服务 Origin/Host 校验缺失与 DNS rebinding）。
- 关联：本地 AI 服务（Ollama、LM Studio、LocalAI 等）普遍使用宽松 CORS 方便桌面客户端，暴露到公网或与不可信 WebView 共存时风险放大。

## 检测与防御

- 防御：把 `OLLAMA_ORIGINS` 收紧为精确的可信来源（如具体的 `http://localhost:3000`、`vscode-webview://<固定 id>`），不要使用 `file://*`、`app://*`、`tauri://*` 等协议通配符；公网/多用户环境尤其如此。
- 防御：Ollama 绑定 127.0.0.1，并在前面加带认证的反向代理；不要把 11434 暴露到公网或不可信内网。
- 防御：桌面客户端使用独立认证令牌/本机 IPC，而不是仅依赖 CORS；对高风险 API（delete/copy/create/pull）要求额外授权。
- 防御：浏览器/WebView 侧限制本地文件与不可信 WebView 访问本地服务；对 `file://`、`app://` 页面做安全提示。
- 检测：Ollama 日志中出现来自 `file://`、`app://`、`tauri://`、`vscode-webview://` 等 Origin 的跨域请求；本地 11434 出现异常 `/api/tags`、`/api/generate`、`/api/delete` 调用；管理员打开未知 HTML/安装未知插件后出现模型操作。
- 响应：收紧 CORS、删除可疑本地页面/插件、审计模型是否被复制/删除/篡改，必要时重置本地 Ollama 配置。
