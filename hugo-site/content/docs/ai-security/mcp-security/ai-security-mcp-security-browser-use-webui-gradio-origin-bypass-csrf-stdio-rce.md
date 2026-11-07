---
id: ai-security-mcp-security-browser-use-webui-gradio-origin-bypass-csrf-stdio-rce
title: browser-use/web-ui Gradio is_valid_origin 反向校验 + 未鉴权 MCP 配置接口：恶意页面 CSRF 启动任意 stdio 命令 RCE
type: scenario
domain: ai-security
path: ai-security/mcp-security
technique: gradio-origin-check-inverted-csrf-mcp-stdio-rce
tags:
- browser-use
- web-ui
- gradio
- cors
- csrf
- mcp
- stdio
- command-injection
- rce
- localhost
- ai-agent
- python
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V112
  verified_at: '2026-11-06T01:55:44+08:00'
  notes: 已对照原文 26 张幻灯片核对：漏洞入口、代码/截图与攻击链描述一致；两案例 PoC 按截图重写未复跑，Gradio postData 字段映射与 browser-tools-mcp 的 fullPath/path 闭合需按目标版本核对；AGENT-MINER 为方法论/框架卡，原文无源码、prompt 或效果数据。原文未给受影响版本，未设置 versions；三卡 frontmatter 无 sources/source_url。
url: /docs/ai-security/mcp-security/ai-security-mcp-security-browser-use-webui-gradio-origin-bypass-csrf-stdio-rce/
draft: false
kb_aliases:
- browser-use web-ui RCE
- Gradio CORS 绕过
- is_valid_origin 反逻辑
- MCP 元数据 RCE
- CSRF 启动 MCP stdio
- 本地 Agent Web UI 未鉴权
---

## 一句话结论

browser-use/web-ui 把未认证的内部任务/MCP 配置 API 绑定到 `0.0.0.0`，且所用 Gradio 的 `is_valid_origin()` 判断写反：只要请求的 `Host` 不是 localhost 别名就一律放行；攻击者页面因此可以跨域读取响应并以 CSRF 方式向 `/gradio_api/queue/join` 提交一份 MCP stdio 配置，让后端用攻击者指定的 `command/args` 启动子进程，在受害者主机上直接 RCE。

## 原理

- **“本地服务不需要鉴权”的错误前提**：web-ui 认为只监听本机就安全，但实际绑定到 `0.0.0.0`，同一局域网或公网可达；其内部任务接口没有认证，任何能访问该端口的人都能提交任务或修改 MCP 配置。
- **Gradio 的 Origin 校验逻辑写反**：漏洞版本的 `is_valid_origin()` 大致为：
  ```python
  return (
      host_name not in self.localhost_aliases
      or origin_name in self.localhost_aliases
  )
  ```
  其中 `localhost_aliases = ["localhost", "127.0.0.1", "0.0.0.0"]`。正确的 DNS rebinding/跨站防护应要求 `Host` 与 `Origin` 都属于可信本地来源；这里却只要 `Host` 不是这三个别名就返回 True。因此攻击者页面访问 `http://<内网IP或公网IP>:<端口>` 时，浏览器发出的 `Host` 是攻击者可控的非 localhost 地址，校验直接通过；用解析到 127.0.0.1 的域名访问也能让 `Host` 变成非别名域名。
- **CORS 通过后即可读响应**：Gradio 的 CORS 中间件基于同一 `is_valid_origin()` 决定是否返回 `Access-Control-Allow-Origin`。校验绕过意味着恶意页面不仅能发请求，还能读取 Gradio 队列/任务的返回，从而完成完整的“提交任务→轮询结果”流程。
- **MCP stdio 语义就是执行本地命令**：MCP 的 stdio 传输需要指定 `command` 与 `args` 来启动子进程。web-ui 的 MCP 配置接口允许用户在任务参数里定义 stdio server；当配置来自跨站请求且没有认证/CSRF token 时，攻击者就能把 `command` 设为 `/bin/sh`、`args` 设为 `-c '<任意命令>'`（或 `cmd.exe /c ...`），后端会忠实地启动它。所谓“可控 MCP 元数据 = RCE”。
- **利用链**：受害者运行 browser-use/web-ui → 访问恶意页面 → 页面跨域向本地 Gradio API 提交带恶意 MCP 配置的任务 → 后端启动攻击者控制的 stdio 进程 → 命令执行并接管主机。整个过程不需要受害者点击授权（除浏览器 Local Network Access 等网络策略外），属于“一键 RCE”型攻击。

## 触发条件

- 受害者本机运行 browser-use/web-ui（Gradio Web UI），且服务绑定 `0.0.0.0` 或可经内网/公网 IP、域名访问。
- 目标 web-ui 版本使用存在逻辑缺陷的 `is_valid_origin()`，且 MCP 配置接口无认证、无 CSRF token。
- 受害者浏览器访问攻击者可控页面；页面能向目标地址发起跨域请求（Chrome 的 Local Network Access 可能要求 HTTPS/用户授权，原文将其视为可满足条件）。
- 攻击者知道目标 web-ui 的地址/端口，且进程有权限执行目标命令（通常与当前用户相同）。

## 利用步骤

1. 确认目标 web-ui 监听在 `0.0.0.0`，并取得可达地址（内网 IP、公网 IP 或解析到回环的域名）。
2. 构造恶意页面，使用 `fetch` 向 `http://<target>:<port>/gradio_api/queue/join?` 提交任务数据；在 MCP 配置字段中把 stdio server 的 `command` 设为 `/bin/sh`（Windows 为 `cmd.exe`），`args` 设为 `-c 'touch /tmp/pwned'` 或反弹 shell。
3. 诱导受害者访问页面；浏览器发出跨域请求，Gradio 的 `is_valid_origin()` 因 Host 非 localhost 别名而放行，并返回 CORS 头。
4. 页面读取任务/队列响应，确认任务被接受；后端启动 MCP stdio 子进程，命令在受害者主机执行。
5. 将命令替换为下载执行、写 SSH key、反弹 shell 等，完成持久化或横向。

## PoC

以下为按原文截图结构重写的示意（原文只给了截图中的 `postUrl` 与 `postData` 数组，未给出完整字段映射；字段顺序随 web-ui 版本变化）：

```html
<script>
const postUrl = 'http://<target>:<port>/gradio_api/queue/join?';
const postData = {
  data: [
    /* ... 任务参数 ... */
    {
      mcp_enabled: true,
      mcp_configs: [{
        name: "rce-test",
        command: "/bin/sh",
        args: ["-c", "touch /tmp/pwned"]
      }]
    }
  ]
};
fetch(postUrl, {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify(postData)
}).then(r => r.text()).then(console.log);
</script>
```

预期：web-ui 后端启动 `/bin/sh -c 'touch /tmp/pwned'`，`/tmp/pwned` 被创建。原文未在本库环境复现，字段结构需按目标版本核对。

## 变体与关联

- **Host 变体**：用内网/公网 IP、解析到 127.0.0.1 的域名、或 DNS rebinding 域名，使 `Host` 不落在 `localhost_aliases` 中。
- **请求方式变体**：若接口接受简单请求，可用表单/`no-cors` 只触发不读取；需要读取队列结果时依赖 CORS 绕过。
- **MCP 配置载体变体**：任务参数、MCP server 管理接口、profile 导入、`mcp_configs` 字段等，凡是能把 `command/args` 写进 stdio 配置的入口都可尝试。
- **关联卡片**：[[ai-security-mcp-security-inspector-cors-stdio-rce]]（MCP Inspector 默认 `cors()` + `/stdio` query 命令执行，同属“本地 MCP 控制面未鉴权 + 跨站调用 → RCE”，但产品、CORS 缺陷点和触发方式不同）、[[ai-security-mcp-stdio-endpoint-command-injection]]（MCP stdio endpoint 直拼 shell）。

## 检测与防御

- **鉴权**：Agent/Web UI 的所有控制面接口（任务提交、MCP 配置、文件操作）必须认证并校验授权，不能把“监听 127.0.0.1/0.0.0.0”当作安全边界。
- **Origin 校验**：修正 Gradio `is_valid_origin()`，要求 `Origin` 与 `Host` 同时属于明确的本地白名单；拒绝缺失/不匹配的 Origin，并加 CSRF token 或自定义请求头。
- **绑定地址**：默认只绑定 `127.0.0.1`；确需对外时放在反向代理后并启用认证、TLS 与访问控制。
- **MCP 配置**：stdio 的 `command/args` 使用白名单（固定可执行文件 + 参数），禁止用户直接指定任意命令；启动前做路径/参数校验。
- **沙箱**：在容器/受限账号中运行 Agent 与 MCP 子进程，隔离文件系统与网络，限制可执行文件与出网。
- **检测**：web-ui 日志中出现跨站 Origin 访问 `/gradio_api/queue/join`、MCP 配置包含 `sh -c`/`cmd.exe /c`、由 web-ui 进程拉起的异常子进程；主机出现临时目录可疑文件或反弹连接。
