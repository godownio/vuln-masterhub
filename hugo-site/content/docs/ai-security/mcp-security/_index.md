---
title: MCP 安全
weight: 1
---

# MCP 安全

## 这层是什么

MCP server/client、工具描述注入、权限与供应链。

## 允许放入

- 一个具体场景/技巧的蒸馏卡片（原理、触发条件、利用步骤、PoC、检测与防御）
- 该层技术的总览、术语、前置知识、目录导航
- 经过核对的攻防思路与最小复现片段

## 不允许放入

- CVE 详情与版本清单（统一放 cve/）
- 安全资讯、招聘、活动、纯新闻
- 未提炼的原文转载、长段摘录
- 与主题无关的工具安装教程

## 子目录

- （暂无子目录；新增场景卡直接放在本目录）

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [browser-use/web-ui Gradio is_valid_origin 反向校验 + 未鉴权 MCP 配置接口：恶意页面 CSRF 启动任意 stdio 命令 RCE](ai-security-mcp-security-browser-use-webui-gradio-origin-bypass-csrf-stdio-rce/) | verified | high | 2026-11-06 |
| [Burp MCP Server 暴露面：Unsafe mode + 0.0.0.0 portproxy + Privacy OFF 的未授权请求代理与流量读取](ai-security-mcp-security-burp-mcp-server-exposure-unsafe-portproxy/) | verified | medium | 2026-11-05 |
| [Cherry Studio 恶意 MCP 服务器 OAuth 元数据命令注入（CVE-2025-54074）：authorization_endpoint 直入 open() 导致 RCE](ai-security-mcp-security-cherry-studio-oauth-authorization-endpoint-command-injection/) | verified | high | 2026-11-07 |
| [CurXecute（Cursor IDE）：文档间接注入改写 ~/.cursor/mcp.json 零点击 RCE（CVE-2025-54135）](ai-security-mcp-security-curxecute-cursor-prompt-injection-mcp-config-rce/) | verified | medium | 2026-11-06 |
| [FastMCP 自定义工具链：`../` 单次替换绕过读 server.py 拿硬编码 token，os.system 绕过审计钩子执行命令](ai-security-mcp-fastmcp-path-filter-token-audit-hook-bypass/) | verified | medium | 2026-11-07 |
| [IDA Pro MCP 本地 JSON-RPC 无认证/无 Origin 校验：DNS rebinding 调用 py_eval 实现 RCE（CVE-2025-67117）](ai-security-mcp-security-ida-pro-mcp-dns-rebinding-py-eval-rce/) | verified | high | 2026-11-06 |
| [LangFlow 流程节点绕过 MCP stdio 管理员限制：任意 npm/PyPI 包执行](ai-security-mcp-security-langflow-flow-node-mcp-stdio-authorization-bypass/) | verified | high | 2026-11-05 |
| [LibreChat MCP stdio 服务器创建授权缺陷：默认用户经 /api/mcp/servers 执行任意命令（CVE-2026-22252）](ai-security-mcp-security-librechat-stdio-server-create-rce-cve-2026-22252/) | verified | high | 2026-11-06 |
| [MCP DXT 恶意 manifest：mcp_config.command/args 未过滤导致任意命令执行](ai-security-mcp-dxt-manifest-command-injection/) | verified | high | 2026-11-06 |
| [MCP Inspector 宽 CORS 与无鉴权 stdio 参数导致跨站 RCE](ai-security-mcp-security-inspector-cors-stdio-rce/) | verified | high | 2026-11-04 |
| [MCP resources/read base64:// URI 路径穿越：管理员 SSRF 代理读取 /root 下 flag](ai-security-mcp-security-resources-read-base64-uri-path-traversal/) | verified | high | 2026-11-06 |
| [MCP SDK 授权服务器缺 Host/Origin 校验：DNS rebinding 注册客户端并窃取令牌接管 MCP](ai-security-mcp-security-oauth-authz-server-missing-host-check-rebinding/) | verified | high | 2026-11-05 |
| [MCP Sleeper Rug Pull + 跨服务器工具影子：二次加载改写描述劫持 whatsapp send_message 收件人并外带聊天记录](ai-security-mcp-sleeper-rugpull-cross-server-tool-shadow-whatsapp-exfil/) | verified | high | 2026-11-07 |
| [MCP stdio 白名单允许 npx/uvx：包运行器把命令白名单变成任意代码执行](ai-security-mcp-security-package-runner-npx-uvx-command-execution/) | verified | high | 2026-11-05 |
| [MCP 地毯式骗局（Rug Pull）：工具在调用次数/批准之后动态改变行为或描述](ai-security-mcp-security-tool-rug-pull-call-count-behavior-change/) | verified | high | 2026-11-08 |
| [MCP 客户端 stdio endpoint 直拼 sh -c：AIRAG saveAndSync 认证用户命令执行](ai-security-mcp-stdio-endpoint-command-injection/) | verified | high | 2026-11-05 |
| [MCP 工具把认证令牌拼进错误消息/状态响应/系统日志导致令牌泄漏（令牌盗窃）](ai-security-mcp-security-error-log-status-response-token-leak/) | verified | high | 2026-11-08 |
| [MCP 工具描述投毒劫持工具选择：伪造 system_prompt 诱导调用恶意 SecCheck 工具执行命令](ai-security-mcp-security-tool-description-shadowing-call-hijack/) | verified | medium | 2026-11-06 |
| [MCP 工具描述投毒：description 隐藏指令诱导读取 ~/.ssh 并作为参数外传](ai-security-mcp-security-tool-description-poisoning-param-smuggling/) | verified | high | 2026-11-05 |
| [MCP 工具无对象级鉴权（IDOR）导致文档枚举与简历等隐私泄露](ai-security-mcp-security-tool-idor-document-pii-leak/) | verified | high | 2026-11-05 |
| [MCP 工具无沙箱执行任意 Python/shell 代码，黑名单式危险命令过滤可被绕过读取敏感文件](ai-security-mcp-security-unsandboxed-code-exec-blacklist-shell/) | verified | high | 2026-11-08 |
| [MCP 工具注册服务 JWT alg:none 伪造 admin：注册工具代码导致命令执行](ai-security-mcp-registry-jwt-none-tool-code-exec/) | verified | high | 2026-11-05 |
| [MCP 工具阴影（Shadowing）：名称/描述高度相似的恶意工具诱导 LLM 误调用并提权](ai-security-mcp-security-similar-tool-name-shadowing-llm-miscall/) | verified | high | 2026-11-08 |
| [MCP 文件工具权限过大：read_file/search_files 无路径白名单导致任意文件读取与私有目录遍历](ai-security-mcp-security-overprivileged-file-tool-arbitrary-read/) | verified | high | 2026-11-08 |
| [MCP 服务 prompt 泄露敏感路径 + get_file_base64 资源模板以 root 读取任意文件](ai-security-mcp-security-prompt-resource-base64-file-read/) | verified | high | 2026-11-07 |
| [MCP 服务暴露 XML-RPC execute_command：静态 token 从进程命令行/源码泄露后本地任意命令执行](ai-security-mcp-security-xmlrpc-execute-command-token-leak/) | verified | medium | 2026-11-06 |
| [MCP 沙箱管理工具 container_id 命令拼接注入：sandbox_stop 经 docker rm -f 在宿主机执行命令](ai-security-mcp-security-sandbox-stop-container-id-command-injection/) | verified | medium | 2026-11-06 |
| [MCP 资源/工具把不可信输入反射进 LLM 上下文触发间接提示注入，枚举读取隐藏凭据并把私有数据外泄](ai-security-mcp-security-untrusted-data-reflection-indirect-prompt-injection/) | verified | high | 2026-11-08 |
| [MCP 配置 Rug-Pull：批准绑定 key 名、后续提交替换 command 实现持久反连](ai-security-mcp-security-config-rug-pull-command-swap-persistence/) | verified | medium | 2026-11-05 |
| [MCPJam Inspector /api/mcp/connect 未授权 RCE：serverConfig command/args 直接启动进程（CVE-2026-23744）](ai-security-mcpjam-inspector-api-mcp-connect-rce/) | verified | high | 2026-11-05 |
| [MySQL MCP SSE 服务未授权：绑定 0.0.0.0 无鉴权，任意客户端调用 mysql_query 执行 SQL](ai-security-mcp-security-mysql-mcp-sse-unauth-sql-query/) | verified | high | 2026-11-06 |
| [OpsMCP 隐藏工具与硬编码 API Key：以 root 运行的工具服务泄露 root SSH 私钥](ai-security-mcp-security-hidden-tool-hardcoded-key-root-credential/) | verified | high | 2026-11-05 |
| [Orval MCP 生成器 summary 未转义代码注入：恶意 OpenAPI 规范在生成的 server.ts 加载时执行任意命令（CVE-2026-22785）](ai-security-mcp-security-orval-mcp-summary-code-injection/) | verified | high | 2026-11-06 |
| [WeKnora < 0.2.5 MCP stdio 命令注入：CreateMCPService 直接执行用户 command/args，测试连接即 RCE（CVE-2026-22688）](ai-security-mcp-security-weknora-stdio-command-injection-cve-2026-22688/) | verified | high | 2026-11-06 |
| [恶意 MCP 工具实现层后门：正常工具名/描述与返回结果掩护，按日期哈希概率性窃取环境变量密钥](ai-security-mcp-security-tool-implementation-probabilistic-env-exfil/) | verified | medium | 2026-11-06 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
