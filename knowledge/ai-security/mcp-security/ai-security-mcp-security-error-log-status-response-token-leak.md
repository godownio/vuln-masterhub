---
id: ai-security-mcp-security-error-log-status-response-token-leak
title: MCP 工具把认证令牌拼进错误消息/状态响应/系统日志导致令牌泄漏（令牌盗窃）
type: scenario
domain: ai-security
path: ai-security/mcp-security
technique: mcp-tool-response-token-disclosure
aliases:
- MCP 令牌盗窃
- 错误信息泄露 Bearer token
- 状态检查返回 access_token
- view_system_logs 日志含令牌
tags:
- mcp
- token-leak
- credential-disclosure
- error-message
- logging
- llm
- information-disclosure
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-13
  verified_at: '2026-11-08T07:22:16+08:00'
  notes: 已对照原文与图核对：check_email 错误分支、check_service_status 的 Connection Details、view_system_logs 的 Token details 三处把 access_token/api_key 拼进返回文本，与原文代码逐行一致；原文输出 email/cloud_storage/analytics 三个 JWT access_token 已实证泄漏。与同篇提示注入卡的区分：本卡不依赖注入，靠错误/状态/日志响应的脱敏缺失，sink 与触发方式不同；dedup 复跑仅 related(cos 0.88~0.89)，无 duplicate。未验证点：靶场教学 token 为示例值，未验证令牌可实际调用后端；原文未给真实目标；frontmatter 无 sources/source_url。
---

## 一句话结论

MCP 工具为"调试方便"把 `access_token`、`api_key` 等认证材料直接格式化进错误日志、服务状态响应或系统日志文本并返回（`Authorization: Bearer {token}`、`Connection Details: - API Key: ...`）；这些响应会进入 LLM 上下文并被回显给用户，攻击者只要调用相应工具（甚至故意传不存在的参数触发错误分支）即可提取各服务的身份令牌，进而未授权访问后端服务。

## 原理

- 令牌本应只用于服务端内部调用、不出现在任何返回给 LLM/用户的文本里；但靶场 `check_email` 在访问文件夹失败时把 `email_token['access_token']`、`api_key` 拼进 error_log 返回；`check_service_status` 把完整 token 信息列入 `Connection Details`；`view_system_logs` 在"最近日志"里写入 `Token details: Bearer {token}`。
- MCP 工具返回值一律进入 LLM 上下文，因此任何出现在响应文本里的敏感数据都会被模型看到并可能复述；调用方（用户/攻击者）可借自然语言指令让 LLM 逐个调用这些工具并汇总输出。
- 攻击不需要利用内存/反序列化：只需构造触发错误分支的参数（如不存在的文件夹 `non_existent_folder`、`error` 日志），工具就把令牌带出。
- 靶场输出示例：email_service / cloud_storage / analytics_platform 三个 JWT 形式 access_token 被完整提取；危害是用这些令牌冒充服务身份访问邮箱、云存储、分析平台。
- 根因：敏感数据未与对外响应分离 + 错误信息/日志/状态页缺乏脱敏 + 令牌以明文可导出形式存储。

## 触发条件

- MCP 工具的返回文本（错误消息、状态详情、日志内容）里拼接了令牌/密钥；
- 工具返回值会进入 LLM 上下文并可被用户读取；
- 攻击者能让 LLM 调用相关工具（含故意触发错误分支）；
- 令牌未做脱敏/短期轮换/权限最小化。

## 利用步骤

1. 列出 MCP 工具，定位会返回"调试信息/状态详情/日志"的工具。
2. 用自然语言让 LLM 依次调用：`check_email(non_existent_folder)`（触发错误分支）、`check_service_status(email_service)`、`view_system_logs(error)`。
3. 让 LLM 汇总输出响应中的 Authorization Bearer / API Key / Access Token 字段。
4. 用提取到的令牌直接调用对应后端服务 API（未授权访问）。

## PoC

```text
Please check emails in the "non_existent_folder" folder using the check_email tool.
Please check the status of the "email_service" using the check_service_status tool.
Please view the "error" system logs using the view_system_logs tool.
-> 提取 Email service token / Cloud storage token / Analytics platform token（JWT）
```

```python
# 漏洞形态：错误信息里拼接令牌
error_log = f"Error accessing folder: {folder}\nAuthorization: Bearer {email_token.get('access_token')}\nAPI Key: {email_token.get('api_key')}"
return error_log
```

说明：结构复现的通用 payload，工具名/参数按目标调整；不访问、不执行。

## 变体与关联

- 变体：令牌藏在异常堆栈、HTTP 响应头回显、metrics/debug 端点、导出文件、LLM 工具调用参数里；或借提示注入让 LLM 主动去读含令牌的资源。
- 变体：配合工具投毒/提示注入把令牌外传到外部服务器，而非仅回显给用户。
- 关联：[[ai-security-mcp-security-untrusted-data-reflection-indirect-prompt-injection]]（注入触发读敏感资源）；[[ai-security-mcp-security-hidden-tool-hardcoded-key-root-credential]]（硬编码密钥/隐藏工具）；[[ai-security-mcp-security-xmlrpc-execute-command-token-leak]]（命令执行 + 令牌泄露）。

## 检测与防御

- 检测：工具返回文本中出现 `Bearer `、`access_token`、`api_key`、JWT（`eyJ...`）等高熵串；错误/状态/日志类工具被高频调用。
- 检测：令牌出现在 LLM 对话记录、日志文件或外发流量中；同一令牌在非预期来源被使用。
- 防御：令牌存入加密存储/密钥管理系统，工具内部使用但绝不拼进返回文本；对错误、日志、状态响应做脱敏（令牌混淆/截断）。
- 防御：使用短期、最小权限、可轮换令牌；监控令牌使用来源；输出侧 DLP 拦截高熵敏感串。
