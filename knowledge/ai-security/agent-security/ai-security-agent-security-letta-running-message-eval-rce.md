---
id: ai-security-agent-security-letta-running-message-eval-rce
title: Letta "Running" 消息参数直接 eval 导致 RCE
type: scenario
domain: ai-security
path: ai-security/agent-security
technique: agent-message-eval-injection
aliases:
- Letta eval 注入
- Running 消息 RCE
- CVE-2025-6101 原始漏洞
- CLIInterface function_message
tags:
- ai-agent
- letta
- rce
- eval
- code-injection
- cve-2025-6101
cve:
- CVE-2025-6101
severity: high
confidence: medium
affected_versions: letta 0.4.1
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-F
  verified_at: '2026-11-04T19:21:06+08:00'
  notes: 全文与 10 张图片逐张核对。0.4.1 interface.py 181-190 行用正则提取 Running 消息的 function_args 后直接 eval(function_args)（图 02），白名单四个记忆函数与原文一致；本地直接调用 CLIInterface.function_message 已实测弹出计算器（图 06/07）。HTTP /v1/agents/{id}/messages 因前置 LLM 访问 api.openai.com 超时未端到端打通（图 05），卡片已在原理/限制中明确该点并将 confidence 定为 medium，未夸大远程未认证利用。affected_versions=letta 0.4.1 与原文一致；路径、frontmatter 合法，无 sources/source/URL 字段。PoC 未在本机执行。
---

## 一句话结论

Letta 0.4.1 的 `CLIInterface.function_message()` 把以 `Running ` 开头的消息用正则拆成函数名与参数，随后直接 `eval(function_args)`；构造 `Running archival_memory_insert(__import__('os').system(...))` 即可在 Agent 进程内执行任意 Python 代码。

## 原理

- `interface.py` 第 181-190 行用正则匹配 `Running <function_name>(<function_args>)`，`function_args = match.group(2)` 未做净化；当函数名落在 `archival_memory_insert`、`archival_memory_search`、`core_memory_replace`、`core_memory_append` 白名单内时，执行 `msg_dict = eval(function_args)`。
- `eval` 使用默认 builtins，`__import__` 可直接调用，因此参数位置能执行 `os.system`、`subprocess`、`open` 等任意表达式。
- 根因是“消息协议”和“代码执行”边界重合：函数名白名单只限制了外层调用的名字，参数仍是一段完整 Python 表达式。攻击者控制消息文本即控制代码。
- 前置 LLM 意图识别模块可能在 HTTP 路径上先消费消息；但 sink 在消息处理函数内部，只要该函数被调用（CLI、内部调用，或 LLM 放行后的消息）就会执行。文章实测 `/v1/agents/{id}/messages` 在离线环境因 LLM 模块访问外网超时被挡，改用直接调用 `cli.function_message()` 验证了 RCE，因此远程入口是否可达取决于部署是否启用/放行该前置模块。

## 触发条件

- Letta 0.4.1（原始漏洞版本）。
- 攻击者能控制进入 `function_message()` 的消息文本，消息以 `Running ` 开头，函数名在四个记忆函数白名单内。
- HTTP 入口需要先通过前置 LLM 意图识别（或部署中该模块不存在/可绕过）；CLI 或内部调用路径可直接触达 sink。
- Agent 进程具备执行系统命令的权限（默认通常具备）。

## 利用步骤

1. 确认目标版本为 Letta 0.4.1，取得可交互的 Agent 消息入口（HTTP 需 Agent ID，或使用本地 CLI）。
2. 构造消息：`Running archival_memory_insert(__import__('os').system('id'))`。
3. 通过消息接口或 `CLIInterface.function_message()` 送入；走 HTTP 时需让请求通过 LLM 意图识别。
4. 用 `__import__('os').popen('id').read()` 之类的表达式把命令输出带回，确认代码执行。
5. 进一步读取环境变量中的模型/云厂商凭据、Agent 记忆与系统提示词，或写入持久化。

## PoC

```python
from letta.interface import CLIInterface

cli = CLIInterface()
payload = "Running archival_memory_insert(__import__('os').system('calc'))"
cli.function_message(payload)
```

```text
# 消息形态（HTTP 与 CLI 共用同一 sink）
Running archival_memory_insert(__import__('os').popen('id').read())
```

## 变体与关联

- 变体：白名单内另外三个记忆函数都能作为外层名；参数可换成 `__import__('subprocess').check_output(...)`、`eval(...)`、`exec(...)`、`open(...).read()` 等。
- 关联：[[ai-security-agent-security-letta-ast-whitelist-eval-fallback-bypass]]（0.16.4 官方修复版中的补丁绕过，同一 CVE 的后续形态）。
- 限制：文章未完成 HTTP 端到端利用，远程路径受 LLM 前置模块影响；直接函数调用已实测 RCE，故 confidence 定为 medium。

## 检测与防御

- 修复：删除对消息参数的 `eval`；需要结构化参数时用 `ast.literal_eval`、JSON schema 或显式类型转换，只接受字面量。
- 防御：消息解析与代码执行分离；函数名白名单不能替代参数校验；Agent 进程按最小权限运行（非 root、限制网络与文件系统）；不要把 LLM 意图识别当作安全边界。
- 检测：日志中出现以 `Running ` 开头且参数含 `__import__`、`eval`、`exec`、`system`、`popen` 的消息；Agent 进程异常拉起 shell/子进程；升级后核对 `interface.py` 中不再存在 `eval(function_args)`。
