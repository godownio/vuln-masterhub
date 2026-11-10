---
id: ai-security-mcp-security-overprivileged-file-tool-arbitrary-read
title: MCP 文件工具权限过大：read_file/search_files 无路径白名单导致任意文件读取与私有目录遍历
type: scenario
domain: ai-security
path: ai-security/mcp-security
technique: mcp-tool-excessive-permission-path-traversal-read
aliases:
- MCP 权限范围过大
- read_file 任意路径读取
- search_files 搜索私有目录
- 目录遍历泄露敏感文件
tags:
- mcp
- excessive-permission
- arbitrary-file-read
- path-traversal
- llm
- information-disclosure
- least-privilege
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-13
  verified_at: '2026-11-08T07:22:14+08:00'
  notes: 已对照原文代码与图核对：read_file 先 os.path.exists(filename) 直接 open(任意路径)、否则回退 public 前缀；search_files 同时遍历 public 与 private 并返回 Private/ 命中，与原文一致；原文 PoC 以 search_files 搜 CONFIDENTIAL 得薪资表(CEO/CTO/CFO)、read_file 传私有目录路径读取，危害(任意文件读)已打通。与同篇 code-exec 卡的区分：本卡 sink 是文件工具缺路径白名单，code-exec 卡 sink 是 subprocess 无沙箱/黑名单，机制不同，不构成同一链拆分；dedup 复跑仅 related(cos 0.894~0.897)，无 duplicate。未验证点：靶场路径 /tmp/dvmcp_challenge3 为教学环境，未在真实目标复跑；frontmatter 无 sources/source_url；本卡无 affected_versions 合规(靶场无版本标记)。
---

## 一句话结论

MCP 工具声称"只读取 public 目录"，但实现里直接把用户给的 `filename` 传给 `open()` 且不做路径规范化/白名单校验，`search_files` 又同时遍历 public 与 private 目录；攻击者（或被引擎诱导的 LLM）只要传入绝对路径或包含私有目录的关键词，就能读到本应受限的薪资、凭据等敏感文件。

## 原理

- `read_file(filename)` 先判断 `os.path.exists(filename)` 就直接 `open(filename).read()`，仅在直接路径不存在时才回退拼 public 前缀；因此传入 `/tmp/.../private/salary.txt` 或 `../private/...` 即可读任意路径（路径遍历 + 任意文件读）。安全实现应校验 `filename` 规范化后必须位于 public 目录内。
- `search_files(keyword)` 同时遍历 public 与 private 目录并把命中结果一并返回；即便用户只搜 public 关键词，也能通过返回里的 `Private/<file>` 推断/读取私有文件存在与内容线索。
- 工具描述 ("Read a file from the public directory") 与实际权限不一致，客户端/LLM 按描述信任工具，不会意识到越权。
- 靶场结果：让 LLM 用 `search_files` 搜关键词 `CONFIDENTIAL`，得到 `Private/salary_information.txt` 等，并输出 CEO/CTO/CFO 薪资等机密数据。
- 根因：工具实现缺少最小权限与路径校验，敏感资源（隐藏 resource `internal://credentials`、private 目录）没有服务端独立访问控制，仅靠"不列在清单里"隐藏。

## 触发条件

- MCP 工具提供文件读取/搜索/日志分析能力且接受用户可控的文件名/路径/关键词；
- 实现未做路径规范化、未限定基准目录、未做权限校验；
- 同一主机上存在敏感文件/私有目录，且工具进程对其有读权限；
- LLM 会按用户自然语言调用该工具。

## 利用步骤

1. 审计/试用工具的 `filename` 参数：传入绝对路径或 `../` 观察是否能读到 public 之外的文件。
2. 若直接读被限制，用 `search_files` 这类"搜索"接口以敏感关键词（CONFIDENTIAL、password、token）检索，命中结果覆盖私有目录。
3. 让 LLM 调用：`Please search for files containing the keyword "CONFIDENTIAL" using the search_files tool.`
4. 从返回结果定位私有文件，再用 `read_file` 传入其完整路径读取内容。

## PoC

```text
# 搜索型：工具同时遍历 public 与 private
Please search for files containing the keyword "CONFIDENTIAL" using the search_files tool.
-> Files containing 'CONFIDENTIAL': Private/salary_information.txt ...（CEO/CTO/CFO 薪资）

# 读取型：filename 未做白名单，直接传私有目录路径
Please read the file "/tmp/dvmcp_challenge3/private/salary_information.txt" using the read_file tool.
```

说明：结构复现的通用 payload，路径按目标环境调整；不访问、不执行。

## 变体与关联

- 变体：`analyze_log_file`、`get_file_contents` 等"只读某个目录"的工具同样若不限路径即可任意读；路径穿越可用 `..`、符号链接、绝对路径、URL 编码绕过弱校验。
- 变体：与提示注入组合，由注入指令让 LLM 主动去读敏感文件并外传（而非用户直接请求）。
- 关联：[[ai-security-mcp-security-untrusted-data-reflection-indirect-prompt-injection]]（注入触发读敏感资源）；[[ai-security-mcp-security-resources-read-base64-uri-path-traversal]]（MCP resource 路径遍历）；[[ai-security-mcp-security-tool-idor-document-pii-leak]]（工具越权读 PII）。

## 检测与防御

- 检测：工具调用参数中出现绝对路径、`..`、private/sensitive 目录名；LLM 读取工具描述声称范围之外的文件；搜索结果里出现私有目录条目。
- 检测：进程打开 Web 目录之外的敏感文件（文件审计/沙箱）。
- 防御：实施最小权限，工具只可访问授权目录；用 `realpath` 规范化并校验路径前缀在允许目录内；对文件名做白名单。
- 防御：敏感文件不与该工具同主机/同权限域；隐藏资源在服务端加独立鉴权；工具调用与文件访问做审计告警。
