---
id: ai-security-agent-security-kilocode-config-file-template-arbitrary-read
title: kilocode 环境变量配置中的 {file:} 模板替换导致任意文件读取（CVE-2026-8766）
type: scenario
domain: ai-security
path: ai-security/agent-security
technique: config-template-file-read
aliases:
- CVE-2026-8766
- kilocode 任意文件读取
- KILO_CONFIG_CONTENT 文件读取
- '{file:} 模板替换'
- AI CLI 配置注入
tags:
- ai-security
- agent
- cli
- config
- arbitrary-file-read
- template-substitution
- cve
- error-leak
cve:
- CVE-2026-8766
severity: medium
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
affected_versions: <= 7.0.47
verification:
  verified_by: verifier-V6
  verified_at: '2026-11-05T00:56:28+08:00'
  notes: 已对照原文与2张图核对：KILO_CONFIG_CONTENT 走 load→parseText→substitute 的 {file:} 模板替换、JSONC 解析失败时回显 --- JSONC Input ---，图中实测泄露 package.json 与 C:\Windows\win.ini，均与卡片一致；受影响版本 ≤7.0.47 已在卡片标注，与原文一致。未验证点：未在本机复现；需攻击者能控制环境变量并看到输出（卡片已注明）。
---

## 一句话结论

kilocode 在解析 `KILO_CONFIG_CONTENT` 环境变量时沿用了配置文件的 `{file:<路径>}` 模板替换，替换后的内容若 JSON 解析失败会原样打印在错误信息里；能控制该环境变量并看到输出的攻击者即可读取进程权限范围内的任意本地文件。

## 原理

- 配置加载统一走 `load(text, options)` → `ConfigPaths.parseText(text, input)`；`parseText` 的第一步是 `substitute(text, input, missing)`，把 `{file:...}` 替换为对应文件内容，第二步才做 JSONC 解析。
- 文件配置使用模板替换是设计内行为；但从旧 `OPENCODE_` 命名空间迁移到 `KILO_` 后，`KILO_CONFIG_CONTENT` 环境变量分支也被接到了同一个 `load`，没有针对“环境变量来源”禁用模板替换。
- 解析失败时抛出的 `JsonError` 会拼接 `--- JSONC Input ---` 和替换后的完整文本，用于定位格式错误；于是被读入的文件内容随错误一起输出到终端/日志。
- 之所以成立：模板替换把“配置文本”扩展为“配置文本 + 任意文件内容”，而错误处理又把整段文本当作可回显的诊断信息；两个各自看似合理的设计叠加成文件读取与泄露。

## 触发条件

- 目标运行 kilocode ≤ 7.0.47；
- 攻击者能设置或影响启动 kilocode 进程的 `KILO_CONFIG_CONTENT` 环境变量（CI 变量、包装脚本、.env 加载、共享终端配置、或另一条能写入环境变量的漏洞）；
- 攻击者能读取 kilocode 的标准输出/错误（终端、CI 日志、日志采集系统）；
- 目标文件对运行 kilocode 的系统用户可读。

## 利用步骤

1. 构造含 `{file:<绝对路径>}` 的配置文本，把模板放进会被 JSON 解析的位置（键名或值均可）。
2. 通过 `KILO_CONFIG_CONTENT` 传给 kilocode 并触发任意命令（如 `auth ls --print-logs`）。
3. 模板替换读入文件内容，破坏 JSONC 语法；解析失败的错误信息回显整段替换后文本，文件内容出现在输出中。
4. 从输出/日志中提取文件内容。若文件本身能被构造成合法 JSON，则不会报错回显，需要改用在语法位置注入模板或配合其他回显点。

## PoC

```powershell
$env:KILO_CONFIG_CONTENT='{"a"{file:C:\Windows\win.ini}":"x"}'
bun run src/index.ts auth ls --print-logs
```

输出中的 `--- JSONC Input ---` 段落包含 `win.ini` 原文：

```text
Error: Config file at KILO_CONFIG_CONTENT is not valid JSON(C):
--- JSONC Input ---
{"a"; for 16-bit app support
[fonts]
[extensions]
...
```

读取项目文件同样可行：

```powershell
$env:KILO_CONFIG_CONTENT='{"{file:C:\test\kilocode-7.0.47\package.json}":"value"}'
bun run src/index.ts auth ls --print-logs
```

## 变体与关联

- 变体：同类“配置文件支持 include/read-file 模板”的 AI CLI/编辑器（`{file:}`、`${file:}`、`@file` 语法）；不依赖报错回显时，可把文件内容替换到会被后续逻辑输出或上报的字段（如模型请求、遥测）。
- 关联：AI 编码助手/Agent 的配置与工具权限面；同目录的 Letta 配置/消息注入卡说明“配置或消息进入解释执行”是同类根因。
- 影响边界：需要控制环境变量，不是未授权远程读取；没有输出可见性时只能造成盲读。若进程以高权限运行（CI runner、root），泄露面显著扩大。
- 修复背景：命名空间迁移时遗留功能未同步禁用，属于“不完整修复/旧特性残留”类问题，审计时应同时检查新旧前缀的所有配置入口。

## 检测与防御

- 检测：CI/终端日志中出现 `--- JSONC Input ---` 且内容含非配置文本；配置错误信息包含绝对路径或敏感文件片段；异常设置 `KILO_CONFIG_CONTENT` 的调用。
- 防御：对环境变量来源的配置禁用 `{file:}` 等模板替换，只允许受信任的配置文件路径使用；模板替换限制在固定目录并做路径规范化/白名单；解析错误只输出结构化位置，不回显原始配置文本；升级到修复版本；CI 中对不可信来源的环境变量做白名单过滤，并限制 Agent 进程的文件读权限。
