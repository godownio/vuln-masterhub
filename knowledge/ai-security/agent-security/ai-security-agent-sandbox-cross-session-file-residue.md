---
id: ai-security-agent-sandbox-cross-session-file-residue
title: LLM Sandbox 跨会话文件残留：删除会话后敏感文件仍可访问
type: scenario
domain: ai-security
path: ai-security/agent-security
technique: sandbox-cross-session-file-residue
aliases:
- /mnt/data 跨会话
- 沙箱会话隔离缺失
- 删除会话文件仍在
- secret.txt 残留
tags:
- llm-sandbox
- 跨会话
- 隔离缺失
- 信息泄露
- mnt-data
- 代码解释器
- 文件上传
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-T1-2
  verified_at: '2026-11-07T21:44:57+08:00'
  notes: 已对照原文核对；会话1上传secret.txt并删除会话后、会话2执行ls /mnt/data/仍可见该文件与图18及正文一致；dedup候选均为工具限制绕过或沙箱逃逸，非同一利用链；非组件漏洞无版本；未验证点：文件名与路径为结构示意，原文实验已验证
---

## 一句话结论

若 LLM 系统的 Sandbox/代码解释器文件系统未在会话间隔离，会话 1 上传的敏感文件在用户关闭并删除会话 1 后仍留在共享的 `/mnt/data/` 中；用户在另一设备新建会话 2 执行 `ls /mnt/data/` 仍能读到该文件，进而在分享分析结果时无意泄露敏感信息。

## 原理

- LLM 系统常配 Sandbox 辅助设施支撑代码解释器与文件上传：用户上传的文件落到 `/mnt/data/`，模型按提示词（如"分析 /mnt/data/ 下所有文件并合并为一个文档"）读写该目录。
- 安全前提应是"会话级隔离"：一个会话上传的文件不能被另一无关会话访问，会话结束/删除时应连同其文件一起清理。
- 若实现上所有会话共享同一持久化目录，且删除会话只删除对话记录、不清理挂载文件，就产生跨会话残留：文件对模型仍可见，用户却误以为已随会话删除。
- 危害隐藏在后续正常使用中：用户在新会话上传公开数据并让模型"分析所有文件再合并输出"，结果 inadvertently 混入上一个会话的敏感文件；一旦把结果分享出去即造成泄露。原文实验在会话 1 上传 secret.txt、删除会话 1 后，会话 2 的 `ls /mnt/data/` 仍列出 secret.txt。

## 触发条件

- LLM 系统提供文件上传 + 代码解释器/沙箱，文件落在跨会话共享的持久化目录（如 `/mnt/data/`）。
- "删除会话"未联动清理该会话上传的文件；无会话级或用户级文件系统隔离。
- 模型可执行列目录/读取全部文件的提示词，并把结果合并输出给用户。

## 利用步骤

1. 在会话 1 上传含敏感内容的文件（如 secret.txt），用"upload to your file system"之类提示确认落盘。
2. 关闭并删除会话 1（用户视角以为文件随之删除）。
3. 在另一设备/新开会话 2 输入 `ls /mnt/data/`，确认敏感文件仍被列出。
4. 让模型"分析 /mnt/data/ 下所有文件并合并为一个文档"，使敏感内容混入输出。
5. 用户分享该文档即造成信息泄露（也可由能触发新会话的攻击者直接读取）。

## PoC

```text
# 会话 1
[上传 secret.txt]  upload to your file system
[删除会话 1]

# 会话 2（另一设备）
You: ls /mnt/data/
ChatGPT: The directory '/mnt/data/' contains the following files: 'secret.txt'
```

（文件名与路径为结构示意，未执行。）

## 变体与关联

- 变体：共享的不只是文件，还可能是环境变量、临时表、pip 安装的包、缓存的凭据与 cookie。
- 变体：多租户场景下若隔离粒度是"用户"而非"会话"，同一用户不同会话串数据；若粒度是"全局"，则跨用户串数据，危害升级。
- 关联：与 SpAIware 等"长期记忆投毒实现跨会话持久化数据外带"同属 LLM 跨会话状态污染，但本场景是文件系统残留而非记忆/提示注入。
- 关联：与沙箱逃逸类（如 `SandboxPython` 恢复 builtins、vm2 逃逸）不同——本场景不需要逃逸，只是隔离与生命周期管理缺失。

## 检测与防御

- 检测：跨会话 `ls /mnt/data/` 出现非本会话上传的文件；删除会话后底层文件仍存在；合并分析结果里出现来源不明内容。
- 防御：按会话（必要时按用户+会话）隔离文件系统，使用一次性挂载卷或命名空间；会话删除/过期时联动清理文件。
- 防御：对"读取全部文件并合并输出"做来源审计与白名单，输出前提示用户确认文件清单；限制模型对共享目录的可见范围。
- 防御：对上传文件设 TTL 与加密，分离对话元数据与文件存储的生命周期，定期做残留文件扫描。
