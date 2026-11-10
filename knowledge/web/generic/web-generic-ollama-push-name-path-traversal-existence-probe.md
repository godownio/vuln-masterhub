---
id: web-generic-ollama-push-name-path-traversal-existence-probe
title: Ollama /api/push 路径遍历文件存在性探测：响应差异枚举服务端模型与文件路径（CVE-2024-39722）
type: scenario
domain: web
path: web/generic
technique: api-response-difference-file-existence-probe
aliases:
- Ollama 模型存在性泄露
- CVE-2024-39722
- Ollama push 路径遍历
- 模型枚举
tags:
- ai-security
- model-extraction
- ollama
- path-traversal
- information-disclosure
- response-difference
cve: CVE-2024-39722
affected_versions: < 0.1.46
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-35
  verified_at: '2026-11-08T18:15:49+08:00'
  notes: 已对照原文核对：CVE-2024-39722、/api/push name 路径遍历存在性探测原理与利用步骤均与原文一致；affected_versions < 0.1.46 与原文「0.1.45 及更早版本/受影响版本 < 0.1.46」一致（初稿已正确，无需改动）；dedup_review 与 /api/create oracle 卡（CVE-2024-39719）端点/CVE/版本差异成立；未验证点：未实际搭建 0.1.45 环境复现
---

## 一句话结论

Ollama（< 0.1.46）的 `/api/push` 端点对用户提供的模型名未做验证清理，攻击者把 `name` 字段构造成路径遍历形式（如 `../../../../etc/passwd:latest`），通过服务器对存在/不存在路径的响应差异（是否返回 error），远程探测任意文件/目录是否存在，并可枚举服务器已部署的 Ollama 模型。

## 原理

Ollama 处理 push 请求时会先按 `name` 检查对应模型是否存在。`name` 正常格式为 `model_name:tag`，但服务端未校验其中是否含路径遍历序列，模型名会被映射为服务器文件系统路径参与检查。当目标路径存在时服务器继续走推送处理流程，响应中不含 error；路径不存在时返回错误。攻击者对比两种响应即可获得一个"文件/模型是否存在"的布尔预言机。修复版本 v0.1.46 的 diff 显示对 `loadModel` 中 Show/Chat 请求的模型名处理做了收紧，证实该响应差异源于未过滤的模型名。

## 触发条件

- 目标暴露 Ollama API（默认端口 11434），版本 <= 0.1.45；
- 攻击者可向 `/api/push` 发送任意 JSON 请求（无需认证）；
- 可先访问 `/api/version` 确认版本辅助判断。

## 利用步骤

1. `GET /api/version` 确认 Ollama 版本 <= 0.1.45。
2. 构造模型名列表：可从 ollama.com/library 爬取公开模型名+标签作为候选，也可用路径遍历串 `../../../../path/to/file:latest`。
3. 对每个候选向 `POST /api/push` 发送 `{"name":"<候选>","insecure":true,"stream":true}`。
4. 判读响应：响应不含 error 字段即视为该模型/路径存在（"leaked"），含 error 则不存在。

## PoC

最小请求（探测模型是否存在）：

```bash
curl -s http://target:11434/api/push -d '{"name":"llama3:70b","insecure":true,"stream":true}'
# 无 error 字段 => 模型存在；返回 error => 不存在
```

公开脚本 srcx404/CVE-2024-39722 演示了完整流程（爬取模型库、多线程发请求、输出 results.json），实测可从目标服务器枚举出 all-minilm:22m、codegemma:2b 等已部署模型。

## 变体与关联

- 同类"响应差异预言机"思路适用于其他把用户输入映射到文件系统路径且返回不一致错误的服务；
- 枚举出已部署模型后，可结合未授权推理 API 直接调用模型，或为后续针对特定模型的攻击做侦察；
- 与直接路径遍历读文件不同，此漏洞只泄露存在性，不返回文件内容。

## 检测与防御

- 升级 Ollama 到 0.1.46 及以上；
- 服务端对模型名等会映射为文件路径的输入做严格校验，拒绝路径遍历字符；
- API 响应错误信息归一化，避免存在性差异；
- Ollama 服务仅监听内网/加认证反代，限制 `/api/push` 等端点的访问来源；
- 监控对 `/api/push` 的高频枚举式请求。
