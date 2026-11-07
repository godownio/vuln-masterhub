---
id: web-generic-file-inclusion-encoded-dotdot-predecode-blacklist-bypass
title: 文件读取参数先黑名单后解码：%2e%2e%2f 绕过 .. 与 / 检查
type: scenario
domain: web
path: web/generic/file-inclusion
technique: encoded-traversal-predecode-check-bypass
aliases:
- URL 编码目录遍历
- '%2e%2e%2f 绕过'
- random-picture 穿越
- 先校验后解码
- 任意文件读取
- 双重 URL 编码穿越
tags:
- file-inclusion
- path-traversal
- url-encoding
- filter-bypass
- java
- arbitrary-file-read
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V22
  verified_at: '2026-11-05T03:12:39+08:00'
  notes: 已对照原文2.3.1模块5核对：random-picture 对原始查询参数检查 .. 与 /，未解码前校验；payload urlenc(../../path-traversal-secret) 绕过并读到 secret 内容，最终提交用户名 SHA-512 通关。原文未给组件版本（WebGoat 8.2.2 靶场），未设置 affected_versions。未复现。
---

## 一句话结论

文件读取接口在原始查询字符串上检查 `..` 和 `/`，之后才由框架/代码做 URL 解码并拼路径；攻击者提交 `%2e%2e%2f`，黑名单看到的是百分号编码、不含 `..` 或 `/`，解码后却是 `../`，从而穿越目录读取任意文件。

## 原理

- 校验顺序错误：代码用 `id.contains("..") || id.contains("/")` 检查原始参数，通过后再把 id 拼进文件路径；而 Servlet 容器/框架在参数绑定阶段已经或即将对 `%2e`、`%2f` 做 URL 解码。
- `%2e` 解码为 `.`、`%2f` 解码为 `/`，因此 `%2e%2e%2f` 在检查时只是一串普通字符，进入文件系统时变成 `../`。
- 如果只解码一次，`%252e%252e%252f` 这类双重编码可能在第二次解码时生效，取决于框架解码次数。
- 常见拼接形式为 `baseDir + id + ".jpg"` 或 `new File(baseDir, id + ".jpg")`；末尾自动追加的扩展名不影响 `../` 穿越，因为 `../secret` 会先定位到上级目录，再拼接 `.jpg`。
- 黑名单只拦 `..` 与 `/`，不拦反斜杠、绝对路径、`..%5c`、Unicode 斜杠等；即使补充了这些，规范化与解码的顺序仍可能被绕过。

## 触发条件

- 文件读取/图片加载接口把用户参数拼进文件路径。
- 参数在黑名单检查时尚未解码，或检查用的字符串与最终拼接用的字符串不是同一个表示。
- 黑名单只覆盖字面量 `..` 与 `/`，没有做路径规范化与前缀校验。
- 进程对目标文件有读权限。

## 利用步骤

1. 触发一次正常读取，确认参数名（如 `id`）、自动追加的扩展名与响应形式。
2. 直接提交 `../../etc/passwd` 观察是否被 400/过滤，记录拦截特征。
3. 将 payload 做 URL 编码：`..%2f..%2fetc%2fpasswd` 或 `%2e%2e%2f%2e%2e%2fetc%2fpasswd`，再提交。
4. 若仍被拦，尝试双重编码 `%252e%252e%252f`、反斜杠 `..%5c`、`....//`。
5. 根据回显/文件内容确认读取成功；无回显时用存在性差异或错误信息判断。

## PoC

```http
GET /PathTraversal/random-picture?id=%2e%2e%2fpath-traversal-secret HTTP/1.1
Host: target
```

```text
# 服务端实际读取 <baseDir>/../path-traversal-secret.jpg
# 若响应返回该文件内容（而不是 400/空），说明编码穿越成功。
```

## 变体与关联

- 变体：双重编码 `%252e%252e%252f`、大小写 `%2E%2E%2F`、`..%5c`（Windows）、`%c0%ae` 等畸形编码。
- 变体：黑名单在解码后检查，但只替换一次 `/`，可用 `..\` 或 `....//` 绕过（见关联卡）。
- 关联：[[web-generic-file-inclusion-windows-backslash-download-traversal]]（分隔符替换不彻底）。
- 关联：[[web-generic-file-upload-single-replace-dotdot-bypass]]（写入侧的单次替换绕过）。
- 关联：[[web-golang-servemux-encoded-slash-path-traversal]]（其他语言/框架的编码路径穿越）。
- 边界：若框架在校验前已解码、或服务端在拼接后做 `getCanonicalPath()` 前缀校验、或参数只允许数字/白名单，穿越不成立。

## 检测与防御

- 修复：先规范化再校验：`Path path = base.resolve(id).normalize(); if (!path.startsWith(base)) reject;`。
- 修复：不要把用户输入当路径；用 ID 到文件名的服务端映射表。
- 修复：校验应基于最终用于文件系统的字符串，且与解码顺序一致；黑名单不可作为唯一防线。
- 加固：文件读取根目录与敏感目录隔离，使用最小权限账户；禁止读取符号链接指向根目录外。
- 检测：参数含 `%2e`、`%2f`、`%5c`、`..`、双重编码；请求路径穿越到 base 目录之外；文件读取接口出现异常扩展名/绝对路径。
