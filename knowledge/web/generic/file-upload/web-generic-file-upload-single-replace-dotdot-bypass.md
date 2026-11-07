---
id: web-generic-file-upload-single-replace-dotdot-bypass
title: 上传文件名目录穿越：单次 replace("../","") 用 ..././ 还原绕过
type: scenario
domain: web
path: web/generic/file-upload
technique: path-traversal-single-pass-replace-bypass
aliases:
- 目录遍历
- 双写绕过 ../
- fullName 路径穿越
- '..././ 绕过'
- 上传路径穿越
- replace 单次替换绕过
tags:
- file-upload
- path-traversal
- filter-bypass
- java
- spring
- multipart
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V22
  verified_at: '2026-11-05T03:11:00+08:00'
  notes: 已对照原文2.3.1节与图58-61核对：ProfileUploadFix.uploadFileHandler 对 fullNameFix 做 replace("../","") 单次替换，payload ..././test 还原为 ../test，响应回显落到 doctor/test。卡内 PoC 的 multipart 字段名写作 uploadedFile（靶场实际为 uploadedFileFix），字段名需按目标调整，不影响机制。原文未给组件版本（WebGoat 8.2.2 靶场），未设置 affected_versions。未复现。
---

## 一句话结论

上传接口用 `fullName.replace("../", "")` 一次性删除 `../`，但替换不是递归的：提交 `..././test` 时，过滤器删掉中间那段 `../`，剩下的字符重新拼成 `../test`，文件名仍然穿越到上传目录之外。

## 原理

- `String.replace(CharSequence, CharSequence)` 从左到右扫描一次，删除第一个匹配后继续从删除点之后扫描，不会回头检查拼接后是否又出现关键字。这与双写绕过 SQL 关键字是同一类问题。
- 以 `..././test` 为例：字符串为 `. . . / . / t e s t`，其中位置 1-3 构成 `../`；删除后剩下位置 0 的 `.`、位置 4 的 `.`、位置 5 的 `/` 和 `test`，正好还原为 `../test`。
- 服务端随后通常执行 `new File(uploadDir, fileName)` 或 `uploadDir + File.separator + fileName`，文件名中的 `..` 由操作系统解析，最终写到上传目录的父目录/目标目录。
- 该过滤只处理 `../` 这一种形态：Windows 反斜杠 `..\`、URL 编码 `%2e%2e%2f`、绝对路径、`....//` 等都不在覆盖范围内。
- 另一个常见失误是“过滤了显式 fullName 参数，却仍使用 multipart 的 `getOriginalFilename()`”：攻击者把 payload 放进文件名而不是 fullName 字段，过滤逻辑根本看不到。

## 触发条件

- 上传接口接受用户可控的文件名/相对路径（表单字段、multipart filename、JSON 字段均可）。
- 服务端只做一次非递归的 `replace("../","")`、`replaceAll("\\.\\./","")` 或类似删除。
- 保存路径直接由上传目录与用户文件名拼接，未做规范化后的根目录校验。
- 进程对目标目录有写权限。

## 利用步骤

1. 正常上传一次，抓包确认文件名参数名（如 `fullName`、`fullNameFix`）与响应中回显的保存路径。
2. 用 `..././` 代替 `../` 构造 payload，如 `..././test`、`..././..././shell`。
3. 若接口同时接收显式文件名和 multipart filename，两个位置都试：一个可能被过滤，另一个可能直接使用。
4. 上传后从响应/回显或后续访问确认文件落点是否在上传目录之外。
5. 评估写入位置：能写 Web 根、计划任务目录、配置文件目录时危害升级为 RCE；仅能写同盘其他目录时为任意文件写入。

## PoC

```http
POST /upload HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----X

------X
Content-Disposition: form-data; name="uploadedFile"; filename="AAA.png"
Content-Type: image/png

aaaaaa
------X
Content-Disposition: form-data; name="fullNameFix"

..././test
------X--
```

```text
# 预期响应回显保存路径为 <uploadDir>/../test 或目标绝对路径下的 test，
# 即文件被写到上传目录之外。
```

## 变体与关联

- 变体：`....//`、`..././`、`..%2f`、`%2e%2e%2f`、Windows `..\`、绝对路径 `/etc/cron.d/x`。
- 变体：同时提交 `fullName` 与 multipart filename，利用两者过滤不一致。
- 变体：过滤只删除 `../` 不删除 `..`，可用 `..%5c`、`..\` 或 `..` + 分隔符组合。
- 关联：[[web-generic-file-inclusion-encoded-dotdot-predecode-blacklist-bypass]]（先校验后解码导致的读取侧穿越）。
- 关联：[[web-generic-file-upload-zip-slip-webshell-write]]（压缩包条目名穿越，另一条任意写入路径）。
- 关联：[[web-generic-file-inclusion-windows-backslash-download-traversal]]（分隔符替换不完整导致的反斜杠穿越）。
- 边界：若服务端在拼接后执行 `getCanonicalPath()` 并校验前缀、或只使用服务端生成的随机文件名，穿越不成立。

## 检测与防御

- 修复：不要使用用户提供的文件名作为路径；由服务端生成 UUID/哈希文件名，扩展名从白名单映射。
- 修复：若必须保留原名，先 `Paths.get(name).getFileName()` 取纯文件名，再规范化并校验 `canonicalPath.startsWith(uploadRoot)`。
- 修复：过滤要做递归/规范化（解析所有 `..` 与分隔符后再判断），不能只做一次字符串替换。
- 加固：上传目录与 Web 根分离，设置最小写权限；禁止上传目录执行脚本。
- 检测：文件名含 `..`、`.../`、`%2e`、反斜杠、绝对路径；保存路径落在上传根之外；同一账号短时间上传异常文件名。
