---
id: web-dotnet-iis-webdav-put-move-webshell
title: IIS WebDAV 开启时 PUT 写文件 + MOVE 改后缀落地 ASP WebShell
type: scenario
domain: web
path: web/dotnet/iis
technique: iis-webdav-put-webshell
aliases:
- IIS PUT 写文件
- WebDAV PUT getshell
- IIS MOVE 改后缀
- iis-put-getshell
- WebDAV 任意文件写入
tags:
- iis
- webdav
- put
- move
- webshell
- asp
- file-write
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-E
  verified_at: '2026-11-04T19:20:47+08:00'
  notes: 已对照原文核对：fscan iis-put-getshell、PUT /1.txt 201、PUT shell.txt、MOVE shell.asp、蚁剑连接与原文一致；原文未明说 WebDAV 开关，按 PUT 201 推断启用 WebDAV；PoC 未在本机执行。
---

## 一句话结论

IIS 启用 WebDAV 且站点目录允许写入时，攻击者可用 `PUT` 方法写入任意文件，再用 `MOVE` 方法把 `.txt` 改成 `.asp`，从而绕过仅按扩展名拦截的防护并落地可执行 WebShell。

## 原理

- WebDAV 在 HTTP 上扩展了 `PUT`、`MOVE`、`COPY`、`PROPFIND` 等方法。IIS 启用 WebDAV 且目录授予写权限后，`PUT /path` 的请求体会被直接写入服务器对应路径，返回 `201 Created` 表示创建成功。
- `MOVE /shell.txt` 配合 `Destination: /shell.asp` 可把已写入的文件移动/改名。很多防护只检查上传文件名或 `PUT` 目标扩展名，先写 `.txt` 再 `MOVE` 成脚本后缀即可绕过。
- 目标站点由 IIS 的 ASP 引擎解析 `.asp` 文件，访问该文件即执行其中的服务端代码。案例中先 `PUT /1.txt` 验证写权限，再写 ASP 一句话并 `MOVE` 为 `shell.asp`，随后用蚁剑连接成功。
- 成立前提是 WebDAV 写权限没有与站点脚本目录隔离；如果目录禁止写入或脚本解析被关闭，只能造成任意文件写入而非 RCE。

## 触发条件

- IIS 启用 WebDAV（`WebDAVModule`/`WebDAVHandler`），站点或虚拟目录允许写入；
- `PUT`/`MOVE` 方法未被 IIS 请求筛选、WAF 或前置代理拦截；
- 目标目录存在脚本映射（案例为 ASP，也可能是 ASPX/PHP 等）；
- 攻击者可访问写入后的文件路径。

## 利用步骤

1. 探测方法：发送 `OPTIONS` 或直接 `PUT` 一个小文本文件，观察是否返回 `201 Created`。
2. 访问写入的文件 URL，确认内容可读且未被重命名。
3. 准备目标解析语言对应的 WebShell 内容，`PUT` 到 `.txt` 或其他非脚本后缀。
4. 发送 `MOVE`，`Destination` 指向 `.asp` 等可执行后缀。
5. 访问脚本路径，确认被解析；用 WebShell 客户端连接并管理文件。
6. 若 WebShell 连接受权限限制，结合 MS17-010 等其他漏洞提权。

## PoC

```http
# 1. 验证写权限
PUT /1.txt HTTP/1.1
Host: target
Content-Length: 3

123
```

```http
# 2. 写入脚本内容到非脚本后缀
PUT /shell.txt HTTP/1.1
Host: target
Content-Length: <len>

<ASP WebShell 内容>
```

```http
# 3. MOVE 改成可解析后缀
MOVE /shell.txt HTTP/1.1
Host: target
Destination: /shell.asp
```

```text
# 预期：PUT/MOVE 返回 201 Created，访问 /shell.asp 被 IIS 解析
```

## 变体与关联

- 变体：`COPY` 方法；`PUT` 直接写 `.asp`（防护未拦截时）；`web.config` 写入；`PROPFIND` 列目录辅助定位；ASPX/JSP/PHP 对应脚本映射。
- 关联：[[web-generic-file-upload-encrypted-webshell-av-bypass]]（上传后的内容查杀绕过）；[[pentest-lateral-movement-ms17-010-eternalblue-psexec]]（IIS 低权限 WebShell 后的提权）。
- 影响边界：案例中 WebShell 以 IIS 应用池账户运行，读取管理员家目录受 NTFS 权限限制；最终通过 MS17-010 提权到 SYSTEM。

## 检测与防御

- 检测：IIS 访问日志中出现 `PUT`、`MOVE`、`COPY` 方法及 `Destination` 头；`201 Created` 响应；Web 目录中新出现的 `.asp`/`.aspx`/`.php` 文件；WebShell 客户端特征流量。
- 修复：不需要 WebDAV 时禁用 `WebDAVModule`；需要时限制为只读、禁止脚本目录写入。
- 缓解：IIS 请求筛选阻止 `PUT`/`MOVE`/`COPY`；WAF 检查方法与 `Destination` 头；上传目录与脚本目录分离；应用池最小权限。
