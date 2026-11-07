---
id: web-generic-file-inclusion-django-token-download-szname-traversal-read
title: Django 拨号记录下载接口 szName 拼接路径穿越任意文件读取（16 位 token 门槛）
type: scenario
domain: web
path: web/generic/file-inclusion
technique: django-download-szname-concat-path-traversal
tags:
- python
- django
- path-traversal
- arbitrary-file-read
- download
- token
- web
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V58
  verified_at: '2026-11-05T08:49:24+08:00'
  notes: 已对照原文与图12-20核对：optDialingOut 将 szName 直接拼接 /opt/dialingtest/records/ 后 cUtil.downFile，token 需存在且长度16并过 getLoginToken，与图13代码一致；原文 token=2wgicpfhyYaKFHbX（16位），请求 szName=../../../../etc/passwd，响应 Content-Length 1192 且回显 /etc/passwd，与图19/20一致。未验证点：文件读取依赖有效登录 token（原文已登录获取）；optDialingDelete 任意删除仅原文代码+AI分析、未展示实际删除请求，卡片已按未验证原语注明；PoC 未本机执行；frontmatter 无 sources/source_url。
url: /docs/web/generic/file-inclusion/web-generic-file-inclusion-django-token-download-szname-traversal-read/
draft: false
kb_aliases:
- szName 路径穿越
- optDialingOut 任意文件读取
- 上网行为管理系统任意文件读取
- /opt/dialingtest/records 目录穿越
- Django downFile 路径穿越
---

## 一句话结论

上网行为管理系统的 Django 视图 `optDialingOut` 把请求参数 `szName` 直接拼到固定目录 `/opt/dialingtest/records/` 后交给下载函数，未做规范化或白名单；攻击者登录后拿到 16 位 token，用 `szName=../../../../etc/passwd` 即可读取服务器任意可读文件。

## 原理

- **拼接而非安全解析**：`szPath = "/opt/dialingtest/records/"`，`szDownPath = szPath + szName`，`cUtil.downFile(szDownPath)` 直接把拼接结果当文件路径打开；`..` 与 `/` 未被过滤，路径规范化发生在文件系统层，于是 `/opt/dialingtest/records/../../../../etc/passwd` 最终解析为 `/etc/passwd`。
- **token 只证明登录态，不限制路径**：前置检查要求 `token` 存在、长度为 16、且 `/tmpfile/loginfile/<token>` 能通过 `getLoginToken()` 校验；满足后仅决定“允许下载”，下载哪个文件完全由 `szName` 决定。token 是登录成功后写入的会话文件标识（登录成功后 `loginfo` 写入 `/tmpfile/loginfile/<token>`），所以这是登录后任意文件读取。
- **为什么不构成目录穿越防护**：代码没有 `os.path.realpath`/`abspath` 后校验前缀，也没有 `basename(szName)` 或字符白名单；`../` 在 `open()` 前原样保留。
- **回显**：`HttpResponse(cUtil.downFile(...))` 把文件内容作为响应体，`Content-Type: application/octet-stream`、`Content-Disposition: attachment;filename="<szName>"`；响应长度与内容可直接判断读取成功，原文读取 `/etc/passwd` 返回 1192 字节并完整回显。

## 触发条件

- 目标为该 Django 上网行为管理系统，`optDialingOut` 路由（原文为 `/optDialingOut/`）可达。
- 攻击者拥有有效登录会话及 16 位 token（登录后从 URL `?token=...` 获取，或从日志/Referer 泄露中获得）。
- `/tmpfile/loginfile/<token>` 存在且 `getLoginToken` 判定有效，否则重定向 `/index/`。
- 运行账号对目标文件有读权限（Web 服务/root 可读 `/etc/passwd`、配置、密钥等）。

## 利用步骤

1. 登录系统，从浏览器地址栏或请求中提取 16 位 `token`（原文截图 URL 形如 `/?token=2wgicpfhyYaKFHbX`）。
2. 构造下载请求，把 `szName` 设为相对穿越路径：`../../../../etc/passwd`（4 层 `../` 从 `/opt/dialingtest/records/` 回到根目录）。
3. 发送 `GET /optDialingOut/?token=<16位token>&szName=../../../../etc/passwd`。
4. 检查响应：`Content-Length` 非预期、正文出现 `/etc/passwd` 内容即成功；若被重定向到 `/index/`，说明 token 无效或已过期。
5. 按需读取应用配置（数据库口令、SECRET_KEY）、SSH 私钥、`/proc/self/environ` 等；读取大文件时可用 Range/分段或选择小文件。

## PoC

```http
GET /optDialingOut/?token=2wgicpfhyYaKFHbX&szName=../../../../etc/passwd HTTP/1.1
Host: <target>
```

```http
HTTP/1.1 200 OK
Content-Type: application/octet-stream
Content-Disposition: attachment;filename="../../../../etc/passwd"
Content-Length: 1192

root:x:0:0:root:/root:/bin/bash
...
```

原文通过 Burp 发送该请求并在响应中看到完整的 `/etc/passwd`；路径穿越部分为 `../../../../etc/passwd`。

## 变体与关联

- **同参数的其他 sink**：同文件中的 `optDialingDelete` 把 `szName` 拼到同一目录后 `os.remove(szPath + szName)`，可造成登录后任意文件删除（原文只给出代码与 AI 分析，未展示删除请求/结果；属于可用但未在原文验证的原语）。
- **更深/更浅的穿越**：目标不在根目录时按层级增加 `../`；Windows 部署可用 `..\..\`，编码变体（`%2e%2e%2f`、双重编码）可绕过只做一次字符串替换的防护。
- **token 获取面**：token 出现在 URL 中，可能经 Referer、访问日志、代理日志、浏览器历史泄露；这也是该类“登录后任意文件读取”常被外部攻击者利用的原因。
- **关联模式**：本库其他“下载接口 fileName/szName 直接拼接”的路径穿越卡（Java `new File(root, path)`、os.path.join 绝对路径覆盖等）；根因相同，差异在拼接方式与前置鉴权。
- **与其他漏洞组合**：读取数据库配置/凭据后可进一步连数据库；读取应用源码可发现更多接口与密钥，形成从任意文件读取到 RCE 的链。

## 检测与防御

- **修复**：`os.path.realpath(os.path.join(base, szName))` 后校验结果仍以 `base + os.sep` 开头；或只接受文件 ID/白名单文件名，绝不接受路径；对 `szName` 做 `os.path.basename()` 与字符白名单。
- **鉴权**：token 校验之外增加文件归属校验（只能下载当前用户/当前任务产生的记录），token 绑定用户与有效期。
- **检测**：请求参数含 `../`、`..\`、`%2e%2e`、绝对路径、`/etc/passwd` 等特征；下载接口响应体出现系统文件内容；同一 token 短时间读取多个非业务路径；Web 日志中出现 `szName=../../`。
- **防御**：Web 服务以低权限账号运行，限制可读目录；敏感文件（配置、密钥）最小权限；token 不要放 URL，改用 Cookie/Header 并设置 HttpOnly、短期有效；WAF 对解码后的参数做路径规范化检查。
