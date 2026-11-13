---
id: web-generic-file-inclusion-bosscms-ueditor-delete-path-traversal-unlink
title: BossCMS ueditor action=delete 任意文件删除：path 仅校验 upload/ 前缀，../ 穿越后 dir::delete 直接 unlink
type: scenario
domain: web
path: web/generic/file-inclusion
technique: bosscms-ueditor-delete-path-traversal-unlink
aliases:
- BossCMS 任意文件删除
- ueditor action=delete 删文件
- BossCMS 未授权删除文件
- dir::delete unlink 穿越
tags:
- web
- php
- bosscms
- cms
- ueditor
- file-delete
- arbitrary-file-deletion
- path-traversal
- code-audit
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V638
  verified_at: '2026-11-13T02:11:35+08:00'
  notes: 已对照原文与截图核对：delete() 的 ^upload/ 前缀校验、dir::replace() 不过滤 ..、dir::delete() unlink 属实；PoC 已按原文抓包修正为 path=upload/../x.txt（Content-Length 20 一致，删除站点根 x.txt；追加 ../ 可删到站点根外）；未授权变体并入；affected_versions 已 clear（原文仅安装环境版本）。未复跑。
---

## 一句话结论

BossCMS 的 ueditor 控制器 `action=delete` 把 POST 参数 `path` 去掉上传 URL 前缀后只要求以 `upload/` 开头，随后 `dir::delete(ROOT_PATH.$path)` 直接 `unlink`；`dir::replace()` 只统一路径分隔符、不过滤 `..`，提交 `path=upload/../x.txt` 即可删除站点根下的文件（追加 `../` 可删到站点根之外任意位置），且 `admin::init()` 未登录只跳转不退出，未授权也能调用。

## 原理

- **入口与过滤**：`system/extend/ueditor/php/ueditor.class.php` 的 `delete()` 中，`$path = str_replace(self::replacepath(url::upload()), '', $_POST['path'])`，再用 `preg_match('/^upload\//', $path)` 校验前缀；校验只保证字符串以 `upload/` 开头，不解析真实路径。
- **路径归一化不拦穿越**：`system/basic/class/dir.class.php` 的 `replace()` 只做 `\` → `/`、盘符占位符等替换，没有把 `..` 段折叠或做白名单 containment 判断。
- **删除动作**：`dir::delete($path)` 先 `replace($path)`，`is_file` 为真就 `unlink($path)`，否则递归删除目录。传入 `ROOT_PATH.'upload/../x.txt'` 时 `unlink` 解析到站点根下的 `x.txt`；增加 `../` 数量即可删到站点根之外的任意位置。
- **默认走本地存储**：存储方式 `store_type` 默认为 0（本地存储），所以默认走 `dir::delete`；只有显式开启外部存储才走 OSS 删除分支。
- **鉴权不拦截**：ueditor 类继承 admin，`admin::init()` 读不到 `manager` session 时只 `header('Location: ...login')`，没有 `exit/die`，PHP 继续执行到 `delete()`，副作用已经产生（响应可能是 302，但文件已被删）。

## 触发条件

- 目标可达 `/system/extend/ueditor/php/controller.php?action=delete`。
- 提供 POST 参数 `path`，内容以 `upload/` 开头并含足够多的 `../` 指向目标文件。
- 目标文件对 PHP 进程用户可删除；相对 `ROOT_PATH` 可定位（Windows/Linux 均可）。
- 存储方式为本地（默认）。

## 利用步骤

1. 先通过目录遍历/正常上传确认网站根目录的绝对位置，并选定目标文件（如安装锁、配置文件、其它站点文件、`.user.ini` 等）。
2. 计算从 `ROOT_PATH` 到目标文件的相对路径，保留 `upload/` 前缀：`upload/../` 回到站点根，再加 `../` 逐级向上，例如删除站点根的 `x.txt` 用 `upload/../x.txt`。
3. 发送 `action=delete` 的 POST 请求。
4. 观察响应 `{"state":"SUCCESS"}`，再用目录列表/下载接口确认文件消失。

## PoC

```http
POST /system/extend/ueditor/php/controller.php?action=delete HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Content-Length: 20

path=upload/../x.txt
```

本地存储下返回：

```json
{"state":"SUCCESS"}
```

原文在站点根放置 `x.txt`，请求后该文件被删除；即使响应头带登录页跳转，删除动作也已执行。（原文抓包 body 为 `path=/upload/../x.txt`，按代码的 `^upload/` 前缀校验，等价的规范写法是 `upload/../x.txt`；`Content-Length: 20` 与该 body 长度一致。）

## 变体与关联

- **未授权变体**：不带 `PHPSESSID` 直接发上述请求同样可删，原因是 `admin::init()` 的 header 跳转缺少 `exit/die`（见关联卡）。
- `store_type=1` 时改走 `oss::delete`，路径穿越的影响面取决于云存储实现；本卡针对默认本地存储。
- 与库内 JFinalCMS/Whir EZOffice 等删除卡对比：本卡过滤点是“前缀字符串校验 + 分隔符归一化”，没有 canonical path 检查。

## 检测与防御

- 删除前用 `realpath()` 解析目标路径，确认仍位于上传目录内；拒绝含 `..` 的输入。
- 后端固定删除白名单（只允许删自己上传的文件），不要接受任意路径。
- 鉴权失败必须 `exit/die`，禁止依赖 `header()` 跳转终止流程。
- 监控 `action=delete` 请求中带 `../` 或路径不在 upload 目录的调用。
