---
id: web-generic-file-inclusion-chfs-downloaddir-directory-traversal
title: chfs（CuteHttpFileServer）/chfs/downloaddir 目录下载路径穿越：../ 逃逸共享根目录读取任意目录
type: scenario
domain: web
path: web/generic/file-inclusion
technique: chfs-downloaddir-path-traversal
aliases:
- chfs 路径穿越
- CuteHttpFileServer 目录穿越
- /chfs/downloaddir
- chfs files filepath 目录浏览
- chfs 任意目录下载
tags:
- chfs
- path-traversal
- file-inclusion
- arbitrary-file-read
- file-server
- web
cve: []
severity: high
confidence: low
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V536
  verified_at: '2026-11-11T18:39:20+08:00'
  notes: 已对照原文与 img02-06 逐张核对：/chfs/files?filepath= 返回 JSON 目录列表（img02）、filepath=../../../../../ 上跳可见 flag 目录（img03/04）、filepath=.. 列出的 base64 文件名可解码为 admin:gdgm.edu.cn@M1n9K1n9P@as（img05）、/chfs/downloaddir/../../../../flag 返回 application/zip 且含 flag/flag.txt（img06）、单文件走 /chfs/shared（原文正文）——卡片与原文一致。证据来自 VNCTF2024 CutePath CTF 题环境，卡片已标 confidence low 并注明真实产品需自行验证版本/默认配置，符合规范。原文『先创建目录再拦截 downloaddir 请求』的触发技巧卡片未收录（直接构造请求即可复现，不影响链条）。dedup 0 duplicate，与 luckyframeweb/mee-admin/zipdownload 等『下载接口拼接路径』卡非同链。保留。
---

## 一句话结论

chfs（CuteHttpFileServer）的 `/chfs/files?filepath=` 接口把 `filepath` 当作相对共享根目录的路径直接列目录（可带 `../` 逐层上跳浏览），而目录下载接口 `/chfs/downloaddir/<path>` 在把整个目录打包成 zip 时未对路径做规范化与前缀校验，用 `/chfs/downloaddir/../../../../<目标目录>` 即可逃逸共享根目录，把任意目录（含 flag 等敏感文件）打包下载。

## 原理

- chfs 是单文件 Go 编写的 HTTP 文件服务器，默认提供两类接口：`/chfs/files?filepath=<相对路径>` 返回 JSON 格式的目录列表（文件名、大小、目录标志等），`/chfs/downloaddir/<相对路径>` 把指定目录打包为 zip 下载；单文件下载则走 `/chfs/shared/<相对路径>`。
- 共享目录边界本应由“相对路径解析后必须仍在 root 内”来保证。若实现只是把 `filepath` 与共享根拼接后交给文件系统（或先 `filepath.Join` 再 `os.Open`），`..` 就会在拼接后逃逸出根目录——`filepath.Join("/share", "../../etc")` 得到 `/etc`。
- `files` 接口的泄漏点在于它直接回显目录项（含文件名），可用来逐层枚举上级目录，寻找目标路径；`downloaddir` 的泄漏点在于把目录整体 zip 打包返回，绕过了单文件接口可能存在的扩展名/路径限制，一次拿到整个目录内容。
- 之所以成立：路径穿越防护依赖对每个 `..` 段的清洗和最终路径的 `root` 前缀校验，二者缺一即可穿越；目录打包功能会递归读取目录下所有文件，放大单次穿越的影响。
- 本文的利用路径还展示了信息收集价值：先 `filepath=..` 逐层上跳，在共享目录中发现含账号口令的 base64 密文文件，再用 `downloaddir` 一次性取走含 flag 的目录。

## 触发条件

- 目标暴露 chfs（CuteHttpFileServer）服务，`/chfs/files` 与 `/chfs/downloaddir` 接口可访问（是否需登录取决于配置）。
- 目标版本/实现未对 `filepath` 与目录下载路径做规范化与前缀校验（存在 `..` 穿越）。
- 目录下载功能未被禁用；服务进程对目标目录有读权限。
- 本文证据来自 CTF 题环境，服务端接口与 chfs 行为一致；在真实产品上利用前需自行验证版本与默认配置。

## 利用步骤

1. 访问 `/chfs/files?filepath=` 观察返回 JSON，确认接口与共享目录结构。
2. 用 `filepath=..`、`filepath=../..` 逐层上跳，枚举上级目录与敏感文件（配置、备份、口令文件等）。
3. 定位目标目录后，构造目录下载请求：`/chfs/downloaddir/../../../../<目标相对路径>`，把返回的 zip 保存到本地。
4. 解压 zip，读取目标目录全部内容（如 `/flag/flag.txt`）。
5. 若目录下载不可用，退回 `files` 接口逐目录浏览并用单文件接口配合穿越读取。

## PoC

```http
GET /chfs/files?filepath=.. HTTP/1.1
Host: <target>
Accept: application/json
```

```http
GET /chfs/downloaddir/../../../../flag HTTP/1.1
Host: <target>
Accept: application/zip
```

```bash
# 保存并解压目录包
curl -s 'http://<target>/chfs/downloaddir/../../../../flag' -o flag_dir.zip
unzip -l flag_dir.zip && unzip flag_dir.zip
```

## 变体与关联

- 变体：`files` 接口本身即可未授权列目录；若返回了用户名/口令等敏感文件名，可直接进入凭据复用。
- 变体：不同版本接口前缀可能不同（`/chfs/shared/` 单文件、`/chfs/files` 列表、`/chfs/downloaddir` 目录包），以实际响应为准。
- 关联：[[web-generic-file-inclusion-luckyframeweb-download-filename-traversal]]、[[web-generic-file-inclusion-mee-admin-common-file-filepath-traversal]]、[[web-generic-file-inclusion-monitoring-platform-downloadfile-filepath-traversal]] 等“下载接口拼接路径”类卡；同类防护缺失可互相迁移测试。
- 边界：若服务端对 `..` 做了清洗、对最终路径做了根目录前缀校验，或目录下载被关闭，则穿越不成立；针对 chfs 的攻击需在授权范围内进行。

## 检测与防御

- **检测**：Web 日志中出现 `/chfs/files?filepath=` 含 `..`、`/chfs/downloaddir/` 路径含 `../` 的请求；短时间内对同一服务的大量目录列表请求与 zip 下载。
- **防御**：升级到修复版本；在反向代理/WAF 层对 URL 规范化并拒绝含 `..` 的路径；禁用不必要的目录下载功能；以低权限运行服务并最小化共享目录内容。
- **加固**：不要把口令、配置、备份文件放入共享目录；对 chfs 类文件服务器做默认口令与未授权访问检查；对外网暴露的文件服务加认证与访问控制。
