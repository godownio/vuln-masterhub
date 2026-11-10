---
id: web-generic-file-inclusion-zipdownload-export-path-traversal
title: zipDownload 与 export 两个打包下载接口的 path 参数穿越：从单文件读取到整站源码与数据库备份打包
type: scenario
domain: web
path: web/generic/file-inclusion
technique: archive-export-path-traversal
tags:
- web
- file-download
- path-traversal
- archive
- source-disclosure
- backup-disclosure
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W1
  verified_at: '2026-11-08T11:29:23+08:00'
  notes: 已对照原文核对；zipDownload 缺 path 时报 Required String parameter 'path' is not present，带 path=/../../../../../../..//etc/passwd 下载成功，Opt/export?path=../../ 打出 11.2MB zip，与卡片 PoC 一致；未验证点：原文未展示 shadow 之外的具体包内文件清单，卡片对 Windows 反斜杠变体属通用补充
url: /docs/web/generic/file-inclusion/web-generic-file-inclusion-zipdownload-export-path-traversal/
draft: false
kb_aliases:
- zipDownload 目录遍历下载
- export?path=../ 整站打包
- 打包下载接口路径穿越
- 源码与备份文件批量泄露
---

## 一句话结论

以 `/xxx/xxx/zipDownload?type=1&path=...` 和 `/xxx/Opt/export?path=...` 为代表的「打包/导出」接口，把客户端传入的 `path` 直接当作待打包目录：把 `../../../` 塞进去就能让服务端把 `/etc/passwd`、`/etc/shadow` 乃至整个 Web 根（含源码、数据库备份、中间件配置）压缩成一个包返回，一次请求拿到批量敏感文件。

## 原理

- 打包功能的实现范式是「接收一个目录/文件路径 → 递归列出 → 逐个读文件 → 写入 zip → 输出流」。开发者通常只校验「是否登录/是否有该功能权限」，而把 `path` 当作可信输入。
- 因为最终动作是 `file_get_contents`/`ZipArchive::addFile` 一类按路径读取的调用，只要路径存在且进程可读，就会被打进包；`../` 不受限制时目录边界失效，绝对路径（`/etc/...`）在部分实现里同样命中。
- 相比单文件下载，打包接口的「读」是批量且带目录遍历的：一个请求即可覆盖整棵目录树，泄露量级从「一个文件」变成「一套源码 + 配置 + 备份」，因此同一个穿越点危害更高。
- 若服务以 root/administrator 运行，`/etc/shadow`、SSH 私钥、数据库数据目录都可读；拿到源码后可继续审计出更多入口，拿到备份（`.sql`/`.zip`）可直接还原口令或配置。
- 这类接口常出现在导出报表、导出配置、日志打包、附件批量下载等业务里，参数名多为 `path`、`dir`、`folder`、`fileName`，语义上「本来就该是路径」，因此最容易被忽略校验。

## 触发条件

- 打包/导出接口可达（是否需要登录取决于实现，本案例两个接口均可在已登录低权限会话下直接调用）。
- `path`（或同义参数）未经规范化校验，`..`、绝对路径、混合分隔符至少一种可用。
- 进程对被读文件有读权限（root/administrator 运行时覆盖面最大）。
- 响应直接返回 zip 流或给出下载链接，无需二次鉴权。

## 利用步骤

1. 从前端 JS/接口文档/抓包中找 `zipDownload`、`export`、`download`、`backup` 一类端点，记录参数名（`path`、`type`、`dir`）。
2. 先传合法值（如 `path=.`、`path=uploads`）确认接口返回 zip 且内容正常，避免把「参数不存在」误判成「被拦截」。
3. 逐级加 `../`：`path=../`、`path=../../`、`path=../../../../../../etc`，观察返回包内文件列表变化；Linux 下也可试绝对路径。
4. 命中后按目标挑目录：`/etc`（passwd/shadow/ssh 私钥）、Web 根（源码、`.env`、`config.php`、`web.config`）、数据库备份目录、中间件配置目录（Tomcat/Nginx）。
5. 解包核对内容，确认泄露范围；对源码做 grep 找数据库口令、第三方密钥、内网地址，形成后续利用面。
6. 控制请求次数与包体大小，只取必要目录，避免把线上服务拖垮。

## PoC

```http
GET /xxx/xxx/zipDownload?type=1&path=/../../../../../../..//etc HTTP/1.1
Host: target
```

```http
GET /xxx/Opt/export?path=../../ HTTP/1.1
Host: target
```

Windows 目标可用反斜杠与混合分隔符变体：

```http
GET /xxx/Opt/export?path=..%5c..%5c..%5c..%5chost%5cwindows HTTP/1.1
Host: target
```

## 变体与关联

- 变体：`type`、`format`、`zipName` 等参数不影响穿越，但可能决定打包内容（如 `type=1` 打包目录、`type=2` 打包指定文件）。
- 变体：`path` 只校验开头不含 `..` 时，用 `....//`、`..%2f`、`%2e%2e%2f`、双写、绝对路径绕过。
- 变体：把穿越与「读取后删除」类导出逻辑组合，可在取包同时清掉日志/备份，兼具痕迹清理效果。
- 关联：[[web-generic-file-inclusion-luckyframeweb-download-filename-traversal]]（单文件下载的 fileName 穿越，本卡是其批量打包版本）。
- 关联：[[web-generic-file-inclusion-extattrs-filename-traversal-download]]、[[web-generic-file-inclusion-flask-sendfile-download-traversal]]（下载接口按记录/拼接路径读取的同类形态）。

## 检测与防御

- 防御：打包/导出只接受资源 ID 或白名单目录名，服务端查表映射到真实路径，绝不接受客户端路径。
- 防御：拼接后 `realpath`/`getCanonicalPath()` 校验必须落在允许目录内，拒绝 `..`、绝对路径、混合分隔符与空字节。
- 防御：运行账号降权，仅授予业务目录读权限；源码、配置、备份目录与 Web 根物理隔离；备份文件不要放在可被遍历的位置。
- 检测：对 `path`/`dir`/`fileName` 参数出现 `../`、`%2e`、`..%5c`、绝对路径的请求告警；监控导出接口单次响应体积异常增大。
- 检测：审计所有「打包」类接口（zip/export/backup/download-all）的参数来源，把路径可控的端点列为高危清单。
