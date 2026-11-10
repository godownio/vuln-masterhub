---
id: web-generic-file-inclusion-docsys-preview-read-delete-path-traversal
title: DocSys 预览/打开接口 readRealDocContentEx 与删除接口不校验 path：目录穿越任意文件读取与删除
type: scenario
domain: web
path: web/generic/file-inclusion
technique: java-doc-preview-read-delete-path-traversal
tags:
- java
- path-traversal
- arbitrary-file-read
- arbitrary-file-delete
- docs-management
- credential-leak
cve: []
severity: high
confidence: medium
status: verified
affected_versions: DocSys V2.02.36（原文使用该 war 包复现，未给修复版本）
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W3
  verified_at: '2026-11-08T19:33:51+08:00'
  notes: 已对照原文核对；本次核对未读取图片；预览按文件类型分流调用 readRealDocContentEx 与删除接口同样不校验 path 的描述与正文一致；具体预览/删除路由名正文只以截图给出，卡内保留为占位路由，穿越回显与删除效果未读图验证
url: /docs/web/generic/file-inclusion/web-generic-file-inclusion-docsys-preview-read-delete-path-traversal/
draft: false
kb_aliases:
- DocSys 任意文件读取
- MxsDoc 预览穿越读文件
- readRealDocContentEx 路径穿越
- 文件管理系统删除穿越
- 文档预览接口读配置
---

## 一句话结论

DocSys（MxsDoc）的文档预览/打开功能在处理请求时只判断了文件类型（文本类走 `readRealDocContentEx`），却没有校验 `path`，因此 `path` 里的 `../` 会把读取点带出仓库根，读到应用配置、数据库口令与源码；同一套"path + name 拼路径"逻辑在删除功能里也没有任何校验，构成同一根因下的任意文件删除。

## 原理

- 预览接口的流程是：按 `path`/`name` 定位文档 → 从扩展名或类型判断是否为文本 → 文本类调用 `readRealDocContentEx` 读取内容并回显。判断分支只关心"能不能当文本打开"，不关心"文件在不在仓库里"。
- 仓库根 + 相对路径的拼接方式（字符串拼接或 `new File(root, path)`）本身不做规范化；`..` 由文件系统在 `open()` 时解析，所以逐级 `../` 就能爬到仓库外。这是 Java 文件类接口最常见的信任边界错误：把"服务端常量根目录"当成安全边界。
- 读取侧的危险在于回显：预览接口本来就要把文件内容返回给前端，所以一旦穿越成功，读到什么就回显什么，不需要额外通道。
- 删除侧代码与上传/读取基本一致（同样取 `path`、`name`），只做了权限与存在性判断，没有路径校验；删除类接口的危害是"可预期地破坏"，也常被用来删除 `.htaccess`、锁文件或日志以掩盖痕迹。

## 触发条件

- 能访问预览/打开接口（需具备该仓库的访问权；原文未验证未授权，不能默认未授权）。
- `path`/`name` 未做规范化包含校验、未过滤 `..` 与分隔符。
- 目标文件对应用进程可读（读）/可写（删）。
- 读取要求目标是文本类型或类型判断可被文件名后缀影响；二进制文件可能只返回部分内容或报错。

## 利用步骤

1. 在文件列表中点开/预览一个文件并抓包，定位预览接口与参数（`path`、`name`，可能还有仓库标识）。
2. 先用正常文件确认回显格式，再逐步加 `../` 观察是否能读到仓库外已知文件。
3. 读取应用配置文件（数据库连接串、密钥）、`web.xml`、源码与日志；Windows 下用 `..\..\` 或绝对路径读 `win.ini` 验证。
4. 换用删除接口，用同样的穿越 `path` 删掉仓库外文件验证危害（靶场环境下测试）。
5. 用读到的数据库凭据或密钥横向，衔接上传写入拿脚本执行。

## PoC

```http
GET /DocSystem/<预览路由>?path=../../../../&name=../../../../etc/passwd HTTP/1.1
Host: target
Cookie: <会话>
```

```text
# 等价脆弱链路（均为字符串拼接，无 canonical 校验）
preview:  readRealDocContentEx(root + path + name)
delete :  new File(root + path + name).delete()
```

## 变体与关联

- 变体（读取 sink）：`FileInputStream`、`Files.readAllBytes`、`FileUtils.readFileToString`；只要路径来自请求且未规范化，原理相同。
- 变体（绕过）：`%2e%2e%2f`、双重编码、`....//`、`..%5c`、绝对路径/盘符；具体能否绕过取决于框架解码与过滤顺序。
- 变体（同根因）：上传（`uploadDoc.do`）与新建文件写入（`saveDataToFile`）同样缺校验，可把读取升级为写入，见关联卡。
- 关联：[[web-generic-file-inclusion-java-new-file-root-path-traversal-read]]（Java `new File(root,path)` 通用原理）、[[web-generic-file-inclusion-luckyframeweb-download-filename-traversal]]（同类下载/删除双用途接口）。
- 边界：若服务端对拼接结果做 `getCanonicalPath()` 前缀校验、或接口只接受文件 ID 查表，则本条失效。

## 检测与防御

- 修复：读取与删除前统一 `getCanonicalPath()`/`toRealPath()` 并校验仍以仓库根为前缀；拒绝绝对路径与 `..`；接口改为只接受文件 ID。
- 加固：应用进程最小权限，配置与密钥目录不在 Web 进程可读范围；删除接口加二次确认与软删除（回收站）机制。
- 检测：请求参数含 `../`、`..\`、`%2e%2e`、盘符；预览接口返回内容与请求的文档扩展名不匹配（如 jsp 接口返回 `password=`、私钥头）；短时间内大量删除请求。
- 审计：搜索 `readRealDocContentEx`、`saveRealDocContentEx`、`delete` 相关方法中 `path`/`name` 的来源与校验情况。
