---
id: web-generic-file-inclusion-whir-ezoffice-deletefile-traversal-delete
title: 万户OA deleteFile.jsp 任意文件删除：delpath 被过滤但 delfile 未校验
type: scenario
domain: web
path: web/generic/file-inclusion
technique: whir-ezoffice-deletefile-traversal-delete
aliases:
- 万户OA 任意文件删除
- ezOFFICE deleteFile.jsp
- delpath delfile 删除
- uploadify deleteFile
- 路径穿越删除文件
tags:
- web
- file-inclusion
- java
- oa
- whir
- ezoffice
- path-traversal
- file-delete
- unauth
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V233
  verified_at: '2026-11-07T09:17:19+08:00'
  notes: 已对照原文与 img32 逐行核对并修正：实际条件为 path.indexOf("../")!=-1 || path.indexOf("..\\")!=-1 || path.indexOf("\\")!=-1 || path.indexOf("/")!=-1；delpath 含 /、\ 或 .. 时进入空分支（return 被注释但删除逻辑在 else 中，不执行），delfile 未过滤，穿越序列须放 delfile。已修正原卡误读的条件符号、转义与失效 PoC（delpath 改为普通目录名）。dup-scan 与 down.jsp 卡 pair 为 likely_duplicate，按原文裁决：本卡为 File.delete 任意删除，down.jsp 为 FileInputStream 任意下载，端点与 sink 不同，并列保留。原文未给出实际删除截图，未复跑。
---

## 一句话结论

万户OA 的 `public/upload/uploadify/deleteFile.jsp` 接收 `delpath`/`delfile` 参数后拼接成 `request.getRealPath("/upload/"+path+"/"+filename)` 并调用 `File.delete()`；`delpath` 含 `/`、`\` 或 `..` 时会进入空分支（`return` 被注释但删除逻辑在 else 中，不会执行），而 `delfile` 完全未过滤，把穿越序列放在 `delfile` 中即可删除服务器上应用账户有权限的任意文件。

## 原理

- `deleteFile.jsp` 关键逻辑：
  - `fileName = request.getParameter("delfile")`，`path = request.getParameter("delpath")`，`portletSettingId = request.getParameter("portletSettingId")`；
  - 当 `path != null` 时进入判断：`if (path.indexOf("../") != -1 || path.indexOf("..\\") != -1 || path.indexOf("\\") != -1 || path.indexOf("/") != -1) { //return; } else { ... }`。条件用 `||` 连接、判断的是“是否包含”而不是“是否不包含”：只要 `delpath` 含 `/`、`\` 或 `..` 就进入 if；`return` 被注释所以不会立即返回，但删除逻辑写在 else 中，因此含穿越字符的 `delpath` 反而不会执行删除，必须给一个不含分隔符/点的普通目录名（如 `abc`）才能进入 else。
  - else 分支根据附件上传配置走 FTP 或本地：
    - FTP：`ftp.deleteFile(path, fileName)`；
    - 本地：`__prefix = fileName.substring(0, 6)`，`__FD = new File(request.getRealPath("/upload/"+path+"/"+__prefix+"/"+fileName))`，存在则 `delete()`；否则再尝试 `new File(request.getRealPath("/upload/"+path+"/"+fileName)).delete()`。
  - `filename`（`delfile`）未做任何 `../`/绝对路径过滤，而 `path`（`delpath`）只要不含 `/`、`\`、`..` 即可正常通过；本地分支把 `"/upload/"+path+"/"+__prefix+"/"+fileName` 或 `"/upload/"+path+"/"+fileName` 交给 `getRealPath`，穿越序列放在 `filename` 中即可跳出 upload 目录删除任意路径。
- 页面位于 `/defaultroot/`，正常需登录，但可配合 `SetCharacterEncodingFilter` 的鉴权绕过未授权访问。

## 触发条件

- 目标为万户OA/ezOFFICE，`public/upload/uploadify/deleteFile.jsp` 存在。
- 能使用鉴权绕过路径到达该 JSP。
- 目标文件对应用进程可删除（同用户/同权限组），且路径可由 `delpath`+`delfile` 拼出。
- `delpath` 非 null 且不含 `/`、`\`、`..`（否则进入空分支、不执行删除）；`delfile` 长度 ≥6 且可含 `../`、`..\` 或绝对路径（代码会 `substring(0,6)`）。

## 利用步骤

1. 用鉴权绕过前缀访问 `deleteFile.jsp`，`delpath` 取不含 `/`、`\`、`..` 的普通目录名（如 `abc`），`delfile` 放穿越路径指向测试文件，确认删除成功（用下载/访问验证文件消失）。
2. 将目标换成配置文件、日志、上传的 webshell、锁文件等；`delfile` 在 Windows 可用 `..\`，注意目录深度与盘符。
3. 若走 FTP 分支，`path`/`filename` 会进入 `ftp.deleteFile`，可按 FTP 侧路径规则构造。
4. 记录请求、删除前后文件状态作为证据；避免删除业务关键文件。
5. 评估删除配合其他漏洞的影响（如删除鉴权配置、日志、竞争条件文件）。

## PoC

```http
GET /defaultroot/iWebOfficeSign/OfficeServer.jsp/../../public/upload/uploadify/deleteFile.jsp?delpath=abc&delfile=../../../../test.txt HTTP/1.1
Host: target
```

说明：`delpath` 必须是不含 `/`、`\`、`..` 的普通目录名（原文示例的 `delpath=../../` 会进入空分支而不会删除）；`delfile` 需长度 ≥6 并携带穿越序列，穿越深度按目标文件位置调整。原文未给出成功删除截图。

## 变体与关联

- 变体：`delfile` 用 `../`、`..\`、绝对路径、编码变体；`delpath` 只能取不含 `/`、`\`、`..` 的普通目录名。本地分支先尝试 `/upload/<delpath>/<delfile前6位>/<delfile>`，不存在再尝试 `/upload/<delpath>/<delfile>`，可分别构造。
- 变体：FTP 分支删除远端上传目录文件；结合上传接口可删除/替换。
- 关联：鉴权绕过 [[web-generic-auth-whir-ezoffice-characterencoding-filter-bypass]]；同产品下载 [[web-generic-file-inclusion-whir-ezoffice-down-jsp-download-ftp]]；通用路径穿越删除 [[web-generic-file-inclusion-goldlib-file-controller-delete-traversal]]。
- 边界：补丁同时校验 `delpath` 与 `delfile`（规范化后限制在上传目录内）、限制删除目录、应用账户无权限时利用不成立。

## 检测与防御

- 检测：`delpath`/`delfile` 出现 `../`、`..\`、绝对路径；删除请求命中非上传目录；`File.delete`/FTP delete 日志中出现异常路径。
- 修复：删除接口只接受文件 ID，服务端按 ID 查记录并映射到固定目录；对最终路径做规范化并校验位于上传目录内；`filename` 只允许 basename，拒绝 `..`/分隔符。
- 加固：上传与删除接口独立鉴权；应用运行账户最小权限；对删除操作做审计与二次确认；修复鉴权绕过，避免未授权到达。
