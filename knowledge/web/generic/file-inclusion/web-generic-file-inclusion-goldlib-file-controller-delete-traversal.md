---
id: web-generic-file-inclusion-goldlib-file-controller-delete-traversal
title: 金盘 FileController /admin/tools/file/delete：file 参数拼 ROOTPATH 后直接删除任意文件
type: scenario
domain: web
path: web/generic/file-inclusion
technique: goldlib-file-controller-delete-traversal
aliases:
- 金盘任意文件删除
- FileController delete
- deleteFile 路径穿越
- /admin/tools/file/delete
- ROOTPATH 拼接删除
tags:
- web
- file-delete
- path-traversal
- java
- spring-mvc
- goldlib
- opac
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V206
  verified_at: '2026-11-07T02:23:03+08:00'
  notes: 已对照原文与图27-28核对：FileController#delete 取 @RequestParam file，parseToPath(ROOTPATH+d.B('z')+file)，exists 后调用 CommonUtils.fileutil.deleteFile；图27 两个重载内部均仅 File.delete()，不会递归，已据此修正卡内“递归删除”表述。未复跑 PoC；鉴权边界按原文 Shiro /admin/**=user 与 CAS 放行描述保留。
---

## 一句话结论

金盘图书馆的 `FileController#delete`（`/admin/tools/file/delete`）接收 `file` 参数，用 `StringUtil.parseToPath(CommonConstants.ROOTPATH + 分隔符 + file)` 拼出路径后直接 `File.delete()`（目录与文件走同一 `deleteFile`，内部仅 `File.delete()`，不会递归），未过滤 `../`，可删除 Web 根之外的任意文件/空目录，造成配置破坏、日志/证据清理或进一步利用。

## 原理

- **入口**：`@RequestMapping({"/delete"})` 的 `delete(ModelMap model, @RequestParam("file") String file, ...)`；`file` 直接来自请求。
- **路径拼接**：`String a3 = StringUtil.parseToPath(CommonConstants.ROOTPATH + d.B("z") + file); File a4 = new File(a3);`；`d.B("z")` 是混淆后的路径分隔符（`/` 或 `\`），`parseToPath` 只做分隔符/点段规范化，不限制 `../`。
- **删除**：若 `a4.exists()`，目录与文件都调用 `CommonUtils.fileutil.deleteFile(a4)`；原文图 27 的两个重载（`deleteFile(String)`、`deleteFile(File)`）内部都只是 `file.delete()`，因此只能删除文件/空目录，非空目录会失败；没有 `canonicalPath` 根目录校验、没有白名单、没有对 `..` 的拒绝。
- **影响**：可删除应用配置（`WEB-INF/web.xml`、数据库配置）、日志、上传目录、`.htaccess`/`web.config`、其他站点文件；删除关键文件可导致服务不可用，删除安全组件/日志可辅助掩盖痕迹；若可删除计划任务/启动脚本，可能影响系统。
- **鉴权边界**：接口位于 `/admin/**`，Shiro 配置 `/admin/** = user` 要求登录；`CasHelperFilter` 的 `excludePrefixes` 含 `/admin`，可能放行；实际可达性取决于部署（CAS 开关、账号权限）。文章给出的请求未展示登录态，故置信度标 medium。

## 触发条件

- 目标部署金盘图书馆系统，`/admin/tools/file/delete` 可访问（有效低权限账号或鉴权绕过）。
- `file` 参数可控；运行用户对目标文件/目录有删除权限（Web 服务账户通常可删应用目录与上传目录）。
- 目标路径存在；目录删除依赖 `File.delete()`，只能删空目录，非空目录需先逐个删文件。
- 若 CAS 开启且 `/admin` 未放行，需要先获得会话或利用 Shiro/Spring 路径绕过。

## 利用步骤

1. 确认接口：向 `/admin/tools/file/delete` 发送 `file=test.txt`，观察返回 JSON 与文件是否消失（在授权测试中使用自建测试文件）。
2. 构造穿越：`file=../../../../tmp/test-delete.txt`（Linux）或 `file=..\..\..\..\Windows\Temp\test-delete.txt`（Windows），先删除测试文件验证越界。
3. 评估影响路径：应用配置、上传目录、日志、`WEB-INF` 下文件；非空目录无法直接删除，需按文件逐个删。
4. 在授权范围内删除证明文件（如临时文件）并记录响应；不要删除生产配置/数据。
5. 组合利用：删除 `.htaccess`/`web.config` 解除访问限制，删除日志掩盖痕迹，或删除安全 agent 配置。

## PoC

```http
POST /admin/tools/file/delete HTTP/1.1
Host: target.example
Cookie: JSESSIONID=<valid-session>
Content-Type: application/x-www-form-urlencoded
Content-Length: 38

file=../../../../tmp/test-delete.txt
```

```text
# 预期返回：{"success":true,...} 或类似；再次访问/检查文件应不存在。
# 空目录删除：file=../../../../tmp/testdir（内部仅 File.delete()，非空目录会失败）。
```

## 变体与关联

- 变体：若 `parseToPath` 对 `../` 做了部分处理，可尝试 `....//`、`..%2f`、`..%5c`、绝对路径、Unicode/大小写变体。
- 变体：删除 `WEB-INF/web.xml`/`classes` 下单个配置文件可导致应用重启失败；逐个删除上传目录内文件可清空证据；删除 `.htaccess` 可绕过访问控制。
- 关联：[[web-java-oa-download-servlet-followup-delete-arbitrary-file]]（下载接口后续删除任意文件）、[[web-java-component-litemall-storage-delete-arbitrary-file]]（存储 key 未规范化删除）、[[web-generic-file-inclusion-goldlib-download-items-traversal-read]]（同产品任意文件读取）。
- 边界：需要有效会话/鉴权绕过；运行账户权限不足时只能删应用可写文件；非空目录不能一次删除，删除操作可能造成不可逆影响。

## 检测与防御

- 检测：`/admin/tools/file/delete` 请求参数含 `../`、绝对路径、编码点段；文件系统监控大量删除/关键配置消失；审计日志中删除操作与登录账号异常。
- 修复：`file` 只接受文件 ID 或白名单相对路径；规范化后校验 `canonicalPath` 位于允许目录内；禁止删除目录；删除操作加二次确认与权限校验。
- 加固：Web 服务账户最小权限（不可删系统/配置）；关键配置只读挂载；备份与文件完整性监控；WAF 拦截路径穿越。
