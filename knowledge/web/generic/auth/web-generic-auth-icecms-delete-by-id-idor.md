---
id: web-generic-auth-icecms-delete-by-id-idor
title: IceCMS 内容删除接口按 ID 越权（CVE-2023-6762）：非所有者 token 可删除任意文章与广场内容
type: scenario
domain: web
path: web/generic/auth
technique: icecms-delete-by-id-idor
aliases:
- IceCMS 越权删除
- CVE-2023-6762
- DelectArticleById
- DelectSquareById
- 遍历 ID 删除文章
- 删除接口 IDOR
tags:
- authz
- idor
- icecms
- delete
- broken-access-control
- jwt
- java
cve:
- CVE-2023-6762
severity: medium
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
affected_versions: Thecosy IceCMS 2.0.1
verification:
  verified_by: verifier-V442-fix
  verified_at: '2026-11-09T23:30:56+08:00'
  notes: V442 核对指出『去掉 Authorization 返回 false 因此需有效 JWT』证据不足：截图所用 ID 271 在前一请求已被删除，重复删除同样返回 false；原文文字称去 JWT 仍删除成功，与本卡结论及同批 CSRF 卡矛盾。已改写一句话结论、广场删除原理、触发条件与 PoC 注释为『文字与截图矛盾、未复测，是否需要 JWT 待确认』，不再断言必须有效 JWT；文章删除越权（CVE-2023-6762，图38 普通用户 sub=376 删他人文章返回 true）核对不变。
---

## 一句话结论

IceCMS 的文章删除 `/article/DelectArticleById/{articleId}` 与广场内容删除 `/square/DelectSquareById/{id}` 只校验 JWT 是否有效（原文文字称广场端点去掉 JWT 也能删除，但截图显示 false，见下），不校验请求者是否为内容所有者：换用一个非所有者的 token、把路径 ID 改成别人的文章/广场内容即可删除成功，遍历 ID 可清空站内内容（CVE-2023-6762）。

## 原理

- **认证 ≠ 授权**：接口把 JWT 当作"已登录"的凭证，删除逻辑直接按路径中的 `articleId`/`id` 执行 DELETE，没有把对象 ID 与 token 中的用户 ID/角色做归属比对（对象级权限校验缺失）。
- **文章删除路径**：作者先以管理员删除文章 `1000002189` 并抓包，注销后换另一个账号（token 的 `sub` 与管理员不同）删除另一篇文章 `1000002190`，服务端返回 `true`，证明删除不依赖该文章的作者身份。
- **广场删除路径**：普通登录用户对 `/square/DelectSquareById/{id}` 携带有效 JWT 即可删除任意 ID 的广场内容，ID 从公开列表按递增枚举。关于是否需要 JWT：原文文字称“删除 jwt 的身份认证，会发现删除成功”，而截图中去掉 Authorization 返回 `false`；但该截图使用的 ID 271 在前一次带 JWT 请求中已被删除，重复删除同样会返回 `false`，因此不能据此断言“必须有效 JWT”。文章文字与截图矛盾且未复测，广场端点是否完全未授权待确认。
- **危害**：任意登录用户（包括低权限/刚注册账号）可批量删除他人文章、广场内容，造成内容破坏与业务损失；结合 ID 遍历可自动化清空。
- **为什么难被察觉**：删除是正常业务动作，日志里只有合法 JWT 与合法接口调用，若审计不记录"操作者 vs 对象所有者"就无法发现越权。

## 触发条件

- 目标为 IceCMS 2.0.1（CVE-2023-6762；广场删除为同版本自测项）。
- 攻击者拥有任意有效账号与 JWT（可自行注册）；广场端点是否要求 JWT 尚未确认（原文文字与截图矛盾、未复测）。
- 目标内容 ID 可枚举（文章/广场列表直接展示连续 ID）。
- 删除接口未做对象级归属/角色校验。

## 利用步骤

1. 登录普通账号，进入文章/广场列表，记录自己内容的删除请求与 ID 形态。
2. 从列表读取他人内容 ID（示例文章 `1000002190`，广场 `271`）。
3. 用普通账号 JWT 请求 `GET /article/DelectArticleById/1000002190` 或 `GET /square/DelectSquareById/271`。
4. 返回 `true` 即删除成功；刷新列表确认目标消失。
5. 写脚本遍历 ID 区间批量删除，注意控制影响范围并留证（授权测试）。

## PoC

```bash
# 用非文章所有者的普通账号 token 删除他人文章，返回 true
curl -s -H "Authorization: Bearer <普通账号 JWT>" \
  "http://target:8181/article/DelectArticleById/1000002190"

# 用普通账号 token 删除任意广场内容；不带 token 的结果原文文字（删除成功）与截图（false）矛盾，未复测
curl -s -H "Authorization: Bearer <普通账号 JWT>" \
  "http://target:8181/square/DelectSquareById/271"
```

## 变体与关联

- 变体：接口若改为 POST/DELETE 方法，参数仍可能只在路径或表单中，替换 ID 即可复用。
- 变体：同产品评论修改/删除接口同样按 ID 操作，可组合成"改内容 + 删内容"的破坏链。
- 关联：[[web-generic-auth-icecms-square-comment-api-missing-jwt]]（未授权读取/篡改评论）；[[web-generic-auth-icecms-user-changeuser-idor]]（同产品 userId 越权）；[[web-generic-csrf-icecms-square-delete-form]]（同一删除接口的 CSRF 视角）。

## 检测与防御

- 检测：删除请求中的对象 ID 不属于 token 用户；同一账号短时间内删除大量不同作者/ID 的内容；删除接口返回成功但无对应站内操作记录。
- 防御：删除前做对象级授权（所有者或管理角色）；管理端删除使用独立接口并校验角色；对批量删除限速与审计；关键内容采用软删除与回收站，保留可恢复窗口。
