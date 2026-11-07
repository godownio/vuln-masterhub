---
id: web-generic-auth-face-photo-update-body-id-idor
title: 移动端人脸照片更新接口按请求体 id 越权：替换他人生物特征照片
type: scenario
domain: web
path: web/generic/auth
technique: face-photo-update-body-id-idor
aliases:
- 越权修改人脸照片
- person/app/face IDOR
- 人脸更新接口越权
- 生物特征越权写入
- 请求体 id 未绑定令牌
- 替换他人人脸
tags:
- idor
- broken-access-control
- horizontal-privilege-escalation
- face
- biometric
- mobile
- api
- write-operation
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V82
  verified_at: '2026-11-05T17:44:10+08:00'
  notes: 已对照原文与图10-13核对：图12 为 POST /evo-apigw/evo-erm/1.0.0/person/app/face，Authorization 为账号A的 bearer，body 首字段 id=6297（受害者B的 personId），后接 base64 图片；图13 登录账号B确认照片已被替换；受害者 userId=6299/personId=6297 来自 person/permission 遍历。图12 未显示 base64 字段名，卡内 faceImage 为按常见结构推断，PoC 未复跑。原文无版本信息，未设置 affected_versions；frontmatter 无 sources/source_url。
---

## 一句话结论

移动端人脸照片更新接口 `POST /evo-apigw/evo-erm/1.0.0/person/app/face` 只校验 Bearer Token 是否有效，却用请求体 JSON 里的 `id`（personId）决定更新哪个用户；攻击者登录自己的账号 A，保留 A 的合法 Authorization、把 body 的 `id` 改成受害者 B 的 personId 并提交 base64 图片，即可替换 B 的人脸照片，导致考勤/门禁等生物识别身份被篡改。

## 原理

- 人脸更新接口的授权分两层：认证（Bearer Token 是否有效）与对象级授权（这个 Token 是否有权修改 body 指定的 personId）。本文只做了前者，没有把 Token 的主体与 body 的 `id` 比对，也没有校验目标用户归属。
- 攻击者不需要伪造 Token：直接使用自己账号 A 的真实 Token 通过认证，只把请求体中的 `id` 改成 B 的 personId；服务端按 `id` 定位 B 的人脸记录并写入新图片，完成越权写入。
- 受害者 personId 可通过其他越权接口获得：本文先用 `person/permission?userId=` 遍历到账号 B 的 `userId=6299`、`personId=6297`（两者相近但不等），再把人脸请求的 `id` 改为 6297。
- 危害是生物特征数据完整性被破坏：人脸通常用于考勤、门禁、考试核验；替换后可让受害者无法通过核验（拒绝服务），或配合其他漏洞冒用身份。本文通过登录账号 B 查看照片，确认已被替换。
- 与只读 IDOR 的区别：写接口的对象级授权缺失更危险，因为它直接修改受害者数据；与“人脸活体绕过”的区别：本卡不需要伪造活体，只是滥用服务端信任的 personId。
- 之所以成立：服务端把“谁在请求”（Token）与“改谁”（body id）解耦，且人脸更新属于低摩擦的普通接口，没有二次验证或变更通知。

## 触发条件

- 攻击者拥有任意有效账号和 Bearer Token。
- 人脸照片更新接口可达，请求体包含可写的 `id`/`personId`/`userId` 与 base64 图片。
- 服务端只校验 Token 有效性，不校验 Token 主体与目标 id 的归属。
- 能获得受害者 personId（通过越权查询、日志、共享链接等）。
- 接口允许直接覆盖人脸，不要求旧人脸比对/活体/管理员审批。

## 利用步骤

1. 登录账号 A，抓取自己的人脸更新请求：
   ```http
   POST /evo-apigw/evo-erm/1.0.0/person/app/face HTTP/2
   Authorization: Bearer <A-token>
   Content-Type: application/json

   {"id": <A-personId>, "faceImage": "<base64>", ...}
   ```
2. 用越权查询拿到受害者 B 的 personId（本文 `userId=6299` → `personId=6297`）。
3. 保留 A 的 Authorization（确保通过认证），把 body 的 `id` 改为 B 的 personId，替换 base64 图片为任意图片。
4. 发送请求；若返回成功，登录 B 查看头像/人脸照片，确认已被替换。
5. 进一步测试同一 id 是否可用于其他人脸/考勤/门禁接口，评估是否可冒用 B 的身份。

## PoC

```http
POST /evo-apigw/evo-erm/1.0.0/person/app/face HTTP/2
Host: target
Authorization: Bearer <attacker-A-valid-token>
Content-Type: application/json;charset=UTF-8
User-Client: 6

{
  "id": 6297,
  "faceImage": "data:image/jpeg;base64,<ATTACKER_IMAGE_BASE64>"
}
```

```text
# 响应成功；登录受害者账号 B 后发现人脸照片已被替换
```

说明：原文先通过 `person/permission?userId=` 遍历到 B 的 `userId=6299`、`personId=6297`，再登录账号 A 替换 Authorization、修改 body 的 `id` 并提交 base64 图片，登录 B 验证照片已变。PoC 未在本机复跑，ID/Token/图片均已脱敏。

## 变体与关联

- **参数位置变体**：`id` 可能在 JSON body、query、multipart 字段或路径中；同一接口可能同时接受 `personId`/`userId`/`brUserId`，逐个替换测试。
- **写操作变体**：除人脸外，姓名、手机号、宿舍、密码、指纹等资料更新接口若按请求体 id 定位对象，同样可越权写入；参见 [[web-generic-auth-newbeemall-updateinfo-userid-idor]]。
- **只读前置**：受害者 ID 通常来自 [[web-generic-auth-mobile-person-permission-userid-idor-pii]] 等越权查询接口；先读后写是常见组合。
- **人脸认证关联**：[[web-generic-auth-face-liveness-background-replace-base64]]（活体绕过）与本卡（生物特征写入）可组合：先改人脸，再绕过/通过核验。
- **边界**：Token 与目标 id 做了绑定、更新人脸要求旧人脸比对/活体/管理员审批、接口只允许本人 id、或有变更通知与二次确认时，本路径失效。

## 检测与防御

- **检测**：同一 Token 对多个不同 personId 发起人脸更新；人脸更新请求的 body id 与 Token 主体不一致；短时间内在多个账号间切换 id。
- **检测**：人脸照片变更事件缺少对应的人脸采集/活体流程；用户投诉头像被改；异常 base64 图片上传。
- **防御**：对象级授权——服务端强制 `body.id == token.subject` 或按角色/数据范围校验；人脸更新只允许本人或管理员，并记录审计。
- **加固**：人脸等生物特征变更要求旧人脸比对/活体/二次验证，变更后通知用户；对批量 ID 查询与人脸写入做速率限制。
- **响应**：回滚被篡改的人脸数据、通知受害者、吊销相关会话、排查是否已用于考勤/门禁冒用。
