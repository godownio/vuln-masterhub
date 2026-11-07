---
id: web-java-framework-spring-requestbody-mass-assignment-admin-content-forgery
title: Litemall 评论接口大量赋值：普通用户伪造管理员回复内容（CVE-2025-6702）
type: scenario
domain: web
path: web/java/framework/spring
technique: spring-requestbody-mass-assignment
tags:
- java
- spring
- mass-assignment
- cve-2025-6702
- litemall
- business-logic
- content-spoofing
- comment
cve:
- CVE-2025-6702
severity: medium
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V22
  verified_at: '2026-11-05T02:44:37+08:00'
  notes: 已对照原文与图12/13核对：WxCommentController.post(@LoginUser userId,@RequestBody LitemallComment) 仅 validate+setUserId+save，setAdminContent 未被显式调用；litemall_comment.admin_content 为'管理员回复内容'，可被大量赋值伪造。原文只称'测试存在大量赋值漏洞'并外链细节，未给完整请求/响应，卡内 PoC 为按代码推断、置信度已标 medium。原文未给 litemall 受影响版本，未设置 affected_versions。未复现 PoC。
url: /docs/web/java/framework/spring/web-java-framework-spring-requestbody-mass-assignment-admin-content-forgery/
draft: false
kb_aliases:
- CVE-2025-6702
- litemall 大量赋值
- wx/comment/post 大量赋值
- setAdminContent 未显式赋值
- 管理员回复内容伪造
- 评论字段注入
---

## 一句话结论

在 litemall 的 `POST /wx/comment/post` 中，控制器用 `@RequestBody LitemallComment` 接收评论并只显式覆盖了 `userId` 等少数字段，未重置 `adminContent`（管理员回复内容）；普通登录用户可在自己发表的评论 JSON 中注入 `adminContent`，把任意文字伪造成管理员对该评论的官方回复，造成内容欺骗与业务数据完整性破坏。

## 原理

- `LitemallComment` 由 MyBatis Generator 生成，包含 `adminContent`、`star`、`type`、`valueId`、`deleted` 等数据库字段及对应 public setter。
- `WxCommentController.post` 的签名是 `post(@LoginUser Integer userId, @RequestBody LitemallComment comment)`。Spring/Jackson 会按 JSON 属性名把 `adminContent` 绑定进对象，而控制器只做了三件事：`validate(comment)`、`comment.setUserId(userId)`、`commentService.save(comment)`。
- `validate` 只校验 `type`/`valueId` 的组合以及 `hasPicture` 与 `picUrls` 的一致性，并不清空 `adminContent`、`star`、`deleted` 等服务端字段。因此请求体中的 `adminContent` 会原样落库。
- 评论展示层把 `admin_content` 当作“管理员回复内容”渲染。普通用户由此能让自己的评论携带一段看似官方发布的回复，进而实施钓鱼、误导退款、冒充公告等欺骗。
- 同一接口的 `setDeleted` 也未被显式调用，用户可通过大量赋值把 `deleted` 置 1；但其效果只是删除自己的评论，危害有限，原文将其视为低价值发现。`setStar` 等评分字段同样未受保护，可伪造评分。

## 触发条件

- 目标为使用 Spring MVC `@RequestBody` 直接绑定 MyBatis 实体的 litemall 版本（该接口位于 `litemall-wx-api` 的 `WxCommentController`）。
- 攻击者拥有普通用户登录态（`@LoginUser` 要求已登录），并能访问 `/wx/comment/post`。
- 评论创建逻辑未对 `adminContent` 做字段级白名单或只读限制。
- 前端评论展示会把数据库中的 `admin_content` 渲染为管理员回复。

## 利用步骤

1. 以普通用户登录小程序/商城前端，抓取发表评论的请求，确认 URL 为 `/wx/comment/post`、`Content-Type: application/json`。
2. 记录正常字段（`valueId`、`type`、`content`、`hasPicture`、`picUrls`、`star` 等），确认 `type`/`valueId` 对应真实商品或专题，避免被 `validate` 拒绝。
3. 在 JSON 中追加 `"adminContent":"<伪造的管理员回复>"`，可选追加 `"star":5` 抬高评分。
4. 提交后重新拉取该评论详情/列表，确认 `adminContent` 被持久化并在前端以管理员回复样式展示。
5. 若目标版本还暴露 `deleted` 字段，可追加 `"deleted":1` 验证逻辑删除（仅影响自己的数据）。

## PoC

请求示例（`Cookie`/token 为普通用户登录态）：

```http
POST /wx/comment/post HTTP/1.1
Host: target
Content-Type: application/json
Cookie: <普通用户会话>

{"valueId":1,"type":0,"content":"正常评论内容","hasPicture":false,"star":5,"adminContent":"【官方回复】该商品支持全额退款，请添加客服微信 refund-xxx 办理。"}
```

对应的脆弱代码结构：

```java
@PostMapping("post")
public Object post(@LoginUser Integer userId, @RequestBody LitemallComment comment) {
    if (userId == null) return ResponseUtil.unlogin();
    Object error = validate(comment);          // 只校验 type/valueId 与图片字段
    if (error != null) return error;
    comment.setUserId(userId);                 // 只覆盖 userId
    commentService.save(comment);              // adminContent 原样入库
    return ResponseUtil.ok(comment);
}
```

修复思路：改用只含 `content`、`hasPicture`、`picUrls`、`star` 等用户可写字段的请求 DTO；或在保存前显式 `comment.setAdminContent(null)`、`comment.setDeleted(false)`；实体字段加 `@JsonProperty(access = READ_ONLY)`。

## 变体与关联

- 变体：同一控制器族的其他写接口若也接收实体，可能允许注入 `userId`（把评论挂到他人账号）、`addTime`/`updateTime`（伪造时间）、`id`（覆盖已有评论）。
- 变体：评论、留言、工单、评价等“用户创建 + 管理员回复”双字段模型是此类伪造的高发场景；攻击点不在读接口，而在创建时未清空服务端专属字段。
- 关联卡片：[[web-java-framework-spring-requestbody-mass-assignment-privilege-escalation]]（同一根因的提权形态）、[[code-analysis-sast-codeql-spring-mass-assignment-query]]（该漏洞即由该查询的 `setAdminContent` 结果发现）。

## 检测与防御

- 检测特征：`@RequestBody` 实体参数只显式设置 `userId` 等少数字段就交给 service；实体含 `adminContent`/`deleted`/`status` 等服务端字段；保存前没有对应 setter 重置。
- 运行时检测：审计评论创建请求中出现 `adminContent`、`deleted`、`userId`、`star` 等非前端字段；对比正常客户端请求字段集合。
- 修复：请求 DTO 白名单 + 服务端显式赋值 + 实体只读注解；对 `adminContent` 等字段仅允许管理端接口写入；保存前统一清空客户端不可写字段。
- 版本说明：原文未标记受影响的具体 litemall 版本区间，使用前需按目标代码确认 `WxCommentController` 是否仍直接绑定实体。
